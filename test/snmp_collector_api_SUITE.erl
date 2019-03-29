%%% snmp_collector_api_SUITE.erl
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% @copyright 2018 SigScale Global Inc.
%%% @end
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%  Test suite for the snmp_collector API.
%%%
-module(snmp_collector_api_SUITE).
-copyright('Copyright (c) 2018 SigScale Global Inc.').

%% common_test required callbacks
-export([suite/0, sequences/0, all/0]).
-export([init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).

-compile(export_all).

-include("snmp_collector.hrl").
-include_lib("common_test/include/ct.hrl").
-include_lib("inets/include/mod_auth.hrl").

%% support deprecated_time_unit()
-define(MILLISECOND, milli_seconds).
%-define(MILLISECOND, millisecond).

%%---------------------------------------------------------------------
%%  Test server callback functions
%%---------------------------------------------------------------------

-spec suite() -> DefaultData :: [tuple()].
%% Require variables and set default values for the suite.
%%
suite() ->
	[{userdata, [{doc, "Test suite for public API"}]},
	{require, snmp_mgr, snmp},
	{default_config, snmp,
			[{mgr_port, rand:uniform(64511) + 1024}]},
	{require, snmp_app},
	{default_config, snmp_app,
			[{manager,
					[{config, [{verbosity, silence}]},
					{server, [{verbosity, silence}]},
					{notestore, [{verbosity, silence}]},
					{net_if, [{verbosity, silence}]}]}]},
	{timetrap, {minutes, 2}}].

-spec init_per_suite(Config :: [tuple()]) -> Config :: [tuple()].
%% Initiation before the whole suite.
%%
init_per_suite(Config) ->
	ok = snmp_collector_test_lib:initialize_db(Config),
	ok = ct_snmp:start(Config, snmp_mgr, snmp_app),
	ok = snmp_collector_test_lib:start(Config),
	Config.

-spec end_per_suite(Config :: [tuple()]) -> any().
%% Cleanup after the whole suite.
%%
end_per_suite(_Config) ->
	ok = snmp_collector_test_lib:stop().

-spec init_per_testcase(TestCase :: atom(), Config :: [tuple()]) -> Config :: [tuple()].
%% Initiation before each test case.
%%
init_per_testcase(TestCase, Config)
		when TestCase == get_faults;
		TestCase == log_agent;
		TestCase == log_severity ->
	AgentNames = [string(20) || _ <- lists:seq(1, 25)],
	Severities = ["CRITICAL", "MAJOR", "MINOR", "WARNING"],
	Fdetails = fun F(0, _SeverityFieldNum, Acc) ->
				Acc;
			F(N, N, Acc) ->
				Severity = lists:nth(rand:uniform(length(Severities)), Severities),
				F(N - 1, N, [{"eventSeverity", Severity} | Acc]);
			F(N, SeverityFieldNum, Acc) ->
				F(N - 1, SeverityFieldNum, [{string(15), string(50)} | Acc])
	end,
	Fill = fun F(0) ->
				ok;
			F(N) ->
				TN = lists:nth(rand:uniform(length(AgentNames)), AgentNames),
				NumDetails = rand:uniform(12),
				AlarmDetails = Fdetails(NumDetails, rand:uniform(NumDetails), []),
				{CH, FF} = snmp_collector_utils:generate_maps(TN, AlarmDetails),
				ok = snmp_collector_utils:log_events(CH, FF),
				F(N - 1)
	end,
	ok = Fill(10),
	{ok, LogName} = application:get_env(snmp_collector, queue_name),
	LogInfo = disk_log:info(LogName),
	{_, CurrentItems} = lists:keyfind(no_current_items, 1, LogInfo),
	{_, CurrentSize} = lists:keyfind(no_current_bytes, 1, LogInfo),
	EventSize = (CurrentSize div CurrentItems) + 1,
	{_, {FileSize, _NumFiles}} = lists:keyfind(size, 1, LogInfo),
	NumEvents = (FileSize div EventSize) * 5,
	ok = Fill(NumEvents),
	Config;
init_per_testcase(_TestCase, Config) ->
	Config.

-spec end_per_testcase(TestCase :: atom(), Config :: [tuple()]) -> any().
%% Cleanup after each test case.
%%
end_per_testcase(_TestCase, _Config) ->
	ok.

-spec sequences() -> Sequences :: [{SeqName :: atom(), Testcases :: [atom()]}].
%% Group test cases into a test sequence.
%%
sequences() ->
	[].

-spec all() -> TestCases :: [Case :: atom()].
%% Returns a list of all test cases in this test suite.
%%
all() ->
	[add_user, get_user, delete_user,
			get_mib,
			get_faults, log_agent, log_severity, log_filter,
	password_to_key_md5, password_to_key_sha].

%%---------------------------------------------------------------------
%%  Test cases
%%---------------------------------------------------------------------

add_user() ->
	[{userdata, [{doc, "Create a new user"}]}].

add_user(_Config) ->
	User = snmp_collector_utils:generate_identity(6),
	Password = snmp_collector_utils:generate_identity(8),
	Locale = "en",
	{ok, {TS, N}} = snmp_collector:add_user(User, Password, Locale),
	true = is_integer(TS),
	true = is_integer(N),
	{Port, Address, Dir, _} = get_params(),
	{ok, #httpd_user{username = User, password = Password,
			user_data = UserData}} = mod_auth:get_user(User, Address, Port, Dir),
	{_, Locale} = lists:keyfind(locale, 1, UserData),
	{_, {_E1, _E2}} = lists:keyfind(last_modified, 1, UserData).

get_user() ->
	[{userdata, [{doc, "Look up a user from table"}]}].

get_user(_Config) ->
	User = snmp_collector_utils:generate_identity(6),
	Password = snmp_collector_utils:generate_identity(8),
	Locale = "en",
	{ok, LastModified} = snmp_collector:add_user(User, Password, Locale),
	{ok, #httpd_user{username = User, password = Password,
			user_data = UserData}} = snmp_collector:get_user(User),
	{_, Locale} = lists:keyfind(locale, 1, UserData),
	{_, LastModified} = lists:keyfind(last_modified, 1, UserData).

delete_user() ->
	[{userdata, [{doc, "Remove user from table"}]}].

delete_user(_Config) ->
	User = snmp_collector_utils:generate_identity(6),
	Password = snmp_collector_utils:generate_identity(8),
	Locale = "en",
	{ok, _} = snmp_collector:add_user(User, Password, Locale),
	{ok, _} = snmp_collector:get_user(User),
	ok = snmp_collector:delete_user(User),
	{error, no_such_user} = snmp_collector:get_user(User).

get_mib() ->
	[{userdata, [{doc,"Get a MIB using the rest interface"}]}].

get_mib(_Config) ->
	{ok, TestMib} = application:get_env(snmp_collector, test_mib),
	{ok, Data} = file:read_file(TestMib),
	{ok, _} = snmp_collector:add_mib(Data).
	
get_faults() ->
	[{userdata, [{doc, "Query event log for (all) faults"}]}].

get_faults(_Config) ->
	PageSize = undefined,
	Start = 1,
	End = erlang:system_time(?MILLISECOND),
	get_faults(PageSize, Start, End, {start, []}, 0).
get_faults(PageSize, Start, End, {Cont, Events}, Acc) ->
	Fall = fun (Event) when element(1, Event) >= Start,
					element(1, Event) =< End,
					is_integer(element(2, Event)),
					is_atom(element(3, Event)),
					is_map(element(4, Event)),
					is_map(element(5, Event)) ->
				true;
			(_) ->
				false
	end,
	true = lists:all(Fall, Events),
	NewAcc = Acc + length(Events),
	case Cont of
		eof ->
			{ok, LogName} = application:get_env(snmp_collector, queue_name),
			{_, NewAcc} = lists:keyfind(no_items, 1, disk_log:info(LogName));
		Cont ->
			get_faults(PageSize, Start, End, snmp_collector_log:fault_query(Cont,
					PageSize, Start, End, '_', '_'), NewAcc)
	end.

log_agent() ->
	[{userdata, [{doc, "Query event log for faults from an agent"}]}].

log_agent(_Config) ->
	PageSize = 50,
	Start = 1,
	End = erlang:system_time(?MILLISECOND),
	case list_to_integer(erlang:system_info(otp_release)) of
		OtpRelease when OtpRelease >= 21 ->
			{ok, LogName} = application:get_env(snmp_collector, queue_name),
			{_Cont, Chunk} = disk_log:chunk(LogName, start),
			#{"reportingEntityName" := Agent} = element(4, lists:last(Chunk)),
			MatchHead = [{#{"reportingEntityName" => Agent}, [], ['$_']}],
			{_Cont, Events} = snmp_collector_log:fault_query(start,
					PageSize, Start, End, MatchHead, '_'),
			true = length(Events) > 0,
			Fall = fun (Event) ->
					case element(4, Event) of
						#{"reportingEntityName" := Agent} ->
							true;
						_ ->
							false
					end
			end,
			true = lists:all(Fall, Events),
			length(Events);
		_OtpRelease ->
			{skip, "requires OTP 21 or later"}
	end.

log_severity() ->
	[{userdata, [{doc, "Query event log for faults with matching severity"}]}].

log_severity(_Config) ->
	case list_to_integer(erlang:system_info(otp_release)) of
		OtpRelease when OtpRelease >= 21 ->
			MatchCondition1 = {'==', "CRITICAL", '$1'},
			MatchCondition2 = {'==', "MAJOR", '$1'},
			MatchConditions = [{'or', MatchCondition1, MatchCondition2}],
			MatchFields = [{#{"eventSeverity" => '$1'}, MatchConditions, ['$_']}],
			{_Cont, Events} = snmp_collector_log:fault_query(start,
					50, 1, erlang:system_time(?MILLISECOND), '_', MatchFields),
			Fall = fun (Event) ->
					case element(5, Event) of
						#{"eventSeverity" := "CRITICAL"} ->
							true;
						#{"eventSeverity" := "MAJOR"} ->
							true;
						#{} ->
							false
					end
			end,
			true = length(Events) > 0,
			true = lists:all(Fall, Events),
			length(Events);
		_OtpRelease ->
			{skip, "requires OTP 21 or later"}
	end.

log_filter() ->
	[{userdata, [{doc, "Query event log for faults with filtered result fields"}]}].

log_filter(_Config) ->
	case list_to_integer(erlang:system_info(otp_release)) of
		OtpRelease when OtpRelease >= 21 ->
			MatchHead = [{#{"eventId" => '$1'}, [], [#{"eventId" => '$1'}]}],
			MatchConditions = [{'==', '$1', "MINOR"}],
			MatchBody = [#{"eventSeverity" => '$1'}],
			MatchFields = [{#{"eventSeverity" => '$1'}, MatchConditions, MatchBody}],
			{_Cont, Events} = snmp_collector_log:fault_query(start,
					50, 1, erlang:system_time(?MILLISECOND), MatchHead, MatchFields),
			Fall = fun (Event) ->
					case element(4, Event) of
						#{"eventId" := _} = FilteredHead
								when map_size(FilteredHead) == 1 ->
							case element(5, Event) of
								#{"eventSeverity" := "MINOR"} = FilteredFields
										when map_size(FilteredFields) == 1 ->
									true;
								#{} ->
									false
							end;
						#{} ->
							false
					end
			end,
			true = length(Events) > 0,
			true = lists:all(Fall, Events),
			length(Events);
		_OtpRelease ->
			{skip, "requires OTP 21 or later"}
	end.

password_to_key_md5() ->
	[{userdata, [{doc, "Generate a localized key using MD5 (RFC3414 A.3.1)"}]}].

password_to_key_md5(_Config) ->
	EngineID = [16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#02],
	Password = "maplesyrup",
	{Elapsed, <<16#52, 16#6f, 16#5e, 16#ed, 16#9f, 16#cc, 16#e2, 16#6f,
			16#89, 16#64, 16#c2, 16#93, 16#07, 16#87, 16#d8, 16#2b>>} =
			timer:tc(snmp_collector_usm, password_to_key_md5, [Password, EngineID]),
	Elapsed.

password_to_key_sha() ->
	[{userdata, [{doc, "Generate a localized key using SHA (RFC3414 A.3.2)"}]}].

password_to_key_sha(_Config) ->
	EngineID = [16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#02],
	Password = "maplesyrup",
	{Elapsed, <<16#66, 16#95, 16#fe, 16#bc, 16#92, 16#88, 16#e3, 16#62,
			16#82, 16#23, 16#5f, 16#c7, 16#15, 16#1f, 16#12, 16#84, 16#97, 16#b3, 16#8f, 16#3f>>} =
			timer:tc(snmp_collector_usm, password_to_key_sha, [Password, EngineID]),
	Elapsed.

%%---------------------------------------------------------------------
%%  Internal functions
%%---------------------------------------------------------------------

get_params() ->
	{_, _, Info} = lists:keyfind(httpd, 1, inets:services_info()),
	{_, Port} = lists:keyfind(port, 1, Info),
	{_, Address} = lists:keyfind(bind_address, 1, Info),
	{ok, EnvObj} = application:get_env(inets, services),
	{httpd, HttpdObj} = lists:keyfind(httpd, 1, EnvObj),
	{directory, {Directory, AuthObj}} = lists:keyfind(directory, 1, HttpdObj),
	case lists:keyfind(require_group, 1, AuthObj) of
		{require_group, [Group | _T]} ->
			{Port, Address, Directory, Group};
		false ->
			exit(not_found)
	end.

%% @hidden
auth_header() ->
	{"authorization", basic_auth()}.

%% @hidden
basic_auth() ->
	RestUser = ct:get_config(rest_user),
	RestPass = ct:get_config(rest_pass),
	EncodeKey = base64:encode_to_string(string:concat(RestUser ++ ":", RestPass)),
	"Basic " ++ EncodeKey.

%% @hidden
string(N) ->
	Charset = lists:seq($0, $9) ++ lists:seq($a, $z),
	CharsetLen = length(Charset),
	string(Charset, CharsetLen, N, []).
%% @hidden
string(_Charset, _CharsetLen, 0, Acc) ->
	Acc;
string(Charset, CharsetLen, N, Acc) ->
	string(Charset, CharsetLen, N - 1,
			[lists:nth(rand:uniform(CharsetLen), Charset) | Acc]).

