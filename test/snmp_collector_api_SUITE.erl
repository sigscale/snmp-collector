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
	{timetrap, {minutes, 1}}].

-spec init_per_suite(Config :: [tuple()]) -> Config :: [tuple()].
%% Initiation before the whole suite.
%%
init_per_suite(Config) ->
	ok = application:load(snmp_collector),
	PrivDir = ?config(priv_dir, Config),
	DbDir = PrivDir ++ "/db",
	ok = file:make_dir(DbDir),
	ok = application:set_env(mnesia, dir, DbDir),
	LogDir = PrivDir ++ "/log",
	ok = file:make_dir(LogDir),
	ok = application:set_env(snmp_collector, queue_dir, LogDir),
	MibDir = PrivDir ++ "/mib",
	ok = file:make_dir(MibDir),
	ok = application:set_env(snmp_collector, mib_dir, MibDir),
	MibBinDir = MibDir ++ "/bin",
	ok = file:make_dir(MibBinDir),
	ok = application:set_env(snmp_collector, bin_dir, MibBinDir),
	ok = snmp_collector_test_lib:initialize_db(),
	ok =  ct_snmp:start(Config, snmp_mgr, snmp_app),
	ok = snmp_collector_test_lib:start(),
	Config.

-spec end_per_suite(Config :: [tuple()]) -> any().
%% Cleanup after the whole suite.
%%
end_per_suite(_Config) ->
	ok = snmp_collector_test_lib:stop().

-spec init_per_testcase(TestCase :: atom(), Config :: [tuple()]) -> Config :: [tuple()].
%% Initiation before each test case.
%%
init_per_testcase(query_faults, Config) ->
	{ok, LogName} = application:get_env(snmp_collector, queue_name),
	LogInfo = disk_log:info(LogName),
	{_, {FileSize, _NumFiles}} = lists:keyfind(size, 1, LogInfo),
	TargetNames = [string(20) || lists:seq(1, 25)],
	Fdetails = fun Fdetails(0, Acc) ->
				Acc;
			Fdetails(N, Acc) ->
				Fdetails(N - 1, [{string(15), string(50)} | Acc])
	end,
	Fill = fun Fill(0) ->
				ok;
			Fill(N) ->
				TN = lists:nth(rand:uniform(length(TargetNames)), TargetNames),
				AlarmDetails = Fdetails(rand:uniform(12)),
				{CH, FF} = snmp_collector_utils:generate_maps(TN, AlarmDetails),
				ok = snmp_collector_utils:log_events(CH, FF),
				Fill(N - 1)
	end,
	EventSize = erlang:external_size(Fill(1)),
	NumItems = (FileSize div EventSize) * 5,
	ok = Fill(NumItems),
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
	[add_user, get_user, delete_user, get_mib, query_faults].

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
	
query_faults() ->
	[{userdata, [{doc, "Query event log for faults"}]}].

query_faults(_Config) ->
	{skip, unimplemented}.

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
string(Charset, CharsetLen, N, Acc) ->
	string(Charset, CharsetLen, N,
			[lists:seq(rand:uniform(CharsetLen), Charset) | Acc]).

