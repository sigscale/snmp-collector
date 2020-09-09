%%% snmp_collector.erl
%%% vim: ts=3
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% @copyright 2016 - 2019 SigScale Global Inc.
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
%%%
-module(snmp_collector).
-copyright('Copyright (c) 2016 - 2019 SigScale Global Inc.').

%% export the snmp_collector public API
-export([add_user/3, get_users/0, get_user/1, delete_user/1,
		update_user/3, query_users/4, add_mib/1, get_mibs/0, get_mib/1,
		query_mibs/3, add_snmp_user/3, remove_snmp_user/1, get_count/0,
		get_count/1, get_vendor_count/1, get_vendor_count/2, get_agent_count/2,
		get_agent_count/3, start_synch/1, add_agent/8, add_snmpm_user/3,
		register_usm_user/7, add_usm_user/7, remove_agent/2, update_agent/3,
		remove_snmpm_user/1, update_usm_user/4, unregister_usm_user/2]).

-include_lib("inets/include/httpd.hrl").
-include_lib("inets/include/mod_auth.hrl").
-include_lib("snmp/include/snmp_types.hrl").
-include("snmp_collector.hrl").

-define(CHUNKSIZE, 100).
%% support deprecated_time_unit()
-define(MILLISECOND, milli_seconds).
%-define(MILLISECOND, millisecond).
-define(MICROSECOND, micro_seconds).
%-define(MICROSECOND, microsecond).

%%----------------------------------------------------------------------
%%  The snmp_collector public API
%%----------------------------------------------------------------------

-spec add_snmp_user(UserName, AuthPass, PrivPass) -> Result
	when
		UserName :: string(),
		PrivPass :: string(),
		AuthPass :: string(),
		Result :: {ok, snmp_user_added} | {error, Reason},
		Reason :: user_exists | invalid_entry | term().
%% @doc Add a SNMP user.
add_snmp_user(UserName, AuthPass, PrivPass) ->
	LookUp = fun() ->
					mnesia:read(snmp_user, UserName, read)
	end,
	case mnesia:transaction(LookUp) of
		{atomic, [_]} ->
			{error, user_exists};
		{atomic, []} ->
			add_snmp_user1(UserName, AuthPass, PrivPass);
		{atomic, aborted} ->
			{error, invalid_entry}
	end.
%$ @hidden
add_snmp_user1(UserName, AuthPass, PrivPass) ->
	NewUser = #snmp_user{name = UserName,
			authPass = AuthPass, privPass = PrivPass},
	AddUser = fun() ->
					mnesia:write(snmp_user, NewUser, write)
	end,
	case mnesia:transaction(AddUser) of
		{atomic, ok} ->
			{ok, snmp_user_added};
		{atomic, aborted} ->
			{error, invalid_entry}
	end.

-spec remove_snmp_user(UserName) -> Result
	when
		UserName :: string(),
		Result :: {ok, snmp_user_removed} | {error, Reason},
		Reason :: user_does_not_exists | invalid_entry | term().
%% @doc Remove a SNMP user.
remove_snmp_user(UserName) ->
	LookUp = fun() ->
					mnesia:read(snmp_user, UserName, read)
	end,
	case mnesia:transaction(LookUp) of
		{atomic, [_]} ->
			Delete = fun() ->
							mnesia:delete({snmp_user, UserName})
			end,
			case mnesia:transaction(Delete) of
				{atomic, ok} ->
					{ok, snmp_user_removed};
				{atomic, aborted} ->
					{error, invalid_entry}
			end;
		{atomic, []} ->
			{error, user_does_not_exists};
		{atomic, aborted} ->
			{error, invalid_entry}
	end.

-spec add_user(Username, Password, Locale) -> Result
	when
		Username :: string(),
		Password :: string(),
		Locale :: string(),
		Result :: {ok, LastModified} | {error, Reason},
		LastModified :: {integer(), integer()},
		Reason :: user_exists | term().
%% @doc Add an HTTP user.
%%		HTTP Basic authentication (RFC7617) is required with
%%		`Username' and  `Password' used to construct the
%%		`Authorization' header in requests.
%%
%%		`Locale' is used to set the language for text in the web UI.
%%		For English use `"en"', for Spanish use `"es'"..
%%
add_user(Username, Password, Locale) when is_list(Username),
		is_list(Password), is_list(Locale) ->
	add_user1(Username, Password, Locale, get_params()).
%% @hidden
add_user1(Username, Password, Locale, {Port, Address, Dir, Group}) ->
	add_user2(Username, Password, Locale,
			Address, Port, Dir, Group, snmp_collector:get_user(Username));
add_user1(_, _, _, {error, Reason}) ->
	{error, Reason}.
%% @hidden
add_user2(Username, Password, Locale,
		Address, Port, Dir, Group, {error, no_such_user}) ->
	LM = {erlang:system_time(?MILLISECOND), erlang:unique_integer([positive])},
	NewUserData = [{last_modified, LM}, {locale, Locale}],
add_user3(Username, Address, Port, Dir, Group, LM,
	mod_auth:add_user(Username, Password, NewUserData, Address, Port, Dir));
add_user2(_, _, _, _, _, _, _, {error, Reason}) ->
	{error, Reason};
add_user2(_, _, _, _, _, _, _, {ok, _}) ->
	{error, user_exists}.
%% @hidden
add_user3(Username, Address, Port, Dir, Group, LM, true) ->
	add_user4(LM, mod_auth:add_group_member(Group, Username, Address, Port, Dir));
add_user3(_, _, _, _, _, _, {error, Reason}) ->
	{error, Reason}.
%% @hidden
add_user4(LM, true) ->
	{ok, LM};
add_user4(_, {error, Reason}) ->
	{error, Reason}.

-spec get_users() -> Result
	when
		Result :: {ok, Users} | {error, Reason},
		Users :: [Username],
		Username :: string(),
		Reason :: term().
%% @doc Get HTTP users.
%% @equiv  mod_auth:list_users(Address, Port, Dir)
get_users() ->
	get_users(get_params()).
%% @hidden
get_users({Port, Address, Dir, _}) ->
	mod_auth:list_users(Address, Port, Dir);
get_users({error, Reason}) ->
	{error, Reason}.

-spec get_user(Username) -> Result
	when
		Username :: string(),
		Result :: {ok, User} | {error, Reason},
		User :: #httpd_user{},
		Reason :: term().
%% @doc Get an HTTP user record.
%% @equiv mod_auth:get_user(Username, Address, Port, Dir)
get_user(Username) ->
	get_user(Username, get_params()).
%% @hidden
get_user(Username, {Port, Address, Dir, _}) ->
	mod_auth:get_user(Username, Address, Port, Dir);
get_user(_, {error, Reason}) ->
	{error, Reason}.

-spec delete_user(Username) -> Result
	when
		Username :: string(),
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Delete an existing HTTP user.
delete_user(Username) ->
	delete_user1(Username, get_params()).
%% @hidden
delete_user1(Username, {Port, Address, Dir, GroupName}) ->
	delete_user2(GroupName, Username, Address, Port, Dir,
			mod_auth:delete_user(Username, Address, Port, Dir));
delete_user1(_, {error, Reason}) ->
	{error, Reason}.
%% @hidden
delete_user2(GroupName, Username, Address, Port, Dir, true) ->
	delete_user3(mod_auth:delete_group_member(GroupName,
			Username, Address, Port, Dir));
delete_user2(_, _, _, _, _, {error, Reason}) ->
	{error, Reason}.
%% @hidden
delete_user3(true) ->
	ok;
delete_user3({error, Reason}) ->
	{error, Reason}.

-spec update_user(Username, Password, Language) -> Result
	when
		Username :: string(),
		Password :: string(),
		Language :: string(),
		Result :: {ok, LM} | {error, Reason},
		LM :: {integer(), integer()},
		Reason :: term().
%% @doc Update user password and language
update_user(Username, Password, Language) ->
	case get_user(Username) of
		{error, Reason} ->
			{error, Reason};
		{ok, #httpd_user{}} ->
			case delete_user(Username) of
				ok ->
					case add_user(Username, Password, Language) of
						{ok, LM} ->
							{ok, LM};
						{error, Reason} ->
							{error, Reason}
					end;
				{error, Reason} ->
					{error, Reason}
			end
	end.

-spec get_count() -> Result
	when
		Result :: non_neg_integer().
%% @doc Get current count of alarms on system.
get_count() ->
	MatchSpec = [{{'$1', '$2'}, [{'or', {'==', '$1', communicationsAlarm},
			{'==', '$1', processingErrorAlarm}, {'==', '$1', environmentalAlarm},
			{'==', '$1', qualityOfServiceAlarm}, {'==', '$1', equipmentAlarm},
			{'==', '$1', integrityViolation},  {'==', '$1', operationalViolation},
			{'==', '$1', physicalViolation},
			{'==', '$1', securityServiceOrMechanismViolation},
			{'==', '$1', timeDomainViolation}}], ['$2']}],
	lists:sum(ets:select(counters, MatchSpec)).

-spec get_count(Metric) -> Result
	when
		Metric :: eventType | perceivedResult,
		Result :: map().
%% @doc Get current count of alarms on system by `metric'.
get_count(Metric) ->
	MatchSpec = [{{'$1', '$2'}, [{'==', '$1', Metric}], ['$2']}],
	Sum = lists:sum(ets:select(counters, MatchSpec)),
	#{Metric => Sum}.

-spec get_vendor_count(Vendor) -> Result
	when
		Vendor :: huawei | nokia | zte | emc | nec | hpe | rfc3877,
		Result :: non_neg_integer().
%% @doc Get current count of alarms for `vendor'.
get_vendor_count(Vendor) ->
	MatchSpec = [{{{'$1', '$2'}, '$3'}, [{'==', '$1', Vendor}], ['$3']}],
	lists:sum(ets:select(counters, MatchSpec)).

-spec get_vendor_count(Vendor, Metric) -> Result
	when
		Vendor :: huawei | nokia | zte | emc | nec | hpe | rfc3877,
		Metric :: eventType | perceivedResult,
		Result :: map().
%% @doc Get current count of alarms for `vendor' by `metric'.
get_vendor_count(Vendor, Metric) ->
	MatchSpec = [{{{'$1', '$2'}, '$3'}, [{'==', '$1', Vendor}, {'==', '$2', Metric}], ['$3']}],
	Sum = lists:sum(ets:select(counters, MatchSpec)),
	#{Metric => Sum}.

-spec get_agent_count(Vendor, Agent) -> Result
	when
		Vendor :: huawei | nokia | zte | emc | nec | hpe | rfc3877,
		Agent :: string(),
		Result :: non_neg_integer().
%% @doc Get current count of alarms for `vendor' by `agent'
get_agent_count(Vendor, Agent) ->
	MatchSpec = [{{{Vendor, Agent, '_'}, '$4'}, [], ['$4']}],
	lists:sum(ets:select(counters, MatchSpec)).

-spec get_agent_count(Vendor, Agent, Metric) -> Result
	when
		Vendor :: huawei | nokia | zte | emc | nec | hpe | rfc3877,
		Agent :: string(),
		Metric :: eventType | perceivedResult,
		Result :: map().
%% @doc Get current count alarms for `vendor' by `agent' and `metric'
get_agent_count(Vendor, Agent, Metric) ->
	MatchSpec = [{{{Vendor, Agent, Metric}, '$4'}, [], ['$4']}],
	Sum = lists:sum(ets:select(counters, MatchSpec)),
	#{Metric => Sum}.

-spec get_mib(Name) -> Result
	when
		Name :: atom() | string(),
		Result :: {ok, Mib} | {error, Reason},
		Mib :: #mib{},
		Reason :: term().
%% @doc Get a mib.
%% @private
get_mib(Name) when is_atom(Name) ->
	get_mib(atom_to_list(Name));
get_mib(Name) when is_list(Name) ->
	{ok, BinDir} = application:get_env(snmp_collector, bin_dir),
	Path = BinDir ++ "/" ++ Name ++ ".bin",
	snmp:read_mib(Path).

-spec get_mibs() -> Result
	when
		Result :: [MibName],
		MibName :: atom().
%% @doc Retrieve a list of all mibs loaded from the bin directory.
get_mibs() ->
	{ok, BinDir} = application:get_env(snmp_collector, bin_dir),
	get_mibs(snmpm:which_mibs(), BinDir, []).
%% @hidden
get_mibs([{MibName, Path} |  T], BinDir, Acc) ->
	case lists:prefix(BinDir, Path) of
		true ->
			get_mibs(T, BinDir, [MibName | Acc]);
		false ->
			get_mibs(T, BinDir, Acc)
	end;
get_mibs([], _, Acc) ->
	lists:reverse(Acc).
	
-spec add_mib(Body) -> Result
	when
		Body :: list() | binary(),
		Result :: MibName :: string() | {error, Reason},
		Reason :: term().
%% @doc Add a new MIB file and load the new MIB to the manager.
add_mib(Body) ->
	{ok, MibDir} = application:get_env(snmp_collector, mib_dir),
	{ok, BinDir} = application:get_env(snmp_collector, bin_dir),
	TempName = MibDir ++ "/" ++ "." ++  snmp_collector_utils:generate_identity(5),
	case file:write_file(TempName, Body) of
		ok ->
			{ok, File} = file:read_file(TempName),
			MibId = snmp_collector_utils:get_name(binary_to_list(File)),
			MibName = MibDir ++ "/" ++ MibId ++ ".mib",
			case file:rename(TempName, MibName) of
				ok ->
					case snmpc:compile(MibName, [module_identity,
							{outdir, BinDir}, {group_check, false}]) of
						{ok, BinFileName} ->
							case snmpm:load_mib(BinFileName) of
								ok ->
									{ok, MibId};
								{error, Reason} ->
									{error, Reason}
							end;
						{error, Reason} ->
							{error, Reason}
					end;
				{error, Reason}->
					{error, Reason}
			end;
		{error, Reason} ->
			{error, Reason}
	end.

-spec query_mibs(Cont, Size, MatchSpec) -> Result
	when
		Cont :: start | [MibName],
		MibName :: atom(),
		Size :: pos_integer() | undefined,
		MatchSpec :: '_' | ets:match_spec(),
		Result :: {Cont2, [#mib{}]} | {error, Reason},
		Cont2 :: eof | [MibName],
		Reason :: term().
%% @doc Query the mibs
query_mibs(start, Size, MatchSpec) ->
	query_mibs(get_mibs(), Size, MatchSpec, []);
query_mibs(Cont, Size, MatchSpec) when is_list(Cont) ->
	query_mibs(Cont, Size, MatchSpec, []).
%% @hidden
query_mibs([_H | T], Size, _MatchSpec, Acc)
		when is_integer(Size), length(Acc) =:= Size->
	{T, lists:reverse(Acc)};
query_mibs([H | T], Size, MatchSpec, Acc) ->
	case get_mib(H) of
		{ok, Mib} when MatchSpec == '_' ->
			query_mibs(T, Size, MatchSpec, [Mib | Acc]);
		{ok, Mib} ->
			case ets:test_ms(Mib, MatchSpec) of
				{ok, false} ->
					query_mibs(T, Size, MatchSpec, Acc);
				{ok, FilteredMib} ->
					query_mibs(T, Size, MatchSpec, [FilteredMib | Acc]);
				{error, Reason} ->
					{error, Reason}
			end;
		{error, Reason} ->
			{error, Reason}
	end;
query_mibs([], _Size, _MatchSpec, Acc) ->
	{eof, lists:reverse(Acc)}.

-spec query_users(Cont, Size, MatchId, MatchLocale) -> Result
	when
		Cont :: start | any(),
		Size :: pos_integer() | undefined,
		MatchId :: Match,
		MatchLocale :: Match,
		Match :: {exact, string()} | {notexact, string()} | {like, string()},
		Result :: {Cont1, [#httpd_user{}]} | {error, Reason},
		Cont1 :: eof | any(),
		Reason :: term().
%% @doc Query the user table.
query_users(Cont, undefined, MatchId, MatchLocale) ->
	{ok, Size} = application:get_env(rest_page_size),
	query_users(Cont, Size, MatchId, MatchLocale);
query_users(start, Size, '_', MatchLocale) ->
	MatchSpec = [{'_', [], ['$_']}],
	query_users1(Size, MatchSpec, MatchLocale);
query_users(start, Size, {Op, String} = _MatchId, MatchLocale)
		when is_list(String), ((Op == exact) orelse (Op == like)) ->
	MatchSpec = case lists:last(String) of
		$% when Op == like ->
			Prefix = lists:droplast(String),
			Username = {Prefix ++ '_', '_', '_', '_'},
			MatchHead = #httpd_user{username = Username, _ = '_'},
			[{MatchHead, [], ['$_']}];
		_ ->
			Username = {String, '_', '_', '_'},
			MatchHead = #httpd_user{username = Username, _ = '_'},
			[{MatchHead, [], ['$_']}]
	end,
	query_users1(Size, MatchSpec, MatchLocale);
query_users(start, Size, {notexact, String} = _MatchId, MatchLocale)
		when is_list(String) ->
	Username = {'$1', '_', '_', '_'},
	MatchHead = #httpd_user{username = Username, _ = '_'},
	MatchSpec = [{MatchHead, [{'/=', '$1', String}], ['$_']}],
	query_users1(Size, MatchSpec, MatchLocale);
query_users(Cont, _Size, _MatchId, MatchLocale) when is_tuple(Cont) ->
	F = fun() ->
			mnesia:select(Cont)
	end,
	case mnesia:ets(F) of
		{Users, Cont1} ->
			query_users2(MatchLocale, Cont1, Users);
		'$end_of_table' ->
			{eof, []}
	end;
query_users(start, Size, MatchId, MatchLocale) when is_tuple(MatchId) ->
	MatchCondition = [match_condition('$1', MatchId)],
	Username = {'$1', '_', '_', '_'},
	MatchHead = #httpd_user{username = Username, _ = '_'},
	MatchSpec = [{MatchHead, MatchCondition, ['$_']}],
	query_users1(Size, MatchSpec, MatchLocale).
%% @hidden
query_users1(Size, MatchSpec, MatchLocale) ->
	F = fun() ->
			mnesia:select(httpd_user, MatchSpec, Size, read)
	end,
	case mnesia:ets(F) of
		{Users, Cont} ->
			query_users2(MatchLocale, Cont, Users);
		'$end_of_table' ->
			{eof, []}
	end.
%% @hidden
query_users2('_' = _MatchLocale, Cont, Users) ->
	{Cont, Users};
query_users2({exact, String} = _MatchLocale, Cont, Users)
		when is_list(String) ->
	F = fun(#httpd_user{user_data = UD}) ->
			case lists:keyfind(locale, 1, UD) of
				{_, String} ->
					true;
				_ ->
					false
			end
	end,
	{Cont, lists:filter(F, Users)};
query_users2({notexact, String} = _MatchLocale, Cont, Users)
		when is_list(String) ->
	F = fun(#httpd_user{user_data = UD}) ->
			case lists:keyfind(locale, 1, UD) of
				{_, String} ->
					false;
				_ ->
					true
			end
	end,
	{Cont, lists:filter(F, Users)};
query_users2({like, String} = _MatchLocale, Cont, Users)
		when is_list(String) ->
	F = case lists:last(String) of
		$% ->
			Prefix = lists:droplast(String),
			fun(#httpd_user{user_data = UD}) ->
					case lists:keyfind(locale, 1, UD) of
						{_, Locale} ->
							lists:prefix(Prefix, Locale);
						_ ->
							false
					end
			end;
		_ ->
			fun(#httpd_user{user_data = UD}) ->
					case lists:keyfind(locale, 1, UD) of
						{_, String} ->
							true;
						_ ->
							false
					end
			end
	end,
	{Cont, lists:filter(F, Users)}.

-spec start_synch(AgentName) -> ok
	when
		AgentName :: string().
%% @doc Start Alarm Synchronization.
start_synch(AgentName)
		when is_list(AgentName) ->
	case ets:match(snmpm_user_table, {user, AgentName,'$1','$2', '_'}) of
		[[Module, _]] ->
			Module:start_synchronization(AgentName);
		[] ->
			error_logger:info_report(["SNMP Manager Agent Not Found",
				{address, AgentName}])
	end.

-spec add_agent(UserId, TargetName, Community, Tdomain, Address, EngineId, Version, SecName) -> Result
	when
		UserId :: string(),
		TargetName :: string(),
		Community :: string(),
		Tdomain :: transportDomainUdpIpv4 | transportDomainUdpIpv6,
		Address :: {inet:ip_address(), inet:port_number()},
		EngineId :: string(),
		Version :: v1 | v2c | v3,
		SecName :: string(),
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Add and load new agent configuration.
add_agent(UserId, TargetName, Community, Tdomain, Address, EngineId, v1, SecName)
		when is_list(TargetName), is_atom(Tdomain), is_tuple(Address),
			is_list(EngineId), is_list(SecName) ->
	AgentConf = {UserId, TargetName, Community, Tdomain, Address, EngineId,
			infinity, 484, v1, v1, SecName, noAuthNoPriv},
	{ok,[{config,[{dir, Dir}, _]}, _, _]} = application:get_env(snmp, manager),
	ok = snmpm_conf:append_agents_config(Dir, [AgentConf]),
	add_agent1(UserId, TargetName, EngineId, Address);
add_agent(UserId, TargetName, Community, Tdomain, Address, EngineId, v2c, SecName)
		when is_list(TargetName), is_atom(Tdomain), is_tuple(Address),
			is_list(EngineId), is_list(SecName) ->
	AgentConf = {UserId, TargetName, Community, Tdomain, Address, EngineId,
			infinity, 484, v2, v2c, SecName, noAuthNoPriv},
	{ok,[{config,[{dir, Dir}, _]}, _, _]} = application:get_env(snmp, manager),
	ok = snmpm_conf:append_agents_config(Dir, [AgentConf]),
	add_agent1(UserId, TargetName, EngineId, Address);
add_agent(UserId, TargetName, _Community, Tdomain, Address, EngineId, v3, SecName)
		when is_list(TargetName), is_atom(Tdomain), is_tuple(Address),
			is_list(EngineId), is_list(SecName) ->
	AgentConf = {UserId, TargetName, "", Tdomain, Address, EngineId,
			infinity, 484, v3, usm, SecName, authPriv},
	{ok,[{config,[{dir, Dir}, _]}, _, _]} = application:get_env(snmp, manager),
	ok = snmpm_conf:append_agents_config(Dir, [AgentConf]),
	add_agent1(UserId, TargetName, EngineId, Address).
%% @hidden
add_agent1(UserId, TargetName, EngineId, Address) ->
	case snmpm:register_agent(UserId, TargetName,
			[{engine_id, EngineId}, {taddress, Address}]) of
		ok ->
			ok;
		{error,Reason} ->
			{error, Reason}
	end.

-spec remove_agent(UserId, TargetName) -> Result
	when
		UserId :: term(),
		TargetName :: string(),
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Remove an existing agent.
remove_agent(UserId, TargetName)
		when is_list(TargetName) ->
	case snmpm:unregister_agent(UserId, TargetName) of
		ok ->
			ok;
		{error, Reason} ->
			{error, Reason}
	end.

-spec update_agent(UserId, TargetName, Info) -> Result
	when
		UserId :: term(),
		TargetName :: string(),
		Info :: [{Attribute, AttributeValue}],
		Attribute :: engine_id | tadress | port | tdomain |
				community | timeout | max_message_size | version |
				sec_model | sec_name | sec_level,
		AttributeValue :: term(),
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Update an existing agent.
update_agent(UserId, TargetName, Info)
		when is_list(TargetName), is_list(Info) ->
	case snmpm:update_agent_info(UserId, TargetName, Info) of
		ok ->
			ok;
		{error, Reason} ->
			{error, Reason}
	end.

-spec add_snmpm_user(UserId, UserMod, UserData) -> Result
	when
		UserId :: string(),
		UserMod :: atom(),
		UserData :: term(),
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Add and load new snmpm user configuration.
add_snmpm_user(UserId, UserMod, UserData)
		when is_list(UserId), is_atom(UserMod) ->
	UserConf = [{UserId, UserMod, UserData, []}],
	{ok,[{config,[{dir, Dir}, _]}, _, _]} = application:get_env(snmp, manager),
	ok = snmpm_conf:append_users_config(Dir, UserConf),
	case snmpm:register_user(UserId, UserMod, UserData) of
		ok ->
			ok;
		{error, Reason} ->
			{error, Reason}
	end.

-spec remove_snmpm_user(UserId) -> Result
	when
		UserId :: term(),
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Remove snmpm user configuration.
remove_snmpm_user(UserId)
		when undefined =/= UserId ->
	case snmpm:unregister_user(UserId) of
		ok ->
			ok;
		{error, Reason} ->
			{error, Reason}
	end.

-spec add_usm_user(EngineId, UserName, SecName, AuthProtocol, PrivProtocol, AuthPass, PrivPass) -> Result
	when
		EngineId :: list(),
		UserName :: list(),
		SecName :: list(),
		AuthProtocol :: usmNoAuthProtocol | usmHMACMD5AuthProtocol | usmHMACSHAAuthProtocol,
		PrivProtocol :: usmNoPrivProtocol | usmDESPrivProtocol | usmAesCfb128Protocol,
		AuthPass :: list(),
		PrivPass :: list(),
		Result :: {usm_user_added, AuthProtocol, PrivProtocol} | {error, Reason},
		Reason :: term().
%% @doc Add a new usm user to the snmp_usm table.
%% {EngineId, UserName, SecName, AuthP, AuthKey, PrivP, PrivKey}.
add_usm_user(EngineId, UserName, SecName, usmNoAuthProtocol, usmNoPrivProtocol, _AuthPass, _PrivPass)
		when is_list(EngineId), is_list(UserName) ->
	Conf = [{EngineId, UserName, SecName, usmNoAuthProtocol, [], usmNoPrivProtocol, []}],
	add_usm_user1(UserName, Conf, usmNoAuthProtocol, usmNoPrivProtocol);
%% @hidden
add_usm_user(EngineId, UserName, SecName, usmHMACMD5AuthProtocol, usmNoPrivProtocol, AuthPass, _PrivPass)
		when is_list(EngineId), is_list(UserName) ->
	AuthKey = snmp_collector_utils:generate_key(usmHMACMD5AuthProtocol, AuthPass, EngineId),
	Conf = [{EngineId, UserName, SecName, usmHMACMD5AuthProtocol, AuthKey, usmNoPrivProtocol, []}],
	add_usm_user1(UserName, Conf, usmHMACMD5AuthProtocol, usmNoPrivProtocol);
%% @hidden
add_usm_user(EngineId, UserName, SecName, usmHMACMD5AuthProtocol, usmDESPrivProtocol, AuthPass, PrivPass)
		when is_list(EngineId), is_list(UserName) ->
	AuthKey = snmp_collector_utils:generate_key(usmHMACMD5AuthProtocol, AuthPass, EngineId),
	PrivKey = snmp_collector_utils:generate_key(usmHMACMD5AuthProtocol, PrivPass, EngineId),
	Conf = [{EngineId, UserName, SecName, usmHMACMD5AuthProtocol, AuthKey, usmDESPrivProtocol, PrivKey}],
	add_usm_user1(UserName, Conf, usmHMACMD5AuthProtocol, usmDESPrivProtocol);
%% @hidden
add_usm_user(EngineId, UserName, SecName, usmHMACMD5AuthProtocol, usmAesCfb128Protocol, AuthPass, PrivPass)
		when is_list(EngineId), is_list(UserName) ->
	AuthKey = snmp_collector_utils:generate_key(usmHMACMD5AuthProtocol, AuthPass, EngineId),
	PrivKey = snmp_collector_utils:generate_key(usmHMACMD5AuthProtocol, PrivPass, EngineId),
	Conf = [{EngineId, UserName, SecName, usmHMACMD5AuthProtocol, AuthKey, usmAesCfb128Protocol, PrivKey}],
	add_usm_user1(UserName, Conf, usmHMACMD5AuthProtocol, usmAesCfb128Protocol);
%% @hidden
add_usm_user(EngineId, UserName, SecName, usmHMACSHAAuthProtocol, usmNoPrivProtocol, AuthPass, _PrivPass)
		when is_list(EngineId), is_list(UserName) ->
	AuthKey = snmp_collector_utils:generate_key(usmHMACSHAAuthProtocol, AuthPass, EngineId),
	Conf = [{EngineId, UserName, SecName, usmHMACSHAAuthProtocol, AuthKey, usmNoPrivProtocol, []}],
	add_usm_user1(UserName, Conf, usmHMACSHAAuthProtocol, usmNoPrivProtocol);
%% @hidden
add_usm_user(EngineId, UserName, SecName, usmHMACSHAAuthProtocol, usmDESPrivProtocol, AuthPass, PrivPass)
		when is_list(EngineId), is_list(UserName) ->
	AuthKey = snmp_collector_utils:generate_key(usmHMACSHAAuthProtocol, AuthPass, EngineId),
	PrivKey = lists:sublist(snmp_collector_utils:generate_key(usmHMACSHAAuthProtocol, PrivPass, EngineId), 16),
	Conf = [{EngineId, UserName, SecName, usmHMACSHAAuthProtocol, AuthKey, usmDESPrivProtocol, PrivKey}],
	add_usm_user1(UserName, Conf, usmHMACSHAAuthProtocol, usmDESPrivProtocol);
%% @hidden
add_usm_user(EngineId, UserName, SecName, usmHMACSHAAuthProtocol, usmAesCfb128Protocol, AuthPass, PrivPass)
		when is_list(EngineId), is_list(UserName) ->
	AuthKey = snmp_collector_utils:generate_key(usmHMACSHAAuthProtocol, AuthPass, EngineId),
	PrivKey = lists:sublist(snmp_collector_utils:generate_key(usmHMACSHAAuthProtocol, PrivPass, EngineId), 16),
	Conf = [{EngineId, UserName, SecName, usmHMACSHAAuthProtocol, AuthKey, usmAesCfb128Protocol, PrivKey}],
	add_usm_user1(UserName, Conf, usmHMACSHAAuthProtocol, usmAesCfb128Protocol).
%% @hidden
add_usm_user1(UserName, Conf, AuthProtocol, PrivProtocol)
		when is_list(UserName) ->
	{ok,[{config,[{dir, Dir}, _]}, _, _]} = application:get_env(snmp, manager),
	case snmpm_conf:append_usm_config(Dir, Conf) of
		ok ->
			{usm_user_added, AuthProtocol, PrivProtocol};
		{error, Reason} ->
			{error, Reason}
	end.

-spec register_usm_user(EngineId, UserName, SecName, AuthProtocol, PrivProtocol, AuthPass, PrivPass) -> Result
	when
		EngineId :: list(),
		UserName :: list(),
		SecName :: list(),
		AuthProtocol :: usmNoAuthProtocol | usmHMACMD5AuthProtocol | usmHMACSHAAuthProtocol,
		PrivProtocol :: usmNoPrivProtocol | usmDESPrivProtocol | usmAesCfb128Protocol,
		AuthPass :: list(),
		PrivPass :: list(),
		Result :: {usm_user_added, AuthProtocol, PrivProtocol} | {error, Reason},
		Reason :: term().
%% @doc Add a new usm user to the snmp_usm table.
%% {EngineId, UserName, SecName, AuthP, AuthKey, PrivP, PrivKey}.
register_usm_user(EngineId, UserName, SecName, usmNoAuthProtocol, usmNoPrivProtocol, _AuthPass, _PrivPass)
		when is_list(EngineId), is_list(UserName) ->
	Conf = [{sec_name, SecName}, {auth, usmNoAuthProtocol}, {priv, usmNoPrivProtocol}],
	register_usm_user1(EngineId, UserName, Conf, usmNoAuthProtocol, usmNoPrivProtocol);
%% @hidden
register_usm_user(EngineId, UserName, SecName, usmHMACMD5AuthProtocol, usmNoPrivProtocol, AuthPass, _PrivPass)
		when is_list(EngineId), is_list(UserName) ->
	AuthKey = snmp_collector_utils:generate_key(usmHMACMD5AuthProtocol, AuthPass, EngineId),
	Conf = [{sec_name, SecName}, {auth, usmHMACMD5AuthProtocol}, {priv, usmNoPrivProtocol},
			{auth_key, AuthKey}],
	register_usm_user1(EngineId, UserName, Conf, usmHMACMD5AuthProtocol, usmNoPrivProtocol);
%% @hidden
register_usm_user(EngineId, UserName, SecName, usmHMACMD5AuthProtocol, usmDESPrivProtocol, AuthPass, PrivPass)
		when is_list(EngineId), is_list(UserName) ->
	AuthKey = snmp_collector_utils:generate_key(usmHMACMD5AuthProtocol, AuthPass, EngineId),
	PrivKey = snmp_collector_utils:generate_key(usmHMACMD5AuthProtocol, PrivPass, EngineId),
	Conf = [{sec_name, SecName}, {auth, usmHMACMD5AuthProtocol}, {auth_key, AuthKey},
			{priv, usmDESPrivProtocol}, {priv_key, PrivKey}],
	register_usm_user1(EngineId, UserName, Conf, usmHMACMD5AuthProtocol, usmDESPrivProtocol);
%% @hidden
register_usm_user(EngineId, UserName, SecName, usmHMACMD5AuthProtocol, usmAesCfb128Protocol, AuthPass, PrivPass)
		when is_list(EngineId), is_list(UserName) ->
	AuthKey = snmp_collector_utils:generate_key(usmHMACMD5AuthProtocol, AuthPass, EngineId),
	PrivKey = snmp_collector_utils:generate_key(usmHMACMD5AuthProtocol, PrivPass, EngineId),
	Conf = [{sec_name, SecName}, {auth, usmHMACMD5AuthProtocol}, {auth_key, AuthKey},
			{priv, usmAesCfb128Protocol}, {priv_key, PrivKey}],
	register_usm_user1(EngineId, UserName, Conf, usmHMACMD5AuthProtocol, usmAesCfb128Protocol);
%% @hidden
register_usm_user(EngineId, UserName, SecName, usmHMACSHAAuthProtocol, usmNoPrivProtocol, AuthPass, _PrivPass)
		when is_list(EngineId), is_list(UserName) ->
	AuthKey = snmp_collector_utils:generate_key(usmHMACSHAAuthProtocol, AuthPass, EngineId),
	Conf = [{sec_name, SecName}, {auth, usmHMACSHAAuthProtocol}, {auth_key, AuthKey},
			{priv, usmNoPrivProtocol}],
	register_usm_user1(EngineId, UserName, Conf, usmHMACSHAAuthProtocol, usmNoPrivProtocol);
%% @hidden
register_usm_user(EngineId, UserName, SecName, usmHMACSHAAuthProtocol, usmDESPrivProtocol, AuthPass, PrivPass)
		when is_list(EngineId), is_list(UserName) ->
	AuthKey = snmp_collector_utils:generate_key(usmHMACSHAAuthProtocol, AuthPass, EngineId),
	PrivKey = lists:sublist(snmp_collector_utils:generate_key(usmHMACSHAAuthProtocol, PrivPass, EngineId), 16),
	Conf = [{sec_name, SecName}, {auth, usmHMACSHAAuthProtocol}, {auth_key, AuthKey},
			{priv, usmDESPrivProtocol}, {priv_key, PrivKey}],
	register_usm_user1(EngineId, UserName, Conf, usmHMACSHAAuthProtocol, usmDESPrivProtocol);
%% @hidden
register_usm_user(EngineId, UserName, SecName, usmHMACSHAAuthProtocol, usmAesCfb128Protocol, AuthPass, PrivPass)
		when is_list(EngineId), is_list(UserName) ->
	AuthKey = snmp_collector_utils:generate_key(usmHMACSHAAuthProtocol, AuthPass, EngineId),
	PrivKey = lists:sublist(snmp_collector_utils:generate_key(usmHMACSHAAuthProtocol, PrivPass, EngineId), 16),
	Conf = [{sec_name, SecName}, {auth, usmHMACSHAAuthProtocol}, {auth_key, AuthKey},
			{priv, usmAesCfb128Protocol}, {priv_key, PrivKey}],
	register_usm_user1(EngineId, UserName, Conf, usmHMACSHAAuthProtocol, usmAesCfb128Protocol).
%% @hidden
register_usm_user1(EngineId, UserName, Conf, AuthProtocol, PrivProtocol)
		when is_list(EngineId), is_list(UserName) ->
	case snmpm:register_usm_user(EngineId, UserName, Conf) of
		ok ->
			{usm_user_added, AuthProtocol, PrivProtocol};
		{error, Reason} ->
			{error, Reason}
	end.

-spec update_usm_user(EngineId, UserName, Attribute, AttributeValue) -> Result
   when
      EngineId :: list(),
      UserName :: term(),
      Attribute :: engine_id | tadress | port | tdomain |
            community | timeout | max_message_size | version |
            sec_model | sec_name | sec_level,
      AttributeValue :: term(),
      Result :: ok | {error, Reason},
      Reason :: term().
%% @doc Update an existing usm user in the snmp_usm table.
update_usm_user(EngineId, UserName, Attribute, AttributeValue)
		when is_list(EngineId) ->
	case snmpm:update_usm_user_info(EngineId, UserName,
			Attribute, AttributeValue) of
		ok ->
			ok;
		{error, Reason} ->
			{error, Reason}
	end.

-spec unregister_usm_user(EngineId, UserId) -> Result
	when
		EngineId :: list(),
		UserId :: term(),
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Unregister an usm user from the snmp_usm table.
unregister_usm_user(EngineId, UserId)
		when is_list(EngineId), undefined =/= UserId ->
	case snmpm:unregister_usm_user(EngineId, UserId) of
		ok ->
			ok;
		{error, Reason} ->
			{error, Reason}
	end.


%%----------------------------------------------------------------------
%%  internal functions
%%----------------------------------------------------------------------

-spec get_params() -> Result
	when
		Result :: {Port :: integer(), Address :: string(),
				Directory :: string(), Group :: string()}
				| {error, Reason :: term()}.
%% @doc Returns configurations details for currently running
%% {@link //inets. httpd} service.
%% @hidden
get_params() ->
	get_params(inets:services_info()).
%% @hidden
get_params({error, Reason}) ->
	{error, Reason};
get_params(ServicesInfo) ->
	get_params1(lists:keyfind(httpd, 1, ServicesInfo)).
%% @hidden
get_params1({httpd, _, HttpdInfo}) ->
	{_, Address} = lists:keyfind(bind_address, 1, HttpdInfo),
	{_, Port} = lists:keyfind(port, 1, HttpdInfo),
	get_params2(Address, Port, application:get_env(inets, services));
get_params1(false) ->
	{error, httpd_not_started}.
%% @hidden
get_params2(Address, Port, {ok, Services}) ->
	get_params3(Address, Port, lists:keyfind(httpd, 1, Services));
get_params2(_, _, undefined) ->
	{error, inet_services_undefined}.
%% @hidden
get_params3(Address, Port, {httpd, Httpd}) ->
	get_params4(Address, Port, lists:keyfind(directory, 1, Httpd));
get_params3(_, _, false) ->
	{error, httpd_service_undefined}.
%% @hidden
get_params4(Address, Port, {directory, {Directory, Auth}}) ->
	get_params5(Address, Port, Directory,
	lists:keyfind(require_group, 1, Auth));
get_params4(_, _, false) ->
	{error, httpd_directory_undefined}.
%% @hidden
get_params5(Address, Port, Directory, {require_group, [Group | _]}) ->
	{Port, Address, Directory, Group};
get_params5(_, _, _, false) ->
	{error, httpd_group_undefined}.

-spec match_condition(MatchVariable, Match) -> MatchCondition
	when
		MatchVariable :: atom(), % '$<number>'
		Match :: {exact, term()} | {notexact, term()} | {lt, term()}
				| {lte, term()} | {gt, term()} | {gte, term()},
		MatchCondition :: {GuardFunction, MatchVariable, Term},
		Term :: any(),
		GuardFunction :: '=:=' | '=/=' | '<' | '=<' | '>' | '>='.
%% @doc Convert REST query patterns to Erlang match specification conditions.
%% @hidden
match_condition(Var, {exact, Term}) ->
	{'=:=', Var, Term};
match_condition(Var, {notexact, Term}) ->
	{'=/=', Var, Term};
match_condition(Var, {lt, Term}) ->
	{'<', Var, Term};
match_condition(Var, {lte, Term}) ->
	{'=<', Var, Term};
match_condition(Var, {gt, Term}) ->
	{'>', Var, Term};
match_condition(Var, {gte, Term}) ->
	{'>=', Var, Term}.

