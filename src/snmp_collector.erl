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
		update_user/3, query_users/4, add_mib/1, get_mibs/0, add_snmp_user/3,
		remove_snmp_user/1]).

-include_lib("inets/include/httpd.hrl").
-include_lib("inets/include/mod_auth.hrl").
-include("snmp_collector.hrl").

%% support deprecated_time_unit()
-define(MILLISECOND, milli_seconds).
%-define(MILLISECOND, millisecond).
-define(MICROSECOND, micro_seconds).
%-define(MICROSECOND, microsecond).

%%----------------------------------------------------------------------
%%  The snmp_collector public API
%%----------------------------------------------------------------------

-spec add_snmp_user(UserName, PrivPass, AuthPass) -> Result
	when
		UserName :: string(),
		PrivPass :: string(),
		AuthPass :: string(),
		Result :: {ok, snmp_user_added} | {error, Reason},
		Reason :: user_exists | invalid_entry | term().
%% @doc Add a SNMP user.
add_snmp_user(UserName, PrivPass, AuthPass) ->
	LookUp = fun() ->
					mnesia:read(snmp_user, UserName, read)
	end,
	case mnesia:transaction(LookUp) of
		{atomic, [_]} ->
			{error, user_exists};
		{atomic, []} ->
			add_snmp_user1(UserName, PrivPass, AuthPass);
		{atomic, aborted} ->
			{error, invalid_entry}
	end.
%$ @hidden
add_snmp_user1(UserName, PrivPass, AuthPass) ->
	NewUser = #snmp_user{name = UserName,
			authPass = PrivPass, privPass = AuthPass},
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
%% @hidden Update user password and language
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

-spec get_mibs() -> Result
	when
		Result :: [MibName] | ok,
		MibName :: atom().
%% @doc Retrieve a list of all mibs loaded from the bin directory.
get_mibs() ->
	{ok, BinDir} = application:get_env(snmp_collector, bin_dir),
	case snmpm:which_mibs() of
		[] ->
			error_logger:info_report(["SNMP Collector",
					{error, bin_directory_empty}]);
		MibList ->
			get_mibs(MibList, BinDir, [])
	end.
get_mibs([{MibName, _} |  T] = MibList, BinDir, Acc) ->
	case lists:keyfind(BinDir ++ "/" ++  atom_to_list(MibName)
			++ ".bin", 2, MibList) of
		{MibName, _} ->
			get_mibs(T, BinDir, [MibName | Acc]);
		false ->
			get_mibs(T, BinDir, [MibName | Acc])
	end;
get_mibs([_H | T], BinDir, Acc) ->
   get_mibs(T, BinDir, Acc);
get_mibs([], _, Acc) ->
   Acc.
	
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

