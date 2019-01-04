%%% snmp_collector.erl
%%% vim: ts=3
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% @copyright 2016 - 2017 SigScale Global Inc.
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
-copyright('Copyright (c) 2016 - 2017 SigScale Global Inc.').

%% export the snmp_collector public API
-export([add_user/3, list_users/0, get_user/1, delete_user/1,
		update_user/3, add_mib/1, add_snmp_user/3]).

-include_lib("inets/include/httpd.hrl").
-include_lib("inets/include/mod_auth.hrl").
-include("../../snmp-collector/include/snmp_collector.hrl").

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
					mnesia:read(snmp_users, UserName, read)
	end,
	case mnesia:transaction(LookUp) of
		{atomic, [_]} ->
			{error, user_exists};
		{atomic, []} ->
			add_snmp_user1(UserName, PrivPass, AuthPass)
	end.
%$ @hidden
add_snmp_user1(UserName, PrivPass, AuthPass) ->
	NewUser = #snmp_users{name = UserName,
			authPass = PrivPass, privPass = AuthPass},
	AddUser = fun() ->
					mnesia:write(snmp_users, NewUser, write)
	end,
	case mnesia:transaction(AddUser) of
		{atomic, ok} ->
			{ok, snmp_user_added};
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

-spec list_users() -> Result
	when
		Result :: {ok, Users} | {error, Reason},
		Users :: [Username],
		Username :: string(),
		Reason :: term().
%% @doc List HTTP users.
%% @equiv  mod_auth:list_users(Address, Port, Dir)
list_users() ->
	list_users1(get_params()).
%% @hidden
list_users1({Port, Address, Dir, _}) ->
	mod_auth:list_users(Address, Port, Dir);
list_users1({error, Reason}) ->
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

%
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

