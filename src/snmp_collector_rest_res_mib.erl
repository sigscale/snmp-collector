%%% snmp_collector_rest_res_mib.erl
%%% vim: ts=3
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
%%%
-module(snmp_collector_rest_res_mib).
-copyright('Copyright (c) 2018 SigScale Global Inc.').

-export([content_types_accepted/0, content_types_provided/0, get_params/0,
		get_mibs/1, get_mib/2]).

-include("snmp_collector.hrl").
-include_lib("snmp/include/snmp_types.hrl").

%% support deprecated_time_unit()
-define(MILLISECOND, milli_seconds).
%-define(MILLISECOND, millisecond).

-spec content_types_accepted() -> ContentTypes
	when
		ContentTypes :: list().
%% @doc Provides list of resource representations accepted.
content_types_accepted() ->
	["application/json", "application/json-patch+json"].

-spec content_types_provided() -> ContentTypes
	when
		ContentTypes :: list().
%% @doc Provides list of resource representations available.
content_types_provided() ->
	["application/json"].

-spec get_mib(ID, Query) -> Result
	when
		ID :: string(),
		Query :: term(),
		Result :: {ok, Headers :: [tuple()], Body :: iolist()}
				| {error, ErrorCode :: integer()}.
%% @doc Body producing function for `GET snmp/v1/mibs/{id}'
%% requests.
get_mib(ID, _Query) ->
	{ok, Dir} = application:get_env(snmp_collector, mib_dir),
	case read_mib(Dir, ID) of
		{ok, Name, Mes, Traps} ->
			Map = create_map(Name, Mes, Traps),
			Href = "snmp/v1/mibs/{id}",
			Headers = [{location, Href},
				{content_type, "application/json"}],
			Body = zj:encode(Map),
			{ok, Headers, Body};
		{error, Reason} ->
			{error, Reason}
	end.
	
-spec get_mibs(Query) -> Result
	when
		Query :: string(),
		Result :: {ok, Headers :: [tuple()], Body :: iolist()}
				| {error, ErrorCode :: integer()}.
%% @doc Body producing function for `GET snmp/v1/mibs/'
%% requests.
get_mibs(_Query) ->
	{ok, Dir} = application:get_env(snmp_collector, mib_dir),
	{ok, Files} = file:list_dir(Dir),
	MibRecords = read_mibs(Dir, Files, []),
	Maps = create_maps(MibRecords, []),
	Href = "snmp/v1/mibs",
	Headers = [{location, Href},
			{content_type, "application/json"}],
	Body = zj:encode(Maps),
	{ok, Headers, Body}.

-spec get_params() -> Result
	when
		Result :: {Port, Address, Directory, Group},
		Port :: integer(),
		Address :: string(),
		Directory :: string(),
		Group :: string().
%% @doc Get {@link //inets/httpd. httpd} configuration parameters.
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

%%----------------------------------------------------------------------
%%  internal functions
%%----------------------------------------------------------------------

-spec mes(Mes, Acc) -> Result
%% @doc Check all the Mes.
%% @private
   when
      Mes :: [#me{}],
      Acc :: [],
      Result :: [map()].
mes([H | T], Acc) ->
   Me = me(H),
   mes(T, [Me | Acc]);
mes([], Acc) ->
   NewAcc = lists:reverse(Acc),
   NewAcc.

-spec notifications(Notifications, Acc) -> Result
	when
		Notifications :: [#me{}],
		Acc :: [],
		Result :: [map()].
notifications([H | T], Acc) ->
	Me = notification(H),
	notifications(T, [Me | Acc]);
notifications([], Acc) ->
	NewAcc = lists:reverse(Acc),
	NewAcc.

-spec oidobjects(OidObjects, Acc) -> Result
	when
		OidObjects:: [{OID, Asn1Type}],
		OID :: list(),
		Asn1Type :: #asn1_type{},
		Acc :: [],
		Result :: [map()].
oidobjects([{OID, Asn1Type} | T], Acc) ->
	Map = #{"name" => oid_to_name(OID),
			"type" => Asn1Type#asn1_type.aliasname},
	oidobjects(T, [Map | Acc]);
oidobjects([], Acc) ->
	NewAcc = lists:reverse(Acc),
	NewAcc.

-spec me(Me) -> Me
	when
		Me :: #me{} | map().
%% @doc CODEC for me record from MIB.
%% @private
me(#me{} = Me) ->
	me(record_info(fields, me), Me, #{}).
%% @hidden
me([oid | T], #me{oid = OID} = M, Acc) when is_list(OID) ->
	me(T, M, maps:put("oid", lists:flatten(io_lib:write(OID)), Acc));
me([aliasname | T], #me{aliasname = AliasName} = M, Acc)
		when is_atom(AliasName) ->
	me(T, M, maps:put("aliasname", AliasName ,Acc));
me([entrytype | T], #me{entrytype = EntryType} = M, Acc)
		when is_atom(EntryType) ->
	me(T, M, maps:put("entrytype", EntryType, Acc));
me([asn1_type | T], #me{asn1_type = {asn1_type, Value, _, _, _, _, _,
		_, _}} = M, Acc) when is_atom(Value) ->
	me(T, M, maps:put("asn1_type", Value, Acc));
me([imported | T], #me{imported = Imported} = M, Acc)
		when is_boolean(Imported) ->
	me(T, M, maps:put("imported", Imported, Acc));
me([access | T], #me{access = Access} = M, Acc)
		when Access /= undefined ->
	me(T, M, maps:put("access", Access, Acc));
me([description | T], #me{description = Description} = M, Acc)
		when Description =/= undefined ->
	me(T, M, maps:put("description", Description, Acc));
me([_H | T], M, Acc) ->
	me(T, M, Acc);
me([], _M, Acc) ->
	Acc.

-spec notification(Notification) -> Notification
	when
		Notification :: #notification{} | map().
%% @doc CODEC for notificaiton record from MIB.
notification(#notification{} = Notification) ->
	notification(record_info(fields, notification), Notification, #{}).
%% @hidden
notification([oid | T], #notification{oid = OID} = N, Acc) when is_list(OID) ->
	notification(T, N, maps:put("oid", lists:flatten(io_lib:write(OID)), Acc));
notification([trapname | T], #notification{trapname = TrapName} = N, Acc)
		when is_atom(trapname) ->
	notification(T, N, maps:put("trapname", TrapName, Acc));
notification([oidobjects | T], #notification{oidobjects = OidObjects} = N, Acc)
		when is_list(OidObjects) ->
	notification(T, N, maps:put("objects", oidobjects(OidObjects, []), Acc));
notification([_H | T], N, Acc) ->
	notification(T, N, Acc);
notification([], _N, Acc) ->
	Acc.

-spec create_map(Name, Mes, Traps) -> Result
	when
		Name :: string(),
		Mes :: [#me{}],
		Traps :: [#notification{}],
		Result :: map().
%% @doc Create a map with the MIB Name and Mes.
%% @private
create_map(Name, Mes, Traps) ->
	#{"id" => Name,
		"href" => "snmp/v1/mibs/" ++ Name,
		"name" => Name,
		"mes" => mes(Mes, []),
		"traps" => notifications(Traps, [])}.

-spec create_maps(MibRecords, Acc) -> Result
	when
		MibRecords :: [{Name, Mes}],
		Name :: string(),
		Mes :: [map()],
		Acc :: [],
		Result :: [map()].
%% @doc Create maps with the MIB Names and Mes.
%% @private
create_maps([{Name, Mes, Traps} | T], Acc) ->
	Map = #{"id" => Name,
				"href" => "snmp/v1/mibs/" ++ Name,
				"name" => Name,
				"mes" => Mes,
				"traps" => Traps},
	create_maps(T, [Map | Acc]);
create_maps([], Acc) ->
	NewAcc = lists:reverse(Acc),
	NewAcc.

-spec read_mib(Dir, ID) -> Result
	when
		Dir :: string(),
		ID :: string(),
		Result :: {ok, Name, Mes, Traps} | {error | Reason},
		Name :: string(),
		Mes :: [#me{}],
		Traps :: [#notification{}],
		Reason :: term().
%% @doc Read the mib.
%% @private
read_mib(Dir, ID) ->
	Read = Dir ++ "/" ++ ID ++ ".bin",
	case snmp:read_mib(Read) of
		{ok, MibRecord} ->
			Name = MibRecord#mib.name,
			Mes = MibRecord#mib.mes,
			Traps = MibRecord#mib.traps,
			{ok, Name, Mes, Traps};
		{error, Reason} ->
			{error, Reason}
	end.

-spec read_mibs(Dir, Files, Acc) -> Result
	when
		Dir :: string(),
		Files :: [string()],
		Acc :: [],
		Result :: [{Name, [map()], [map()]}] | {error, Reason},
		Name :: string(),
		Reason :: term().
%% @doc Read all mib files in the directory.
%% @private
read_mibs(Dir, [H | T], Acc)
		when H =/= "Makefile" ->
	Read = Dir ++ "/" ++ H,
	case snmp:read_mib(Read) of
		{ok, MibRecord} ->
			Name = MibRecord#mib.name,
			Mes = MibRecord#mib.mes,
			Traps = MibRecord#mib.traps,
			read_mibs(Dir, T, [{Name, mes(Mes, []), 
					notifications(Traps, [])} | Acc]);
		{error, Reason} ->
			{error, Reason}
	end;
read_mibs(Dir, [_H | T], Acc) ->
	read_mibs(Dir, T, Acc);
read_mibs(_Dir, [], Acc) ->
	NewAcc = lists:reverse(Acc),
	NewAcc.

-spec oid_to_name(OID) -> Name
	when
		OID :: snmp:oid(),
		Name :: string().
%% @doc Get a name for an OID.
oid_to_name(OID) ->
	oid_to_name(OID, lists:reverse(OID), snmpm:oid_to_name(OID)).
%% @hidden
oid_to_name(_OID, [0], {ok, Name}) ->
	lists:flatten(io_lib:fwrite("~s", [Name]));
oid_to_name(OID, T, {ok, Name}) ->
	case lists:sublist(OID, length(T) + 1, length(OID)) of
		[0] ->
			lists:flatten(io_lib:fwrite("~s", [Name]));
		Rest ->
			lists:flatten(io_lib:fwrite("~s.~p", [Name, Rest]))
	end;
oid_to_name(OID, [_H | T], {error, _Reason}) ->
	oid_to_name(OID, T, snmpm:oid_to_name(lists:reverse(T)));
oid_to_name(OID, [], {error, _Reason}) ->
	lists:flatten(io_lib:fwrite("~p", [OID])).
