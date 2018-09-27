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

-export([content_types_accepted/0, content_types_provided/0,
		get_mibs/1, get_mib/2, post_mib/1, delete_mib/1]).

-include_lib("inets/include/mod_auth.hrl").
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
	["application/json", "application/json-patch+json", "text/plain"].

-spec content_types_provided() -> ContentTypes
	when
		ContentTypes :: list().
%% @doc Provides list of resource representations available.
content_types_provided() ->
	["application/json", "text/plain"].

-spec get_mib(ID, Query) -> Result
	when
		ID :: string(),
		Query :: term(),
		Result :: {ok, Headers :: [tuple()], Body :: iolist()}
				| {error, ErrorCode :: integer()}.
%% @doc Body producing function for `GET snmp/v1/mibs/{id}'
%% requests.
get_mib(ID, _Query) ->
	{ok, Dir} = application:get_env(snmp_collector, bin_dir),
	case read_mib(Dir, ID) of
		{ok, Name, Mes, Traps} ->
			Map = create_map(Name, Mes, Traps),
			Href = "snmp/v1/mibs/{id}",
			Headers = [{location, Href},
				{content_type, "application/json"}],
			Body = zj:encode(Map),
			{ok, Headers, Body};
		{error, _Reason} ->
			{error, 400}
	end.
	
-spec get_mibs(Query) -> Result
	when
		Query :: string(),
		Result :: {ok, Headers :: [tuple()], Body :: iolist()}
				| {error, ErrorCode :: integer()}.
%% @doc Body producing function for `GET snmp/v1/mibs/'
%% requests.
get_mibs(_Query) ->
	{ok, Dir} = application:get_env(snmp_collector, bin_dir),
	{ok, Files} = file:list_dir(Dir),
	case read_mibs(Dir, Files, []) of
		{ok, MibRecords} ->
			Maps = create_maps(MibRecords, []),
			Href = "snmp/v1/mibs",
			Headers = [{location, Href},
					{content_type, "application/json"}],
			Body = zj:encode(Maps),
			{ok, Headers, Body};
		{error, _Reason} ->
			{error, 400}
	end.

-spec post_mib(RequestBody) -> Result
	when
		RequestBody :: list(),
		Result :: {ok, Headers :: [tuple()], Body :: iolist()}
				| {error, ErrorCode :: integer()}.
%% @doc Respond to `POST /snmp/v1/mibs' and add a new `MIB'
%% resource.
post_mib(RequestBody) ->
	{ok, MibDir} = application:get_env(snmp_collector, mib_dir),
	{ok, BinDir} = application:get_env(snmp_collector, bin_dir),
	TempName = MibDir ++ "/" ++ "temp.mib",
	case file:write_file(TempName, RequestBody) of
		ok ->
			{ok, File} = file:read_file(TempName),
			MibName = MibDir ++ "/" ++ get_name(binary_to_list(File)) ++ ".mib",
			case file:rename(TempName, MibName) of
				ok ->
					case snmpc:compile(MibName, [module_identity,
							{outdir, BinDir}, {group_check, false}]) of
						{ok, BinFileName} ->
							snmpm:load_mib(BinFileName),
							ID = get_name(binary_to_list(File)),
							case read_mib(BinDir, ID) of
								{ok, Name, Mes, Traps} ->
									Map = create_map(Name, Mes, Traps),
									Href = "snmp/v1/mibs/{id}",
									Headers = [{location, Href},
											{content_type, "application/json"}],
									Body = zj:encode(Map),
									{ok, Headers, Body};
								{error, Reason} ->
									{error, Reason}
							end;
						{error, _Reason} ->
							{error, 400}
					end;
				{error, Reason}->
					{error, Reason}
			end;
		{error, Reason} ->
			{error, Reason}
	end.

-spec delete_mib(ID) -> Result
	when
		ID :: string(),
		Result :: {ok, Headers :: [tuple()], Body :: iolist()}
				| {error, ErrorCode :: integer()}.
%% @doc Respond to `DELETE /snmp/v1/mibs' and remove a `MIB'
%% resource.
delete_mib(ID) ->
	{ok, MibDir} = application:get_env(snmp_collector, mib_dir),
	{ok, BinDir} = application:get_env(snmp_collector, bin_dir),
	MibFile = MibDir ++ "/" ++ ID ++ ".mib",
	BinFile = BinDir ++ "/" ++ ID ++ ".bin",
	case snmpm:unload_mib(BinFile) of
		ok ->
			case file:delete(BinFile) of
				ok ->
					case file:delete(MibFile) of
						ok->
							{ok, [], []};
						{error,Reason} ->
							{error, Reason}
					end;
				{error, Reason} ->
					{error, Reason}
			end;
		{error, _Reason} ->
			{error, 400}
	end.

%%----------------------------------------------------------------------
%%  internal functions
%%----------------------------------------------------------------------

-spec mes(Mes, Acc) -> Result
%% @doc Check all the Mes.
%% @private
when
		Mes :: [#me{}],
		Acc :: list(),
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
		Acc :: list(),
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
		Acc :: list(),
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
create_map(Name, Mes, Traps)
		when Traps =/= [] ->
	#{"id" => Name,
		"href" => "snmp/v1/mibs/" ++ Name,
		"name" => Name,
		"mes" => mes(Mes, []),
		"traps" => notifications(Traps, [])};
create_map(Name, Mes, Traps)
		when Traps == [] ->
	#{"id" => Name,
		"href" => "snmp/v1/mibs/" ++ Name,
		"name" => Name,
		"mes" => mes(Mes, [])}.

-spec create_maps(MibRecords, Acc) -> Result
	when
		MibRecords :: [{Name, Mes}],
		Name :: string(),
		Mes :: [map()],
		Acc :: list(),
		Result :: [map()].
%% @doc Create maps with the MIB Names and Mes.
%% @private
create_maps([{Name, Mes, Traps} | T], Acc)
		when Traps =/= [] ->
	Map = #{"id" => Name,
				"href" => "snmp/v1/mibs/" ++ Name,
				"name" => Name,
				"mes" => Mes,
				"traps" => Traps},
	create_maps(T, [Map | Acc]);
create_maps([{Name, Mes, Traps} | T], Acc)
		when Traps == [] ->
	Map = #{"id" => Name,
				"href" => "snmp/v1/mibs/" ++ Name,
				"name" => Name,
				"mes" => Mes},
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
read_mibs(Dir, [H | T], Acc) ->
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
read_mibs(_Dir, [], Acc) ->
	NewAcc = lists:reverse(Acc),
	{ok, NewAcc}.

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

get_name([H | _] = Body) when H >= $A, H =< $Z ->
	get_name1(Body, []);
get_name([$ | T]) ->
	get_name(T);
get_name([$\t | T]) ->
	get_name(T);
get_name([$\r | T]) ->
	get_name(T);
get_name([$\n | T]) ->
	get_name(T);
get_name([$-, $- | T]) ->
	get_name(skip_to_eol(T)).

get_name1([H | T], Acc) when H >= $A, H =< $Z ->
 	get_name1(T, [H | Acc]);
get_name1([H | T], Acc) when H >= $a, H =< $z ->
	get_name1(T, [H | Acc]);
get_name1([H | T], Acc) when H >= $0, H =< $9 ->
	get_name1(T, [H | Acc]);
get_name1([$- | T], Acc) ->
	get_name1(T, [$- | Acc]);
get_name1([$  | T], Acc) ->
	get_name2(T, lists:reverse(Acc)).

get_name2([$  | T], Name) ->
	get_name2(T, Name);
get_name2([$\t | T], Name) ->
	get_name2(T, Name);
get_name2([$\r | T], Name) ->
	get_name2(T, Name);
get_name2([$\n | T], Name) ->
	get_name2(T, Name);
get_name2("DEFINITIONS " ++ _,  Name) ->
	Name.

skip_to_eol([$\n | T]) ->
	T;
skip_to_eol([_ | T]) ->
	skip_to_eol(T).
