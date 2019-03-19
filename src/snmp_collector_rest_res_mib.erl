%%% snmp_collector_rest_res_mib.erl
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
-module(snmp_collector_rest_res_mib).
-copyright('Copyright (c) 2016 - 2019 SigScale Global Inc.').

-export([content_types_accepted/0, content_types_provided/0,
		get_mibs/1, get_mib/2, post_mib/1, delete_mib/1]).

-include_lib("inets/include/mod_auth.hrl").
-include("snmp_collector.hrl").
-include_lib("snmp/include/snmp_types.hrl").

%% support deprecated_time_unit()
-define(MILLISECOND, milli_seconds).
%-define(MILLISECOND, millisecond).

%%----------------------------------------------------------------------
%%  The snmp_collector_rest_res)mib public API
%%----------------------------------------------------------------------

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
erlang:display({?MODULE, ?LINE}),
	{ok, Dir} = application:get_env(snmp_collector, bin_dir),
	{ok, Files} = file:list_dir(Dir),
	case read_mibs(Dir, Files, []) of
		{ok, MibRecords} ->
erlang:display({?MODULE, ?LINE}),
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
			MibName = MibDir ++ "/" ++
					snmp_collector_utils:get_name(binary_to_list(File)) ++ ".mib",
			case file:rename(TempName, MibName) of
				ok ->
					case snmpc:compile(MibName, [module_identity,
							{outdir, BinDir}, {group_check, false}]) of
						{ok, BinFileName} ->
							case snmpm:load_mib(BinFileName) of
								ok ->
									ID = snmp_collector_utils:get_name(binary_to_list(File)),
									case read_mib(BinDir, ID) of
										{ok, Name, Mes, Traps} ->
											Map = create_map(Name, Mes, Traps),
											Href = "snmp/v1/mibs/{id}",
											Headers = [{location, Href},
													{content_type, "application/json"}],
											Body = zj:encode(Map),
											{ok, Headers, Body};
										{error, _Reason} ->
											{error, 400}
									end;
								{error, _Reason} ->
									{error, 400}
							end;
						{error, _Reason} ->
							{error, 400}
					end;
				{error, _Reason}->
					{error, 400}
			end;
		{error, _Reason} ->
			{error, 400}
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

-spec records_to_maps(Records, Acc) -> Result
	when
		Records :: [#me{}] | [#notification{}] | [#trap{}],
		Acc :: [],
		Result :: [map()].
%% @doc Covert a records to maps using the relevent CODEC.
records_to_maps([#me{} = H | T], Acc) ->
	Me = me(H),
	records_to_maps(T, [Me | Acc]);
records_to_maps([#notification{} = H | T], Acc) ->
	Notification = notification(H),
	records_to_maps(T, [Notification | Acc]);
records_to_maps([#trap{} = H | T], Acc) ->
	Trap = trap(H),
	records_to_maps(T, [Trap | Acc]);
records_to_maps([], Acc) ->
	Acc.

-spec oidobjects(OidObjects, Acc) -> Result
	when
		OidObjects:: [{OID, Asn1Type}],
		OID :: list(),
		Asn1Type :: #asn1_type{},
		Acc :: list(),
		Result :: [map()].
%% @doc
oidobjects([{OID, Asn1Type} | T], Acc) ->
	Map = #{"name" => snmp_collector_utils:oid_to_name(OID),
			"type" => Asn1Type#asn1_type.aliasname},
	oidobjects(T, [Map | Acc]);
oidobjects([], Acc) ->
	lists:reverse(Acc).

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

-spec trap(Notification) -> Notification
	when
		Notification :: #trap{} | map().
%% @doc CODEC for trap record from MIB.
trap(#trap{} = Notification) ->
	trap(record_info(fields, trap), Notification, #{}).
%% @hidden
trap([enterpriseoid| T], #trap{enterpriseoid = OID} = N, Acc) when is_list(OID) ->
	trap(T, N, maps:put("oid", lists:flatten(io_lib:write(OID)), Acc));
trap([trapname | T], #trap{trapname = TrapName} = N, Acc)
		when is_atom(trapname) ->
	trap(T, N, maps:put("trapname", TrapName, Acc));
trap([oidobjects | T], #trap{oidobjects = OidObjects} = N, Acc)
		when is_list(OidObjects) ->
	trap(T, N, maps:put("objects", oidobjects(OidObjects, []), Acc));
trap([_H | T], N, Acc) ->
	trap(T, N, Acc);
trap([], _N, Acc) ->
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
		"mes" => records_to_maps(Mes, []),
		"traps" => records_to_maps(Traps, [])}.

-spec create_maps(MibRecords, Acc) -> Result
	when
		MibRecords :: [{Name, Mes}],
		Name :: string(),
		Mes :: [map()],
		Acc :: list(),
		Result :: [map()].
%% @doc Create maps with the MIB Names and Mes.
%% @private
create_maps([{{Name, Organization, LastUpdated, Description},
		Mes, Traps} | T], Acc) ->
	Map = #{"id" => Name,
		"organization" => Organization,
		"last_update" => LastUpdated,
		"description" => snmp_collector_utils:stringify(Description),
		"href" => "snmp/v1/mibs/" ++ Name,
		"name" => Name,
		"mes" => Mes,
		"traps" => Traps},
	create_maps(T, [Map | Acc]);
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
%% @doc Read a mib.
%% @private
read_mib(Dir, ID) ->
	Read = Dir ++ "/" ++ ID ++ ".bin",
	case snmp:read_mib(Read) of
		{ok, #mib{name = Name ,mes = Mes,
				traps = #notification{} = Traps}} ->
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
erlang:display({?MODULE, ?LINE, Read}),
	case snmp:read_mib(Read) of
		{ok, #mib{name = Name, module_identity = #module_identity{organization = Organization,
				last_updated = LastUpdated, description = Description},
				mes = Mes, traps = Traps}} ->
			Info = {Name, Organization, LastUpdated, Description},
			read_mibs(Dir, T, [{Info, records_to_maps(Mes, []), records_to_maps(Traps, [])} | Acc]);
		{ok, #mib{name = Name, module_identity = undefined, mes = Mes, traps = Traps} = MibRecord} ->
			read_mibs(Dir, T, [{Name, records_to_maps(Mes, []), records_to_maps(Traps, [])} | Acc]);
		{error, Reason} ->
			{error, Reason}
	end;
read_mibs(_Dir, [], Acc) ->
	{ok, lists:reverse(Acc)}.

