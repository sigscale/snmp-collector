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
		get_mibs/3, get_mib/2, post_mib/1, delete_mib/1]).
-export([mib/1, module_identity/1, me/1]).

-include_lib("inets/include/mod_auth.hrl").
-include("snmp_collector.hrl").
-include_lib("snmp/include/snmp_types.hrl").

%% support deprecated_time_unit()
-define(MILLISECOND, milli_seconds).
%-define(MILLISECOND, millisecond).

%%----------------------------------------------------------------------
%%  The snmp_collector_rest_res_mib public API
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
	case snmp_collector:get_mib(ID) of
		{ok, Mib} ->
			Map = mib(Mib),
			Href = "snmp/v1/mibs/" ++ ID,
			Headers = [{location, Href},
				{content_type, "application/json"}],
			Body = zj:encode(Map),
			{ok, Headers, Body};
		{error, _Reason} ->
			{error, 404}
	end.
	
-spec get_mibs(Method, Query, Headers) -> Result
	when
		Method :: string(), % "GET" | "HEAD",
		Query :: [{Key :: string(), Value :: string()}],
		Headers :: [tuple()],
		Result :: {ok, Headers :: [tuple()], Body :: iolist()}
				| {error, ErrorCode :: integer()}.
%% @doc Body producing function for
%%    `GET|HEAD /snmp/v1/mibs'
%%    requests.
get_mibs(Method, Query, Headers) ->
	case lists:keytake("fields", 1, Query) of
		{value, {_, Filters}, NewQuery} ->
			get_mibs1(Method, NewQuery, Filters, Headers);
		false ->
			get_mibs1(Method, Query, [], Headers)
	end.
%% @hidden
get_mibs1(Method, Query, Filters, Headers) ->
	case {lists:keyfind("if-match", 1, Headers),
			lists:keyfind("if-range", 1, Headers),
			lists:keyfind("range", 1, Headers)} of
		{{"if-match", Etag}, false, {"range", Range}} ->
			case global:whereis_name(Etag) of
				undefined ->
					{error, 412};
				PageServer ->
					case snmp_collector_rest:range(Range) of
						{error, _} ->
							{error, 400};
						{ok, {Start, End}} ->
							query_page(PageServer, Etag, Query, Filters, Start, End)
					end
			end;
		{{"if-match", Etag}, false, false} ->
			case global:whereis_name(Etag) of
				undefined ->
					{error, 412};
				PageServer ->
					query_page(PageServer, Etag, Query, Filters, undefined, undefined)
			end;
		{false, {"if-range", Etag}, {"range", Range}} ->
			case global:whereis_name(Etag) of
				undefined ->
					case snmp_collector_rest:range(Range) of
						{error, _} ->
							{error, 400};
						{ok, {Start, End}} ->
							query_start(Method, Query, Filters, Start, End)
					end;
				PageServer ->
					case snmp_collector_rest:range(Range) of
						{error, _} ->
							{error, 400};
						{ok, {Start, End}} ->
							query_page(PageServer, Etag, Query, Filters, Start, End)
					end
			end;
		{{"if-match", _}, {"if-range", _}, _} ->
			{error, 400};
		{_, {"if-range", _}, false} ->
			{error, 400};
		{false, false, {"range", "items=1-" ++ _ = Range}} ->
			case snmp_collector_rest:range(Range) of
				{error, _} ->
					{error, 400};
				{ok, {Start, End}} ->
					query_start(Method, Query, Filters, Start, End)
			end;
		{false, false, {"range", _Range}} ->
			{error, 416};
		{false, false, false} ->
			query_start(Method, Query, Filters, undefined, undefined)
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
									case snmp_collector:get_mib(ID) of
										{ok, #mib{} = Mib} ->
											Map = mib(Mib),
											Href = "snmp/v1/mibs/" ++ ID,
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

%% @hidden
query_start(Method, Query, Filters, RangeStart, RangeEnd) ->
	try
		CountOnly = case Method of
			"GET" ->
				false;
			"HEAD" ->
				true
		end,
		FilterArgs = case lists:keyfind("filter", 1, Query) of
			{_, StringF} ->
				{ok, Tokens, _} = snmp_collector_rest_query_scanner:string(StringF),
				case snmp_collector_rest_query_parser:parse(Tokens) of
					{ok, [{array, [{complex, Filter}]}]} ->
						['_'] %% @todo Build MatchSpecs from Filters
				end;
			false ->
				['_']
		end,
		MFA = [snmp_collector, query_mibs, FilterArgs],
		case supervisor:start_child(snmp_collector_rest_pagination_sup, [MFA]) of
			{ok, PageServer, Etag} ->
				query_page(PageServer, Etag, Query, Filters, RangeStart, RangeEnd);
			{error, _Reason} ->
				{error, 500}
		end
	catch
		_ ->
			{error, 400}
	end.

%% @hidden
query_page(PageServer, Etag, _Query, _Filters, Start, End) ->
	case gen_server:call(PageServer, {Start, End}, infinity) of
		{error, Status} ->
			{error, Status};
		{undefined, ContentRange} ->
			Headers = [{content_type, "application/json"},
				{etag, Etag}, {accept_ranges, "items"},
				{content_range, ContentRange}],
			{ok, Headers, []};
		{Events, ContentRange} ->
			Json =  zj:encode(mib(Events)),
			Headers = [{content_type, "application/json"},
				{etag, Etag}, {accept_ranges, "items"},
				{content_range, ContentRange}],
			{ok, Headers, Json}
	end.

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

%% @hidden
-spec mib(Mib) -> Mib 
	when
		Mib :: [#mib{}] | [map()] | #mib{} | map().
%% @doc CODEC for mib record.
mib(#mib{} = Mib) ->
	Fields = record_info(fields, mib),
	mib(Fields, Mib, #{});
mib([#mib{} | _] = MibList) ->
	[mib(Mib) || Mib <- MibList].
%% @hidden
mib([misc | T], #mib{misc = Misc} = A, Acc)
		when length(Misc) > 0 ->
	mib(T, A, Acc#{"misc" => Misc});
mib([mib_format_version | T], #mib{mib_format_version = MibFormat} = A, Acc)
		when length(MibFormat) > 0 ->
	mib(T, A, Acc#{"mib_format_version" => MibFormat});
mib([name | T], #mib{name = Name} = A, Acc)
		when length(Name) > 0 ->
	mib(T, A, Acc#{"name" => Name});
mib([module_identity | T], #mib{module_identity = MID} = A, Acc)
		when is_record(MID, module_identity) ->
	mib(T, A, Acc#{"module_identity" => module_identity(MID)});
mib([mes | T], #mib{mes = Mes} = A, Acc)
		when is_list(Mes), length(Mes) > 0 ->
	mib(T, A, Acc#{"mes" => me(Mes)});
mib([asn1_types | T], #mib{asn1_types = Asn} = A, Acc)
		when length(Asn) > 0 ->
	mib(T, A, Acc#{"asn1_types" => Asn});
mib([traps | T], #mib{traps = Traps} = A, Acc)
		when is_list(Traps), length(Traps) > 0 ->
	mib(T, A, Acc#{"traps" => trap(Traps)});
mib([variable_infos | T], #mib{variable_infos = VarInfo} = A, Acc)
		when length(VarInfo) > 0 ->
	mib(T, A, Acc#{"variable_infos" => VarInfo});
%mib([table_infos | T], #mib{table_infos = TabInfo} = A, Acc)
%		when length(TabInfo) > 0 ->
%	mib(T, A, Acc#{"table_infos" => TabInfo});
mib([imports | T], #mib{imports = Imports} = A, Acc)
		when length(Imports) > 0 ->
	mib(T, A, Acc#{"imports" => Imports});
mib([_H | T], A, Acc) ->
	mib(T, A, Acc);
mib([], _A, Acc) ->
	Acc.

%% @hidden
-spec module_identity(Mid) -> Mid 
	when
		Mid :: [#module_identity{}] | [map()] | #module_identity{} | map().
%% @doc CODEC for module_identity record.
module_identity(#module_identity{} = Mid) ->
	Fields = record_info(fields, module_identity),
	module_identity(Fields, Mid, #{});
module_identity([#module_identity{} | _] = MidList) ->
	[module_identity(Mid) || Mid <- MidList].
%% @hidden
module_identity([last_updated | T], #module_identity{last_updated = Last} = B, Acc)
	when length(Last) > 0 ->
	module_identity(T, B, Acc#{"last_updated" => Last});
module_identity([organization | T], #module_identity{organization = Org} = B, Acc)
	when length(Org) > 0 ->
	module_identity(T, B, Acc#{"organization" => Org});
module_identity([contact_info | T], #module_identity{contact_info = Contact} = B, Acc)
	when length(Contact) > 0 ->
	ContactStrinf = snmp_collector_utils:stringify(Contact),
	module_identity(T, B, Acc#{"contact_info" => ContactStrinf});
module_identity([description | T], #module_identity{description = Des} = B, Acc)
	when length(Des) > 0 ->
	DesString = snmp_collector_utils:stringify(Des),
	module_identity(T, B, Acc#{"description" => DesString});
%module_identity([revisions | T], #module_identity{revisions = Revision} = B, Acc) ->
%	module_identity(T, B, Acc#{"revisions" => Revision});
module_identity([_H | T], B, Acc) ->
	module_identity(T, B, Acc);
module_identity([], _B, Acc) ->
	Acc.

-spec me(Me) -> Me
	when
		Me :: #me{} | map() | [#me{}] | [map()].
%% @doc CODEC for me record from MIB.
%% @private
me(#me{} = Me) ->
	Fields = record_info(fields, me),
	me(Fields, Me, #{});
me([#me{} | _] = MeList) ->
	[me(Me) || Me <- MeList].
%% @hidden
me([oid | T], #me{oid = OID} = M, Acc)
		when is_list(OID), length(OID) > 0 ->
	me(T, M, Acc#{"oid" => OID});
me([aliasname | T], #me{aliasname = AliasName} = M, Acc)
		when is_atom(AliasName), AliasName /= undefined->
	AliasNameList = atom_to_list(AliasName),
	me(T, M, Acc#{"aliasname" => AliasNameList});
me([entrytype | T], #me{entrytype = EntryType} = M, Acc)
		when is_atom(EntryType), EntryType /= undefined ->
	EntryTypeList = atom_to_list(EntryType),
	me(T, M, Acc#{"entrytype" => EntryTypeList});
me([asn1_type | T],
		#me{asn1_type = {asn1_type, Value, _, _, _, _, _, _, _}} = M,
		Acc) when is_atom(Value), Value /= undefined ->
	Asn = atom_to_list(Value),
	me(T, M, Acc#{"asn1_type" => Asn});
me([imported | T], #me{imported = Imported} = M, Acc)
		when is_boolean(Imported), Imported /= undefined ->
	ImportList = atom_to_list(Imported),
	me(T, M, Acc#{"imported" => ImportList});
me([access | T], #me{access = Access} = M, Acc)
		when Access /= undefined ->
	me(T, M, Acc#{"access" => Access});
me([description | T], #me{description = Description} = M, Acc)
		when is_list(Description), Description /= undefined ->
	me(T, M, Acc#{"description" => Description});
me([_H | T], M, Acc) ->
	me(T, M, Acc);
me([], _M, Acc) ->
	Acc.

-spec trap(TrapNotification) -> TrapNotification
	when
		TrapNotification :: [Trap] | [Notification] | Trap | Notification,
		Trap :: #trap{} | map(),
		Notification :: #trap{} | map().
%% @doc CODEC for trap and notification records from MIB.
trap(TrapNotification) when is_record(TrapNotification, trap) ->
	Fields = record_info(fields, trap),
	trap(Fields, TrapNotification, #{});
trap(TrapNotification) when is_record(TrapNotification, notification)  ->
	Fields = record_info(fields, notification),
	trap(Fields, TrapNotification, #{});
trap(TrapNotification) when is_list(TrapNotification) ->
	trap(TrapNotification, []).
%% @hidden
trap([H | T], Acc) ->
	trap(T, [trap(H) | Acc]);
trap([], Acc) ->
	lists:reverse(Acc).
%% @hidden
trap([enterpriseoid| T], #trap{enterpriseoid = OID} = N, Acc)
		when is_list(OID), length(OID) > 0 ->
	trap(T, N, Acc#{"oid" => lists:flatten(io_lib:write(OID))});
trap([trapname | T], #trap{trapname = TrapName} = N, Acc)
		when is_atom(trapname), TrapName /= undefined ->
	trap(T, N, Acc#{"trapname" => atom_to_list(TrapName)});
trap([trapname | T], #notification{trapname = TrapName} = N, Acc)
		when is_atom(trapname), TrapName /= undefined ->
	TrapNameList1 = atom_to_list(TrapName),
	trap(T, N, Acc#{"trapname" => atom_to_list(TrapName)});
trap([oidobjects | T], #trap{oidobjects = OidObjects} = N, Acc)
		when is_list(OidObjects), length(OidObjects) > 0 ->
	trap(T, N, Acc#{"objects" => oidobjects(OidObjects, [])});
trap([oid | T], #notification{oid = OID} = N, Acc)
		when is_list(OID), length(OID) > 0 ->
	trap(T, N, Acc#{"oid" => lists:flatten(io_lib:write(OID))});
trap([oidobjects | T], #notification{oidobjects = OidObjects} = N, Acc)
		when is_list(OidObjects), length(OidObjects) > 0 ->
	trap(T, N, Acc#{"objects" => oidobjects(OidObjects, [])});
trap([_H | T], N, Acc) ->
	trap(T, N, Acc);
trap([], _N, Acc) ->
	Acc.

