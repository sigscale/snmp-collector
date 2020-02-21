%%% snmp_collector_get_fsm.erl
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
-module(snmp_collector_get_fsm).
-copyright('Copyright (c) 2016 - 2019 SigScale Global Inc.').

-behaviour(gen_fsm).

%% export the gen fsm callbacks.
-export([init/1, terminate/3]).
-export([code_change/4, handle_event/3 ,handle_info/3 ,handle_sync_event/4]).
%% export the gen fsm states.
-export([get/2]).

%% support deprecated_time_unit()
-define(MILLISECOND, milli_seconds).
%-define(MILLISECOND, millisecond).
-define(MICROSECOND, micro_seconds).
%-define(MICROSECOND, microsecond).

-record(statedata, {}).

%%----------------------------------------------------------------------
%%  The call back functions
%%----------------------------------------------------------------------

-spec init(Args) -> Result
	when
		Args :: list(),
		Result :: {ok, StateName, StateData} | {ok, StateName, StateData, Timeout}
		| {ok, StateName, StateData, hibernate} | {stop, Reason} | ignore,
		StateName ::atom(),
		StateData :: #statedata{},
Timeout :: non_neg_integer() | infinity,
Reason :: term().
%% @doc Initialize the {@module} finite state machine.
%% @see //stdlib/gen_fsm:init/1
%% @private
%%
init([]) ->
	{ok, get, #statedata{}, 0}.

-spec get(Event, StateData) -> Result
	when
		Event :: timeout | term(),
		StateData :: #statedata{},
		Result :: {next_state, NextStateName, NewStateData}
			| {next_state, NextStateName, NewStateData, Timeout}
			| {next_state, NextStateName, NewStateData, hibernate}
			| {stop, Reason, NewStateData},
		NextStateName :: atom(),
		NewStateData :: #statedata{},
		Timeout :: non_neg_integer() | infinity,
		Reason :: normal | term().
%% @doc Handle events sent with {@link //stdlib/gen_fsm:send_event/2.
%%		gen_fsm:send_event/2} in the <b>send_request</b> state.
%% @private
%%
get(timeout, StateData) ->
	try
		{NameResponseOID, QueryOID} = get_oids(oid_list(), [], []),
		{ok ,Objects, Acc2, Value} = get_varbinds(NameResponseOID, undefined, QueryOID, []),
		{ok, JSON} = print_varbinds(Objects, Acc2, Value, []),
		disk_log:log(fault, JSON)
	of
		ok ->
			{next_state, get, StateData, 3000000};
		{error, Reason} ->
			{stop, Reason, StateData}
	catch
		_:Reason ->
			{stop, Reason, StateData}
	end.

-spec handle_event(Event, StateName, StateData) -> Result
	when
		Event :: atom(),
		Result :: {next_state, StateName, StateData},
		StateName :: atom(),
		StateData :: #statedata{}.
%% @doc Handle an event sent with
%%		{@link //stdlib/gen_fsm:send_all_state_event/2.
%%		gen_fsm:send_all_state_event/2}.
%% @see //stdlib/gen_fsm:handle_event/3
%% @private
%%
handle_event(_Event, StateName, StateData) ->
	{next_state, StateName, StateData}.

-spec handle_sync_event(Event, From, StateName, StateData) -> Result
	when
		Event :: term(),
		From :: {Pid :: pid(), Tag :: term()},
		StateName :: atom(),
		StateData :: #statedata{},
		Result :: {reply, Reply, NextStateName, NewStateData}
		| {reply, Reply, NextStateName, NewStateData, Timeout}
		| {reply, Reply, NextStateName, NewStateData, hibernate}
		| {next_state, NextStateName, NewStateData}
		| {next_state, NextStateName, NewStateData, Timeout}
		| {next_state, NextStateName, NewStateData, hibernate}
		| {stop, Reason, Reply, NewStateData}
		| {stop, Reason, NewStateData},
		Reply :: term(),
		NextStateName :: atom(),
		NewStateData :: #statedata{},
		Timeout :: non_neg_integer() | infinity,
		Reason :: normal | term().
%% @doc Handle an event sent with
%%    {@link //stdlib/gen_fsm:sync_send_all_state_event/2.
%%     gen_fsm:sync_send_all_state_event/2,3}.
%% @see //stdlib/gen_fsm:handle_sync_event/4
%% @private
%%
handle_sync_event(_Event, _From, StateName, StateData) ->
	Reply = ok,
	{reply, Reply, StateName, StateData}.

-spec handle_info(Info, StateName, StateData) -> Result
	when
		Info :: term(),
		StateName :: atom(),
		StateData :: #statedata{},
		Result :: {next_state, NextStateName, NewStateData}
		| {next_state, NextStateName, NewStateData, Timeout}
		| {next_state, NextStateName, NewStateData, hibernate}
		| {stop, Reason, NewStateData},
		NextStateName :: atom(),
		NewStateData :: #statedata{},
		Timeout :: non_neg_integer() | infinity,
		Reason :: normal | term().
%% @doc Handle a received message.
%% @see //stdlib/gen_fsm:handle_info/3
%% @private
%%
handle_info(_Info, StateName, StateData) ->
	{next_state, StateName, StateData}.

-spec terminate(Reason, StateName, StateData) -> Result
	when
		Reason :: normal | shutdown | {shutdown,term()} | term(),
		StateName :: atom(),
		StateData :: term(),
		Result :: atom().
%% @doc Stop the snmp collecter.
%% @private

terminate(_Reason, _State, _Data) ->
	ok.

-spec code_change(OldVsn, StateName, StateData, Extra) -> Result
	when
		OldVsn :: (Vsn :: term() | {down, Vsn :: term()}),
		StateName :: atom(),
		StateData :: #statedata{},
		Extra :: term(),
		Result :: {ok, NextStateName :: atom(), NewStateData :: #statedata{}}.
%% @doc Update internal state data during a release upgrade&#047;downgrade.
%% @see //stdlib/gen_fsm:code_change/4
%% @private
%%
code_change(_OldVsn, StateName, StateData, _Extra) ->
	{ok, StateName, StateData}.

%%----------------------------------------------------------------------
%%  The internal functions
%%----------------------------------------------------------------------

-spec oid_list() -> OIDList
	when
		OIDList :: list().
%% @doc Provides the list of varbinds for snmp-get-bulk.
%% @hidden
oid_list() ->
	[[{"sysContact", [1,3,6,1,2,1,1,4,0], [1,3,6,1,2,1,1,5,0]},
			{"sysName", [1,3,6,1,2,1,1,5,0], [1,3,6,1,2,1,1,6,0]},
			{"sysLocation", [1,3,6,1,2,1,1,6,0], [1,3,6,1,2,1,1,7,0]},
			{"sysServices", [1,3,6,1,2,1,1,7,0], [1,3,6,1,2,1,1,8,0]},
			{"sysORLastChange", [1,3,6,1,2,1,1,8,0], [1,3,6,1,2,1,1,9,0]}]].

-spec get_oids(Varbinds, Acc1, Acc2) -> Result
	when
		Varbinds :: list(),
		Acc1 :: list(),
		Acc2 :: list(),
		Result :: {NewAcc1, NewAcc2},
		NewAcc1 :: list(),
		NewAcc2 :: list().
%% @doc Seperate the name, reponse OID and the query OID.
%% @hidden
get_oids([H | T], Acc1, Acc2) ->
	ReponseOID = [{Name, OID} || {Name, _, OID} <- H],
	QueryOID = [OID2 || {_, OID2, _} <- H],
	get_oids(T, [QueryOID | Acc1], [ReponseOID | Acc2]);
get_oids([], Acc1 ,Acc2) ->
	NewAcc1 = lists:reverse(Acc1),
	NewAcc2 = lists:flatten(lists:reverse(Acc2)),
	{NewAcc1, NewAcc2}.

-spec get_varbinds(QueryOID, EngineId, Objects, Acc) -> Result
	when
		QueryOID :: snmp:oid(),
		EngineId :: undefined,
		Objects :: [{Name, snmp:oid()}],
		Acc :: list(),
		Name :: string(),
		Result :: {ok ,Objects, Acc2, Value} | {error, Reason},
		Acc2 :: list(),
		Value :: list(),
		Reason :: term().
%% @doc Peforms snmp-get on the whole list of oids.
%% @hidden
get_varbinds([H | T], EngineId, Objects, Acc) ->
	{ok, UserName} = application:get_env(snmp_collector, snmp_get_username),
	OIDs = case EngineId of
		undefined ->
			[[128,0,196,210,3,66,1,10,140,0,5] | H];
		EngineId ->
			H
	end,
	case snmpm:sync_get_bulk("simple_user", UserName, length(OIDs), 0, OIDs, 15000) of
		{ok,{noError, _, VarBinds}, _} ->
			NewEngineID = case lists:keyfind([128,0,196,210,3,66,1,10,140,0,5], 2, VarBinds) of
				{_, _, _, EID, _} ->
					EID;
				false ->
					EngineId
			end,
			get_varbinds(T, NewEngineID, Objects, [VarBinds | Acc]);
		{error, Reason} ->
			get_varbinds(T, EngineId, Objects, Acc),
			error_logger:error_report(["SNMP GET-BULK failed", {error, Reason}]),
			{error, Reason}
	end;
get_varbinds([], _EngineId, Objects, Acc) ->
	Acc2 = lists:flatten(lists:reverse(Acc)),
	get_varbinds2(Objects, Acc2 ,Acc2).
get_varbinds2(Objects, Acc2, [H | _]) ->
	get_varbinds3(Objects, Acc2, H).
get_varbinds3(Objects, Acc2, {varbind, _OID, _Type, Value, _}) ->
	{ok ,Objects, Acc2, Value}.

-spec print_varbinds(Objects, Acc2, EngineID, Acc) -> Result
	when
		Objects :: [{Name, snmp:oid()}],
		Name :: string(),
		Acc2 :: [{varbind, OID, Type, Value, Seqnum}],
		OID :: snmp:oid(),
		Type :: 'INTEGER' | 'OCTET STRING',
		Value :: term(),
		Seqnum :: integer(),
		EngineID :: list(),
		Acc :: list(),
		Result ::  {ok, JSON} | {error, not_found},
		JSON :: list().
%% @doc Creats a map of names to values.
%% @hidden
print_varbinds(Objects, [{varbind, OID, Type, Value, _Seqnum} | T], EngineID, Acc)
	when Type == 'INTEGER' ->
		case lists:keyfind(OID, 2, Objects) of
			{Name, _}  when Name =/= "snmpEngineID.0"->
				print_varbinds(Objects, T, EngineID, [#{"name" => Name, "value" => Value} | Acc]);
			false ->
				{error, not_found}
		end;
print_varbinds(Objects, [{varbind, OID, Type, Value, _Seqnum} | T], EngineID, Acc)
	when Type == 'OCTET STRING' ->
		case unicode:characters_to_list(list_to_binary(Value), utf8) of
			Value ->
				case lists:keyfind(OID, 2, Objects) of
					{Name, _}  when Name =/= "snmpEngineID.0"->
						print_varbinds(Objects, T, EngineID, [#{"name" => Name, "value" => Value} | Acc]);
					false ->
						{error, not_found}
				end;
			{error,[],_} ->
				print_varbinds(Objects, T, EngineID, Acc)
	end;
print_varbinds(_Objects, [], EngineID, Ves) ->
	Header = event_header(sourceId(EngineID)),
	Event = #{"event" =>  #{"commonEventHeader" => Header,
		"otherFields" => #{"nameValuePairs" => lists:reverse(Ves),
		"otherFieldsVersion" => 1}}},
	case catch zj:encode(Event) of
		JSON when is_list(JSON) ->
			{ok, JSON};
		{'EXIT', Reason} ->
			error_logger:error_report(["JSON Encode Failed", {error, Reason}]),
			{error, Reason}
	end.

-spec event_header(SourceID) -> EventHeader
	when
	SourceID :: string(),
	EventHeader :: map().
%% @doc Create VES common event header.
%% @hidden
event_header(SourceID) ->
	#{"domain" => "other",
		"eventId" => event_id(),
		"eventName" => notifyNewAlarm,
		"lastEpochMicrosec" => timestamp(),
		"priority" => "Normal",
		"reportingEntityName" => atom_to_list(node()),
		"sequence" => "0",
		"sourceId"=> SourceID,
		"sourceName" => "SNMP Manager",
		"startEpochMicrosec" => timestamp(),
		"version" => 1}.

-spec event_id() -> EventId
	when
		EventId :: string().
%% @doc Create unique event id.
%% @hidden
event_id() ->
	Ts = erlang:system_time(?MILLISECOND),
	N = erlang:unique_integer([positive]),
	integer_to_list(Ts) ++ "-" ++ integer_to_list(N).

-spec timestamp() -> TimeStamp
	when
		TimeStamp :: string().
%% @doc Create time stamp.
%% @hidden
timestamp() ->
	integer_to_list(erlang:system_time(?MICROSECOND)).

-spec sourceId(EngineID) -> SourceId
	when
		EngineID :: string(),
		SourceId :: string().
%% @doc Create a unique source Id.
%% @hidden
sourceId(EngineID) ->
	sourceId2 (EngineID, []).
sourceId2([H | T], Acc) ->
	NewEngineID = integer_to_list(H , 16),
	sourceId2(T, [NewEngineID | Acc]);
sourceId2([], Acc) ->
	string:to_lower(lists:flatten(lists:reverse(Acc))).

