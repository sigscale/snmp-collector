%%% snmp_collector_manager_fsm.erl
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
%%% @docfile "{@docsrc supervision.edoc}"
%%%
-module(snmp_collector_manager_fsm).
-copyright('Copyright (c) 2016 - 2017 SigScale Global Inc.').

-behaviour(gen_fsm).

%% export the gen fsm callbacks.
-export([init/1, terminate/3]).
-export([code_change/4, handle_event/3 ,handle_info/3 ,handle_sync_event/4]).
%% export the gen fsm states.
-export([decode/2]).

-record(statedata, {socket :: inet:socket() | undefined,
		address :: inet:ip_address() | undefined,
		port :: non_neg_integer() | undefined,
		packet :: [byte()] | undefined}).

-include_lib("snmp/include/snmp_types.hrl").

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
init([Socket, Address, Port, Packet]) ->
	{ok, decode, #statedata{socket = Socket,
			address = Address, port = Port,
			packet = Packet}, 0}.

-spec decode(Event, StateData) -> Result
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
%%		gen_fsm:send_event/2} in the <b>send_request</b> state. This state is responsible
%%		for sending a RADIUS-Disconnect/Request to an access point.
%% @@see //stdlib/gen_fsm:StateName/2
%% @private
%%
decode(_Event, #statedata{socket = Socket, address = Address,
		port = Port, packet = Packet} = StateData) ->
	decode(Socket, Address, Port, Packet),
	{next_state, decode, StateData, 0}.

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
handle_sync_event(Event, _From, _StateName, StateData) ->
	{stop, Event, StateData}.

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

-spec decode(Socket, Address, Port, Packet) -> Result
	when
		Socket :: inet:socket() | undefined,
		Address :: inet:ip_address() | undefined,
		Port :: non_neg_integer() | undefined,
		Packet :: [byte()]| undefined,
		Result :: Varbinds :: [tuple()] | ok.
%% @doc Decode the packet.
decode(Socket,Address, Port, Packet) ->
	case catch snmp_pdus:dec_message(Packet) of
		#message{version = 'version-1',
				data = Data} ->
			decode_v1_v2(v1, Data);
		#message{version = 'version-2',
				data = Data} ->
			decode_v1_v2(v2c, Data);
		Message = #message{version = 'version-3',
				data = Data} ->
			decode_v3(v3, Message, Data);
		{'EXIT', Reason} ->
			error_logger:info_report(["SNMP Manager",
					{reason, Reason},
					{socket, Socket},
					{address, Address},
					{port, Port}])
	end.

-spec decode_v1_v2(Version, Data) -> Result
	when
		Version :: v1 | v2c,
		Data :: #pdu{} | #scopedPdu{},
		Result :: ok.
%% @doc Decode the data from a SNMP  'v1' or 'v2c' Packet.
decode_v1_v2(Version, #pdu{varbinds = Varbinds} = Data) ->
	ok;
decode_v1_v2(Version, #scopedPdu{data = Varbinds} = Data) ->
	ok.
	

-spec decode_v3(Message, Version, Data) -> Result
	when
		Message :: #message{},
		Version :: v3,
		Data :: #pdu{} | #scopedPdu{},
		Result :: ok | {'EXIT', Reason},
		Reason :: term().
%% @doc Decode the data from a SNMP 'v3' Packet.
decode_v3(Version, #message{community = V3Header} = Message, Data) ->
	DecodedPacket = V3Header#v3_hdr.msgSecurityParameters,
	case catch snmp_pdus:dec_usm_security_parameters(DecodedPacket) of
		#usmSecurityParameters{msgUserName = UserName,
				msgAuthoritativeEngineID = EngineID} ->
			[{{EntityName, engine_id}, _}] = ets:lookup(snmpm_agent_table, {UserName, engine_id}),
			ok;
		{'EXIT', Reason} ->
			{'EXIT', Reason}
	end.
	
