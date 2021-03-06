%%% snmp_collector_debug_fsm.erl
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
-module(snmp_collector_debug_fsm).
-copyright('Copyright (c) 2016 - 2019 SigScale Global Inc.').

-behaviour(gen_fsm).

%% export the gen fsm callbacks.
-export([init/1, terminate/3]).
-export([code_change/4, handle_event/3 ,handle_info/3 ,handle_sync_event/4]).
%% export the gen fsm states.
-export([decode/2]).

-record(statedata, {socket :: inet:socket()}).

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
init([{Address, Port}]) ->
	case gen_udp:open(Port, [{ifaddr, Address}, {active, once}]) of
		{ok, Socket} ->
			{ok, decode, #statedata{socket = Socket}};
		{error, Reason} ->
			{error, Reason}
	end.

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
%% @doc Handle decode state event.
%% @private
%%
decode(Event, StateData) ->
	{stop, Event, StateData}.

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
handle_info({udp, Socket, Address, Port, Packet}, 
		StateName, #statedata{} = StateData) ->
	decode(Address, Port, Packet),
	inet:setopts(Socket, [{active, once}]),
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

-spec decode(Address, Port, Packet) -> Result
	when
		Address :: list(),
		Port :: pos_integer(),
		Packet :: list(),
		Result :: ok | {'EXIT', Reason},
		Reason :: term().
%% @doc Decode the packet.
decode(Address, Port, Packet) ->
	case catch snmp_pdus:dec_message(Packet) of
		#message{} = Message->
			decode1(Message, Address, Port);
		{'EXIT', Reason} ->
			{'EXIT', Reason}
	end.
%% @hidden
decode1(#message{version = 'version-1', 
		community = Community} = _Message, Address, Port) -> 
	Version = "v1",
	error_logger:info_report(["SNMP Debug", 
			{address, Address}, 
			{port, Port}, 
			{version, Version}, 
			{community, Community}]);
decode1(#message{version = 'version-2',
		community = Community} = _Message, Address, Port) ->
	Version = "v2c",
	error_logger:info_report(["SNMP Debug", 
			{address, Address}, 
			{port, Port}, 
			{version, Version}, 
			{community, Community}]);
decode1(#message{version = 'version-3', 
		community = V3Header} = _Message, Address, Port) ->
	Version = "v3",
	DecodedPacket = V3Header#v3_hdr.msgSecurityParameters,
	MsgFlags = case V3Header#v3_hdr.msgFlags of
		[0] ->
			noAuthNoPriv;
		[1] ->
			authNoPriv;
		[3] ->
			authPriv;
		N ->
			N
	end,
	case catch snmp_pdus:dec_usm_security_parameters(DecodedPacket) of
		#usmSecurityParameters{msgUserName = UserName, 
				msgAuthoritativeEngineID = EngineID} ->
			error_logger:info_report(["SNMP Debug", 
					{address, Address},
					{port, Port},
					{version, Version},
					{flags, MsgFlags},
					{user_name, UserName},
					{engine_id, EngineID}]);
		{'EXIT', Reason} ->
			{'EXIT', Reason}
	end.


