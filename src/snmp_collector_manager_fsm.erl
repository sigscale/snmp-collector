%%% snmp_collector_manager_fsm.erl
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
%%% @docfile "{@docsrc supervision.edoc}"
%%%
-module(snmp_collector_manager_fsm).
-copyright('Copyright (c) 2016 - 2019 SigScale Global Inc.').

-behaviour(gen_fsm).

%% export the gen fsm callbacks.
-export([init/1, terminate/3]).
-export([code_change/4, handle_event/3 ,handle_info/3 ,handle_sync_event/4]).
%% export the gen fsm states.
-export([handle_pdu/2]).
% add handle_trap/2
-record(statedata, {socket :: inet:socket() | undefined,
		address :: inet:ip_address() | undefined,
		port :: non_neg_integer() | undefined,
		packet :: [byte()] | undefined}).

-define(SNMP_USE_V3, true).

-include("snmp_collector.hrl").
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
	process_flag(trap_exit, true),
	{ok, handle_pdu, #statedata{socket = Socket,
			address = Address, port = Port,
			packet = Packet}, 0}.

-spec handle_pdu(Event, StateData) -> Result
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
		Reason :: normal | shutdown | term().
%% @doc Handle events sent with {@link //stdlib/gen_fsm:send_event/2.
%%		gen_fsm:send_event/2} in the <b>send_request</b> state.
%% @@see //stdlib/gen_fsm:StateName/2
%% @private
%%
handle_pdu(timeout = _Event, #statedata{socket = _Socket, address = Address,
		port = Port, packet = Packet} = StateData) ->
	case catch snmp_pdus:dec_message_only(Packet) of
		#message{version = 'version-1'} ->
			{stop, shutdown, StateData};
		#message{version = 'version-2'} ->
			{stop, shutdown, StateData};
		#message{version = 'version-3', vsn_hdr = #v3_hdr{msgSecurityParameters = SecurityParams, msgFlags = [Flag]}, data = Data} ->
			case catch snmp_pdus:dec_usm_security_parameters(SecurityParams) of
				#usmSecurityParameters{msgUserName = UserName, msgAuthoritativeEngineID = EngineID, msgAuthoritativeEngineBoots = EngineBoots,
						msgAuthoritativeEngineTime = EngineTime, msgPrivacyParameters = MsgPrivParams, msgAuthenticationParameters = MsgAuthenticationParams} ->
					Fsearch = fun() ->
								mnesia:read(snmp_user, UserName, read)
					end,
					case catch mnesia:ets(Fsearch) of
						[#snmp_user{authPass = AuthPass, privPass = PrivPass}] ->
							case catch snmp_pdus:dec_scoped_pdu_data(Data) of
								#scopedPdu{data = #pdu{varbinds = Varbinds}} ->
									case snmp_collector_utils:security_params(EngineID, Address, UserName, MsgAuthenticationParams,
											Packet, AuthPass, PrivPass) of
										{ok, usmNoAuthProtocol, usmNoPrivProtocol} when Flag == 0 ->
											case handle_trap(Address, Port, {noError, 0, Varbinds}) of
												ignore ->
													{stop, shutdown, StateData};
												{error, Reason} ->
													error_logger:info_report(["SNMP Manager Agent Not Recognized",
															{error, Reason},
															{engine_id, EngineID},
															{username, UserName},
															{flags, noAuthNoPriv},
															{port, Port},
															{address, Address}]),
														{stop, shutdown, StateData}
											end;
										{ok, usmHMACMD5AuthProtocol, usmNoPrivProtocol} when Flag == 1 ->
											case handle_trap(Address, Port, {noError, 0, Data}) of
												ignore ->
													{stop, shutdown, StateData};
												{error, Reason} ->
													error_logger:info_report(["SNMP Manager Agent Not Recognized",
															{error, Reason},
															{engine_id, EngineID},
															{username, UserName},
															{flags, authNoPriv},
															{port, Port},
															{address, Address}]),
														{stop, shutdown, StateData}
											end;
										{ok, usmHMACSHAAuthProtocol, usmNoPrivProtocol} when Flag == 1 ->
											case handle_trap(Address, Port, {noError, 0, Data}) of
												ignore ->
													{stop, shutdown, StateData};
												{error, Reason} ->
													error_logger:info_report(["SNMP Manager Agent Not Recognized",
															{error, Reason},
															{engine_id, EngineID},
															{username, UserName},
															{flags, authNoPriv},
															{port, Port},
															{address, Address}]),
														{stop, shutdown, StateData}
											end;
										{error, Reason} ->
											error_logger:info_report(["SNMP Manager Incorrect Security Params",
														{error, Reason},
														{engine_id, EngineID},
														{username, UserName},
														{flags, flag(Flag)},
														{port, Port},
														{address, Address}]),
											{stop, shutdown, StateData}
									end;
								PDU when is_list(PDU) ->
									case snmp_collector_utils:security_params(EngineID, Address, UserName, MsgAuthenticationParams,
											Packet, AuthPass, PrivPass) of
										{ok, usmNoAuthProtocol, usmNoPrivProtocol} when Flag == 0 ->
											case handle_trap(Address, Port, {noError, 0, Data}) of
												ignore ->
													{stop, shutdown, StateData};
												{error, Reason} ->
													error_logger:info_report(["SNMP Manager Agent Not Recognized",
															{error, Reason},
															{engine_id, EngineID},
															{username, UserName},
															{flags, authPriv},
															{port, Port},
															{address, Address}]),
														{stop, shutdown, StateData}
											end;
										{ok, usmHMACMD5AuthProtocol, usmNoPrivProtocol} when Flag == 1 ->
											case handle_trap(Address, Port, {noError, 0, Data}) of
												ignore ->
													{stop, shutdown, StateData};
												{error, Reason} ->
													error_logger:info_report(["SNMP Manager Agent Not Recognized",
															{error, Reason},
															{engine_id, EngineID},
															{username, UserName},
															{flags, authPriv},
															{port, Port},
															{address, Address}]),
														{stop, shutdown, StateData}
											end;
										{ok, usmHMACMD5AuthProtocol, usmDESPrivProtocol} when Flag == 3 ->
											PrivKey = snmp:passwd2localized_key(md5, PrivPass, EngineID),
											case dec_des(PrivKey, MsgPrivParams, PDU) of
												{ErrorStatus, ErrorIndex, Varbinds} ->
													case handle_trap(Address, Port, {ErrorStatus, ErrorIndex, Varbinds}) of
														ignore ->
															{stop, shutdown, StateData};
														{error, Reason} ->
															error_logger:info_report(["SNMP Manager Agent Not Recognized",
																	{error, Reason},
																	{engine_id, EngineID},
																	{username, UserName},
																	{flags, authPriv},
																	{port, Port},
																	{address, Address}]),
															{stop, shutdown, StateData}
													end;
												{error, Reason} ->
													error_logger:info_report(["SNMP Manager Decryption Failed",
															{error, Reason},
															{engine_id, EngineID},
															{username, UserName},
															{flags, authPriv},
															{protocol, md5},
															{port, Port},
															{address, Address}]),
														{stop, shutdown, StateData}
											end;
										{ok, usmHMACMD5AuthProtocol, usmAesCfb128Protocol} when Flag == 3 ->
											PrivKey = snmp:passwd2localized_key(md5, PrivPass, EngineID),
											case dec_aes(PrivKey, MsgPrivParams, PDU, EngineBoots, EngineTime) of
												{ErrorStatus, ErrorIndex, Varbinds} ->
													case handle_trap(Address, Port, {ErrorStatus, ErrorIndex, Varbinds}) of
														ignore ->
															{stop, shutdown, StateData};
														{error, Reason} ->
															error_logger:info_report(["SNMP Manager Agent Not Recognized",
																	{error, Reason},
																	{engine_id, EngineID},
																	{username, UserName},
																	{flags, authPriv},
																	{port, Port},
																	{address, Address}]),
															{stop, shutdown, StateData}
													end;
												{error, Reason} ->
													error_logger:warning_report(["SNMP Manager Decryption Failed",
															{error, Reason},
															{engine_id, EngineID},
															{username, UserName},
															{flags, authPriv},
															{protocol, aes},
															{port, Port},
															{address, Address}]),
														{stop, shutdown, StateData}
											end;
										{ok, usmHMACSHAAuthProtocol, usmNoPrivProtocol} when Flag == 1 ->
											case handle_trap(Address, Port, {noError, 0, Data}) of
												ignore ->
													{stop, shutdown, StateData};
												{error, Reason} ->
													error_logger:info_report(["SNMP Manager Agent Not Recognized",
															{error, Reason},
															{engine_id, EngineID},
															{username, UserName},
															{flags, authPriv},
															{port, Port},
															{address, Address}]),
														{stop, shutdown, StateData}
											end;
										{ok, usmHMACSHAAuthProtocol, usmDESPrivProtocol} when Flag == 3 ->
											[A, B, C, D, E, F, G, H, I, J, K, L, P, Q, R, S | _] = snmp:passwd2localized_key(sha, PrivPass, EngineID),
											PrivKey = [A, B, C, D, E, F, G, H, I, J, K, L, P, Q, R, S],
											case dec_des(PrivKey, MsgPrivParams, PDU) of
												{ErrorStatus, ErrorIndex, Varbinds} ->
													case handle_trap(Address, Port, {ErrorStatus, ErrorIndex, Varbinds}) of
														ignore ->
															{stop, shutdown, StateData};
														{error, Reason} ->
															error_logger:info_report(["SNMP Manager Agent Not Found",
																	{error, Reason},
																	{engine_id, EngineID},
																	{username, UserName},
																	{flags, authPriv},
																	{port, Port},
																	{address, Address}]),
															{stop, shutdown, StateData}
													end;
												{error, Reason} ->
													error_logger:info_report(["SNMP Manager Decryption Failed",
															{error, Reason},
															{engine_id, EngineID},
															{username, UserName},
															{flags, authPriv},
															{protocol, sha},
															{port, Port},
															{address, Address}]),
														{stop, shutdown, StateData}
											end;
										{ok, usmHMACSHAAuthProtocol, usmAesCfb128Protocol} when Flag == 3 ->
											[A, B, C, D, E, F, G, H, I, J, K, L, P, Q, R, S | _] = snmp:passwd2localized_key(sha, PrivPass, EngineID),
											PrivKey = [A, B, C, D, E, F, G, H, I, J, K, L, P, Q, R, S],
											case dec_aes(PrivKey, MsgPrivParams, PDU, EngineBoots, EngineTime) of
												{ErrorStatus, ErrorIndex, Varbinds} ->
													case handle_trap(Address, Port, {ErrorStatus, ErrorIndex, Varbinds}) of
														ignore ->
															{stop, shutdown, StateData};
														{error, Reason} ->
															error_logger:info_report(["SNMP Manager Agent Not Found",
																	{error, Reason},
																	{engine_id, EngineID},
																	{username, UserName},
																	{flags, authPriv},
																	{port, Port},
																	{address, Address}]),
															{stop, shutdown, StateData}
													end;
												{error, Reason} ->
													error_logger:warning_report(["SNMP Manager Decryption Failed",
															{error, Reason},
															{engine_id, EngineID},
															{username, UserName},
															{flags, authPriv},
															{protocol, sha},
															{port, Port},
															{address, Address}]),
														{stop, shutdown, StateData}
											end;
										{error, Reason} ->
											error_logger:error_report(["SNMP Manager Incorrect Security Params",
													{error, Reason},
													{engine_id, EngineID},
													{username, UserName},
													{flags, authPriv},
													{port, Port},
													{address, Address}]),
											{stop, shutdown, StateData}
									end;
								{'EXIT', Reason} ->
									error_logger:error_report(["SNMP Manager Decoding SNMP v3 Failed",
											{error, Reason},
											{engine_id, EngineID},
											{username, UserName},
											{flags, authPriv},
											{port, Port},
											{address, Address}]),
										{stop, shutdown, StateData}
							end;
						[] ->
							error_logger:info_report(["SNMP Manager User Not Found",
									{engine_id, EngineID},
									{username, UserName},
									{flags, authPriv},
									{port, Port},
									{address, Address}]),
							{stop, shutdown, StateData};
						{'EXIT', Reason} ->
							error_logger:error_report(["SNMP Manager SNMP Users Table Not Found",
									{error, Reason}]),
							{stop, shutdown, StateData}
					end;
				{'EXIT', Reason} ->
					error_logger:info_report(["SNMP Manager Decoding SNMP v3 Failed",
							{error, Reason},
							{flags, authPriv},
							{port, Port},
							{address, Address}]),
						{stop, shutdown, StateData}
			end;
		{'EXIT', Reason} ->
			error_logger:info_report(["SNMP Manager Decoding SNMP v3 Failed",
						{error, Reason},
						{flags, authPriv},
						{port, Port},
						{address, Address}]),
					{stop, shutdown, StateData}
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

-spec dec_des(PrivKey, MsgPrivParams, Data) -> Result
	when
		PrivKey :: list(),
		MsgPrivParams :: list(),
		Data :: [byte()],
		Result :: {ErrorStatus, ErrorIndex, Varbinds} | {error, Reason},
		ErrorStatus :: atom(),
		ErrorIndex :: integer(),
		Varbinds :: [snmp:varbinds()],
		Reason :: des_decryption_failed | term().
%% @doc Decrypt a SNMP packet using DES privacy protocol.
dec_des(PrivKey, MsgPrivParams, Data)
	when is_list(PrivKey) ->
	case catch snmp_usm:des_decrypt(PrivKey, MsgPrivParams, Data) of
		{ok, DecryptedData} ->
			case snmp_pdus:dec_scoped_pdu_data(DecryptedData) of
				#scopedPdu{data = #pdu{error_status = ErrorStatus,
						error_index = ErrorIndex, varbinds = Varbinds}} ->
					{ErrorStatus, ErrorIndex, Varbinds};
				ScopedPDU ->
					case snmp_pdus:dec_scoped_pdu(ScopedPDU) of
						#scopedPdu{data = #pdu{error_status = ErrorStatus,
								error_index = ErrorIndex, varbinds = Varbinds}} ->
							{ErrorStatus, ErrorIndex, Varbinds};
						_ ->
							{error, des_decryption_failed}
					end
			end;
		{'EXIT', Reason}->
			{error, Reason}
	end.

-spec dec_aes(PrivKey, MsgPrivParams, Data, EngineBoots, EngineTime) -> Result
	when
		PrivKey :: list(),
		MsgPrivParams :: list(),
		Data :: [byte()],
		EngineBoots :: integer(),
		EngineTime :: integer(),
		Result :: {ErrorStatus, ErrorIndex, Varbinds} | {error, Reason},
		ErrorStatus :: atom(),
		ErrorIndex :: integer(),
		Varbinds :: [snmp:varbinds()],
		Reason :: aes_decryption_failed | term().
%% @doc Decrypt a SNMP packet data using AES privacy protocol.
dec_aes(PrivKey, MsgPrivParams, Data, EngineBoots, EngineTime) ->
	case catch snmp_usm:aes_decrypt(PrivKey, MsgPrivParams, Data, EngineBoots, EngineTime) of
		{ok, DecryptedData} ->
			case snmp_pdus:dec_scoped_pdu_data(DecryptedData) of
				#scopedPdu{data = #pdu{error_status = ErrorStatus,
						error_index = ErrorIndex, varbinds = Varbinds}} ->
					{ErrorStatus, ErrorIndex, Varbinds};
				ScopedPDU ->
					case snmp_pdus:dec_scoped_pdu(ScopedPDU) of
						#scopedPdu{data = #pdu{error_status = ErrorStatus,
								error_index = ErrorIndex, varbinds = Varbinds}} ->
							{ErrorStatus, ErrorIndex, Varbinds};
						_ ->
							{error, aes_decryption_failed}
					end
			end;
		{'EXIT', Reason}->
			{error, Reason}
	end.

-spec handle_trap(Address, Port, TrapInfo) -> Result
	when
		Address :: inet:ip_address(),
		Port :: pos_integer(),
		TrapInfo :: {ErrorStatus, ErrorIndex, Varbinds},
		ErrorStatus :: atom(),
		ErrorIndex :: integer(),
		Varbinds :: [snmp:varbinds()],
		Result :: ignore | {error, Reason},
		Reason :: term().
%% @doc Send Varbinds to the associated trap handler modules.
handle_trap(Address, Port, {ErrorStatus, ErrorIndex, Varbinds})
		when ErrorStatus == noError ->
	case snmp_collector_utils:agent_name(Address) of
		{AgentName, TargetName} when is_list(AgentName), is_list(TargetName) ->
			case ets:match(snmpm_user_table, {user, AgentName,'$1','$2', '_'}) of
				[[Module, UserData]] ->
					Module:handle_trap(TargetName, {ErrorStatus, ErrorIndex, Varbinds}, UserData);
				[] ->
					snmp_collector_snmpm_user_default:handle_agent(transportDomainUdpIpv4, {Address, Port},
							trap, {ErrorStatus, ErrorIndex, Varbinds}, []),
					{error, agent_name_not_found}
			end;
		{error, Reason} ->
			snmp_collector_snmpm_user_default:handle_agent(transportDomainUdpIpv4, {Address, Port},
					trap, {ErrorStatus, ErrorIndex, Varbinds}, []),
			{error, Reason}
	end.

-spec flag(Flag) -> Result
	when
		Flag :: integer(),
		Result :: noAuthNoPriv |  authNoPriv |authPriv.
%% @doc Determine the flag of the trap.
flag(0) ->
	noAuthNoPriv;
flag(1) ->
	authNoPriv;
flag(3) ->
	authPriv.
