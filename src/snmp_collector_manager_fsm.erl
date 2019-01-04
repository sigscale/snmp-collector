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
-export([handle_pdu/2]).
% add handle_trap/2
-record(statedata, {socket :: inet:socket() | undefined,
		address :: inet:ip_address() | undefined,
		port :: non_neg_integer() | undefined,
		packet :: [byte()] | undefined}).

-define(SNMP_USE_V3, true).
-define(VMODULE,"USM").

-include_lib("snmp/include/snmp_types.hrl").
-include_lib("../../snmp-collector/include/snmp_collector.hrl").

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
								mnesia:read(snmp_users, UserName, read)
					end,
					case mnesia:ets(Fsearch) of
						[{snmp_users, _, AuthPass, PrivPass}] ->
							case catch snmp_pdus:dec_scoped_pdu_data(Data) of
								PDU when is_list(PDU) ->
									case snmp_collector_utils:security_params(EngineID, UserName, MsgAuthenticationParams,
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
													{error, Reason}
											end;
										{ok, usmHMACMD5AuthProtocol, usmAesCfb128Protocol} when Flag == 3 ->
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
													{error, Reason}
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
											PrivKey = snmp:passwd2localized_key(sha, PrivPass, EngineID),
											case dec_aes(PrivKey, MsgPrivParams, Data, EngineBoots, EngineTime) of
												{ErrorStatus, ErrorIndex, Varbinds} ->
													case handle_trap(Address, Port, {ErrorStatus, ErrorIndex, Varbinds}) of
														ignore ->
															{stop, shutdown, StateData};
														{error, Reason} ->
															error_logger:info_report(["SNMP Manager Agent Not Found",
																	{error, Reason},
																	{username, UserName},
																	{port, Port},
																	{address, Address}]),
															{stop, shutdown, StateData}
													end;
												{error, Reason} ->
													{error, Reason}
											end;
										{ok, usmHMACSHAAuthProtocol, usmAesCfb128Protocol} when Flag == 3 ->
											PrivKey = snmp:passwd2localized_key(sha, PrivPass, EngineID),
											case dec_aes(PrivKey, MsgPrivParams, Data, EngineBoots, EngineTime) of
												{ErrorStatus, ErrorIndex, Varbinds} ->
													case handle_trap(Address, Port, {ErrorStatus, ErrorIndex, Varbinds}) of
														ignore ->
															{stop, shutdown, StateData};
														{error, Reason} ->
															error_logger:info_report(["SNMP Manager Agent Not Found",
																	{error, Reason},
																	{username, UserName},
																	{port, Port},
																	{address, Address}]),
															{stop, shutdown, StateData}
													end;
												{error, Reason} ->
													{error, Reason}
											end;
										{error, Reason} ->
											error_logger:info_report(["SNMP Manager Incorrect Security Params",
													{error, Reason},
													{username, UserName},
													{port, Port},
													{address, Address}]),
											{stop, shutdown, StateData}
									end;
								{'EXIT', Reason} ->
									error_logger:info_report(["SNMP Manager Decoding SNMP v3 Failed",
											{reason, Reason},
											{port, Port},
											{address, Address}]),
										{stop, shutdown, StateData}
							end;
						_ ->
							error_logger:info_report(["SNMP Manager User Not Found",
									{username, UserName},
									{port, Port},
									{address, Address}]),
							{stop, shutdown, StateData}
					end;
				{'EXIT', Reason} ->
					error_logger:info_report(["SNMP Manager Decoding SNMP v3 Failed",
							{reason, Reason},
							{port, Port},
							{address, Address}]),
							{stop, shutdown, StateData}
		end;
		{'EXIT', Reason} ->
			error_logger:info_report(["SNMP Manager Decoding SNMP v3 Failed",
					{reason, Reason},
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
	when is_list(PrivKey), is_list(MsgPrivParams) ->
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
%% @doc Decrypt a SNMP packet data using DES privacy protocol.
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
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Send Varbinds to the associated trap handler modules.
handle_trap(Address, Port, {ErrorStatus, ErrorIndex, Varbinds})
		when ErrorStatus == noError ->
	case agent_name(Address, Port) of
		{"huawei", TargetName} ->
			snmp_collector_huawei_trap:handle_trap(TargetName, {ErrorStatus, ErrorIndex, Varbinds}, []);
		{"zte", TargetName} ->
			snmp_collector_zte_trap:handle_trap(TargetName, {ErrorStatus, ErrorIndex, Varbinds}, []);
		{"nec", TargetName} ->
			snmp_collector_nec_trap:handle_trap(TargetName, {ErrorStatus, ErrorIndex, Varbinds}, []);
		{"nokia", TargetName} ->
			snmp_collector_nokia_trap:handle_trap(TargetName, {ErrorStatus, ErrorIndex, Varbinds}, []);
		{"huawei-datacom", TargetName} ->
			snmp_collector_huawei_data_com_trap:handle_trap(TargetName, {ErrorStatus, ErrorIndex, Varbinds}, []);
		{"huawei-optical", TargetName} ->
			snmp_collector_huawei_data_com_trap:handle_trap(TargetName, {ErrorStatus, ErrorIndex, Varbinds}, []);
		{"emc", _TargetName} ->
			snmp_collector_snmpm_user_default:handle_agent(transportDomainUdpIpv4, {Address, Port},
					trap, {ErrorStatus, ErrorIndex, Varbinds}, []);
		{"hp", _TargetName} ->
			snmp_collector_snmpm_user_default:handle_agent(transportDomainUdpIpv4, {Address, Port},
					trap, {ErrorStatus, ErrorIndex, Varbinds}, []);
		{error, Reason} ->
		snmp_collector_snmpm_user_default:handle_agent(transportDomainUdpIpv4, {Address, Port},
				trap, {ErrorStatus, ErrorIndex, Varbinds}, []),
			{error, Reason}
	end.

-spec agent_name(Address, Port) -> Result
	when
		Address :: inet:ip_address(),
		Port :: pos_integer(),
		Result :: {AgentName, TargetName} | {error, Reason},
		AgentName :: string(),
		TargetName :: snmpm:target_name(),
		Reason :: target_name_not_found | agent_name_not_found | term().
%% @doc Identify the Agent Name for the received packet.
agent_name(Address, Port) ->
	case ets:match(snmpm_agent_table, {{'$1', '_'}, {Address ,Port}}) of
		[[TargetName]] ->
			case ets:match(snmpm_agent_table, {{TargetName, user_id},'$1'}) of
				[[AgentName]] ->
					{AgentName, TargetName};
				[] ->
					{error, agent_name_not_found}
			end;
		[] ->
			{error, target_name_not_found}
	end.
	

