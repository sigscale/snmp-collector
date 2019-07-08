%%% snmp_collector_trap_nokia.erl
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

%% @doc This module normalizes traps received on NBI from Nokia EMS.
%%
%% Varbinds are mapped to alarm attributes, using the MIBs avaialable,
%% and to VES attributes.
%%
%%	The following table shows the mapping between Nokia MIB attributes
%% and VES attributes.
%%
%% <h3> MIB Values and VNF Event Stream (VES) </h3>
%%
%% <p><table id="mt">
%% <thead>
%% 	<tr id="mt">
%% 		<th id="mt">MIB Values</th>
%%			<th id="mt">VNF Event Stream (VES)</th>
%%			<th id="mt">VES Value Type</th>
%% 	</tr>
%% </thead>
%% <tbody>
%%		<tr id="mt">
%% 		<td id="mt">nbiAlarmType</td>
%% 		<td id="mt">commonEventheader.eventType</td>
%%			<td id="mt">e.g. "Quality of Service Alarm"</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">nbiProbableCause</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.probableCause</td>
%%			<td id="mt">3GPP 32.111-2 Annex B  e.g. "Alarm Indication Signal (AIS)"</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">nbiSpecificProblem</td>
%% 		<td id="mt">faultFields.specificProblem</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">nbiAdditionalText</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmDetails</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">nbiAlarmId</td>
%% 		<td id="mt">faultFields.alarmAdditionalInformation.alarmId</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">nbiOptionalInformation</td>
%% 		<td id="mt">commonEventHeader.sourceName</td>
%%			<td id="mt">String</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">nbiSequenceId</td>
%% 		<td id="mt">commonEventHeader.sourceId</td>
%%			<td id="mt">Distinguished Name (DN)</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">nbiObjectInstance</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.objectInstance</td>
%%			<td id="mt">Distinguished Name (DN)</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">nbiAckState</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmAckState</td>
%%			<td id="mt">acknowledged | unacknowledged</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">nbiAckSystemId</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmAckUserId</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">nbiAckTime</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmAckTime</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">nbiAckUser</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmAckUser</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">nbiPerceivedSeverity</td>
%% 		<td id="mt">faultFields.eventSeverity</td>
%%			<td id="mt">CRITICAL | MAJOR | MINOR | WARNING | INDETERMINATE | CLEARED</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">snmpTrapOID</td>
%% 		<td id="mt">faultsFields.alarmCondition</td>
%%			<td id="mt">Short name of the alarm condition/problem, such as a trap name.
%%					Should not have white space (e.g., tpLgCgiNotInConfig, BfdSessionDown, linkDown, etc…)</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">snmpTrapOID</td>
%% 		<td id="mt">commonEventHeader.eventName</td>
%%			<td id="mt">notifyNewAlarm | notifyChangedAlarm | notifyClearedAlarm</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">nbiEventTime</td>
%% 		<td id="mt">commonEventHeader.startEpochMicrosec</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">nbiProposedRepairAction</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.proposedRepairActions</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">nbiCommentText</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.eventComment</td>
%%			<td id="mt"></td>
%% 	</tr>
%% </tbody>
%% </table></p>

-module(snmp_collector_trap_nokia).
-copyright('Copyright (c) 2016 - 2019 SigScale Global Inc.').

-include("snmp_collector.hrl").

-behaviour(snmpm_user).

%% export snmpm_user call backs.
-export([handle_error/3, handle_agent/5,
    handle_pdu/4, handle_trap/3, handle_inform/3,
    handle_report/3]).

%% support deprecated_time_unit()
-define(MILLISECOND, milli_seconds).
%-define(MILLISECOND, millisecond).
-define(MICROSECOND, micro_seconds).
%-define(MICROSECOND, microsecond).

% calendar:datetime_to_gregorian_seconds({{1970,1,1},{0,0,0}})
-define(EPOCH, 62167219200).

%%----------------------------------------------------------------------
%%  The snmp_collector_trap_nokia public API
%%----------------------------------------------------------------------

-spec handle_error(ReqId, Reason, UserData) -> snmp:void()
	when
		ReqId :: integer(),
		Reason :: {unexpected_pdu, SnmpInfo} |
		{invalid_sec_info, SecInfo, SnmpInfo} |
		{empty_message, Addr, Port} | term(),
		SnmpInfo :: snmpm:snmp_gen_info(),
		SecInfo :: term(),
		Addr :: inet:ip_address(),
		Port ::  integer(),
		UserData :: term().
%% @doc Handle sending an "asynchronous" error to the user.
%% @private
handle_error(ReqId, Reason, UserData) ->
	snmp_collector_snmpm_user_default:handle_error(ReqId, Reason, UserData).

-spec handle_agent(Domain, Address, Type, SnmpInfo, UserData) -> Reply
	when
		Domain :: transportDomainUdpIpv4 | transportDomainUdpIpv6,
		Address :: {inet:ip_address(), inet:port_number()},
		Type :: pdu | trap | report | inform,
		SnmpInfo :: SnmpPduInfo | SnmpTrapInfo |
		SnmpReportInfo | SnmpInformInfo,
		SnmpPduInfo :: snmpm:snmp_gen_info(),
		SnmpTrapInfo :: snmpm:snmp_v1_trap_info(),
		SnmpReportInfo :: snmpm:snmp_gen_info(),
		SnmpInformInfo :: snmpm:snmp_gen_info(),
		UserData :: term(),
		Reply :: ignore.
%% @doc Handle messages received from an unknown agent.
%% @private
handle_agent(Domain, Address, Type, {ErrorStatus, ErrorIndex, Varbind}, UserData) ->
	snmp_collector_snmpm_user_default:handle_agent(Domain,
			Address , Type, {ErrorStatus, ErrorIndex, Varbind},
			UserData);
handle_agent(Domain, Address, Type, {Enteprise, Generic, Spec, Timestamp, Varbinds}, UserData) ->
	snmp_collector_snmpm_user_default:handle_agent(Domain,
			Address, Type, {Enteprise, Generic, Spec, Timestamp, Varbinds},
			UserData).

-spec handle_pdu(TargetName, ReqId, SnmpPduInfo, UserData) -> snmp:void()
	when
		TargetName :: snmpm:target_name(),
		ReqId :: term(),
		SnmpPduInfo :: snmpm:snmp_gen_info(),
		UserData :: term().
%% @doc Handle the reply to a asynchronous request.
%% @private
handle_pdu(TargetName, ReqId, SnmpResponse, UserData) ->
	snmp_collector_snmpm_user_default:handle_pdu(TargetName, ReqId, SnmpResponse, UserData).

-spec handle_trap(TargetName, SnmpTrapInfo, UserData) -> Reply
	when
		TargetName :: snmpm:target_name(),
		SnmpTrapInfo :: snmpm:snmp_v1_trap_info() | snmpm:snmp_gen_info(),
		UserData :: term(),
		Reply :: ignore.
%% @doc Handle a trap/notification message from an agent.
%% @private
handle_trap(TargetName, {_ErrorStatus, _ErrorIndex, Varbinds}, _UserData) ->
	case heartbeat(Varbinds) of
		true ->
			ignore;
		false ->
			{ok, Pairs} = snmp_collector_utils:arrange_list(Varbinds),
			{ok, NamesValues} = snmp_collector_utils:oids_to_names(Pairs, []),
			AlarmDetails = event(NamesValues),
			{CommonEventHeader, FaultFields} = snmp_collector_utils:generate_maps(TargetName, AlarmDetails),
			case snmp_collector_utils:log_events(CommonEventHeader, FaultFields) of
				ok ->
					ignore;
				{error, Reason} ->
					{error, Reason}
			end
	end;
handle_trap(TargetName, {_Enteprise, _Generic, _Spec, _Timestamp, Varbinds}, _UserData) ->
	case heartbeat(Varbinds) of
		true ->
			ignore;
		false ->
			{ok, Pairs} = snmp_collector_utils:arrange_list(Varbinds),
			{ok, NamesValues} = snmp_collector_utils:oids_to_names(Pairs, []),
			AlarmDetails = event(NamesValues),
			{CommonEventHeader, FaultFields} = snmp_collector_utils:generate_maps(TargetName, AlarmDetails),
			case snmp_collector_utils:log_events(CommonEventHeader, FaultFields) of
				ok ->
					ignore;
				{error, Reason} ->
					{error, Reason}
			end
	end.

-spec handle_inform(TargetName, SnmpInformInfo, UserData) -> Reply
	when
		TargetName :: snmpm:target_name(),
		SnmpInformInfo :: snmpm:snmp_gen_info(),
		UserData :: term(),
		Reply :: ignore.
%% @doc Handle a inform message.
%% @private
handle_inform(TargetName, SnmpInform, UserData) ->
	snmp_collector_snmpm_user_default:handle_inform(TargetName, SnmpInform, UserData),
	ignore.

-spec handle_report(TargetName, SnmpReport, UserData) -> Reply
	when
		TargetName :: snmpm:target_name(),
		SnmpReport :: snmpm:snmp_gen_info(),
		UserData :: term(),
		Reply :: ignore.
%% @doc Handle a report message.
%% @private
handle_report(TargetName, SnmpReport, UserData) ->
	snmp_collector_snmpm_user_default:handle_report(TargetName, SnmpReport, UserData),
	ignore.

%%----------------------------------------------------------------------
%%  The internal functions
%%----------------------------------------------------------------------

-spec event(OidNameValuePair) -> VesNameValuePair
	when
		OidNameValuePair :: [{OidName, OidValue}],
		OidName :: string(),
		OidValue :: string(),
		VesNameValuePair :: [{VesName, VesValue}],
		VesName :: string(),
		VesValue :: string().
%% @doc CODEC for event.
event(NameValuePair) ->
	event(NameValuePair, []).
%% @hidden
event([{"nbiAlarmId", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"alarmId", Value} | Acc]);
event([{"nbiOptionalInformation", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"sourceName", Value} | Acc]);
event([{"nbiSequenceId", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"sourceId", Value} | Acc]);
event([{"nbiObjectInstance", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"objectInstance", Value} | Acc]);
event([{"nbiSpecificProblem", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	case catch string:tokens(Value, "|") of
		[_, SpecificProblem] ->
			case maps:get(SpecificProblem, probable_causes(), ?PC_Indeterminate) of
				ProbableCause when is_list(ProbableCause) ->
					event(T, [{"specificProblem", SpecificProblem},
							{"probableCause", ProbableCause} ,
							{"eventType", ?ET_Quality_Of_Service_Alarm} | Acc]);
				{badmap, _Map} ->
					event(T, [{"specificProblem", SpecificProblem},
							{"probableCause", ?PC_Indeterminate},
							{"eventType", ?ET_Quality_Of_Service_Alarm} | Acc])
			end;
		{'EXIT', _Reason} ->
			event(T, Acc)
	end;
event([{"nbiPerceivedSeverity", "1"} | T], Acc) ->
	event(T, [{"eventSeverity", ?ES_CRITICAL} | Acc]);
event([{"nbiPerceivedSeverity", "2"} | T], Acc) ->
	event(T, [{"eventSeverity", ?ES_MAJOR} | Acc]);
event([{"nbiPerceivedSeverity", "3"} | T], Acc) ->
	event(T, [{"eventSeverity", ?ES_MINOR} | Acc]);
event([{"nbiPerceivedSeverity", "4"} | T], Acc) ->
	event(T, [{"eventSeverity", ?ES_WARNING} | Acc]);
event([{"nbiPerceivedSeverity", "5"} | T], Acc) ->
	event(T, [{"eventSeverity", ?ES_CLEARED} | Acc]);
event([{"nbiPerceivedSeverity", "6"} | T], Acc) ->
	event(T, [{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "nbiAlarmNewNotification"} | T], Acc) ->
	event(T, [{"eventName", ?EN_NEW},
			{"alarmCondition", "alarmNewNotification"} | Acc]);
event([{"snmpTrapOID", "nbiAlarmClearedNotification"} | T], Acc) ->
	event(T, [{"eventName", ?EN_CLEARED},
			{"alarmCondition", "alarmClearedNotification"},
			{"eventSeverity", ?ES_CLEARED} | Acc]);
event([{"snmpTrapOID", "nbiAlarmChangedNotification"} | T], Acc) ->
	event(T, [{"eventName", ?EN_CHANGED},
			{"alarmCondition", "alarmChangedNotification"} | Acc]);
event([{"snmpTrapOID", "nbiAlarmAckChangedNotification"} | T], Acc) ->
	event(T, [{"eventName", ?ES_CLEARED},
			{"alarmCondition", "alarmAckChangedNotification"} | Acc]);
event([{"nbiEventTime", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"raisedTime", Value} | Acc]);
event([{"nbiProposedRepairAction", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"proposedRepairActions", Value} | Acc]);
event([{"nbiAdditionalText", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"additionalText", Value} | Acc]);
event([{"nbiCommentText", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"eventComment", Value} | Acc]);
event([{"nbiAlarmType", "1"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Communication_System} | Acc]);
event([{"nbiAlarmType", "2"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Quality_Of_Service_Alarm} | Acc]);
event([{"nbiAlarmType", "3"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Processing_Error} | Acc]);
event([{"nbiAlarmType", "4"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Equipment_Alarm} | Acc]);
event([{"nbiAlarmType", "5"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Environmental_Alarm} | Acc]);
event([{"nbiAckState", "1"} | T], Acc) ->
	event(T, [{"alarmAckState", ?ACK_Acknowledged} | Acc]);
event([{"nbiAckState", "2"} | T], Acc) ->
	event(T, [{"alarmAckState", ?ACK_Unacknowledged} | Acc]);
event([{"nbiAckSystemId", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"alarmAckUserId", Value} | Acc]);
event([{"nbiAckTime", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"alarmAckTime", Value} | Acc]);
event([{"nbiAckUser", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"alarmAckUser", Value} | Acc]);
event([_H | T], Acc) ->
	event(T, Acc);
event([], Acc) ->
	Acc.

-spec heartbeat(Varbinds) -> Result
	when
		Varbinds :: [Varbinds],
		Result :: true | false.
%% @doc Verify if the event is a HeartBeat event or not.
heartbeat(Varbinds) ->
	case snmpm:name_to_oid(snmpTrapOID) of
		{ok, [HeartBeat]} ->
			NewHeartBeat = lists:flatten(HeartBeat ++ [0]),
			case lists:keyfind(NewHeartBeat, 2, Varbinds) of
				{varbind, _, _, Value, _}
						when Value == [1,3,6,1,4,1,28458,1,26,2,0,1,2]->
					true;
				{varbind, _, _, _Value, _} ->
					false;
				false ->
					false
			end;
		{error, _Reason} ->
			false
	end.

%% @hidden
probable_causes() ->
	#{"BASE STATION CONNECTIVITY DEGRADED" => ?PC_Degraded_Signal,
			"LOW VOLTAGE" => ?PC_Power_Problem,
			"ToP master service 10.40.61.86 unusable" => ?PC_Unavailable,
			"Water Alarm" => ?PC_Low_Water,
			"CRITICAL LIMIT IN SECURITY REPORTING REACHED" => ?PC_Reduced_Logging_Capability,
			"CELL OPERATION DEGRADED" => ?PC_Performance_Degraded,
			"BASE STATION NOTIFICATION" => ?PC_Alarm_Indication_Signal,
			"FIRE" => ?PC_Fire,
			"ASP ACTIVATION FAILED" => ?PC_CPU_Cycles_Limit_Exceeded,
			"NE O&M CONNECTION FAILURE" => ?PC_Connection_Establishment_Error,
			"AUTOMATIC RECOVERY ACTION" => ?PC_Reinitialized,
			"WCDMA CELL OUT OF USE" => ?PC_Broadcast_Channel_Failure,
			"WORKING STATE CHANGE" => ?PC_Alarm_Indication_Signal,
			"D-CHANNEL FAILURE" => ?PC_LOS,
			"Synchronization lost" => ?PC_Loss_Of_Synchronization,
			"FAILURE IN D-CHANNEL ACTIVATION OR RESTORATION" => ?PC_Reinitialized,
			"BASE STATION CONNECTIVITY PROBLEM" => ?PC_Connection_Establishment_Error,
			"SIGNALING SERVICE INTERNAL FAILURE" => ?PC_LOS,
			"TRX RESTARTED" => ?PC_Reinitialized,
			"SCTP ASSOCIATION LOST" => ?PC_Communication_Protocol_Error,
			"CONFUSION IN BSSMAP SIGNALING" => ?PC_Signal_Label_Mismatch,
			"RECOVERY GROUP SWITCHOVER" => ?PC_Reinitialized,
			"BCF INITIALIZATION" => ?PC_Reinitialized,
			"MAINS FAIL" => ?PC_Power_Supply_Failure,
			"INTRUDER" => ?PC_Unauthorized_Access_Attempt,
			"BTS Configuration Synchronisation Problem Notification" =>
					?PC_Configuration_Or_Customization_Error,
			"BCCH MISSING" => ?PC_Power_Problem,
			"NTP Server 10.10.27.121 unavailable" => ?PC_Unavailable,
			"LOS on unit 0, Ethernet interface 1" => ?PC_LOS,
			"RECTIFIER FAULT" => ?PC_Rectifier_Failure,
			"ETHERNET LINK FAILURE" => ?PC_LAN_Error,
			"CELL FAULTY" => ?PC_Processor_Problem,
			"BASE STATION ANTENNA LINE PROBLEM" => ?PC_Antenna_Failure,
			"BASE STATION OPERATION DEGRADED" => ?PC_Performance_Degraded,
			"SYSTEM CLOCK OUT-OF-SYNC WITH NTP SERVER" => ?PC_Real_Time_Clock_Failure,
			"DATABASE DISK UPDATES ARE PREVENTED" => ?PC_Software_Download_Failure,
			"HUMIDITY" => ?PC_Humidity_Unacceptable,
			"HIGH TEMPERATURE" => ?PC_High_Temperature,
			"UNIT RESTARTED" => ?PC_Reinitialized,
			"BCCH IS NOT AT PREFERRED BCCH TRX" => ?PC_Power_Problem,
			"PLAN BASED CONFIGURATION OPERATION ONGOING" => "Plan based configuration operation ongoing",
			"ALARM DATABASE UPLOAD IN PROGRESS" => "Alarm Database upload in progress",
			"MEAN HOLDING TIME ABOVE DEFINED THRESHOLD" => ?PC_Excessive_Rresponse_Time,
			"SIGNALLING MEASUREMENT REPORT LOST" => ?PC_Resource_at_or_Nearing_Capacity,
			"MANAGED OBJECT FAILED" => ?PC_Alarm_Indication_Signal}.

