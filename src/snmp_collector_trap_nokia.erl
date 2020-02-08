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
handle_trap(TargetName, {ErrorStatus, ErrorIndex, Varbinds}, UserData) ->
	case domain(Varbinds) of
		other ->
			snmp_collector_trap_generic:handle_trap(TargetName, {ErrorStatus,
					ErrorIndex, Varbinds}, UserData);
		heartbeat ->
			ignore;
		notification ->
			handle_notification(TargetName, Varbinds);
		fault ->
			handle_fault(TargetName, Varbinds)
	end;
handle_trap(TargetName, {Enteprise, Generic, Spec, Timestamp, Varbinds}, UserData) ->
	case domain(Varbinds) of
		other ->
			snmp_collector_trap_generic:handle_trap(TargetName,
					{Enteprise, Generic, Spec, Timestamp, Varbinds}, UserData);
		heartbeat ->
			ignore;
		notification ->
			handle_notification(TargetName, Varbinds);
		fault ->
			handle_fault(TargetName, Varbinds)
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

-spec handle_fault(TargetName, Varbinds) -> Result
	when
		TargetName :: string(),
		Varbinds :: snmp:varbinds(),
		Result :: ignore | {error, Reason},
		Reason :: term().
%% @doc Handle a fault fault.
handle_fault(TargetName, Varbinds) ->
	try
		{ok, Pairs} = snmp_collector_utils:arrange_list(Varbinds),
		{ok, NamesValues} = snmp_collector_utils:oids_to_names(Pairs, []),
		AlarmDetails = fault(NamesValues),
		snmp_collector_utils:update_counters(nokia, TargetName, AlarmDetails),
		Event = snmp_collector_utils:generate_maps(TargetName, AlarmDetails, fault),
		snmp_collector_utils:log_event(Event)
	of
		ok ->
			ignore;
		{error, Reason} ->
			{error, Reason}
	catch
		_:Reason ->
			{error, Reason}
	end.

-spec fault(OidNameValuePair) -> VesNameValuePair
	when
		OidNameValuePair :: [{OidName, OidValue}],
		OidName :: string(),
		OidValue :: string(),
		VesNameValuePair :: [{VesName, VesValue}],
		VesName :: string(),
		VesValue :: string().
%% @doc CODEC for event.
fault(NameValuePair) ->
	fault(NameValuePair, []).
%% @hidden
fault([{"nbiAlarmId", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"alarmId", Value} | Acc]);
fault([{"nbiEventTime", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"raisedTime", Value} | Acc]);
fault([{"nbiSequenceId", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"sourceId", Value} | Acc]);
fault([{"nbiOptionalInformation", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"sourceName", Value} | Acc]);
fault([{"nbiObjectInstance", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"objectInstance", Value} | Acc]);
fault([{"nbiSpecificProblem", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	case catch string:tokens(Value, "|") of
		[_, SpecificProblem] ->
			fault(T, [{"specificProblem", SpecificProblem},
					{"probableCause", probable_cause(SpecificProblem)} | Acc]);
		{'EXIT', _Reason} ->
			fault(T, Acc)
	end;
fault([{"snmpTrapOID", "nbiAlarmNewNotification"} | T], Acc) ->
	fault(T, [{"eventName", ?EN_NEW},
			{"alarmCondition", "alarmNewNotification"} | Acc]);
fault([{"snmpTrapOID", "nbiAlarmClearedNotification"} | T], Acc) ->
	fault(T, [{"eventName", ?EN_CLEARED},
			{"alarmCondition", "alarmClearedNotification"},
			{"eventSeverity", ?ES_CLEARED} | Acc]);
fault([{"snmpTrapOID", "nbiAlarmChangedNotification"} | T], Acc) ->
	fault(T, [{"eventName", ?EN_CHANGED},
			{"alarmCondition", "alarmChangedNotification"} | Acc]);
fault([{"snmpTrapOID", "nbiAlarmAckChangedNotification"} | T], Acc) ->
	fault(T, [{"eventName", ?EN_CHANGED},
			{"alarmCondition", "alarmAckChangedNotification"} | Acc]);
fault([{"nbiPerceivedSeverity", "1"} | T], Acc) ->
	fault(T, [{"eventSeverity", ?ES_CRITICAL} | Acc]);
fault([{"nbiPerceivedSeverity", "2"} | T], Acc) ->
	fault(T, [{"eventSeverity", ?ES_MAJOR} | Acc]);
fault([{"nbiPerceivedSeverity", "3"} | T], Acc) ->
	fault(T, [{"eventSeverity", ?ES_MINOR} | Acc]);
fault([{"nbiPerceivedSeverity", "4"} | T], Acc) ->
	fault(T, [{"eventSeverity", ?ES_WARNING} | Acc]);
fault([{"nbiPerceivedSeverity", "5"} | T], Acc) ->
	fault(T, [{"eventSeverity", ?ES_CLEARED} | Acc]);
fault([{"nbiPerceivedSeverity", "6"} | T], Acc) ->
	fault(T, [{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
fault([{"nbiAlarmType", "1"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Communication_System} | Acc]);
fault([{"nbiAlarmType", "2"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Quality_Of_Service_Alarm} | Acc]);
fault([{"nbiAlarmType", "3"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Processing_Error} | Acc]);
fault([{"nbiAlarmType", "4"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Equipment_Alarm} | Acc]);
fault([{"nbiAlarmType", "5"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Environmental_Alarm} | Acc]);
fault([{"nbiProposedRepairAction", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"proposedRepairActions", Value} | Acc]);
fault([{"nbiAckState", "1"} | T], Acc) ->
	fault(T, [{"alarmAckState", ?ACK_Acknowledged} | Acc]);
fault([{"nbiAckState", "2"} | T], Acc) ->
	fault(T, [{"alarmAckState", ?ACK_Unacknowledged} | Acc]);
fault([{"nbiAckSystemId", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"alarmAckSystemId", Value} | Acc]);
fault([{"nbiAckTime", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"alarmAckTime", Value} | Acc]);
fault([{"nbiAckUser", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"ackUserId", Value} | Acc]);
fault([{"nbiAdditionalText", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"additionalText", Value} | Acc]);
fault([{"nbiCommentText", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"eventComment", Value} | Acc]);
fault([{_, [$ ]} | T], Acc) ->
	fault(T, Acc);
fault([{_, []} | T], Acc) ->
	fault(T, Acc);
fault([{Name, Value} | T], Acc) ->
	fault(T, [{Name, Value} | Acc]);
fault([], Acc) ->
	Acc.

-spec handle_notification(TargetName, Varbinds) -> Result
	when
		TargetName :: string(),
		Varbinds :: snmp:varbinds(),
		Result :: ignore | {error, Reason},
		Reason :: term().
%% @doc Handle a notification fault.
handle_notification(TargetName, Varbinds) ->
	try
		{ok, Pairs} = snmp_collector_utils:arrange_list(Varbinds),
		{ok, NamesValues} = snmp_collector_utils:oids_to_names(Pairs, []),
		AlarmDetails = notification(NamesValues),
		Event = snmp_collector_utils:generate_maps(TargetName, AlarmDetails, notification),
		snmp_collector_utils:log_event(Event)
	of
		ok ->
			ignore;
		{error, Reason} ->
			{error, Reason}
	catch
		_:Reason ->
			{error, Reason}
	end.

-spec notification(OidNameValuePair) -> VesNameValuePair
	when
		OidNameValuePair :: [{OidName, OidValue}],
		OidName :: string(),
		OidValue :: string(),
		VesNameValuePair :: [{VesName, VesValue}],
		VesName :: string(),
		VesValue :: string().
%% @doc CODEC for event.
notification(NameValuePair) ->
	notification(NameValuePair, []).
%% @hidden
notification([{"snmpTrapOID", "nbiAlarmSummaryNotification"},
		{"nbiSequenceId", SequenceId}, {"nbiEventTime", RaisedTime},
		{"nbiEmsSynchronizationState", SynchronizationState},
		{"nbiNotSyncNEs", NotSyncNEs},
		{"nbiNumberCriticalAlarms", NoCriticalAlarms},
		{"nbiNumberMajorAlarms", NoMajorAlarms},
		{"nbiNumberMinorAlarms", NoMinorAlarms},
		{"nbiNumberWarningAlarms", NoWarningAlarms},
		{"nbiNumberClearedAlarms", NoClearedAlarms},
		{"nbiNumberIndeterminateAlarms", NoIndeterminateAlarms} | T], Acc) ->
	notification(T, [{"Id",  snmp_collector_utils:generate_identity(7)},
			{"eventName", ?EN_NEW},
			{"sourceId", SequenceId},
			{"raisedTime", RaisedTime},
			{"newState", inService},
			{"alarmCondition", "alarmSummaryNotification"},
			{"eventType", ?ET_Communication_System},
			{"notSyncNEs", NotSyncNEs},
			{"synchronizationState", SynchronizationState},
			{"numberCriticalAlarms", NoCriticalAlarms},
			{"numberMajorAlarms", NoMajorAlarms},
			{"numberMinorAlarms", NoMinorAlarms},
			{"numberWarningAlarms", NoWarningAlarms},
			{"numberClearedAlarms", NoClearedAlarms},
			{"numberIndeterminateAlarms", NoIndeterminateAlarms} | Acc]);
notification([_H | T], Acc) ->
	notification(T, Acc);
notification([], Acc) ->
	Acc.

-spec domain(Varbinds) -> Result
	when
		Varbinds :: [Varbinds],
		Result :: fault | heartbeat | notification | other.
%% @doc Check the domain of the event.
domain([_TimeTicks, {varbind, [1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0] , _, TrapName, _} | _T]) ->
	domain1(snmp_collector_utils:oid_to_name(TrapName)).
%% @hidden
domain1("nbiAlarmChangedNotification") ->
	fault;
domain1("nbiAlarmCommentNotification") ->
	fault;
domain1("nbiAlarmClearedNotification") ->
	fault;
domain1("nbiAlarmSyncNotification") ->
	fault;
domain1("nbiAlarmNewNotification") ->
	fault;
domain1("nbiAlarmAckChangedNotification") ->
	fault;
domain1("nbiAlarmSummaryNotification") ->
	notification;
domain1("nbiHeartbeatNotification") ->
	heartbeat;
domain1(_) ->
	other.

-spec probable_cause(EventCause) -> Result
	when
		EventCause :: string(),
		ProbableCause :: string(),
		Result :: EventCause | ProbableCause.
%% @hidden
probable_cause("BASE STATION CONNECTIVITY DEGRADED") ->
	?PC_Degraded_Signal;
probable_cause("LOW VOLTAGE") ->
	?PC_Power_Problem;
probable_cause("ToP master service 10.40.61.86 unusable") ->
	?PC_Unavailable;
probable_cause("Water Alarm") ->
	?PC_Low_Water;
probable_cause("CRITICAL LIMIT IN SECURITY REPORTING REACHED") ->
	?PC_Reduced_Logging_Capability;
probable_cause("CELL OPERATION DEGRADED") ->
	?PC_Performance_Degraded;
probable_cause("BASE STATION NOTIFICATION") ->
	?PC_Alarm_Indication_Signal;
probable_cause("FIRE") ->
	?PC_Fire;
probable_cause("ASP ACTIVATION FAILED") ->
	?PC_CPU_Cycles_Limit_Exceeded;
probable_cause("NE O&M CONNECTION FAILURE") ->
	?PC_Connection_Establishment_Error;
probable_cause("AUTOMATIC RECOVERY ACTION") ->
	?PC_Reinitialized;
probable_cause("WCDMA CELL OUT OF USE") ->
	?PC_Broadcast_Channel_Failure;
probable_cause("WORKING STATE CHANGE") ->
	?PC_Alarm_Indication_Signal;
probable_cause("D-CHANNEL FAILURE") ->
	?PC_LOS;
probable_cause("Synchronization lost") ->
	?PC_Loss_Of_Synchronization;
probable_cause("FAILURE IN D-CHANNEL ACTIVATION OR RESTORATION") ->
	?PC_Reinitialized;
probable_cause("BASE STATION CONNECTIVITY PROBLEM") ->
	?PC_Connection_Establishment_Error;
probable_cause("SIGNALING SERVICE INTERNAL FAILURE") ->
	?PC_LOS;
probable_cause("TRX RESTARTED") ->
	?PC_Reinitialized;
probable_cause("SCTP ASSOCIATION LOST") ->
	?PC_Communication_Protocol_Error;
probable_cause("CONFUSION IN BSSMAP SIGNALING") ->
	?PC_Signal_Label_Mismatch;
probable_cause("RECOVERY GROUP SWITCHOVER") ->
	?PC_Reinitialized;
probable_cause("BCF INITIALIZATION") ->
	?PC_Reinitialized;
probable_cause("MAINS FAIL") ->
	?PC_Power_Supply_Failure;
probable_cause("BTS Configuration Synchronisation Problem Notification") ->
	?PC_Configuration_Or_Customization_Error;
probable_cause("NTP Server 10.10.27.121 unavailable") ->
	?PC_Unavailable;
probable_cause("LOS on unit 0, Ethernet interface 1") ->
	?PC_LOS;
probable_cause("RECTIFIER FAULT") ->
	?PC_Rectifier_Failure;
probable_cause("ETHERNET LINK FAILURE") ->
	?PC_LAN_Error;
probable_cause("CELL FAULTY") ->
		?PC_Processor_Problem;
probable_cause("INTRUDER") ->
	?PC_Unauthorized_Access_Attempt;
probable_cause("BCCH MISSING") ->
	?PC_Power_Problem;
probable_cause("BASE STATION ANTENNA LINE PROBLEM") ->
	?PC_Antenna_Failure;
probable_cause("HUMIDITY") ->
	?PC_Humidity_Unacceptable;
probable_cause("UNIT RESTARTED") ->
	?PC_Reinitialized;
probable_cause("BCCH IS NOT AT PREFERRED BCCH TRX") ->
	?PC_Power_Problem;
probable_cause("PLAN BASED CONFIGURATION OPERATION ONGOING") ->
	undefined;
probable_cause("ALARM DATABASE UPLOAD IN PROGRESS") ->
	undefined;
probable_cause("MEAN HOLDING TIME ABOVE DEFINED THRESHOLD") ->
	?PC_Excessive_Rresponse_Time;
probable_cause("SIGNALLING MEASUREMENT REPORT LOST") ->
	?PC_Excessive_Rresponse_Time;
probable_cause("MANAGED OBJECT FAILED") ->
	?PC_Alarm_Indication_Signal;
probable_cause(EventCause) ->
	error_logger:info_report(["SNMP Manager Unrecognized Probable Cause",
			{probableCause, EventCause},
			{module, ?MODULE}]),
	EventCause.

