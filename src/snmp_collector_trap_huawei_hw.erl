%%% snmp_collector_trap_huawei_hw.erl
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

%% @doc This module normalizes traps received from Huawei (IT) agents.
%%
%% Varbinds are mapped to alarm attributes, using the MIBs avaialable,
%% and to VES attributes.
%%
%%	The following table shows the mapping between Huawei MIB attributes
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
%% 		<td id="mt">hwNmNorthboundEventType</td>
%% 		<td id="mt">commonEventheader.eventType</td>
%%		 	<td id="mt">e.g. "Quality of Service Alarm"</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundProbableCause</td>
%% 		<td id="mt">faultsFields.specificProblem</td>
%%		 	<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">reasonId</td>
%% 		<td id="mt">faultFields.alarmAdditionalInformation.probableCause</td>
%%		 	<td id="mt">3GPP 32.111-2 Annex B  e.g. "Alarm Indication Signal (AIS)</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundAdditionalInfo</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.additionalText</td>
%%		 	<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundSerialNo</td>
%% 		<td id="mt">faultFields.alarmAdditionalInformation.alarmId</td>
%%		 	<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundResourceIDs</td>
%% 		<td id="mt">commonEventHeader.sourceId</td>
%%		 	<td id="mt">Distinguished Name (DN)</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundNEName</td>
%% 		<td id="mt">commonEventHeader.sourceName</td>
%%		 	<td id="mt">String</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">snmpTrapOID</td>
%% 		<td id="mt">faultsFields.alarmCondition</td>
%%		 	<td id="mt">Short name of the alarm condition/problem,
%%		 			such as a trap name. Should not have white space
%%		 			(e.g., tpLgCgiNotInConfig, BfdSessionDown, linkDown, etc…)</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundDeviceType</td>
%% 		<td id="mt">faultsFields.eventSourceType</td>
%%		 	<td id="mt"> Managed Object Class (MOC) name</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundSeverity</td>
%% 		<td id="mt">faultFields.eventSeverity</td>
%%		 	<td id="mt">CRITICAL | MAJOR | MINOR | WARNING | INDETERMINATE | CLEARED</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundFaultFlag</td>
%% 		<td id="mt">commonEventHeader.eventName</td>
%%		 	<td id="mt">notifyNewAlarm | notifyChangedAlarm | notifyClearedAlarm</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundEventTime</td>
%% 		<td id="mt">commonEventHeader.startEpochMicrosec</td>
%%		 	<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundNEType</td>
%% 		<td id="mt">faultFields.alarmAdditionalInformation.networkElementType</td>
%%		 	<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundObjectInstance</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.objectInstance</td>
%%		 	<td id="mt">Distinguished Name (DN)</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundFaultFunction</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.faultFunction</td>
%%		 	<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundDeviceIP</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.deviceIP</td>
%%		 	<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundProbableRepair</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.proposedRepairActions</td>
%%		 	<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundReasonID</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.reasonID</td>
%%		 	<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundFaultID</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.faultID</td>
%%		 	<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundTrailName</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.trailName</td>
%%		 	<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundRootAlarm</td>
%% 		<td id="mt">aultsFields.alarmAdditionalInformation.rootAlarm</td>
%%		 	<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundGroupID</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.groupID</td>
%%		 	<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundMaintainStatus</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.maintainStatus</td>
%%		 	<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundConfirmStatus</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmAckState</td>
%%		 	<td id="mt">acknowledged | unacknowledged</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundEventName</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmEventName</td>
%%		 	<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundFaultID</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.faultId</td>
%%		 	<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundGroupID</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.groupId</td>
%%		 	<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundEventDetail</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.eventDetail</td>
%%		 	<td id="mt"></td>
%% 	</tr>
%% </tbody>
%% </table></p>

-module(snmp_collector_trap_huawei_hw).
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
%%  The snmp_collector_trap_huawei_hw public API
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
%% @doc Handle a fault event.
handle_fault(TargetName, Varbinds) ->
	try
		{ok, Pairs} = snmp_collector_utils:arrange_list(Varbinds),
		{ok, NamesValues} = snmp_collector_utils:oids_to_names(Pairs, []),
		AlarmDetails = fault(NamesValues),
		snmp_collector_utils:update_counters(huawei, TargetName, AlarmDetails),
		Event = snmp_collector_utils:generate_maps(TargetName, AlarmDetails, fault),
		snmp_collector_utils:log_event(Event),
		{ok, Url} = application:get_env(snmp_collector, ves_url),
		snmp_collector_utils:post_event(Event, Url)
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
fault([{"hwNmNorthboundSerialNo", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"alarmId", Value} | Acc]);
fault([{"hwNmNorthboundEventTime", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"raisedTime", Value} | Acc]);
fault([{"hwNmNorthboundResourceIDs", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"sourceId", Value} | Acc]);
fault([{"hwNmNorthboundNEName", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"sourceName", Value} | Acc]);
fault([{"hwNmNorthboundDeviceType", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"eventSourceType", Value} | Acc]);
fault([{"hwNmNorthboundObjectInstance", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"objectInstance", Value} | Acc]);
fault([{"snmpTrapOID", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"alarmCondition", Value} | Acc]);
fault([{"hwNmNorthboundSeverity", "Critical"} | T], Acc) ->
	fault(T, [{"eventSeverity", ?ES_CRITICAL} | Acc]);
fault([{"hwNmNorthboundSeverity", "Major"} | T], Acc) ->
	fault(T, [{"eventSeverity", ?ES_MAJOR} | Acc]);
fault([{"hwNmNorthboundSeverity", "Minor"} | T], Acc) ->
	fault(T, [{"eventSeverity", ?ES_MINOR} | Acc]);
fault([{"hwNmNorthboundSeverity", "Warning"} | T], Acc) ->
	fault(T, [{"eventSeverity", ?ES_WARNING} | Acc]);
fault([{"hwNmNorthboundSeverity", "Indeterminate"} | T], Acc) ->
	fault(T, [{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
fault([{"hwNmNorthboundRestoreStatus", 1} | T], Acc) ->
	fault(T, [{"eventSeverity", ?ES_CLEARED} | Acc]);
fault([{"hwNmNorthboundFaultFlag", "Fault"} | T], Acc) ->
	fault(T, [{"eventName", ?EN_NEW} | Acc]);
fault([{"hwNmNorthboundFaultFlag", "Change"} | T], Acc) ->
	fault(T, [{"eventName", ?EN_CHANGED} | Acc]);
fault([{"hwNmNorthboundFaultFlag", "Recovery"} | T], Acc) ->
	fault(T, [{"eventName", ?EN_CLEARED} | Acc]);
fault([{"hwNmNorthboundFaultFlag", "Acknowledge"} | T], Acc) ->
	fault(T, [{"eventName", ?ACK_Acknowledged} | Acc]);
fault([{"hwNmNorthboundFaultFlag", "Unacknowledge"} | T], Acc) ->
	fault(T, [{"eventName", ?ACK_Unacknowledged} | Acc]);
fault([{"hwNmNorthboundEventType", "Environment"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Environmental_Alarm} | Acc]);
fault([{"hwNmNorthboundEventType", "Communication"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Communication_System} | Acc]);
fault([{"hwNmNorthboundEventType", "Service"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Quality_Of_Service_Alarm} | Acc]);
fault([{"hwNmNorthboundEventType", "Processerror"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Processing_Error} | Acc]);
fault([{"hwNmNorthboundEventType", "Hardware"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Equipment_Alarm} | Acc]);
fault([{"hwNmNorthboundEventType", "Software"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Processing_Error} | Acc]);
fault([{"hwNmNorthboundEventType", "Run"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Processing_Error} | Acc]);
fault([{"hwNmNorthboundEventType", "Power"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Environmental_Alarm} | Acc]);
fault([{"hwNmNorthboundEventType", "Signal"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Communication_System} | Acc]);
fault([{"hwNmNorthboundEventType", "Relay"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Communication_System} | Acc]);
fault([{"hwNmNorthboundEventType", _} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Quality_Of_Service_Alarm} | Acc]);
fault([{"hwNmNorthboundProbableCause", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"specificProblem", Value}, {"probableCause", ?PC_Indeterminate} | Acc]);
fault([{"hwNmNorthboundProbableRepair", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"proposedRepairActions", Value} | Acc]);
fault([{"hwNmNorthboundConfirmStatus", 1} | T], Acc) ->
	fault(T, [{"alarmAckState", ?ACK_Acknowledged} | Acc]);
fault([{"hwNmNorthboundConfirmStatus", 2} | T], Acc) ->
	fault(T, [{"alarmAckState", ?ACK_Unacknowledged} | Acc]);
fault([{"hwNmNorthboundNEType", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"networkElementType", Value} | Acc]);
fault([{"hwNmNorthboundAdditionalInfo", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"additionalText", Value} | Acc]);
fault([{"hwNmNorthboundFaultFunction", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"eventFunction", Value} | Acc]);
fault([{"hwNmNorthboundDeviceIP", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"deviceIP", Value} | Acc]);
fault([{"hwNmNorthboundResourceIds", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"resourceIds", Value} | Acc]);
fault([{"hwNmNorthboundTrailName", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"trailName", Value} | Acc]);
fault([{"hwNmNorthboundRootAlarm", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"rootAlarm", Value} | Acc]);
fault([{"hwNmNorthboundGroupId", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"groupId", Value} | Acc]);
fault([{"hwNmNorthboundMaintainStatus", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"maintainStatus", Value} | Acc]);
fault([{"hwNmNorthboundEventName", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"alarmEventName", Value} | Acc]);
fault([{"hwNmNorthboundFaultID", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"eventId", Value} | Acc]);
fault([{"hwNmNorthboundGroupID", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"groupId", Value} | Acc]);
fault([{"hwNmNorthboundEventDetail", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"eventDetail", Value} | Acc]);
fault([{_, [$ ]} | T], Acc) ->
	fault(T, Acc);
fault([{_, []} | T], Acc) ->
	fault(T, Acc);
fault([{Name, Value} | T], Acc) ->
	fault(T, [{Name, Value} | Acc]);
fault([], Acc) ->
	Acc.

-spec domain(Varbinds) -> Result
	when
		Varbinds :: [Varbinds],
		Result :: fault | heartbeat | other.
%% @doc Check the domain of the event.
domain([_TimeTicks, {varbind, [1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0] , _, TrapName, _} | _T]) ->
	domain1(snmp_collector_utils:oid_to_name(TrapName)).
%% @hidden
domain1("hwNmNorthboundEventNotify") ->
	fault;
domain1("hwNmNorthboundEventNotifyCritical") ->
	fault;
domain1("hwNmNorthboundEventNotifyMajor") ->
	fault;
domain1("hwNmNorthboundEventNotifyMinor") ->
	fault;
domain1("hwNmNorthboundEventNotifyWarning") ->
	fault;
domain1("hwNmNorthboundEventNotifyIndefinitely") ->
	fault;
domain1("hwNmNorthboundEventNotifyUnknownSeverity") ->
	fault;
domain1("hwNmNorthboundEventSynchronizationStartNotify") ->
	fault;
domain1("hwNmNorthboundEventSynchronizationQueryResultNotify") ->
	fault;
domain1("hwNmNorthboundEventSynchronizationEndNotify") ->
	fault;
domain1("hwNmNorthboundEventKeepAlive") ->
	heartbeat;
domain1(_) ->
	other.

-spec probable_cause(ReasonId) -> ProbableCause
	when
		ReasonId :: string(),
		ProbableCause :: string().
%% @doc Look up a probable cause.
probable_cause("1") ->
	?PC_LOS;
probable_cause("2") ->
	?PC_LOS;
probable_cause("3") ->
	?PC_Clock_Synchronization_Problem;
probable_cause("4") ->
	?PC_Clock_Synchronization_Problem;
probable_cause("5") ->
	?PC_LOF;
probable_cause("6") ->
	?PC_Replaceable_Unit_Missing;
probable_cause("7") ->
	?PC_Replaceable_Unit_Type_Mismatch;
probable_cause("8") ->
	?PC_LOF;
probable_cause("9") ->
	?PC_Transmission_Error;
probable_cause("10") ->
	?PC_Performance_Degraded;
probable_cause("11") ->
	?PC_Performance_Degraded;
probable_cause(_EventDetail) ->
	"fault".

