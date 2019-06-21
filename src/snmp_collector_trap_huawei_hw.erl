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
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.probableCause</td>
%%		 	<td id="mt">3GPP 32.111-2 Annex B  e.g. "Alarm Indication Signal (AIS)"</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundEventDetail</td>
%% 		<td id="mt">faultFields.specificProblem</td>
%%		 	<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">hwNmNorthboundAdditionalInfo</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmDetails</td>
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
event([{"hwNmNorthboundSerialNo", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"alarmId", Value} | Acc]);
event([{"hwNmNorthboundResourceIDs", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"sourceId", Value} | Acc]);
event([{"hwNmNorthboundNEName", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"sourceName", Value} | Acc]);
event([{"hwNmNorthboundEventDetail", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"specificProblem", Value}, {"eventName", ?EN_NEW} | Acc]);
event([{"snmpTrapOID", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"alarmCondition", Value} | Acc]);
event([{"hwNmNorthboundDeviceType", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"eventSourceType", Value} | Acc]);
event([{"hwNmNorthboundSeverity", "Critical"} | T], Acc) ->
	event(T, [{"eventSeverity", ?ES_CRITICAL} | Acc]);
event([{"hwNmNorthboundSeverity", "Major"} | T], Acc) ->
	event(T, [{"eventSeverity", ?ES_MAJOR} | Acc]);
event([{"hwNmNorthboundSeverity", "Minor"} | T], Acc) ->
	event(T, [{"eventSeverity", ?ES_MINOR} | Acc]);
event([{"hwNmNorthboundSeverity", "Warning"} | T], Acc) ->
	event(T, [{"eventSeverity", ?ES_WARNING} | Acc]);
event([{"hwNmNorthboundSeverity", "Indeterminate"} | T], Acc) ->
	event(T, [{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"hwNmNorthboundFaultFlag", "Fault"} | T], Acc) ->
	event(T, [{"eventName", ?EN_NEW} | Acc]);
event([{"hwNmNorthboundFaultFlag", "Change"} | T], Acc) ->
	event(T, [{"eventName", ?EN_CHANGED} | Acc]);
event([{"hwNmNorthboundRestoreStatus", "Recovery"} | T], Acc) ->
	event(T, [{"eventName", ?EN_CLEARED} | Acc]);
event([{"hwNmNorthboundEventTime", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"raisedTime", Value} | Acc]);
event([{"hwNmNorthboundNEType", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"networkElementType", Value} | Acc]);
event([{"hwNmNorthboundObjectInstance", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"objectInstance", Value} | Acc]);
event([{"hwNmNorthboundProbableCause", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"probableCause", Value},
			{"eventType", ?ET_Quality_Of_Service_Alarm} | Acc]);
event([{"hwNmNorthboundEventType", "Environment"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Environmental_Alarm} | Acc]);
event([{"hwNmNorthboundEventType", "Communication"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Communication_System} | Acc]);
event([{"hwNmNorthboundEventType", "Service"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Quality_Of_Service_Alarm} | Acc]);
event([{"hwNmNorthboundEventType", "Processerror"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Processing_Error} | Acc]);
event([{"hwNmNorthboundEventType", "Hardware"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Equipment_Alarm} | Acc]);
event([{"hwNmNorthboundEventType", "Software"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Processing_Error} | Acc]);
event([{"hwNmNorthboundEventType", "Run"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Processing_Error} | Acc]);
event([{"hwNmNorthboundEventType", "Power"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Environmental_Alarm} | Acc]);
event([{"hwNmNorthboundEventType", "Signal"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Communication_System} | Acc]);
event([{"hwNmNorthboundEventType", "Relay"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Communication_System} | Acc]);
event([{"hwNmNorthboundAdditionalInfo", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"additionalText", Value} | Acc]);
event([{"hwNmNorthboundFaultFunction", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"faultFunction", Value} | Acc]);
event([{"hwNmNorthboundDeviceIP", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"deviceIP", Value} | Acc]);
event([{"hwNmNorthboundProbableRepair", Value} | T], Acc) ->
	event(T, [{"proposedRepairActions", Value} | Acc]);
event([{"hwNmNorthboundResourceIDs", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"resourceIDs", Value} | Acc]);
event([{"hwNmNorthboundReasonID", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"resonID", Value} | Acc]);
event([{"hwNmNorthboundFaultID", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"faultID", Value} | Acc]);
event([{"hwNmNorthboundTrailName", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"trailName", Value} | Acc]);
event([{"hwNmNorthboundRootAlarm", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"rootAlarm", Value} | Acc]);
event([{"hwNmNorthboundGroupID", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"groupID", Value} | Acc]);
event([{"hwNmNorthboundMaintainStatus", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"maintainStatus", Value} | Acc]);
event([{"hwNmNorthboundConfirmStatus", 1} | T], Acc) ->
	event(T, [{"alarmAckState", ?ACK_Acknowledged} | Acc]);
event([{"hwNmNorthboundConfirmStatus", 2} | T], Acc) ->
	event(T, [{"alarmAckState", ?ACK_Unacknowledged} | Acc]);
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
	case snmpm:name_to_oid(hwNmAgent) of
		{ok, [HeartBeat]} ->
			case lists:keyfind(HeartBeat, 2, Varbinds) of
				{varbind, _, _, _, _} ->
					true;
				false ->
					false
			end;
		{error, _Reason} ->
				false
	end.

