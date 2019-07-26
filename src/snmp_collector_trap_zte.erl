%%% snmp_collector_trap_zte.erl
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

%% @doc This module normalizes traps received on NBI from ZTE EMS.
%%
%% Varbinds are mapped to alarm attributes, using the MIBs avaialable,
%% and to VES attributes.
%%
%%	The following table shows the mapping between ZTE MIB attributes
%% and VES attributes.
%%
%% <h3> MIB Values and VNF Event Stream (VES) </h3>
%%
%% <p><table id="mt">
%% <thead>
%% 	<tr id="mt">
%% 		<th id="mt">MIB </th>
%%			<th id="mt">VNF Event Stream (VES)</th>
%%			<th id="mt">VES Value Type</th>
%% 	</tr>
%% </thead>
%% <tbody>
%%		<tr id="mt">
%% 		<td id="mt">alarmEventType</td>
%% 		<td id="mt">commonEventheader.eventType</td>
%%			<td id="mt">e.g. "Quality of Service Alarm"</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmProbableCause</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.probableCause</td>
%%			<td id="mt">3GPP 32.111-2 Annex B e.g. "Alarm Indication Signal (AIS)"</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmSpecificProblem</td>
%% 		<td id="mt">faultFields.specificProblem</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmOtherInfo</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmDetails</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmId</td>
%% 		<td id="mt">faultFields.alarmAdditionalInformation.alarmId</td>
%%			<td id="mt">Unique identifier of an alarm</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">systemDN</td>
%% 		<td id="mt">faultFields.alarmAdditionalInformation.reportingEntityID</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmNeIP</td>
%% 		<td id="mt">commonEventHeader.sourceId</td>
%%			<td id="mt">Distinguished Name (DN)</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt"></td>
%% 		<td id="mt">commonEventHeader.sourceName</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmNetype</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.NeType</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmPerceivedSeverity</td>
%% 		<td id="mt">faultFields.eventSeverity</td>
%%			<td id="mt">CRITICAL | MAJOR | MINOR | WARNING | INDETERMINATE | CLEARED</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">snmpTrapOID</td>
%% 		<td id="mt">commonEventHeader.eventName</td>
%%			<td id="mt">notifyNewAlarm | notifyChangedAlarm | notifyClearedAlarm</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">snmpTrapOID</td>
%% 		<td id="mt">faultsFields.alarmCondition</td>
%%			<td id="mt">Short name of the alarm condition/problem, such as a trap name.
%%					Should not have white space (e.g., tpLgCgiNotInConfig, BfdSessionDown, linkDown, etc…)</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmEventTime</td>
%% 		<td id="mt">commonEventHeader.startEpochMicrosec</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmMocObjectInstance</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.eventSourceType</td>
%%			<td id="mt">NE name</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmManagedObjectInstanceName</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.objectInstance</td>
%%			<td id="mt">Distinguished Name (DN)</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmAck</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmAckState</td>
%%			<td id="mt">acknowledged | unacknowledged</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmSystemType</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmSystemType</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmNeIP</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmNeIP</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">timeZoneID</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.timeZoneID</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmIndex</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmIndex</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmCodeName</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmCodeName</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmCode</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmCodeName</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">aid</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmAID</td>
%%			<td id="mt"></td>
%% 	</tr>
%% </tbody>
%% </table></p>

-module(snmp_collector_trap_zte).
-copyright('Copyright (c) 2016 - 2019 SigScale Global Inc.').

-include("snmp_collector.hrl").

-behaviour(snmpm_user).

%% export snmpm_user call backs.
-export([handle_error/3, handle_agent/5,
    handle_pdu/4, handle_trap/3, handle_inform/3,
    handle_report/3, event/1]).

%% support deprecated_time_unit()
-define(MILLISECOND, milli_seconds).
%-define(MILLISECOND, millisecond).
-define(MICROSECOND, micro_seconds).
%-define(MICROSECOND, microsecond).

% calendar:datetime_to_gregorian_seconds({{1970,1,1},{0,0,0}})
-define(EPOCH, 62167219200).

%%----------------------------------------------------------------------
%%  The snmp_collector_trap_zte public API
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
event([{"alarmId", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"alarmId", Value} | Acc]);
event([{"alarmEventTime", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"raisedTime", Value} | Acc]);
event([{"alarmNeIP", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"sourceId", Value} | Acc]);
event([{"systemDN", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"reportingEntityID", Value} | Acc]);
event([{"alarmMocObjectInstance", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"eventSourceType", Value} | Acc]);
event([{"alarmManagedObjectInstanceName", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"objectInstance", Value} | Acc]);
event([{"alarmSpecificProblem", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"specificProblem", Value} | Acc]);
event([{"alarmPerceivedSeverity", "1"} | T], Acc) ->
	event(T, [{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"alarmPerceivedSeverity", "2"} | T], Acc) ->
	event(T, [{"eventSeverity", ?ES_CRITICAL} | Acc]);
event([{"alarmPerceivedSeverity", "3"} | T], Acc) ->
	event(T, [{"eventSeverity", ?ES_MAJOR} | Acc]);
event([{"alarmPerceivedSeverity", "4"} | T], Acc) ->
	event(T, [{"eventSeverity", ?ES_MINOR} | Acc]);
event([{"alarmPerceivedSeverity", "5"} | T], Acc) ->
	event(T, [{"eventSeverity", ?ES_WARNING} | Acc]);
event([{"alarmPerceivedSeverity", "6"} | T], Acc) ->
	event(T, [{"eventSeverity", ?ES_CLEARED} | Acc]);
event([{"snmpTrapOID", "alarmNew"} | T], Acc) ->
	event(T, [{"eventName", ?EN_NEW}, {"alarmCondition", "alarmNew"} | Acc]);
event([{"snmpTrapOID", "alarmCleared"} | T], Acc) ->
	event(T, [{"eventName", ?EN_CLEARED}, {"alarmCondition", "alarmCleared"} | Acc]);
event([{"snmpTrapOID",  "alarmAckChange"} | T], Acc) ->
	event(T, [{"eventName", ?EN_CHANGED}, {"alarmCondition", "alarmAckChange"} | Acc]);
event([{"snmpTrapOID", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"alarmCondition", Value} | Acc]);
event([{"alarmEventType", "1"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Communication_System} | Acc]);
event([{"alarmEventType", "2"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Processing_Error} | Acc]);
event([{"alarmEventType", "3"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Environmental_Alarm} | Acc]);
event([{"alarmEventType", "4"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Quality_Of_Service_Alarm} | Acc]);
event([{"alarmEventType", "5"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Equipment_Alarm} | Acc]);
event([{"alarmEventType", "6"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Integrity_Violation} | Acc]);
event([{"alarmEventType", "7"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Operational_Violation} | Acc]);
event([{"alarmEventType", "8"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Physical_Violation} | Acc]);
event([{"alarmEventType", "9"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Security_Service_Or_Mechanism_Violation} | Acc]);
event([{"alarmEventType", "10"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Time_Domain_Violation} | Acc]);
event([{"alarmEventType", "11"} | T], Acc) ->
	event(T, [{"eventType", ?ET_Quality_Of_Service_Alarm} | Acc]);
event([{"alarmProbableCause", Value} | T], Acc) ->
	event(T, [{"probableCause", Value} | Acc]);
event([{"alarmAck", "1"} | T], Acc) ->
	event(T, [{"alarmAckState", ?ACK_Acknowledged} | Acc]);
event([{"alarmAck", "2"} | T], Acc) ->
	event(T, [{"alarmAckState", ?ACK_Unacknowledged} | Acc]);
event([{"alarmOtherInfo", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"additionalText", Value} | Acc]);
event([{"alarmNetype", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"Netype", Value} | Acc]);
event([{"alarmSystemType", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"alarmSystemType", Value} | Acc]);
event([{"alarmNeIP", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"alarmNeIP", Value} | Acc]);
event([{"timeZoneID", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"timeZoneID", Value} | Acc]);
event([{"alarmIndex", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"alarmIndex", Value} | Acc]);
event([{"alarmCodeName", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"alarmCodeName", Value} | Acc]);
event([{"alarmCode", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"alarmCode", Value} | Acc]);
event([{"aid", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"alarmAID", Value} | Acc]);
event([{"alarmAdditionalText", _, Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{"alarmAdditionalText", Value} | Acc]);
event([{Name, Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	event(T, [{Name, Value} | Acc]);
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
	case snmpm:name_to_oid(csIRPHeartbeatPeriod) of
		{ok, [HeartBeat]} ->
			NewHeartBeat = lists:flatten(HeartBeat ++ [0]),
			case lists:keyfind(NewHeartBeat, 2, Varbinds) of
				{varbind, _, _, _, _} ->
					true;
				false ->
					false
			end;
		{error, _Reason} ->
			false
	end.

