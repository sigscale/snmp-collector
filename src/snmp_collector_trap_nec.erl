%%% snmp_collector_trap_nec.erl
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

%% @doc This module normalizes traps received on NBI from NEC EMS.
%%
%% Varbinds are mapped to alarm attributes, using the MIBs avaialable,
%% and to VES attributes.
%%
%%	The following table shows the mapping between NEC MIB attributes
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
%% 		<td id="mt">ospDtlProbableCauseQualifier</td>
%% 		<td id="mt">alarmId</td>
%%			<td id="mt">Unique identifier of an alarm</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlSnmpTrapAddress</td>
%% 		<td id="mt">sourceId</td>
%%			<td id="mt">Distinguished Name (DN)</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlAlarmOccurredPlace</td>
%% 		<td id="mt">sourceName</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlNeName</td>
%% 		<td id="mt">eventSourceType</td>
%%			<td id="mt">NE name</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlNeTypeText</td>
%% 		<td id="mt">objectInstanceType</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">snmpTrapOID</td>
%% 		<td id="mt">alarmCondition</td>
%%			<td id="mt">Short name of the alarm condition/problem, such as a trap name.
%%             Should not have white space (e.g., tpLgCgiNotInConfig, BfdSessionDown, linkDown, etc…)</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlAlarmSeverityText</td>
%% 		<td id="mt">eventSeverity</td>
%%			<td id="mt">CRITICAL | MAJOR | MINOR | WARNING | INDETERMINATE | CLEARED</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlAlarmTypeText</td>
%% 		<td id="mt">eventType</td>
%%			<td id="mt">e.g. "Quality of Service Alarm"</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlProbableCauseText</td>
%% 		<td id="mt">probableCause</td>
%%			<td id="mt">3GPP 32.111-2 Annex B e.g. "Alarm Indication Signal (AIS)"</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlAlarmItemStatusText</td>
%% 		<td id="mt">eventName</td>
%%			<td id="mt">notifyNewAlarm | notifyChangedAlarm | notifyClearedAlarm</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlAlarmDate and ospDtlAlarmTime </td>
%% 		<td id="mt">raisedTime/clearTime</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlAlarmTrapSequenceNumber</td>
%% 		<td id="mt">alarmTrapSequenceNumber</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlAlarmSeverity</td>
%% 		<td id="mt">alarmSeverity</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlAlarmSource</td>
%% 		<td id="mt">alarmSource</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlNotificationId</td>
%% 		<td id="mt">notificationId</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlSerialNeId</td>
%% 		<td id="mt">serialNeId</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlMoIId</td>
%% 		<td id="mt">moIId</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlAlarmItem</td>
%% 		<td id="mt">alarmItem</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlIsClearable</td>
%% 		<td id="mt">isClearable</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlProbableCauseStd</td>
%% 		<td id="mt">probableCauseStd</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlAdditionalInfo</td>
%% 		<td id="mt">additionalInfo</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlEquipmentAlarmType</td>
%% 		<td id="mt">equipmentAlarmType</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlNeType</td>
%% 		<td id="mt">neType</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlAlarmType</td>
%% 		<td id="mt">alarmType</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlProbableCause</td>
%% 		<td id="mt">probableCauseNo</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlEventCount</td>
%% 		<td id="mt">eventCount</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlEventTime</td>
%% 		<td id="mt">eventTime</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlEventType</td>
%% 		<td id="mt">eventTypeNo</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlAlarmItemStatus</td>
%% 		<td id="mt">alarmItemStatus</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlNeIPAddress</td>
%% 		<td id="mt">neIPAddress</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlOppIPAddress1</td>
%% 		<td id="mt">oppIpAddress</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlOppNEName1</td>
%% 		<td id="mt">oppNeName</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlAdditionalText1</td>
%% 		<td id="mt">additionalText1</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlAdditionalText2</td>
%% 		<td id="mt">additionalText2</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlAdditionalText3</td>
%% 		<td id="mt">additionalText3</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ospDtlAdditionalText5</td>
%% 		<td id="mt">additionalText5</td>
%%			<td id="mt"></td>
%% 	</tr>
%% </tbody>
%% </table></p>

-module(snmp_collector_trap_nec).
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
%%  The snmp_collector_trap_nec public API
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
	snmp_collector_snmpm_user_default:handle_agent(Domain, Address, Type, 
			{Enteprise, Generic, Spec, Timestamp, Varbinds}, UserData).

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
handle_trap(TargetName, {_ErrorStatus, _ErrorIndex, Varbinds}, UserData) ->
	case domain(Varbinds) of
		other ->
			ignore;
		fault ->
			handle_fault(TargetName, UserData, Varbinds)
	end;
handle_trap(TargetName, {_Enteprise, _Generic, _Spec, _Timestamp, Varbinds}, UserData) ->
	case domain(Varbinds) of
		other ->
			ignore;
		fault ->
			handle_fault(TargetName, UserData, Varbinds)
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

-spec handle_fault(TargetName, UserData, Varbinds) -> Result
	when
		TargetName :: string(),
		UserData :: term(),
		Varbinds :: snmp:varbinds(),
		Result :: ignore | {error, Reason},
		Reason :: term().
%% @doc Handle a fault fault.
handle_fault(TargetName, UserData, Varbinds) ->
	try
		{ok, Pairs} = snmp_collector_utils:arrange_list(Varbinds),
		{ok, NamesValues} = snmp_collector_utils:oids_to_names(Pairs, []),
		case fault(NamesValues) of
			[{[],[]}] ->
				ok;
			AlarmDetails ->
				snmp_collector_utils:update_counters(nec, TargetName, AlarmDetails),
				Address = lists:keyfind(address, 1, UserData),
				Event = snmp_collector_utils:create_event(TargetName,
						[{"alarmIp", Address} | AlarmDetails], fault),
				snmp_collector_utils:send_event(Event)
		end
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
	case lists:keyfind("ospDtlAlarmItemStatusText", 1, NameValuePair) of
		false ->
			[{[],[]}];
		{_, Value} ->
			fault(NameValuePair, Value, [])
	end.
%% @hidden
fault([{"ospDtlProbableCauseQualifier", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"alarmId", Value}, {"nfVendorName", "nec"} | Acc]);
fault([{"ospDtlSnmpTrapAddress", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"sourceId", Value} | Acc]);
fault([{"ospDtlAlarmOccurredPlace", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"sourceName", Value} | Acc]);
fault([{"ospEventNeName", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"eventSourceType", Value} | Acc]);
fault([{"ospDtlAlarmOccurredPlace", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"sourceName", Value} | Acc]);
fault([{"ospDtlNeName", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"objectInstance", Value} | Acc]);
fault([{"ospDtlNeTypeText", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"objectInstanceType", Value} | Acc]);
fault([{"snmpTrapOID", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"alarmCondition", Value} | Acc]);
fault([{"ospDtlAlarmSeverityText", "Cleared"} | T], AC, Acc) ->
	fault(T, AC, [{"eventSeverity", ?ES_CLEARED} | Acc]);
fault([{"ospDtlAlarmSeverityText", "Indeterminate"} | T], AC, Acc) ->
	fault(T, AC, [{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
fault([{"ospDtlAlarmSeverityText", "Warning"} | T], AC, Acc) ->
	fault(T, AC, [{"eventSeverity", ?ES_WARNING} | Acc]);
fault([{"ospDtlAlarmSeverityText", "Minor"} | T], AC, Acc) ->
	fault(T, AC, [{"eventSeverity", ?ES_MINOR} | Acc]);
fault([{"ospDtlAlarmSeverityText", "Major"} | T], AC, Acc) ->
	fault(T, AC, [{"eventSeverity", ?ES_MAJOR} | Acc]);
fault([{"ospDtlAlarmSeverityText", "Critical"} | T], AC, Acc) ->
	fault(T, AC, [{"eventSeverity", ?ES_CRITICAL} | Acc]);
fault([{"ospDtlAlarmTypeText", "equipmentAlarm"} | T], AC, Acc) ->
	fault(T, AC, [{"eventType", ?ET_Equipment_Alarm} | Acc]);
fault([{"ospDtlAlarmTypeText", "environmentalAlarm"} | T], AC, Acc) ->
	fault(T, AC, [{"eventType", ?ET_Environmental_Alarm} | Acc]);
fault([{"ospDtlAlarmTypeText", "communicationsAlarm"} | T], AC, Acc) ->
	fault(T, AC, [{"eventType", ?ET_Communication_System} | Acc]);
fault([{"ospDtlAlarmTypeText", "processingErrorAlarm"} | T], AC, Acc) ->
	fault(T, AC, [{"eventType", ?ET_Processing_Error} | Acc]);
fault([{"ospDtlAlarmTypeText", "qualityofServiceAlarm"} | T], AC, Acc) ->
	fault(T, AC, [{"eventType", ?ET_Processing_Error} | Acc]);
fault([{"ospDtlAlarmTypeText", "integrityViolation"} | T], AC, Acc) ->
	fault(T, AC, [{"eventType", ?ET_Integrity_Violation} | Acc]);
fault([{"ospDtlAlarmTypeText", "operationalViolation"} | T], AC, Acc) ->
	fault(T, AC, [{"eventType", ?ET_Operational_Violation} | Acc]);
fault([{"ospDtlAlarmTypeText", "physicalViolation"} | T], AC, Acc) ->
	fault(T, AC, [{"eventType", ?ET_Physical_Violation} | Acc]);
fault([{"ospDtlAlarmTypeText", "securityServiceOrMechanismViolation"} | T], AC, Acc) ->
	fault(T, AC, [{"eventType", ?ET_Security_Service_Or_Mechanism_Violation} | Acc]);
fault([{"ospDtlAlarmTypeText", "timeDomainViolation"} | T], AC, Acc) ->
	fault(T, AC, [{"eventType", ?ET_Time_Domain_Violation} | Acc]);
fault([{"ospDtlProbableCauseText", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"probableCause", probable_cause(Value)} | Acc]);
fault([{"ospDtlAlarmItemStatusText", "Alarm" = AC} | T], AC, Acc) ->
	fault(T, AC, [{"eventName", ?EN_NEW} | Acc]);
fault([{"ospDtlAlarmItemStatusText", "Normal" = AC} | T], AC, Acc) ->
	fault(T, AC, [{"eventName", ?EN_CLEARED} | Acc]);
fault([{"ospDtlAlarmDate", Date}, {"ospDtlAlarmTime", Time} | T], AC, Acc)
      when AC == "Alarm", length(Date) > 0, Date =/= [$ ],
		length(Time) > 0, Time =/= [$ ] ->
	DateTime = Date ++ "-" ++ Time,
   fault(T, AC, [{"raisedTime", DateTime} | Acc]);
fault([{"ospDtlAlarmDate", Date}, {"ospDtlAlarmTime", Time} | T], AC, Acc)
      when AC == "Normal", length(Date) > 0, Date =/= [$ ],
		length(Time) > 0, Time =/= [$ ] ->
	DateTime = Date ++ "-" ++ Time,
   fault(T, AC, [{"clearedTime", DateTime} | Acc]);
fault([{"ospDtlAlarmTrapSequenceNumber", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"alarmTrapSequenceNumber", Value} | Acc]);
fault([{"ospDtlAlarmSeverity", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"alarmSeverity", Value} | Acc]);
fault([{"ospDtlAlarmSource", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"alarmSource", Value} | Acc]);
fault([{"ospDtlNotificationId", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"notificationId", Value} | Acc]);
fault([{"ospDtlSerialNeId", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"serialNeId", Value} | Acc]);
fault([{"ospDtlMoIId", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"moIId", Value} | Acc]);
fault([{"ospDtlAlarmItem", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"alarmItem", Value} | Acc]);
fault([{"ospDtlIsClearable", 0} | T], AC, Acc) ->
	fault(T, AC, [{"isClearable", "Manual clearing is enabled."} | Acc]);
fault([{"ospDtlIsClearable", 1} | T], AC, Acc) ->
	fault(T, AC, [{"isClearable", "Manual clearing is disabled."} | Acc]);
fault([{"ospDtlProbableCauseStd", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"probableCauseStd", Value} | Acc]);
fault([{"ospDtlProbableCauseQualifier", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"probableCauseQualifier", Value} | Acc]);
fault([{"ospDtlAdditionalInfo", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"additionalInfo", Value} | Acc]);
fault([{"ospDtlEquipmentAlarmType", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"equipmentAlarmType", Value} | Acc]);
fault([{"ospDtlNeType", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"neType", Value} | Acc]);
fault([{"ospDtlAlarmType", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"alarmType", Value} | Acc]);
fault([{"ospDtlProbableCause", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"probableCauseNo", Value} | Acc]);
fault([{"ospDtlEventCount", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"eventCount", Value} | Acc]);
fault([{"ospDtlEventTime", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"eventTime", Value} | Acc]);
fault([{"ospDtlEventType", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"eventTypeNo", Value} | Acc]);
fault([{"ospDtlAlarmItemStatus", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"alarmItemStatus", Value} | Acc]);
fault([{"ospDtlAdditionalText5", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"additionalText5", Value} | Acc]);
fault([{"ospDtlNeIPAddress", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"neIPAddress", Value} | Acc]);
fault([{"ospDtlOppIPAddress1", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"oppIpAddress", Value} | Acc]);
fault([{"ospDtlOppNEName1", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"oppNeName", Value} | Acc]);
fault([{"ospDtlAdditionalText1", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"additionalText1", Value} | Acc]);
fault([{"ospDtlAdditionalText2", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"additionalText2", Value} | Acc]);
fault([{"ospDtlAdditionalText3", Value} | T], AC, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, AC, [{"additionalText3", Value} | Acc]);
fault([{_, [$ ]} | T], AC, Acc) ->
	fault(T, AC, Acc);
fault([{_, []} | T], AC, Acc) ->
	fault(T, AC, Acc);
fault([{Name, Value} | T], AC, Acc) ->
	fault(T, AC, [{Name, Value} | Acc]);
fault([], _, Acc) ->
	Acc.

-spec domain(Varbinds) -> Result
	when
		Varbinds :: [Varbinds],
		Result :: fault | other.
%% @doc Check the domain of the event.
domain([_TimeTicks, {varbind, [1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0] , _, TrapName, _} | _T]) ->
	domain1(snmp_collector_utils:oid_to_name(TrapName)).
%% @hidden
domain1("alarmDetails") ->
	fault;
domain1(_) ->
	other.

-spec probable_cause(ProbableCauseCode) -> Result
	when
		ProbableCauseCode :: string(),
		Result :: ProbableCause | ok,
		ProbableCause :: string().
%% @doc Look up a probable cause.
probable_cause("indeterminate") ->
	?PC_Indeterminate;
probable_cause("alarmIndicationSignal") ->
	?PC_Alarm_Indication_Signal;
probable_cause("broadcastChannelFailure") ->
	?PC_Broadcast_Channel_Failure;
probable_cause("callSetupFailure") ->
	?PC_Call_Setup_Failure;
probable_cause("communicationsReceiveFailure") ->
	?PC_Communications_Receive_Failure;
probable_cause("communicationsTransmitFailure") ->
	?PC_Communications_Transmit_Failure;
probable_cause("connectionEstablishmentError") ->
	?PC_Connection_Establishment_Error;
probable_cause("degradedSignal") ->
	?PC_Degraded_Signal;
probable_cause("demodulationFailure") ->
	?PC_Demodulation_Failure;
probable_cause("farEndReceiverFailure") ->
	?PC_FERF;
probable_cause("invalidMessageReceived") ->
	?PC_Invalid_Message_Received;
probable_cause("lossOfFrame") ->
	?PC_LOF;
probable_cause("lossOfPointer") ->
	?PC_LOP;
probable_cause("lossOfSignal") ->
	?PC_LOS;
probable_cause("modulationFailure") ->
	?PC_Modulaion_Failure;
probable_cause("payloadTypeMismatch") ->
	?PC_Payload_Type_Mismatch;
probable_cause("transmissionError") ->
	?PC_Transmission_Error;
probable_cause("remoteAlarmInterface") ->
	?PC_Remote_Alarm_Interface;
probable_cause("routingFailure") ->
	?PC_Routing_Failure;
probable_cause("pathTraceMismatch") ->
	?PC_Path_Trace_Mismatch;
probable_cause("unavailable") ->
	?PC_Unavailable;
probable_cause("signalLabelMismatch") ->
	?PC_Signal_Label_Mismatch;
probable_cause("lossOfMultiFrame") ->
	?PC_Loss_Of_Multi_Frame;
probable_cause("antennaFailure") ->
	?PC_Antenna_Failure;
probable_cause("backPlaneFailure") ->
	?PC_Back_Plane_Failure;
probable_cause("batteryChargingFailure") ->
	?PC_Battery_Charging_Failure;
probable_cause("dataSetProblem") ->
	?PC_Data_Set_Problem;
probable_cause("diskFailure") ->
	?PC_Disk_Failure;
probable_cause("equipmentIdentifierDuplication") ->
	?PC_Equipment_Identifier_Duplication;
probable_cause("externalIfDeviceProblem") ->
	?PC_External_If_Device_Problem;
probable_cause("frequencyHoppingFailure") ->
	?PC_Frequency_Hopping_Failure;
probable_cause("lineCardProblem") ->
	?PC_Line_Card_Problem;
probable_cause("lossOfRedundancy") ->
	?PC_Loss_Of_Redundancy;
probable_cause("lossOfSynchronization") ->
	?PC_Loss_Of_Synchronization;
probable_cause("multiplexerProblem") ->
	?PC_Multiplexer_Problem;
probable_cause("nEIdentifierDuplication") ->
	?PC_NE_Identifier_Duplication;
probable_cause("powerProblem") ->
	?PC_Power_Problem;
probable_cause("powerSupplyFailure") ->
	?PC_Power_Supply_Failure;
probable_cause("protectionPathFailure") ->
	?PC_Protection_Path_Failure;
probable_cause("protectingResourceFailure") ->
	?PC_Protecting_Resource_Failure;
probable_cause("protectionMechanismFailure") ->
	?PC_Protection_Mechanism_Failure;
probable_cause("realTimeClockFailure") ->
	?PC_Real_Time_Clock_Failure;
probable_cause("receiverFailure") ->
	?PC_Receiver_Failure;
probable_cause("replaceableUnitMissing") ->
	?PC_Replaceable_Unit_Missing;
probable_cause("replaceableUnitTypeMismatch") ->
	?PC_Replaceable_Unit_Type_Mismatch;
probable_cause("signalQualityEvaluationFailure") ->
	?PC_Signal_Quality_Evaluation_Failure;
probable_cause("synchronizationSourceMismatch") ->
	?PC_Synchronization_Source_Mismatch;
probable_cause("terminalProblem") ->
	?PC_Terminal_Problem;
probable_cause("timingProblem") ->
	?PC_Timing_Problem;
probable_cause("transceiverFailure") ->
	?PC_Transceiver_Failure;
probable_cause("transmitterFailure") ->
	?PC_Transmitter_Failure;
probable_cause("trunkCardProblem") ->
	?PC_Trunk_Card_Problem;
probable_cause("replaceableUnitProblem") ->
	?PC_Replaceable_Unit_Problem;
probable_cause("airCompressorFailure") ->
	?PC_Air_Compressor_Failure;
probable_cause("airConditioningFailure") ->
	?PC_Air_Conditioning_Failure;
probable_cause("airDryerFailure") ->
	?PC_Air_Dryer_Failure;
probable_cause("batteryDischarging") ->
	?PC_Battery_Discharging;
probable_cause("batteryFailure") ->
	?PC_Battery_Failure;
probable_cause("commercialPowerFailure") ->
	?PC_Commercial_Power_Failure;
probable_cause("coolingFanFailure") ->
	?PC_Cooling_Fan_Failure;
probable_cause("coolingSystemFailure") ->
	?PC_Cooling_System_Failure;
probable_cause("engineFailure") ->
	?PC_Engine_Failure;
probable_cause("fireDetectorFailure") ->
	?PC_Fire_Detector_Failure;
probable_cause("fuseFailure") ->
	?PC_Fuse_Failure;
probable_cause("generatorFailure") ->
	?PC_Generator_Failure;
probable_cause("lowBatteryThreshold") ->
	?PC_Low_Battery_Threshold;
probable_cause("pumpFailure") ->
	?PC_Pump_Failure;
probable_cause("rectifierFailure") ->
	?PC_Rectifier_Failure;
probable_cause("rectifierHighVoltage") ->
	?PC_Rectifier_High_Voltage;
probable_cause("rectifierLowVoltage") ->
	?PC_Rectifier_Low_Voltage;
probable_cause("ventilationSystemFailure") ->
	?PC_Ventilation_System_Failure;
probable_cause("enclosureDoorOpen") ->
	?PC_Enclosure_Door_Open;
probable_cause("explosiveGas") ->
	?PC_Explosive_Gas;
probable_cause("externalEquipmentFailure") ->
	?PC_External_Equipment_Failure;
probable_cause("equipmentMalfunction") ->
	?PC_Equipment_Malfunction;
probable_cause("externalPointFailure") ->
	?PC_External_Point_Failure;
probable_cause("fire") ->
	?PC_Fire;
probable_cause("fireDetected") ->
	?PC_Fire_Detected;
probable_cause("flood") ->
	?PC_Flood;
probable_cause("highHumidity") ->
	?PC_High_Humidity;
probable_cause("highTemperature") ->
	?PC_High_Temperature;
probable_cause("highWind") ->
	?PC_High_Wind;
probable_cause("iceBuildUp") ->
	?PC_Ice_Build_Up;
probable_cause("intrusionDetection") ->
	?PC_Intrusion_Detection;
probable_cause("lowFuel") ->
	?PC_Low_Fuel;
probable_cause("lowHumidity") ->
	?PC_Low_Humidity;
probable_cause("lowCablePressure") ->
	?PC_Low_Cable_Pressure;
probable_cause("lowTemperature") ->
	?PC_Low_Temperature;
probable_cause("lowWater") ->
	?PC_Low_Water;
probable_cause("smoke") ->
	?PC_Smoke;
probable_cause("toxicGas") ->
	?PC_Toxic_Gas;
probable_cause("applicationSubsystemFailure") ->
	?PC_Application_Subsystem_Failure;
probable_cause("configurationOrCustomizationError") ->
	?PC_Configuration_Or_Customization_Error;
probable_cause("fileError") ->
	?PC_File_Error;
probable_cause("PC_Storage_Capacity_Problem") ->
	?PC_Storage_Capacity_Problem;
probable_cause("memoryMismatch") ->
	?PC_Memory_Mismatch;
probable_cause("corruptData") ->
	?PC_Corrupt_Data;
probable_cause("lossOfRealTime") ->
	?PC_Loss_Of_Real_Time;
probable_cause("outOfCPUCycles") ->
	?PC_Out_Of_CPU_Cycles;
probable_cause("outOfMemory") ->
	?PC_Out_Of_Memory;
probable_cause("reinitialized") ->
	?PC_Reinitialized;
probable_cause("softwareEnvironmentProblem") ->
	?PC_Software_Environment_Problem;
probable_cause("softwareDownloadFailure") ->
	?PC_Software_Download_Failure;
probable_cause("timeoutExpired") ->
	?PC_Timeout_Expired;
probable_cause("underlyingResourceUnavailable") ->
	?PC_Underlying_Resource_Unavailable;
probable_cause("versionMismatch") ->
	?PC_Version_Mismatch;
probable_cause("bandwidthReduced") ->
	?PC_Bandwidth_Reduced;
probable_cause("congestion") ->
	?PC_Congestion;
probable_cause("excessiveErrorRate") ->
	?PC_Excessive_Error_Rate;
probable_cause("excessiveRresponseTime") ->
	?PC_Excessive_Rresponse_Time;
probable_cause("excessiveRetransmissionRate") ->
	?PC_Excessive_Retransmission_Rate;
probable_cause("reducedLoggingCapability") ->
	?PC_Reduced_Logging_Capability;
probable_cause("systemResourcesOverload") ->
	?PC_System_Resources_Overload;
probable_cause("adapterError") ->
	?PC_Adapter_Error;
probable_cause("authenticationFailure") ->
	?PC_Authentication_Failure;
probable_cause("breachOfConfidentiality") ->
	?PC_Breach_Of_Confidentiality;
probable_cause("cableTamper") ->
	?PC_Cable_Tamper;
probable_cause("communicationProtocolError") ->
	?PC_Communication_Protocol_Error;
probable_cause("communicationSubsystemFailure") ->
	?PC_Communication_Subsystem_Failure;
probable_cause("cPUCyclesLimitExceeded") ->
	?PC_CPU_Cycles_Limit_Exceeded;
probable_cause("dataSetOrModemError") ->
	?PC_Data_Set_Or_Modem_Error;
probable_cause("denialOfService") ->
	?PC_Denial_Of_Service;
probable_cause("dTEDCEInterfaceError") ->
	?PC_DTE_DCE_Interface_Error;
probable_cause("duplicateInformation") ->
	?PC_Duplicate_Information;
probable_cause("excessiveVibration") ->
	?PC_Excessive_Vibration;
probable_cause("framingError") ->
	?PC_Framing_Error;
probable_cause("heatingOrVentilationOrCoolingSystemProblem") ->
	?PC_HOVOCP;	
probable_cause("humidityUnacceptable") ->
	?PC_Humidity_Unacceptable;
probable_cause("infoMissing") ->
	?PC_Info_Missing;
probable_cause("infoModDetected") ->
	?PC_Info_Mod_Detected;
probable_cause("infoOutOfSequence") ->
	?PC_Info_Out_Of_Sequence;
probable_cause("inputOutputDeviceError") ->
	?PC_Input_Output_Device_Error;
probable_cause("inputDeviceError") ->
	?PC_Input_Device_Error;
probable_cause("keyExpired") ->
	?PC_Key_Expired;
probable_cause("lANError") ->
	?PC_LAN_Error;
probable_cause("leakDetection") ->
	?PC_Leak_Detection;
probable_cause("localNodeTransmissionError") ->
	?PC_Local_Node_Transmission_Error;
probable_cause("materialSupplyExhausted") ->
	?PC_Material_Supply_Exhausted;
probable_cause("nonRepudiationFailure") ->
	?PC_Non_Repudiation_Failure;
probable_cause("outOfHoursActivity") ->
	?PC_Out_Of_Hours_Activity;
probable_cause("OutOfService") ->
	?PC_Out_Of_Service;
probable_cause("outputDeviceError") ->
	?PC_Output_Device_Error;
probable_cause("performanceDegraded") ->
	?PC_Performance_Degraded;
probable_cause("pressureUnacceptable") ->
	?PC_Pressure_Unacceptable;
probable_cause("proceduralError") ->
	?PC_Procedural_Error;
probable_cause("processorProblem") ->
	?PC_Processor_Problem;
probable_cause("queueSizeExceeded") ->
	?PC_Queue_Size_Exceeded;
probable_cause("receiveFailure") ->
	?PC_Receive_Failure;
probable_cause("remoteNodeTransmissionError") ->
	?PC_Remote_Node_Transmission_Error;
probable_cause("resourceAtOrNearingCapacity") ->
	?PC_Resource_at_or_Nearing_Capacity;
probable_cause("softwareError") ->
	?PC_Software_Error;
probable_cause("softwareProgramAbnormallyTerminated") ->
	?PC_Software_Program_Abnormally_Terminated;
probable_cause("softwareProgramError") ->
	?PC_Software_Program_Error;
probable_cause("temperatureUnacceptable") ->
	?PC_Temperature_Unacceptable;
probable_cause("thresholdCrossed") ->
	?PC_Threshold_Crossed;
probable_cause("toxicLeakDetected") ->
	?PC_Toxic_Leak_Detected;
probable_cause("transmitFailure") ->
	?PC_Transmit_Failure;
probable_cause("unauthorizedAccessAttempt") ->
	?PC_Unauthorized_Access_Attempt;
probable_cause("unexpectedInfo") ->
	?PC_Unexpected_Info;
probable_cause("unspecifiedReason") ->
	?PC_Unspecified_Reason;
probable_cause("databaseInconsistency") ->
	?PC_Database_Inconsistency;
probable_cause("fileSystem_CallUnsuccessful") ->
	?PC_File_System_Call_Unsuccessful;
probable_cause("callEstablishmentError") ->
	?PC_Call_Establishment_Error;
probable_cause("inputParameterOutOfRange") ->
	?PC_Input_Parameter_Out_Of_Range;
probable_cause("invalidParameter") ->
	?PC_Invalid_Parameter;
probable_cause("invalidPointer") ->
	?PC_Invalid_Pointer;
probable_cause("messageNotExpected") ->
	?PC_Message_Not_Expected;
probable_cause("messageNotInitialized") ->
	?PC_Message_Not_Initialized;
probable_cause("messageOutOfSequence") ->
	?PC_Message_Out_Of_Sequence;
probable_cause("systemCallUnsuccessful") ->
	?PC_System_Call_Unsuccessful;
probable_cause("variableOutOfRange") ->
	?PC_Variable_Out_Of_Range;
probable_cause("sS7ProtocolFailure") ->
	?PC_SS7_Protocol_Failure;
probable_cause("watchDogTimerExpired") ->
	?PC_Watch_Dog_Timer_Expired;
probable_cause("externalPowerSupplyFailure") ->
	?PC_External_Power_Supply_Failure;
probable_cause("externalTransmissionDeviceFailure") ->
	?PC_External_Transmission_Device_Failure;
probable_cause("fanFailure") ->
	?PC_Fan_Failure;
probable_cause("linkFailure") ->
	?PC_Link_Failure;
probable_cause("reducedAlarmReporting") ->
	?PC_Reduced_Alarm_Reporting;
probable_cause("reducedEventReporting") ->
	?PC_Reduced_Event_Reporting;
probable_cause("invalidMSUReceived") ->
	?PC_Invalid_MSU_Received;
probable_cause("lAPDLinkProtocolFailure") ->
	?PC_LAPD_Link_Protocol_Failure;
probable_cause("equipmentFailure") ->
	?PC_Equipment_Failure;
probable_cause("a-bisToBTSInterfaceFailure") ->
	?PC_A_bis_To_BTS_Interface_Failure;
probable_cause("a-bisToTRXInterfaceFailure") ->
	?PC_A_bis_To_TRX_Interface_Failure;
probable_cause("batteryBreakdown") ->
	?PC_Battery_Breakdown;
probable_cause("batteryChargingFault") ->
	?PC_Battery_Charging_Fault;
probable_cause("clockSynchronizationProblem") ->
	?PC_Clock_Synchronization_Problem;
probable_cause("combinerProblem") ->
	?PC_Combiner_Problem;
probable_cause("excessiveReceiverTemperature") ->
	?PC_Excessive_Receiver_Temperature;
probable_cause("excessiveTransmitterOutputPower") ->
	?PC_Excessive_Transmitter_Output_Power;
probable_cause("excessiveTransmitterTemperature") ->
	?PC_Excessive_Transmitter_Temperature;
probable_cause("frequencyHoppingDegraded") ->
	?PC_Frequency_Hopping_Degraded;
probable_cause("frequencyRedefinitionFailed") ->
	?PC_Frequency_Redefinition_Failed;
probable_cause("lineInterfaceFailure") ->
	?PC_Line_Interface_Failure;
probable_cause("mainsBreakDownWithBatteryBackUp") ->
	?PC_Mains_BreakDown_With_Battery_Back_Up;
probable_cause("mainsBreakDownWithoutBatteryBackUp") ->
	?PC_Mains_BreakDown_Without_Battery_Back_Up;
probable_cause("receiverAntennaFault") ->
	?PC_Receiver_Antenna_Fault;
probable_cause("receiverMulticouplerFailure") ->
	?PC_Receiver_Multicoupler_Failure;
probable_cause("reducedTransmitterOutputPower") ->
	?PC_Reduced_Transmitter_Output_Power;
probable_cause("transceiverProblem") ->
	?PC_Transceiver_Problem;
probable_cause("transcoderProblem") ->
	?PC_Transcoder_Problem;
probable_cause("TranscoderOrRateAdapterProblem") ->
	?PC_Transcoder_Or_Rate_Adapter_Problem;
probable_cause("transmitterAntennaFailure") ->
	?PC_Transmitter_Antenna_Failure;
probable_cause("transmitterAntennaNotAdjusted") ->
	?PC_Transmitter_Antenna_Not_Adjusted;
probable_cause("transmitterLowVoltageOrCurrent") ->
	?PC_Transmitter_Low_Voltage_Or_Current;
probable_cause("transmitterOffFrequency") ->
	?PC_Transmitter_Off_Frequency;
probable_cause("re-transmissionRateExcessive") ->
	?PC_Re_transmission_Rate_Excessive;
probable_cause("delayedInformation") ->
	?PC_Delayed_Information;
probable_cause("timeslotHardwareFailure") ->
	?PC_Timeslot_Hardware_Failure;
probable_cause("localAlarmIndication") ->
	?PC_Local_Alarm_Indication;
probable_cause("remoteAlarmIndication") ->
	?PC_Remote_Alarm_Indication;
probable_cause("equipmentOutOfService") ->
	?PC_Equipment_Out_Of_Service;
probable_cause("excessiveBER") ->
	?PC_Excessive_Bit_Error_Rate;
probable_cause(ProbableCauseCode) ->
	error_logger:info_report(["SNMP Manager Unrecognized Probable Cause",
			{probableCause, ProbableCauseCode},
			{module, ?MODULE}]),
	ProbableCauseCode.

