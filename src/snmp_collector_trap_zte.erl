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
%% 		<td id="mt">alarmCodeName</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.probableCause</td>
%%			<td id="mt">3GPP 32.111-2 Annex B e.g. "Alarm Indication Signal (AIS)"</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmProbableCause</td>
%% 		<td id="mt">faultFields.probableCause</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmspecificProblem</td>
%% 		<td id="mt">faultFields.specificProblem</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmOtherInfo</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmDetails</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmIndex</td>
%% 		<td id="mt">faultFields.alarmAdditionalInformation.alarmId</td>
%%			<td id="mt">Unique identifier of an alarm</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">systemDN</td>
%% 		<td id="mt">faultFields.alarmAdditionalInformation.reportingEntityI</td>
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
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.neType</td>
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
%% 		<td id="mt">alarmCustomAttr12</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.objectInstance</td>
%%			<td id="mt">Distinguished Name (DN)</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmCustomAttr2</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmObjectName</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmAck</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.ackState</td>
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
    handle_report/3, fault/1]).

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
		snmp_collector_utils:update_counters(zte, TargetName, AlarmDetails),
		Event = snmp_collector_utils:create_event(TargetName, AlarmDetails, fault),
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
		VesValue :: string ().
%% @doc CODEC for event.
fault([{"snmpTrapOID", "alarmNew"} | T] = _OldNameValuePair) ->
	fault(T, "alarmNew", [{"eventName", ?EN_NEW},
			{"alarmCondition", "alarmNew"}]);
fault([{"snmpTrapOID", "alarmCleared"} | T]) ->
	fault(T, "alarmCleared", [{"eventName", ?EN_CLEARED},
			{"alarmCondition", "alarmCleared"},
			{"eventSeverity", ?ES_CLEARED}]);
fault([{"snmpTrapOID", "alarmSeverityChange"} | T]) ->
	fault(T, alarmSeverityChange, [{"eventName", ?EN_CHANGED},
			{"alarmCondition", "alarmSeverityChange"}]);
fault([{"snmpTrapOID", "alarmManagedObjectInstanceNameChange"} | T]) ->
	fault(T, "alarmMOINameChange", [{"eventName", ?EN_CHANGED},
			{"alarmCondition", "alarmMOINameChange"}]);
fault([{"snmpTrapOID", "alarmAckChange"} | T]) ->
	fault(T, "alarmAckChange", [{"eventName", ?EN_CHANGED},
			{"alarmCondition", "alarmAckChange"}]).
%% @hidden
fault([{"id", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"alarmId", Value} | Acc]);
fault([{"alarmEventTime", Value} | T], EN, Acc)
		when EN == "alarmNew", is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"raisedTime", Value} | Acc]);
fault([{"alarmEventTime", Value} | T], EN, Acc)
		when EN == "alarmSeverityChange", is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"changedTime", Value} | Acc]);
fault([{"alarmEventTime", Value} | T], EN, Acc)
		when EN == "alarmCleared", is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"clearedTime", Value} | Acc]);
fault([{"alarmEventTime", Value} | T], EN, Acc)
		when EN == "alarmMOINameChange", is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"changedTime", Value} | Acc]);
fault([{"alarmEventTime", Value} | T], EN, Acc)
		when EN == "alarmAckChange", is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"alarmAckTime", Value} | Acc]);
fault([{"alarmNeIP", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"sourceId", Value} | Acc]);
fault([{"systemDN", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"reportingEntityId", Value} | Acc]);
fault([{"alarmMocObjectInstance", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"eventSourceType", Value} | Acc]);
fault([{"alarmProbableCause", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"probableCause", snmp_collector_utils:probable_cause(Value)} | Acc]);
fault([{"alarmSpecificProblem", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"specificProblem", Value} | Acc]);
fault([{"alarmPerceivedSeverity", "1"} | T], EN, Acc) ->
	fault(T, EN, [{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
fault([{"alarmPerceivedSeverity", "2"} | T], EN, Acc) ->
	fault(T, EN, [{"eventSeverity", ?ES_CRITICAL} | Acc]);
fault([{"alarmPerceivedSeverity", "3"} | T], EN, Acc) ->
	fault(T, EN, [{"eventSeverity", ?ES_MAJOR} | Acc]);
fault([{"alarmPerceivedSeverity", "4"} | T], EN, Acc) ->
	fault(T, EN, [{"eventSeverity", ?ES_MINOR} | Acc]);
fault([{"alarmPerceivedSeverity", "5"} | T], EN, Acc) ->
	fault(T, EN, [{"eventSeverity", ?ES_WARNING} | Acc]);
fault([{"alarmPerceivedSeverity", "6"} | T], EN, Acc) ->
	fault(T, EN, [{"eventSeverity", ?ES_CLEARED} | Acc]);
fault([{"alarmEventType", "1"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Communication_System} | Acc]);
fault([{"alarmEventType", "2"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Processing_Error} | Acc]);
fault([{"alarmEventType", "3"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Environmental_Alarm} | Acc]);
fault([{"alarmEventType", "4"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Quality_Of_Service_Alarm} | Acc]);
fault([{"alarmEventType", "5"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Equipment_Alarm} | Acc]);
fault([{"alarmEventType", "6"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Integrity_Violation} | Acc]);
fault([{"alarmEventType", "7"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Operational_Violation} | Acc]);
fault([{"alarmEventType", "8"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Physical_Violation} | Acc]);
fault([{"alarmEventType", "9"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Security_Service_Or_Mechanism_Violation} | Acc]);
fault([{"alarmEventType", "10"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Time_Domain_Violation} | Acc]);
fault([{"alarmEventType", "11"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Quality_Of_Service_Alarm} | Acc]);
fault([{"alarmCodeName", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"alarmCodeName", Value} | Acc]);
fault([{"alarmAck", "1"} | T], EN, Acc) ->
	fault(T, EN,[{"alarmAckState", ?ACK_Acknowledged} | Acc]);
fault([{"alarmAck", "2"} | T], EN, Acc) ->
	fault(T, EN, [{"alarmAckState", ?ACK_Unacknowledged} | Acc]);
fault([{"alarmOtherInfo", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"additionalText", Value} | Acc]);
fault([{"alarmNetype", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"netype", Value} | Acc]);
fault([{"alarmSystemType", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN,[{"alarmSystemType", Value} | Acc]);
fault([{"timeZoneID", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"timeZoneID", Value} | Acc]);
fault([{"alarmCode", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"alarmCode", Value} | Acc]);
fault([{"aid", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"alarmAID", Value} | Acc]);
fault([{"alarmCustomAttr12", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"objectInstance", Value} | Acc]);
fault([{"alarmCustomAttr2", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"alarmObjectName", Value} | Acc]);
fault([{"alarmCustomAttr6", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"boardType", Value} | Acc]);
fault([{"alarmId", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"exId", Value} | Acc]);
fault([{_, [$ ]} | T], EN, Acc) ->
	fault(T, EN, Acc);
fault([{_, []} | T], EN, Acc) ->
	fault(T, EN, Acc);
fault([{Name, Value} | T], EN, Acc) ->
	fault(T, EN, [{Name, Value} | Acc]);
fault([], _, Acc) ->
	Acc.

-spec domain(Varbinds) -> Result
	when
		Varbinds :: [Varbinds],
		Result :: fault | heartbeat | other.
%% @doc Check the domain of the event.
domain([_TimeTicks, {varbind, [1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0] , _, TrapName, _} | _T]) ->
	domain1(snmp_collector_utils:oid_to_name(TrapName)).
%% @hidden
domain1("alarmNew") ->
	fault;
domain1("alarmAckChange") ->
	fault;
domain1("alarmCleared") ->
	fault;
domain1("alarmCommentChange") ->
	fault;
domain1("alarmListRebuild") ->
	fault;
domain1("alarmSync") ->
	fault;
domain1("messageInfo") ->
	fault;
domain1("alarmSeverityChange") ->
	fault;
domain1("alarmManagedObjectInstanceNameChange") ->
	fault;
domain1("heartbeatNotification") ->
	heartbeat;
domain1(_Other) ->
	other.
	
