%%% snmp_collector_trap_huawei_imap.erl
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

%% @doc This module normalizes traps received on NBI from Huawei EMS.
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
%% 		<td id="mt">iMAPNorthboundAlarmType</td>
%% 		<td id="mt">commonEventheader.eventType</td>
%%			<td id="mt">e.g. "Quality of Service Alarm"</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmSpecificproblems</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.probableCause</td>
%%			<td id="mt">3GPP 32.111-2 Annex B  e.g. "Alarm Indication Signal (AIS)"</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt"></td>
%% 		<td id="mt">faultFields.specificProblem</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmAdditionalInfo</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmDetails</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmID</td>
%% 		<td id="mt">faultFields.alarmAdditionalInformation.alarmId</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmNEDevID</td>
%% 		<td id="mt">commonEventHeader.sourceName</td>
%%			<td id="mt">String</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmDevCsn</td>
%% 		<td id="mt">commonEventHeader.sourceId</td>
%%			<td id="mt">Distinguished Name (DN)</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmMOName</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.objectInstance</td>
%%			<td id="mt">Distinguished Name (DN)</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmNEType</td>
%% 		<td id="mt">faultsFields.eventSourceType</td>
%%			<td id="mt">Managed Object Class (MOC) name</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmLevel</td>
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
%% 		<td id="mt">iMAPNorthboundAlarmCategory</td>
%% 		<td id="mt">commonEventHeader.eventName</td>
%%			<td id="mt">notifyNewAlarm | notifyChangedAlarm | notifyClearedAlarm</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmRestore</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmRestore</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmOccurTime</td>
%% 		<td id="mt">commonEventHeader.startEpochMicrosec</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmServiceAffectFlag</td>
%% 		<td id="mt">serviceAffectFlag</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmClearType</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.clearType</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmClearCategory</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.clearCategory</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmObjectInstanceType</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.objectInstanceType</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmClearOperator</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.clearOperator</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmProposedrepairactions</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.proposedRepairActions</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmExtendInfo</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.additionalText</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmOperator</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmOperator</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmRestoreTime</td>
%% 		<td id="mt">rfaultsFields.alarmAdditionalInformation.restoreTime</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmAckTime</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmAckTime</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmConfirm</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmAckState</td>
%%			<td id="mt">acknowledged | unacknowledged</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmRestore</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmRestore</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmProductID</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmProductID</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmCSN</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmSerialNumber</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">iMAPNorthboundAlarmClearType</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.alarmClearType</td>
%%			<td id="mt"></td>
%% 	</tr>
%% </tbody>
%% </table></p>

-module(snmp_collector_trap_huawei_imap).
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
%%  The snmp_collector_trap_huawei_imap public API
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
			snmp_collector_trap_generic:handle_trap(TargetName, {Enteprise,
					Generic, Spec, Timestamp, Varbinds}, UserData);
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
%% @doc Handle a fault fault.
handle_fault(TargetName, Varbinds) ->
	try
		{ok, Pairs} = snmp_collector_utils:arrange_list(Varbinds),
erlang:display({?MODULE, ?LINE, here}),
		{ok, NamesValues} = snmp_collector_utils:oids_to_names(Pairs, []),
erlang:display({?MODULE, ?LINE, here}),
		AlarmDetails = fault(NamesValues),
erlang:display({?MODULE, ?LINE, here}),
		snmp_collector_utils:update_counters(huawei, TargetName, AlarmDetails),
erlang:display({?MODULE, ?LINE, here}),
		Event = snmp_collector_utils:generate_maps(TargetName, AlarmDetails, fault),
erlang:display({?MODULE, ?LINE, here}),
		snmp_collector_utils:log_event(Event),
erlang:display({?MODULE, ?LINE, here}),
		{ok, Url} = application:get_env(snmp_collector, ves_url),
erlang:display({?MODULE, ?LINE, here}),
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
fault([{"iMAPNorthboundAlarmCSN", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"alarmId", Value} | Acc]);
fault([{"iMAPNorthboundAlarmOccurTime", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"raisedTime", Value} | Acc]);
fault([{"iMAPNorthboundAlarmDevCsn", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"sourceId", Value} | Acc]);
fault([{"iMAPNorthboundAlarmNEDevID", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"sourceName", Value} | Acc]);
fault([{"iMAPNorthboundAlarmNEType", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"eventSourceType", Value} | Acc]);
fault([{"iMAPNorthboundAlarmMOName", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"objectInstance", Value}| Acc]);
fault([{"iMAPNorthboundAlarmObjectInstanceType", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"objectInstanceType", Value} | Acc]);
fault([{"snmpTrapOID", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"alarmCondition", Value} | Acc]);
fault([{"iMAPNorthboundAlarmLevel", "1"} | T], Acc) ->
	fault(T, [{"eventSeverity", ?ES_CRITICAL} | Acc]);
fault([{"iMAPNorthboundAlarmLevel", "2"} | T], Acc) ->
	fault(T, [{"eventSeverity", ?ES_MAJOR} | Acc]);
fault([{"iMAPNorthboundAlarmLevel", "3"} | T], Acc) ->
	fault(T, [{"eventSeverity", ?ES_MINOR} | Acc]);
fault([{"iMAPNorthboundAlarmLevel", "4"} | T], Acc) ->
	fault(T, [{"eventSeverity", ?ES_WARNING} | Acc]);
fault([{"iMAPNorthboundAlarmLevel", "5"} | T], Acc) ->
	fault(T, [{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
fault([{"iMAPNorthboundAlarmLevel", "6"} | T], Acc) ->
	fault(T, [{"eventSeverity", ?ES_CLEARED} | Acc]);
fault([{"iMAPNorthboundAlarmCategory", "1"} | T], Acc) ->
	fault(T, [{"eventName", ?EN_NEW} | Acc]);
fault([{"iMAPNorthboundAlarmCategory", "2"} | T], Acc) ->
	fault(T, [{"eventName", ?EN_CLEARED} | Acc]);
fault([{"iMAPNorthboundAlarmCategory", "3"} | T], Acc) ->
	fault(T, [{"eventName", ?EN_NEW} | Acc]);
fault([{"iMAPNorthboundAlarmCategory", "4"} | T], Acc) ->
	fault(T, [{"eventName", ?ACK_Acknowledged} | Acc]);
fault([{"iMAPNorthboundAlarmCategory", "5"} | T], Acc) ->
	fault(T, [{"eventName", ?ACK_Unacknowledged} | Acc]);
fault([{"iMAPNorthboundAlarmCategory", "9"} | T], Acc) ->
	fault(T, [{"eventName", ?EN_CHANGED} | Acc]);
fault([{"iMAPNorthboundAlarmType", "1"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Equipment_Alarm} | Acc]);
fault([{"iMAPNorthboundAlarmType", "2"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Environmental_Alarm} | Acc]);
fault([{"iMAPNorthboundAlarmType", "3"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Communication_System} | Acc]);
fault([{"iMAPNorthboundAlarmType", "4"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Communication_System} | Acc]);
fault([{"iMAPNorthboundAlarmType", "5"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Equipment_Alarm} | Acc]);
fault([{"iMAPNorthboundAlarmType", "6"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Processing_Error} | Acc]);
fault([{"iMAPNorthboundAlarmType", "7"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Processing_Error} | Acc]);
fault([{"iMAPNorthboundAlarmType", "8"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Communication_System} | Acc]);
fault([{"iMAPNorthboundAlarmType", "9"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Quality_Of_Service_Alarm} | Acc]);
fault([{"iMAPNorthboundAlarmType", "10"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Processing_Error} | Acc]);
fault([{"iMAPNorthboundAlarmType", "11"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Quality_Of_Service_Alarm} | Acc]);
fault([{"iMAPNorthboundAlarmType", "12"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Integrity_Violation} | Acc]);
fault([{"iMAPNorthboundAlarmType", "13"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Operational_Violation} | Acc]);
fault([{"iMAPNorthboundAlarmType", "14"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Physical_Violation} | Acc]);
fault([{"iMAPNorthboundAlarmType", "15"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Security_Service_Or_Mechanism_Violation} | Acc]);
fault([{"iMAPNorthboundAlarmType", "16"} | T], Acc) ->
	fault(T, [{"eventType", ?ET_Time_Domain_Violation} | Acc]);
fault([{"iMAPNorthboundAlarmProbablecause", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"probableCause", ?PC_Indeterminate}, {"specificProblem", Value} | Acc]);
fault([{"iMAPNorthboundAlarmProposedrepairactions", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"proposedRepairActions", Value} | Acc]);
fault([{"iMAPNorthboundAlarmAckTime", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"alarmAckTime", Value} | Acc]);
fault([{"iMAPNorthboundAlarmConfirm", "1"} | T], Acc) ->
	fault(T, [{"alarmAckState", ?ACK_Acknowledged} | Acc]);
fault([{"iMAPNorthboundAlarmConfirm", "2"} | T], Acc) ->
	fault(T, [{"alarmAckState", ?ACK_Unacknowledged} | Acc]);
fault([{"iMAPNorthboundAlarmExtendInfo", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"additionalText", Value} | Acc]);
fault([{"iMAPNorthboundAlarmAdditionalInfo", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"alarmDetails", Value} | Acc]);
fault([{"iMAPNorthboundAlarmClearType", "0"} | T], Acc) ->
	fault(T, Acc);
fault([{"iMAPNorthboundAlarmClearType", "1"} | T], Acc) ->
	fault(T, [{"clearType", "Normal Clear"} | Acc]);
fault([{"iMAPNorthboundAlarmClearType", "2"} | T], Acc) ->
	fault(T, [{"clearType", "Restore Clear"} | Acc]);
fault([{"iMAPNorthboundAlarmClearType", "3"} | T], Acc) ->
	fault(T, [{"clearType", "Manual Clear"} | Acc]);
fault([{"iMAPNorthboundAlarmClearType", "4"} | T], Acc) ->
	fault(T, [{"clearType", "Configure Clear"} | Acc]);
fault([{"iMAPNorthboundAlarmClearType", "5"} | T], Acc) ->
	fault(T, [{"clearType", "Co-relation Clear"} | Acc]);
fault([{"iMAPNorthboundAlarmClearCategory", "1"} | T], Acc) ->
	fault(T, [{"clearCategory", "Automatically Detected Automcatically Cleared"} | Acc]);
fault([{"iMAPNorthboundAlarmClearCategory", "2"} | T], Acc) ->
	fault(T, [{"clearCategory", "Automatically Detected Manually Cleared"} | Acc]);
fault([{"iMAPNorthboundAlarmRestore", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"alarmRestore", Value} | Acc]);
fault([{"iMAPNorthboundAlarmServiceAffectFlag", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"serviceAffectFlag", Value} | Acc]);
fault([{"iMAPNorthboundAlarmClearOperator", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"clearUser", Value} | Acc]);
fault([{"iMAPNorthboundAlarmOperator", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"alarmOperator", Value} | Acc]);
fault([{"iMAPNorthboundAlarmRestoreTime", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"restoreTime", Value} | Acc]);
fault([{"iMAPNorthboundAlarmRestore", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"alarmRestore", Value} | Acc]);
fault([{"iMAPNorthboundAlarmProductID", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"alarmProductID", Value} | Acc]);
fault([{"iMAPNorthboundAlarmExtendInfo", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"alarmSerialNumber", Value} | Acc]);
fault([{"iMAPNorthboundAlarmID", Value} | T], Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, [{"id", Value} | Acc]);
fault([{"iMAPNorthboundAlarmSpecificproblems", Value} | T], Acc)
		when is_list(Value), length(Value) > 0; Value =/= [$ ] ->
	fault(T, [{"alarmSpecificproblems", Value} | Acc]);
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
domain1("iMAPNorthboundFaultAlarmQueryEndNotificationType ") ->
	fault;
domain1("iMAPNorthboundFaultAlarmReportNotificationType") ->
	fault;
domain1("iMAPNorthboundFaultAlarmQueryBeginNotificationType") ->
	fault;
domain1("iMAPNorthboundFaultAlarmQueryNotificationTyp") ->
	fault;
domain1("iMAPNorthboundHeartbeatNotificationType") ->
	heartbeat;
domain1(_) ->
	other.
