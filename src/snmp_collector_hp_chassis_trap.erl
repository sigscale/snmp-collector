%%% snmp_collector_hp_chassis_trap.erl
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

%% @doc This module normalizes traps received from CISCO agents.
%%
%% Varbinds are mapped to alarm attributes, using the MIBs avaialable, and to VES attributes.
%%
%%	The following table shows the mapping between CISCO MIB attributes and VES attributes.
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
%% 		<td id="mt">snmpTrapOID.eventType</td>
%% 		<td id="mt">commonEventheader.eventType</td>
%%			<td id="mt">e.g. "Quality of Service Alarm"</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">snmpTrapOID.probableCause</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.probableCause</td>
%%			<td id="mt">3GPP 32.111-2 Annex B  e.g. "Alarm Indication Signal (AIS)"</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">cpqRackCommonEnclosureSerialNum</td>
%% 		<td id="mt">faultFields.alarmAdditionalInformation.alarmId</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">cpqRackUid</td>
%% 		<td id="mt">commonEventHeader.sourceId</td>
%%			<td id="mt">Distinguished Name (DN)</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">cpqRackName</td>
%% 		<td id="mt">commonEventHeader.sourceName</td>
%%			<td id="mt">String</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">cpqRackCommonEnclosureIndex</td>
%% 		<td id="mt">commonEventHeader.eventId</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmNetype</td>
%% 		<td id="mt">faultsFields.eventSourceType</td>
%%			<td id="mt">Managed Object Class (MOC) name</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">cpqRackEventTime</td>
%% 		<td id="mt">commonEventHeader.startEpochMicrosec</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">cpqRackEventCategory</td>
%% 		<td id="mt">faultsFields.eventCategory</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">cpqRackPowerSupplyEnclosureName</td>
%% 		<td id="mt">faultFields.alarmAdditionalInformation.rackPowerSupplyEnclosureName</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">cpqRackPowerSupplySerialNum</td>
%% 		<td id="mt">faultFields.alarmAdditionalInformation.rackPowerSupplySerialNum</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">cpqRackPowerSupplyPosition</td>
%% 		<td id="mt">faultFields.alarmAdditionalInformation.rackPowerSupplyPosition</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">cpqRackPowerSupplyFWRev</td>
%% 		<td id="mt">faultFields.alarmAdditionalInformation.rackPowerSupplyFWRev</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">cpqRackPowerSupplySparePartNumber</td>
%% 		<td id="mt">faultFields.alarmAdditionalInformation.rackPowerSupplySparePartNumber</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">cpqRackCommonEnclosureTrapSequenceNum</td>
%% 		<td id="mt">faultFields.alarmAdditionalInformation.rackCommonEnclosureTrapSequenceNum</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">cpqHoTrapFlags</td>
%% 		<td id="mt">commonEventHeader.eventName</td>
%%			<td id="mt">notifyNewAlarm | notifyChangedAlarm | notifyClearedAlarm</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">snmpTrapOID.alarmCondition</td>
%% 		<td id="mt">faultsFields.alarmCondition</td>
%%			<td id="mt">Short name of the alarm condition/problem, such as a trap name.
%%					Should not have white space (e.g., tpLgCgiNotInConfig, BfdSessionDown, linkDown, etc…)</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">snmpTrapOID.eventSeverity</td>
%% 		<td id="mt">faultFields.eventSeverity</td>
%%			<td id="mt">CRITICAL | MAJOR | MINOR | WARNING | INDETERMINATE | CLEARED</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">snmpTrapOID.alarmAdditionalInformation</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.proposedRepairActions</td>
%%			<td id="mt"></td>
%% 	</tr>
%% </tbody>
%% </table></p>

-module(snmp_collector_hp_chassis_trap).
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
%%  The snmp_collector_hp_chassis_trap public API
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
handle_trap(TargetName, {_ErrorStatus, _ErrorIndex, Varbinds}, _UserData) ->
	{ok, Pairs} = snmp_collector_utils:arrange_list(Varbinds),
	{ok, NamesValues} = snmp_collector_utils:oids_to_names(Pairs, []),
	AlarmDetails = event(NamesValues),
	{CommonEventHeader, FaultFields} = snmp_collector_utils:generate_maps(TargetName, AlarmDetails),
	case snmp_collector_utils:log_events(CommonEventHeader, FaultFields) of
		ok ->
			ignore;
		{error, Reason} ->
			{error, Reason}
	end;
handle_trap(TargetName, {_Enteprise, _Generic, _Spec, _Timestamp, Varbinds}, _UserData) ->
	{ok, Pairs} = snmp_collector_utils:arrange_list(Varbinds),
	{ok, NamesValues} = snmp_collector_utils:oids_to_names(Pairs, []),
	AlarmDetails = event(NamesValues),
	{CommonEventHeader, FaultFields} = snmp_collector_utils:generate_maps(TargetName, AlarmDetails),
	case snmp_collector_utils:log_events(CommonEventHeader, FaultFields) of
		ok ->
			ignore;
		{error, Reason} ->
			{error, Reason}
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

-spec event(NameValuePair) -> NameValuePair
	when
		NameValuePair :: [{Name, Value}] | [{Name, Value}].
%% @doc CODEC for event.
event(NameValuePair) ->
	event(NameValuePair, []).
%% @hidden
event([{"cpqRackCommonEnclosureSerialNum", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"alarmId", Value} | Acc]);
event([{"cpqRackUid", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"sourceId", Value} | Acc]);
event([{"cpqRackName", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"sourceName", Value} | Acc]);
event([{"cpqRackCommonEnclosureIndex", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"eventid", Value} | Acc]);
event([{"alarmNetype", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"eventSourceType", Value}, {"eventName", ?EN_NEW} | Acc]);
event([{"cpqRackEventTime", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"raisedTime", Value} | Acc]);
event([{"cpqRackEventCategory", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"eventCategory", Value} | Acc]);
event([{"cpqRackPowerSupplyEnclosureName", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"rackPowerSupplyEnclosureName", Value} | Acc]);
event([{"cpqRackPowerSupplySerialNum", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"rackPowerSupplySerialNum", Value} | Acc]);
event([{"cpqRackPowerSupplyPosition", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"rackPowerSupplyPosition", Value} | Acc]);
event([{"cpqRackPowerSupplyFWRev", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"rackPowerSupplyFWRev", Value} | Acc]);
event([{"cpqRackPowerSupplySparePartNumber", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"rackPowerSupplySparePartNumber", Value} | Acc]);
event([{"cpqRackCommonEnclosureTrapSequenceNum", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"rackCommonEnclosureTrapSequenceNum", Value} | Acc]);
event([{"cpqHoTrapFlags", 2} | T], Acc) ->
	event(T, [{"eventName", ?EN_CLEARED} | Acc]);
event([{"cpqHoTrapFlags", 3} | T], Acc) ->
	event(T, [{"eventName", ?EN_NEW} | Acc]);
event([{"cpqHoTrapFlags", 4} | T], Acc) ->
	event(T, [{"eventName", ?EN_NEW} | Acc]);
event([{"snmpTrapOID", "compaqq.[22001]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackNameChanged"},
		{"probableCause", "Rack name changed"},
		{"eventType", ?ET_Communication_System} ,
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22002]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackEnclosureNameChanged"},
		{"probableCause", "Enclosure name changed"},
		{"eventType", ?ET_Communication_System},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22003]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackEnclosureRemoved"},
		{"probableCause", "Enclosure removed"},
		{"eventType", ?ET_Physical_Violation},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22004]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackEnclosureInserted"},
		{"probableCause", "Enclosure inserted"},
		{"eventType", ?ET_Physical_Violation},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22005]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackEnclosureTempFailed"},
		{"probableCause", "Enclosure temperature failed"},
		{"eventType", ?ET_Environmental_Alarm},
		{"eventSeverity", ?ES_CRITICAL},
		{"proposedRepairActions", "Shutdown the enclosure and possibly the rack as soon as possible.
				Ensure all fans are working properly and that air flow in the rack has not been blocked."} | Acc]);
event([{"snmpTrapOID", "compaqq.[22006]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackEnclosureTempDegraded"},
		{"probableCause", ?PC_Temperature_Unacceptable},
		{"eventType", ?ET_Environmental_Alarm}, {"eventSeverity", ?ES_MAJOR},
		{"proposedRepairActions", "Shutdown the enclosure and possibly the rack as soon as possible.
				Ensure all fans are working properly and that air flow in the rack has not been blocked."} | Acc]);
event([{"snmpTrapOID", "compaqq.[22007]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackEnclosureTempOk"},
		{"probableCause", "Temperature Ok"},
		{"eventType", ?ET_Environmental_Alarm} ,
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22008]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackEnclosureFanFailed"},
		{"probableCause", ?PC_Cooling_System_Failure},
		{"eventType", ?ET_Environmental_Alarm},
		{"eventSeverity", ?ES_CRITICAL},
		{"proposedRepairActions", "Replace the failed enclosure fan."} | Acc]);
event([{"snmpTrapOID", "compaqq.[22009]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackEnclosureFanDegraded"},
		{"probableCause", ?PC_Cooling_System_Failure},
		{"eventType", ?ET_Environmental_Alarm},
		{"eventSeverity", ?ES_MAJOR},
		{"proposedRepairActions", "Replace the failing enclosure fan."} | Acc]);
event([{"snmpTrapOID", "compaqq.[22010]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackEnclosureFanOk"},
		{"probableCause", "Enclosure fan ok"},
		{"eventType", ?ET_Environmental_Alarm} ,
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22011]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackEnclosureFanRemoved"},
		{"probableCause", "Enclosure fan removed"},
		{"eventType", "Hardware System"},
		{"eventSeverity", ?ES_MINOR} | Acc]);
event([{"snmpTrapOID", "compaqq.[22012]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackEnclosureFanInserted"},
		{"probableCause", "Enclosure fan inserted"},
		{"eventType", ?ET_Physical_Violation},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22013]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackPowerSupply Failed"},
		{"probableCause", ?PC_Power_Supply_Failure},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_CRITICAL} | Acc]);
event([{"snmpTrapOID", "compaqq.[22014]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackPowerSupplyDegraded"},
		{"probableCause", ?PC_Power_Supply_Failure},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_MAJOR} | Acc]);
event([{"snmpTrapOID", "compaqq.[22015]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rack Power Supply Ok"},
		{"probableCause", "Rack power supply ok"},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22016]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackPowerSupplyRemoved"},
		{"probableCause", ?ET_Equipment_Alarm},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_MINOR} | Acc]);
event([{"snmpTrapOID", "compaqq.[22017]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackPowerSupplyInserted"},
		{"probableCause", "Rack power supply inserted."},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22018]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackPowerSubsystemNotRedundant"},
		{"probableCause", "Rack power subsystem not redundant."},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_MAJOR} | Acc]);
event([{"snmpTrapOID", "compaqq.[22019]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackPowerSubsystemLineVoltageProblem"},
		{"probableCause", "Rack power supply input voltage problem."},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_MAJOR},
		{"proposedRepairActions", "Check the power input for the power supply
		or replace any failed power supplies as soon as possible"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22020]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackPowerSubsystemOverloadCondition"},
		{"probableCause", "The rack power subsystem overload condition."},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_MAJOR},
		{"proposedRepairActions", "Replace any failed power supplies as soon as possible"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22021]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackPowerShedAutoShutdown"},
		{"probableCause", "The server shutdown due to lack of power blade."},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_CRITICAL},
		{"proposedRepairActions", "Check the power connections for problems,
		then add power supplies if necessary"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22022]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackServerPowerOnFailedNotRedundant"},
		{"probableCause", "Server power on prevented to preserve redundancy in blade."},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_CRITICAL},
		{"proposedRepairActions", "Check the power connections for problems,
		then add power supplies if necessary"} | Acc]);
event([{"snmpTrapOID", Value} | T], Acc)
		when Value == "compaqq.[22023]"; Value == "compaqq.[22024]";
		Value == "compaqq.[22025]"->
	event(T, [{"alarmCondition", "rackServerPowerOnFailedNotEnoughPower"},
		{"probableCause", "Inadequate power to power on."},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_CRITICAL},
		{"proposedRepairActions", "Check the power connections for problems,
		then add power supplies if necessary"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22026]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackServerPowerOnManualOverride"},
		{"probableCause", "Server power On via manual override."},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_MAJOR} | Acc]);
event([{"snmpTrapOID", "compaqq.[22027]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackFuseOpen"},
		{"probableCause", "Fuse Open"},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_MAJOR},
		{"proposedRepairActions", "Check the enclosure and blade power connections,
		then reset the fuse"} | Acc]);
event([{"snmpTrapOID", Value} | T], Acc)
		when Value == "compaqq.[22028]"; Value == "compaqq.[22050]"->
	event(T, [{"alarmCondition", "rackServerBladeRemoved"},
		{"probableCause", "Server blade removed."},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", Value} | T], Acc)
		when Value == "compaqq.[22029]"; Value == "compaqq.[22051]"->
	event(T, [{"alarmCondition", "rackServerBladeInserted"},
		{"probableCause", "Server blade inserted."},
		{"eventType", ?ET_Equipment_Alarm} ,
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22030]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackPowerChassisDcPowerProblem"},
		{"probableCause", "Power subsystem not load balanced."},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_MAJOR},
		{"proposedRepairActions", "Check the power enclosure and power supplies.
		Replace any failed or degraded power supplies. Add additional power supplies if needed"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22031]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackPowerChassisDcPowerProblem"},
		{"probableCause", "Power subsystem DC power problem."},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_MAJOR},
		{"proposedRepairActions", "Check the power enclosure and power supplies.
		Replace any failed or degraded power supplies"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22032]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackPowerChassisAcFacilityPowerExceeded"},
		{"probableCause", "Power subsystem AC facility input power exceeded."},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_MAJOR},
		{"proposedRepairActions", "Check the power enclosure and power supplies.
		Replace any failed or degraded power supplies"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22033]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackPowerUnknownPowerConsumption"},
		{"probableCause", "Unknown power consumption."},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_MAJOR},
		{"proposedRepairActions", "Check the power enclosure and power supplies.
		Replace any failed or degraded power supplies"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22034]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackPowerChassisLoadBalancingWireMissing"},
		{"probableCause", "Unknown power consumption."},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_MAJOR},
		{"proposedRepairActions", "Check the power enclosure and power supplies.
		Replace any failed or degraded power supplies"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22035]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackPowerChassisTooManyPowerChassis"},
		{"probableCause", "Power subsystem has too may power enclosures."},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_MAJOR},
		{"proposedRepairActions", "Remove the extra power enclosure"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22036]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackPowerChassisConfigError"},
		{"probableCause", "Power subsystem improperly configured."},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_MAJOR},
		{"proposedRepairActions", "Check the cabling of the power enclosure"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22037]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackEnclosureManagerDegraded"},
		{"probableCause", ?PC_Power_Problem},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_MAJOR},
		{"proposedRepairActions", "The following conditions can result in a degraded Onboard Administrator
		1) one OA failed but the second OA is still operating,
		2) one or more OAs is in a non-optimal operating state, or
		3) a firmware revision mismatch occurred between the primary and secondary OAs. 
		To determine what caused the issue, see the OA and check the logs for more information.
		If a firmware mismatch occurred, use the OA UI or CLI (UPDATE IMAGE SYNC command)
		to resynchronizethe firmware on the OAs."} | Acc]);
event([{"snmpTrapOID", "compaqq.[22038]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackEnclosureManagerOK"},
		{"probableCause", "Onboard or management processor ok."},
		{"eventType", ?ET_Quality_Of_Service_Alarm},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22039]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackEnclosureManagerRemoved"},
		{"probableCause", "Onboard Administrator removed."},
		{"eventType", ?ET_Quality_Of_Service_Alarm},
		{"eventSeverity", ?ES_MINOR} | Acc]);
event([{"snmpTrapOID", "compaqq.[22040]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackEnclosureManagerInserted"},
		{"probableCause", "The Onboard Administrator or other management processor has been inserted."},
		{"eventType", ?ET_Operational_Violation},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22041]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackManagerPrimaryRole"},
		{"probableCause", "The Onboard Administrator or other management processor has taken the role of primary."},
		{"eventType", ?ET_Operational_Violation},
		{"eventSeverity", ?ES_MAJOR} | Acc]);
event([{"snmpTrapOID", "compaqq.[22042]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackServerBladeEKeyingFailed"},
		{"probableCause", "The server blade e-keying has failed."},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_MAJOR},
		{"proposedRepairActions", "Reconfigure the server blade mezz cards"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22043]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackServerBladeEKeyingOK"},
		{"probableCause", "Server Blade e-keying ok."},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22044]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackNetConnectorRemoved"},
		{"probableCause", "Interconnect removed."},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_MAJOR} | Acc]);
event([{"snmpTrapOID", "compaqq.[22045]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackNetConnectorInserted"},
		{"probableCause", "Interconnect inserted."},
		{"eventType", ?ET_Operational_Violation},
		{"eventSeverity", ?ES_MAJOR} | Acc]);
event([{"snmpTrapOID", "compaqq.[22046]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackNetConnectorFailed"},
		{"probableCause", "The interconnect status has been set to failed."},
		{"eventType", ?ET_Operational_Violation},
		{"eventSeverity", ?ES_CRITICAL},
		{"proposedRepairActions", "Refer to the OA and the status diagnostics reported for the interconnect"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22047]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackNetConnectorDegraded"},
		{"probableCause", "The interconnect status has been set to degrade."},
		{"eventType", ?ET_Operational_Violation},
		{"eventSeverity", ?ES_MAJOR},
		{"proposedRepairActions", "Refer to the OA and the status diagnostics reported for the interconnect"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22048]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackNetConnectorOk"},
		{"probableCause", "The interconnect status has been set to ok."},
		{"eventType", ?ET_Operational_Violation},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22049]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackServerBladeToLowPower"},
		{"probableCause", "Server Blade requested to low power."},
		{"eventType", ?ET_Operational_Violation},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22052]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackServerBladeStatusRepaired"},
		{"probableCause", "Server blade repaired."},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22053]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackServerBladeStatusDegraded"},
		{"probableCause", "Server blade health status Degraded."},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_MAJOR},
		{"proposedRepairActions", "Check the blade server and enclosure SYSLOG"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22054]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackServerBladeStatusCritical"},
		{"probableCause", "Server blade health status Critical."},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_CRITICAL},
		{"proposedRepairActions", "Check the blade server and enclosure SYSLOG"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22055]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackServerBladeGrpCapTimeout"},
		{"probableCause", "The server blade is not responding to the group capper."},
		{"eventType", ?ET_Equipment_Alarm},
		{"eventSeverity", ?ES_CRITICAL},
		{"proposedRepairActions", "Reset the iLO management processor"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22056]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackServerBladeUnexpectedShutdown"},
		{"probableCause", "Server blade shutdown unexpectadly."},
		{"eventType", ?ET_Operational_Violation},
		{"eventSeverity", ?ES_INDETERMINATE},
		{"proposedRepairActions", "Check the blade server and enclosure SYSLOG"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22057]"} | T], Acc) ->
	event(T, [{"alarmCondition", "Rack Server Blade Mangement Controller Firmware Updating"},
		{"probableCause", "Server blade management controller firmware update started."},
		{"eventType", ?ET_Operational_Violation},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22058]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackServerBladeMangementControllerFirmwareUpdateComplete"},
		{"probableCause", "Server blade management controller firmware update completed"},
		{"eventType", ?ET_Operational_Violation},
		{"eventSeverity", ?ET_Communication_System} | Acc]);
event([{"snmpTrapOID", "compaqq.[22059]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackServerBladeSystemBIOSFirmwareUpdating"},
		{"probableCause", "Server blade's system BIOS firmware updating"},
		{"eventType", ?ET_Communication_System},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22060]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackServerBladeSystemBIOSFirmwareUpdateCompleted"},
		{"probableCause", "Server blade's system BIOS firmware update complete"},
		{"eventType", ?ET_Communication_System},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22061]"} | T], Acc) ->
	event(T, [{"alarmCondition", "serverBladeFrontIOBlankingActive"},
		{"probableCause", "Server blade has disabled front IO ports"},
		{"eventType", ?ET_Operational_Violation},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22062]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackServerBladeRemoteFrontIOBlankingInactive"},
		{"probableCause", "Server blade front IO blanking inactive"},
		{"eventType", ?ET_Operational_Violation},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22063]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackServerBladeDiagnosticAdaptorInserted"},
		{"probableCause", "Server blade diagnostic adaptor inserted"},
		{"eventType", ?ET_Physical_Violation},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22064]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackServerBladeDiagnosticAdaptorRemoved"},
		{"probableCause", "Server blade diagnostic adaptor removed"},
		{"eventType", ?ET_Physical_Violation},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22065]"} | T], Acc) ->
	event(T, [{"alarmCondition", "Rack Server Blade Entered PXE BootMode"},
		{"probableCause", "Server blade has entered PXE Boot Mode"},
		{"eventType", ?ET_Operational_Violation},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22066]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackServerBladeExitedPXEBootMode"},
		{"probableCause", "Server blade has exited PXE Boot Mode"},
		{"eventType", ?ET_Operational_Violation},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22067]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackServerBladeWarmReset"},
		{"probableCause", ?ET_Quality_Of_Service_Alarm},
		{"eventType", ?ET_Operational_Violation},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22068]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackServerBladePOSTCompleted"},
		{"probableCause", "Server blade system BIOS POST complete"},
		{"eventType", ?ET_Communication_System},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22069]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackServerBladePoweredOn"},
		{"probableCause", "Server blade has powered on"},
		{"eventType", ?ET_Communication_System},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22070]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackServerBladePoweredOff"},
		{"probableCause", "Server blade has powered off"},
		{"eventType", ?ET_Operational_Violation},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([{"snmpTrapOID", "compaqq.[22078]"} | T], Acc) ->
	event(T, [{"alarmCondition", "rackServerBladePartitionChange"},
		{"probableCause", "Server Blade Partition Changed trap"},
		{"eventType", ?ET_Operational_Violation},
		{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
event([_H | T], Acc) ->
	event(T, Acc);
event([], Acc) ->
	Acc.

