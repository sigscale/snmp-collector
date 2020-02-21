%%% snmp_collector_trap_hpe.erl
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

%% @doc This module normalizes traps received from HPE agents.
%%
%% Varbinds are mapped to alarm attributes, using the MIBs avaialable,
%% and to VES attributes.
%%
%%	The following table shows the mapping between HPE MIB attributes
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

-module(snmp_collector_trap_hpe).
-copyright('Copyright (c) 2016 - 2019 SigScale Global Inc.').

-include("snmp_collector.hrl").

-behaviour(snmpm_user).

%% export snmpm_user call backs.
-export([handle_error/3, handle_agent/5,
		handle_pdu/4, handle_trap/3, handle_inform/3,
		handle_report/3, fault/1, notification/1]).

%% support deprecated_time_unit()
-define(MILLISECOND, milli_seconds).
%-define(MILLISECOND, millisecond).
-define(MICROSECOND, micro_seconds).
%-define(MICROSECOND, microsecond).

% calendar:datetime_to_gregorian_seconds({{1970,1,1},{0,0,0}})
-define(EPOCH, 62167219200).

%%----------------------------------------------------------------------
%%  The snmp_collector_trap_hpe public API
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
handle_trap(TargetName, {ErrorStatus, ErrorIndex, Varbinds}, UserData) ->
	case domain(Varbinds) of
		other ->
			snmp_collector_trap_generic:handle_trap(TargetName, {ErrorStatus,
					ErrorIndex, Varbinds}, UserData);
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
%% @doc Handle a fault event.
handle_fault(TargetName, Varbinds) ->
	try
		{ok, Pairs} = snmp_collector_utils:arrange_list(Varbinds),
		{ok, NamesValues} = snmp_collector_utils:oids_to_names(Pairs, []),
		AlarmDetails = fault(NamesValues),
		snmp_collector_utils:update_counters(hpe, TargetName, AlarmDetails),
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
		VesValue :: string().
%% @doc CODEC for event.
fault(OidNameValuePair) ->
	fault(OidNameValuePair, []).
%% @hidden
fault([{"snmpTrapOID", "compaq.[22005]"}, {"sysName", SysName},
		{"cpqRackName", RackName}, {"cpqRackUid", RackUid}, {"cpqRackEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTempLocation", TempLocation},
		{"cpqRackCommonEnclosureSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", ?EN_NEW},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackEnclosureTempFailed"},
			{"probableCause", "Temperature Unacceptable"},
			{"eventType", ?ET_Environmental_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"specificProblem", "The temperature sensor" ++ TempLocation ++ "in enclosure" ++
				EnclosureName ++ "in rack" ++ RackName ++ "has been set to failed."},
			{"proposedRepairActions", "Shutdown the enclosure and possibly the rack as soon as
					possible. Ensure all fans are working properly and that air flow in the rack
					has not been blocked."},
			{"enclosureName", EnclosureName},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", RackTrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22006]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTempLocation", TempLocation},
		{"cpqRackCommonEnclosureSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackEnclosureTempDegraded"},
			{"probableCause", ?PC_Temperature_Unacceptable},
			{"eventType", ?ET_Environmental_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "The temperature sensor" ++ TempLocation ++ "in enclosure" ++
				EnclosureName ++ "in rack" ++ RackName ++ "has been set to degraded."},
			{"proposedRepairActions", "Shutdown the enclosure and possibly the rack as soon as
					possible. Ensure all fans are working properly and that air flow in the rack
					has not been blocked."},
			{"enclosureName", EnclosureName},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", RackTrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22007]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTempLocation", TempLocation},
		{"cpqRackCommonEnclosureSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackEnclosureTempOk"},
			{"probableCause", "Temperature Ok"},
			{"eventType", ?ET_Environmental_Alarm},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "The temperature sensor" ++ TempLocation ++ "in enclosure" ++
				EnclosureName ++ "in rack" ++ RackName ++ "has been set to ok."},
			{"enclosureName", EnclosureName},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", RackTrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22008]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureFanLocation", FanLocation},
		{"cpqRackCommonEnclosureSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackEnclosureFanFailed"},
			{"probableCause", ?PC_Cooling_System_Failure},
			{"eventType", ?ET_Environmental_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"specificProblem", "The fan " ++ FanLocation ++ "in enclosure" ++
				EnclosureName ++ "in rack" ++ RackName ++ "has been set to failed."},
			{"proposedRepairActions", "Replace the failed enclosure fan."},
			{"enclosureName", EnclosureName},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", RackTrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22009]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureFanLocation", FanLocation},
		{"cpqRackCommonEnclosureFanSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackEnclosureFanDegraded"},
			{"probableCause", ?PC_Cooling_System_Failure},
			{"eventType", ?ET_Environmental_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "The fan " ++ FanLocation ++ "in enclosure" ++
				EnclosureName ++ "in rack" ++ RackName ++ "has been set to degraded."},
			{"proposedRepairActions", "Replace the failing enclosure fan."},
			{"enclosureName", EnclosureName},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", RackTrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22010]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureFanLocation", FanLocation},
		{"cpqRackCommonEnclosureFanSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackEnclosureFanOk"},
			{"probableCause", "Enclosure fan ok"},
			{"eventType", ?ET_Environmental_Alarm},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "The fan " ++ FanLocation ++ "in enclosure" ++
				EnclosureName ++ "in rack" ++ RackName ++ "has been set to ok."},
			{"enclosureName", EnclosureName},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", RackTrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22011]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureFanLocation", FanLocation},
		{"cpqRackCommonEnclosureFanSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackEnclosureFanRemoved"},
			{"probableCause", "Enclosure fan removed"},
			{"eventType", ?ET_Physical_Violation},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "The fan " ++ FanLocation ++ "in enclosure" ++
				EnclosureName ++ "in rack" ++ RackName ++ "has been removed."},
			{"enclosureName", EnclosureName},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", RackTrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22012]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureFanLocation", FanLocation},
		{"cpqRackCommonEnclosureFanSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackEnclosureFanInserted"},
			{"probableCause", "Enclosure fan inserted"},
			{"eventType", ?ET_Physical_Violation},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "The fan " ++ FanLocation ++ "in enclosure" ++
				EnclosureName ++ "in rack" ++ RackName ++ "has been inserted."},
			{"enclosureName", EnclosureName},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"fanLocation", FanLocation},
			{"fanSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", RackTrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22013]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackPowerSupplyEnclosureName", EnclosureName},
		{"cpqRackPowerSupplySerialNum", SerialNum},
		{"cpqRackPowerSupplyFWRev", PowerSupplyFWRev},
		{"cpqRackPowerSupplyPosition", PowerSupplyLocation},
		{"cpqRackPowerSupplySparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", SerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackPowerSupplyFailed"},
			{"probableCause", ?PC_Power_Supply_Failure},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"specificProblem", "The power supply " ++ PowerSupplyLocation ++ "in enclosure" ++
				EnclosureName ++ "in rack" ++ RackName ++ "has been set to failed."},
			{"proposedRepairActions", "Replace the failed power supply"},
			{"enclosureName", EnclosureName},
			{"powerSupplySerialNum", SerialNum},
			{"powerSupplyFwRev", PowerSupplyFWRev},
			{"powerSupplyLocation", PowerSupplyLocation},
			{"powerSupplySparePartNum", SparePartNumber},
			{"enclosureTrapSerialNum", SerialNum},
			{"enclosureTrapSequenceNum", RackTrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22014]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackPowerSupplyEnclosureName", EnclosureName},
		{"cpqRackPowerSupplySerialNum", SerialNum},
		{"cpqRackPowerSupplyFWRev", PowerSupplyFWRev},
		{"cpqRackPowerSupplyPosition", PowerSupplyLocation},
		{"cpqRackPowerSupplySparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", SerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackPowerSupplyDegraded"},
			{"probableCause", ?PC_Power_Supply_Failure},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "The power supply " ++ PowerSupplyLocation ++ "in enclosure" ++
				EnclosureName ++ "in rack" ++ RackName ++ "has been set to degraded."},
			{"proposedRepairActions", "Replace the failing power supply"},
			{"enclosureName", EnclosureName},
			{"powerSupplySerialNum", SerialNum},
			{"powerSupplyFwRev", PowerSupplyFWRev},
			{"powerSupplyLocation", PowerSupplyLocation},
			{"powerSupplySparePartNum", SparePartNumber},
			{"enclosureTrapSerialNum", SerialNum},
			{"enclosureTrapSequenceNum", RackTrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22015]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackPowerSupplyEnclosureName", EnclosureName},
		{"cpqRackPowerSupplySerialNum", SerialNum},
		{"cpqRackPowerSupplyFWRev", PowerSupplyFWRev},
		{"cpqRackPowerSupplyPosition", PowerSupplyLocation},
		{"cpqRackPowerSupplySparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", SerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackPowerSupplyOk"},
			{"probableCause", "Rack power supply ok"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "The power supply " ++ PowerSupplyLocation ++ "in enclosure" ++
				EnclosureName ++ "in rack" ++ RackName ++ "has been set to ok."},
			{"enclosureName", EnclosureName},
			{"powerSupplySerialNum", SerialNum},
			{"powerSupplyFwRev", PowerSupplyFWRev},
			{"powerSupplyLocation", PowerSupplyLocation},
			{"powerSupplySparePartNum", SparePartNumber},
			{"enclosureTrapSerialNum", SerialNum},
			{"enclosureTrapSequenceNum", RackTrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22016]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackPowerSupplyEnclosureName", EnclosureName},
		{"cpqRackPowerSupplySerialNum", SerialNum},
		{"cpqRackPowerSupplyFWRev", PowerSupplyFWRev},
		{"cpqRackPowerSupplyPosition", PowerSupplyLocation},
		{"cpqRackPowerSupplySparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", SerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackPowerSupplyRemoved"},
			{"probableCause", "Rack power supply removed"},
			{"eventType", ?ET_Physical_Violation},
			{"eventSeverity", ?ES_MINOR},
			{"specificProblem", "The power supply " ++ PowerSupplyLocation ++ "in enclosure" ++
				EnclosureName ++ "in rack" ++ RackName ++ "has been removed."},
			{"enclosureName", EnclosureName},
			{"powerSupplySerialNum", SerialNum},
			{"powerSupplyFwRev", PowerSupplyFWRev},
			{"powerSupplyLocation", PowerSupplyLocation},
			{"powerSupplySparePartNum", SparePartNumber},
			{"enclosureTrapSerialNum", SerialNum},
			{"enclosureTrapSequenceNum", RackTrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22017]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackPowerSupplyEnclosureName", EnclosureName},
		{"cpqRackPowerSupplySerialNum", SerialNum},
		{"cpqRackPowerSupplyFWRev", PowerSupplyFWRev},
		{"cpqRackPowerSupplyPosition", PowerSupplyLocation},
		{"cpqRackPowerSupplySparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", SerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackPowerSupplyInserted"},
			{"probableCause", "Rack power supply inserted "},
			{"eventType", ?ET_Physical_Violation},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "The power supply " ++ PowerSupplyLocation ++ "in enclosure" ++
				EnclosureName ++ "in rack" ++ RackName ++ "has been inserted."},
			{"enclosureName", EnclosureName},
			{"powerSupplySerialNum", SerialNum},
			{"powerSupplyFwRev", PowerSupplyFWRev},
			{"powerSupplyLocation", PowerSupplyLocation},
			{"powerSupplySparePartNum", SparePartNumber},
			{"enclosureTrapSerialNum", SerialNum},
			{"enclosureTrapSequenceNum", RackTrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22018]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackPowerSupplyEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", SerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackPowerSubsystemNotRedundant"},
			{"probableCause", "Rack power subsystem not redundant."},
			{"eventType", ?ET_Quality_Of_Service_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "The power supply subsystem in enclosure" ++ EnclosureName ++
					"in rack" ++ RackName ++ "is no longer redundant."},
			{"proposedRepairActions", "Replace any failed power supplies as soon as possible
					to return the system to a redundant state"},
			{"enclosureName", EnclosureName},
			{"enclosureTrapSerialNum", SerialNum},
			{"enclosureTrapSequenceNum", RackTrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22019]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackPowerSupplyEnclosureName", EnclosureName},
		{"cpqRackPowerSupplyPosition", PowerSupplyPosition}, {"cpqRackPowerSupplyFWRev", PowerSupplyFWRev},
		{"cpqRackPowerSupplyInputLineStatus", InputLineStatus},
		{"cpqRackPowerSupplySparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", SerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackPowerSubsystemLineVoltageProblem"},
			{"probableCause", "Rack power supply input voltage problem."},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "The rack power supply detected an input line voltage problem in power supply"
					++ PowerSupplyPosition ++ ",enclosure " ++ EnclosureName ++ "rack" ++ RackName},
			{"proposedRepairActions", "Replace any failed power supplies as soon as possible
					to return the system to a redundant state"},
			{"enclosureName", EnclosureName},
			{"powerSupplyFWRev", PowerSupplyFWRev},
			{"powerSupplyInputLineStatus", InputLineStatus},
			{"powerSupplySparePartNumber", SparePartNumber},
			{"enclosureTrapSerialNum", SerialNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22020]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackPowerEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSparePartNumber", SparePartNumber}, {"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackPowerSubsystemOverloadCondition"},
			{"probableCause", "Rack power subsystem overload condition."},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "The power subsystem in enclosure" ++ EnclosureName ++ "in rack" ++ RackName
					++ "is in an overload condition."},
			{"proposedRepairActions", "Replace any failed power supplies as soon as possible"},
			{"enclosureName", EnclosureName},
			{"enclosureTrapSerialNum", EnclosureSerialNum},
			{"enclosureSparePartNumber", SparePartNumber},
			{"commonEnclosureSerialNum", EnclosureSerialNum},
			{"enclosSerialNum", EnclosureSerialNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22021]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladePosition", BladePosition}, {"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackPowerShedAutoShutdown"},
			{"probableCause", "The server shutdown due to lack of power blade.."},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"specificProblem", "The server shutdown due to lack of power blade" ++ BladePosition ++
					"in enclosure" ++ EnclosureName ++ "in rack" ++ RackName},
			{"proposedRepairActions", "Replace any failed power supplies as soon as possible"},
			{"enclosureName", EnclosureName},
			{"bladePosition", BladePosition},
			{"enclosureSparePartNumber", SparePartNumber},
			{"enclosureTrapSerialNum", EnclosureSerialNum},
			{"enclosureSerialNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22022]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", BladeEnclosureName},
		{"cpqRackServerBladePosition", BladePosition}, {"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerPowerOnFailedNotRedundant"},
			{"probableCause", "Server power on prevented to preserve redundancy in blade."},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"specificProblem", "Server power on prevented to preserve redundancy in blade" ++ BladePosition ++
					"in enclosure" ++  BladeEnclosureName ++ "in rack" ++ RackName},
			{"proposedRepairActions", "Check the power connections for problems,
					then add power supplies if necessary"},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureManagerSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22023]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", BladeEnclosureName},
		{"cpqRackServerBladePosition", BladePosition}, {"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerPowerOnFailedNotEnoughPower"},
			{"probableCause", "Inadequate power to power on.."},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"specificProblem", "Inadequate power to power on blade" ++ BladePosition ++ "in enclosure" ++
					BladeEnclosureName ++ "in rack" ++ RackName},
			{"proposedRepairActions", "Check the power connections for problems,
					then add power supplies if necessary"},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureManagerSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22024]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", BladeEnclosureName},
		{"cpqRackServerBladePosition", BladePosition}, {"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerPowerOnFailedEnclosureNotFound"},
			{"probableCause", "Inadequate power to power on.."},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"specificProblem", "Inadequate power to power on blade" ++ BladePosition ++ "in enclosure" ++
					BladeEnclosureName ++ "in rack" ++ RackName},
			{"proposedRepairActions", "Check the power connections for problems,
					then add power supplies if necessary"},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureManagerSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22025]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", BladeEnclosureName},
		{"cpqRackServerBladePosition", BladePosition}, {"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerPowerOnFailedPowerChassisNotFound"},
			{"probableCause", "Inadequate power to power on.."},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"specificProblem", "Inadequate power to power on blade" ++ BladePosition ++ "in enclosure" ++
					BladeEnclosureName ++ "in rack" ++ RackName},
			{"proposedRepairActions", "Check the power connections for problems,
					then add power supplies if necessary"},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureManagerSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22026]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", BladeEnclosureName},
		{"cpqRackServerBladePosition", BladePosition}, {"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerPowerOnManualOverride"},
			{"probableCause", "Server power On via manual override"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "Server power on via manual override on blade" ++ BladePosition ++ " in enclosure,"
					++ BladeEnclosureName ++ "in rack" ++ RackName},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureManagerSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22027]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureFuseLocation", FuseLocation}, {"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackFuseOpen"},
			{"probableCause", "Fuse Open"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "Fuse open fuse" ++ FuseLocation ++ ",in enclosure" ++ EnclosureName ++
					 "in rack" ++ RackName},
			{"proposedRepairActions", "Check the enclosure and blade power connections,
					then reset the fuse"},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureManagerSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22028]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerBladeRemoved"},
			{"probableCause", "Server Blade Removed"},
			{"eventType", ?ET_Physical_Violation},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "Server blade" ++ BladeName ++ " removed from position" ++ BladePosition ++
					",in enclosure" ++ EnclosureName ++ "in rack" ++ RackName},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureManagerSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22029]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerBladeInserted"},
			{"probableCause", "Server blade inserted."},
			{"eventType", ?ET_Physical_Violation},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "Server blade" ++ BladeName ++ " inserted into position" ++ BladePosition ++
					",in enclosure" ++ EnclosureName ++ "in rack" ++ RackName},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureManagerSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22030]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "cpqRackPowerChassisNotLoadBalanced"},
			{"probableCause", "Power subsystem not load balanced."},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "Power subsystem load not balanced in enclosure" ++ EnclosureName ++ "in rack" ++ RackName},
			{"proposedRepairActions", "Check the power enclosure and power supplies. Replace any failed or
					degraded power supplies. Add additional power supplies if needed."},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureManagerSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22031]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackPowerChassisDcPowerProblem"},
			{"probableCause", "Power subsystem DC power problem."},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "Power subsystem DC power problem in enclosure"
					++ EnclosureName ++ "in rack"++ RackName},
			{"proposedRepairActions", "Check the power enclosure and power supplies.
					Replace any failed or degraded power supplies"},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureManagerSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22032]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackPowerChassisAcFacilityPowerExceeded"},
			{"probableCause", "Power subsystem AC facility input power exceeded."},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "Power subsystem AC facility input power exceeded in enclosure"
					++ EnclosureName ++ "in rack" ++ RackName},
			{"proposedRepairActions", "Check the power enclosure and power supplies.
					Replace any failed or degraded power supplies"},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureManagerSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22033]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackPowerUnknownPowerConsumption"},
			{"probableCause", "Unknown power consumption."},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "Unknown power consumption in rack" ++ RackName},
			{"proposedRepairActions", "Check the power enclosure and power supplies.
					Replace any failed or degraded power supplies"},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22034]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackPowerChassisLoadBalancingWireMissing"},
			{"probableCause", "Power subsystem load balancing wire missing "},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "Power subsystem load balancing wire missing for enclosure,"
					++ EnclosureName ++ "in rack" ++ RackName},
			{"proposedRepairActions", "Connect the load balancing wire."},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureManagerSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22035]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackPowerChassisTooManyPowerChassis"},
			{"probableCause", "Power subsystem has too may power enclosures."},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "Power subsystem has too may power enclosures in" ++ EnclosureName
					++ "in rack" ++ RackName},
			{"proposedRepairActions", "Remove the extra power enclosure"},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22036]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackPowerChassisConfigError"},
			{"probableCause", "Power subsystem improperly configured."},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "Power subsystem has been improperly configured in enclosure"
					++ EnclosureName ++ "in rack" ++ RackName},
			{"proposedRepairActions", "Check the cabling of the power enclosure."},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22037]"},  {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureManagerLocation", ManagerLocation},
		{"cpqRackCommonEnclosureManagerSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureManagerSerialNum", ManagerSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackEnclosureManagerDegraded"},
			{"probableCause", ?PC_Power_Problem},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "The enclosure" ++ EnclosureName ++ "manager in rack" ++ RackName ++ "has been set to degraded"},
			{"proposedRepairActions", "The following conditions can result in a degraded Onboard Administrator"
					"1) one OA failed but the second OA is still operating"
					"2) one or more OAs is in a non-optimal operating state"
					"3) a firmware revision mismatch occurred between the primary and secondary OAs,
					To determine what caused the issue, see the OA and check the logs for more information,
					If a firmware mismatch occurred, use the OA UI or CLI (UPDATE IMAGE SYNC command)
					to resynchronizethe firmware on the OAs."},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureManagerLocation", ManagerLocation},
			{"enclosureManagerSparePartNumber", SparePartNumber},
			{"enclosureManagerSerialNum", ManagerSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22038]"},  {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureManagerLocation", ManagerLocation},
		{"cpqRackCommonEnclosureManagerSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureManagerSerialNum", ManagerSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackEnclosureManagerOK"},
			{"probableCause", "Onboard or management processor ok."},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "The Onboard Administrator or management processor" ++ EnclosureName ++
					"in rack" ++ RackName ++ "has been set to ok"},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureManagerLocation", ManagerLocation},
			{"enclosureManagerSparePartNumber", SparePartNumber},
			{"enclosureManagerSerialNum", ManagerSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22039"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureManagerLocation", ManagerLocation},
		{"cpqRackCommonEnclosureManagerSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureManagerSerialNum", ManagerSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackEnclosureManagerRemoved"},
			{"probableCause", "Onboard Administrator removed."},
			{"eventType", ?ET_Physical_Violation},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "The Onboard Administrator or management processor" ++ EnclosureName ++
					"in rack" ++ RackName ++ "has been removed"},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureManagerLocation", ManagerLocation},
			{"enclosureManagerSparePartNumber", SparePartNumber},
			{"enclosureManagerSerialNum", ManagerSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22040]"},  {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureManagerLocation", ManagerLocation},
		{"cpqRackCommonEnclosureManagerSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureManagerSerialNum", ManagerSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackEnclosureManagerInserted"},
			{"probableCause", "Onboard Administrator inserted."},
			{"eventType", ?ET_Physical_Violation},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "The Onboard Administrator or management processor" ++ EnclosureName ++
					"in rack" ++ RackName ++ "has been inserted"},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureManagerLocation", ManagerLocation},
			{"enclosureManagerSparePartNumber", SparePartNumber},
			{"enclosureManagerSerialNum", ManagerSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22041]"},  {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureManagerLocation", ManagerLocation},
		{"cpqRackCommonEnclosureManagerSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureManagerSerialNum", ManagerSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackManagerPrimaryRole"},
			{"probableCause", "Onboard Administrator as taken the role of primary."},
			{"eventType", ?ET_Operational_Violation},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "The Onboard Administrator or management processor" ++ EnclosureName ++
					"in rack" ++ RackName ++ "has taken the role of primary."},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureManagerLocation", ManagerLocation},
			{"enclosureManagerSparePartNumber", SparePartNumber},
			{"enclosureManagerSerialNum", ManagerSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22042]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerBladeEKeyingFailed"},
			{"probableCause", "Server Blade e-keying failed."},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "Server blade" ++ BladeName ++ "e-keying failed in position" ++ BladePosition
				++ "in enclosure" ++ EnclosureName ++ "in rack" ++ RackName},
			{"proposedRepairActions", "Reconfigure the server blade mezz cards."},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"serverBladePosition", BladePosition},
			{"enclosureManagerSparePartNumber", SparePartNumber},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22043]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerBladeEKeyingOK"},
			{"probableCause", "Server Blade e-keying ok."},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "Server blade" ++ BladeName ++ "e-keying is ok in position" ++ BladePosition
				++ "in enclosure" ++ EnclosureName ++ "in rack" ++ RackName},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"serverBladePosition", BladePosition},
			{"enclosureManagerSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22044]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackNetConnectorEnclosureName", EnclosureName},
		{"cpqRackNetConnectorName", ConnectorName}, {"cpqRackNetConnectorLocation", ConnectorLocation},
		{"cpqRackNetConnectorSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackNetConnectorRemoved"},
			{"probableCause", "Interconnect removed."},
			{"eventType", ?ET_Physical_Violation},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "Interconnect" ++ ConnectorName ++  "removed from position" ++
					ConnectorLocation ++ "in enclosure" ++ EnclosureName ++  "in rack" ++ RackName},
			{"rackNetConnectorName", ConnectorName},
			{"rackNetConnectorLocation", ConnectorLocation},
			{"enclosureManagerSparePartNumber", SparePartNumber},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22045]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackNetConnectorEnclosureName", EnclosureName},
		{"cpqRackNetConnectorName", ConnectorName}, {"cpqRackNetConnectorLocation", ConnectorLocation},
		{"cpqRackNetConnectorSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackNetConnectorInserted"},
			{"probableCause", "Interconnect inserted."},
			{"eventType", ?ET_Physical_Violation},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "Interconnect" ++ ConnectorName ++  "inserted into position" ++
					ConnectorLocation ++ "in enclosure" ++ EnclosureName ++  "in rack" ++ RackName},
			{"rackNetConnectorName", ConnectorName},
			{"rackNetConnectorLocation", ConnectorLocation},
			{"enclosureManagerSparePartNumber", SparePartNumber},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22046]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackNetConnectorEnclosureName", EnclosureName},
		{"cpqRackNetConnectorName", ConnectorName}, {"cpqRackNetConnectorLocation", ConnectorLocation},
		{"cpqRackNetConnectorSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackNetConnectorFailed"},
			{"probableCause", "The interconnect status has been set to failed."},
			{"eventType", ?ET_Physical_Violation},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "Interconnect" ++ ConnectorName ++  "failed in position" ++
					ConnectorLocation ++ "in enclosure" ++ EnclosureName ++  "in rack" ++ RackName},
			{"proposedRepairActions", "Refer to the OA and the status diagnostics reported for the interconnect"},
			{"rackNetConnectorName", ConnectorName},
			{"rackNetConnectorLocation", ConnectorLocation},
			{"rackNetConnectorSparePartNumber", SparePartNumber},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22047]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackNetConnectorEnclosureName", EnclosureName},
		{"cpqRackNetConnectorName", ConnectorName}, {"cpqRackNetConnectorLocation", ConnectorLocation},
		{"cpqRackNetConnectorSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackNetConnectorDegraded"},
			{"probableCause", "The interconnect status has been set to degrade."},
			{"eventType", ?ET_Physical_Violation},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "Interconnect" ++ ConnectorName ++  "degraded in position" ++
					ConnectorLocation ++ "in enclosure" ++ EnclosureName ++  "in rack" ++ RackName},
			{"proposedRepairActions", "Refer to the OA and the status diagnostics reported for the interconnect"},
			{"rackNetConnectorName", ConnectorName},
			{"rackNetConnectorLocation", ConnectorLocation},
			{"rackNetConnectorSparePartNumber", SparePartNumber},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22048]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackNetConnectorEnclosureName", EnclosureName},
		{"cpqRackNetConnectorName", ConnectorName}, {"cpqRackNetConnectorLocation", ConnectorLocation},
		{"cpqRackNetConnectorSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackNetConnectorOk"},
			{"probableCause", "The interconnect status has been set to ok ."},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "Interconnect" ++ ConnectorName ++  "okin position" ++
					ConnectorLocation ++ "in enclosure" ++ EnclosureName ++  "in rack" ++ RackName},
			{"proposedRepairActions", "Refer to the OA and the status diagnostics reported for the interconnect"},
			{"rackNetConnectorName", ConnectorName},
			{"rackNetConnectorLocation", ConnectorLocation},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"rackNetConnectorSparePartNumber", SparePartNumber},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22049]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerBladeToLowPower"},
			{"probableCause", "Server Blade requested to low power."},
			{"eventType", ?ET_Operational_Violation},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem","Server blade" ++ BladeName ++ "requested to low power in position" ++ BladePosition ++
					"in enclosure" ++ EnclosureName ++  "in rack" ++ RackName},
			{"serverBladeName", BladeName},
			{"serverBladePosition", BladePosition},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"bladeSparePartNumber", SparePartNumber},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22050]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeUid", ServerBladeUid},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerBladeRemoved2"},
			{"probableCause", "Server blade removed ."},
			{"eventType", ?ET_Physical_Violation},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "Server blade" ++ BladeName ++ "removed from position" ++ BladePosition
					++ "in enclosure" ++ EnclosureName ++  "in rack" ++ RackName},
			{"serverBladeName", BladeName},
			{"serverBladePosition", BladePosition},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"serverBladeUid", ServerBladeUid},
			{"bladeSparePartNumber", SparePartNumber},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22051]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "cpqRackServerBladeInserted2"},
			{"probableCause", "Server blade inserted "},
			{"eventType", ?ET_Quality_Of_Service_Alarm},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "Server blade" ++ BladeName ++ "inserted into position" ++ BladePosition
					++ "in enclosure" ++ EnclosureName ++  "in rack" ++ RackName},
			{"serverBladeName", BladeName},
			{"serverBladePosition", BladePosition},
			{"enclosureSerialNum", BladePosition},
			{"serverBladeUid", BladeUid},
			{"bladeSparePartNumber", SparePartNumber},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22052]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladeProductId", BladeProductId},
		{"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerBladeStatusRepaired"},
			{"probableCause", "Server blade repaired."},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "Server blade" ++ BladeName ++ "in position" ++ BladePosition ++ "in enclosure" ++
					EnclosureName ++ "in rack" ++ RackName ++ "status has changed to OK."},
			{"serverBladeName", BladeName},
			{"serverBladeProductId", BladeProductId},
			{"serverBladePosition", BladePosition},
			{"enclosureSerialNum", BladePosition},
			{"serverBladeUid", BladeUid},
			{"bladeSparePartNumber", SparePartNumber},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22053]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladeProductId", BladeProductId},
		{"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladeFaultMajor", BladeFaultMajor},
		{"cpqRackServerBladeFaultMinor", BladeFaultMinor},
		{"cpqRackServerBladeFaultDiagnosticString", DiagnosticString},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerBladeStatusDegraded"},
			{"probableCause", "Server blade health status Degraded."},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem" "Server blade %s in position" ++ BladePosition ++ "in enclosure" ++ EnclosureName ++
					"in rack" ++ RackName ++  "health status has changed to degraded. Reason:" ++ DiagnosticString},
			{"proposedRepairActions","Check the blade server and enclosure SYSLOG."},
			{"serverBladeName", BladeName},
			{"serverBladeProductId", BladeProductId},
			{"serverBladeUid", BladeUid},
			{"bladeFaultMajor", BladeFaultMajor},
			{"bladeFaultMinor", BladeFaultMinor},
			{"enclosureSerialNum", BladePosition},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"bladeSparePartNumber", SparePartNumber},
			{"bladeSerialNum", BladeSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22054]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladeProductId", BladeProductId},
		{"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladeFaultMajor", BladeFaultMajor},
		{"cpqRackServerBladeFaultMinor", BladeFaultMinor},
		{"cpqRackServerBladeFaultDiagnosticString", DiagnosticString},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerBladeStatusCritical"},
			{"probableCause", "Server blade health status Critical."},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem" "Server blade %s in position" ++ BladePosition ++ "in enclosure" ++ EnclosureName ++
					"in rack" ++ RackName ++ "health status has changed to Critical. Reason:" ++ DiagnosticString},
			{"proposedRepairActions","Check the blade server and enclosure SYSLOG."},
			{"serverBladeName", BladeName},
			{"serverBladeProductId", BladeProductId},
			{"serverBladePosition", BladePosition},
			{"enclosureSerialNum", BladeSerialNum},
			{"serverBladeUid", BladeUid},
			{"bladeFaultMajor", BladeFaultMajor},
			{"bladeFaultMinor", BladeFaultMinor},
			{"bladeSparePartNumber", SparePartNumber},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22055]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerBladeGrpCapTimeout"},
			{"probableCause", "The server blade is not responding to the group capper.."},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem" "Server blade %s in position" ++ BladePosition ++ "in enclosure" ++ EnclosureName ++
					"in rack" ++ RackName ++ "is not responding to requests from the enclosure group capper."},
			{"proposedRepairActions","Check the blade server and enclosure SYSLOG."},
			{"serverBladeName", BladeName},
			{"serverBladePosition", BladePosition},
			{"enclosureSerialNum", BladeSerialNum},
			{"bladeSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22056]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerBladeUnexpectedShutdown"},
			{"probableCause", "Server blade shutdown unexpectadly."},
			{"eventType", ?ET_Operational_Violation},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem" "Server blade %s in position" ++ BladePosition ++ "in enclosure" ++ EnclosureName ++
					"in rack" ++ RackName ++ "has unexpectedly shutdown."},
			{"proposedRepairActions","Check the blade server and enclosure SYSLOG."},
			{"serverBladeName", BladeName},
			{"serverBladePosition", BladePosition},
			{"enclosureSerialNum", BladeSerialNum},
			{"serverBladeUid", BladeUid},
			{"bladeSparePartNumber", SparePartNumber},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22057]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladeManagementDeviceFirmwareFlashingStatus", FirmwareFlashingStatus},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerBladeMangementControllerFirmwareUpdating"},
			{"probableCause", "Server blade management controller firmware update started.."},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem" "Server blade" ++ BladeName ++ "in position," ++ BladePosition ++ "in enclosure"
					++ EnclosureName ++  "in rack" ++ RackName ++ "has started updating it's management controller firmware."},
			{"serverBladeName", BladeName},
			{"serverBladePosition", BladePosition},
			{"enclosureSerialNum", BladeSerialNum},
			{"serverBladeUid", BladeUid},
			{"deviceFrirmwareFlashingStatus", FirmwareFlashingStatus},
			{"bladeSparePartNumber", SparePartNumber},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22058]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladeManagementDeviceFirmwareFlashingStatus", FirmwareFlashingStatus},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerBladeMangementControllerFirmwareUpdateComplete"},
			{"probableCause", "Server blade management controller firmware update completed"},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem" "Server blade" ++ BladeName ++ "in position," ++ BladePosition ++ "in enclosure"
					++ EnclosureName ++  "in rack" ++ RackName ++ "has finished updating it's management controller firmware."},
			{"serverBladeName", BladeName},
			{"serverBladePosition", BladePosition},
			{"enclosureSerialNum", BladeSerialNum},
			{"serverBladeUid", BladeUid},
			{"deviceFrirmwareFlashingStatus", FirmwareFlashingStatus},
			{"bladeSparePartNumber", SparePartNumber},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22059]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladeSystemBIOSFlashingStatus", FirmwareFlashingStatus},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerBladeSystemBIOSFirmwareUpdating"},
			{"probableCause", "Server blade's system BIOS firmware updating"},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem" "Server blade" ++ BladeName ++ "in position," ++ BladePosition ++ "in enclosure"
					++ EnclosureName ++  "in rack" ++ RackName ++ "has started updating it's system BIOS firmware."},
			{"serverBladeName", BladeName},
			{"serverBladePosition", BladePosition},
			{"enclosureSerialNum", BladeSerialNum},
			{"serverBladeUid", BladeUid},
			{"deviceBIOSFlashingStatus", FirmwareFlashingStatus},
			{"bladeSparePartNumber", SparePartNumber},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22060]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladeSystemBIOSFlashingStatus", FirmwareFlashingStatus},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerBladeSystemBIOSFirmwareUpdateCompleted"},
			{"probableCause", "Server blade's system BIOS firmware update complete"},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem" "Server blade" ++ BladeName ++ "in position," ++ BladePosition ++ "in enclosure"
					++ EnclosureName ++  "in rack" ++ RackName ++ "has finished updating it's system BIOS firmware."},
			{"serverBladeName", BladeName},
			{"serverBladePosition", BladePosition},
			{"enclosureSerialNum", BladeSerialNum},
			{"serverBladeUid", BladeUid},
			{"deviceBIOSFlashingStatus", FirmwareFlashingStatus},
			{"bladeSparePartNumber", SparePartNumber},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22061]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladeFrontIOBlankingModeStatus", BladeFrontIOBlankingModeStatus},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "serverBladeFrontIOBlankingActive"},
			{"probableCause", "Server blade has disabled front IO ports"},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "Server blade" ++ BladeName ++ "in position" ++ BladePosition ++ "in enclosure,"
					++ EnclosureName ++ " in rack" ++ RackName ++ "has disabled front IO."},
			{"serverBladeName", BladeName},
			{"serverBladePosition", BladePosition},
			{"enclosureSerialNum", BladeSerialNum},
			{"serverBladeUid", BladeUid},
			{"frontIOBlankingModeStatus", BladeFrontIOBlankingModeStatus},
			{"bladeSparePartNumber", SparePartNumber},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22062]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladeFrontIOBlankingModeStatus", BladeFrontIOBlankingModeStatus},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "serverBladeRemoteFrontIOBlankingInactive"},
			{"probableCause", "Server blade front IO blanking inactive"},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "Server blade" ++ BladeName ++ "in position" ++ BladePosition ++ "in enclosure,"
					++ EnclosureName ++ " in rack" ++ RackName ++ "has enabled front IO."},
			{"serverBladeName", BladeName},
			{"serverBladePosition", BladePosition},
			{"enclosureSerialNum", BladeSerialNum},
			{"serverBladeUid", BladeUid},
			{"frontIOBlankingModeStatus", BladeFrontIOBlankingModeStatus},
			{"bladeSparePartNumber", SparePartNumber},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22063]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladeDiagnosticAdaptorPresence", DiagnosticAdaptorPresence},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerBladeDiagnosticAdaptorInserted"},
			{"probableCause", "Server blade diagnostic adaptor inserted"},
			{"eventType", ?ET_Physical_Violation},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "Server blade" ++ BladeName ++ "in position" ++ BladePosition ++ "in enclosure"
					++ EnclosureName ++ "in rack" ++ RackName ++ "diagnostic adaptor inserted."},
			{"serverBladeName", BladeName},
			{"serverBladePosition", BladePosition},
			{"enclosureSerialNum", BladeSerialNum},
			{"serverBladeUid", BladeUid},
			{"diagnosticAdaptorPresence", DiagnosticAdaptorPresence},
			{"bladeSparePartNumber", SparePartNumber},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22064]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladeDiagnosticAdaptorPresence", DiagnosticAdaptorPresence},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerBladeDiagnosticAdaptorRemoved"},
			{"probableCause", "Server blade diagnostic adaptor removed"},
			{"eventType", ?ET_Physical_Violation},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "Server blade" ++ BladeName ++ "in position" ++ BladePosition ++ "in enclosure"
					++ EnclosureName ++ "in rack" ++ RackName ++ "diagnostic adaptor removed."},
			{"serverBladeName", BladeName},
			{"serverBladePosition", BladePosition},
			{"enclosureSerialNum", BladeSerialNum},
			{"serverBladeUid", BladeUid},
			{"bladeSparePartNumber", SparePartNumber},
			{"diagnosticAdaptorPresence", DiagnosticAdaptorPresence},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22065]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladePXEBootModeStatus", PXEBootModeStatus},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerBladeEnteredPXEBootMode"},
			{"probableCause", "Server blade has entered PXE Boot Mode"},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "Server blade" ++ BladeName ++ "in position" ++ BladePosition ++ "in enclosure"
					++ EnclosureName ++ "in rack" ++ RackName ++ "has entered PXE Boot Mode."},
			{"serverBladeName", BladeName},
			{"serverBladePosition", BladePosition},
			{"enclosureSerialNum", BladeSerialNum},
			{"serverBladeSparePartNumber", SparePartNumber},
			{"serverBladeUid", BladeUid},
			{"pXEBootModeStatus", PXEBootModeStatus},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22066]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladePXEBootModeStatus", PXEBootModeStatus},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerBladeExitedPXEBootMode"},
			{"probableCause", "Server blade has exited PXE Boot Mode"},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "Server blade" ++ BladeName ++ "in position" ++ BladePosition ++ "in enclosure"
					++ EnclosureName ++ "in rack" ++ RackName ++ "has exited PXE Boot Mode."},
			{"serverBladeName", BladeName},
			{"serverBladePosition", BladePosition},
			{"enclosureSerialNum", BladeSerialNum},
			{"serverBladeSparePartNumber", SparePartNumber},
			{"serverBladeUid", BladeUid},
			{"pXEBootModeStatus", PXEBootModeStatus},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22067]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladePOSTStatus", BladePOSTStatus},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerBladeWarmReset"},
			{"probableCause", "Server blade warm reset occurred"},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "Server blade" ++ BladeName ++ "in position" ++ BladePosition ++ "in enclosure"
					++ EnclosureName ++ "in rack" ++ RackName ++ "has been warm reset."},
			{"serverBladeName", BladeName},
			{"serverBladePosition", BladePosition},
			{"enclosureSerialNum", BladeSerialNum},
			{"bladeSparePartNumber", SparePartNumber},
			{"serverBladeUid", BladeUid},
			{"bladePOSTStatus", BladePOSTStatus},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22068]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladePOSTStatus", BladePOSTStatus},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerBladePOSTCompleted"},
			{"probableCause", "Server blade system BIOS POST complete"},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "Server blade" ++ BladeName ++ "in position" ++ BladePosition ++ "in enclosure"
					++ EnclosureName ++ "in rack" ++ RackName ++ "system BIOS POST completed."},
			{"serverBladeName", BladeName},
			{"serverBladePosition", BladePosition},
			{"enclosureSerialNum", BladeSerialNum},
			{"serverBladeUid", BladeUid},
			{"bladePOSTStatus", BladePOSTStatus},
			{"bladeSparePartNumber", SparePartNumber},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22069]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladePowered", BladePowered},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerBladePoweredOn"},
			{"probableCause", "Server blade has powered on"},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "Server blade" ++ BladeName ++ "in position" ++ BladePosition ++ "in enclosure"
					++ EnclosureName ++ "in rack" ++ RackName ++ "has been powered on."},
			{"serverBladeName", BladeName},
			{"serverBladePosition", BladePosition},
			{"enclosureSerialNum", BladeSerialNum},
			{"serverBladeUid", BladeUid},
			{"bladeSparePartNumber", SparePartNumber},
			{"bladePowerStatus", BladePowered},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22070]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladePowered", BladePowered},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerBladePoweredOff"},
			{"probableCause", "Server blade has powered off"},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "Server blade" ++ BladeName ++ "in position" ++ BladePosition ++ "in enclosure"
					++ EnclosureName ++ "in rack" ++ RackName ++ "has been powered off."},
			{"serverBladeName", BladeName},
			{"serverBladePosition", BladePosition},
			{"enclosureSerialNum", BladeSerialNum},
			{"serverBladeSparePartNumber", SparePartNumber},
			{"serverBladeUid", BladeUid},
			{"bladePowerStatus", BladePowered},
			{"enclosureManagerSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22071]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum},
		{"cpqRackLastEAEEvent", LastEAEEvent} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackInformationalEAETrap"},
			{"probableCause", "Generic EAE Informational trap"},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", LastEAEEvent},
			{"bladeEnclosureName", EnclosureName},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22072]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum},
		{"cpqRackLastEAEEvent", LastEAEEvent} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackMinorEAETrap"},
			{"probableCause", "Generic EAE Minor trap"},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_MINOR},
			{"specificProblem", LastEAEEvent},
			{"bladeEnclosureName", EnclosureName},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22073]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum},
		{"cpqRackLastEAEEvent", LastEAEEvent} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackMajorEAETrap"},
			{"probableCause", "Generic EAE Major trap"},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", LastEAEEvent},
			{"bladeEnclosureName", EnclosureName},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22074]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum},
		{"cpqRackLastEAEEvent", LastEAEEvent} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackCriticalEAETrap"},
			{"probableCause", "Generic EAE Critical trap"},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_CRITICAL},
			{"specificProblem", LastEAEEvent},
			{"bladeEnclosureName", EnclosureName},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22075]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum},
		{"cpqRackLastEAEEvent", LastEAEEvent} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackPowerMinorEAETrap"},
			{"probableCause", "Generic Power Subsystem EAE Minor trap"},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_MINOR},
			{"specificProblem", LastEAEEvent},
			{"bladeEnclosureName", EnclosureName},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22076]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum},
		{"cpqRackLastEAEEvent", LastEAEEvent} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackPowerMajorEAETrap"},
			{"probableCause", "Generic Power Subsystem EAE Major trap"},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", LastEAEEvent},
			{"bladeEnclosureName", EnclosureName},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[22078]"}, {"sysName", SysName},
		{"cpqRackName", RackName}, {"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", BladeSparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid}, {"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	fault(T, [{"alarmId", TrapSequenceNum},
			{"eventName", notifyNewAlarm},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "rackServerBladePartitionChange"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"probableCause", "Server blade partition changed"},
			{"specificProblem", "Server blade" ++ BladeName ++ "in position" ++ BladePosition ++ "in enclosure"
					++ EnclosureName ++ "in rack" ++ RackName ++ "partition has changed."},
			{"serverBladeName", BladeName},
			{"serverBladePosition", BladePosition},
			{"enclosureSerialNum", BladeSerialNum},
			{"serverBladeSparePartNumber", BladeSparePartNumber},
			{"serverBladeUid", BladeUid},
			{"enclosureManagerSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,9002]"}, {"sysName", SysName},
		{cpqHoTrapFlags, TrapFlags} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(TrapFlags)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "serverPowerOutage"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?SYS_CRITICAL},
			{"probableCause", ?PC_Power_Problem},
			{"specificProblem", "Server power outage detected."} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,9003]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqSm2CntlrBadLoginAttemptsThresh", LoginAttempts} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(TrapFlags)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "serverPowerOutage"},
			{"eventType", ?ET_Operational_Violation},
			{"eventSeverity", ?ES_MAJOR},
			{"probableCause", ?PC_Unauthorized_Access_Attempt},
			{"specificProblem", "More than" ++ LoginAttempts ++
					"unauthorized login attempts detected."} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,9004]"}, {"sysName", SysName},
		{cpqHoTrapFlags, TrapFlags} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(TrapFlags)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "cpqSm2BatteryFailed"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?SYS_CRITICAL},
			{"probableCause", ?PC_Battery_Failure},
			{"specificProblem", "Remote Insight battery failed."} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,9007]"}, {"sysName", SysName},
		{cpqHoTrapFlags, TrapFlags} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(TrapFlags)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "cpqSm2BatteryDisconnected"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"probableCause", ?PC_Battery_Failure},
			{"specificProblem", "Remote Insight Battery Disconnected"} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,9008]"}, {"sysName", SysName},
		{cpqHoTrapFlags, TrapFlags} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(TrapFlags)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "cpqSm2KeyboardCableDisconnected"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"probableCause", ?PC_Cable_Tamper},
			{"specificProblem", "Remote Insight keyboard cable disconnected."} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,9009]"}, {"sysName", SysName},
		{cpqHoTrapFlags, TrapFlags} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(TrapFlags)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "cpqSm2MouseCableDisconnected"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"probableCause", ?PC_Cable_Tamper},
			{"specificProblem", "Remote Insight mouse cable disconnected."} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,9010]"}, {"sysName", SysName},
		{cpqHoTrapFlags, TrapFlags} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(TrapFlags)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "cpqSm2ExternalPowerCableDisconnected"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"probableCause", ?PC_Cable_Tamper},
			{"specificProblem", "Remote Insight external power cable disconnected."} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,9012]"}, {"sysName", SysName},
		{cpqHoTrapFlags, TrapFlags} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(TrapFlags)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "securityOverrideEngaged"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"probableCause", ?PC_Cable_Tamper},
			{"specificProblem", "Remote Insight external power cable disconnected."} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6003]"} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(4)},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "thermalTempFailed"},
			{"eventType", ?ET_Environmental_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_High_Temperature},
			{"specificProblem", "System will be shutdown due to this thermal condition."} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6004]"}, {"cpqHeThermalDegradedAction", DegradeAction} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(4)},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "thermalTempDegraded"},
			{"eventType", ?ET_Environmental_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Temperature_Unacceptable},
			{"thermalDegradedAtion", DegradeAction},
			{"specificProblem", "The temperature status has been set to degraded."} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6005]"} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(2)},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "thermalTempOk"},
			{"eventType", ?ET_Environmental_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Temperature_Unacceptable},
			{"specificProblem", "Temperature has returned to normal range."} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6006]"}, {"cpqHeThermalDegradedAction", DegradeAction} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(4)},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "thermalSystemFanFailed"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Fan_Failure},
			{"thermalDegradedAtion", DegradeAction},
			{"specificProblem", "The system fan status has been set to failed."} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6007]"} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(2)},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "thermalSystemFanDegraded"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Fan_Failure},
			{"specificProblem", "An optional fan is not operating normally."} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6008]"} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(4)},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "thermalSystemFanOk"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Fan_Failure},
			{"specificProblem", "The system fan status has been set to ok."} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6009]"} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(4)},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "thermalCpuFanFailed"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Fan_Failure},
			{"specificProblem", "The CPU fan status has been set to failed."} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6010]"} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(4)},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "thermalCpuFanOk"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Fan_Failure},
			{"specificProblem", "The CPU fan status has been set to ok."} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6018]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", Flag}, {cpqHeThermalDegradedAction, DegradeAction} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(Flag)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "thermalTempDegraded"},
			{"eventType", ?ET_Environmental_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Temperature_Unacceptable},
			{"degradAction", DegradeAction},
			{"proposedRepairActions", "Check the system for hardware failures
					and verify the environment is properly cooled."},
			{"specificProblem", "Temperature out of range, shutdown may occur."} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6019]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", Flag} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(Flag)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "thermalTempOk"},
			{"eventType", ?ET_Environmental_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Temperature_Unacceptable},
			{"specificProblem", "Temperature has returned to normal range."} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6020]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", Flag}, {cpqHeThermalDegradedAction, DegradeAction} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(Flag)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "thermalSystemFanFailed"},
			{"eventType", ?ET_Environmental_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Fan_Failure},
			{"degradAction", DegradeAction},
			{"proposedRepairActions", "Replace the failed fan."},
			{"specificProblem", "Required fan not operating normally, shutdown may occur."} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6021]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", Flag}, {cpqHeThermalDegradedAction, DegradeAction} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(Flag)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "thermalSystemFanDegraded"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Fan_Failure},
			{"degradAction", DegradeAction},
			{"proposedRepairActions", "Replace the failed fan."},
			{"specificProblem", "An optional fan is not operating normally."} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6022]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", Flag} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(Flag)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "thermalSystemFanOk"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Fan_Failure},
			{"specificProblem", "System fan has returned to normal operation."} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6023]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", Flag} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(Flag)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "thermalCpuFanFailed"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Fan_Failure},
			{"proposedRepairActions", "Replace the failed fan."},
			{"specificProblem", "CPU fan has failed, server will be shutdown."} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6024]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", Flag} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(Flag)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "thermalCpuFanOk"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Fan_Failure},
			{"specificProblem", "The CPU fan status has been set to ok."} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6032]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", Flag}, {"cpqHeFltTolPowerSupplyChassis", Chassis} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(Flag)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "powerRedundancyLost"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"probableCause", ?PC_Power_Supply_Failure},
			{"proposedRepairActions", "Check the system power supplies for a failure."},
			{"specificProblem", "The power supplies are no longer redundant on
					chassis" ++ Chassis} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6033]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", Flag}, {"cpqHeFltTolPowerSupplyChassis", Chassis},
		{"cpqHeFltTolPowerSupplyBay", SupplyBay} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(Flag)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "powerSupplyInserted"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"probableCause", ?PC_Power_Supply_Failure},
			{"specificProblem", "The power supply has been inserted on
					chassis" ++ Chassis ++ "bay" ++ SupplyBay} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6034]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", Flag}, {"cpqHeFltTolPowerSupplyChassis", Chassis},
		{"cpqHeFltTolPowerSupplyBay", SupplyBay} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(Flag)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "powerSupplyRemoved"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Power_Supply_Failure},
			{"specificProblem", "The power supply has been removed on
					chassis" ++ Chassis ++ "bay" ++ SupplyBay} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6035]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", Flag}, {"cpqHeFltTolFanChassis", Chassis},
		{"cpqHeFltTolFanIndex", FanIndex} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(Flag)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "fanDegraded"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Fan_Failure},
			{"proposedRepairActions", "Replace the failing fan."},
			{"specificProblem", "The fan degraded on chassis" ++ Chassis
					 ++ "fan" ++ FanIndex} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6036]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", Flag}, {"cpqHeFltTolFanChassis", Chassis},
		{"cpqHeFltTolFanIndex", FanIndex} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(Flag)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "fanFailed"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Fan_Failure},
			{"proposedRepairActions", "Replace the failing fan."},
			{"specificProblem", "The fan failed on chassis" ++ Chassis
					 ++ "fan" ++ FanIndex} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6037]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", Flag}, {"cpqHeFltTolFanChassis", Chassis} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(Flag)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "fanRedundancyLost"},
			{"eventTypa", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"probableCause", ?PC_Loss_Of_Redundancy},
			{"proposedRepairActions", "Check the system fans for a failure."},
			{"specificProblem", "The fans are no longer redundant on chassis" ++ Chassis} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6038]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", Flag}, {"cpqHeFltTolFanChassis", Chassis},
		{"cpqHeFltTolFanIndex", FanIndex} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(Flag)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "fanInserted"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"probableCause", ?PC_Fan_Failure},
			{"specificProblem", "The fan has been inserted on chassis"
					++ Chassis ++ "fan" ++ FanIndex} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6039]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", Flag}, {"cpqHeFltTolFanChassis", Chassis},
		{"cpqHeFltTolFanIndex", FanIndex} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(Flag)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "fanRemoved"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Fan_Failure},
			{"specificProblem", "The fan has been removed on chassis"
					++ Chassis ++ "fan" ++ FanIndex} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6040]"}, {"sysName", SysName}, {"cpqHoTrapFlags", Flag},
		{"cpqHeTemperatureChassis", Chassis}, {"cpqHeTemperatureLocale", Locale} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(Flag)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "thermalFailure"},
			{"eventType", ?ET_Environmental_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_High_Temperature},
			{"proposedRepairActions", "Check the system for hardware failures
					and verify the environment is properly cooled."},
			{"specificProblem", "Temperature exceeded on chassis" ++ Chassis
					++ "location" ++ Locale} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6041]"}, {"sysName", SysName}, {"cpqHoTrapFlags", Flag},
		{"cpqHeThermalDegradedAction", DegradeAction}, {"cpqHeTemperatureChassis", Chassis},
		{"cpqHeTemperatureLocale", Locale} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(Flag)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "thermalStatusDegraded"},
			{"eventType", ?ET_Environmental_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Low_Temperature},
			{"degradeAction", DegradeAction},
			{"proposedRepairActions", "Check the system for hardware failures and
					verify the environment is properly cooled."},
			{"specificProblem", "Temperature out of range on chassis" ++
					Chassis ++ "location" ++ Locale ++ ". Shutdown may occur."} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6042]"}, {"sysName", SysName}, {"cpqHoTrapFlags", Flag},
		{"cpqHeTemperatureChassis", Chassis}, {"cpqHeTemperatureLocale", Locale} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(Flag)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "thermalStatusOK"},
			{"eventType", ?ET_Environmental_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Temperature_Unacceptable},
			{"specificProblem", "Temperature are normal on chassis" ++
					Chassis ++ "location" ++ Locale} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6048]"}, {"sysName", SysName}, {"cpqHoTrapFlags", Flag},
		{"cpqHeFltTolPowerSupplyChassis", Chassis}, {"cpqHeFltTolPowerSupplyBay", SupplyBay},
		{"cpqHeFltTolPowerSupplyStatus", Status}, {"cpqHeFltTolPowerSupplyModel", Model},
		{"cpqHeFltTolPowerSupplySerialNumber", SerialNumber}, {"cpqHeFltTolPowerSupplyAutoRev", Rev},
		{"cpqHeFltTolPowerSupplyFirmwareRev", FirmwareRev},
		{"cpqHeFltTolPowerSupplySparePartNum", SparePartNum},
		{"cpqSiServerSystemId", SystemId}, {"snmpTrapEnterprise", "compaq"} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(Flag)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "powerSupplyOK "},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Power_Supply_Failure},
			{"sparePartNumber", SparePartNum},
			{"powerSupplyAutoRev", Rev},
			{"chassis", Chassis},
			{"systemId", SystemId},
			{"specificProblem", "The power supply is ok on bay" ++ SupplyBay ++
					"status" ++ Status ++ "model" ++ Model ++ "serial number" ++ SerialNumber ++
					"firmware" ++ FirmwareRev} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6049]"}, {"sysName", SysName}, {"cpqHoTrapFlags", Flag},
		{"cpqHeFltTolPowerSupplyChassis", Chassis}, {"cpqHeFltTolPowerSupplyBay", SupplyBay},
		{"cpqHeFltTolPowerSupplyStatus", Status}, {"cpqHeFltTolPowerSupplyModel", Model},
		{"cpqHeFltTolPowerSupplySerialNumber", SerialNumber}, {"cpqHeFltTolPowerSupplyAutoRev", Rev},
		{"cpqHeFltTolPowerSupplyFirmwareRev", FirmwareRev},
		{"cpqHeFltTolPowerSupplySparePartNum", SparePartNum},
		{"cpqSiServerSystemId", SystemId} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(Flag)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "powerSupplyDegraded"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Power_Supply_Failure},
			{"proposedRepairActions", "Replace the failing power supply."},
			{"sparePartNumber", SparePartNum},
			{"chassis", Chassis},
			{"powerSupplyAutoRev", Rev},
			{"systemId", SystemId},
			{"specificProblem", "The power supply is degraded on bay" ++ SupplyBay ++
					"status" ++ Status ++ "model" ++ Model ++ "serial number" ++ SerialNumber ++
					"firmware" ++ FirmwareRev} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6050]"}, {"sysName", SysName}, {"cpqHoTrapFlags", Flag},
		{"cpqHeFltTolPowerSupplyChassis", Chassis}, {"cpqHeFltTolPowerSupplyBay", SupplyBay},
		{"cpqHeFltTolPowerSupplyStatus", Status}, {"cpqHeFltTolPowerSupplyModel", Model},
		{"cpqHeFltTolPowerSupplySerialNumber", SerialNumber}, {"cpqHeFltTolPowerSupplyAutoRev", Rev},
		{"cpqHeFltTolPowerSupplyFirmwareRev", FirmwareRev},
		{"cpqHeFltTolPowerSupplySparePartNum", SparePartNum},
		{"cpqSiServerSystemId", SystemId} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(Flag)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "powerSupplyFailed"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Power_Supply_Failure},
			{"proposedRepairActions", "Replace the failing power supply."},
			{"sparePartNumber", SparePartNum},
			{"chassis", Chassis},
			{"powerSupplyAutoRev", Rev},
			{"systemId", SystemId},
			{"specificProblem", "The power supply failed on bay" ++ SupplyBay ++
					"status" ++ Status ++ "model" ++ Model ++ "serial number" ++ SerialNumber ++
					"firmware" ++ FirmwareRev} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6054]"}, {"sysName", SysName}, {"cpqHoTrapFlags", Flag},
		{"cpqHeFltTolPowerSupplyChassis", Chassis} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(Flag)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "powerRedundancyRestored"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Power_Problem},
			{"specificProblem", "The power supplies are now redundant on chassis" ++ Chassis} | Acc]);
fault([{"snmpTrapOID", "compaq.[0,6055]"}, {"sysName", SysName}, {"cpqHoTrapFlags", Flag},
		{"cpqHeFltTolFanChassis", Chassis} | T], Acc) ->
	fault(T, [{"alarmId", snmp_collector_utils:generate_identity(7)},
			{"eventName", flags(Flag)},
			{"sysName", SysName},
			{"raisedTime", snmp_collector_log:iso8601(erlang:system_time(milli_seconds))},
			{"alarmCondition", "fanRedundancyRestored "},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_CRITICAL},
			{"probableCause", ?PC_Fan_Failure},
			{"specificProblem", "The fans are now redundant on chassis" ++ Chassis} | Acc]);
fault([{Name, Value} | T], Acc)
		when length(Value) > 0 ->
	fault(T, [{Name, Value} | Acc]);
fault([], Acc) ->
	Acc.

-spec handle_notification(TargetName, Varbinds) -> Result
	when
		TargetName :: string(),
		Varbinds :: snmp:varbinds(),
		Result :: ignore | {error, Reason},
		Reason :: term().
%% @doc Handle a syslog event.
handle_notification(TargetName, Varbinds) ->
	try
		{ok, Pairs} = snmp_collector_utils:arrange_list(Varbinds),
		{ok, NamesValues} = snmp_collector_utils:oids_to_names(Pairs, []),
		AlarmDetails = notification(NamesValues),
		Event = snmp_collector_utils:create_event(TargetName, AlarmDetails, syslog),
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
%% @doc CODEC for fault.
notification(NameValuePair) ->
	notification(NameValuePair, []).
%% @hidden
notification([{"snmpTrapOID", "compaq.[0,11020]"}, {"sysName", SysName} | T], Acc) ->
	notification(T, [{"id", snmp_collector_utils:generate_identity(7)},
			{priority, normal},
			{version, "1"},
			{sourceName, SysName},
			{eventType, "hoMibHealthStatusArrayChangeTrap"},
			{"description", "A change in the health status of the server has occurred,
					the status is now SystemStatus"} | Acc]);
notification([{"snmpTrapOID", "compaq.[22001]"}, {"sysName", SysName} | T], Acc) ->
	notification(T, [{"id", snmp_collector_utils:generate_identity(7)},
			{priority, normal},
			{version, "1"},
			{sourceName, SysName},
			{eventType, "cpqRackNameChanged"},
			{"description", "Rack name has changed."} | Acc]);
notification([{"snmpTrapOID", "compaq.[22002]"}, {"sysName", SysName} | T], Acc) ->
	notification(T, [{"id", snmp_collector_utils:generate_identity(7)},
			{priority, normal},
			{version, "1"},
			{sourceName, SysName},
			{eventType, "cpqRackEnclosureNameChanged"},
			{"description", "Enclosure name has changed."} | Acc]);
notification([{"snmpTrapOID", "compaq.[22003]"}, {"sysName", SysName} | T], Acc) ->
	notification(T, [{"id", snmp_collector_utils:generate_identity(7)},
			{priority, normal},
			{version, "1"},
			{sourceName, SysName},
			{eventType, "cpqRackEnclosureRemoved"},
			{"description", "The enclosure has been removed."} | Acc]);
notification([{"snmpTrapOID", "compaq.[22004]"}, {"sysName", SysName} | T], Acc) ->
	notification(T, [{"id", snmp_collector_utils:generate_identity(7)},
			{priority, normal},
			{version, "1"},
			{sourceName, SysName},
			{eventType, "cpqRackEnclosureInserted"},
			{"description", "The enclosure has been inserted."} | Acc]);
notification([{Name, Value} | T], Acc)
		when length(Value) > 0 ->
	notification(T, [{Name, Value} | Acc]);
notification([], Acc) ->
	Acc.

-spec domain(Varbinds) -> Result
	when
		Varbinds :: [Varbinds],
		Result :: fault | notification | other.
%% @doc Check the domain of the event.
domain([_TimeTicks, {varbind, [1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0] , _, TrapName, _} | _T]) ->
	domain1(snmp_collector_utils:oid_to_name(TrapName)).
%% @hidden
domain1("compaq.[22001]") ->
	fault;
domain1("compaq.[22002]") ->
	fault;
domain1("compaq.[22003]") ->
	fault;
domain1("compaq.[22004]") ->
	fault;
domain1("compaq.[22005]") ->
	fault;
domain1("compaq.[22006]") ->
	fault;
domain1("compaq.[22007]") ->
	fault;
domain1("compaq.[22008]") ->
	fault;
domain1("compaq.[22009]") ->
	fault;
domain1("compaq.[22010]") ->
	fault;
domain1("compaq.[22011]") ->
	fault;
domain1("compaq.[22012]") ->
	fault;
domain1("compaq.[22013]") ->
	fault;
domain1("compaq.[22014]") ->
	fault;
domain1("compaq.[22015]") ->
	fault;
domain1("compaq.[22016]") ->
	fault;
domain1("compaq.[22017]") ->
	fault;
domain1("compaq.[22018]") ->
	fault;
domain1("compaq.[22019]") ->
	fault;
domain1("compaq.[22020]") ->
	fault;
domain1("compaq.[22021]") ->
	fault;
domain1("compaq.[22022]") ->
	fault;
domain1("compaq.[22023]") ->
	fault;
domain1("compaq.[22024]") ->
	fault;
domain1("compaq.[22025]") ->
	fault;
domain1("compaq.[22026]") ->
	fault;
domain1("compaq.[22027]") ->
	fault;
domain1("compaq.[22028]") ->
	fault;
domain1("compaq.[22029]") ->
	fault;
domain1("compaq.[22030]") ->
	fault;
domain1("compaq.[22031]") ->
	fault;
domain1("compaq.[22032]") ->
	fault;
domain1("compaq.[22033]") ->
	fault;
domain1("compaq.[22034]") ->
	fault;
domain1("compaq.[22035]") ->
	fault;
domain1("compaq.[22036]") ->
	fault;
domain1("compaq.[22037]") ->
	fault;
domain1("compaq.[22038]") ->
	fault;
domain1("compaq.[22039]") ->
	fault;
domain1("compaq.[22040]") ->
	fault;
domain1("compaq.[22041]") ->
	fault;
domain1("compaq.[22042]") ->
	fault;
domain1("compaq.[22043]") ->
	fault;
domain1("compaq.[22044]") ->
	fault;
domain1("compaq.[22045]") ->
	fault;
domain1("compaq.[22046]") ->
	fault;
domain1("compaq.[22047]") ->
	fault;
domain1("compaq.[22048]") ->
	fault;
domain1("compaq.[22049]") ->
	fault;
domain1("compaq.[22050]") ->
	fault;
domain1("compaq.[22051]") ->
	fault;
domain1("compaq.[22052]") ->
	fault;
domain1("compaq.[22053]") ->
	fault;
domain1("compaq.[22054]") ->
	fault;
domain1("compaq.[22055]") ->
	fault;
domain1("compaq.[22056]") ->
	fault;
domain1("compaq.[22057]") ->
	fault;
domain1("compaq.[22058]") ->
	fault;
domain1("compaq.[22059]") ->
	fault;
domain1("compaq.[22060]") ->
	fault;
domain1("compaq.[22061]") ->
	fault;
domain1("compaq.[22062]") ->
	fault;
domain1("compaq.[22063]") ->
	fault;
domain1("compaq.[22064]") ->
	fault;
domain1("compaq.[22065]") ->
	fault;
domain1("compaq.[22066]") ->
	fault;
domain1("compaq.[22067]") ->
	fault;
domain1("compaq.[22068]") ->
	fault;
domain1("compaq.[22069]") ->
	fault;
domain1("compaq.[22070]") ->
	fault;
domain1("compaq.[22071]") ->
	fault;
domain1("compaq.[22072]") ->
	fault;
domain1("compaq.[22073]") ->
	fault;
domain1("compaq.[22074]") ->
	fault;
domain1("compaq.[22075]") ->
	fault;
domain1("compaq.[22076]") ->
	fault;
domain1("compaq.[22077]") ->
	fault;
domain1("compaq.[22078]") ->
	fault;
domain1("compaq.[0,9002]") ->
	fault;
domain1("compaq.[0,9003]") ->
	fault;
domain1("compaq.[0,9004]") ->
	fault;
domain1("compaq.[0,9007]") ->
	fault;
domain1("compaq.[0,9008]") ->
	fault;
domain1("compaq.[0,9009]") ->
	fault;
domain1("compaq.[0,9010]") ->
	fault;
domain1("compaq.[0,6003]") ->
	fault;
domain1("compaq.[0,6004]") ->
	fault;
domain1("compaq.[0,6005]") ->
	fault;
domain1("compaq.[0,6006]") ->
	fault;
domain1("compaq.[0,6007]") ->
	fault;
domain1("compaq.[0,6008]") ->
	fault;
domain1("compaq.[0,6009]") ->
	fault;
domain1("compaq.[0,6010]") ->
	fault;
domain1("compaq.[0,6018]") ->
	fault;
domain1("compaq.[0,6019]") ->
	fault;
domain1("compaq.[0,6020]") ->
	fault;
domain1("compaq.[0,6021]") ->
	fault;
domain1("compaq.[0,6022]") ->
	fault;
domain1("compaq.[0,6023]") ->
	fault;
domain1("compaq.[0,6024]") ->
	fault;
domain1("compaq.[0,6032]") ->
	fault;
domain1("compaq.[0,6033]") ->
	fault;
domain1("compaq.[0,6034]") ->
	fault;
domain1("compaq.[0,6035]") ->
	fault;
domain1("compaq.[0,6036]") ->
	fault;
domain1("compaq.[0,6037]") ->
	fault;
domain1("compaq.[0,6038]") ->
	fault;
domain1("compaq.[0,6039]") ->
	fault;
domain1("compaq.[0,6040]") ->
	fault;
domain1("compaq.[0,6041]") ->
	fault;
domain1("compaq.[0,6042]") ->
	fault;
domain1("compaq.[0,6048]") ->
	fault;
domain1("compaq.[0,6049]") ->
	fault;
domain1("compaq.[0,6050]") ->
	fault;
domain1("compaq.[0,6054]") ->
	fault;
domain1("compaq.[0,6055]") ->
	fault;
domain1("compaq.[0,11020]") ->
	notification;
domain1(_) ->
	other.

flags(Flag) ->
	Flag.

