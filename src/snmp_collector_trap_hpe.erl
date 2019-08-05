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
		handle_report/3]).

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
handle_trap(TargetName, {_ErrorStatus, _ErrorIndex, Varbinds}, _UserData) ->
	try
		{ok, Pairs} = snmp_collector_utils:arrange_list(Varbinds),
		{ok, NamesValues} = snmp_collector_utils:oids_to_names(Pairs, []),
		AlarmDetails = event(NamesValues),
		Event  = snmp_collector_utils:generate_maps(TargetName, AlarmDetails),
		snmp_collector_utils:log_events(Event)
	of
		ok ->
			ignore;
		{error, Reason} ->
			{error, Reason}
	catch
		_:Reason ->
			{error, Reason}
	end;
handle_trap(TargetName, {_Enteprise, _Generic, _Spec, _Timestamp, Varbinds}, _UserData) ->
	try
		{ok, Pairs} = snmp_collector_utils:arrange_list(Varbinds),
		{ok, NamesValues} = snmp_collector_utils:oids_to_names(Pairs, []),
		AlarmDetails = event(NamesValues),
		Event  = snmp_collector_utils:generate_maps(TargetName, AlarmDetails),
		snmp_collector_utils:log_events(Event)
	of
		ok ->
			ignore;
		{error, Reason} ->
			{error, Reason}
	catch
		_:Reason ->
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

-spec event(OidNameValuePair) -> VesNameValuePair
	when
		OidNameValuePair :: [{OidName, OidValue}],
		OidName :: string(),
		OidValue :: string(),
		VesNameValuePair :: [{VesName, VesValue}],
		VesName :: string(),
		VesValue :: string().
%% @doc CODEC for event.
event(OidNameValuePair) ->
	event(OidNameValuePair, []).
%% @hidden

event([{"snmpTrapOID", "compaqq.[22001]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackSerialNum", RackSerialNum},
		{"cpqRackTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId",  RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "rackNameChanged"},
			{"probableCause", "Rack name changed"},
			{"eventType", ?ET_Communication_System} ,
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "The rack name has changed to " ++ RackName},
			{"rackSerialNum", RackSerialNum}| Acc]);
event([{"snmpTrapOID", "compaqq.[22002]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureModel", EnclosureModel},
		{"cpqRackCommonEnclosureSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "rackEnclosureNameChanged"},
			{"probableCause", "Enclosure name changed"},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "The enclosure name has changed to" ++ EnclosureName
				++ "in rack" ++ RackName},
			{"enclosureName", EnclosureName},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureModel", EnclosureModel},
			{"enclosureSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", RackTrapSequenceNum} | Acc]);
event([{"snmpTrapOID", "compaqq.[22003]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureModel", EnclosureModel},
		{"cpqRackCommonEnclosureSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "rackEnclosureRemoved"},
			{"probableCause", "Enclosure removed"},
			{"eventType", ?ET_Physical_Violation},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "The enclosure name has" ++ EnclosureName ++
				"been removed from rack" ++ RackName},
			{"enclosureName", EnclosureName},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureModel", EnclosureModel},
			{"enclosureSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", RackTrapSequenceNum} | Acc]);
event([{"snmpTrapOID", "compaqq.[22004]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureModel", EnclosureModel},
		{"cpqRackCommonEnclosureSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "rackEnclosureInserted"},
			{"probableCause", "Enclosure inserted"},
			{"eventType", ?ET_Physical_Violation},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "The enclosure name has" ++ EnclosureName ++
					"been inserted into rack" ++ RackName},
			{"enclosureName", EnclosureName},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureModel", EnclosureModel},
			{"enclosureSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", RackTrapSequenceNum} | Acc]);
event([{"snmpTrapOID", "compaqq.[22005]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTempLocation", TempLocation},
		{"cpqRackCommonEnclosureSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "rackEnclosureTempFailed"},
			{"probableCause", "Enclosure temperature failed"},
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
event([{"snmpTrapOID", "compaqq.[22006]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTempLocation", TempLocation},
		{"cpqRackCommonEnclosureSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22007]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTempLocation", TempLocation},
		{"cpqRackCommonEnclosureSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22008]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureFanLocation", FanLocation},
		{"cpqRackCommonEnclosureSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22009]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureFanLocation", FanLocation},
		{"cpqRackCommonEnclosureFanSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22010]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureFanLocation", FanLocation},
		{"cpqRackCommonEnclosureFanSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22011]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureFanLocation", FanLocation},
		{"cpqRackCommonEnclosureFanSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22012]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureFanLocation", FanLocation},
		{"cpqRackCommonEnclosureFanSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22013]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackPowerSupplyEnclosureName", EnclosureName},
		{"cpqRackPowerSupplySerialNum", SerialNum},
		{"cpqRackPowerSupplyFWRev", PowerSupplyFWRev},
		{"cpqRackPowerSupplyPosition", PowerSupplyLocation},
		{"cpqRackPowerSupplySparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", SerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22014]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackPowerSupplyEnclosureName", EnclosureName},
		{"cpqRackPowerSupplySerialNum", SerialNum},
		{"cpqRackPowerSupplyFWRev", PowerSupplyFWRev},
		{"cpqRackPowerSupplyPosition", PowerSupplyLocation},
		{"cpqRackPowerSupplySparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", SerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22015]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackPowerSupplyEnclosureName", EnclosureName},
		{"cpqRackPowerSupplySerialNum", SerialNum},
		{"cpqRackPowerSupplyFWRev", PowerSupplyFWRev},
		{"cpqRackPowerSupplyPosition", PowerSupplyLocation},
		{"cpqRackPowerSupplySparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", SerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22016]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackPowerSupplyEnclosureName", EnclosureName},
		{"cpqRackPowerSupplySerialNum", SerialNum},
		{"cpqRackPowerSupplyFWRev", PowerSupplyFWRev},
		{"cpqRackPowerSupplyPosition", PowerSupplyLocation},
		{"cpqRackPowerSupplySparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", SerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22017]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackPowerSupplyEnclosureName", EnclosureName},
		{"cpqRackPowerSupplySerialNum", SerialNum},
		{"cpqRackPowerSupplyFWRev", PowerSupplyFWRev},
		{"cpqRackPowerSupplyPosition", PowerSupplyLocation},
		{"cpqRackPowerSupplySparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", SerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22018]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackPowerSupplyEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", SerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22019]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackPowerSupplyEnclosureName", EnclosureName},
		{"cpqRackPowerSupplyPosition", PowerSupplyPosition}, {"cpqRackPowerSupplyFWRev", PowerSupplyFWRev},
		{"cpqRackPowerSupplyInputLineStatus", InputLineStatus},
		{"cpqRackPowerSupplySparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", SerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", RackTrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", RackTrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22020]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackPowerEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSparePartNumber", SparePartNumber}, {"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22021]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladePosition", BladePosition}, {"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22022]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", BladeEnclosureName},
		{"cpqRackServerBladePosition", BladePosition}, {"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22023]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", BladeEnclosureName},
		{"cpqRackServerBladePosition", BladePosition}, {"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22024]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", BladeEnclosureName},
		{"cpqRackServerBladePosition", BladePosition}, {"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22025]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", BladeEnclosureName},
		{"cpqRackServerBladePosition", BladePosition}, {"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22026]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", BladeEnclosureName},
		{"cpqRackServerBladePosition", BladePosition}, {"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "rackServerPowerOnManualOverride"},
			{"probableCause", "Server power On via manual override"},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "Server power on via manual override on blade" ++ BladePosition ++ " in enclosure,"
					++ BladeEnclosureName ++ "in rack" ++ RackName},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureManagerSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
event([{"snmpTrapOID", "compaqq.[22027]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureFuseLocation", FuseLocation}, {"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22028]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "rackServerBladeRemoved"},
			{"probableCause", "Server Blade Removed"},
			{"eventType", ?ET_Physical_Violation},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "Server blade" ++ BladeName ++ " removed from position" ++ BladePosition ++
					",in enclosure" ++ EnclosureName ++ "in rack" ++ RackName},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureManagerSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
event([{"snmpTrapOID", "compaqq.[22029]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "rackServerBladeInserted"},
			{"probableCause", "Server blade inserted."},
			{"eventType", ?ET_Physical_Violation},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", "Server blade" ++ BladeName ++ " inserted into position" ++ BladePosition ++
					",in enclosure" ++ EnclosureName ++ "in rack" ++ RackName},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureManagerSparePartNumber", SparePartNumber},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
event([{"snmpTrapOID", "compaqq.[22030]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22031]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22032]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22033]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "rackPowerUnknownPowerConsumption"},
			{"probableCause", "Unknown power consumption."},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "Unknown power consumption in rack" ++ RackName},
			{"proposedRepairActions", "Check the power enclosure and power supplies.
					Replace any failed or degraded power supplies"},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
event([{"snmpTrapOID", "compaqq.[22034]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22035]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "rackPowerChassisTooManyPowerChassis"},
			{"probableCause", "Power subsystem has too may power enclosures."},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "Power subsystem has too may power enclosures in" ++ EnclosureName
					++ "in rack" ++ RackName},
			{"proposedRepairActions", "Remove the extra power enclosure"},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
event([{"snmpTrapOID", "compaqq.[22036]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "rackPowerChassisConfigError"},
			{"probableCause", "Power subsystem improperly configured."},
			{"eventType", ?ET_Equipment_Alarm},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", "Power subsystem has been improperly configured in enclosure"
					++ EnclosureName ++ "in rack" ++ RackName},
			{"proposedRepairActions", "Check the cabling of the power enclosure."},
			{"enclosureSerialNum", EnclosureSerialNum},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
event([{"snmpTrapOID", "compaqq.[22037]"},  {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureManagerLocation", ManagerLocation},
		{"cpqRackCommonEnclosureManagerSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureManagerSerialNum", ManagerSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22038]"},  {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureManagerLocation", ManagerLocation},
		{"cpqRackCommonEnclosureManagerSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureManagerSerialNum", ManagerSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22039"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureManagerLocation", ManagerLocation},
		{"cpqRackCommonEnclosureManagerSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureManagerSerialNum", ManagerSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22040]"},  {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureManagerLocation", ManagerLocation},
		{"cpqRackCommonEnclosureManagerSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureManagerSerialNum", ManagerSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22041]"},  {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackCommonEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureManagerLocation", ManagerLocation},
		{"cpqRackCommonEnclosureManagerSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureManagerSerialNum", ManagerSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22042]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22043]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22044]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackNetConnectorEnclosureName", EnclosureName},
		{"cpqRackNetConnectorName", ConnectorName}, {"cpqRackNetConnectorLocation", ConnectorLocation},
		{"cpqRackNetConnectorSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22045]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackNetConnectorEnclosureName", EnclosureName},
		{"cpqRackNetConnectorName", ConnectorName}, {"cpqRackNetConnectorLocation", ConnectorLocation},
		{"cpqRackNetConnectorSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22046]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackNetConnectorEnclosureName", EnclosureName},
		{"cpqRackNetConnectorName", ConnectorName}, {"cpqRackNetConnectorLocation", ConnectorLocation},
		{"cpqRackNetConnectorSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22047]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackNetConnectorEnclosureName", EnclosureName},
		{"cpqRackNetConnectorName", ConnectorName}, {"cpqRackNetConnectorLocation", ConnectorLocation},
		{"cpqRackNetConnectorSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22048]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackNetConnectorEnclosureName", EnclosureName},
		{"cpqRackNetConnectorName", ConnectorName}, {"cpqRackNetConnectorLocation", ConnectorLocation},
		{"cpqRackNetConnectorSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22049]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22050]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeUid", ServerBladeUid},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22051]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22052]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladeProductId", BladeProductId},
		{"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22053]"}, {"sysName", SysName},
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
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22054]"}, {"sysName", SysName},
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
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22055]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22056]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22057]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladeManagementDeviceFirmwareFlashingStatus", FirmwareFlashingStatus},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22058]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladeManagementDeviceFirmwareFlashingStatus", FirmwareFlashingStatus},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22059]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladeSystemBIOSFlashingStatus", FirmwareFlashingStatus},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22060]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladeSystemBIOSFlashingStatus", FirmwareFlashingStatus},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22061]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladeFrontIOBlankingModeStatus", BladeFrontIOBlankingModeStatus},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22062]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladeFrontIOBlankingModeStatus", BladeFrontIOBlankingModeStatus},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22063]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladeDiagnosticAdaptorPresence", DiagnosticAdaptorPresence},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22064]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladeDiagnosticAdaptorPresence", DiagnosticAdaptorPresence},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22065]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladePXEBootModeStatus", PXEBootModeStatus},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22066]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladePXEBootModeStatus", PXEBootModeStatus},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22067]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladePOSTStatus", BladePOSTStatus},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22068]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladePOSTStatus", BladePOSTStatus},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22069]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladePowered", BladePowered},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22070]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", SparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid},
		{"cpqRackServerBladePowered", BladePowered},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([{"snmpTrapOID", "compaqq.[22071]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum},
		{"cpqRackLastEAEEvent", LastEAEEvent} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "rackInformationalEAETrap"},
			{"probableCause", "Generic EAE Informational trap"},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_INDETERMINATE},
			{"specificProblem", LastEAEEvent},
			{"bladeEnclosureName", EnclosureName},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
event([{"snmpTrapOID", "compaqq.[22072]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum},
		{"cpqRackLastEAEEvent", LastEAEEvent} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "rackMinorEAETrap"},
			{"probableCause", "Generic EAE Minor trap"},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_MINOR},
			{"specificProblem", LastEAEEvent},
			{"bladeEnclosureName", EnclosureName},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
event([{"snmpTrapOID", "compaqq.[22073]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum},
		{"cpqRackLastEAEEvent", LastEAEEvent} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "rackMajorEAETrap"},
			{"probableCause", "Generic EAE Major trap"},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", LastEAEEvent},
			{"bladeEnclosureName", EnclosureName},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
event([{"snmpTrapOID", "compaqq.[22074]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum},
		{"cpqRackLastEAEEvent", LastEAEEvent} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "rackCriticalEAETrap"},
			{"probableCause", "Generic EAE Critical trap"},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_CRITICAL},
			{"specificProblem", LastEAEEvent},
			{"bladeEnclosureName", EnclosureName},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
event([{"snmpTrapOID", "compaqq.[22075]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum},
		{"cpqRackLastEAEEvent", LastEAEEvent} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "rackPowerMinorEAETrap"},
			{"probableCause", "Generic Power Subsystem EAE Minor trap"},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_MINOR},
			{"specificProblem", LastEAEEvent},
			{"bladeEnclosureName", EnclosureName},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
event([{"snmpTrapOID", "compaqq.[22076]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum},
		{"cpqRackLastEAEEvent", LastEAEEvent} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "rackPowerMajorEAETrap"},
			{"probableCause", "Generic Power Subsystem EAE Major trap"},
			{"eventType", ?ET_Communication_System},
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", LastEAEEvent},
			{"bladeEnclosureName", EnclosureName},
			{"enclosureTrapSequenceNum", TrapSequenceNum} | Acc]);
event([{"snmpTrapOID", "compaqq.[22078]"}, {"sysName", SysName},
		{"cpqHoTrapFlags", TrapFlags}, {"cpqRackName", RackName},
		{"cpqRackUid", RackUid}, {"cpqRackServerBladeEnclosureName", EnclosureName},
		{"cpqRackServerBladeName", BladeName}, {"cpqRackServerBladePosition", BladePosition},
		{"cpqRackServerBladeSparePartNumber", BladeSparePartNumber},
		{"cpqRackCommonEnclosureSerialNum", EnclosureSerialNum},
		{"cpqRackServerBladeSerialNum", BladeSerialNum},
		{"cpqRackServerBladeUid", BladeUid}, {"cpqRackCommonEnclosureTrapSequenceNum", TrapSequenceNum} | T], Acc) ->
	event(T, [{"alarmId", TrapSequenceNum},
			{"eventName", flags(TrapFlags)},
			{"sourceId", RackUid},
			{"sourceName", RackName},
			{"sysName", SysName},
			{"raisedTime", erlang:system_time(milli_seconds)},
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
event([_H | T], Acc) ->
	event(T, Acc);
event([], Acc) ->
	Acc.

-spec flags(Flag) -> Result
	when
		Flag :: integer(),
		Result :: ?EN_CLEARED | ?EN_NEW | ?EN_NEW.
%% @doc Get a event name using a flag value.
%% @private
flags(2) ->
	?EN_CLEARED;
flags(3) ->
	?EN_NEW;
flags(4) ->
	?EN_NEW.

