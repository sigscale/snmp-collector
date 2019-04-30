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
-module(snmp_collector_hp_chassis_trap).
-copyright('Copyright (c) 2016 - 2019 SigScale Global Inc.').

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
%	case heartbeat(Varbinds) of
%		true ->
%			ignore;
%		false ->
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
%	end;
handle_trap(TargetName, {_Enteprise, _Generic, _Spec, _Timestamp, Varbinds}, _UserData) ->
%	case heartbeat(Varbinds) of
%		true ->
%			ignore;
%		false ->
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
%	end.

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
event([{"", Value} | T], Acc)
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
	event(T, [{"eventSourceType", Value} | Acc]);
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
	event(T, [{"alarmCondtion", "CLEARED"}, {"eventName", notifyClearedAlarm} | Acc]);
event([{"cpqHoTrapFlags", 3} | T], Acc) ->
	event(T, [{"alarmCondtion", "NEW"}, {"eventName", notifyNewAlarm} | Acc]);
event([{"cpqHoTrapFlags", 4} | T], Acc) ->
	event(T, [{"alarmCondtion", "NEW"}, {"eventName", notifyNewAlarm} | Acc]);
event([{"snmpTrapOID", "compaqq.[22001]"} | T], Acc) ->
	event(T, [{"eventName", "cpqRackNameChanged"}, {"probableCause", "Rack name changed"},
		{"eventType", "Operational Violation"} , {eventSeverity, "INFORMATIONAL"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22002]"} | T], Acc) ->
	event(T, [{"eventName", "cpqRackEnclosureNameChanged"}, {"probableCause", "Enclosure name changed"},
		{"eventType", "Operational Violation"}, {eventSeverity, "INFORMATIONAL"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22003]"} | T], Acc) ->
	event(T, [{"eventName", "cpqRackEnclosureRemoved"}, {"probableCause", "Enclosure removed"},
		{"eventType", "Operational Violation"}, {eventSeverity, "INFORMATIONAL"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22004]"} | T], Acc) ->
	event(T, [{"eventName", "cpqRackEnclosureInserted"}, {"probableCause", "Enclosure inserted"},
		{"eventType", "Operational Violation"}, {eventSeverity, "INFORMATIONAL"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22005]"} | T], Acc) ->
	event(T, [{"eventName", "cpqRackEnclosureTempFailed"}, {"probableCause", "Enclosure temperature failed"},
		{"eventType", "Hardware System"}, {eventSeverity, "CRITICAL"},
		{proposedRepairactions, "Shutdown the enclosure and possibly the rack as soon as possible.
				Ensure all fans are working properly and that air flow in the rack has not been blocked."} | Acc]);
event([{"snmpTrapOID", "compaqq.[22006]"} | T], Acc) ->
	event(T, [{"eventName", "cpqRackEnclosureTempDegraded"}, {"probableCause", "Enclosure temperature degraded"},
		{"eventType", "Hardware Violation"}, {eventSeverity, "MAJOR"},
		{proposedRepairactions, "Shutdown the enclosure and possibly the rack as soon as possible.
				Ensure all fans are working properly and that air flow in the rack has not been blocked."} | Acc]);
event([{"snmpTrapOID", "compaqq.[22007]"} | T], Acc) ->
	event(T, [{"eventName", "cpqRackEnclosureTempOk"}, {"probableCause", "Enclosure temperature ok"},
		{"eventType", "Operational Violation"} , {eventSeverity, "INFORMATIONAL"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22008]"} | T], Acc) ->
	event(T, [{"eventName", "cpqRackEnclosureFanFailed"}, {"probableCause", "Enclosure fan failed"},
		{"eventType", "Hardware System"} , {eventSeverity, "CRITICAL"},
		{proposedRepairactions, "Replace the failed enclosure fan."} | Acc]);
event([{"snmpTrapOID", "compaqq.[22009]"} | T], Acc) ->
	event(T, [{"eventName", "cpqRackEnclosureFanDegraded"}, {"probableCause", "Enclosure fan degraded"},
		{"eventType", "Hardware System"} , {eventSeverity, "MAJOR"},
		{proposedRepairactions, "Replace the failing enclosure fan."} | Acc]);
event([{"snmpTrapOID", "compaqq.[22010]"} | T], Acc) ->
	event(T, [{"eventName", "cpqRackEnclosureFanOk"}, {"probableCause", "Enclosure fan ok"},
		{"eventType", "Operational System"} , {eventSeverity, "INFORMATIONAL"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22011]"} | T], Acc) ->
	event(T, [{"eventName", "cpqRackEnclosureFanRemoved"}, {"probableCause", "Enclosure fan removed"},
		{"eventType", "Hardware System"} , {eventSeverity, "MINOR"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22012]"} | T], Acc) ->
	event(T, [{"eventName", "cpqRackEnclosureFanInserted"}, {"probableCause", "Enclosure fan inserted"},
		{"eventType", "Operational System"} , {eventSeverity, "INFORMATIONAL"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22013]"} | T], Acc) ->
	event(T, [{"eventName", "cpqRackPowerSupplyFailed"}, {"probableCause", "Rack power supply failed"},
		{"eventType", "Power System"} , {eventSeverity, "CRITICAL"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22014]"} | T], Acc) ->
	event(T, [{"eventName", "cpqRackPowerSupplyDegraded"}, {"probableCause", "Rack power supply degraded"},
		{"eventType", "Power System"} , {eventSeverity, "MAJOR"} | Acc]);
event([{"snmpTrapOID", "compaqq.[22015]"} | T], Acc) ->
	event(T, [{"eventName", "cpqRackPowerSupplyOk"}, {"probableCause", "Rack power supply ok"},
		{"eventType", "Power System"} , {eventSeverity, "INFORMATIONAL"} | Acc]);
event([_H | T], Acc) ->
	event(T, Acc);
event([], Acc) ->
	Acc.

