%%% snmp_collector_huawei_trap.erl
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
-module(snmp_collector_huawei_trap).
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

-spec event(NameValuePair) -> NameValuePair
	when
		NameValuePair :: [{Name, Value}] | [{Name, Value}].
%% @doc CODEC for event.
event(NameValuePair) ->
	event(NameValuePair, []).
%% @hidden
event([{"iMAPNorthboundAlarmID", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"alarmId", Value} | Acc]);
event([{"iMAPNorthboundAlarmCSN", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"eventId	", Value} | Acc]);
event([{"iMAPNorthboundAlarmDevCsn", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"eventName", Value} | Acc]);
event([{"iMAPNorthboundAlarmNEDevID", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"sourceName", Value} | Acc]);
event([{"iMAPNorthboundAlarmMOName", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"objectInstance", Value}| Acc]);
event([{"iMAPNorthboundAlarmSpecificproblems", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"specificProblem", Value} | Acc]);
event([{"iMAPNorthboundAlarmNEType", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"eventSourceType", Value} | Acc]);
event([{"iMAPNorthboundAlarmLevel", "1"} | T], Acc) ->
	event(T, [{"eventSeverity", "CRITICAL"} | Acc]);
event([{"iMAPNorthboundAlarmLevel", "2"} | T], Acc) ->
	event(T, [{"eventSeverity", "MAJOR"} | Acc]);
event([{"iMAPNorthboundAlarmLevel", "3"} | T], Acc) ->
	event(T, [{"eventSeverity", "MINOR"} | Acc]);
event([{"iMAPNorthboundAlarmLevel", "4"} | T], Acc) ->
	event(T, [{"eventSeverity", "WARNING"} | Acc]);
event([{"iMAPNorthboundAlarmLevel", "5"} | T], Acc) ->
	event(T, [{"eventSeverity", "INDETERMINATE"} | Acc]);
event([{"iMAPNorthboundAlarmLevel", "6"} | T], Acc) ->
	event(T, [{"eventSeverity", "CLEARED"} | Acc]);
event([{"iMAPNorthboundAlarmCategory", "1"} | T], Acc) ->
	event(T, [{"alarmCondition", "NEW"}, {"eventName", notifyNewAlarm} | Acc]);
event([{"iMAPNorthboundAlarmCategory", "2"} | T], Acc) ->
	event(T, [{"alarmCondition", "CLEARED"}, {"eventName", notifyClearedAlarm} | Acc]);
event([{"iMAPNorthboundAlarmCategory", "9"} | T], Acc) ->
	event(T, [{"alarmCondition", "CHANGED"} , {"eventName", notifyChangedAlarm}| Acc]);
event([{"iMAPNorthboundAlarmRestore", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"alarmRestore", Value} | Acc]);
event([{"iMAPNorthboundAlarmOccurTime", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"alarmOccurTime", Value} | Acc]);
event([{"iMAPNorthboundAlarmOccurTime", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"raisedTime", Value} | Acc]);
event([{"iMAPNorthboundAlarmAdditionalInfo", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"additionalInfo", Value} | Acc]);
event([{"iMAPNorthboundAlarmServiceAffectFlag", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"serviceAffectFlag", Value} | Acc]);
event([{"iMAPNorthboundAlarmClearType", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"clearType", Value} | Acc]);
event([{"iMAPNorthboundAlarmClearCategory", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"clearCategory", Value} | Acc]);
event([{"iMAPNorthboundAlarmObjectInstanceType", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"objectInstanceType", Value} | Acc]);
event([{"iMAPNorthboundAlarmClearOperator", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"clearOperator", Value} | Acc]);
event([{"iMAPNorthboundAlarmProposedrepairactions", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"proposedRepairactions", Value} | Acc]);
event([{"iMAPNorthboundAlarmProbablecause", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"probableCause", Value} | Acc]);
event([{"iMAPNorthboundAlarmExtendInfo", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"extendInfo", Value} | Acc]);
event([{"iMAPNorthboundAlarmOperator", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"alarmOperator", Value} | Acc]);
event([{"iMAPNorthboundAlarmRestoreTime", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"restoreTime", Value} | Acc]);
event([{"iMAPNorthboundAlarmAckTime", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"alarmAckTime", Value} | Acc]);
event([{"iMAPNorthboundAlarmConfirm", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"alarmAckState", Value} | Acc]);
event([{"iMAPNorthboundAlarmRestore", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"alarmRestore", Value} | Acc]);
event([{"iMAPNorthboundAlarmType", 1} | T], Acc) ->
	event(T, [{"eventType", "Power System"} | Acc]);
event([{"iMAPNorthboundAlarmType", 2} | T], Acc) ->
	event(T, [{"eventType", "Environmental Alarm"} | Acc]);
event([{"iMAPNorthboundAlarmType", 3} | T], Acc) ->
	event(T, [{"eventType", "Signaling System"} | Acc]);
event([{"iMAPNorthboundAlarmType", 4} | T], Acc) ->
	event(T, [{"eventType", "Trunk System"} | Acc]);
event([{"iMAPNorthboundAlarmType", 5} | T], Acc) ->
	event(T, [{"eventType", "Hardware System"} | Acc]);
event([{"iMAPNorthboundAlarmType", 6} | T], Acc) ->
	event(T, [{"eventType", "Software System"} | Acc]);
event([{"iMAPNorthboundAlarmType", 7} | T], Acc) ->
	event(T, [{"eventType", "Running System"} | Acc]);
event([{"iMAPNorthboundAlarmType", 8} | T], Acc) ->
	event(T, [{"eventType", "Communication System"} | Acc]);
event([{"iMAPNorthboundAlarmType", 9} | T], Acc) ->
	event(T, [{"eventType", "Quality Of Service Alarm"} | Acc]);
event([{"iMAPNorthboundAlarmType", 10} | T], Acc) ->
	event(T, [{"eventType", "Processing error"} | Acc]);
event([{"iMAPNorthboundAlarmType", 11} | T], Acc) ->
	event(T, [{"eventType", "OMC"} | Acc]);
event([{"iMAPNorthboundAlarmType", 12} | T], Acc) ->
	event(T, [{"eventType", "Integrity Violation"} | Acc]);
event([{"iMAPNorthboundAlarmType", 13} | T], Acc) ->
	event(T, [{"eventType", "Operational Violation"} | Acc]);
event([{"iMAPNorthboundAlarmType", 14} | T], Acc) ->
	event(T, [{"eventType", "Physical Violation"} | Acc]);
event([{"iMAPNorthboundAlarmType", 15} | T], Acc) ->
	event(T, [{"eventType", "Security Service Or Mechanism Violation"} | Acc]);
event([{"iMAPNorthboundAlarmType", 16} | T], Acc) ->
	event(T, [{"eventType", "Time Domain Violation"} | Acc]);
event([{"iMAPNorthboundAlarmProductID", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"alarmProductID", Value} | Acc]);
event([{"iMAPNorthboundAlarmOccurTime", Value} | T], Acc)
		when is_list(Value) ->
	event(T, [{"alarmOccurTime", Value} ,{"alarmReportingTime",
			erlang:system_time(?MILLISECOND)}| Acc]);
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
	case snmpm:name_to_oid(iMAPNorthboundHeartbeatTimeStamp) of
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

