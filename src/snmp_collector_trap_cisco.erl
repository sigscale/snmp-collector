%%% snmp_collector_trap_cisco.erl
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
%% Varbinds are mapped to alarm attributes, using the MIBs avaialable,
%% and to VES attributes.
%%
%%	The following table shows the mapping between CISCO MIB attributes
%%	and VES attributes.
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
%% 		<td id="mt"></td>
%% 		<td id="mt"></td>
%%			<td id="mt"></td>
%% 	</tr>
%% </tbody>
%% </table></p>

-module(snmp_collector_trap_cisco).

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
%%  The snmp_collector_trap_cisco public API
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
		fault ->
			handle_fault(TargetName, Varbinds);
		syslog ->
			handle_syslog(TargetName, Varbinds)
	end;
handle_trap(TargetName, {Enteprise, Generic, Spec, Timestamp, Varbinds}, UserData) ->
	case domain(Varbinds) of
		other ->
			snmp_collector_trap_generic:handle_trap(TargetName,
					{Enteprise, Generic, Spec, Timestamp, Varbinds}, UserData);
		fault ->
			handle_fault(TargetName, Varbinds);
		syslog ->
			handle_syslog(TargetName, Varbinds)
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
		snmp_collector_utils:update_counters(cisco, TargetName, AlarmDetails),
		Event = snmp_collector_utils:generate_maps(TargetName, AlarmDetails, fault),
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
%% @doc CODEC for fault.
fault(NameValuePair) ->
	fault(NameValuePair, []).
%% @hidden
fault([{"snmpTrapOID", "cefcPowerSupplyOutputChange"},
		{"entPhysicalName", PhysicalName}, {"entPhysicalModelName", ModelName},
		{"cefcPSOutputModeCurrent", OutputModeCurrent} | T], Acc) ->
	fault(T, [{"alarmId",  snmp_collector_utils:generate_identity(7)},
			{"eventName", ?EN_NEW},
			{"sourceName", PhysicalName},
			{"modelName", ModelName},
			{"outputModeCurrent", OutputModeCurrent},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "powerSupplyOutputChange"},
			{"probableCause", ?PC_Power_Problem},
			{"eventType", ?ET_Equipment_Alarm} ,
			{"eventSeverity", ?ES_WARNING} | Acc]);
fault([{"snmpTrapOID", "ciscoEnvMonSuppStatusChangeNotif"},
		{"ciscoEnvMonSupplyStatusDescr", StatusDescription},
		{"ciscoEnvMonSupplyState", SupplyState} | T], Acc) ->
	fault(T, [{"alarmId",  snmp_collector_utils:generate_identity(7)},
			{"eventName", ?EN_NEW},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "powerSupplyOutputChange"},
			{"probableCause", ?PC_Power_Problem},
			{"eventType", ?ET_Environmental_Alarm} ,
			{"specificProblem", StatusDescription},
			{"powerSupplyState", SupplyState},
			{"eventSeverity", ?ES_WARNING} | Acc]);
fault([{"snmpTrapOID", "ciscoEnvMonShutdownNotification"} | T], Acc) ->
	fault(T, [{"alarmId",  snmp_collector_utils:generate_identity(7)},
			{"eventName", ?EN_NEW},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "envMonShutdownNotification"},
			{"probableCause", ?ET_Environmental_Alarm},
			{"specificProblem", "environmental monitor detected a testpoint reaching a
					critical state and is about to initiate a shutdown"},
			{"eventSeverity", ?ES_CRITICAL} | Acc]);
fault([{"snmpTrapOID", "ciscoEnvMonTempStatusChangeNotif"},
		{"ciscoEnvMonTemperatureStatusDescr", StatusDescription},
		{"ciscoEnvMonTemperatureStatusValue", StatusValue},
		{"ciscoEnvMonTemperatureState", TempState} | T], Acc) ->
	fault(T, [{"alarmId",  snmp_collector_utils:generate_identity(7)},
			{"eventName", ?EN_NEW},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "envMonTempStatusChangeNotif"},
			{"probableCause", ?PC_Temperature_Unacceptable},
			{"eventType", ?ET_Environmental_Alarm} ,
			{"specificProblem", StatusDescription},
			{"envMonTempStatysValue", StatusValue},
			{"powerSupplyState", TempState},
			{"eventSeverity", ?ES_WARNING} | Acc]);
fault([{"snmpTrapOID", "ciscoEnvMonVoltStatusChangeNotif"},
		{"ciscoEnvMonVoltageStatusDescr", StatusDescription},
		{"ciscoEnvMonVoltageStatusValue", StatusValue},
		{"ciscoEnvMonVoltageState", VoltageState} | T], Acc) ->
	fault(T, [{"alarmId",  snmp_collector_utils:generate_identity(7)},
			{"eventName", ?EN_NEW},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "envMonVoltStatusChangeNotif"},
			{"probableCause", ?PC_Rectifier_High_Voltage},
			{"eventType", ?ET_Environmental_Alarm} ,
			{"specificProblem", StatusDescription},
			{"envMonTempStatysValue", StatusValue},
			{"volatageState", VoltageState},
			{"eventSeverity", ?ES_WARNING} | Acc]);
fault([{"snmpTrapOID", "ciscoEnvMonFanStatusChangeNotif"},
		{"ciscoEnvMonFanStatusDescr", StatusDescription},
		{"ciscoEnvMonFanState", FanState} | T], Acc) ->
	fault(T, [{"alarmId",  snmp_collector_utils:generate_identity(7)},
			{"eventName", ?EN_NEW},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "envMonFanStatusChangeNotif"},
			{"probableCause", ?PC_Threshold_Crossed},
			{"eventType", ?ET_Environmental_Alarm} ,
			{"specificProblem", StatusDescription},
			{"fanState", FanState},
			{"eventSeverity", ?ES_WARNING} | Acc]);
fault([{"snmpTrapOID", "cErrDisableInterfaceEventRev1"},
		{"cErrDisableIfStatusCause", SpecificProblem} | T], Acc) ->
	fault(T, [{"alarmId",  snmp_collector_utils:generate_identity(7)},
			{"eventName", ?EN_NEW},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "errDisableInterfaceEvent"},
			{"probableCause", "Interface Error-Disabled"},
			{"eventType", ?ET_Operational_Violation} ,
			{"specificProblem", SpecificProblem},
			{"eventSeverity", ?ES_CRITICAL} | Acc]);
fault([{"snmpTrapOID", "ciscoMemoryPoolLowMemoryNotif"},
		{"ciscoMemoryPoolName", MemoryPoolName},
		{"ciscoMemoryPoolUsed", MemoryPoolUsed} | T], Acc) ->
	fault(T, [{"alarmId",  snmp_collector_utils:generate_identity(7)},
			{"eventName", ?EN_NEW},
			{"sourceName", MemoryPoolName},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "memoryPoolLowMemoryNotif"},
			{"probableCause", ?PC_Out_Of_Memory},
			{"memoryUsed", MemoryPoolUsed},
			{"eventType", ?ET_Operational_Violation} ,
			{"specificProblem", "Available memory in the system has fallen the below threshold"},
			{"eventSeverity", ?ES_MAJOR} | Acc]);
fault([{"snmpTrapOID", "ciscoMemoryPoolLowMemoryRecoveryNotif"},
		{"ciscoMemoryPoolName", MemoryPoolName},
		{"ciscoMemoryPoolUsed", MemoryPoolUsed} | T], Acc) ->
	fault(T, [{"alarmId",  snmp_collector_utils:generate_identity(7)},
			{"eventName", ?EN_CLEARED},
			{"sourceName", MemoryPoolName},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "memoryPoolLowMemoryNotif"},
			{"probableCause", "Memory Pool Recovered"},
			{"memoryUsed", MemoryPoolUsed},
			{"eventType", ?ET_Operational_Violation} ,
			{"specificProblem", "Recovered from low memory levels"},
			{"eventSeverity", ?ES_CLEARED} | Acc]);
fault([{"snmpTrapOID", "cswStackPowerInsufficientPower"},
		{"cswStackPowerName", StackPowerName} | T], Acc) ->
	fault(T, [{"alarmId",  snmp_collector_utils:generate_identity(7)},
			{"eventName", ?EN_NEW},
			{"sourceName", StackPowerName},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "stackPowerInsufficientPower"},
			{"probableCause", ?PC_Power_Problem},
			{"eventType", ?ET_Equipment_Alarm} ,
			{"specificProblem", "The switch's power stack does not have enough power
					to bring up all the switches in the power stack"},
			{"eventSeverity", ?ES_WARNING} | Acc]);
fault([{"snmpTrapOID", "cswStackPowerInvalidInputCurrent"},
		{"cswSwitchNumCurrent", SwitchNum},
		{"cswStackPowerPortOverCurrentThreshold", ExceededCurrentThreshold},
		{"cswStackPowerPortName", PortName} | T], Acc) ->
	fault(T, [{"alarmId",  snmp_collector_utils:generate_identity(7)},
			{"eventName", ?EN_NEW},
			{"sourceId", SwitchNum},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "stackPowerInvalidInputCurrent"},
			{"probableCause", ?PC_Power_Problem},
			{"eventType", ?ET_Equipment_Alarm} ,
			{"exceededThreadholdValue", ExceededCurrentThreshold},
			{"portName", PortName},
			{"specificProblem", "Input current in the
					stack power cable is over the limit of the threshold"},
			{"proposedRepairActions", "The user should add a power supply to the system whose
					switch number is generated with this alarm"},
			{"eventSeverity", ?ES_MINOR} | Acc]);
fault([{"snmpTrapOID", "cswStackPowerInvalidOutputCurrent"},
		{"cswSwitchNumCurrent", SwitchNum},
		{"cswStackPowerPortOverCurrentThreshold", ExceededCurrentThreshold},
		{"cswStackPowerPortName", PortName} | T], Acc) ->
	fault(T, [{"alarmId",  snmp_collector_utils:generate_identity(7)},
			{"eventName", ?EN_NEW},
			{"sourceId", SwitchNum},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "stackPowerInvalidOutputCurrent"},
			{"probableCause", ?PC_Power_Problem},
			{"eventType", ?ET_Equipment_Alarm} ,
			{"exceededThreadholdValue", ExceededCurrentThreshold},
			{"portName", PortName},
			{"specificProblem", "Output current in the
					stack power cable is over the limit of the threshold"},
			{"proposedRepairActions", "The user should remove a power supply from the system whose
					switch number is generated with this alarm"},
			{"eventSeverity", ?ES_MINOR} | Acc]);
fault([{"snmpTrapOID", "cswStackPowerPriorityConflict"},
		{"cswStackPowerName", StackPowerName} | T], Acc) ->
	fault(T, [{"alarmId",  snmp_collector_utils:generate_identity(7)},
			{"eventName", ?EN_NEW},
			{"sourceName", StackPowerName},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "stackPowerPriorityConflict"},
			{"probableCause", ?PC_Power_Problem},
			{"eventType", ?ET_Equipment_Alarm} ,
			{"specificProblem", "The switch's power priorities are conflicting with
					power priorities of another switch in the same power stack"},
			{"eventSeverity", ?ES_MINOR} | Acc]);
fault([{"snmpTrapOID", "cswStackPowerUnbalancedPowerSupplies"},
		{"cswStackPowerName", StackPowerName} | T], Acc) ->
	fault(T, [{"alarmId",  snmp_collector_utils:generate_identity(7)},
			{"eventName", ?EN_NEW},
			{"sourceName", StackPowerName},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"alarmCondition", "stackPowerUnbalancedPowerSupplies"},
			{"probableCause", ?PC_Power_Problem},
			{"eventType", ?ET_Equipment_Alarm} ,
			{"specificProblem", "The switch has no power supply but another switch
					in the same stack has more than one power supply"},
			{"eventSeverity", ?ES_MINOR} | Acc]);
fault([{Name, Value} | T], Acc)
      when length(Value) > 0 ->
	fault(T, [{Name, Value} | Acc]);
fault([], Acc) ->
	Acc.

-spec handle_syslog(TargetName, Varbinds) -> Result
	when
		TargetName :: string(),
		Varbinds :: snmp:varbinds(),
		Result :: ignore | {error, Reason},
		Reason :: term().
%% @doc Handle a syslog event.
handle_syslog(TargetName, Varbinds) ->
	try
		{ok, Pairs} = snmp_collector_utils:arrange_list(Varbinds),
		{ok, NamesValues} = snmp_collector_utils:oids_to_names(Pairs, []),
		AlarmDetails = syslog(NamesValues),
		Event = snmp_collector_utils:generate_maps(TargetName, AlarmDetails, syslog),
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

-spec syslog(OidNameValuePair) -> VesNameValuePair
	when
		OidNameValuePair :: [{OidName, OidValue}],
		OidName :: string(),
		OidValue :: string(),
		VesNameValuePair :: [{VesName, VesValue}],
		VesName :: string(),
		VesValue :: string().
%% @doc CODEC for syslog.
syslog(NameValuePair) ->
	syslog(NameValuePair, []).
%% @hidden
syslog([{"snmpTrapOID", "clogMessageGenerated"},
		{"clogHistFacility", FacilityName},
		{"clogHistSeverity", SysLogSeverity}, {"clogHistMsgName", MessageName},
		{"clogHistMsgText", MessageText}, {"clogHistTimestamp", TimeStamp} | T], Acc) ->
	syslog(T, [{"sysSourceType", FacilityName},
			{"eventFieldsVersion", 1},
			{"syslogMsg", MessageText},
			{"eventType", ?ET_Communication_System},
			{"syslogSev", snmp_collector_trap_generic:syslog_severity(SysLogSeverity)},
			{"syslogTag", MessageName},
			{"raisedTime", TimeStamp} | Acc]);
syslog([{Name, Value} | T], Acc)
      when length(Value) > 0 ->
	syslog(T, [{Name, Value} | Acc]);
syslog([], Acc) ->
	Acc.

-spec domain(Varbinds) -> Result
	when
		Varbinds :: [snmp:varbinds()],
		Result :: fault | syslog | heartbeat | other.
%% @doc Verify if the domain of the event.
domain([_TimeTicks, {varbind, [1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0] , _, TrapName, _} | _T]) ->
	domain1(snmp_collector_utils:oid_to_name(TrapName)).
%% @hidden
%%
domain1("cefcPowerSupplyOutputChange") ->
	fault;
domain1("ciscoEnvMonSuppStatusChangeNotif") ->
	fault;
domain1("ciscoEnvMonShutdownNotification") ->
	fault;
domain1("ciscoEnvMonTempStatusChangeNotif") ->
	fault;
domain1("ciscoEnvMonVoltStatusChangeNotif") ->
	fault;
domain1("ciscoEnvMonFanStatusChangeNotif") ->
	fault;
domain1("cErrDisableInterfaceEventRev1") ->
	fault;
domain1("ciscoMemoryPoolLowMemoryNotif") ->
	fault;
domain1("ciscoMemoryPoolLowMemoryRecoveryNotif") ->
	fault;
domain1("cswStackPowerInsufficientPower") ->
	fault;
domain1("cswStackPowerInvalidInputCurrent") ->
	fault;
domain1("cswStackPowerInvalidOutputCurrent") ->
	fault;
domain1("cswStackPowerPriorityConflict") ->
	fault;
domain1("cswStackPowerUnbalancedPowerSupplies") ->
	fault;
domain1("clogMessageGenerated") ->
	syslog;
domain1(_) ->
	other.
	
