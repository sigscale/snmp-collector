%%% snmp_collector_trap_generic.erl
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

%% @doc This module normalizes Generic Traps.
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

-module(snmp_collector_trap_generic).
-copyright('Copyright (c) 2016 - 2019 SigScale Global Inc.').

-include("snmp_collector.hrl").

-behaviour(snmpm_user).

%% export snmpm_user call backs.
-export([handle_error/3, handle_agent/5,
		handle_pdu/4, handle_trap/3, handle_inform/3,
		handle_report/3, syslog_severity/1]).

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
handle_trap(TargetName, {_ErrorStatus, _ErrorIndex, Varbinds}, _UserData) ->
	try
		{ok, Pairs} = snmp_collector_utils:arrange_list(Varbinds),
		{ok, NamesValues} = snmp_collector_utils:oids_to_names(Pairs, []),
		AlarmDetails = event(NamesValues),
		Event = snmp_collector_utils:generate_maps(TargetName, AlarmDetails, fault),
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
		Event = snmp_collector_utils:generate_maps(TargetName, AlarmDetails, fault),
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
event(NameValuePair) ->
	event(NameValuePair, []).
%% hidden
event([{"snmpTrapOID", "authenticationFailure"}, {"authAddar", AuthAddress},
		{"cExtSnmpTargetAuthInetType", AuthAddressType},
		{"cExtSnmpTargetAuthInetAddr", HostAddress} | T], Acc) ->
	event(T, [{"eventSourceType", AuthAddressType},
			{"sysSourceHost", HostAddress},
			{"authAddress", AuthAddress},
			{"eventFieldsVersion", 1},
			{"syslogMsg", "authenticationFailure"},
			{"syslogSev", ?SYS_WARNING},
			{"raisedTime", erlang:system_time(milli_seconds)} | Acc]);
event([{"snmpTrapOID", "linkDown"}, {"ifIndex", InterfaceIndex},
		{"ifDescr", InterfaceDescripton}, {"ifType", InterfaceType},
		{"locIfReason", StatusChangeReason} | T], Acc) ->
	event(T, [{"alarmId", InterfaceIndex},
			{"sourceName", InterfaceDescripton},
			{"alarmMocObjectInstance", InterfaceType},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"eventName", ?EN_NEW},
			{"alarmCondition", "linkup"},
			{"probableCause", ?PC_External_If_Device_Problem},
			{"eventType", ?ET_Equipment_Alarm} ,
			{"eventSeverity", ?ES_MAJOR},
			{"specificProblem", StatusChangeReason} | Acc]);
event([{"snmpTrapOID", "linkUp"}, {"ifIndex", InterfaceIndex},
		{"ifDescr", InterfaceDescripton}, {"ifType", InterfaceType},
		{"locIfReason", StatusChangeReason} | T], Acc) ->
	event(T, [{"alarmId", InterfaceIndex},
			{"sourceName", InterfaceDescripton},
			{"alarmMocObjectInstance", InterfaceType},
			{"raisedTime", erlang:system_time(milli_seconds)},
			{"eventName", ?EN_CLEARED},
			{"alarmCondition", "linkup"},
			{"probableCause", ?PC_External_If_Device_Problem},
			{"eventType", ?ET_Equipment_Alarm} ,
			{"eventSeverity", ?ES_CLEARED},
			{"specificProblem", StatusChangeReason} | Acc]);
event([{Name, Value} | T], Acc)
      when is_list(Value), length(Value) > 0 ->
	event(T, [{Name, Value} | Acc]);
event([_H | T], Acc) ->
	event(T, Acc);
event([], Acc) ->
	Acc.

-spec syslog_severity(Severity) -> Result
	when
		Severity :: pos_integer(),
		Result :: string().
 %% @doc Look up the syslog severity.
syslog_severity(1) ->
	?SYS_EMERGENCY;
syslog_severity(2) ->
	?SYS_ALERT;
syslog_severity(3) ->
	?SYS_CRITICAL;
syslog_severity(4) ->
	?SYS_ERROR;
syslog_severity(5) ->
	?SYS_WARNING;
syslog_severity(6) ->
	?SYS_NOTICE;
syslog_severity(8) ->
	?SYS_DEBUG;
syslog_severity(_) ->
	?SYS_WARNING.

