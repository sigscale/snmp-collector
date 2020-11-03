%%% snmp_collector_trap_adva.erl
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
%% 		<td id="mt"></td>
%% 		<td id="mt"></td>
%%			<td id="mt"></td>
%% 	</tr>
%% </tbody>
%% </table></p>

-module(snmp_collector_trap_adva).
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
%%  The snmp_collector_trap_adva public API
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
		fault ->
			handle_fault(TargetName, UserData, Varbinds)
	end;
handle_trap(TargetName, {Enteprise, Generic, Spec, Timestamp, Varbinds}, UserData) ->
	case domain(Varbinds) of
		other ->
			snmp_collector_trap_generic:handle_trap(TargetName,
					{Enteprise, Generic, Spec, Timestamp, Varbinds}, UserData);
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
%%
-spec handle_fault(TargetName, UserData, Varbinds) -> Result
	when
		TargetName :: string(),
		UserData :: term(),
		Varbinds :: snmp:varbinds(),
		Result :: ignore | {error, Reason},
		Reason :: term().
%% @doc Handle a fault event.
handle_fault(TargetName, _UserData, Varbinds) ->
	try
		{ok, Pairs} = snmp_collector_utils:arrange_list(Varbinds),
		{ok, NamesValues} = snmp_collector_utils:oids_to_names(Pairs, []),
		AlarmDetails = fault(NamesValues),
		snmp_collector_utils:update_counters(adva, TargetName, AlarmDetails),
		Event = snmp_collector_utils:create_event(TargetName, AlarmDetails, fault),
		snmp_collector_utils:send_event(Event)
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
fault(NameValuePair) ->
	case lists:keyfind("disposition", 1, NameValuePair) of
		{_, "1"} ->
			fault(NameValuePair, ?EN_NEW,
					[{"eventName", ?EN_NEW}]);
		{_, "2"} ->
			fault(NameValuePair, ?EN_CLEARED,
					[{"eventName", ?EN_CLEARED}]);
		{_, _} ->
			fault(NameValuePair, ?EN_CHANGED,
					[{"eventName", ?EN_CHANGED}])
	end.
%% @hidden
fault([{"id", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"alarmId", Value}, {"nfVendorName", "adva"} | Acc]);
fault([{"neIpAddress", Value} | T], EN, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, EN, [{"sourceId", Value} | Acc]);
fault([{"elementName", Value} | T], EN, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, EN, [{"sourceName", Value} | Acc]);
fault([{"", Value} | T], EN, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, EN, [{"eventSourceType", Value} | Acc]);
fault([{"entity", Value} | T], EN, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, EN, [{"objectInstance", Value}| Acc]);
fault([{"snmpTrapOID", "fspNmGenericEvent"} | T], EN, Acc) ->
	fault(T, EN, [{"alarmCondition", "genericEvent"} | Acc]);
fault([{"nmsTime", Value} | T], EN, Acc)
		when EN == ?EN_NEW, is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"raisedTime", snmptime_to_string(Value)} | Acc]);
fault([{"nmsTime", Value} | T], EN, Acc)
		when EN == ?EN_CHANGED, is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"changedTime", snmptime_to_string(Value)} | Acc]);
fault([{"nmsTime", Value} | T], EN, Acc)
		when EN == ?EN_CLEARED, is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"clearedTime", snmptime_to_string(Value)} | Acc]);
fault([{"neTime", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"neTime", snmptime_to_string(Value)} | Acc]);
fault([{"severity", "1"} | T], EN, Acc) ->
	fault(T, EN, [{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
fault([{"severity", "2"} | T], EN, Acc) ->
	fault(T, EN, [{"eventSeverity", ?ES_CRITICAL} | Acc]);
fault([{"severity", "3"} | T], EN, Acc) ->
	fault(T, EN, [{"eventSeverity", ?ES_MAJOR} | Acc]);
fault([{"severity", "4"} | T], EN, Acc) ->
	fault(T, EN, [{"eventSeverity", ?ES_MINOR} | Acc]);
fault([{"severity", "5"} | T], EN, Acc) ->
	fault(T, EN, [{"eventSeverity", ?ES_WARNING} | Acc]);
fault([{"name", Value} | T], EN, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, EN, [{"specificProblem", Value} | Acc]);
fault([{"impairment", "1"} | T], EN, Acc) ->
	fault(T, EN, [{"impairment", "Service Affecting"} | Acc]);
fault([{"impairment", "2"} | T], EN, Acc) ->
	fault(T, EN, [{"impairment", "Not Service Affecting"} | Acc]);
fault([{"disabled", "1"} | T], EN, Acc) ->
	fault(T, EN, [{"disabled", "Yes"} | Acc]);
fault([{"disabled", "2"} | T], EN, Acc) ->
	fault(T, EN, [{"disabled", "No"} | Acc]);
fault([{"location", "0"} | T], EN, Acc) ->
	fault(T, EN, [{"location", "None"} | Acc]);
fault([{"location", "1"} | T], EN, Acc) ->
	fault(T, EN, [{"location", "Both"} | Acc]);
fault([{"location", "2"} | T], EN, Acc) ->
	fault(T, EN, [{"location", "FarEnd"} | Acc]);
fault([{"location", "3"} | T], EN, Acc) ->
	fault(T, EN, [{"location", "NearEnd"} | Acc]);
fault([{"location", "4"} | T], EN, Acc) ->
	fault(T, EN, [{"location", "Not Applicable"} | Acc]);
fault([{"direction", "0"} | T], EN, Acc) ->
	fault(T, EN, [{"location", "None"} | Acc]);
fault([{"direction", "1"} | T], EN, Acc) ->
	fault(T, EN, [{"location", "Bidirectional"} | Acc]);
fault([{"direction", "2"} | T], EN, Acc) ->
	fault(T, EN, [{"location", "Both Directions"} | Acc]);
fault([{"direction", "3"} | T], EN, Acc) ->
	fault(T, EN, [{"location", "Not Applicable"} | Acc]);
fault([{"direction", "4"} | T], EN, Acc) ->
	fault(T, EN, [{"location", "Receive Direction Only"} | Acc]);
fault([{"direction", "5"} | T], EN, Acc) ->
	fault(T, EN, [{"location", "Transmission Direction Only"} | Acc]);
fault([{"direction", "6"} | T], EN, Acc) ->
	fault(T, EN, [{"location", "Unidirectional"} | Acc]);
fault([{"description", Value} | T], EN, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, EN, [{"additionalText", Value} | Acc]);
fault([{"acknowledged", "1"} | T], EN, Acc) ->
	fault(T, EN, [{"alarmAckState", ?ACK_Acknowledged} | Acc]);
fault([{"acknowledged", "2"} | T], EN, Acc) ->
	fault(T, EN, [{"alarmAckState", ?ACK_Unacknowledged} | Acc]);
fault([{"corr", "1"} | T], EN, Acc) ->
	fault(T, EN, [{"corr", "Redundant"} | Acc]);
fault([{"corr", "2"} | T], EN, Acc) ->
	fault(T, EN, [{"corr", "Primary"} | Acc]);
fault([{"corrRef", Value} | T], EN, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, EN, [{"corrRef", Value} | Acc]);
fault([{"mtosiNeType", Value} | T], EN, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, EN, [{"mtosiNeType", Value} | Acc]);
fault([{"serviceName", Value} | T], EN, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, EN, [{"serviceName", Value} | Acc]);
fault([{"customerName", Value} | T], EN, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, EN, [{"customerName", Value} | Acc]);
fault([{"security", "1"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Security_Service_Or_Mechanism_Violation} | Acc]);
fault([{"eventType", "1"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Communication_System} | Acc]);
fault([{"eventType", "2"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Quality_Of_Service_Alarm} | Acc]);
fault([{"eventType", "3"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Processing_Error} | Acc]);
fault([{"eventType", "4"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Equipment_Alarm} | Acc]);
fault([{"eventType", "5"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Environmental_Alarm} | Acc]);
fault([{"security", Value} | T], EN, Acc) ->
	fault(T, EN, [{"security", Value} | Acc]);
fault([{"comment", Value} | T], EN, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, EN, [{"eventComments", Value} | Acc]);
fault([{"neType", Value} | T], EN, Acc) ->
	fault(T, EN, [{"neType", ne_type(Value)} | Acc]);
fault([{"name", Value} | T], EN, Acc)
		when length(Value) > 0, Value =/= [$ ] ->
	fault(T, EN, [{"specificProblem", Value} | Acc]);
fault([{"update", "1"} | T], EN, Acc) ->
	fault(T, EN, [{"update", "true"} | Acc]);
fault([{"update", "2"} | T], EN, Acc) ->
	fault(T, EN, [{"update", "false"} | Acc]);
fault([{"update", "3"} | T], EN, Acc) ->
	fault(T, EN, [{"update", "sync"} | Acc]);
fault([{_, [$ ]} | T], EN, Acc) ->
	fault(T, EN, Acc);
fault([{_, []} | T], EN, Acc) ->
	fault(T, EN, Acc);
fault([{Name, Value} | T], EN, Acc) ->
	fault(T, EN, [{Name, Value} | Acc]);
fault([], _, Acc) ->
	[{"probableCause", ?PC_Indeterminate} | Acc].

-spec domain(Varbinds) -> Result
	when
		Varbinds :: [Varbinds],
		Result :: fault | other.
%% @doc Check the domain of the event.
domain([_TimeTicks, {varbind, [1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0] , _, TrapName, _} | _T]) ->
	domain1(snmp_collector_utils:oid_to_name(TrapName)).
%% @hidden
domain1("fspNmGenericEvent") ->
	fault;
domain1(_Other) ->
	other.

-spec snmptime_to_string(SnmpDateAndTime) -> Result
	when
		SnmpDateAndTime :: [integer()],
		Result :: DateTime | {error, Reason},
		DateTime :: string(),
		Reason :: term().
%% @doc Convert a SnmpDateAndTime list to a printable string,
snmptime_to_string(SnmpDateAndTime)
		when is_list(SnmpDateAndTime) ->
	case catch snmp:date_and_time_to_string(SnmpDateAndTime) of
		DateTime when is_list(DateTime) ->
			DateTime;
		{'EXIT', Reason} ->
			{error, Reason}
	end.

-spec ne_type(Value) -> Result
	when
		Value :: string(),
		Result :: string().
%% @doc Look up a NEType
ne_type("1") ->
	"fsp500";
ne_type("2") ->
	"fsp1500";
ne_type("3") ->
	"fsp2000";
ne_type("4") ->
	"fsp3000";
ne_type("5") ->
	"fsp150CP";
ne_type("6") ->
	"fsp150Mx";
ne_type("10") ->
	"fsp150CCt-312";
ne_type("11") ->
	"fsp150CCd-410";
ne_type("12") ->
	"fsp150CCf-411";
ne_type("13") ->
	"fsp150CCt-512";
ne_type("14") ->
	"fsp150CCs-624";
ne_type("15") ->
	"fsp150CCd-811";
ne_type("16") ->
	"fsp150CCf-814";
ne_type("17") ->
	"fsp150CCf-815";
ne_type("18") ->
	"fsp150CCf-825";
ne_type("19") ->
	"fsp150CCs-925";
ne_type("20") ->
	"fsp150CC-GE206";
ne_type("21") ->
	"fsp150CC-GE201";
ne_type("22") ->
	"fsp150CC-GE201SE";
ne_type("23") ->
	"fsp150CC-324";
ne_type("24") ->
	"fsp150CC-584";
ne_type("25") ->
	"fsp150CC-GE206F";
ne_type("26") ->
	"fsp150EG-X";
ne_type("27") ->
	"fsp150CC-GE206V";
ne_type("28") ->
	"fsp150CC-GE112";
ne_type("29") ->
	"fsp150CC-GE114";
ne_type("30") ->
	"fsp150CC-GE114S";
ne_type("31") ->
	"fsp150CC-XG210";
ne_type("32") ->
	"osa-5410";
ne_type("33") ->
	"fsp150CC-GE114H";
ne_type("34") ->
	"fsp150CC-GE114SH";
ne_type("35") ->
	"fsp150CC-GE114PH";
ne_type("36") ->
	"fsp150CC-T1804";
ne_type("37") ->
	"fsp150CC-T3204";
ne_type("38") ->
	"fsp150CC-SH1PCS";
ne_type("39") ->
	"osa-5411";
ne_type("40") ->
	"fsp150CC-XG210C";
ne_type("50") ->
	"fsp150CM";
ne_type("60") ->
	"osa-5331";
ne_type("61") ->
	"osa-5548C-SSU60";
ne_type("62") ->
	"osa-5548C-SSU200";
ne_type("63") ->
	"osa-5548C-TSG60";
ne_type("64") ->
	"osa-5548C-TSG200";
ne_type("65") ->
	"osa-5335-PTPGM";
ne_type("66") ->
	"osa-5420";
ne_type("67") ->
	"osa-5421";
ne_type("71") ->
	"fsp150-GE112pro";
ne_type("72") ->
	"fsp150-GE112proM";
ne_type("73") ->
	"fsp150-GE112proH";
ne_type("74") ->
	"fsp150-GE114pro";
ne_type("75") ->
	"fsp150-GE114proC";
ne_type("76") ->
	"fsp150-GE114proSH";
ne_type("77") ->
	"fsp150-GE114proCSH";
ne_type("78") ->
	"fsp150-GE114proHE";
ne_type("79") ->
	"osaSNMPProxy";
ne_type("80") ->
	"osa-5401";
ne_type("81") ->
	"fsp150-proVMeF26x4";
ne_type("82") ->
	"fsp150-proVMeF26x8CS";
ne_type("83") ->
	"fsp150-GE101pro";
ne_type("84") ->
	"fsp150-proVMeF26x4C";
ne_type("100") ->
	"fsp3000R7";
ne_type("101") ->
	"fsp3000RE";
ne_type("102") ->
	"ots1000";
ne_type("103") ->
	"fsp3000R7-ALM";
ne_type("104") ->
	"fsp1500-STM16";
ne_type("105") ->
	"fsp1500-STM16-PROT";
ne_type("106") ->
	"fsp1500-STM4-PROT";
ne_type("2000") ->
	"unmanaged";
ne_type("200") ->
	"t320";
ne_type("201") ->
	"t340";
ne_type("202") ->
	"t1600";
ne_type("203") ->
	"t4000";
ne_type("204") ->
	"mx240";
ne_type("205") ->
	"mx480";
ne_type("206") ->
	"mx960";
ne_type("207") ->
	"mx80";
ne_type("208") ->
	"ptx5000";
ne_type("300") ->
	"tp5000";
ne_type("1000") ->
	"hn4000";
ne_type("1001") ->
	"hn400";
ne_type("1002") ->
	"fsp150-egm4";
ne_type("1003") ->
	"fsp150-egm8";
ne_type("9999") ->
	"fspNm";
ne_type("10000") ->
	"customProduct";
ne_type("10001") ->
	"customProduct1";
ne_type("10002") ->
	"customProduct2";
ne_type("10003") ->
	"customProduct3".

