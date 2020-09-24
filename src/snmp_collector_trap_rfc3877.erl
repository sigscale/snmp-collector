%%% snmp_collector_trap_rfc3877.erl
%%% vim: ts=3
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% @copyright 2016 - 2020 SigScale Global Inc.
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

%% @doc This module normalizes RFC3877 traps received on NBI.
%%
%% Varbinds are mapped to alarm attributes, using the MIBs avaialable,
%% and to VES attributes.
%%
%%	The following table shows the mapping between RFC3877 MIB attributes
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
%% 		<td id="mt">ituAlarmEventType</td>
%% 		<td id="mt">commonEventheader.eventType</td>
%%			<td id="mt">e.g. "Quality of Service Alarm"</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ituAlarmProbableCause</td>
%% 		<td id="mt">faultsFields.alarmAdditionalInformation.probableCause</td>
%%			<td id="mt">3GPP 32.111-2 Annex B e.g. "Alarm Indication Signal (AIS)</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmDescription</td>
%% 		<td id="mt">faultFields.specificProblem</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ituAlarmAdditionalText</td>
%% 		<td id="mt">additionalText</td>
%%			<td id="mt"></td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmActiveIndex/alarmClearIndex</td>
%% 		<td id="mt">faultFields.alarmAdditionalInformation.alarmId</td>
%%			<td id="mt">Unique identifier of an alarm</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">ituAlarmPerceivedSeverity</td>
%% 		<td id="mt">faultFields.eventSeverity</td>
%%			<td id="mt">CRITICAL | MAJOR | MINOR | WARNING | INDETERMINATE | CLEARED</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">snmpTrapOID</td>
%% 		<td id="mt">commonEventHeader.eventName</td>
%%			<td id="mt">notifyNewAlarm | notifyChangedAlarm | notifyClearedAlarm</td>
%% 	</tr>
%%		<tr id="mt">
%% 		<td id="mt">alarmActiveDateAndTime/alarmClearDateAndTime</td>
%% 		<td id="mt">commonEventHeader.startEpochMicrosec</td>
%%			<td id="mt"></td>
%% 	</tr>
%% </tbody>
%% </table></p>

-module(snmp_collector_trap_rfc3877).
-copyright('Copyright (c) 2016 - 2020 SigScale Global Inc.').

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
%%  The snmp_collector_trap_rfc3877 public API
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

-spec handle_fault(TargetName, UserData, Varbinds) -> Result
	when
		TargetName :: string(),
		UserData :: term(),
		Varbinds :: snmp:varbinds(),
		Result :: ignore | {error, Reason},
		Reason :: term().
%% @doc Handle a fault event.
handle_fault(TargetName, UserData, Varbinds) ->
	try
		{ok, Pairs} = snmp_collector_utils:arrange_list(Varbinds),
		{ok, NamesValues} = snmp_collector_utils:oids_to_names(Pairs, []),
		AlarmDetails = fault(NamesValues),
		snmp_collector_utils:update_counters(rfc3877, TargetName, AlarmDetails),
		Address = lists:keyfind(address, 1, UserData),
		Event = snmp_collector_utils:create_event(TargetName,
				[{"alarmIp", Address} | AlarmDetails], fault),
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
fault([{"snmpTrapOID", "alarmActiveState"} | T] = _OldNameValuePair) ->
	fault(T, "alarmNew", [{"eventName", ?EN_NEW},
			{"alarmCondition", "alarmNew"}]);
fault([{"snmpTrapOID", "alarmClearState"} | T]) ->
	fault(T, "alarmCleared", [{"eventName", ?EN_CLEARED},
			{"alarmCondition", "alarmCleared"},
			{"eventSeverity", ?ES_CLEARED}]).
%% @hidden
fault([{"alarmActiveIndex", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"alarmId", Value} | Acc]);
fault([{"alarmClearIndex", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"alarmId", Value} | Acc]);
fault([{"alarmActiveDateAndTime", Value} | T], EN, Acc)
		when EN == "alarmNew", is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"raisedTime", Value} | Acc]);
fault([{"alarmActiveDateAndTime", Value} | T], EN, Acc)
		when EN == "alarmSeverityChange", is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"changedTime", Value} | Acc]);
fault([{"alarmClearDateAndTime", Value} | T], EN, Acc)
		when EN == "alarmCleared", is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"clearedTime", Value} | Acc]);
fault([{"alarmActiveResourceId", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"sourceId", Value} | Acc]);
fault([{"alarmClearResourceId", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"sourceId", Value} | Acc]);
fault([{"alarmActiveEngineID", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"reportingEntityId", Value} | Acc]);
fault([{"alarmClearEngineID", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"reportingEntityId", Value} | Acc]);
fault([{"ituAlarmProbableCause", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"probableCause", probable_cause(Value)} | Acc]);
fault([{"alarmActiveDescription", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"specificProblem", Value} | Acc]);
fault([{"ituAlarmPerceivedSeverity", "1"} | T], EN, Acc) ->
	fault(T, EN, [{"eventSeverity", ?ES_CLEARED} | Acc]);
fault([{"ituAlarmPerceivedSeverity", "2"} | T], EN, Acc) ->
	fault(T, EN, [{"eventSeverity", ?ES_INDETERMINATE} | Acc]);
fault([{"ituAlarmPerceivedSeverity", "3"} | T], EN, Acc) ->
	fault(T, EN, [{"eventSeverity", ?ES_CRITICAL} | Acc]);
fault([{"ituAlarmPerceivedSeverity", "4"} | T], EN, Acc) ->
	fault(T, EN, [{"eventSeverity", ?ES_MAJOR} | Acc]);
fault([{"ituAlarmPerceivedSeverity", "5"} | T], EN, Acc) ->
	fault(T, EN, [{"eventSeverity", ?ES_MINOR} | Acc]);
fault([{"ituAlarmPerceivedSeverity", "6"} | T], EN, Acc) ->
	fault(T, EN, [{"eventSeverity", ?ES_WARNING} | Acc]);
fault([{"ituAlarmEventType", "2"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Communication_System} | Acc]);
fault([{"ituAlarmEventType", "3"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Quality_Of_Service_Alarm} | Acc]);
fault([{"ituAlarmEventType", "4"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Processing_Error} | Acc]);
fault([{"ituAlarmEventType", "5"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Equipment_Alarm} | Acc]);
fault([{"ituAlarmEventType", "6"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Environmental_Alarm} | Acc]);
fault([{"ituAlarmEventType", "7"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Integrity_Violation} | Acc]);
fault([{"ituAlarmEventType", "8"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Operational_Violation} | Acc]);
fault([{"ituAlarmEventType", "9"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Physical_Violation} | Acc]);
fault([{"ituAlarmEventType", "10"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Security_Service_Or_Mechanism_Violation} | Acc]);
fault([{"ituAlarmEventType", "11"} | T], EN, Acc) ->
	fault(T, EN, [{"eventType", ?ET_Time_Domain_Violation} | Acc]);
fault([{"ituAlarmAdditionalText", Value} | T], EN, Acc)
		when is_list(Value), length(Value) > 0 ->
	fault(T, EN, [{"additionalText", Value} | Acc]);
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
		Result :: fault | other.
%% @doc Check the domain of the event.
domain([_TimeTicks, {varbind, [1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0] , _, TrapName, _} | _T]) ->
	domain1(snmp_collector_utils:oid_to_name(TrapName)).
%% @hidden
domain1("alarmActiveState") ->
	fault;
domain1("alarmClearState") ->
	fault;
domain1(_Other) ->
	other.

-spec probable_cause(ProbableCauseCode) -> Result
	when
		ProbableCauseCode :: string(),
		Result :: ProbableCause | ok,
		ProbableCause :: string().
%% @doc Look up a probable cause.
probable_cause("1") ->
	?PC_Alarm_Indication_Signal;
probable_cause("2") ->
	?PC_Call_Setup_Failure;
probable_cause("3") ->
	?PC_Degraded_Signal;
probable_cause("4") ->
	?PC_FERF;
probable_cause("5") ->
	?PC_Framing_Error;
probable_cause("6") ->
	?PC_LOF;
probable_cause("7") ->
	?PC_LOP;
probable_cause("8") ->
	?PC_LOS;
probable_cause("9") ->
	?PC_Payload_Type_Mismatch;
probable_cause("10") ->
	?PC_Transmission_Error;
probable_cause("11") ->
	?PC_Remote_Alarm_Interface;
probable_cause("12") ->
	?PC_Excessive_Error_Rate;
probable_cause("13") ->
	?PC_Path_Trace_Mismatch;
probable_cause("14") ->
	?PC_Unavailable;
probable_cause("15") ->
	?PC_Signal_Label_Mismatch;
probable_cause("16") ->
	?PC_Loss_Of_Multi_Frame;
probable_cause("17") ->
	?PC_Communications_Receive_Failure;
probable_cause("18") ->
	?PC_Communications_Transmit_Failure;
probable_cause("19") ->
	?PC_Modulaion_Failure;
probable_cause("20") ->
	?PC_Demodulation_Failure;
probable_cause("21") ->
	?PC_Broadcast_Channel_Failure;
probable_cause("22") ->
	?PC_Connection_Establishment_Error;
probable_cause("23") ->
	?PC_Invalid_Message_Received;
probable_cause("24") ->
	?PC_Local_Node_Transmission_Error;
probable_cause("25") ->
	?PC_Remote_Node_Transmission_Error;
probable_cause("26") ->
	?PC_Routing_Failure;
probable_cause("51") ->
	?PC_Back_Plane_Failure;
probable_cause("52") ->
	?PC_Data_Set_Problem;
probable_cause("53") ->
	?PC_Equipment_Identifier_Duplication;
probable_cause("54") ->
	?PC_External_If_Device_Problem;
probable_cause("55") ->
	?PC_Line_Card_Problem;
probable_cause("56") ->
	?PC_Multiplexer_Problem;
probable_cause("57") ->
	?PC_NE_Identifier_Duplication;
probable_cause("58") ->
	?PC_Power_Problem;
probable_cause("59") ->
	?PC_Processor_Problem;
probable_cause("60") ->
	?PC_Protection_Path_Failure;
probable_cause("61") ->
	?PC_Receiver_Failure;
probable_cause("62") ->
	?PC_Replaceable_Unit_Missing;
probable_cause("63") ->
	?PC_Replaceable_Unit_Type_Mismatch;
probable_cause("64") ->
	?PC_Synchronization_Source_Mismatch;
probable_cause("65") ->
	?PC_Terminal_Problem;
probable_cause("66") ->
	?PC_Timing_Problem;
probable_cause("67") ->
	?PC_Transmitter_Failure;
probable_cause("68") ->
	?PC_Trunk_Card_Problem;
probable_cause("69") ->
	?PC_Replaceable_Unit_Problem;
probable_cause("70") ->
	?PC_Real_Time_Clock_Failure;
probable_cause("71") ->
	?PC_Antenna_Failure;
probable_cause("72") ->
	?PC_Battery_Charging_Failure;
probable_cause("73") ->
	?PC_Disk_Failure;
probable_cause("74") ->
	?PC_Frequency_Hopping_Failure;
probable_cause("75") ->
	?PC_Input_Output_Device_Error;
probable_cause("76") ->
	?PC_Loss_Of_Synchronization;
probable_cause("77") ->
	?PC_Loss_Of_Redundancy;
probable_cause("78") ->
	?PC_Power_Supply_Failure;
probable_cause("79") ->
	?PC_Signal_Quality_Evaluation_Failure;
probable_cause("80") ->
	?PC_Transceiver_Failure;
probable_cause("81") ->
	?PC_Protection_Mechanism_Failure;
probable_cause("82") ->
	?PC_Protecting_Resource_Failure;
probable_cause("101") ->
	?PC_Air_Compressor_Failure;
probable_cause("102") ->
	?PC_Air_Conditioning_Failure;
probable_cause("103") ->
	?PC_Air_Dryer_Failure;
probable_cause("104") ->
	?PC_Battery_Discharging;
probable_cause("105") ->
	?PC_Battery_Failure;
probable_cause("106") ->
	?PC_Commercial_Power_Failure;
probable_cause("107") ->
	?PC_Cooling_Fan_Failure;
probable_cause("108") ->
	?PC_Engine_Failure;
probable_cause("109") ->
	?PC_Fire_Detector_Failure;
probable_cause("110") ->
	?PC_Fuse_Failure;
probable_cause("111") ->
	?PC_Generator_Failure;
probable_cause("112") ->
	?PC_Low_Battery_Threshold;
probable_cause("113") ->
	?PC_Pump_Failure;
probable_cause("114") ->
	?PC_Rectifier_Failure;
probable_cause("115") ->
	?PC_Rectifier_High_Voltage;
probable_cause("116") ->
	?PC_Rectifier_Low_Voltage;
probable_cause("117") ->
	?PC_Ventilation_System_Failure;
probable_cause("118") ->
	?PC_Enclosure_Door_Open;
probable_cause("119") ->
	?PC_Explosive_Gas;
probable_cause("120") ->
	?PC_Fire;
probable_cause("121") ->
	?PC_Flood;
probable_cause("122") ->
	?PC_High_Humidity;
probable_cause("123") ->
	?PC_High_Temperature;
probable_cause("124") ->
	?PC_High_Wind;
probable_cause("125") ->
	?PC_Ice_Build_Up;
probable_cause("126") ->
	?PC_Intrusion_Detection;
probable_cause("127") ->
	?PC_Low_Fuel;
probable_cause("128") ->
	?PC_Low_Humidity;
probable_cause("129") ->
	?PC_Low_Cable_Pressure;
probable_cause("130") ->
	?PC_Low_Temperature;
probable_cause("131") ->
	?PC_Low_Water;
probable_cause("132") ->
	?PC_Smoke;
probable_cause("133") ->
	?PC_Toxic_Gas;
probable_cause("134") ->
	?PC_Cooling_System_Failure;
probable_cause("135") ->
	?PC_External_Equipment_Failure;
probable_cause("136") ->
	?PC_External_Point_Failure;
probable_cause("151") ->
	?PC_Storage_Capacity_Problem;
probable_cause("152") ->
	?PC_Memory_Mismatch;
probable_cause("153") ->
	?PC_Corrupt_Data;
probable_cause("154") ->
	?PC_Out_Of_CPU_Cycles;
probable_cause("155") ->
	?PC_Software_Environment_Problem;
probable_cause("156") ->
	?PC_Software_Download_Failure;
probable_cause("157") ->
	?PC_Loss_Of_Real_Time;
probable_cause("158") ->
	?PC_Reinitialized;
probable_cause("159") ->
	?PC_Application_Subsystem_Failure;
probable_cause("160") ->
	?PC_Configuration_Or_Customization_Error;
probable_cause("161") ->
	?PC_Database_Inconsistency;
probable_cause("162") ->
	?PC_File_Error;
probable_cause("163") ->
	?PC_Out_Of_Memory;
probable_cause("164") ->
	?PC_Software_Error;
probable_cause("165") ->
	?PC_Timeout_Expired;
probable_cause("166") ->
	?PC_Underlying_Resource_Unavailable;
probable_cause("167") ->
	?PC_Version_Mismatch;
probable_cause("201") ->
	?PC_Bandwidth_Reduced;
probable_cause("202") ->
	?PC_Congestion;
probable_cause("203") ->
	?PC_Excessive_Error_Rate;
probable_cause("204") ->
	?PC_Excessive_Rresponse_Time;
probable_cause("205") ->
	?PC_Excessive_Retransmission_Rate;
probable_cause("206") ->
	?PC_Reduced_Logging_Capability;
probable_cause("207") ->
	?PC_System_Resources_Overload;
probable_cause("500") ->
	?PC_Adapter_Error;
probable_cause("501") ->
	?PC_Application_Subsystem_Failure;
probable_cause("502") ->
	?PC_Bandwidth_Reduced;
probable_cause("503") ->
	?PC_Call_Establishment_Error;
probable_cause("504") ->
	?PC_Communication_Protocol_Error;
probable_cause("505") ->
	?PC_Communication_Subsystem_Failure;
probable_cause("506") ->
	?PC_Configuration_Or_Customization_Error;
probable_cause("507") ->
	?PC_Congestion;
probable_cause("508") ->
	?PC_Corrupt_Data;
probable_cause("509") ->
	?PC_CPU_Cycles_Limit_Exceeded;
probable_cause("510") ->
	?PC_Data_Set_Or_Modem_Error;
probable_cause("511") ->
	?PC_Degraded_Signal;
probable_cause("512") ->
	?PC_DTE_DCE_Interface_Error;
probable_cause("513") ->
	?PC_Enclosure_Door_Open;
probable_cause("514") ->
	?PC_Equipment_Malfunction;
probable_cause("515") ->
	?PC_Excessive_Vibration;
probable_cause("516") ->
	?PC_File_Error;
probable_cause("517") ->
	?PC_Fire_Detected;
probable_cause("518") ->
	?PC_Framing_Error;
probable_cause("519") ->
	?PC_HOVOCP;
probable_cause("520") ->
	?PC_Humidity_Unacceptable;
probable_cause("521") ->
	?PC_Input_Output_Device_Error;
probable_cause("522") ->
	?PC_Input_Device_Error;
probable_cause("523") ->
	?PC_LAN_Error;
probable_cause("524") ->
	?PC_Leak_Detection;
probable_cause("525") ->
	?PC_Local_Node_Transmission_Error;
probable_cause("526") ->
	?PC_LOF;
probable_cause("527") ->
	?PC_LOS;
probable_cause("528") ->
	?PC_Material_Supply_Exhausted;
probable_cause("529") ->
	?PC_Multiplexer_Problem;
probable_cause("530") ->
	?PC_Out_Of_Memory;
probable_cause("531") ->
	?PC_Output_Device_Error;
probable_cause("532") ->
	?PC_Performance_Degraded;
probable_cause("533") ->
	?PC_Power_Problem;
probable_cause("534") ->
	?PC_Pressure_Unacceptable;
probable_cause("535") ->
	?PC_Processor_Problem;
probable_cause("536") ->
	?PC_Pump_Failure;
probable_cause("537") ->
	?PC_Queue_Size_Exceeded;
probable_cause("538") ->
	?PC_Receive_Failure;
probable_cause("539") ->
	?PC_Receiver_Failure;
probable_cause("540") ->
	?PC_Remote_Node_Transmission_Error;
probable_cause("541") ->
	?PC_Resource_at_or_Nearing_Capacity;
probable_cause("542") ->
	?PC_Excessive_Rresponse_Time;
probable_cause("543") ->
	?PC_Excessive_Retransmission_Rate;
probable_cause("544") ->
	?PC_Software_Error;
probable_cause("545") ->
	?PC_Software_Program_Abnormally_Terminated;
probable_cause("546") ->
	?PC_Software_Program_Error;
probable_cause("547") ->
	?PC_Storage_Capacity_Problem;
probable_cause("548") ->
	?PC_Temperature_Unacceptable;
probable_cause("549") ->
	?PC_Threshold_Crossed;
probable_cause("550") ->
	?PC_Timing_Problem;
probable_cause("551") ->
	?PC_Toxic_Leak_Detected;
probable_cause("552") ->
	?PC_Transmit_Failure;
probable_cause("553") ->
	?PC_Transmitter_Failure;
probable_cause("554") ->
	?PC_Underlying_Resource_Unavailable;
probable_cause("555") ->
	?PC_Version_Mismatch;
probable_cause("600") ->
	?PC_Authentication_Failure;
probable_cause("601") ->
	?PC_Breach_Of_Confidentiality;
probable_cause("602") ->
	?PC_Cable_Tamper;
probable_cause("603") ->
	?PC_Delayed_Information;
probable_cause("604") ->
	?PC_Denial_Of_Service;
probable_cause("605") ->
	?PC_Duplicate_Information;
probable_cause("606") ->
	?PC_Info_Missing;
probable_cause("607") ->
	?PC_Info_Mod_Detected;
probable_cause("608") ->
	?PC_Info_Out_Of_Sequence;
probable_cause("609") ->
	?PC_Key_Expired;
probable_cause("610") ->
	?PC_Non_Repudiation_Failure;
probable_cause("611") ->
	?PC_Out_Of_Hours_Activity;
probable_cause("612") ->
	?PC_Out_Of_Service;
probable_cause("613") ->
	?PC_Procedural_Error;
probable_cause("614") ->
	?PC_Unauthorized_Access_Attempt;
probable_cause("615") ->
	?PC_Unexpected_Info;
probable_cause("1024") ->
	?PC_Indeterminate;
probable_cause(ProbableCauseCode) ->
	error_logger:info_report(["SNMP Manager Unrecognized Probable Cause",
			{probableCause, ProbableCauseCode},
			{module, ?MODULE}]),
	ProbableCauseCode.

