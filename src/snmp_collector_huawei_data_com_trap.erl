%%% snmp_collector_huawei_data_com_trap.erl
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
-module(snmp_collector_huawei_data_com_trap).
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
			case snmp_collector_utils:create_pairs(Varbinds) of
				{ok, Pairs} ->
					{ok, OIDsValues} = snmp_collector_utils:arrange_list(Pairs, []),
					{ok, NewOIDsValues} = oid_to_name(OIDsValues, []),
					{ok, Objects, EventDetails} = event_details(NewOIDsValues, []),
					{ok, AdditionalInformation} = snmp_collector_utils:map_names_values(Objects, []),
					NormalizedAdditionalInfo = additional_information(AdditionalInformation),
					FaultFields = snmp_collector_utils:fault_fields(NormalizedAdditionalInfo, EventDetails),
					CommentEventHeader = snmp_collector_utils:event_header(TargetName, EventDetails),
					case snmp_collector_utils:log_events(CommentEventHeader, FaultFields) of
					ok ->
						ignore;
					{error, _Reason} ->
						ignore
				end,
				ignore
			end
	end;
handle_trap(TargetName, {_Enteprise, _Generic, _Spec, _Timestamp, Varbinds}, _UserData) ->
	case heartbeat(Varbinds) of
		true ->
			ignore;
		false ->
			case snmp_collector_utils:create_pairs(Varbinds) of
				{ok, Pairs} ->
					{ok, OIDsValues} = snmp_collector_utils:arrange_list(Pairs, []),
					{ok, NewOIDsValues} = oid_to_name(OIDsValues, []),
					{ok, Objects, EventDetails} = event_details(NewOIDsValues, []),
					{ok, AdditionalInformation} = snmp_collector_utils:map_names_values(Objects, []),
					NormalizedAdditionalInfo = additional_information(AdditionalInformation),
					FaultFields = snmp_collector_utils:fault_fields(NormalizedAdditionalInfo, EventDetails),
					CommentEventHeader = snmp_collector_utils:event_header(TargetName, EventDetails),
					case snmp_collector_utils:log_events(CommentEventHeader, FaultFields) of
					ok ->
						ignore;
					{error, _Reason} ->
						ignore
				end,
				ignore
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

-spec oid_to_name(OIDsValues, Acc) -> Result
	when
		OIDsValues :: [{OID, Value}],
		Acc :: list(),
		OID :: list(),
		Value :: string() | integer(),
		Result :: {ok, [{Name, Value}]},
		Name :: string().
%% @doc Convert OIDs to valid names.
oid_to_name([{OID, Value} | T], Acc) ->
	Name = snmp_collector_utils:oid_to_name(OID),
	oid_to_name(T, [{Name, Value} | Acc]);
oid_to_name([], Acc) ->
	NewAcc = lists:reverse(Acc),
	{ok, NewAcc}.

-spec event_details(NameValuePair, Acc) -> Result
	when
		NameValuePair :: [{Name, Value}],
		Name :: string(),
		Value :: term(),
		Result :: {ok, NewObjects, Acc},
		NewObjects :: [{Name, Value}],
		Acc :: list().
%% @doc Turn the list of names and values into a map format.
%% @hidden
event_details(NameValuePair, Acc) ->
	case lists:keytake("hwNmNorthboundSerialNo", 1,
			NameValuePair) of
		{value, {_, Value}, Objects} ->
			event_details1(Objects, [ {sourceId, Value} | Acc]);
		false ->
			event_details1(NameValuePair, Acc)
	end.
%% @hidden
event_details1(Objects, Acc) ->
	case lists:keytake("hwNmNorthboundNEName", 1,
			Objects) of
		{value, {_, Value}, Objects1} ->
			event_details2(Objects1, [ {sourceName, Value} | Acc]);
		false ->
			event_details2(Objects, Acc)
	end.
%% @hidden
event_details2(Objects, Acc) ->
	case lists:keytake("hwNmNorthboundEventName", 1,
			Objects) of
		{value, {_, Value}, Objects2} ->
			event_details3(Objects2, [ {eventName, Value} | Acc]);
		false ->
			event_details3(Objects, Acc)
	end.
%% @hidden
event_details3(Objects, Acc) ->
	case lists:keytake("hwNmNorthboundEventDetail", 1,
			Objects) of
		{value, {_, Value}, Objects3} ->
			event_details4(Objects3, [ {specificProblem, Value} | Acc]);
		false ->
			event_details4(Objects, Acc)
	end.
%% @hidden
event_details4(Objects, Acc) ->
	case lists:keytake("hwNmNorthboundDeviceType", 1,
			Objects) of
		{value, {_, Value}, Objects4} ->
			event_details5(Objects4, [ {eventSourceType, Value} | Acc]);
		false ->
			event_details5(Objects, Acc)
	end.
%% @hidden
event_details5(Objects, Acc) ->
	case lists:keytake("hwNmNorthboundSeverity", 1,
			Objects) of
		{value, {_, Value}, Objects5} when Value == "Critical" ->
			event_details6(Objects5, [ {eventSeverity, "CRITICAL"} | Acc]);
		{value, {_, Value}, Objects5} when Value == "Major" ->
			event_details6(Objects5, [ {eventSeverity, "MAJOR"} | Acc]);
		{value, {_, Value}, Objects5} when Value == "Minor" ->
			event_details6(Objects5, [ {eventSeverity, "MINOR"} | Acc]);
		{value, {_, Value}, Objects5} when Value == "Warning" ->
			event_details6(Objects5, [ {eventSeverity, "WARNING"} | Acc]);
		{value, {_, Value}, Objects5} when Value == "Indeterminate" ->
			event_details6(Objects5, Acc);
		false ->
			event_details6(Objects, Acc)
	end.
%% @hidden
event_details6(Objects, Acc) ->
	case lists:keytake("hwNmNorthboundFaultFlag", 1,
			Objects) of
		{value, {_, Value}, Objects6} when Value == "Fault" ->
			event_details7(Objects6, [ {eventCategory, "fault"} | Acc]);
		{value, {_, Value}, Objects6} when Value == "Event" ->
			event_details7(Objects6, [ {eventCategory, "event"} | Acc]);
		{value, {_, Value}, Objects6} when Value == "Acknowledge" ->
			event_details7(Objects6, [ {eventCategory, "acknowledge"} | Acc]);
		{value, {_, Value}, Objects6} when Value == "Unacknowledge" ->
			event_details7(Objects6, [ {eventCategory, unacknowledge} | Acc]);
		{value, {_, Value}, Objects6} when Value == "Change" ->
			event_details7(Objects6, [ {eventCategory, "changed"} | Acc]);
		{value, {_, Value}, Objects6} when Value == "Recovery" ->
			event_details7(Objects6, [ {eventCategory, "recovery"} | Acc]);
		false ->
			event_details7(Objects, Acc)
	end.
%% @hidden
event_details7(Objects, Acc) ->
	case lists:keytake("", 1,
			Objects) of
		{value, {_, Value}, Objects7} ->
			event_details8(Objects7, [ {alarmCondtion, Value} | Acc]);
		false ->
			event_details8(Objects, Acc)
	end.
%% @hidden
event_details8(Objects, Acc) ->
	case lists:keyfind("hwNmNorthboundRestoreStatus", 1,
			Objects) of
		{_, Value} ->
			event_details9(Objects, [ {eventStatus, Value} | Acc]);
		false ->
			event_details9(Objects, Acc)
	end.
%% @hidden
event_details9(Objects, Acc) ->
	case lists:keyfind("hwNmNorthboundEventTime", 1,
			Objects) of
		{_, Value} ->
			event_details10(Objects, [ {raisedTime, Value} | Acc]);
		false ->
			event_details10(Objects, Acc)
	end.
%% @hidden
event_details10(NewObjects, Acc) ->
	{ok, NewObjects, Acc}.

-spec additional_information(AddtionalInformation) -> AddtionalInformation
	when
		AddtionalInformation :: [map()] | [map()].
%% @doc CODEC to normalize name fields.
additional_information(AddtionalInformation) ->
	additional_information1(AddtionalInformation, []).
%% @hidden
additional_information1([#{"name" := Name, "value" := Value} | T], Acc) ->
	[H | T] = string:sub_string(Name, 15),
	NormalizedName = string:to_lower(H) ++ T,
	additional_information1(T, [#{"name" => NormalizedName, "value" => Value} | Acc]);
additional_information1([], Acc) ->
	{ok, Acc}.

-spec heartbeat(Varbinds) -> Result
	when
		Varbinds :: [Varbinds],
		Result :: true | false.
%% @doc Verify if the event is a HeartBeat event or not.
heartbeat(Varbinds) ->
	case snmpm:name_to_oid(hwNmAgent) of
		{ok, [HeartBeat]} ->
			case lists:keyfind(HeartBeat, 2, Varbinds) of
				{varbind, _, _, _, _} ->
					true;
				false ->
					false
			end;
		{error, _Reason} ->
				false
	end.



