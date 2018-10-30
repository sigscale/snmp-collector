%%% snmp_collector_zte_trap.erl
%%% vim: ts=3
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% @copyright 2016 - 2017 SigScale Global Inc.
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
-module(snmp_collector_zte_trap).
-copyright('Copyright (c) 2016 - 2017 SigScale Global Inc.').

-behaviour(snmpm_user).

-export([handle_error/3, handle_agent/5,
    handle_pdu/4, handle_trap/3, handle_inform/3,
    handle_report/3]).

-include_lib("sigscale_fm/include/fm.hrl").

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
					FieldData = snmp_collector_utils:map_names_values(Objects, []),
					FaultFields = snmp_collector_utils:fault_fields(FieldData, EventDetails),
					CommentEventHeader = snmp_collector_utils:event_header(TargetName, EventDetails),
					case snmp_collector_utils:log_to_disk(CommentEventHeader, FaultFields) of
					ok ->
						ok;
%						ID = {entity_name(TargetName), get_values(eventName, EventDetails)},
%						Alarm = #alarm{id = ID,
%						event_id = get_values(eventId, EventDetails),
%						source_id = get_values(sourceId, EventDetails),
%						fault_fields = FaultFields},
%						case get_values(eventStatus, EventDetails) of
%						Value when Value == "cleared" ->
%							fm:delete_alarm(ID);
%						Value when Value == "uncleared" ->
%							fm:update_alarm(Alarm, get_values(raisedTime, EventDetails),
%									FaultFields);
%						Value when Value == "" ->
%							ignore
%						end;
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
					FieldData = snmp_collector_utils:map_names_values(Objects, []),
					FaultFields = snmp_collector_utils:fault_fields(FieldData, EventDetails),
					CommentEventHeader = snmp_collector_utils:event_header(TargetName, EventDetails),
					case snmp_collector_utils:log_to_disk(CommentEventHeader, FaultFields) of
					ok ->
						ok;
%						ID = {entity_name(TargetName), get_values(eventName, EventDetails)},
%						Alarm = #alarm{id = ID,
%						event_id = get_values(eventId, EventDetails),
%						source_id = get_values(sourceId, EventDetails),
%						fault_fields = FaultFields},
%						case get_values(eventStatus, EventDetails) of
%						Value when Value == "cleared" ->
%							fm:delete_alarm(ID);
%						Value when Value == "uncleared" ->
%							fm:update_alarm(Alarm, get_values(raisedTime, EventDetails),
%									FaultFields);
%						Value when Value == "" ->
%							ignore
%						end;
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
	snmp_collector_snmpm_user_default:handle_inform(TargetName, SnmpInform, UserData).

-spec handle_report(TargetName, SnmpReport, UserData) -> Reply
	when
		TargetName :: snmpm:target_name(),
		SnmpReport :: snmpm:snmp_gen_info(),
		UserData :: term(),
		Reply :: ignore.
%% @doc Handle a report message.
%% @private
handle_report(TargetName, SnmpReport, UserData) ->
	snmp_collector_snmpm_user_default:handle_report(TargetName, SnmpReport, UserData).

%%----------------------------------------------------------------------
%%  The internal functions
%%----------------------------------------------------------------------

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
	case lists:keytake("alarmNeIP", 1,
			NameValuePair) of
		{value, {_, Value}, Objects} ->
			event_details1(Objects, [ {sourceId, Value} | Acc]);
		false ->
			event_details1(NameValuePair, Acc)
	end.
%% @hidden
event_details1(Objects, Acc) ->
	case lists:keytake("alarmManagedObjectInstanceName", 1,
			Objects) of
		{value, {_, Value}, Objects1} ->
			event_details2(Objects1, [ {sourceName, Value} | Acc]);
		false ->
			event_details2(Objects, Acc)
	end.
%% @hidden
event_details2(Objects, Acc) ->
	case lists:keytake("systemDN", 1,
			Objects) of
		{value, {_, Value}, Objects2} ->
			event_details3(Objects2, [ {eventName, Value} | Acc]);
		false ->
			event_details3(Objects, Acc)
	end.
%% @hidden
event_details3(Objects, Acc) ->
	case lists:keytake("alarmSpecificProblem", 1,
			Objects) of
		{value, {_, Value}, Objects3} ->
			event_details4(Objects3, [ {specificProblem, Value} | Acc]);
		false ->
			event_details4(Objects, Acc)
	end.
%% @hidden
event_details4(Objects, Acc) ->
	case lists:keytake("alarmNetype", 1,
			Objects) of
		{value, {_, Value}, Objects4} ->
			event_details5(Objects4, [ {eventSourceType, Value} | Acc]);
		false ->
			event_details5(Objects, Acc)
	end.
%% @hidden
event_details5(Objects, Acc) ->
	case lists:keytake("alarmPerceivedSeverity", 1,
			Objects) of
		{value, {_, Value}, Objects5} ->
			event_details6(Objects5, [ {eventSeverity , Value} | Acc]);
		false ->
			event_details6(Objects, Acc)
	end.
%% @hidden
event_details6(Objects, Acc) ->
	case lists:keytake("alarmEventType", 1,
			Objects) of
		{value, {_, Value}, Objects6} ->
			event_details7(Objects6, [ {alarmCondtion, Value} | Acc]);
		false ->
			event_details7(Objects, Acc)
	end.
%% @hidden
event_details7(Objects, Acc) ->
	case lists:keyfind("snmpTrapOID", 1,
			Objects) of
		{_, Value} when Value == "1" ->
			event_details8(Objects, [ {eventStatus, "cleared"} | Acc]);
		{_, Value} when Value == "2" ->
			event_details8(Objects, [ {eventStatus, "uncleared"} | Acc]);
		false ->
			event_details8(Objects, Acc)
	end.
%% @hidden
event_details8(Objects, Acc) ->
	case lists:keyfind("alarmEventTime", 1,
			Objects) of
		{_, Value} ->
			event_details9(Objects, [ {raisedTime, Value} | Acc]);
		false ->
			event_details9(Objects, Acc)
	end.
%% @hidden
event_details9(NewObjects, Acc) ->
	{ok, NewObjects, Acc}.

-spec heartbeat(Varbinds) -> Result
	when
		Varbinds :: [Varbinds],
		Result :: true | false.
%% @doc Verify if the event is a HeartBeat event or not.
heartbeat(Varbinds) ->
	case snmpm:name_to_oid(csIRPHeartbeatPeriod) of
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

-spec oid_to_name(OIDsValues, Acc) -> Result
	when
		OIDsValues :: [{OID, Value}],
		Acc :: [],
		OID :: list(),
		Value :: string() | integer(),
		Result :: [{Name, Value}],
		Name :: string().
%% @doc Convert OIDs to valid names.
oid_to_name([{OID, Value} | T], Acc) ->
	case catch oid_to_name1(OID) of
		Name when is_list(Name) ->
			oid_to_name(T, [{Name, Value} | Acc]);
		{'EXIT', _Reason} ->
			Name = snmp_collector_utils:oid_to_name(OID),
			oid_to_name(T, [{Name, Value} | Acc])
	end;
oid_to_name([], Acc) ->
	NewAcc = lists:reverse(Acc),
	{ok, NewAcc}.
%% @hidden
oid_to_name1([1,3,6,1,4,1,3902,4101,1,3,1,17,_Index]) ->
	"alarmNeIP";
oid_to_name1([1,3,6,1,4,1,3902,4101,1,3,1,15,_Index]) ->
	"alarmManagedObjectInstanceName";
oid_to_name1([1,3,6,1,4,1,3902,4101,1,1,3]) ->
	"systemDN";
oid_to_name1([1,3,6,1,4,1,3902,4101,1,3,1,8]) ->
	"alarmSpecificProblem";
oid_to_name1([1,3,6,1,4,1,3902,4101,1,3,1,12,_Index]) ->
	"alarmNetype";
oid_to_name1([1,3,6,1,4,1,3902,4101,1,3,1,7,_Index]) ->
	"alarmPerceivedSeverity";
oid_to_name1([1,3,6,1,4,1,3902,4101,1,3,1,5,_Index]) ->
	"alarmEventType";
oid_to_name1([1,3,6,1,6,3,1,1,4,1]) ->
	"snmpTrapOID";
oid_to_name1([1,3,6,1,4,1,3902,4101,1,3,1,4,_Index]) ->
	"alarmEventTime".

