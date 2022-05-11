%%% snmp_collector_utils.erl
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
-module(snmp_collector_utils).
-copyright('Copyright (c) 2016 - 2020 SigScale Global Inc.').

-include("snmp_collector.hrl").
-include("snmp_collector_log.hrl").

-export([oid_to_name/1, get_name/1, generate_identity/1,
		arrange_list/1, stringify/1, send_event/1, security_params/7,
		agent_name/1, oids_to_names/2, create_event/3, engine_id/0,
		authenticate_v1_v2/2, update_counters/3, timestamp/0,
		generate_key/3, authenticate_v3/4, strip_target_name/1, fault_fields/1]).

%% support deprecated_time_unit()
-define(MILLISECOND, milli_seconds).
%-define(MILLISECOND, millisecond).
-define(MICROSECOND, micro_seconds).
%-define(MICROSECOND, microsecond).

% calendar:datetime_to_gregorian_seconds({{1970,1,1},{0,0,0}})
-define(EPOCH, 62167219200).

-define(sigscalePEN, 50386).

%%----------------------------------------------------------------------
%%  The snmp_collector_utilites public API
%%----------------------------------------------------------------------

-spec oid_to_name(OID) -> Name
	when
		OID :: snmp:oid(),
		Name :: string().
%% @doc Get a name for an OID.
oid_to_name(OID)
		when is_list(OID) ->
	oid_to_name(OID, lists:reverse(OID), snmpm:oid_to_name(OID)).
%% @hidden
oid_to_name(_OID, [0], {ok, Name}) ->
	lists:flatten(io_lib:fwrite("~s", [Name]));
oid_to_name(_OID, [], {ok, Name}) ->
	lists:flatten(io_lib:fwrite("~s", [Name]));
oid_to_name(OID, T, {ok, Name}) ->
	case lists:sublist(OID, length(T) + 1, length(OID)) of
		[0] ->
			lists:flatten(io_lib:fwrite("~s", [Name]));
		[] ->
			lists:flatten(io_lib:fwrite("~s", [Name]));
		Rest ->
			lists:flatten(io_lib:fwrite("~s.~w", [Name, Rest]))
	end;
oid_to_name(OID, [_H | T], {error, _Reason}) ->
	oid_to_name(OID, T, snmpm:oid_to_name(lists:reverse(T)));
oid_to_name(OID, [], {error, _Reason}) ->
	lists:flatten(io_lib:fwrite("~p", [OID])).

-spec get_name(Body) -> Name
	when
		Body :: list(),
		Name :: string().
%% @doc Get the name of a MIB from the MIB body.
get_name([H | _] = Body) when H >= $A, H =< $Z ->
	get_name1(Body, []);
get_name([$ | T]) ->
	get_name(T);
get_name([$\t | T]) ->
	get_name(T);
get_name([$\r | T]) ->
	get_name(T);
get_name([$\n | T]) ->
	get_name(T);
get_name([$-, $- | T]) ->
	get_name(skip_to_eol(T)).
get_name1([H | T], Acc) when H >= $A, H =< $Z ->
	get_name1(T, [H | Acc]);
get_name1([H | T], Acc) when H >= $a, H =< $z ->
	get_name1(T, [H | Acc]);
get_name1([H | T], Acc) when H >= $0, H =< $9 ->
	get_name1(T, [H | Acc]);
get_name1([$- | T], Acc) ->
	get_name1(T, [$- | Acc]);
get_name1([$  | T], Acc) ->
	get_name2(T, lists:reverse(Acc)).
%% @hidden
get_name2([$  | T], Name) ->
	get_name2(T, Name);
get_name2([$\t | T], Name) ->
	get_name2(T, Name);
get_name2([$\r | T], Name) ->
	get_name2(T, Name);
get_name2([$\n | T], Name) ->
	get_name2(T, Name);
get_name2("DEFINITIONS " ++ _,  Name) ->
	Name.

%% @hidden
skip_to_eol([$\n | T]) ->
	T;
skip_to_eol([_ | T]) ->
	skip_to_eol(T).

-spec generate_identity(Length) -> string()
	when
		Length :: pos_integer().
%% @doc Generate a random uniform numeric identity.
%% @private
generate_identity(Length) when Length > 0 ->
	Charset = lists:seq($0, $9),
	NumChars = length(Charset),
	Random = crypto:strong_rand_bytes(Length),
	generate_identity(Random, Charset, NumChars,[]).
%% @hidden
generate_identity(<<N, Rest/binary>>, Charset, NumChars, Acc) ->
	CharNum = (N rem NumChars) + 1,
	NewAcc = [lists:nth(CharNum, Charset) | Acc],
	generate_identity(Rest, Charset, NumChars, NewAcc);
generate_identity(<<>>, _Charset, _NumChars, Acc) ->
	Acc.

-spec create_event(TargetName, AlarmDetails, Domain) -> Result
	when
		TargetName :: list(),
		AlarmDetails :: [{Name, Value}],
		Domain :: fault | syslog | notification | heartbeat,
		Name :: list(),
		Value :: list(),
		Result :: fault_event().
%% @doc Generate the Common event header and Fault Fields maps.
create_event(TargetName, AlarmDetails, fault) ->
	{CommonEventHeader, Remainder} = common_event_header(TargetName, AlarmDetails, "fault"),
	FaultFields = fault_fields(Remainder),
	{NewCommonEventHeader, NewFaultFields} = check_fields(CommonEventHeader, FaultFields),
	create_event1(NewCommonEventHeader, NewFaultFields);
create_event(TargetName, AlarmDetails, syslog) ->
	{CommonEventHeader, Remainder} = common_event_header(TargetName, AlarmDetails, "syslog"),
	SyslogFields = syslog_fields(Remainder),
	{NewCommonEventHeader, _} = check_fields(CommonEventHeader, #{}),
	create_event1(NewCommonEventHeader, SyslogFields);
create_event(TargetName, AlarmDetails, notification) ->
	{CommonEventHeader, Remainder} = common_event_header(TargetName, AlarmDetails, "notification"),
	NotificationFields = notification_fields(Remainder),
	{NewCommonEventHeader, _} = check_fields(CommonEventHeader, #{}),
	create_event1(NewCommonEventHeader, NotificationFields);
create_event(TargetName, AlarmDetails, heartbeat) ->
	{CommonEventHeader, Remainder} = common_event_header(TargetName, AlarmDetails, "heartbeat"),
	NotificationFields = heartbeat_fields(Remainder),
	create_event1(CommonEventHeader, NotificationFields).
%% @hidden
create_event1(#{"startEpochMicrosec" := _,
		"lastEpochMicrosec" := _} = CommonEventHeader, OtherFields) ->
	TS = timestamp(),
	N = erlang:unique_integer([positive]),
	EventId = integer_to_list(TS) ++ "-" ++ integer_to_list(N),
	{TS, N, node(), CommonEventHeader#{"eventId" => EventId}, OtherFields};
create_event1(#{"eventName" := ?EN_NEW,
		"lastEpochMicrosec" := Last} = CommonEventHeader, OtherFields) ->
	TS = timestamp(),
	N = erlang:unique_integer([positive]),
	EventId = integer_to_list(TS) ++ "-" ++ integer_to_list(N),
	{TS, N, node(), CommonEventHeader#{"eventId" => EventId,
			"startEpochMicrosec" => Last}, OtherFields};
create_event1(#{"eventName" := ?EN_NEW,
		"startEpochMicrosec" := Start} = CommonEventHeader, OtherFields) ->
	TS = timestamp(),
	N = erlang:unique_integer([positive]),
	EventId = integer_to_list(TS) ++ "-" ++ integer_to_list(N),
	{TS, N, node(), CommonEventHeader#{"eventId" => EventId,
			"lastEpochMicrosec" => Start}, OtherFields};
create_event1(#{"eventName" := ?EN_NEW} = CommonEventHeader, OtherFields) ->
	TS = timestamp(),
	N = erlang:unique_integer([positive]),
	EventId = integer_to_list(TS) ++ "-" ++ integer_to_list(N),
	{TS, N, node(), CommonEventHeader#{"eventId" => EventId,
			"startEpochMicrosec" => TS, "lastEpochMicrosec" => TS}, OtherFields};
create_event1(#{"lastEpochMicrosec" := _} = CommonEventHeader, OtherFields) ->
	TS = timestamp(),
	N = erlang:unique_integer([positive]),
	EventId = integer_to_list(TS) ++ "-" ++ integer_to_list(N),
	{TS, N, node(), CommonEventHeader#{"eventId" => EventId}, OtherFields};
create_event1(CommonEventHeader, OtherFields) ->
	TS = timestamp(),
	N = erlang:unique_integer([positive]),
	EventId = integer_to_list(TS) ++ "-" ++ integer_to_list(N),
	{TS, N, node(), CommonEventHeader#{"eventId" => EventId,
			"lastEpochMicrosec" => TS}, OtherFields}.

-spec security_params(EngineID, Address, SecName,
		AuthParams, Packet, AuthPass, PrivPass) -> Result
	when
		EngineID :: string(),
		Address :: inet:ip_address(),
		SecName :: string(),
		AuthParams :: list(),
		Packet :: [byte()],
		AuthPass :: string(),
		PrivPass :: string(),
		Result :: {ok, AuthProtocol, PrivProtocol } | {error, Reason},
		AuthProtocol :: usmNoAuthProtocol | usmHMACMD5AuthProtocol | usmHMACSHAAuthProtocol,
		PrivProtocol :: usmNoPrivProtocol | usmDESPrivProtocol | usmAesCfb128Protocol,
		Reason :: not_found | authentication_failed | term().
%% @doc Looks up the Authentication Protocol and the Privacy Protocol to complete authentication.
%% @private
security_params(EngineID, Address, SecName, AuthParms, Packet, AuthPass, PrivPass)
		when is_list(EngineID), is_list(SecName) ->
	case agent_name(Address) of
		{_, TargetName, SecurityModel} when is_list(TargetName), SecurityModel == any;
				SecurityModel == 3 ->
			case ets:lookup(snmpm_usm_table, {usmUserTable, EngineID, SecName}) of
				[{_, {usm_user, _, _, _, AuthProtocol, _, PrivProtocol, _}}] ->
					AuthKey = generate_key(AuthProtocol, AuthPass, EngineID),
					case authenticate_v3(AuthProtocol, AuthKey, AuthParms, Packet) of
						true ->
							{ok, AuthProtocol, PrivProtocol};
						false ->
							{error, authentication_failed}
					end;
				[] ->
					security_params1(EngineID, TargetName, SecName, AuthParms,
							Packet, AuthPass, PrivPass)
			end;
		{error, Reason} ->
			{error, Reason}
	end.
%% @hidden
security_params1(EngineID, TargetName, SecName, AuthParms, Packet, AuthPass, PrivPass)
		when is_list(EngineID), is_list(SecName) ->
	case ets:match(snmpm_usm_table, {{usmUserTable, '_', TargetName},
			{usm_user, '_', TargetName, SecName, '$1', '_', '$2', '_'}}) of
		[[AuthProtocol, PrivProtocol]] ->
			AuthKey = generate_key(AuthProtocol, AuthPass, EngineID),
			case authenticate_v3(AuthProtocol, AuthKey, AuthParms ,Packet) of
				true ->
					case snmp_collector:register_usm_user(EngineID, TargetName, SecName, AuthProtocol,
							PrivProtocol, AuthPass, PrivPass) of
						{usm_user_added, AuthProtocol, PrivProtocol} ->
							{ok, AuthProtocol, PrivProtocol};
						{error, {already_registered, _, _}} ->
							{ok, AuthProtocol, PrivProtocol};
						{error, Reason} ->
							{error, Reason}
					end;
				false ->
					{error, authentication_failed}
			end;
		[[AuthProtocol, PrivProtocol],  _] ->
			AuthKey = generate_key(AuthProtocol, AuthPass, EngineID),
			case authenticate_v3(AuthProtocol, AuthKey, AuthParms ,Packet) of
				true ->
					case snmp_collector:register_usm_user(EngineID, TargetName, SecName, AuthProtocol,
							PrivProtocol, AuthPass, PrivPass) of
						{usm_user_added, AuthProtocol, PrivProtocol} ->
							{ok, AuthProtocol, PrivProtocol};
						{error, {already_registered, _, _}} ->
							{ok, AuthProtocol, PrivProtocol};
						{error, Reason} ->
							{error, Reason}
					end;
				false ->
					{error, authentication_failed}
			end;
		[] ->
			{error, not_found}
	end.

-spec authenticate_v1_v2(Address, Community) -> Result
	when
		Address :: inet:ip_address(),
		Community :: string(),
		Result :: {authenticated, TargetName, AgentName} | {authentication_failed, Reason},
		TargetName :: string(),
		AgentName :: string(),
		Reason :: invalid_community | invalid_security_model.
%% @doc Authenticate SNMPv2 Packets.
authenticate_v1_v2(Address, Community) ->
	case agent_name(Address) of
		{AgentName, TargetName, SecurityModel} when is_list(TargetName), SecurityModel == any;
				SecurityModel == 2 ->
			case ets:lookup(snmpm_agent_table, {TargetName, community}) of
				[{_, Community}] ->
					{authenticated, TargetName, AgentName};
				[] ->
					{authentication_failed, invalid_community}
			end;
		_ ->
			{authentication_failed, invalid_security_model}
	end.

-spec agent_name(Address) -> Result
	when
		Address :: inet:ip_address(),
		Result :: {AgentName, TargetName, SecurityModel} | {error, Reason},
		AgentName :: string(),
		TargetName :: snmpm:target_name(),
		SecurityModel :: any | v1 | v2c | usm,
		Reason :: term().
%% @doc Identify the Agent name and Target Name for the received packet.
agent_name(Address) ->
	case ets:match(snmpm_agent_table, {{'$1', '_'}, {Address ,'_'}}) of
		[[TargetName]] ->
			case ets:match(snmpm_agent_table, {{TargetName, user_id},'$1'}) of
				[[AgentName]] ->
					case ets:match(snmpm_agent_table, {{TargetName, sec_model}, '$1'}) of
						[[SecurityModel]] ->
							{AgentName, TargetName, SecurityModel};
						[] ->
							{error, security_model_not_found}
					end;
				[] ->
					{error, agent_name_not_found}
			end;
		[] ->
			{error, target_name_not_found}
	end.

-spec send_event(Event) -> Result
   when
		Event :: {TS, N, Node, CommonEventHeader, OtherFields},
		TS :: pos_integer(),
		N :: pos_integer(),
		Node :: node(),
		CommonEventHeader :: map(),
		OtherFields :: map(),
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Log and POST the event.
%% @private
send_event({TS, N, Node, CommonEventHeader, OtherFields}) ->
	try
		Event1 = {TS, N, Node, CommonEventHeader, OtherFields},
		gen_event:notify(snmp_collector_event, Event1)
	of
		ok ->
			ok
	catch
		_:Reason ->
			error_logger:info_report(["SNMP Manager Event Logging Failed",
					{reason, Reason}]),
			{error, Reason}
	end.

-spec arrange_list(Varbinds) -> Result
	when
		Varbinds :: [Varbind],
		Varbind :: {varbind, OID, Type, Value, Seqnum},
		OID :: snmp:oid(),
		Type :: 'OCTET STRING' | 'OBJECT IDENTIFIER' | 'INTEGER',
		Value :: string() | atom() | integer(),
		Seqnum :: integer(),
		Result :: {ok ,Acc},
		Acc :: [tuple()].
%% @doc Filter and map the OIDs to names and appropriate values.
%% @private
arrange_list(Varbinds)
		when is_list(Varbinds) ->
	arrange_list(Varbinds, []).
%% @hidden
arrange_list([{varbind, [1,3,6,1,2,1,1,3,0], 'TimeTicks', Value, _Seqnum},
		{varbind, [1,3,6,1,6,3,1,1,4,1,0], _, Value1, _Seqnum1} | T], Acc) ->
	arrange_list(T, [{[1,3,6,1,2,1,1,3,0], Value}, {[1,3,6,1,6,3,1,1,4,1,0], oid_to_name(Value1)} | Acc]);
arrange_list([{varbind, OID, Type, Value, _Seqnum} | T], Acc)
		when Type == 'OCTET STRING', is_list(Value) ->
	case unicode:characters_to_list(Value, utf8) of
		Value2 when is_list(Value2) ->
			arrange_list(T, [{OID, stringify(Value2)} | Acc]);
		{incomplete, Good, Bad} ->
			error_logger:info_report(["Error parsing 'OCTET STRING'",
					{error, incomplete},
					{oid, OID},
					{good, Good},
					{bad, Bad}]),
			arrange_list(T, Acc);
		{error, Good, Bad} ->
			error_logger:info_report(["Error parsing 'OCTET STRING'",
					{oid, OID},
					{good, Good},
					{bad, Bad}]),
			arrange_list(T, Acc)
	end;
arrange_list([{varbind, OID, Type, Value, _Seqnum} | T], Acc)
		when Type == 'OBJECT IDENTIFIER', is_list(Value) ->
	arrange_list(T, [{OID, oid_to_name(Value)} | Acc]);
arrange_list([{varbind, OID, Type, Value, _Seqnum} | T], Acc)
		when Type =='INTEGER', is_integer(Value) ->
	Value2 = integer_to_list(Value),
	arrange_list(T, [{OID, Value2} | Acc]);
arrange_list([_ | T], Acc) ->
	arrange_list(T, Acc);
arrange_list([], Acc) ->
	NewAcc = lists:reverse(Acc),
	{ok ,NewAcc}.

-spec oids_to_names(OIDsValues, Acc) -> Result
	when
		OIDsValues :: [{OID, Value}],
		Acc :: list(),
		OID :: list(),
		Value :: string() | integer(),
		Result :: {ok, [{StrippedName, Value}]},
		StrippedName :: string().
%% @doc Convert OIDs to valid names.
oids_to_names([{OID, Value} | T], Acc)
		when is_list(OID) ->
	Name = oid_to_name(OID),
	oids_to_names(T, [{strip_name(Name), Value} | Acc]);
oids_to_names([], Acc) ->
	NewAcc = lists:reverse(Acc),
	{ok, NewAcc}.

-spec stringify(String) -> String
	when
		String :: string().
%% @doc JSON encode a string.
%% @private
stringify(String) ->
	case io_lib:printable_unicode_list(String) of
		true ->
			String;
		false ->
			case snmp:validate_date_and_time(String) of 
				true ->
					String;
				false ->
					stringify1(String, [])
			end
	end.
%% @hidden
stringify1([$\s | T], Acc) ->
	stringify1(T, [$s, $\\ | Acc]);
stringify1([$\~ | T], Acc) ->
	stringify1(T, [$~, $\\ | Acc]);
stringify1([$\, | T], Acc) ->
	stringify1(T, [$,, $\\ | Acc]);
stringify1([$\b | T], Acc) ->
	stringify1(T, [$b, $\\ | Acc]);
stringify1([$\d | T], Acc) ->
	stringify1(T, [$d, $\\ | Acc]);
stringify1([$\e | T], Acc) ->
	stringify1(T, [$e, $\\ | Acc]);
stringify1([$\f | T], Acc) ->
	stringify1(T, [$f, $\\ | Acc]);
stringify1([$\n | T], Acc) ->
	stringify1(T, [$n, $\\ | Acc]);
stringify1([$\r | T], Acc) ->
	stringify1(T, [$r, $\\ | Acc]);
stringify1([$\t | T], Acc) ->
	stringify1(T, [$t, $\\ | Acc]);
stringify1([$\v | T], Acc) ->
	stringify1(T, [$v, $\\ | Acc]);
stringify1([$\' | T], Acc) ->
	stringify1(T, Acc);
stringify1([$\" | T], Acc) ->
	stringify1(T, Acc);
stringify1([$\\ | T], Acc) ->
	stringify1(T, [$\\, $\\ | Acc]);
stringify1([H | T], Acc) when H < $\s; H > $~ ->
	stringify1(T, [io_lib:fwrite("\\u~4.16.0b", [H]) | Acc]);
stringify1([H | T], Acc) ->
	stringify1(T, [H | Acc]);
stringify1([], Acc) ->
	lists:reverse(Acc).

-spec engine_id() -> EngineID
	when
		EngineID :: [byte()].
%% @doc Create a unique SNMP EngineID for SigScale Enterprise.
%%
%% 	The algorithm in RFC3411 is used to generate a unique value to
%% 	be used as `snmpEngineID' in an `agent.conf' configuration file
%% 	for the OTP SNMP agent.
%%
engine_id() ->
	PEN = binary_to_list(<<1:1, ?sigscalePEN:31>>),
	case inet:getifaddrs() of
		{ok, IfList} ->
			engine_id1(IfList, PEN, []);
		{error, _Reason} ->
			engine_id4(PEN, [])
	end.
%% @hidden
engine_id1([{_, IfOpt} | T], PEN, Acc) ->
	case lists:keyfind(hwaddr, 1, IfOpt) of
		{hwaddr, [0, 0, 0, 0, 0, 0]} ->
			engine_id1(T, PEN, Acc);
		{hwaddr, [255, 255, 255, 255, 255, 255]} ->
			engine_id1(T, PEN, Acc);
		{hwaddr, HwAddr} when length(HwAddr) == 6 ->
			engine_id1(T, PEN, [HwAddr | Acc]);
		false ->
			engine_id1(T, PEN, Acc)
	end;
engine_id1([], PEN, []) ->
	case inet:getifaddrs() of
		{ok, IfList} ->
			engine_id2(IfList, PEN, []);
		{error, _Reason} ->
			engine_id4(PEN, [])
	end;
engine_id1([], PEN, Acc) ->
	[H | _] = lists:sort(Acc),
	PEN ++ [3 | H].
%% @hidden
%% avoid RFC5735 special-use ipv4 addresses
engine_id2([{_, IfOpt} | T], PEN, Acc) ->
	case lists:keyfind(hwaddr, 1, IfOpt) of
		{addr, {N, _, _, _}} when N == 0; N == 10; N == 127 ->
			engine_id2(T, PEN, Acc);
		{addr, {169, 254, _, _}} ->
			engine_id2(T, PEN, Acc);
		{addr, {172, N, _, _}} when N > 15 ->
			engine_id2(T, PEN, Acc);
		{addr, {192, 0, N, _}} when N == 0; N == 2 ->
			engine_id2(T, PEN, Acc);
		{addr, {192, 88, 99, _}} ->
			engine_id2(T, PEN, Acc);
		{addr, {192, 168, _, _}} ->
			engine_id2(T, PEN, Acc);
		{addr, {198, N, _, _}} when N > 253 ->
			engine_id2(T, PEN, Acc);
		{addr, {198, 51, 100, _}} ->
			engine_id2(T, PEN, Acc);
		{addr, {203, 0, 113, _}} ->
			engine_id2(T, PEN, Acc);
		{addr, {N, _, _, _}} when N > 239 ->
			engine_id2(T, PEN, Acc);
		{addr, {A, B, C, D}} ->
			engine_id2(T, PEN, [[A, B, C, D] | Acc]);
		_ ->
			engine_id2(T, PEN, Acc)
	end;
engine_id2([], PEN, []) ->
	case inet:getifaddrs() of
		{ok, IfList} ->
			engine_id3(IfList, PEN, []);
		{error, _Reason} ->
			engine_id4(PEN, [])
	end;
engine_id2([], PEN, Acc) ->
	[H | _] = lists:sort(Acc),
	PEN ++ [1 | H].
%% @hidden
%% avoid RFC5156 special-use ipv6 addresses
engine_id3([{_, IfOpt} | T], PEN, Acc) ->
	case lists:keyfind(hwaddr, 1, IfOpt) of
		{addr, {0, 0, 0, 0, 0, 0, 0, 1}} ->
			engine_id3(T, PEN, Acc);
		{addr, {0, 0, 0, 0, 0, 65535, _, _}} ->
			engine_id3(T, PEN, Acc);
		{addr, {N, _, _, _, _, _, _, _}} when N > 65199, N < 65216 ->
			engine_id3(T, PEN, Acc);
		{addr, {N, _, _, _, _, _, _, _}} when N > 64511, N < 65024 ->
			engine_id3(T, PEN, Acc);
		{addr, {8193, 3512,_, _, _, _, _, _}} ->
			engine_id3(T, PEN, Acc);
		{addr, {8194, _, _, _, _, _, _, _}} ->
			engine_id3(T, PEN, Acc);
		{addr, {8193, 0, _, _, _, _, _, _}} ->
			engine_id3(T, PEN, Acc);
		{addr, {N, _, _, _, _, _, _, _}} when N > 24319; N < 24576 ->
			engine_id3(T, PEN, Acc);
		{addr, {16382, _, _, _, _, _, _, _}} ->
			engine_id3(T, PEN, Acc);
		{addr, {8193, N, _, _, _, _, _, _}} when N > 4095; N < 4112 ->
			engine_id3(T, PEN, Acc);
		{addr, {0, 0, 0, 0, 0, 0, 0, 0}} ->
			engine_id3(T, PEN, Acc);
		{addr, {N, _, _, _, _, _, _, _}} when N > 65279 ->
			engine_id3(T, PEN, Acc);
		{addr, {A, B, C, D, E, F, G, H}} ->
			engine_id3(T, PEN, [[A, B, C, D, E, F, G, H] | Acc]);
		_ ->
			engine_id3(T, PEN, Acc)
	end;
engine_id3([], PEN, []) ->
	engine_id4(PEN, []);
engine_id3([], PEN, Acc) ->
	[H | _] = lists:sort(Acc),
	A = [[N bsr 8, N band 16#00FF] || N <- H],
	PEN ++ [2 | A].
%% @hidden
engine_id4(PEN, Acc) when length(Acc) == 27 ->
	PEN ++ [5 | Acc];
engine_id4(PEN, Acc) ->
	engine_id4(PEN, [rand:uniform(255) | Acc]).

-spec strip_name(Name) -> Name
	when
		Name :: string().
%% @doc Removes the index from required names.
%% @hidden
strip_name(Name) ->
	case string:tokens(Name, ".") of
		[StripedName, _Index] ->
			StripedName;
		[Name] ->
			Name
	end.

-spec timestamp() -> TimeStamp
	when
		TimeStamp :: integer().
%% @doc Create time stamp.
timestamp() ->
	erlang:system_time(?MILLISECOND).

-spec update_counters(AgentName, TargetName, AlarmDetails) -> Result
	when
		AgentName :: atom(),
		TargetName :: string(),
		AlarmDetails :: [tuple()],
		Result :: ok.
%% @doc Update counters for SNMP notifications received
update_counters(AgentName, TargetName,
		[{"eventType", ?ET_Communication_System} | T]) ->
	ets:update_counter(counters, {AgentName, TargetName, communicationsAlarm},
			{2, 1}, {{AgentName, TargetName, communicationsAlarm}, 0}),
	ets:update_counter(counters, {AgentName, communicationsAlarm}, {2, 1},
			{{AgentName, communicationsAlarm}, 0}),
	ets:update_counter(counters, communicationsAlarm, {2, 1}, {communicationsAlarm, 0}),
	update_counters(AgentName, TargetName, T);
update_counters(AgentName, TargetName,
		[{"eventType", ?ET_Processing_Error} | T]) ->
	ets:update_counter(counters, {AgentName, TargetName, processingErrorAlarm}, {2, 1},
			{{AgentName, TargetName, processingErrorAlarm}, 0}),
	ets:update_counter(counters, {AgentName, processingErrorAlarm}, {2, 1},
			{{AgentName, processingErrorAlarm}, 0}),
	ets:update_counter(counters, processingErrorAlarm, {2, 1}, {processingErrorAlarm, 0}),
	update_counters(AgentName, TargetName, T);
update_counters(AgentName, TargetName,
		[{"eventType", ?ET_Environmental_Alarm} | T]) ->
	ets:update_counter(counters, {AgentName, TargetName, environmentalAlarm},
			{2, 1}, {{AgentName, TargetName, environmentalAlarm}, 0}),
	ets:update_counter(counters, {TargetName, environmentalAlarm},
			{2, 1}, {{TargetName, environmentalAlarm}, 0}),
	ets:update_counter(counters, environmentalAlarm, {2, 1}, {environmentalAlarm, 0}),
	update_counters(AgentName, TargetName, T);
update_counters(AgentName, TargetName,
		[{"eventType", ?ET_Quality_Of_Service_Alarm} | T]) ->
	ets:update_counter(counters, {AgentName, TargetName, qualityOfServiceAlarm},
			{2, 1}, {{AgentName, TargetName, qualityOfServiceAlarm}, 0}),
	ets:update_counter(counters, {AgentName, qualityOfServiceAlarm},
			{2, 1}, {{AgentName, qualityOfServiceAlarm}, 0}),
	ets:update_counter(counters, qualityOfServiceAlarm,
			{2, 1}, {qualityOfServiceAlarm, 0}),
	update_counters(AgentName, TargetName, T);
update_counters(AgentName, TargetName,
		[{"eventType", ?ET_Equipment_Alarm} | T]) ->
	ets:update_counter(counters, {AgentName, TargetName, equipmentAlarm},
			{2, 1}, {{AgentName, TargetName, equipmentAlarm}, 0}),
	ets:update_counter(counters, {AgentName,equipmentAlarm},
			{2, 1}, {{AgentName, equipmentAlarm}, 0}),
	ets:update_counter(counters, equipmentAlarm,
			{2, 1}, {equipmentAlarm, 0}),
	update_counters(AgentName, TargetName, T);
update_counters(AgentName, TargetName,
		[{"eventType", ?ET_Integrity_Violation} | T]) ->
	ets:update_counter(counters, {AgentName, TargetName, integrityViolation},
			{2, 1}, {{AgentName, TargetName, integrityViolation}, 0}),
	ets:update_counter(counters, {TargetName, integrityViolation},
			{2, 1}, {{AgentName, integrityViolation}, 0}),
	ets:update_counter(counters, integrityViolation,
			{2, 1}, {integrityViolation, 0}),
	update_counters(AgentName, TargetName, T);
update_counters(AgentName, TargetName,
		[{"eventType", ?ET_Operational_Violation} | T]) ->
	ets:update_counter(counters, {AgentName, TargetName, operationalViolation},
			{2, 1}, {{AgentName, TargetName, operationalViolation}, 0}),
	ets:update_counter(counters, {AgentName, operationalViolation},
			{2, 1}, {{AgentName, operationalViolation}, 0}),
	ets:update_counter(counters, operationalViolation,
			{2, 1}, {operationalViolation, 0}),
	update_counters(AgentName, TargetName, T);
update_counters(AgentName, TargetName,
		[{"eventType", ?ET_Physical_Violation} | T]) ->
	ets:update_counter(counters, {AgentName, TargetName, physicalViolation},
			{2, 1}, {{AgentName, TargetName, physicalViolation}, 0}),
	ets:update_counter(counters, {AgentName, physicalViolation},
			{2, 1}, {{AgentName, physicalViolation}, 0}),
	ets:update_counter(counters, physicalViolation,
			{2, 1}, {physicalViolation, 0}),
	update_counters(AgentName, TargetName, T);
update_counters(AgentName, TargetName,
		[{"eventType", ?ET_Security_Service_Or_Mechanism_Violation} | T]) ->
	ets:update_counter(counters, {AgentName, TargetName, securityServiceOrMechanismViolation},
			{2, 1}, {{AgentName, TargetName, securityServiceOrMechanismViolation}, 0}),
	ets:update_counter(counters, {AgentName, securityServiceOrMechanismViolation},
			{2, 1}, {{AgentName, securityServiceOrMechanismViolation}, 0}),
	ets:update_counter(counters, securityServiceOrMechanismViolation,
			{2, 1}, {securityServiceOrMechanismViolation, 0}),
	update_counters(AgentName, TargetName, T);
update_counters(AgentName, TargetName,
		[{"eventType", ?ET_Time_Domain_Violation} | T]) ->
	ets:update_counter(counters, {AgentName, TargetName, timeDomainViolation},
			{2, 1}, {{AgentName, TargetName, timeDomainViolation}, 0}),
	ets:update_counter(counters, {AgentName, timeDomainViolation},
			{2, 1}, {{AgentName, timeDomainViolation}, 0}),
	ets:update_counter(counters, timeDomainViolation,
			{2, 1}, {timeDomainViolation, 0}),
	update_counters(AgentName, TargetName, T);
update_counters(AgentName, TargetName,
		[{"eventSeverity", ?ES_CRITICAL} | T]) ->
	ets:update_counter(counters, {AgentName, TargetName, critical},
			{2, 1}, {{AgentName, TargetName, critical}, 0}),
	ets:update_counter(counters, {AgentName, critical},
			{2, 1}, {{AgentName, critical}, 0}),
	ets:update_counter(counters, critical,
			{2, 1}, {critical, 0}),
	update_counters(AgentName, TargetName, T);
update_counters(AgentName, TargetName,
		[{"eventSeverity", ?ES_MAJOR}| T]) ->
	ets:update_counter(counters, {AgentName, TargetName, major},
			{2, 1}, {{AgentName, TargetName, major}, 0}),
	ets:update_counter(counters, {AgentName, major},
			{2, 1}, {{AgentName, major}, 0}),
	ets:update_counter(counters, major,
			{2, 1}, {major, 0}),
	update_counters(AgentName, TargetName, T);
update_counters(AgentName, TargetName,
		[{"eventSeverity", ?ES_MINOR} | T]) ->
	ets:update_counter(counters, {AgentName, TargetName, minor},
			{2, 1}, {{AgentName, TargetName, minor}, 0}),
	ets:update_counter(counters, {AgentName, minor},
			{2, 1}, {{AgentName, minor}, 0}),
	ets:update_counter(counters, minor,
			{2, 1}, {minor, 0}),
	update_counters(AgentName, TargetName, T);
update_counters(AgentName, TargetName,
		[{"eventSeverity", ?ES_WARNING} | T]) ->
	ets:update_counter(counters, {AgentName, TargetName, warning},
			{2, 1}, {{AgentName, TargetName, warning}, 0}),
	ets:update_counter(counters, {AgentName, warning},
			{2, 1}, {{AgentName, warning}, 0}),
	ets:update_counter(counters, warning,
			{2, 1}, {warning, 0}),
	update_counters(AgentName, TargetName, T);
update_counters(AgentName, TargetName,
		[{"eventSeverity", ?ES_INDETERMINATE} | T]) ->
	ets:update_counter(counters, {AgentName, TargetName, indeterminate},
			{2, 1}, {{AgentName, TargetName, indeterminate}, 0}),
	ets:update_counter(counters, {AgentName, indeterminate},
			{2, 1}, {{AgentName, indeterminate}, 0}),
	ets:update_counter(counters, indeterminate,
			{2, 1}, {indeterminate, 0}),
	update_counters(AgentName, TargetName, T);
update_counters(AgentName, TargetName,
		[{"eventSeverity", ?ES_CLEARED} | T]) ->
	ets:update_counter(counters, {AgentName, TargetName, cleared},
			{2, 1}, {{AgentName, TargetName, cleared}, 0}),
	ets:update_counter(counters, {AgentName, cleared},
			{2, 1}, {{AgentName, cleared}, 0}),
	ets:update_counter(counters, cleared,
			{2, 1}, {cleared, 0}),
	update_counters(AgentName, TargetName, T);
update_counters(AgentName, TargetName, [_H | T]) ->
	update_counters(AgentName, TargetName, T);
update_counters(_, _, []) ->
	ok.

-spec strip_target_name(TargetName) -> Result
	when
		TargetName :: string(),
		Result :: string().
%% @doc Trim extra values suffixed to the TargetName
strip_target_name(TargetName)
		when is_list(TargetName) ->
	case lists:last(TargetName) of
		$) ->
			Length = length(TargetName),
			case lists:split(Length - 3, TargetName) of
				{StrippedName, [$(, N, $)]} when is_integer(N) ->
					StrippedName;
				_ ->
					TargetName
				end;
		_ ->
			TargetName
	end.

%%----------------------------------------------------------------------
%%  The internal functions
%%----------------------------------------------------------------------

-spec common_event_header(TargetName, AlarmDetails, Domain) -> Result
	when
		AlarmDetails :: [{Name, Value}],
		Name :: list(),
		TargetName :: string(),
		Domain :: string(),
		Value :: list(),
		Result :: {map(), AlarmDetails}.
%% @doc Create the VES common event header map.
common_event_header(TargetName, AlarmDetails, Domain)
		when is_list(TargetName), is_list(AlarmDetails) ->
	DefaultMap = #{"domain" => Domain,
			"priority" => "Normal",
			"reportingEntityName" => TargetName,
			"sequence" => 0,
			"vesEventListenerVersion" => "7.0.1",
			"version" => "4.0.1"},
	common_event_header(AlarmDetails, TargetName, DefaultMap, []).
%% @hidden
common_event_header([{"reportingEntityId", Value} | T], TargetName, CH, AD) ->
	common_event_header(T, TargetName, CH#{"reportingEntityId" => Value}, AD);
common_event_header([{"eventName", Value} | T], TargetName, CH, AD) ->
	common_event_header(T, TargetName, CH#{"eventName" => Value}, AD);
common_event_header([{"sourceId", Value} | T], TargetName, CH, AD) ->
	common_event_header(T, TargetName, CH#{"sourceId" => Value}, AD);
common_event_header([{"sourceName", Value} | T], TargetName, CH, AD) ->
	common_event_header(T, TargetName, CH#{"sourceName" => Value}, AD);
common_event_header([{"priority", Value} | T], TargetName, CH, AD) ->
	common_event_header(T, TargetName, CH#{"priority" => Value}, AD);
common_event_header([{"sequence", Value} | T], TargetName, CH, AD) ->
	common_event_header(T, TargetName, CH#{"sequence" => Value}, AD);
common_event_header([{"version", Value} | T], TargetName, CH, AD) ->
	common_event_header(T, TargetName, CH#{"version" => Value}, AD);
common_event_header([{"eventType", Value} | T], TargetName, CH, AD) ->
	common_event_header(T, TargetName, CH#{"eventType" => Value}, AD);
common_event_header([{"raisedTime", Value} | T], TargetName, CH, AD) ->
	common_event_header(T, TargetName, CH#{"startEpochMicrosec" => snmp_collector_log:iso8601(Value)}, AD);
common_event_header([{"changedTime", Value} | T], TargetName, CH, AD) ->
	common_event_header(T, TargetName, CH#{"lastEpochMicrosec" => snmp_collector_log:iso8601(Value)}, AD);
common_event_header([{"clearedTime", Value} | T], TargetName, CH, AD) ->
	common_event_header(T, TargetName, CH#{"lastEpochMicrosec" => snmp_collector_log:iso8601(Value)}, AD);
common_event_header([{"alarmAckTime", Value} | T], TargetName, CH, AD) ->
	common_event_header(T, TargetName, CH#{"lastEpochMicrosec" => snmp_collector_log:iso8601(Value)}, AD);
common_event_header([H | T], TargetName, CH, AD) ->
	common_event_header(T, TargetName, CH, [H | AD]);
common_event_header([], _TargetName, CH, AD) ->
	{CH, AD}.

-spec heartbeat_fields(AlarmDetails) -> NotificationFields
	when
		AlarmDetails :: [{Name, Value}],
		Name :: list(),
		Value :: list(),
		NotificationFields :: map().
%% @doc Create the fault fields map.
heartbeat_fields(AlarmDetails) when is_list(AlarmDetails) ->
	DefaultMap = #{"alarmAdditionalInformation" => #{},
			"heartbeatFieldVersion" => 1},
	heartbeat_fields(AlarmDetails, DefaultMap).
%% @hidden
heartbeat_fields([{"systemLabel", Value} | T], Acc) ->
	heartbeat_fields(T, Acc#{"systemLabel" => Value});
heartbeat_fields([{"heartbeatInterval", Value} | T], Acc) ->
	heartbeat_fields(T, Acc#{"heartbeatInterval" => Value});
heartbeat_fields([{"raisedTime", Value} | T], Acc) ->
	heartbeat_fields(T, Acc#{"raisedTime" => Value});
heartbeat_fields([{Name, Value} | T],
		#{"additionalFields" := AI} = Acc) ->
	NewAI = AI#{Name => Value},
	heartbeat_fields(T, Acc#{"additionalFields" => NewAI});
heartbeat_fields([], Acc) ->
	Acc.

-spec notification_fields(AlarmDetails) -> NotificationFields
	when
		AlarmDetails :: [{Name, Value}],
		Name :: list(),
		Value :: list(),
		NotificationFields :: map().
%% @doc Create the fault fields map.
notification_fields(AlarmDetails) when is_list(AlarmDetails) ->
	DefaultMap = #{"alarmAdditionalInformation" => #{},
			"notificationFieldsVersion" => 1},
	notification_fields(AlarmDetails, DefaultMap).
%% @hidden
notification_fields([{"id", Value} | T], Acc) ->
	notification_fields(T, Acc#{"id" => Value});
notification_fields([{"description", Value} | T], Acc) ->
	notification_fields(T, Acc#{"description" => Value});
notification_fields([{"status", Value} | T], Acc) ->
	notification_fields(T, Acc#{"status" => Value});
notification_fields([{"name", Value} | T], Acc) ->
	notification_fields(T, Acc#{"name" => Value});
notification_fields([{"priority", Value} | T], Acc) ->
	notification_fields(T, Acc#{"priority" => Value});
notification_fields([{"eventType", Value} | T], Acc) ->
	notification_fields(T, Acc#{"eventType" => Value});
notification_fields([{"stateInterface", Value} | T], Acc) ->
	notification_fields(T, Acc#{"stateInterface" => Value});
notification_fields([{"changeType", Value} | T], Acc) ->
	notification_fields(T, Acc#{"changeType" => Value});
notification_fields([{Name, Value} | T],
		#{"additionalFields" := AI} = Acc) ->
	NewAI = AI#{Name => Value},
	notification_fields(T, Acc#{"additionalFields" => NewAI});
notification_fields([], Acc) ->
	Acc.

-spec syslog_fields(AlarmDetails) -> SysLogFields
	when
		AlarmDetails :: [{Name, Value}],
		Name :: list(),
		Value :: list(),
		SysLogFields :: map().
%% @doc Create the fault fields map.
syslog_fields(AlarmDetails) when is_list(AlarmDetails) ->
	DefaultMap = #{"alarmAdditionalInformation" => #{},
			"syslogFieldsVersion" => 1},
	syslog_fields(AlarmDetails, DefaultMap).
%% @hidden
syslog_fields([{"sysSourceType", Value} | T], Acc) ->
	syslog_fields(T, Acc#{"eventSourceType" => Value});
syslog_fields([{"sysSourceHost", Value} | T], Acc) ->
	syslog_fields(T, Acc#{"eventSourceHost" => Value});
syslog_fields([{"syslogMsg", Value} | T], Acc) ->
	syslog_fields(T, Acc#{"syslogMsg" => Value});
syslog_fields([{"syslogSev", Value} | T], Acc) ->
	syslog_fields(T, Acc#{"syslogSev" => Value});
syslog_fields([{"syslogTag", Value} | T], Acc) ->
	syslog_fields(T, Acc#{"syslogTag" => Value});
syslog_fields([{Name, Value} | T],
		#{"additionalFields" := AI} = Acc) ->
	NewAI = AI#{Name => Value},
	syslog_fields(T, Acc#{"additionalFields" => NewAI});
syslog_fields([], Acc) ->
	Acc.

-spec fault_fields(AlarmDetails) -> FaultFields
	when
		AlarmDetails :: [{Name, Value}],
		Name :: list(),
		Value :: list(),
		FaultFields :: map().
%% @doc Create the fault fields map.
fault_fields(AlarmDetails) when is_list(AlarmDetails) ->
	DefaultMap = #{"alarmAdditionalInformation" => #{},
			"faultFieldsVersion" => 1},
	fault_fields(AlarmDetails, DefaultMap).
%% @hidden
fault_fields([{"alarmCondition", Value} | T], Acc) ->
	fault_fields(T, Acc#{"alarmCondition" => Value});
fault_fields([{"eventCategory", Value} | T], Acc) ->
	fault_fields(T, Acc#{"eventCategory" => Value});
fault_fields([{"eventSeverity", Value} | T], Acc) ->
	fault_fields(T, Acc#{"eventSeverity" => Value});
fault_fields([{"eventSourceType", Value} | T], Acc) ->
	fault_fields(T, Acc#{"eventSourceType" => Value});
fault_fields([{"specificProblem", Value} | T], Acc) ->
	fault_fields(T, Acc#{"specificProblem" => Value});
fault_fields([{"nfVendorName", Value} | T], Acc) ->
	fault_fields(T, Acc#{"nfVendorName" => Value});
fault_fields([{Name, Value} | T],
		#{"alarmAdditionalInformation" := AI} = Acc) ->
	NewAI = AI#{Name => Value},
	fault_fields(T, Acc#{"alarmAdditionalInformation" => NewAI});
fault_fields([], Acc) ->
	Acc.

-spec check_fields(CommonEventHeader, FaultFields) -> Result
	when
		CommonEventHeader :: map(),
		FaultFields :: map(),
		Result :: {NewCommonEventHeader, NewFaultFields},
		NewCommonEventHeader :: map(),
		NewFaultFields :: map().
%% @doc Normalize mandatory fields.
%% @hidden
check_fields(#{"eventName" := ?EN_CLEARED} = CH, #{"eventSeverity" := ?ES_CLEARED} = FF) ->
	check_fields1(CH, FF);
check_fields(#{"eventName" := ?EN_CLEARED} = CH, #{"eventSeverity" := EventSeverity} = FF)
		when is_list(EventSeverity), length(EventSeverity) > 0 ->
	check_fields1(CH, FF#{"eventSeverity" =>  ?ES_CLEARED});
check_fields(#{"eventName" := _EventName} = CH, #{"eventSeverity" := ?ES_CLEARED} = FF) ->
	check_fields1(CH#{"eventName" => ?EN_CLEARED}, FF);
check_fields(#{"eventName" := EventName} = CH, #{"eventSeverity" := EventSeverity} = FF)
		when is_list(EventName), length(EventName) > 0,
		is_list(EventSeverity), length(EventSeverity) > 0 ->
	check_fields1(CH, FF);
check_fields(#{"eventName" := ?EN_CLEARED} = CH, FF) ->
	check_fields1(CH, FF#{"eventSeverity" =>  ?ES_CLEARED});
check_fields(#{"eventName" := EventName} = CH, FF)
		when is_list(EventName), length(EventName) > 0 ->
	check_fields1(CH, FF);
check_fields(CH, #{"eventSeverity" := ?ES_CLEARED} = FF) ->
	check_fields1(CH#{"eventName" => ?EN_CLEARED}, FF);
check_fields(CH, FF) ->
	check_fields1(CH#{"eventName" => ?EN_NEW}, FF).
%% @hidden
check_fields1(CH, #{"eventSeverity" := EventSeverity} = FF)
		when is_list(EventSeverity), length(EventSeverity) > 0 ->
	check_fields2(CH, FF);
check_fields1(CH, FF) ->
	check_fields2(CH#{"eventSeverity" => ?ES_INDETERMINATE}, FF).
%% @hidden
check_fields2(#{"eventType" := EventType, "domain" := "fault"} = CH, FF)
		when is_list(EventType), length(EventType) > 0 ->
	check_fields3(CH, FF);
check_fields2(CH, FF) ->
	check_fields3(CH#{"eventType" => ?ET_Quality_Of_Service_Alarm}, FF).
check_fields3(CH, #{"alarmAdditionalInformation" := #{"probableCause" := ProbableCause}} = FF)
		when is_list(ProbableCause), length(ProbableCause) > 0 ->
	{CH, FF};
check_fields3(CH, FF) ->
	{CH, FF#{"alarmAdditionalInformation" =>
			#{"probableCause" => ?PC_Indeterminate}}}.

-spec authenticate_v3(AuthProtocol, AuthKey, AuthParams, Packet) -> Result
	when
		AuthProtocol :: usmNoAuthProtocol | usmHMACMD5AuthProtocol | usmHMACSHAAuthProtocol,
		AuthKey :: [byte()],
		AuthParams :: list(),
		Packet :: [byte()],
		Result :: true | false.
%% @doc Authenticate the SNMP agent.
%% @hidden
authenticate_v3(usmHMACMD5AuthProtocol, AuthKey, AuthParams, Packet) ->
	case snmp_collector_snmp_usm:auth_in(usmHMACMD5AuthProtocol, AuthKey, AuthParams, Packet) of
		true ->
			true;
		false ->
			false
	end;
authenticate_v3(usmHMACSHAAuthProtocol, AuthKey, AuthParams ,Packet) ->
	case snmp_collector_snmp_usm:auth_in(usmHMACSHAAuthProtocol, AuthKey, AuthParams, Packet) of
		true ->
			true;
		false ->
			false
	end;
authenticate_v3(usmNoAuthProtocol, _AuthKey, _AuthParams, _Packet) ->
	true.

-spec generate_key(Protocol, Pass, EngineID) -> Key
	when
		Protocol :: usmNoAuthProtocol | usmHMACMD5AuthProtocol
				| usmHMACSHAAuthProtocol | usmDESPrivProtocol | usmAesCfb128Protocol,
		Pass :: string(),
		EngineID :: [byte()],
		Key :: [byte()].
%% @doc Generates a localized key (Kul) for authentication or privacy.
generate_key(usmNoAuthProtocol, AuthPass, EngineID)
		when is_list(AuthPass), is_list(EngineID) ->
	[];
generate_key(usmHMACMD5AuthProtocol, AuthPass, EngineID)
		when is_list(AuthPass), is_list(EngineID) ->
	Ku = snmp_collector_usm:ku(md5, AuthPass),
	snmp_collector_usm:kul(md5, Ku, EngineID);
generate_key(usmDESPrivProtocol, AuthPass, EngineID)
		when is_list(AuthPass), is_list(EngineID) ->
	Ku = snmp_collector_usm:ku(md5, AuthPass),
	snmp_collector_usm:kul(md5, Ku, EngineID);
generate_key(usmAesCfb128Protocol, AuthPass, EngineID)
		when is_list(AuthPass), is_list(EngineID) ->
	Ku = snmp_collector_usm:ku(md5, AuthPass),
	snmp_collector_usm:kul(md5, Ku, EngineID);
generate_key(usmHMACSHAAuthProtocol, AuthPass, EngineID)
		when is_list(AuthPass), is_list(EngineID) ->
	Ku = snmp_collector_usm:ku(sha, AuthPass),
	snmp_collector_usm:kul(sha, Ku, EngineID).

