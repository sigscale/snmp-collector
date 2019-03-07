%%%snmp_collector_utils.erl
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
-module(snmp_collector_utils).
-copyright('Copyright (c) 2016 - 2019 SigScale Global Inc.').

-export([iso8601/1, oid_to_name/1, get_name/1, generate_identity/1, stringify/1,
		entity_name/1, entity_id/1, event_id/0, timestamp/0, create_pairs/1,
		arrange_list/2, map_names_values/2, fault_fields/2, event_header/2,
		log_events/2, get_values/2, security_params/7, agent_name/1, destringify/1]).

%% support deprecated_time_unit()
-define(MILLISECOND, milli_seconds).
%-define(MILLISECOND, millisecond).
-define(MICROSECOND, micro_seconds).
%-define(MICROSECOND, microsecond).

% calendar:datetime_to_gregorian_seconds({{1970,1,1},{0,0,0}})
-define(EPOCH, 62167219200).

%%----------------------------------------------------------------------
%%  The snmp_collector_utilites public API
%%----------------------------------------------------------------------

-spec date(MilliSeconds) -> Result
	when
		MilliSeconds :: pos_integer(),
		Result :: calendar:datetime().
%% @doc Convert timestamp to date and time.
date(MilliSeconds) when is_integer(MilliSeconds) ->
	Seconds = ?EPOCH + (MilliSeconds div 1000),
	calendar:gregorian_seconds_to_datetime(Seconds).

-spec iso8601(DateTime) -> DateTime
	when
		DateTime :: pos_integer() | string().
%% @doc Convert between ISO 8601 and Unix epoch milliseconds.
%% 	Parsing is not strict to allow prefix matching.
iso8601(DateTime) when is_integer(DateTime) ->
	{{Year, Month, Day}, {Hour, Minute, Second}} = date(DateTime),
	DateFormat = "~4.10.0b-~2.10.0b-~2.10.0b",
	TimeFormat = "T~2.10.0b:~2.10.0b:~2.10.0b.~3.10.0bZ",
	Chars = io_lib:fwrite(DateFormat ++ TimeFormat,
			[Year, Month, Day, Hour, Minute, Second, DateTime rem 1000]),
	lists:flatten(Chars);
iso8601([Y1, Y2, Y3, Y4 | T])
		when Y1 >= $0, Y1 =< $9, Y2 >= $0, Y2 =< $9,
		Y3 >= $0, Y3 =< $9, Y4 >= $0, Y4 =< $9 ->
	iso8601month(list_to_integer([Y1, Y2, Y3, Y4]), T).
%% @hidden
iso8601month(Year, []) ->
	DateTime = {{Year, 1, 1}, {0, 0, 0}},
	GS = calendar:datetime_to_gregorian_seconds(DateTime),
	(GS - ?EPOCH) * 1000;
iso8601month(Year, [$-]) ->
	iso8601month(Year, []);
iso8601month(Year, [$-, $0]) ->
	iso8601month(Year, [$-, $0, $1]);
iso8601month(Year, [$-, $1]) ->
	iso8601month(Year, [$-, $1, $0]);
iso8601month(Year, [$-, M, $- | T])
		when M >= $1, M =< $9 ->
	iso8601day(Year, list_to_integer([M]), T);
iso8601month(Year, [$/, M1, M2 | T])
		when M1 >= $0, M1 =< $1, M2 >= $0, M2 =< $9 ->
	iso8601day(Year, list_to_integer([M1, M2]), T);
iso8601month(Year, [$-, M1, M2 | T])
		when M1 >= $0, M1 =< $1, M2 >= $0, M2 =< $9 ->
	iso8601day(Year, list_to_integer([M1, M2]), T).
%% @hidden
iso8601day(Year, Month, []) ->
	DateTime = {{Year, Month, 1}, {0, 0, 0}},
	GS = calendar:datetime_to_gregorian_seconds(DateTime),
	(GS - ?EPOCH) * 1000;
iso8601day(Year, Month, [$-]) ->
	iso8601day(Year, Month, []);
iso8601day(Year, Month, [$-, $0]) ->
	iso8601day(Year, Month, [$-, $1, $0]);
iso8601day(Year, Month, [$-, D1])
		when D1 >= $1, D1 =< $3 ->
	iso8601day(Year, Month, [$-, D1, $0]);
iso8601day(Year, Month, [$/, D])
		when D >= $1, D =< $9 ->
	iso8601day(Year, Month, [$-, D]);
iso8601day(Year, Month, [$-, D, _ | T])
		when D >= $1, D =< $9 ->
	Day = list_to_integer([D]),
	iso8601hour({Year, Month, Day}, T);
iso8601day(Year, Month, [$-, D, $, | T])
		when D >= $1, D =< $9 ->
	Day = list_to_integer([D]),
	iso8601hour({Year, Month, Day}, T);
iso8601day(Year, Month, [D, $, | T])
		when D >= $1, D =< $9 ->
	Day = list_to_integer([D]),
	iso8601hour({Year, Month, Day}, T);
iso8601day(Year, Month, [$-, D, $- | T])
		when D >= $1, D =< $9 ->
	Day = list_to_integer([D]),
	iso8601hour({Year, Month, Day}, T);
iso8601day(Year, Month, [$/, D1, D2 | T])
		when D1 >= $0, D1 =< $3, D2 >= $0, D2 =< $9 ->
	Day = list_to_integer([D1, D2]),
	iso8601hour({Year, Month, Day}, T);
iso8601day(Year, Month, [D1, D2, $, | T])
		when D1 >= $0, D1 =< $3, D2 >= $0, D2 =< $9 ->
	Day = list_to_integer([D1, D2]),
	iso8601hour({Year, Month, Day}, T);
iso8601day(Year, Month, [$-, D1, D2 | T])
		when D1 >= $0, D1 =< $3, D2 >= $0, D2 =< $9 ->
	Day = list_to_integer([D1, D2]),
	iso8601hour({Year, Month, Day}, T).
%% @hidden
iso8601hour(Date, []) ->
	DateTime = {Date, {0, 0, 0}},
	GS = calendar:datetime_to_gregorian_seconds(DateTime),
	(GS - ?EPOCH) * 1000;
iso8601hour(Date, [$T]) ->
	iso8601hour(Date, []);
iso8601hour(Date, [$ ]) ->
	iso8601hour(Date, []);
iso8601hour(Date, [H1, $:])
		when H1 >= $0, H1 =< $2 ->
	iso8601hour(Date, [$T, H1, $0]);
iso8601hour(Date, [$T, H1])
		when H1 >= $0, H1 =< $2 ->
	iso8601hour(Date, [$T, H1, $0]);
iso8601hour(Date, [$ , H1])
		when H1 >= $0, H1 =< $2 ->
	iso8601hour(Date, [$ , H1, $0]);
iso8601hour(Date, [$, , H1])
		when H1 >= $0, H1 =< $2 ->
	iso8601hour(Date, [$ , H1, $0]);
iso8601hour(Date, [$T, H, $- | T])
		when H >= $1, H =< $9 ->
	Hour = list_to_integer([H]),
	iso8601minute(Date, Hour, T);
iso8601hour(Date, [$, , H1, H2 | T])
		when H1 >= $0, H1 =< $2, H2 >= $0, H2 =< $9 ->
	Hour = list_to_integer([H1, H2]),
	iso8601minute(Date, Hour, T);
iso8601hour(Date, [H1, H2 | T])
		when H1 >= $0, H1 =< $2, H2 >= $0, H2 =< $9 ->
	Hour = list_to_integer([H1, H2]),
	iso8601minute(Date, Hour, T);
iso8601hour(Date, [$T, H1, H2 | T])
		when H1 >= $0, H1 =< $2, H2 >= $0, H2 =< $9 ->
	Hour = list_to_integer([H1, H2]),
	iso8601minute(Date, Hour, T);
iso8601hour(Date, [$ , $- , $ , H1, H2 | T])
		when H1 >= $0, H1 =< $2, H2 >= $0, H2 =< $9 ->
	Hour = list_to_integer([H1, H2]),
	iso8601minute(Date, Hour, T);
iso8601hour(Date, [$ , H1, H2 | T])
		when H1 >= $0, H1 =< $2, H2 >= $0, H2 =< $9 ->
	Hour = list_to_integer([H1, H2]),
	iso8601minute(Date, Hour, T).
%% @hidden
iso8601minute(Date, Hour, []) ->
	DateTime = {Date, {Hour, 0, 0}},
	GS = calendar:datetime_to_gregorian_seconds(DateTime),
	(GS - ?EPOCH) * 1000;
iso8601minute(Date, Hour, [$:]) ->
	iso8601minute(Date, Hour, []);
iso8601minute(Date, Hour, [$:, M1])
		when M1 >= $0, M1 =< $5 ->
	iso8601minute(Date, Hour, [$:, M1, $0]);
iso8601minute(Date, Hour, [M1, $:, M2 | T])
		when M1 >= $0, M1 =< $5, M2 >= $0, M2 =< $9 ->
	Minute = list_to_integer([M1, M2]),
	iso8601second(Date, Hour, Minute, T);
iso8601minute(Date, Hour, [$:, M1, M2 | T])
		when M1 >= $0, M1 =< $5, M2 >= $0, M2 =< $9 ->
	Minute = list_to_integer([M1, M2]),
	iso8601second(Date, Hour, Minute, T);
iso8601minute(Date, Hour, _) ->
	DateTime = {Date, {Hour, 0, 0}},
	GS = calendar:datetime_to_gregorian_seconds(DateTime),
	(GS - ?EPOCH) * 1000.
%% @hidden
iso8601second(Date, Hour, Minute, []) ->
	DateTime = {Date, {Hour, Minute, 0}},
	GS = calendar:datetime_to_gregorian_seconds(DateTime),
	(GS - ?EPOCH) * 1000;
iso8601second(Date, Hour, Minute, [$:]) ->
	iso8601second(Date, Hour, Minute, []);
iso8601second(Date, Hour, Minute, [$:, S1])
		when S1 >= $0, S1 =< $5 ->
	iso8601second(Date, Hour, Minute, [$:, S1, $0]);
iso8601second(Date, Hour, Minute, [$:, S1, S2 | T])
		when S1 >= $0, S1 =< $5, S2 >= $0, S2 =< $9 ->
	Second = list_to_integer([S1, S2]),
	DateTime = {Date, {Hour, Minute, Second}},
	GS = calendar:datetime_to_gregorian_seconds(DateTime),
	EpocMilliseconds = (GS - ?EPOCH) * 1000,
	iso8601millisecond(EpocMilliseconds, T);
iso8601second(Date, Hour, Minute, _) ->
	DateTime = {Date, {Hour, Minute, 0}},
	GS = calendar:datetime_to_gregorian_seconds(DateTime),
	(GS - ?EPOCH) * 1000.
%% @hidden
iso8601millisecond(EpocMilliseconds, []) ->
	EpocMilliseconds;
iso8601millisecond(EpocMilliseconds, [$.]) ->
	EpocMilliseconds;
iso8601millisecond(EpocMilliseconds, [$., N1, N2, N3 | _])
		when N1 >= $0, N1 =< $9, N2 >= $0, N2 =< $9,
		N3 >= $0, N3 =< $9 ->
	EpocMilliseconds + list_to_integer([N1, N2, N3]);
iso8601millisecond(EpocMilliseconds, [$., N1, N2 | _])
		when N1 >= $0, N1 =< $9, N2 >= $0, N2 =< $9 ->
	EpocMilliseconds + list_to_integer([N1, N2]) * 10;
iso8601millisecond(EpocMilliseconds, [$., N | _])
		when N >= $0, N =< $9 ->
	EpocMilliseconds + list_to_integer([N]) * 100;
iso8601millisecond(EpocMilliseconds, _) ->
	EpocMilliseconds.

-spec oid_to_name(OID) -> Name
	when
		OID :: snmp:oid(),
		Name :: string().
%% @doc Get a name for an OID.
oid_to_name(OID) ->
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

-spec get_name(Body) -> Result
	when
		Body :: list(),
		Result :: Name,
		Name :: string().
%% @doc Get the name of the MIB from the body of a MIB.
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
-spec create_pairs(Varbinds) -> Result
	when
		Varbinds :: [Varbind],
		Varbind :: {varbind, OID, Type, Value, Seqnum},
		OID :: snmp:oid(),
		Type :: 'OCTET STRING' | 'OBJECT IDENTIFIER' | 'INTEGER',
		Value :: string() | atom() | integer(),
		Seqnum :: integer(),
		Result :: {ok, Pairs} | {error, no_sysuptime},
		Pairs :: list().
%% @doc Create a list of the OIDS ,Types and Values.
%% @private
create_pairs(Varbinds) ->
	case snmpm:name_to_oid(sysUpTime) of
		{ok, SysUpTime} ->
			NewSysUpTime = lists:flatten(SysUpTime ++ [0]),
				case lists:keytake(NewSysUpTime, 2, Varbinds) of
					{value, {varbind, _, 'TimeTicks', _, _}, Varbind1} ->
						Pairs = [{OID, Type, Value} || {varbind, OID, Type, Value, _} <- Varbind1],
						{ok, Pairs};
					false ->
						{error, no_sysuptime}
				end;
		{error, _Reason} ->
			Pairs = [{OID, Type, Value} || {varbind ,OID, Type, Value, _} <- Varbinds],
			{ok, Pairs}
	end.

-spec arrange_list(Pairs, Acc) -> Result
	when
		Pairs :: [tuple()],
		Result :: {ok ,NewAcc},
		NewAcc :: [tuple()],
		Acc :: list().
%% @doc Filter and map the OIDs to names and appropriate values.
%% @private
arrange_list([{OID, Type, Value} | T], Acc)
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
arrange_list([{OID, Type, Value} | T], Acc)
		when Type == 'OBJECT IDENTIFIER', is_list(Value) ->
	arrange_list(T, [{OID, oid_to_name(Value)} | Acc]);
arrange_list([{OID, Type, Value} | T], Acc)
		when Type =='INTEGER', is_integer(Value) ->
	Value2 = integer_to_list(Value),
	arrange_list(T, [{OID, Value2} | Acc]);
arrange_list([_ | T], Acc) ->
	arrange_list(T, Acc);
arrange_list([], Acc) ->
	NewAcc = lists:reverse(Acc),
	{ok ,NewAcc}.

-spec map_names_values(Objects, Acc) -> Result
	when
		Objects :: [{Name, Value}],
		Acc :: list(),
		Name :: string(),
		Value :: term(),
		Result :: {ok, Acc}.
%% @doc Turn the list of names and values into a map format.
%% @private
map_names_values([{Name, Value} | T], Acc) ->
	map_names_values(T, [#{"name" => Name, "value" => Value} | Acc]);
map_names_values([], Acc) ->
	{ok, Acc}.

-spec fault_fields(AdditionalInformation, EventDetails) -> Result
	when
		AdditionalInformation :: [map()],
		EventDetails :: [tuple()],
		Result :: #{}.
%% @doc Create the Fault Fields map.
fault_fields(AdditionalInformation, EventDetails) ->
	#{"alarmAdditionalInformation" => lists:reverse(AdditionalInformation),
		"alarmCondition" => get_values(alarmCondtion, EventDetails),
		"eventCategory" => get_values(eventCategory, EventDetails),
		"eventSeverity" => get_values(eventSeverity, EventDetails),
		"eventSourceType" => get_values(eventSourceType, EventDetails),
		"faultFieldsVersion" => 1,
		"specificProblem"=> get_values(specificProblem, EventDetails)}.

-spec event_header(TargetName, EventDetails) -> EventHeader
	when
		TargetName :: string(),
		EventDetails :: [tuple()],
		EventHeader :: map().
%% @doc Create VES common event header.
event_header(TargetName, EventDetails) ->
	#{"domain" => "fault",
			"eventId" => event_id(),
			"eventName" => get_values(eventName, EventDetails),
			"lastEpochMicrosec" => timestamp(),
			"priority" => "Normal",
			"reportingEntityID" => stringify(entity_id(TargetName)),
			"reportingEntityName" => entity_name(TargetName),
			"sequence" => 0,
			"sourceId" => get_values(sourceId, EventDetails),
			"sourceName" => get_values(sourceName, EventDetails),
			"startEpochMicrosec" => iso8601(get_values(raisedTime, EventDetails)),
			"version" => 1}.

-spec security_params(EngineID, Address, SecName, AuthParams, Packet, AuthPass, PrivPass) -> Result
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
	case ets:lookup(snmpm_usm_table, {usmUserTable, EngineID, SecName}) of
		[{_, {usm_user, _, _, _, AuthProtocol, _, PrivProtocol, _}}] ->
			AuthKey = auth_key(AuthProtocol, AuthPass, EngineID),
			case authenticate(AuthProtocol, AuthKey, AuthParms ,Packet) of
				true ->
					{ok, AuthProtocol, PrivProtocol};
				false ->
					{error, authentication_failed}
			end;
		[] ->
			case agent_name(Address) of
				{_, TargetName} when is_list(TargetName) ->
					security_params1(EngineID, TargetName, SecName, AuthParms, Packet, AuthPass, PrivPass);
				{error, _Reason} ->
					{error, not_found}
			end
	end.
%% @hidden
security_params1(EngineID, TargetName, SecName, AuthParms, Packet, AuthPass, PrivPass)
		when is_list(EngineID), is_list(SecName) ->
	case ets:match(snmpm_usm_table, {{usmUserTable, '_', TargetName},
			{usm_user, '_', TargetName, SecName, '$1', '_', '$2', '_'}}) of
		[[AuthProtocol, PrivProtocol]] ->
			AuthKey = auth_key(AuthProtocol, AuthPass, EngineID),
			case authenticate(AuthProtocol, AuthKey, AuthParms ,Packet) of
				true ->
					case add_usm_user(EngineID, TargetName, SecName, AuthProtocol,
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
			AuthKey = auth_key(AuthProtocol, AuthPass, EngineID),
			case authenticate(AuthProtocol, AuthKey, AuthParms ,Packet) of
				true ->
					case add_usm_user(EngineID, TargetName, SecName, AuthProtocol,
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

-spec agent_name(Address) -> Result
	when
		Address :: inet:ip_address(),
		Result :: {AgentName, TargetName} | {error, Reason},
		AgentName :: string(),
		TargetName :: snmpm:target_name(),
		Reason :: target_name_not_found | agent_name_not_found | term().
%% @doc Identify the Agent name and Target Name for the received packet.
agent_name(Address) ->
	case ets:match(snmpm_agent_table, {{'$1', '_'}, {Address ,'_'}}) of
		[[TargetName]] ->
			case ets:match(snmpm_agent_table, {{TargetName, user_id},'$1'}) of
				[[AgentName]] ->
					{AgentName, TargetName};
				[] ->
					{error, agent_name_not_found}
			end;
		[] ->
			{error, target_name_not_found}
	end.

-spec log_events(CommonEventHeader, FaultFields) -> Result
   when
		CommonEventHeader :: map(), FaultFields :: map(),
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Log the event to disk.
%% @private
log_events(CommonEventHeader, FaultFields) ->
	{ok, LogName} = application:get_env(snmp_collector, queue_name),
	TimeStamp = erlang:system_time(milli_seconds),
	Identifer = erlang:unique_integer([positive]),
	Node = node(),
	Event = {TimeStamp, Identifer, Node, CommonEventHeader, FaultFields},
	case disk_log:log(LogName, Event) of
		ok ->
			case post_event(CommonEventHeader, FaultFields) of
				ok ->
					ok;
				{error, Reason} ->
					error_logger:info_report(["SNMP Manager POST Failed",
							{timestamp, TimeStamp},
							{identifier, Identifer},
							{node, Node},
							{reason, Reason}]),
					{error, Reason}
			end;
		{error, Reason} ->
			error_logger:info_report(["SNMP Manager Event Logging Failed",
					{timestamp, TimeStamp},
					{identifier, Identifer},
					{node, Node},
					{reason, Reason}]),
			{error, Reason}
	end.

-spec post_event(CommonEventHeader, FaultFields) -> Result
   when
		CommonEventHeader :: map(),
		FaultFields :: map(),
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Log the event to disk.
post_event(CommonEventHeader, FaultFields) ->
	{ok, Url} = application:get_env(snmp_collector, ves_url),
	{ok, UserName } = application:get_env(snmp_collector, ves_username),
	{ok, Password} = application:get_env(snmp_collector, ves_password),
	ContentType = "application/json",
	Accept = {"accept", "application/json"},
	EncodeKey = "Basic" ++ base64:encode_to_string(string:concat(UserName ++ ":", Password)),
	Authentication = {"authorization", EncodeKey},
	Event = #{"event" => #{"commonEventHeader" => CommonEventHeader, "faultFields" => FaultFields}},
	RequestBody = destringify(zj:encode(Event)),
	Request = {Url ++ "/eventListener/v5", [Accept, Authentication], ContentType, RequestBody},
	case httpc:request(post, Request, [],
		[{sync, false}, {receiver, fun check_response/1}]) of
			{error, Reason} ->
				error_logger:info_report(["SNMP Manager POST Failed",
						{error, Reason}]);
			_RequestID ->
				ok
	end.

%%----------------------------------------------------------------------
%%  The internal functions
%%----------------------------------------------------------------------

-spec check_response(ReplyInfo) -> any()
	when
		ReplyInfo :: tuple().
%% @doc Check the response of a httpc request.
check_response({_RequestId, {error, Reason}}) ->
	error_logger:info_report(["SNMP Manager POST Failed",
			{error, Reason}]);
check_response({_RequestId, {{"HTTP/1.1",400, "Bad Request"},_ , _}}) ->
			error_logger:info_report(["SNMP Manager POST Failed",
					{error, "400, bad_request"}]);
check_response({_RequestId, {{"HTTP/1.1",200, _Created},_ , _}}) ->
			void.

-spec get_values(Name, EventDetails) -> Value
	when
		Name :: atom(),
		EventDetails :: [tuple()],
		Value :: string() | atom() | integer() | list().
%% @doc Use a name to get a value from a list of names and value.
get_values(Name, EventDetails) ->
	case lists:keyfind(Name, 1, EventDetails) of
		{_, Value} ->
			Value;
		false ->
			""
	end.

-spec entity_name(TargetName) -> EntityName
	when
	TargetName :: string(),
	EntityName :: string().
%% @doc Generate the agents name.
%% @private
entity_name(TargetName) ->
	[{{EntityName, engine_id}, _}] = ets:lookup(snmpm_agent_table, {TargetName, engine_id}),
	EntityName.

-spec entity_id(TargetName) -> EntityID
	when
	TargetName :: string(),
	EntityID :: string().
%% @doc Generate the agents engine ID.
%% @private
entity_id(TargetName) ->
	[{_ , EntityID}] = ets:lookup(snmpm_agent_table, {TargetName, engine_id}),
	lists:flatten(io_lib:fwrite("~p", [EntityID])).

-spec event_id() -> EventId
	when
		EventId :: string().
%% @doc Create unique event id.
event_id() ->
	Ts = erlang:system_time(?MILLISECOND),
	N = erlang:unique_integer([positive]),
	integer_to_list(Ts) ++ "-" ++ integer_to_list(N).

-spec timestamp() -> TimeStamp
	when
		TimeStamp :: integer().
%% @doc Create time stamp.
timestamp() ->
	erlang:system_time(?MILLISECOND).

-spec authenticate(AuthProtocol, AuthKey, AuthParams, Packet) -> Result
	when
		AuthProtocol :: usmNoAuthProtocol | usmHMACMD5AuthProtocol | usmHMACSHAAuthProtocol,
		AuthKey :: list(),
		AuthParams :: list(),
		Packet :: [byte()],
		Result :: true | false.
%% @doc Authenticate the SNMP agent.
authenticate(usmNoAuthProtocol, _AuthKey, _AuthParams, _Packet) ->
	true;
authenticate(usmHMACMD5AuthProtocol, AuthKey, AuthParams, Packet) ->
	case snmp_usm:auth_in(usmHMACMD5AuthProtocol, AuthKey,
			AuthParams, list_to_binary(Packet)) of
		true ->
			true;
		false ->
			false
	end;
authenticate(usmHMACSHAAuthProtocol, AuthKey, AuthParams ,Packet) ->
	case snmp_usm:auth_in(usmHMACSHAAuthProtocol, AuthKey,
			AuthParams, list_to_binary(Packet)) of
		true ->
			true;
		false ->
			false
	end.

-spec add_usm_user(EngineID, UserName, SecName, AuthProtocol, PrivProtocol, AuthPass, PrivPass) -> Result
	when
		EngineID :: list(),
		UserName :: list(),
		SecName :: list(),
		AuthProtocol :: usmNoAuthProtocol | usmHMACMD5AuthProtocol | usmHMACSHAAuthProtocol,
		PrivProtocol :: usmNoPrivProtocol | usmDESPrivProtocol | usmAesCfb128Protocol,
		AuthPass :: list(),
		PrivPass :: list(),
		Result :: {usm_user_added, AuthProtocol, PrivProtocol} | {error, Reason},
		Reason :: term().
%% @doc Add a new usm user to the snmp_usm table.
add_usm_user(EngineID, UserName, SecName, usmNoAuthProtocol, usmNoPrivProtocol, _AuthPass, _PrivPass)
		when is_list(EngineID), is_list(UserName) ->
	Conf = [{sec_name, SecName}, {auth, usmNoAuthProtocol}, {priv, usmNoPrivProtocol}],
	add_usm_user1(EngineID, UserName, Conf, usmNoAuthProtocol, usmNoPrivProtocol);
%% @hidden
add_usm_user(EngineID, UserName, SecName, usmHMACMD5AuthProtocol, usmNoPrivProtocol, AuthPass, _PrivPass)
		when is_list(EngineID), is_list(UserName) ->
	AuthKey = snmp:passwd2localized_key(md5, AuthPass, EngineID),
	Conf = [{sec_name, SecName}, {auth, usmHMACMD5AuthProtocol}, {priv, usmNoPrivProtocol},
			{auth_key, AuthKey}],
	add_usm_user1(EngineID, UserName, Conf, usmHMACMD5AuthProtocol, usmNoPrivProtocol);
%% @hidden
add_usm_user(EngineID, UserName, SecName, usmHMACMD5AuthProtocol, usmDESPrivProtocol, AuthPass, PrivPass)
		when is_list(EngineID), is_list(UserName) ->
	AuthKey = snmp:passwd2localized_key(md5, AuthPass, EngineID),
	PrivKey = snmp:passwd2localized_key(md5, PrivPass, EngineID),
	Conf = [{sec_name, SecName}, {auth, usmNoAuthProtocol}, {auth_key, AuthKey},
			{priv, usmDESPrivProtocol}, {priv_key, PrivKey}],
	add_usm_user1(EngineID, UserName, Conf, usmHMACMD5AuthProtocol, usmDESPrivProtocol);
%% @hidden
add_usm_user(EngineID, UserName, SecName, usmHMACMD5AuthProtocol, usmAesCfb128Protocol, AuthPass, PrivPass)
		when is_list(EngineID), is_list(UserName) ->
	AuthKey = snmp:passwd2localized_key(md5, AuthPass, EngineID),
	PrivKey = snmp:passwd2localized_key(md5, PrivPass, EngineID),
	Conf = [{sec_name, SecName}, {auth, usmHMACMD5AuthProtocol}, {auth_key, AuthKey},
			{priv, usmAesCfb128Protocol}, {priv_key, PrivKey}],
	add_usm_user1(EngineID, UserName, Conf, usmHMACMD5AuthProtocol, usmAesCfb128Protocol);
%% @hidden
add_usm_user(EngineID, UserName, SecName, usmHMACSHAAuthProtocol, usmNoPrivProtocol, AuthPass, _PrivPass)
		when is_list(EngineID), is_list(UserName) ->
	AuthKey = snmp:passwd2localized_key(sha, AuthPass, EngineID),
	Conf = [{sec_name, SecName}, {auth, usmHMACSHAAuthProtocol}, {auth_key, AuthKey},
			{priv, usmNoPrivProtocol}],
	add_usm_user1(EngineID, UserName, Conf, usmHMACSHAAuthProtocol, usmNoPrivProtocol);
%% @hidden
add_usm_user(EngineID, UserName, SecName, usmHMACSHAAuthProtocol, usmDESPrivProtocol, AuthPass, PrivPass)
		when is_list(EngineID), is_list(UserName) ->
	AuthKey = snmp:passwd2localized_key(sha, AuthPass, EngineID),
	PrivKey = snmp:passwd2localized_key(sha, PrivPass, EngineID),
	Conf = [{sec_name, SecName}, {auth, usmHMACSHAAuthProtocol}, {auth_key, AuthKey},
			{priv, usmDESPrivProtocol}, {priv_key, PrivKey}],
	add_usm_user1(EngineID, UserName, Conf, usmHMACSHAAuthProtocol, usmDESPrivProtocol);
%% @hidden
add_usm_user(EngineID, UserName, SecName, usmHMACSHAAuthProtocol, usmAesCfb128Protocol, AuthPass, PrivPass)
		when is_list(EngineID), is_list(UserName) ->
	AuthKey = snmp:passwd2localized_key(sha, AuthPass, EngineID),
	PrivKey = snmp:passwd2localized_key(sha, PrivPass, EngineID),
	Conf = [{sec_name, SecName}, {auth, usmHMACSHAAuthProtocol}, {auth_key, AuthKey},
			{priv, usmAesCfb128Protocol}, {priv_key, PrivKey}],
	add_usm_user1(EngineID, UserName, Conf, usmHMACSHAAuthProtocol, usmAesCfb128Protocol).
%% @hidden
add_usm_user1(EngineID, UserName, Conf, AuthProtocol, PrivProtocol)
		when is_list(EngineID), is_list(UserName) ->
	case snmpm:register_usm_user(EngineID, UserName, Conf) of
		ok ->
			{usm_user_added, AuthProtocol, PrivProtocol};
		{error, Reason} ->
			{error, Reason}
	end.

-spec stringify(String) -> Result
	when
		String :: string(),
		Result :: string().
%% @doc JSON encode a string.
%% @private
stringify(String) ->
	stringify1(String, []).
%% @hidden
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
stringify1([H | T], Acc) ->
	stringify1(T, [H | Acc]);
stringify1([], Acc) ->
	lists:reverse(Acc).

-spec destringify(String) -> Result
	when
		String :: string(),
		Result :: string().
%% @doc JSON encode a string.
%% @private
destringify(String) ->
	destringify1(String, []).
%% @hidden
destringify1([$\\, $b| T], Acc) ->
	destringify1(T, [$\b | Acc]);
destringify1([$\\, $d | T], Acc) ->
	destringify1(T, [$\d | Acc]);
destringify1([$\\, $e | T], Acc) ->
	destringify1(T, [$\e | Acc]);
destringify1([$\\, $f | T], Acc) ->
	destringify1(T, [$\f | Acc]);
destringify1([$\n | T], Acc) ->
	destringify1(T, Acc);
destringify1([$\\, $r | T], Acc) ->
	destringify1(T, [$\r | Acc]);
destringify1([$\\, $t | T], Acc) ->
	destringify1(T, [$\t | Acc]);
destringify1([$\\, $v | T], Acc) ->
	destringify1(T, [$\v | Acc]);
destringify1([H | T], Acc) ->
	destringify1(T, [H | Acc]);
destringify1([], Acc) ->
	lists:reverse(Acc).

-spec auth_key(AuthProtocol, AuthPass, EngineID) -> AuthKey
	when
		AuthProtocol :: usmNoAuthProtocol | usmHMACMD5AuthProtocol | usmHMACSHAAuthProtocol,
		AuthPass :: list(),
		EngineID :: list(),
		AuthKey :: list().
%% @doc Generates a key that can be used as an authentication using MD5 or SHA.
auth_key(usmNoAuthProtocol, AuthPass, EngineID)
		when is_list(AuthPass), is_list(EngineID) ->
	[];
auth_key(usmHMACMD5AuthProtocol, AuthPass, EngineID)
		when is_list(AuthPass), is_list(EngineID) ->
	snmp:passwd2localized_key(md5, AuthPass, EngineID);
auth_key(usmHMACSHAAuthProtocol, AuthPass, EngineID)
		when is_list(AuthPass), is_list(EngineID) ->
	snmp:passwd2localized_key(sha, AuthPass, EngineID).

