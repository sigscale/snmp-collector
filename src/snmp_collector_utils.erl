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

-include("snmp_collector.hrl").

-export([iso8601/1, oid_to_name/1, get_name/1, generate_identity/1,
		arrange_list/1, stringify/1, log_events/2, security_params/7,
		agent_name/1, oids_to_names/2, generate_maps/2, engine_id/0,
		authenticate_v1_v2/2, check_fields/1]).

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

-spec date(MilliSeconds) -> DateTime
	when
		MilliSeconds :: pos_integer(),
		DateTime :: calendar:datetime().
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
	iso8601minute(Date, Hour, T);
iso8601hour(Date, Other) ->
erlang:display({?MODULE, ?LINE, Date, Other}), exit(badarg).
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

-spec generate_maps(TargetName, AlarmDetails) -> Result
	when
		TargetName :: list(),
		AlarmDetails :: [{Name, Value}],
		Name :: list(),
		Value :: list(),
		Result :: {CommonEventHeader, FaultFields},
		CommonEventHeader :: map(),
		FaultFields :: map().
%% @doc Generate the Common event header and Fault Fields maps.
generate_maps(TargetName, AlarmDetails) ->
	{CommonEventHeader, Remainder} = common_event_header(TargetName, AlarmDetails),
	FaultFields = fault_fields(Remainder),
	{check_fields(CommonEventHeader), check_fields(FaultFields)}.

-spec check_fields(VesMap) -> Result
	when
		VesMap :: map(),
		Result :: map().
%% @doc Check and replace empty values in mandatory fields.
check_fields(#{"eventName" := Value} = VesMap)
		when is_atom(Value), length(Value) > 0 ->
	check_fields1(VesMap);
check_fields(VesMap) ->
	check_fields1(VesMap#{"eventName" => ?EN_NEW}).
%% @hidden
check_fields1(#{"eventSeverity" := Value} = VesMap)
		when is_list(Value), length(Value) > 0 ->
	check_fields2(VesMap);
check_fields1(VesMap) ->
	check_fields2(VesMap#{"eventSeverity" => ?ES_INDETERMINATE}).
%% @hidden
check_fields2(#{"probableCause" := Value} = VesMap)
		when is_list(Value), length(Value) > 0 ->
	check_fields3(VesMap);
check_fields2(VesMap) ->
	check_fields3(VesMap#{"probableCause" => ?PC_Indeterminate}).
%% @hidden
check_fields3(#{"eventType" := Value} = VesMap)
		when is_list(Value), length(Value) > 0 ->
	VesMap;
check_fields3(VesMap) ->
	VesMap#{"eventType" => ?ET_Communication_System}.

-spec common_event_header(TargetName, AlarmDetails) -> Result
	when
		AlarmDetails :: [{Name, Value}],
		Name :: list(),
		TargetName :: string(),
		Value :: list(),
		Result :: {map(), AlarmDetails}.
%% @doc Create the VES common event header map.
common_event_header(TargetName, AlarmDetails)
		when is_list(TargetName), is_list(AlarmDetails) ->
	DefaultMap = #{"domain" => "fault",
			"eventId" => event_id(),
			"lastEpochMicrosec" => timestamp(),
			"priority" => "Normal",
			"reportingEntityName" => TargetName,
			"sequence" => 0,
			"version" => 1},
	common_event_header(AlarmDetails, TargetName, DefaultMap, []).
%% @hidden
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
	common_event_header(T, TargetName, CH#{"startEpochMicrosec" => iso8601(Value)}, AD);
common_event_header([H | T], TargetName, CH, AD) ->
	common_event_header(T, TargetName, CH, [H | AD]);
common_event_header([], _TargetName, CH, AD) ->
	{CH, AD}.

-spec fault_fields(AlarmDetails) -> FaultFields
	when
		AlarmDetails :: [{Name, Value}],
		Name :: list(),
		Value :: list(),
		FaultFields :: map().
%% @doc Create the fault fields map.
fault_fields(AlarmDetails) when is_list(AlarmDetails) ->
	DefaultMap = #{"alarmAdditionalInformation" => [],
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
fault_fields([{Name, Value} | T],
		#{"alarmAdditionalInformation" := AI} = Acc) ->
	NewAI = [#{"name" => Name, "value" => Value} | AI],
	fault_fields(T, Acc#{"alarmAdditionalInformation" => NewAI});
fault_fields([], Acc) ->
	Acc.

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
			AuthKey = generate_key(AuthProtocol, AuthPass, EngineID),
			case authenticate_v3(AuthProtocol, AuthKey, AuthParms ,Packet) of
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
					case ets:match(snmpm_agent_table, {{TargetName,sec_model}, '$1'}) of
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

-spec log_events(CommonEventHeader, FaultFields) -> Result
   when
		CommonEventHeader :: map(), FaultFields :: map(),
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Log the event to disk.
%% @private
log_events(CommonEventHeader, FaultFields)
		when is_map(CommonEventHeader), is_map(FaultFields) ->
	{ok, LogName} = application:get_env(snmp_collector, queue_name),
	{ok, Url} = application:get_env(snmp_collector, ves_url),
	TimeStamp = erlang:system_time(milli_seconds),
	Identifer = erlang:unique_integer([positive]),
	Node = node(),
	Event = {TimeStamp, Identifer, Node, CommonEventHeader, FaultFields},
	case disk_log:log(LogName, Event) of
		ok ->
			post_event(CommonEventHeader, FaultFields, Url);
		{error, Reason} ->
			error_logger:info_report(["SNMP Manager Event Logging Failed",
					{timestamp, TimeStamp},
					{identifier, Identifer},
					{node, Node},
					{reason, Reason}]),
			{error, Reason}
	end.

-spec post_event(CommonEventHeader, FaultFields, Url) -> ok
   when
		CommonEventHeader :: map(),
		FaultFields :: map(),
		Url :: inet:ip_address() | [].
%% @doc Log the event to disk.
post_event(_CommonEventHeader, _FaultFields, []) ->
	ok;
post_event(CommonEventHeader, FaultFields, Url)
		when is_map(CommonEventHeader), is_map(FaultFields), is_list(Url) ->
	{ok, UserName } = application:get_env(snmp_collector, ves_username),
	{ok, Password} = application:get_env(snmp_collector, ves_password),
	ContentType = "application/json",
	Accept = {"accept", "application/json"},
	EncodeKey = "Basic" ++ base64:encode_to_string(string:concat(UserName ++ ":", Password)),
	Authentication = {"authorization", EncodeKey},
	Event = #{"event" => #{"commonEventHeader" => CommonEventHeader, "faultFields" => FaultFields}},
	RequestBody = zj:encode(Event),
	Request = {Url ++ "/eventListener/v5", [Accept, Authentication], ContentType, RequestBody},
	case httpc:request(post, Request, [],
		[{sync, false}, {receiver, fun check_response/1}]) of
			{error, Reason} ->
				error_logger:info_report(["SNMP Manager POST Failed",
						{error, Reason}]);
			_RequestID ->
				ok
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
arrange_list([{vabind, [1,3,6,1,2,1,1,3,0], 'TimeTicks', _Value, _Seqnum} | T], Acc) ->
	arrange_list(T, Acc);
arrange_list([{varbind, OID, Type, Value, _Seqnum} | T], Acc)
		when Type == 'OCTET STRING', is_list(Value) ->
	case unicode:characters_to_list(Value, utf8) of
		Value2 when is_list(Value2) ->
			arrange_list(T, [{OID, (Value2)} | Acc]);
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
		Result :: {ok, [{Name, Value}]},
		Name :: string().
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
check_response({_RequestId, {{"HTTP/1.1",400, _BadRequest},_ , _}}) ->
	error_logger:info_report(["SNMP Manager POST Failed",
			{error, "400, bad_request"}]);
check_response({_RequestId, {{"HTTP/1.1",500, _InternalError},_ , _}}) ->
	error_logger:info_report(["SNMP Manager POST Failed",
			{error, "500, internal_server_error"}]);
check_response({_RequestId, {{"HTTP/1.1",502, _GateWayError},_ , _}}) ->
	error_logger:info_report(["SNMP Manager POST Failed",
			{error, "502, bad_gateway"}]);
check_response({_RequestId, {{"HTTP/1.1",201, _Created},_ , _}}) ->
	void.

-spec strip_name(Name) -> Name
	when
		Name :: string().
%% @doc Removes the index from required names.
strip_name(Name) ->
	case string:tokens(Name, ".") of
		[StripedName, _Index] ->
			StripedName;
		[Name] ->
			Name
	end.

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

-spec authenticate_v3(AuthProtocol, AuthKey, AuthParams, Packet) -> Result
	when
		AuthProtocol :: usmNoAuthProtocol | usmHMACMD5AuthProtocol | usmHMACSHAAuthProtocol,
		AuthKey :: [byte()],
		AuthParams :: list(),
		Packet :: [byte()],
		Result :: true | false.
%% @doc Authenticate the SNMP agent.
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
	AuthKey = generate_key(usmHMACMD5AuthProtocol, AuthPass, EngineID),
	Conf = [{sec_name, SecName}, {auth, usmHMACMD5AuthProtocol}, {priv, usmNoPrivProtocol},
			{auth_key, AuthKey}],
	add_usm_user1(EngineID, UserName, Conf, usmHMACMD5AuthProtocol, usmNoPrivProtocol);
%% @hidden
add_usm_user(EngineID, UserName, SecName, usmHMACMD5AuthProtocol, usmDESPrivProtocol, AuthPass, PrivPass)
		when is_list(EngineID), is_list(UserName) ->
	AuthKey = generate_key(usmHMACMD5AuthProtocol, AuthPass, EngineID),
	PrivKey = generate_key(usmHMACMD5AuthProtocol, PrivPass, EngineID),
	Conf = [{sec_name, SecName}, {auth, usmHMACMD5AuthProtocol}, {auth_key, AuthKey},
			{priv, usmDESPrivProtocol}, {priv_key, PrivKey}],
	add_usm_user1(EngineID, UserName, Conf, usmHMACMD5AuthProtocol, usmDESPrivProtocol);
%% @hidden
add_usm_user(EngineID, UserName, SecName, usmHMACMD5AuthProtocol, usmAesCfb128Protocol, AuthPass, PrivPass)
		when is_list(EngineID), is_list(UserName) ->
	AuthKey = generate_key(usmHMACMD5AuthProtocol, AuthPass, EngineID),
	PrivKey = generate_key(usmHMACMD5AuthProtocol, PrivPass, EngineID),
	Conf = [{sec_name, SecName}, {auth, usmHMACMD5AuthProtocol}, {auth_key, AuthKey},
			{priv, usmAesCfb128Protocol}, {priv_key, PrivKey}],
	add_usm_user1(EngineID, UserName, Conf, usmHMACMD5AuthProtocol, usmAesCfb128Protocol);
%% @hidden
add_usm_user(EngineID, UserName, SecName, usmHMACSHAAuthProtocol, usmNoPrivProtocol, AuthPass, _PrivPass)
		when is_list(EngineID), is_list(UserName) ->
	AuthKey = generate_key(usmHMACSHAAuthProtocol, AuthPass, EngineID),
	Conf = [{sec_name, SecName}, {auth, usmHMACSHAAuthProtocol}, {auth_key, AuthKey},
			{priv, usmNoPrivProtocol}],
	add_usm_user1(EngineID, UserName, Conf, usmHMACSHAAuthProtocol, usmNoPrivProtocol);
%% @hidden
add_usm_user(EngineID, UserName, SecName, usmHMACSHAAuthProtocol, usmDESPrivProtocol, AuthPass, PrivPass)
		when is_list(EngineID), is_list(UserName) ->
	AuthKey = generate_key(usmHMACSHAAuthProtocol, AuthPass, EngineID),
	PrivKey = lists:sublist(generate_key(usmHMACSHAAuthProtocol, PrivPass, EngineID), 16),
	Conf = [{sec_name, SecName}, {auth, usmHMACSHAAuthProtocol}, {auth_key, AuthKey},
			{priv, usmDESPrivProtocol}, {priv_key, PrivKey}],
	add_usm_user1(EngineID, UserName, Conf, usmHMACSHAAuthProtocol, usmDESPrivProtocol);
%% @hidden
add_usm_user(EngineID, UserName, SecName, usmHMACSHAAuthProtocol, usmAesCfb128Protocol, AuthPass, PrivPass)
		when is_list(EngineID), is_list(UserName) ->
	AuthKey = generate_key(usmHMACSHAAuthProtocol, AuthPass, EngineID),
	PrivKey = lists:sublist(generate_key(usmHMACSHAAuthProtocol, PrivPass, EngineID), 16),
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

