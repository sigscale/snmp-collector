%%% snmp_collector_rest_res_event.erl
%%% vim: ts=3
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% @copyright 2018-2019 SigScale Global Inc.
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
%%% @doc This library module implements resource handling functions.
%%%
-module(snmp_collector_rest_res_event).
-copyright('Copyright (c) 2018-2019 SigScale Global Inc.').

-export([content_types_accepted/0, content_types_provided/0, get_events/2]).

-include("snmp_collector_log.hrl").

-define(eventPath, "/eventManagement/v1/event/").

%% support deprecated_time_unit()
-define(MILLISECOND, milli_seconds).
%-define(MILLISECOND, millisecond).

%%----------------------------------------------------------------------
%%  The snmp_collector_rest_res_event API
%%----------------------------------------------------------------------

-spec content_types_accepted() -> ContentTypes
	when
		ContentTypes :: list().
%% @doc Provides list of resource representations accepted.
content_types_accepted() ->
	["application/json"].

-spec content_types_provided() -> ContentTypes
	when
		ContentTypes :: list().
%% @doc Provides list of resource representations available.
content_types_provided() ->
	["application/json"].

-spec get_events(Query, Headers) -> Result
	when
		Query :: [{Key :: string(), Value :: string()}],
		Headers :: [tuple()],
		Result :: {ok, Headers :: [tuple()], Body :: iolist()}
				| {error, ErrorCode :: integer()}.
%% @doc Body producing function for
%%		`GET /eventManagement/v1/event'
%%		requests.
%% @hidden
get_events(Query, Headers) ->
	case lists:keytake("fields", 1, Query) of
		{value, {_, Filters}, NewQuery} ->
			get_events1(NewQuery, Filters, Headers);
		false ->
			get_events1(Query, [], Headers)
	end.
%% @hidden
get_events1(Query, Filters, Headers) ->
	case {lists:keyfind("if-match", 1, Headers),
			lists:keyfind("if-range", 1, Headers),
			lists:keyfind("range", 1, Headers)} of
		{{"if-match", Etag}, false, {"range", Range}} ->
			case global:whereis_name(Etag) of
				undefined ->
					{error, 412};
				PageServer ->
					case snmp_collector_rest:range(Range) of
						{error, _} ->
							{error, 400};
						{ok, {Start, End}} ->
							query_page(PageServer, Etag, Query, Filters, Start, End)
					end
			end;
		{{"if-match", Etag}, false, false} ->
			case global:whereis_name(Etag) of
				undefined ->
					{error, 412};
				PageServer ->
					query_page(PageServer, Etag, Query, Filters, undefined, undefined)
			end;
		{false, {"if-range", Etag}, {"range", Range}} ->
			case global:whereis_name(Etag) of
				undefined ->
					case snmp_collector_rest:range(Range) of
						{error, _} ->
							{error, 400};
						{ok, {Start, End}} ->
							query_start(Query, Filters, Start, End)
					end;
				PageServer ->
					case snmp_collector_rest:range(Range) of
						{error, _} ->
							{error, 400};
						{ok, {Start, End}} ->
							query_page(PageServer, Etag, Query, Filters, Start, End)
					end
			end;
		{{"if-match", _}, {"if-range", _}, _} ->
			{error, 400};
		{_, {"if-range", _}, false} ->
			{error, 400};
		{false, false, {"range", "items=1-" ++ _ = Range}} ->
			case snmp_collector_rest:range(Range) of
				{error, _Reason} ->
					{error, 400};
				{ok, {Start, End}} ->
					query_start(Query, Filters, Start, End)
			end;
		{false, false, {"range", _Range}} ->
			{error, 416};
		{false, false, false} ->
			query_start(Query, Filters, undefined, undefined)
	end.

%%----------------------------------------------------------------------
%%  internal functions
%%----------------------------------------------------------------------

%% @hidden
match_header([{"sourceName", _Op, _Value} = H | T] = _Filter, Acc) ->
	match_header(T, match(H, Acc));
match_header([{"sourceId", _Op, _Value} = H | T] = _Filter, Acc) ->
	match_header(T, match(H, Acc));
match_header([{"eventId", _Op, _Value} = H | T] = _Filter, Acc) ->
	match_header(T, match(H, Acc));
match_header([{"eventName", _Op, _Value} = H | T] = _Filter, Acc) ->
	match_header(T, match(H, Acc));
match_header([{"priority", _Op, _Value} = H | T] = _Filter, Acc) ->
	match_header(T, match(H, Acc));
match_header([{"reportingEntityName", _Op, _Value} = H | T] = _Filter, Acc) ->
	match_header(T, match(H, Acc));
match_header([{"lastEpochMicrosec", _Op, _Value} = H | T] = _Filter, Acc) ->
	match_header(T, match(H, Acc));
match_header([_H | T] = _Filter, Acc) ->
	match_header(T, Acc);
match_header([], []) ->
	'_';
match_header([], Acc) ->
	lists:reverse(Acc).
%% @hidden
match({Key, like, [Value]}, Acc) ->
	case lists:last(Value) of
		$% ->
			Prefix = lists:droplast(Value),
			[{Key, {like, [Prefix]}} | Acc];
		_ ->
			[{Key, {like, [Value]}} | Acc]
	end.

%% @hidden
match_fields([{"eventCharacteristic", contains, Value} | T] = _Filter, Acc) ->
	match_fields(T, match_fields1(Value, Acc));
match_fields([_Value | T] = _Filter, Acc) ->
	match_fields(T, Acc);
match_fields([], []) ->
	'_';
match_fields([], Acc) ->
	lists:reverse(Acc).
%% @hidden
match_fields1([{complex, [{"name", exact, Key}, {"value", like, Like}]}], Acc) ->
	match({Key, like, Like}, Acc).
	
%% @hidden
query_start(Query, Filters, RangeStart, RangeEnd) ->
	{DateStart, DateEnd} = case lists:keyfind("date", 1, Query) of
		{_, DateTime} when length(DateTime) > 3 ->
			range(DateTime);
		false ->
			{1, erlang:system_time(?MILLISECOND)}
	end,
	query_start1(Query, Filters, RangeStart, RangeEnd, DateStart, DateEnd).
%% @hidden
query_start1(Query, Filters, RangeStart, RangeEnd, DateStart, DateEnd) ->
	try
		case lists:keyfind("filter", 1, Query) of
			{_, String} ->
				{ok, Tokens, _} = snmp_collector_rest_query_scanner:string(String),
				case snmp_collector_rest_query_parser:parse(Tokens) of
					{ok, [{array, [{complex, Filter}]}]} ->
						HeaderMatch = match_header(Filter, []),
						FieldsMatch = match_fields(Filter, []),
						MFA = [snmp_collector_log, fault_query, [DateStart, DateEnd, HeaderMatch, FieldsMatch]],
						case supervisor:start_child(snmp_collector_rest_pagination_sup, [MFA]) of
							{ok, PageServer, Etag} ->
								query_page(PageServer, Etag, Query, Filters, RangeStart, RangeEnd);
							{error, _Reason} ->
								{error, 500}
						end
				end;
			false ->
				MFA1 = [snmp_collector_log, fault_query, [DateStart, DateEnd, '_', '_']],
				case supervisor:start_child(snmp_collector_rest_pagination_sup, [MFA1]) of
					{ok, PageServer1, Etag1} ->
						query_page(PageServer1, Etag1, Query, Filters, RangeStart, RangeEnd);
					{error, _Reason1} ->
						{error, 500}
				end
		end
	catch
		_:_ ->
			{error, 400}
	end.
%% display here for Token error
%% @hidden
query_page(PageServer, Etag, _Query, _Filters, Start, End) ->
	case gen_server:call(PageServer, {Start, End}, infinity) of
		{error, Status} ->
			{error, Status};
		{Events, ContentRange} ->
			JsonObj = lists:map(fun event/1, Events),
			Body = zj:encode(JsonObj),
			Headers = [{content_type, "application/json"},
				{etag, Etag}, {accept_ranges, "items"},
				{content_range, ContentRange}],
			{ok, Headers, Body}
	end.

%% @hidden
range([Y1, Y2, Y3, Y4 | T] = DateTime)
		when Y1 >= $0, Y1 =< $9, Y2 >= $0, Y2 =< $9,
		Y3 >= $0, Y3 =< $9, Y4 >= $0, Y4 =< $9 ->
	{snmp_collector_log:iso8601(DateTime), range([Y1, Y2, Y3, Y4], T)}.
%% @hidden
range(Year, []) ->
	EndYear = list_to_integer(Year) + 1,
	End = lists:flatten(io_lib:fwrite("~4.10.0b", [EndYear])),
	snmp_collector_log:iso8601(End) - 1;
range(Year, "-") ->
	range(Year, []);
range(Year, "-0") ->
	snmp_collector_log:iso8601(Year ++ "-10-01") - 1;
range(Year, "-1") ->
	EndYear = list_to_integer(Year) + 1,
	End = lists:flatten(io_lib:fwrite("~4.10.0b", [EndYear])),
	snmp_collector_log:iso8601(End) - 1;
range(Year, [$-, $0, N]) when N >= $1, N =< $8 ->
	snmp_collector_log:iso8601(Year ++ [$-, $0, N + 1]) - 1;
range(Year, "-09") ->
	snmp_collector_log:iso8601(Year ++ "-10") - 1;
range(Year, "-10") ->
	snmp_collector_log:iso8601(Year ++ "-11") - 1;
range(Year, "-11") ->
	snmp_collector_log:iso8601(Year ++ "-12") - 1;
range(Year, "-12") ->
	EndYear = list_to_integer(Year) + 1,
	End = lists:flatten(io_lib:fwrite("~4.10.0b", [EndYear])),
	snmp_collector_log:iso8601(End) - 1;
range(Year, [$-, M1, M2, $-]) ->
	range(Year, [$-, M1, M2]);
range(Year, [$-, M1, M2, $-, $0]) ->
	snmp_collector_log:iso8601(Year ++ [$-, M1, M2, $-, $1, $0]) - 1;
range(Year, [$-, M1, M2, $-, $1]) ->
	snmp_collector_log:iso8601(Year ++ [$-, M1, M2, $-, $2, $0]) - 1;
range(Year, "-02-2") ->
	snmp_collector_log:iso8601(Year ++ "-03") - 1;
range(Year, [$-, M1, M2, $-, $2]) ->
	snmp_collector_log:iso8601(Year ++ [$-, M1, M2, $-, $3, $0]) - 1;
range(Year, "-12-3") ->
	EndYear = list_to_integer(Year) + 1,
	End = lists:flatten(io_lib:fwrite("~4.10.0b", [EndYear])),
	snmp_collector_log:iso8601(End) - 1;
range(Year, [$-, M1, M2, $-, $3]) ->
	Month = list_to_integer([M1, M2]) + 1,
	End = lists:flatten(io_lib:fwrite("-~2.10.0b", [Month])),
	snmp_collector_log:iso8601(Year ++ End) - 1;
range(Year, "-02-29") ->
	snmp_collector_log:iso8601(Year ++ "-03-01") - 1;
range(Year, "-02-28") ->
	case calendar:last_day_of_the_month(list_to_integer(Year), 2) of
		28 ->
			snmp_collector_log:iso8601(Year ++ "-03-01") - 1;
		29 ->
			snmp_collector_log:iso8601(Year ++ "-02-29") - 1
	end;
range(Year, [$-, M1, M2, $-, $0, $9]) ->
	snmp_collector_log:iso8601(Year ++ [$-, M1, M2, $-, $1, $0]) - 1;
range(Year, [$-, M1, M2, $-, $0, D2]) ->
	snmp_collector_log:iso8601(Year ++ [$-, M1, M2, $-, $0, D2 + 1]) - 1;
range(Year, [$-, M1, M2, $-, $1, $9]) ->
	snmp_collector_log:iso8601(Year ++ [$-, M1, M2, $-, $2, $0]) - 1;
range(Year, [$-, M1, M2, $-, $1, D2]) ->
	snmp_collector_log:iso8601(Year ++ [$-, M1, M2, $-, $1, D2 + 1]) - 1;
range(Year, [$-, M1, M2, $-, $2, $9]) ->
	snmp_collector_log:iso8601(Year ++ [$-, M1, M2, $-, $3, $0]) - 1;
range(Year, [$-, $0, $4, $-, $3, $0]) ->
	snmp_collector_log:iso8601(Year ++ [$-, $0, $5, $-, $0, $1]) - 1;
range(Year, [$-, $0, $6, $-, $3, $0]) ->
	snmp_collector_log:iso8601(Year ++ [$-, $0, $7, $-, $0, $1]) - 1;
range(Year, [$-, $0, $9, $-, $3, $0]) ->
	snmp_collector_log:iso8601(Year ++ [$-, $1, $0, $-, $0, $1]) - 1;
range(Year, [$-, $1, $1, $-, $3, $0]) ->
	snmp_collector_log:iso8601(Year ++ [$-, $1, $2, $-, $0, $1]) - 1;
range(Year, [$-, $1, $2, $-, $3, $1]) ->
	EndYear = list_to_integer(Year) + 1,
	End = lists:flatten(io_lib:fwrite("~4.10.0b", [EndYear])),
	snmp_collector_log:iso8601(End) - 1;
range(Year, [$-, M1, M2, $-, $3, $0]) ->
	snmp_collector_log:iso8601(Year ++ [$-, M1, M2, $-, $3, $1]) - 1;
range(Year, [$-, M1, M2, $-, D1, D2, $T]) ->
	range(Year, [$-, M1, M2, $-, D1, D2]);
range(Year, [$-, M1, M2, $-, D1, D2, $T | T]) ->
	range(Year, [$-, M1, M2, $-, D1, D2, $T], T).
%% @hidden
range(Year, Day, [$0]) ->
	snmp_collector_log:iso8601(Year ++ Day ++ "10") - 1;
range(Year, Day, [$1]) ->
	snmp_collector_log:iso8601(Year ++ Day ++ "20") - 1;
range(Year, Day, [$2]) ->
	snmp_collector_log:iso8601(Year ++ Day ++ "24") - 1;
range(Year, Day, "09") ->
	snmp_collector_log:iso8601(Year ++ Day ++ "10") - 1;
range(Year, Day, [$0, N]) ->
	snmp_collector_log:iso8601(Year ++ Day ++ [$0, N + 1]) - 1;
range(Year, Day, "19") ->
	snmp_collector_log:iso8601(Year ++ Day ++ "20") - 1;
range(Year, Day, [$1, N]) ->
	snmp_collector_log:iso8601(Year ++ Day ++ [$1, N + 1]) - 1;
range(Year, Day, [$2, N]) when N >= $0, N =< $3 ->
	snmp_collector_log:iso8601(Year ++ Day ++ [$1, N + 1]) - 1;
range(Year, Day, [H1, H2, $:]) ->
	range(Year, Day, [H1, H2]);
range(Year, Day, [H1, H2, $:, $5]) ->
	Hour = list_to_integer([H1, H2]) + 1,
	End = lists:flatten(io_lib:fwrite("~2.10.0b", [Hour])),
	snmp_collector_log:iso8601(Year ++ Day ++ End) - 1;
range(Year, Day, [H1, H2, $:, M]) ->
	snmp_collector_log:iso8601(Year ++ Day ++ [H1, H2, $:, M + 1]) - 1;
range(Year, Day, [H1, H2, $:, $5, $9]) ->
	Hour = list_to_integer([H1, H2]) + 1,
	End = lists:flatten(io_lib:fwrite("~2.10.0b", [Hour])),
	snmp_collector_log:iso8601(Year ++ Day ++ End) - 1;
range(Year, Day, [H1, H2, $:, M, $9]) ->
	snmp_collector_log:iso8601(Year ++ Day ++ [H1, H2, $:, M + 1, $0]) - 1;
range(Year, Day, [H1, H2, $:, M1, M2]) ->
	snmp_collector_log:iso8601(Year ++ Day ++ [H1, H2, $:, M1, M2 + 1]) - 1;
range(Year, Day, [H1, H2, $:, M1, M2, $:]) ->
	range(Year, Day, [H1, H2, $:, M1, M2]);
range(Year, Day, [H1, H2, $:, $5, $9, $:, $5]) ->
	Hour = list_to_integer([H1, H2]) + 1,
	End = lists:flatten(io_lib:fwrite("~2.10.0b", [Hour])),
	snmp_collector_log:iso8601(Year ++ Day ++ End) - 1;
range(Year, Day, [H1, H2, $:, M1, M2, $:, $5]) ->
	Minute = list_to_integer([M1, M2]) + 1,
	End = lists:flatten(io_lib:fwrite("~2.10.0b", [Minute])),
	snmp_collector_log:iso8601(Year ++ Day ++ [H1, H2, $:] ++ End) - 1;
range(Year, Day, [H1, H2, $:, M1, M2, $:, N]) ->
	snmp_collector_log:iso8601(Year ++ Day ++ [H1, H2, $:, M1, M2, $:, N + 1]) - 1;
range(Year, Day, [H1, H2, $:, $5, $9, $:, $5, $9]) ->
	Hour = list_to_integer([H1, H2]) + 1,
	End = lists:flatten(io_lib:fwrite("~2.10.0b", [Hour])),
	snmp_collector_log:iso8601(Year ++ Day ++ End) - 1;
range(Year, Day, [H1, H2, $:, M1, M2, $:, $5, $9]) ->
	Minute = list_to_integer([M1, M2]) + 1,
	End = lists:flatten(io_lib:fwrite("~2.10.0b", [Minute])),
	snmp_collector_log:iso8601(Year ++ Day ++ [H1, H2, $:] ++ End) - 1;
range(Year, Day, [H1, H2, $:, M1, M2, $:, S1, $9]) ->
	snmp_collector_log:iso8601(Year ++ Day ++ [H1, H2, $:, M1, M2, $:, S1 + 1, $0]) - 1;
range(Year, Day, [H1, H2, $:, M1, M2, $:, S1, S2]) ->
	snmp_collector_log:iso8601(Year ++ Day ++ [H1, H2, $:, M1, M2, $:, S1, S2 + 1]) - 1;
range(Year, Day, [H1, H2, $:, M1, M2, $:, S1, S2, $.]) ->
	range(Year, Day, [H1, H2, $:, M1, M2, $:, S1, S2]);
range(Year, Day, [_, _, $:, _, _, $:, _, _, $., _] = S) ->
	snmp_collector_log:iso8601(Year ++ Day ++ S ++ "99");
range(Year, Day, [_, _, $:, _, _, $:, _, _, $., _, _] = S) ->
	snmp_collector_log:iso8601(Year ++ Day ++ S ++ "9");
range(Year, Day, [_, _, $:, _, _, $:, _, _, $., _, _ | _] = S) ->
	snmp_collector_log:iso8601(Year ++ Day ++ S).

-spec event(Event) -> Event 
	when
		Event :: fault_event() | map().
%% @hidden
event({Timestamp, N, _Node, Header, Fields}) ->
	Event = #{"id" => integer_to_list(Timestamp) ++ "-" ++ integer_to_list(N),
			"timeReceived" => snmp_collector_log:iso8601(Timestamp)},
	event1(Header, Fields, Event).
%% @hidden
event1(#{"sourceName" := SourceName} = Header, Fields, Acc)
		when is_list(SourceName) ->
	event2(Header, Fields, Acc#{"sourceSystem" => SourceName});
event1(Header, Fields, Acc) ->
	event2(Header, Fields, Acc).
%% @hidden
event2(#{"sourceId" := SourceId} = Header, Fields, Acc)
		when is_list(SourceId) ->
	event3(Header, Fields, Acc#{"sourceSystemId" => SourceId});
event2(Header, Fields, Acc) ->
	event3(Header, Fields, Acc).
%% @hidden
event3(#{"eventId" := EventId} = Header, Fields, Acc)
		when is_list(EventId) ->
	event4(Header, Fields, Acc#{"eventId" => EventId});
event3(Header, Fields, Acc) ->
	event4(Header, Fields, Acc).
%% @hidden
event4(#{"eventName" := EventName} = Header, Fields, Acc)
		when is_list(EventName) ->
	event5(Header, Fields, Acc#{"eventName" => EventName});
event4(Header, Fields, Acc) ->
	event5(Header, Fields, Acc).
%% @hidden
event5(#{"priority" := Priority} = Header, Fields, Acc)
		when is_list(Priority) ->
	event6(Header, Fields, Acc#{"significance" => Priority});
event5(Header, Fields, Acc) ->
	event6(Header, Fields, Acc).
%% @hidden
event6(#{"reportingEntityName" := ReportEntity} = Header, Fields, Acc)
		when is_list(ReportEntity) ->
	event7(Header, Fields, Acc#{"reportingEntityName" => ReportEntity});
event6(Header, Fields, Acc) ->
	event7(Header, Fields, Acc).
%% @hidden
event7(#{"lastEpochMicrosec" := LastEpoch} = Header, Fields, Acc) ->
	event8(Header, Fields, Acc#{"timeStatusChanged" => snmp_collector_log:iso8601(LastEpoch)});
event7(Header, Fields, Acc) ->
	event8(Header, Fields, Acc).
%% @hidden
event8(_Header, Fields, Acc) ->
	maps:put("eventCharacteristic", maps:fold(fun fields/3, [], Fields), Acc).

%% @hidden
fields(Name, Value, Acc) ->
	[#{"name" => Name, "value" => Value} | Acc].

