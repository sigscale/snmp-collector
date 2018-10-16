%%%snmp_collector_utils.erl
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
-module(snmp_collector_utils).
-copyright('Copyright (c) 2016 - 2017 SigScale Global Inc.').

-export([iso8601/1, oid_to_name/1, get_name/1, generate_identity/1, strip/1]).

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
iso8601hour(Date, [$T, H1])
		when H1 >= $0, H1 =< $2 ->
	iso8601hour(Date, [$T, H1, $0]);
iso8601hour(Date, [$ , H1])
		when H1 >= $0, H1 =< $2 ->
	iso8601hour(Date, [$ , H1, $0]);
iso8601hour(Date, [$T, H1, H2 | T])
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
		lists:flatten(io_lib:fwrite("~s.~p", [Name, Rest]))
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

-spec strip(Value) -> Result
	when
		Value :: string(),
		Result :: string().
%% @doc Strip extra characters from inside a string.
%% @private
strip(Value) ->
	NewValue = lists:filter(fun strip1/1, Value),
	NewValue.
%% @hidden
strip1($") ->
	false;
strip1($\n) ->
	false;
strip1($\r) ->
	false;
strip1($	) ->
	false;
strip1($@) ->
	false;
strip1($/) ->
	false;
strip1(_) ->
	true.

