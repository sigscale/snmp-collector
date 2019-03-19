%%% snmp_collector_log.erl
%%% vim: ts=3
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% @copyright 2016 - 2019 SigScale Global Inc.
%%% @end
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%  http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%
-module(snmp_collector_log).
-copyright('Copyright (c) 2016 - 2019 SigScale Global Inc.').

%% export the snmp_collector_log_public API.
-export([fault_open/0, fault_close/0, fault_query/6]).
-export([httpd_logname/1, http_query/8, http_file/2, last/2]).
-export([dump_file/2, date/1, iso8601/1]).

%% exported the private function
-export([fault_filter/3]).

%% export the snmp_collector_log event types
-export_type([fault_event/0, http_event/0]).

-include("snmp_collector_log.hrl").

-define(FAULTLOG, fault).

%% support deprecated_time_unit()
-define(MILLISECOND, milli_seconds).
%-define(MILLISECOND, millisecond).

% calendar:datetime_to_gregorian_seconds({{1970,1,1},{0,0,0}})
-define(EPOCH, 62167219200).

%%----------------------------------------------------------------------
%%  The snmp_collecotr_log public API
%%----------------------------------------------------------------------

-spec fault_open() -> Result
	when
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Open the fault event disk log.
fault_open() ->
	{ok, Directory} = application:get_env(snmp_collector, queue_dir),
	{ok, LogSize} = application:get_env(snmp_collector, queue_size),
	{ok, LogFiles} = application:get_env(snmp_collector, queue_size),
	{ok, LogNodes} = application:get_env(snmp_collector, queue_nodes),
	open_log(Directory, ?FAULTLOG, LogSize, LogFiles, LogNodes).

-spec fault_close() -> Result
	when
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Close the fault disk log.
fault_close() ->
	close_log(?FAULTLOG).

-record(event,
		{host :: string(),
		user :: string() | undefined,
		date :: string() | undefined,
		method :: string() | undefined,
		uri :: string() | undefined,
		httpStatus :: integer() | undefined}).

-spec http_query(Continuation, LogType, DateTime, Host, User, Method, URI, HTTPStatus) -> Result
	when
		Continuation :: start | disk_log:continuation(),
		LogType ::  transfer | error | security,
		DateTime :: '_' | string(),
		Host :: '_' | string(),
		User :: '_' | string(),
		Method :: '_' | string(),
		URI :: '_' | string(),
		HTTPStatus :: '_' | string() | integer(),
		Result :: {Continuation2, Events} | {error, Reason},
		Continuation2 :: eof | disk_log:continuation(),
		Events :: [http_event()],
		Reason :: term().
%% @doc query http log events with filters
http_query(start, LogType, DateTime, Host, User, Method, URI, HTTPStatus) ->
	Log = httpd_logname(LogType),
	http_query1(disk_log:chunk(Log, start), Log,
		DateTime, Host, User, Method, URI, HTTPStatus, []);
http_query(Cont, LogType, DateTime, Host, User, Method, URI, HTTPStatus) ->
	Log = httpd_logname(LogType),
	http_query1(disk_log:chunk(Log, Cont), Log,
		DateTime, Host, User, Method, URI, HTTPStatus, []).
%% @hidden
http_query1({error, Reason}, _, _, _, _, _, _, _, _) ->
	{error, Reason};
http_query1(eof, _Log, DateTime, Host, User, Method, URI, HTTPStatus, Prevchunk) ->
	http_query2(lists:flatten(Prevchunk), DateTime, Host, User, Method, URI, HTTPStatus);
http_query1({Cont, Chunk}, Log, DateTime, Host, User, Method, URI, HTTPStatus, PrevChunk) ->
	ParseChunk = lists:map(fun http_parse/1, Chunk),
	CurrentChunk = [ParseChunk | PrevChunk],
	http_query1(disk_log:chunk(Log, Cont), Log, DateTime,
			Host, User, Method, URI, HTTPStatus, CurrentChunk).
%% @hidden
http_query2(Chunks, DateTime, Host, User, Method, URI, '_') ->
	http_query3(Chunks, DateTime, Host, User, Method, URI);
http_query2(Chunks, DateTime, Host, User, Method, URI, HTTPStatus) when is_list(HTTPStatus) ->
	http_query2(Chunks, DateTime, Host, User, Method, URI, list_to_integer(HTTPStatus));
http_query2(Chunks, DateTime, Host, User, Method, URI, HTTPStatus) ->
	F = fun(#event{httpStatus = HS}) when HS =:= HTTPStatus -> true; (_) -> false end,
	http_query3(lists:filtermap(F, Chunks), DateTime, Host, User, Method, URI).
%% @hidden
http_query3(Chunks, DateTime, Host, User, Method, '_') ->
	http_query4(Chunks, DateTime, Host, User, Method);
http_query3(Chunks, DateTime, Host, User, Method, URI) ->
	F = fun(#event{uri = U}) -> lists:prefix(URI, U) end,
	http_query4(lists:filtermap(F, Chunks), DateTime, Host, User, Method).
%% @hidden
http_query4(Chunks, DateTime, Host, User, '_') ->
	http_query5(Chunks, DateTime, Host, User);
http_query4(Chunks, DateTime, Host, User, Method) ->
	F = fun(#event{method = M}) -> lists:prefix(Method, M) end,
	http_query5(lists:filtermap(F, Chunks), DateTime, Host, User).
%% @hidden
http_query5(Chunks, DateTime, Host, '_') ->
	http_query6(Chunks, DateTime, Host);
http_query5(Chunks, DateTime, Host, User) ->
	F = fun(#event{user = U}) -> lists:prefix(User, U) end,
	http_query6(lists:filtermap(F, Chunks), DateTime, Host).
%% @hidden
http_query6(Chunks, DateTime, '_') ->
	http_query7(Chunks, DateTime);
http_query6(Chunks, DateTime, Host) ->
	F = fun(#event{host = H}) -> lists:prefix(Host, H) end,
	http_query7(lists:filtermap(F, Chunks), DateTime).
%% @hidden
http_query7(Chunks, '_') ->
	http_query8(Chunks);
http_query7(Chunks, DateTime) ->
	F = fun(#event{date = D}) -> lists:prefix(DateTime, D) end,
	http_query8(lists:filtermap(F, Chunks)).
%% @hidden
http_query8(Chunks) ->
	F = fun(#event{host = H, user = U, date = D, method = M, uri = URI, httpStatus = S}, Acc) ->
			[{H, U, D, M, URI, S} | Acc]
	end,
	{eof, lists:reverse(lists:foldl(F, [], Chunks))}.

-spec http_file(LogType, FileName) -> Result
	when
		LogType :: transfer | error | security,
		FileName :: file:filename(),
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Write events logged by `httpd' to a file.
%%
http_file(LogType, FileName) when is_atom(LogType), is_list(FileName) ->
	Log = httpd_logname(LogType),
	case file:open(FileName, [raw, write]) of
		{ok, IoDevice} ->
			file_chunk(Log, IoDevice, binary, start);
		{error, Reason} ->
			error_logger:error_report([file:format_error(Reason),
					{module, ?MODULE}, {log, Log},
					{filename, FileName}, {error, Reason}]),
		{error, Reason}
	end.

-spec httpd_logname(LogType) -> disk_log:log()
	when
		LogType :: transfer | error | security.
%% @doc Find local name of {@link //inets/httpd. httpd} disk_log.
%%
httpd_logname(LogType) ->
	{ok, Services} = application:get_env(inets, services),
	{_, HttpdConfig} = lists:keyfind(httpd, 1, Services),
	{_, ServerRoot} = lists:keyfind(server_root, 1, HttpdConfig),
	httpd_logname(LogType, ServerRoot, HttpdConfig).
%% @hidden
httpd_logname(transfer, ServerRoot, HttpdConfig) ->
	{_, LogName} = lists:keyfind(transfer_disk_log, 1, HttpdConfig),
	filename:join(ServerRoot, string:strip(LogName));
httpd_logname(error, ServerRoot, HttpdConfig) ->
	{_, LogName} = lists:keyfind(error_disk_log, 1, HttpdConfig),
	filename:join(ServerRoot, string:strip(LogName));
httpd_logname(security, ServerRoot, HttpdConfig) ->
	{_, LogName} = lists:keyfind(security_disk_log, 1, HttpdConfig),
	filename:join(ServerRoot, string:strip(LogName)).

-spec dump_file(Log, FileName) -> Result
	when
		Log :: disk_log:log(),
		FileName :: file:filename(),
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Write all logged events to a file.
%%
dump_file(Log, FileName) when is_list(FileName) ->
	case file:open(FileName, [write]) of
		{ok, IoDevice} ->
			file_chunk(Log, IoDevice, tuple, start);
		{error, Reason} ->
			error_logger:error_report([file:format_error(Reason),
					{module, ?MODULE}, {log, Log},
					{filename, FileName}, {error, Reason}]),
			{error, Reason}
	end.

-spec last(Log, MaxItems) -> Result
	when
		Log :: disk_log:log(),
		MaxItems :: pos_integer(),
		Result :: {NumItems, Items} | {error, Reason},
		NumItems :: non_neg_integer(),
		Items :: [term()],
		Reason :: term().
%% @doc Get the last `MaxItems' events in most recent item first order.
last(Log, MaxItems) ->
	case disk_log:chunk_step(Log, start, 0) of
		{error, end_of_log} ->
			{0, []};
		{error, Reason} ->
			{error, Reason};
		{ok, Cont1} ->
			last(Log, MaxItems, Cont1, [Cont1])
	end.
%% @hidden
last(Log, MaxItems, Cont1, [H | _] = Acc) ->
	case disk_log:chunk_step(Log, H, 1) of
		{error, end_of_log} ->
			last1(Log, MaxItems, Acc, {0, []});
		{ok, Cont1} ->
			last1(Log, MaxItems, Acc, {0, []});
		{ok, ContN} ->
			last(Log, MaxItems, Cont1, [ContN | Acc])
	end.
%% @hidden
last1(Log, MaxItems, [Cont | T], _Acc) ->
	case last2(Log, MaxItems, Cont, []) of
		{error, Reason} ->
			{error, Reason};
		{N, Items} when N < MaxItems ->
			last1(Log, MaxItems, T, {N, Items});
		{MaxItems, Items} ->
			{MaxItems, lists:flatten(Items)}
	end;
last1(_Log, _MaxItems, [], {NumItems, Items}) ->
	{NumItems, lists:flatten(Items)}.
%% @hidden
last2(Log, MaxItems, Cont, Acc) ->
	case disk_log:bchunk(Log, Cont) of
		{error, Reason} ->
			{error, Reason};
		eof ->
			last3(Log, MaxItems, Acc, 0, []);
		{Cont1, _Chunk} ->
			last2(Log, MaxItems, Cont1, [Cont | Acc])
	end.
%% @hidden
last3(Log, MaxItems, [Cont | T], NumItems, Acc) ->
	case disk_log:chunk(Log, Cont) of
		{error, Reason} ->
			{error, Reason};
		{_, Items} ->
			RevItems = lists:reverse(Items),
			NumNewItems = length(RevItems),
			case NumItems + NumNewItems of
				MaxItems ->
					NewAcc = [RevItems | Acc],
					{MaxItems, lists:reverse(NewAcc)};
				N when N > MaxItems ->
					NumHead = MaxItems - NumItems,
					{NewItems, _} = lists:split(NumHead, RevItems),
					NewAcc = [NewItems | Acc],
					{MaxItems, lists:reverse(NewAcc)};
				N ->
					NewAcc = [RevItems | Acc],
					last3(Log, MaxItems, T, N, NewAcc)
			end
	end;
last3(_Log, _MaxItems, [], NumItems, Acc) ->
	{NumItems, lists:reverse(Acc)}.


-spec open_log(Directory, Log, LogSize, LogFiles, LogNodes) -> Result
	when
		Directory  :: string(),
		Log :: atom(),
		LogSize :: integer(),
		LogFiles :: integer(),
		LogNodes :: [Node],
		Node :: atom(),
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc open disk log file
open_log(Directory, Log, LogSize, LogFiles, LogNodes) ->
	case file:make_dir(Directory) of
		ok ->
			open_log1(Directory, Log, LogSize, LogFiles, LogNodes);
		{error, eexist} ->
			open_log1(Directory, Log, LogSize, LogFiles, LogNodes);
		{error, Reason} ->
			{error, Reason}
	end.
%% @hidden
open_log1(Directory, Log, LogSize, LogFiles, LogNodes) ->
	FileName = Directory ++ "/" ++ atom_to_list(Log),
	case disk_log:open([{name, Log}, {file, FileName},
					{type, wrap}, {size, {LogSize, LogFiles}},
					{distributed, [node() | LogNodes]}]) of
		{ok, _} = Result ->
			open_log2(Log, [{node(), Result}], [], undefined);
		{repaired, _, _, _} = Result ->
			open_log2(Log, [{node(), Result}], [], undefined);
		{error, _} = Result ->
			open_log2(Log, [], [{node(), Result}], undefined);
		{OkNodes, ErrNodes} ->
			open_log2(Log, OkNodes, ErrNodes, undefined)
	end.
%% @hidden
open_log2(Log, OkNodes,
		[{Node, {error, {node_already_open, _}}} | T], Reason)
		when Node == node() ->
	open_log2(Log, [{Node, {ok, Log}} | OkNodes], T, Reason);
open_log2(Log, OkNodes, [{_, {error, {node_already_open, _}}} | T], Reason) ->
	open_log2(Log, OkNodes, T, Reason);
open_log2(Log, OkNodes, [{Node, Reason1} | T], Reason2) ->
	Descr = lists:flatten(disk_log:format_error(Reason1)),
	Trunc = lists:sublist(Descr, length(Descr) - 1),
	error_logger:error_report([Trunc, {module, ?MODULE},
		{log, Log}, {node, Node}, {error, Reason1}]),
	open_log2(Log, OkNodes, T, Reason2);
open_log2(_Log, OkNodes, [], Reason) ->
	case lists:keymember(node(), 1, OkNodes) of
		true ->
			ok;
		false ->
			{error, Reason}
	end.

-spec fault_query(Continuation, Size, Start, End, HeaderMatch, FieldsMatch) -> Result
	when
		Continuation :: start | disk_log:continuation(),
		Size :: pos_integer() | undefined,
		HeaderMatch :: '_' | ets:match_spec(),
		FieldsMatch :: '_' | ets:match_spec(),
		Start :: calendar:datetime() | pos_integer(),
		End :: calendar:datetime() | pos_integer(),
		Result :: {Continuation2, Events} | {error, Reason},
		Continuation2 :: eof | disk_log:continuation(),
		Events :: [fault_event()],
		Reason :: term().
%% @doc Query fault log events with filters.
%%
fault_query(Continuation, _Size, Start, End, HeaderMatch, FieldsMatch) ->
	MFA = {?MODULE, fault_filter, [HeaderMatch, FieldsMatch]},
	query_log(Continuation, Start, End, ?FAULTLOG, MFA).

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
iso8601hour(Date, [$T, H1])
		when H1 >= $0, H1 =< $2 ->
	iso8601hour(Date, [$T, H1, $0]);
iso8601hour(Date, [$T, H1, H2 | T])
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

%%----------------------------------------------------------------------
%%  The internal functions
%%----------------------------------------------------------------------

%% @hidden
file_chunk(Log, IoDevice, Type, Cont) when Type == binary; Type == tuple ->
	case disk_log:chunk(Log, Cont) of
		eof ->
			file:close(IoDevice);
		{error, Reason} ->
			Descr = lists:flatten(disk_log:format_error(Reason)),
			Trunc = lists:sublist(Descr, length(Descr) - 1),
			error_logger:error_report([Trunc, {module, ?MODULE},
					{log, Log}, {error, Reason}]),
			file:close(IoDevice),
			{error, Reason};
		{NextCont, Terms} ->
			file_chunk1(Log, IoDevice, Type, NextCont, Terms)
	end.
%% @hidden
file_chunk1(Log, IoDevice, tuple, Cont, [Event | T]) ->
	io:fwrite(IoDevice, "~999p~n", [Event]),
	file_chunk1(Log, IoDevice, tuple, Cont, T);
file_chunk1(Log, IoDevice, binary, Cont, [Event | T]) ->
	case file:write(IoDevice, Event) of
		ok ->
			file_chunk1(Log, IoDevice, binary, Cont, T);
		{error, Reason} ->
			error_logger:error_report([file:format_error(Reason),
					{module, ?MODULE}, {log, Log}, {error, Reason}]),
			file:close(IoDevice),
			{error, Reason}
	end;
file_chunk1(Log, IoDevice, Type, Cont, []) ->
	file_chunk(Log, IoDevice, Type, Cont).

% @private
http_parse(Event) ->
	{Offset, 1} = binary:match(Event, <<32>>),
	<<Host:Offset/binary, 32, $-, 32, Rest/binary>> = Event,
	http_parse1(Rest, #event{host = binary_to_list(Host)}).
% @hidden
http_parse1(Event, Acc) ->
	{Offset, 1} = binary:match(Event, <<32>>),
	<<User:Offset/binary, 32, $[, Rest/binary>> = Event,
	http_parse2(Rest, Acc#event{user = binary_to_list(User)}).
% @hidden
http_parse2(Event, Acc) ->
	{Offset, 1} = binary:match(Event, <<$]>>),
	<<Date:Offset/binary, $], 32, $", Rest/binary>> = Event,
	http_parse3(Rest, Acc#event{date = binary_to_list(Date)}).
% @hidden
http_parse3(Event, Acc) ->
	{Offset, 1} = binary:match(Event, <<32>>),
	<<Method:Offset/binary, 32, Rest/binary>> = Event,
	http_parse4(Rest, Acc#event{method = binary_to_list(Method)}).
% @hidden
http_parse4(Event, Acc) ->
	{Offset, 1} = binary:match(Event, <<32>>),
	<<URI:Offset/binary, 32, Rest/binary>> = Event,
	http_parse5(Rest, Acc#event{uri = binary_to_list(URI)}).
% @hidden
http_parse5(Event, Acc) ->
	{Offset, 2} = binary:match(Event, <<$", 32>>),
	<<_Http:Offset/binary, $", 32, Rest/binary>> = Event,
	http_parse6(Rest, Acc).
% @hidden
http_parse6(Event, Acc) ->
	{Offset, 1} = binary:match(Event, <<32>>),
	<<Status:Offset/binary, 32, _Rest/binary>> = Event,
	Acc#event{httpStatus = binary_to_integer(Status)}.

-spec close_log(Log) -> Result
	when
		Log :: atom(),
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc close log files
close_log(Log) ->
	case disk_log:close(Log) of
		ok ->
			ok;
		{error, Reason} ->
			Descr = lists:flatten(disk_log:format_error(Reason)),
			Trunc = lists:sublist(Descr, length(Descr) - 1),
			error_logger:error_report([Trunc, {module, ?MODULE},
					{log, Log}, {error, Reason}]),
			{error, Reason}
	end.

-spec query_log(Continuation, Start, End, Log, MFA) -> Result
	when
		Continuation :: start | disk_log:continuation(),
		Start :: calendar:datetime() | pos_integer(),
		End :: calendar:datetime() | pos_integer(),
		MFA :: {Module, Function, Args},
		Log :: atom(),
		Module :: atom(),
		Function :: atom(),
		Args :: [Arg],
		Arg :: term(),
		Result :: {Continuation2, Events} | {error, Reason},
		Continuation2 :: eof | disk_log:continuation(),
		Events :: [fault_event()],
		Reason :: term().
%% @doc
query_log(Continuation, {{_, _, _}, {_, _, _}} = Start, End, Log, MFA) ->
	Seconds = calendar:datetime_to_gregorian_seconds(Start) - ?EPOCH,
	query_log(Continuation, Seconds * 1000, End, Log, MFA);
query_log(Continuation, Start, {{_, _, _}, {_, _, _}} = End, Log, MFA) ->
	Seconds = calendar:datetime_to_gregorian_seconds(End) - ?EPOCH,
	query_log(Continuation, Start, Seconds * 1000 + 999, Log, MFA);
query_log(start, Start, End, Log, MFA) when is_integer(Start), is_integer(End) ->
	case btree_search(Log, Start) of
		{error, Reason} ->
			{error, Reason};
		Continuation ->
			query_log1(Start, End, MFA, disk_log:chunk(Log, Continuation), [])
	end;
query_log(Continuation, Start, End, Log, MFA) when is_integer(Start), is_integer(End) ->
	query_log1(Start, End, MFA, disk_log:chunk(Log, Continuation), []).
%% @hidden
query_log1(_Start, _End, {M, F, A}, eof, Acc) ->
	apply(M, F, [{eof, lists:reverse(Acc)} | A]);
query_log1(_Start, _End, _MFA, {error, Reason}, _Acc)->
	{error, Reason};
query_log1(_Start, End, {M, F, A}, {_, [Event | _]}, Acc) when element(1, Event) > End ->
	apply(M, F, [{eof, lists:reverse(Acc)} | A]);
query_log1(Start, End, MFA, {Cont, [Event | T]}, Acc)
		when element(1, Event) >= Start, element(1, Event) =< End ->
	query_log1(Start, End, MFA, {Cont, T}, [Event | Acc]);
query_log1(Start, End, MFA, {Cont, [_ | T]}, Acc) ->
	query_log1(Start, End, MFA, {Cont, T}, Acc);
query_log1(_Start, _End, {M, F, A}, {Cont, []}, Acc) ->
	apply(M, F, [{Cont, lists:reverse(Acc)} | A]).

-spec fault_filter(Chunk, HeaderMatch, FieldsMatch) -> Result
	when
		Chunk :: {Cont, Events},
		Cont :: eof | disk_log:continuation(),
		Events :: [fault_event()],
		HeaderMatch :: '_' | ets: match_spec(),
		FieldsMatch :: '_' |  ets:match_spec(),
		Result :: {Cont, FilteredEvents} | {error, Reason},
		FilteredEvents :: [fault_event()],
		Reason :: [{ErrorType, string()}],
		ErrorType :: error | warning.
%% @doc Filter fault events.
%%
%%		Applies match specifications against the common header
%% 	and fault fields. Returns matching events.
%%
%% 	Returned events have common header and fault fields
%% 	as defined in the match body of the match specifications.
%%
%% @private
fault_filter(Chunk, '_' = _HeaderMatch, '_' = _FieldsMatch) ->
	Chunk;
fault_filter({Cont, Events} = _Chunk, HeaderMatch, FieldsMatch) ->
	{Cont, fault_filter1(Events, HeaderMatch, FieldsMatch, [])}.
%% @hidden
fault_filter1([H | T], '_' = HeaderMatch, FieldsMatch, Acc) ->
	fault_filter2(H, T, HeaderMatch, FieldsMatch, Acc);
fault_filter1([H | T], HeaderMatch, FieldsMatch, Acc) ->
	CommonHeader = element(4, H),
	case ets:test_ms(CommonHeader, HeaderMatch) of
		{ok, false} ->
			fault_filter1(T, HeaderMatch, FieldsMatch, Acc);
		{ok, CommonHeader} ->
			fault_filter2(H, T, HeaderMatch, FieldsMatch, Acc);
		{ok, NewCommonHeader} ->
			NewEvent = setelement(4, H, NewCommonHeader),
			fault_filter2(NewEvent, T, HeaderMatch, FieldsMatch, Acc);
		{error, Reason} ->
			{error, Reason}
	end;
fault_filter1([], _, _, Acc) ->
	lists:reverse(Acc).
%% @hidden
fault_filter2(H, T, HeaderMatch, '_' = FieldsMatch, Acc) ->
	fault_filter1(T, HeaderMatch, FieldsMatch, [H | Acc]);
fault_filter2(H, T, HeaderMatch, FieldsMatch, Acc) ->
	FaultFields = element(5, H),
	case ets:test_ms(FaultFields, FieldsMatch) of
		{ok, false} ->
			fault_filter1(T, HeaderMatch, FieldsMatch, Acc);
		{ok, FaultFields} ->
			fault_filter1(T, HeaderMatch, FieldsMatch, [H | Acc]);
		{ok, NewFaultFields} ->
			NewEvent = setelement(5, H, NewFaultFields),
			fault_filter1(T, HeaderMatch, FieldsMatch, [NewEvent | Acc]);
		{error, Reason} ->
			{error, Reason}
	end.

-spec btree_search(Log, Start) -> Result
	when
		Log :: disk_log:log(),
		Start :: pos_integer(),
		Result :: disk_log:continuation() | {error, Reason},
		Reason :: term().
%% @doc Binary tree search of multi file wrap disk_log.
%% @private
%% @hidden
btree_search(Log, Start) ->
	btree_search(Log, Start, disk_log:chunk(Log, start, 1)).
%% @hidden
btree_search(Log, Start, {Cont, Terms, BadBytes}) ->
	error_logger:error_report(["Error reading log",
			{log, Log},{badbytes, BadBytes}]),
	btree_search(Log, Start, {Cont, Terms});
btree_search(_Log, _Start, eof) ->
	start;
btree_search(_Log, _Start, {error, Reason}) ->
	{error, Reason};
btree_search(_Log, Start, {_Cont, [R]}) when element(1, R) >= Start ->
	start;
btree_search(Log, Start, {Cont, [R]}) when element(1, R) < Start ->
	InfoList = disk_log:info(Log),
	Step = case lists:keyfind(size, 1, InfoList) of
		{size, {_MaxBytes, MaxFiles}} when (MaxFiles rem 2) == 0, MaxFiles > 2 ->
			(MaxFiles div 2) - 1;
		{size, {_MaxBytes, MaxFiles}} ->
			MaxFiles div 2
	end,
	btree_search(Log, Start, Step, start, element(1, R), disk_log:chunk_step(Log, Cont, Step)).
%% @hidden
btree_search(Log, Start, Step, PrevCont, PrevChunkStart, {ok, Cont}) ->
	btree_search(Log, Start, Step, PrevCont, PrevChunkStart, Cont,
			disk_log:chunk(Log, Cont, 1));
btree_search(_Log, _Start, Step, PrevCont, _PrevChunkStart, {error, end_of_log})
		when Step == 1; Step == -1 ->
	PrevCont;
btree_search(Log, Start, _Step, PrevCont, PrevChunkStart, {error, end_of_log}) ->
	LogInfo = disk_log:info(Log),
	Step1 = case lists:keyfind(current_file, 1, LogInfo) of
		{current_file, CurrentFile} when (CurrentFile rem 2) == 0, CurrentFile > 2 ->
			(CurrentFile div 2) - 1;
		{current_file, CurrentFile} ->
			CurrentFile div 2
	end,
	btree_search(Log, Start, Step1, PrevCont, PrevChunkStart, disk_log:chunk_step(Log, PrevCont, Step1));
btree_search(_Log, _Start, _Step, _PrevCont, _PrevChunkStart, {error, Reason}) ->
	{error, Reason}.
%% @hidden
btree_search(_Log, Start, 1, PrevCont, _PrevChunkStart, _Cont, {_NextCont, [R]})
		when element(1, R) > Start ->
	PrevCont;
btree_search(_Log, _Start, Step, _PrevCont, PrevChunkStart, Cont, {_NextCont, [R]})
		when Step < 0, element(1, R) > PrevChunkStart ->
	Cont;
btree_search(_Log, _Start, Step, PrevCont, PrevChunkStart, _Cont, {_NextCont, [R]})
		when Step > 0, element(1, R) < PrevChunkStart ->
	PrevCont;
btree_search(_Log, Start, -1, _PrevCont, _PrevChunkStart, Cont, {_NextCont, [R]})
		when element(1, R) < Start ->
	Cont;
btree_search(Log, Start, Step, _PrevCont, _PrevChunkStart, Cont, {_NextCont, [R]})
		when Step == 1; Step == -1 ->
	btree_search(Log, Start, Step, Cont, element(1, R), disk_log:chunk_step(Log, Cont, Step));
btree_search(Log, Start, Step, _PrevCont, _PrevChunkStart, Cont, {_NextCont, [R]})
		when Step > 2, element(1, R) < Start, (Step rem 2) == 0 ->
	NextStep = (Step div 2) - 1,
	btree_search(Log, Start, NextStep, Cont, element(1, R), disk_log:chunk_step(Log, Cont, NextStep));
btree_search(Log, Start, Step, _PrevCont, _PrevChunkStart, Cont, {_NextCont, [R]})
		when Step > 0, element(1, R) < Start ->
	NextStep = Step div 2,
	btree_search(Log, Start, NextStep, Cont, element(1, R), disk_log:chunk_step(Log, Cont, NextStep));
btree_search(Log, Start, Step, _PrevCont, _PrevChunkStart, Cont, {_NextCont, [R]})
		when Step > 0, element(1, R) > Start ->
	NextStep = -(Step div 2),
	btree_search(Log, Start, NextStep, Cont, element(1, R), disk_log:chunk_step(Log, Cont, NextStep));
btree_search(Log, Start, Step, _PrevCont, _PrevChunkStart, Cont, {_NextCont, [R]})
		when Step < -2, element(1, R) > Start, (Step rem 2) == 0 ->
	NextStep = (Step div 2) - 1,
	btree_search(Log, Start, NextStep, Cont, element(1, R), disk_log:chunk_step(Log, Cont, NextStep));
btree_search(Log, Start, Step, _PrevCont, _PrevChunkStart, Cont, {_NextCont, [R]})
		when Step < 0, element(1, R) > Start ->
	NextStep = Step div 2,
	btree_search(Log, Start, NextStep, Cont, element(1, R), disk_log:chunk_step(Log, Cont, NextStep));
btree_search(Log, Start, Step, _PrevCont, _PrevChunkStart, Cont, {_NextCont, [R]})
		when Step < 0, element(1, R) < Start ->
	NextStep = -(Step div 2),
	btree_search(Log, Start, NextStep, Cont, element(1, R), disk_log:chunk_step(Log, Cont, NextStep));
btree_search(_Log, _Start, _Step, _PrevCont, _PrevChunkStart, Cont, eof) ->
	Cont;
btree_search(_Log, _Start, _Step, _PrevCont, _PrevChunkStart, _Cont, {error, Reason}) ->
	{error, Reason}.
