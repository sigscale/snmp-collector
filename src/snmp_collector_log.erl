%%% snmp_collector_log.erl
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
-module(snmp_collector_log).
-copyright('Copyright (c) 2016 - 2019 SigScale Global Inc.').

%% export the snmp_collector_log_public API.
-export([fault_open/0, fault_close/0, fault_query/6]).

%% exported the private function
-export([fault_query/3]).

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
	{ok, LogNodes} = application:get_env(snmp_collector, fault_log_nodes),
	open_log(Directory, ?FAULTLOG, LogSize, LogFiles, LogNodes).

-spec fault_close() -> Result
	when
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Close the fault disk log.
fault_close() ->
	close_log(?FAULTLOG).

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

-spec fault_query(Continuation, Size, Start, End, HeaderMatch, FieldMatch) -> Result
	when
		Continuation :: start | disk_log:continuation(),
		Size :: pos_integer() | undefined,
		HeaderMatch :: [{Header, Match}] | '_',
		FieldMatch :: [{Header, Match}] | '_',
		Header :: string(),
		Match :: {like, [term()]},
		Start :: calendar:datetime() | pos_integer(),
		End :: calendar:datetime() | pos_integer(),
		Result :: {Continuation2, Events} | {error, Reason},
		Continuation2 :: eof | disk_log:continuation(),
		Events :: [],
		Reason :: term().
%% @doc Query fault log events with filters.
%%
fault_query(Continuation, _Size, Start, End, HeaderMatch, FieldMatch) ->
	MFA = {?MODULE, fault_query, [HeaderMatch, FieldMatch]},
	query_log(Continuation, Start, End, ?FAULTLOG, MFA).

%%----------------------------------------------------------------------
%%  The internal functions
%%----------------------------------------------------------------------

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
		Events :: [term()],
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

-spec fault_query(Continuation, HeaderMatch, FieldMatch) -> Result
	when
		HeaderMatch :: [{Header, Match}] | '_',
		FieldMatch :: [{Field, Match}] | '_',
		Header :: string(),
		Field :: string(),
		Match :: {like, [term()]},
		Continuation :: {Continuation2, Events},
		Result :: {Continuation2, Events},
		Continuation2 :: eof | disk_log:continuation(),
		Events :: [fault_event()].
%% @private
%% @doc Query fault log events with filters.
%%
fault_query({Cont, Events}, HeaderMatch, FieldMatch) ->
	{Cont, fault_query1(Events, HeaderMatch, FieldMatch, [])}.
%% @hidden
fault_query1(Events, '_',  FieldMatch, Acc) ->
	fault_query2(Events, '_', FieldMatch, Acc);
fault_query1([H | T] = Events, HeaderMatch, FieldMatch, Acc) ->
	CommonHeader = element(4, H),
	case fault_query3(CommonHeader, HeaderMatch) of
		true ->
			fault_query2(Events, HeaderMatch, FieldMatch, Acc);
		false ->
			fault_query1(T, HeaderMatch, FieldMatch, Acc)
	end;
fault_query1([], _HeaderMatch,  _FieldMatch, Acc) ->
	lists:reverse(Acc).
%% @hidden
fault_query2(Events, '_', '_', _Acc) ->
	Events;
fault_query2([H | T], HeaderMatch, '_', Acc) ->
	fault_query1(T, HeaderMatch, '_', [H | Acc]);
fault_query2([H | T], HeaderMatch, FieldMatch, Acc) ->
	Fields = element(5, H),
	case fault_query3(Fields, FieldMatch) of
		true ->
			fault_query1(T, HeaderMatch, FieldMatch, [H | Acc]);
		false ->
			fault_query1(T, HeaderMatch, FieldMatch, Acc)
	end;
fault_query2([], _HeaderMatch, _FieldMatch, Acc) ->
	lists:reverse(Acc).
%% @hidden
fault_query3(Map, [{"lastEpochMicrosec", {like, Like}} | T]) ->
	case maps:find("lastEpochMicrosec", Map) of
		{ok, Value} ->
			case fault_query4(snmp_collector_utils:iso8601(Value), Like) of
				true ->
					fault_query3(Map, T);
				false ->
					false
			end;
		error ->
			false
	end;
fault_query3(Map, [{Name, {like, Like}} | T]) ->
	case maps:find(Name, Map) of
		{ok, Value} ->
			case fault_query4(Value, Like) of
				true ->
					fault_query3(Map, T);
				false ->
					false
			end;
		error ->
			false
	end;
fault_query3(_, []) ->
	true.
%% @hidden
fault_query4(Value, [H | T]) ->
	case lists:prefix(H, Value) of
		true ->
			true;
		false ->
			fault_query4(Value, T)
	end;
fault_query4(_Value, []) ->
	false.

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
