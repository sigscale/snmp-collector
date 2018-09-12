%%% snmp_collector_app.erl
%%% vim: ts=3
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% @copyright 2018 SigScale Global Inc.
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
%%% @doc This {@link //stdlib/application. application} behaviour callback
%%%   module starts and stops the
%%%   {@link //sigcale_snmp_collector. sigscale_snmp_collector} application.
%%%
-module(snmp_collector_app).
-copyright('Copyright (c) 2018 SigScale Global Inc.').

-behaviour(application).

%% callbacks needed for application behaviour
-export([start/2, stop/1, config_change/3]).
%% optional callbacks for application behaviour
-export([prep_stop/1, start_phase/3]).

-define(INTERVAL, 300000).

-include("snmp_collector.hrl").

-include_lib("sigscale_fm/include/fm.hrl").

-record(state, {}).

%%----------------------------------------------------------------------
%%  The snmp_collector_app aplication callbacks
%%----------------------------------------------------------------------

-type start_type() :: normal | {takeover, node()} | {failover, node()}.
-spec start(StartType, StartArgs) -> Result
	when
		StartType :: start_type(),
		StartArgs :: term(),
		Result :: {ok, pid()} | {ok, pid(), State} | {error, Reason},
		State :: #state{},
		Reason :: term().
%% @doc Starts the application processes.
start(normal = _StartType, _Args) ->
	Tables = [alarm],
	case mnesia:wait_for_tables(Tables, 60000) of
		ok ->
			start1(normal = _StartType, []);
		{timeout, BadTabList} ->
			case force(BadTabList) of
				ok ->
					start1(normal = _StartType, []);
				{error, Reason} ->
					error_logger:error_report(["snmp_collector application failed to start",
							{reason, Reason}, {module, ?MODULE}]),
					{error, Reason}
			end;
		{error, Reason} ->
			{error, Reason}
   end.
%% @hidden
start1(_StartType, _Args) ->
	{ok, Name} = application:get_env(queue_name),
	{ok, Type} = application:get_env(queue_type),
	{ok, Size} = application:get_env(queue_size),
	{ok, File} = application:get_env(queue_files),
	{ok, Dir} = application:get_env(queue_dir),
	case open_log(Dir, Name, Type ,File, Size) of
		ok ->
			case supervisor:start_link(snmp_collector_sup, []) of
				{ok, PID} ->
					_ChildSup =
					case timer:apply_interval(?INTERVAL, supervisor,
							start_child, [snmp_collector_get_sup, [[], []]]) of
						{ok, _TRef} ->
							{ok, PID};
						{error, Reason} ->
							{error, Reason}
					end;
				{error, Reason} ->
					{error, Reason}
			end;
		{error , Reason} ->
			{error , Reason}
	end.

-spec start_phase(Phase, StartType, PhaseArgs) -> Result
	when
		Phase :: atom(),
		StartType :: start_type(),
		PhaseArgs :: term(),
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Called for each start phase in the application and included
%%   applications.
%% @see //kernel/app
%%
start_phase(_Phase, _StartType, _PhaseArgs) ->
	ok.

-spec prep_stop(State) -> #state{}
	when
		State :: #state{}.
%% @doc Called when the application is about to be shut down,
%%   before any processes are terminated.
%% @see //kernel/application:stop/1
%%
prep_stop(State) ->
	State.

-spec stop(State) -> any()
	when
		State :: #state{}.
%% @doc Called after the application has stopped to clean up.
%%
stop(_State) ->
	ok.

-spec config_change(Changed, New, Removed) -> ok
	when
		Changed:: [{Par, Val}],
		New :: [{Par, Val}],
		Removed :: [Par],
		Par :: atom(),
		Val :: atom().
%% @doc Called after a code  replacement, if there are any
%%   changes to the configuration  parameters.
%%
config_change(_Changed, _New, _Removed) ->
	ok.

%%----------------------------------------------------------------------
%%  internal functions
%%----------------------------------------------------------------------

-spec open_log(Dir, Name, Type ,File, Size) -> Result
	when
		Dir :: string(),
		Name :: atom(),
		Type :: atom(),
		File :: integer(),
		Size :: integer(),
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Open a disk log file.
open_log(Dir, Name, Type ,File, Size) ->
	case file:make_dir(Dir) of
		ok ->
			open_log1(Dir, Name, Type ,File, Size);
		{error, eexist} ->
			open_log1(Dir, Name, Type ,File, Size);
		{error, Reason} ->
			{error, Reason}
	end.
open_log1(Dir, Name, Type ,File, Size) ->
	FileName = Dir ++ "/" ++ atom_to_list(Name),
	case disk_log:open([{name, Name},
			{file, FileName},
			{type, Type}, {size, {Size, File}}]) of
		{ok, _} = Result ->
			open_log2(Name, [{node(), Result}], [], undefined);
		{repaired, _, _, _} = Result ->
			open_log2(Name, [{node(), Result}], [], undefined);
		{error, _} = Result ->
			open_log2(Name, [], [{node(), Result}], undefined);
		{OkNodes, ErrNodes} ->
			open_log2(Name, OkNodes, ErrNodes, undefined)
	end.
%% @hidden
open_log2(Name, OkNodes,
		[{Node, {error, {node_already_open, _}}} | T], Reason)
		when Node == node() ->
	open_log2(Name, [{Node, {ok, Name}} | OkNodes], T, Reason);
open_log2(Name, OkNodes, [{_, {error, {node_already_open, _}}} | T], Reason) ->
	open_log2(Name, OkNodes, T, Reason);
open_log2(Name, OkNodes, [{Node, Reason1} | T], Reason2) ->
	Descr = lists:flatten(disk_log:format_error(Reason1)),
	Trunc = lists:sublist(Descr, length(Descr) - 1),
	error_logger:error_report([Trunc, {module, ?MODULE},
		{log, Name}, {node, Node}, {error, Reason1}]),
	open_log2(Name, OkNodes, T, Reason2);
open_log2(_Name, OkNodes, [], Reason) ->
	case lists:keymember(node(), 1, OkNodes) of
		true ->
			ok;
		false ->
			{error, Reason}
	end.

-spec force(Tables) -> Result
	when
		Tables :: [TableName],
		Result :: ok | {error, Reason},
		TableName :: atom(),
		Reason :: term().
%% @doc Try to force load bad tables.
force([alarm | T ]) ->
	force(T);
force([H | T]) ->
	case mnesia:force_load_table(H) of
		yes ->
			force(T);
		ErrorDescription ->
			{error, ErrorDescription}
	end;
force([]) ->
	ok.
