%%% snmp_collector_app.erl
%%% vim: ts=3
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% @copyright 2017 SigScale Global Inc.
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
-copyright('Copyright (c) 2017 SigScale Global Inc.').

-behaviour(application).

%% callbacks needed for application behaviour
-export([start/2, stop/1, config_change/3]).
%% optional callbacks for application behaviour
-export([prep_stop/1, start_phase/3]).
%% export the snmp_collector_app private API for installation
-export([install/0, install/1]).

-define(INTERVAL, 300000).
-define(WAITFORSCHEMA, 9000).
-define(WAITFORTABLES, 9000).

-include("snmp_collector.hrl").
-include_lib("inets/include/mod_auth.hrl").
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
	{ok, Name} = application:get_env(queue_name),
	{ok, Type} = application:get_env(queue_type),
	{ok, Size} = application:get_env(queue_size),
	{ok, File} = application:get_env(queue_files),
	{ok, Dir} = application:get_env(queue_dir),
	{ok, MibDir} = application:get_env(mib_dir),
	{ok, BinDir} = application:get_env(bin_dir),
	case open_log(Dir, Name, Type ,File, Size) of
		ok ->
			case create_dirs(MibDir, BinDir) of
				ok ->
					start1(normal, []);
				{error, Reason} ->
					{error, Reason}
			end;
		{error, Reason} ->
			{error, Reason}
	end.
%% @hidden
start1(normal = _StartType, _Args) ->
	Tables = [snmp_user],
	case mnesia:wait_for_tables(Tables, ?WAITFORTABLES) of
		ok ->
			start2();
		{timeout, BadTabList} ->
			case force(BadTabList) of
				ok ->
					start2();
				{error, Reason} ->
					error_logger:error_report(["SNMP Manager application failed to start",
							{reason, Reason},
							{module, ?MODULE}]),
						{error, Reason}
			end;
		{error, Reason} ->
			{error, Reason}
	end.
%% @hidden
start2() ->
	case supervisor:start_link(snmp_collector_sup, []) of
		{ok, TopSup} ->
			Children = supervisor:which_children(TopSup),
			{ok, ManagerPorts} = application:get_env(manager_ports),
			{_, ManagerSup, _, _} = lists:keyfind(snmp_collector_manager_sup_sup, 1, Children),
			{_, DebugSup, _, _} = lists:keyfind(snmp_collector_debug_sup, 1, Children),
			start3(TopSup, ManagerSup, DebugSup, ManagerPorts);
		{error, Reason} ->
			{error, Reason}
	end.
%% @hidden
start3(TopSup, ManagerSup, DebugSup, [Port | T] = _ManagerPorts)
		when is_integer(Port) ->
	case supervisor:start_child(ManagerSup, [[Port]]) of
		{ok, _ManagerServerSup} ->
			start3(TopSup, ManagerSup, DebugSup, T);
		{error, Reason} ->
			{error, Reason}
	end;
start3(TopSup, _ManangerSup, DebugSup, []) ->
	{ok, DebugPorts} = application:get_env(debug_ports),
	start4(TopSup, DebugSup, DebugPorts).
%% @hidden
start4(TopSup, DebugSup, [Port | T] = _DebugPorts)
		when is_integer(Port) ->
	case supervisor:start_child(DebugSup, [[Port], []]) of
		{ok, _DebugServer} ->
			start4(TopSup, DebugSup, T);
		{error, Reason} ->
			{error, Reason}
	end;
start4(TopSup, _DebugSup, []) ->
	StartMods = [snmp_collector_get_sup, [[], []]],
	case timer:apply_interval(?INTERVAL, supervisor,
			start_child, StartMods) of
		{ok, _TRef} ->
			{ok, TopSup};
		{error, Reason} ->
			{error, Reason}
	end.
%% @hidden

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

-spec install() -> Result
	when
		Result :: {ok, Tables},
		Tables :: [atom()].
%% @equiv install([node() | nodes()])
install() ->
	Nodes = [node() | nodes()],
	install(Nodes).

-spec install(Nodes) -> Result
	when
		Nodes :: [node()],
		Result :: {ok, Tables},
		Tables :: [atom()].
%% @doc Initialize Snmp Collector Application tables.
%% 	`Nodes' is a list of the nodes where
%%
%% 	If {@link //mnesia. mnesia} is not running an attempt
%% 	will be made to create a schema on all available nodes.
%% 	If a schema already exists on any node
%% 	{@link //mnesia. mnesia} will be started on all nodes
%% 	using the existing schema.
%%
%% @private
%%
install(Nodes) when is_list(Nodes) ->
	case mnesia:system_info(is_running) of
		no ->
			case mnesia:create_schema(Nodes) of
				ok ->
					error_logger:info_report("Created mnesia schema",
							[{nodes, Nodes}]),
					install1(Nodes);
				{error, Reason} ->
					error_logger:error_report(["Failed to create schema",
							mnesia:error_description(Reason),
							{nodes, Nodes}, {error, Reason}]),
					{error, Reason}
			end;
		_ ->
			install2(Nodes)
	end.
%% @hidden
install1([Node] = Nodes) when Node == node() ->
	case mnesia:start() of
		ok ->
			error_logger:info_msg("Started mnesia~n"),
			install2(Nodes);
		{error, Reason} ->
			error_logger:error_report([mnesia:error_description(Reason),
					{error, Reason}]),
			{error, Reason}
	end;
install1(Nodes) ->
	case rpc:multicall(Nodes, mnesia, start, [], 50000) of
		{Results, []} ->
			F = fun(ok) ->
						false;
					(_) ->
						true
			end,
			case lists:filter(F, Results) of
				[] ->
					error_logger:info_report(["Started mnesia on all nodes",
							{nodes, Nodes}]),
					install2(Nodes);
				NotOKs ->
					error_logger:error_report(["Failed to start mnesia"
							" on all nodes", {nodes, Nodes}, {errors, NotOKs}]),
					{error, NotOKs}
			end;
		{Results, BadNodes} ->
			error_logger:error_report(["Failed to start mnesia"
					" on all nodes", {nodes, Nodes}, {results, Results},
					{badnodes, BadNodes}]),
			{error, {Results, BadNodes}}
	end.
%% @hidden
install2(Nodes) ->
	case mnesia:wait_for_tables([schema], ?WAITFORSCHEMA) of
		ok ->
			install3(Nodes, []);
		{error, Reason} ->
			error_logger:error_report([mnesia:error_description(Reason),
				{error, Reason}]),
			{error, Reason};
		{timeout, Tables} ->
			error_logger:error_report(["Timeout waiting for tables",
					{tables, Tables}]),
			{error, timeout}
	end.
%% @hidden
install3(Nodes, Acc) ->
   case mnesia:create_table(snmp_user, [{disc_copies, Nodes},
         {attributes, record_info(fields, snmp_user)}]) of
      {atomic, ok} ->
         error_logger:info_msg("Created new SNMP users table.~n"),
         install4(Nodes, [snmp_user| Acc]);
      {aborted, {not_active, _, Node} = Reason} ->
         error_logger:error_report(["Mnesia not started on node",
               {node, Node}]),
         {error, Reason};
      {aborted, {already_exists, snmp_user}} ->
         error_logger:info_msg("Found existing SNMP users table.~n"),
         install4(Nodes, [snmp_user| Acc]);
      {aborted, Reason} ->
         error_logger:error_report([mnesia:error_description(Reason),
            {error, Reason}]),
         {error, Reason}
   end.
%% @hidden
install4(Nodes, Acc) ->
	case application:load(inets) of
		ok ->
			error_logger:info_msg("Loaded inets.~n"),
			install5(Nodes, Acc);
		{error, {already_loaded, inets}} ->
			install5(Nodes, Acc)
	end.
%% @hidden
install5(Nodes, Acc) ->
	case application:get_env(inets, services) of
		{ok, InetsServices} ->
			install6(Nodes, Acc, InetsServices);
		undefined ->
			error_logger:info_msg("Inets services not defined. "
					"User table not created~n"),
			install10(Nodes, Acc)
	end.
%% @hidden
install6(Nodes, Acc, InetsServices) ->
	case lists:keyfind(httpd, 1, InetsServices) of
		{httpd, HttpdInfo} ->
			install7(Nodes, Acc, lists:keyfind(directory, 1, HttpdInfo));
		false ->
			error_logger:info_msg("Httpd service not defined. "
					"User table not created~n"),
			install10(Nodes, Acc)
	end.
%% @hidden
install7(Nodes, Acc, {directory, {_, DirectoryInfo}}) ->
	case lists:keyfind(auth_type, 1, DirectoryInfo) of
		{auth_type, mnesia} ->
			install8(Nodes, Acc);
		_ ->
			error_logger:info_msg("Auth type not mnesia. "
					"User table not created~n"),
			install10(Nodes, Acc)
	end;
install7(Nodes, Acc, false) ->
	error_logger:info_msg("Auth directory not defined. "
			"User table not created~n"),
	install10(Nodes, Acc).
%% @hidden
install8(Nodes, Acc) ->
	case mnesia:create_table(httpd_user, [{disc_copies, Nodes},
			{attributes, record_info(fields, httpd_user)}]) of
		{atomic, ok} ->
			error_logger:info_msg("Created new httpd_user table.~n"),
			install9(Nodes, [httpd_user | Acc]);
		{aborted, {not_active, _, Node} = Reason} ->
			error_logger:error_report(["Mnesia not started on node",
					{node, Node}]),
			{error, Reason};
		{aborted, {already_exists, httpd_user}} ->
			error_logger:info_msg("Found existing httpd_user table.~n"),
			install9(Nodes, [httpd_user | Acc]);
		{aborted, Reason} ->
			error_logger:error_report([mnesia:error_description(Reason),
				{error, Reason}]),
			{error, Reason}
	end.
%% @hidden
install9(Nodes, Acc) ->
	case mnesia:create_table(httpd_group, [{disc_copies, Nodes},
			{attributes, record_info(fields, httpd_group)}]) of
		{atomic, ok} ->
			error_logger:info_msg("Created new httpd_group table.~n"),
			install10(Nodes, [httpd_group | Acc]);
		{aborted, {not_active, _, Node} = Reason} ->
			error_logger:error_report(["Mnesia not started on node",
					{node, Node}]),
			{error, Reason};
		{aborted, {already_exists, httpd_group}} ->
			error_logger:info_msg("Found existing httpd_group table.~n"),
			install10(Nodes, [httpd_group | Acc]);
		{aborted, Reason} ->
			error_logger:error_report([mnesia:error_description(Reason),
				{error, Reason}]),
			{error, Reason}
	end.
%% @hidden
install10(_Nodes, Tables) ->
	case mnesia:wait_for_tables(Tables, ?WAITFORTABLES) of
		ok ->
			install11(Tables, lists:member(httpd_user, Tables));
		{timeout, Tables} ->
			error_logger:error_report(["Timeout waiting for tables",
					{tables, Tables}]),
			{error, timeout};
		{error, Reason} ->
			error_logger:error_report([mnesia:error_description(Reason),
					{error, Reason}]),
			{error, Reason}
	end.
%% @hidden
install11(Tables, true) ->
	case inets:start() of
		ok ->
			error_logger:info_msg("Started inets.~n"),
			install12(Tables);
		{error, {already_started, inets}} ->
			install12(Tables);
		{error, Reason} ->
			error_logger:error_msg("Failed to start inets~n"),
			{error, Reason}
	end;
install11(Tables, false) ->
	{ok, Tables}.
%% @hidden
install12(Tables) ->
	case snmp_collector:list_users() of
		{ok, []} ->
			case snmp_collector:add_user("admin", "admin", "en") of
				{ok, _LastModified} ->
					error_logger:info_report(["Created a default user",
							{username, "admin"}, {password, "admin"},
							{locale, "en"}]),
					{ok, Tables};
				{error, Reason} ->
					error_logger:error_report(["Failed to create default user",
							{username, "admin"}, {password, "admin"},
							{locale, "en"}]),
					{error, Reason}
			end;
		{ok, Users} ->
			error_logger:info_report(["Found existing http users",
					{users, Users}]),
			{ok, Tables};
		{error, Reason} ->
			error_logger:error_report(["Failed to list http users",
				{error, Reason}]),
			{error, Reason}
	end.

-spec create_dirs(MibDir, BinDir) -> Result
	when
		MibDir :: string(),
		BinDir :: string(),
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Create the MIB directory.
create_dirs(MibDir, BinDir) ->
	case file:make_dir(MibDir) of
		ok ->
			case file:make_dir(BinDir) of
				ok ->
					ok;
				{error, eexist} ->
					ok;
				{error, Reason} ->
					{error, Reason}
			end;
		{error, eexist} ->
			ok;
		{error, Reason} ->
			{error, Reason}
	end.

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
force([H | T]) ->
	case mnesia:force_load_table(H) of
		yes ->
			force(T);
		ErrorDescription ->
			{error, ErrorDescription}
		end;
force([]) ->
	ok.
