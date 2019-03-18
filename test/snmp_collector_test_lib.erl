%% snmp_collector_test_lib.erl
%%% vim: ts=3
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% @copyright 2019 SigScale Global Inc.
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
%%%  @doc Test suite for SNMP manager of the
%%% 	{@link //snmp_collector. snmp_collector} application.
%%%
-module(snmp_collector_test_lib).
-copyright('Copyright (c) 2019 SigScale Global Inc.').

%% common_test required callbacks
-export([initialize_db/1, start/1, stop/0]).

%% Note: This directive should only be used in test suites.
-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include("snmp_collector.hrl").

%%---------------------------------------------------------------------
%%  Test server callback functions
%%---------------------------------------------------------------------

initialize_db(Config) ->
	PrivDir = ?config(priv_dir, Config),
	DbDir = PrivDir ++ "db",
	case file:make_dir(DbDir) of
		ok ->
			ok = application:set_env(mnesia, dir, DbDir),
			initialize_db();
		{error, eexist} ->
			ok = application:set_env(mnesia, dir, DbDir),
			initialize_db();
		{error, Reason} ->
			{error, Reason}
	end.
initialize_db() ->
	case mnesia:system_info(is_running) of
		no ->
			ok = application:start(mnesia),
			initialize_db();
		S when S == starting; S == stopping ->
			receive
				after 1000 ->
					initialize_db()
			end;
		yes ->
			Tables = [snmp_user, http_group, http_user], 
			case mnesia:wait_for_tables(Tables, 1000) of
				{timeout, _} ->
					ok = application:stop(mnesia),
					{ok, _} = snmp_collector_app:install(),
					ok;
				ok ->
					ok
			end
	end.

start(Config) ->
	start(Config, [crypto, inets, asn1, public_key, ssl, mnesia, snmp]).
start(Config, [H | T]) ->
	case application:start(H) of
		ok  ->
			start(Config, T);
	{error, {already_started, H}} ->
		start(Config, T);
	{error, Reason} ->
		{error, Reason}
	end;
start(Config, []) ->
	application:load(snmp_collector),
	case ct:get_config({snmp_mgr_agent, agent_target_address_def}) of
		[TargetAdressDef] ->
			{_, Port} = element(3, TargetAdressDef),
			ok = application:set_env(snmp_collector, manager_ports, [Port]);
		undefined ->
			ok
	end,
	PrivDir = ?config(priv_dir, Config),
	DbDir = PrivDir ++ "db",
	case file:make_dir(DbDir) of
		ok ->
			ok = application:set_env(mnesia, dir, DbDir),
			start1(Config, PrivDir);
		{error, eexist} ->
			ok = application:set_env(mnesia, dir, DbDir),
			start1(Config, PrivDir);
		{error, Reason} ->
			{error, Reason}
	end.
start1(Config, PrivDir) ->
	LogDir = PrivDir ++ "log",
	case file:make_dir(LogDir) of
		ok ->
			ok = application:set_env(snmp_collector, queue_dir, LogDir),
			start2(Config, PrivDir);
		{error, eexist} ->
			ok = application:set_env(snmp_collector, queue_dir, LogDir),
			start2(Config, PrivDir);
		{error, Reason} ->
			{error, Reason}
	end.
start2(Config, PrivDir) ->
	MibDir = PrivDir ++ "mib",
	case file:make_dir(MibDir) of
		ok ->
			ok = application:set_env(snmp_collector, mib_dir, MibDir),
			start3(Config, PrivDir);
		{error, eexist} ->
			ok = application:set_env(snmp_collector, mib_dir, MibDir),
			start3(Config, PrivDir);
		{error, Reason} ->
			{error, Reason}
	end.
start3(Config, PrivDir) ->
	MibBinDir = PrivDir ++ "mib/bin",
	case file:make_dir(MibBinDir) of
		ok ->
			ok = application:set_env(snmp_collector, bin_dir, MibBinDir),
			start4(Config);
		{error, eexist} ->
			ok = application:set_env(snmp_collector, bin_dir, MibBinDir),
			start4(Config);
		{error, Reason} ->
			{error, Reason}
	end.
start4(_Config) ->
	application:start(snmp_collector).

stop() ->
	application:stop(snmp_collector).

%%---------------------------------------------------------------------
%%  Internal functions
%%---------------------------------------------------------------------

