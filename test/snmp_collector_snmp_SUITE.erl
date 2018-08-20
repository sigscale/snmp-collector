%%% snmp_collector_snmp_SUITE.erl
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
%%%  @doc Test suite for SNMP manager of the
%%% 	{@link //snmp_collector. snmp_collector} application.
%%%
-module(snmp_collector_snmp_SUITE).
-copyright('Copyright (c) 2018 SigScale Global Inc.').

%% common_test required callbacks
-export([suite/0, sequences/0, all/0]).
-export([init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).

%% Note: This directive should only be used in test suites.
-compile(export_all).

-define(INTERVAL, interval).
-define(sigscalePEN, 50386).

-include_lib("common_test/include/ct.hrl").
-include("snmp_collector.hrl").

%%---------------------------------------------------------------------
%%  Test server callback functions
%%---------------------------------------------------------------------

-spec suite() -> DefaultData :: [tuple()].
%% Require variables and set default values for the suite.
%%
suite() ->
	ManagerPort = rand:uniform(32767) + 32768,
	AgentPort = rand:uniform(32767) + 32768,
	[{userdata, [{doc, "Test suite for SNMP manager in SigScale SNMP Collector"}]},
	{require, snmp_mgr_agent, snmp},
	{default_config, snmp,
			[{start_manager, true},
			{mgr_port, ManagerPort},
			{users,
					[{?MODULE, [snmp_collector_trap, undefined]}]},
			{managed_agents,
					[{?MODULE, [?MODULE, {127,0,0,1}, AgentPort, []]}]},
			{start_agent, true},
			{agent_udp, AgentPort},
			{agent_trap_udp, ManagerPort}]},
	{require, snmp_app},
	{default_config, snmp_app,
			[{manager,
					[{config, [{verbosity, silence}]},
					{server, [{verbosity, silence}]},
					{net_if, [{verbosity, silence}]}]},
			{agent,
					[{config, [{verbosity, silence}]},
					{agent_verbosity, silence},
					{net_if, [{verbosity, silence}]}]}]},
	{timetrap, {minutes, 1}}].

-spec init_per_suite(Config :: [tuple()]) -> Config :: [tuple()].
%% Initialization before the whole suite.
%%
init_per_suite(Config) ->
erlang:display({?MODULE, ?LINE, Config}),
erlang:display({?MODULE, ?LINE, start_init}),
	ok = ct_snmp:start(Config, snmp_mgr_agent, snmp_app),
erlang:display({?MODULE, ?LINE, snmp_mgr_agent_started}),
	ok = application:start(snmp_collector),
erlang:display({?MODULE, ?LINE, collector_started}),
	DataDir = ?config(data_dir, Config),
erlang:display({?MODULE, ?LINE, data_varible_configured}),
	TrapMib = DataDir ++ "CT-TRAP-MIB.bin",
	SPv2Mib = DataDir ++ "SNMPv2-MIB.bin",
erlang:display({?MODULE, ?LINE, trapmib_varible_configured}),
	ok = snmpa:load_mib(TrapMib),
erlang:display({?MODULE, ?LINE, agent_loaded_mib}),
	ok = snmpm:load_mib(TrapMib),
	ok = snmpm:load_mib(SPv2Mib),
erlang:display({?MODULE, ?LINE, manager_loaded_mib}),
	Config.

-spec end_per_suite(Config :: [tuple()]) -> any().
%% Cleanup after the whole suite.
%%
end_per_suite(Config) ->
	ok = application:stop(snmp_collector),
	ok = ct_snmp:stop(Config).

-spec init_per_testcase(TestCase :: atom(), Config :: [tuple()]) -> Config :: [tuple()].
%% Initialization before each test case.
%%
init_per_testcase(_TestCase, Config) ->
	Config.

-spec end_per_testcase(TestCase :: atom(), Config :: [tuple()]) -> any().
%% Cleanup after each test case.
%%
end_per_testcase(_TestCase, _Config) ->
	ok.

-spec sequences() -> Sequences :: [{SeqName :: atom(), Testcases :: [atom()]}].
%% Group test cases into a test sequence.
%%
sequences() ->
	[].

-spec all() -> TestCases :: [Case :: atom()].
%% Returns a list of all test cases in this test suite.
%%
all() ->
	[send_trap].

%%---------------------------------------------------------------------
%%  Test cases
%%---------------------------------------------------------------------

send_trap() ->
	[{userdata, [{doc, "Receive an SNMP trap."}]}].

send_trap(_Config) ->
	snmpa:send_notification(snmp_master_agent, ctTrap1, no_receiver, "", "", []).

%%---------------------------------------------------------------------
%%  Internal functions
%%---------------------------------------------------------------------

%% @doc Create a unique SNMP EngineID for SigScale Enterprise.
%% @hidden
engine_id() ->
   PEN = binary_to_list(<<1:1, ?sigscalePEN:31>>),
	engine_id(PEN, []).
%% @hidden
engine_id(PEN, Acc) when length(Acc) == 27 ->
	PEN ++ [5 | Acc];
engine_id(PEN, Acc) ->
   engine_id(PEN, [rand:uniform(255) | Acc]).
