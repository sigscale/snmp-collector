%%% snmp_collector_rest_SUITE.erl
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
%%%  @doc Test suite for REST API in the
%%% 	{@link //snmp_collector. snmp_collector} application.
%%%
-module(snmp_collector_rest_SUITE).
-copyright('Copyright (c) 2018 SigScale Global Inc.').

%% common_test required callbacks
-export([suite/0, sequences/0, all/0]).
-export([init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).

-compile(export_all).

-include("snmp_collector.hrl").
-include_lib("common_test/include/ct.hrl").

%%---------------------------------------------------------------------
%%  Test server callback functions
%%---------------------------------------------------------------------

-spec suite() -> DefaultData :: [tuple()].
%% Require variables and set default values for the suite.
%%
suite() ->
	[{userdata, [{doc, "Test suite for REST API"}]},
	{require, snmp_mgr, snmp},
	{default_config, snmp,
			[{mgr_port, rand:uniform(64511) + 1024}]},
	{require, snmp_app},
	{default_config, snmp_app,
			[{manager,
					[{config, [{verbosity, silence}]},
					{server, [{verbosity, silence}]},
					{notestore, [{verbosity, silence}]},
					{net_if, [{verbosity, silence}]}]}]},
	{timetrap, {minutes, 2}}].

-spec init_per_suite(Config :: [tuple()]) -> Config :: [tuple()].
%% Initiation before the whole suite.
%%
init_per_suite(Config) ->
	ok = snmp_collector_test_lib:initialize_db(Config),
	ok = ct_snmp:start(Config, snmp_mgr, snmp_app),
	ok = snmp_collector_test_lib:start(Config),
	Config.

-spec end_per_suite(Config :: [tuple()]) -> any().
%% Cleanup after the whole suite.
%%
end_per_suite(_Config) ->
	ok = snmp_collector_test_lib:stop().

-spec init_per_testcase(TestCase :: atom(), Config :: [tuple()]) -> Config :: [tuple()].
%% Initiation before each test case.
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
	[add_mib, get_mib, get_mibs, delete_mib].

%%---------------------------------------------------------------------
%%  Test cases
%%---------------------------------------------------------------------

add_mib() ->
	[{userdata, [{doc, "Add a new member of the MIB colection."}]}].

add_mib(_Config) ->
	{skip, unimplemented}.

get_mib() ->
	[{userdata, [{doc, "Get a member of the MIB colection."}]}].

get_mib(_Config) ->
	{skip, unimplemented}.

get_mibs() ->
	[{userdata, [{doc, "Get all members of the MIB colection."}]}].

get_mibs(_Config) ->
	{skip, unimplemented}.

delete_mib() ->
	[{userdata, [{doc, "Delete a member of the MIB colection."}]}].

delete_mib(_Config) ->
	{skip, unimplemented}.


%%---------------------------------------------------------------------
%%  Internal functions
%%---------------------------------------------------------------------

