%%% snmp_collector_api_SUITE.erl
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
%%%  Test suite for the snmp_collector API.
%%%
-module(snmp_collector_api_SUITE).
-copyright('Copyright (c) 2018 SigScale Global Inc.').

%% common_test required callbacks
-export([suite/0, sequences/0, all/0]).
-export([init_per_suite/1, end_per_suite/1]).
-export([init_per_testcase/2, end_per_testcase/2]).

-compile(export_all).

-include("snmp_collector.hrl").
-include_lib("common_test/include/ct.hrl").
-include_lib("inets/include/mod_auth.hrl").

%%---------------------------------------------------------------------
%%  Test server callback functions
%%---------------------------------------------------------------------

-spec suite() -> DefaultData :: [tuple()].
%% Require variables and set default values for the suite.
%%
suite() ->
	ManagerPort = rand:uniform(32767) + 32768,
	[{userdata, [{doc, "Test suite for SNMP collector API"}]},
	{require, snmp_mgr_agent, snmp},
	{default_config, snmp,
			[{start_manager, true},
			{mgr_port, ManagerPort},
			{users,
					[{?MODULE, [snmp_collector_trap, undefined]}]},
			{start_agent, false}]},
	{require, snmp_app},
	{default_config, snmp_app,
			[{manager,
					[{config, [{verbosity, silence}]},
					{server, [{verbosity, silence}]},
					{net_if, [{verbosity, silence}]}]}]},
	{timetrap, {minutes, 2}}].

-spec init_per_suite(Config :: [tuple()]) -> Config :: [tuple()].
%% Initiation before the whole suite.
%%
init_per_suite(Config) ->
	PrivDir = ?config(priv_dir, Config),
	MnesiaDir = PrivDir ++ "db",
	ok = file:make_dir(MnesiaDir),
	ok = application:set_env(mnesia, dir, MnesiaDir),
	ok = ct_snmp:start(Config, snmp_mgr_agent, snmp_app),
	ok = application:start(snmp_collector),
	snmp_collector_app:install(),
	Config.

-spec end_per_suite(Config :: [tuple()]) -> any().
%% Cleanup after the whole suite.
%%
end_per_suite(_Config) ->
	ok = application:stop(snmp_collector),
	ok = application:stop(snmp),
	ok = application:stop(mnesia).

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
	[add_user, get_user, delete_user].

%%---------------------------------------------------------------------
%%  Test cases
%%---------------------------------------------------------------------

add_user() ->
	[{userdata, [{doc, "Create a new user"}]}].

add_user(_Config) ->
	User = snmp_collector:generate_identity(6),
	Password = snmp_collector:generate_identity(8),
	Locale = "en",
	{ok, {TS, N}} = snmp_collector:add_user(User, Password, Locale),
	true = is_integer(TS),
	true = is_integer(N),
	{Port, Address, Dir, _} = get_params(),
	{ok, #httpd_user{username = User, password = Password,
			user_data = UserData}} = mod_auth:get_user(User, Address, Port, Dir),
	{_, Locale} = lists:keyfind(locale, 1, UserData),
	{_, {_E1, _E2}} = lists:keyfind(last_modified, 1, UserData).

get_user() ->
	[{userdata, [{doc, "Look up a user from table"}]}].

get_user(_Config) ->
	User = snmp_collector:generate_identity(6),
	Password = snmp_collector:generate_identity(8),
	Locale = "en",
	{ok, LastModified} = snmp_collector:add_user(User, Password, Locale),
	{ok, #httpd_user{username = User, password = Password,
			user_data = UserData}} = snmp_collector:get_user(User),
	{_, Locale} = lists:keyfind(locale, 1, UserData),
	{_, LastModified} = lists:keyfind(last_modified, 1, UserData).

delete_user() ->
	[{userdata, [{doc, "Remove user from table"}]}].

delete_user(_Config) ->
	User = snmp_collector:generate_identity(6),
	Password = snmp_collector:generate_identity(8),
	Locale = "en",
	{ok, _} = snmp_collector:add_user(User, Password, Locale),
	{ok, _} = snmp_collector:get_user(User),
	ok = snmp_collector:delete_user(User),
	{error, no_such_user} = snmp_collector:get_user(User).

%%---------------------------------------------------------------------
%%  Internal functions
%%---------------------------------------------------------------------

get_params() ->
	{_, _, Info} = lists:keyfind(httpd, 1, inets:services_info()),
	{_, Port} = lists:keyfind(port, 1, Info),
	{_, Address} = lists:keyfind(bind_address, 1, Info),
	{ok, EnvObj} = application:get_env(inets, services),
	{httpd, HttpdObj} = lists:keyfind(httpd, 1, EnvObj),
	{directory, {Directory, AuthObj}} = lists:keyfind(directory, 1, HttpdObj),
	case lists:keyfind(require_group, 1, AuthObj) of
		{require_group, [Group | _T]} ->
			{Port, Address, Directory, Group};
		false ->
			exit(not_found)
	end.

