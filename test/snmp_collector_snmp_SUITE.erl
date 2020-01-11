%% snmp_collector_snmp_SUITE.erl
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

-define(sigscalePEN, 50386).

-include_lib("inets/include/mod_auth.hrl").
-include_lib("common_test/include/ct.hrl").
-include("snmp_collector.hrl").

%%---------------------------------------------------------------------
%%  Test server callback functions
%%---------------------------------------------------------------------

-spec suite() -> DefaultData :: [tuple()].
%% Require variables and set default values for the suite.
%%
suite() ->
	[{userdata, [{doc, "Test suite for SNMP manager in SigScale SNMP Collector"}]},
	{timetrap, {minutes, 6}}].

-spec init_per_suite(Config :: [tuple()]) -> Config :: [tuple()].
%% Initialization before the whole suite.
%%
init_per_suite(Config) ->
	Config.

-spec end_per_suite(Config :: [tuple()]) -> any().
%% Cleanup after the whole suite.
%%
end_per_suite(_Config) ->
	ok.

-spec init_per_testcase(TestCase :: atom(), Config :: [tuple()]) -> Config :: [tuple()].
%% Initialization before each test case.
%%
init_per_testcase(send_trap_v1, Config) ->
	ok = init_snmp(Config),
	{ok, [Port | _]} = application:get_env(snmp_collector, manager_ports),
	AgentConf = [{engine_id, "snmpv1trap"}, {taddress, {127,0,0,1}}, {port, Port},
			{community, "public"}, {version, v2}, {sec_model, v2c}, {sec_level, noAuthNoPriv}],
	ok = snmpm:register_agent("ct", "ct", AgentConf),
	Config;
init_per_testcase(send_trap_v2, Config) ->
	ok = init_snmp(Config),
	{ok, [Port | _]} = application:get_env(snmp_collector, manager_ports),
	AgentConf = [{engine_id, "snmpv2trap"}, {taddress, {127,0,0,1}}, {port, Port},
			{community, "public"}, {version, v2}, {sec_model, v2c}, {sec_level, noAuthNoPriv}],
	ok = snmpm:register_agent("ct", "ct", AgentConf),
	Config;
init_per_testcase(send_trap_noauth_nopriv, Config) ->
	ok = init_snmp(Config),
	{ok, [Port | _]} = application:get_env(snmp_collector, manager_ports),
	AgentConf = [{engine_id, "noAuthNoPrivAgent"}, {taddress, {127,0,0,1}}, {port, Port},
			{community, "public"}, {version, v3}, {sec_model, usm}, {sec_name, "ct"},
			{sec_level, noAuthNoPriv}],
	USMConf = [{sec_name, "ct"}, {auth, usmNoAuthProtocol}, {priv, usmNoPrivProtocol}],
	ok = snmpm:register_agent("ct", "ct", AgentConf),
	ok = snmpm:register_usm_user("noAuthNoPrivAgent", "ct", USMConf),
	Config;
%% @hidden
init_per_testcase(send_trap_md5_nopriv, Config) ->
	ok = init_snmp(Config),
	{ok, [Port | _]} = application:get_env(snmp_collector, manager_ports),
	AgentConf = [{engine_id, "md5NoPrivAgent"}, {taddress, {127,0,0,1}}, {port, Port},
			{community, "public"}, {version, v3}, {sec_model, usm}, {sec_name, "ct"},
			{sec_level, authNoPriv}],
	USMConf = [{sec_name, "ct"}, {auth, usmHMACMD5AuthProtocol},
			{auth_key, [132,103,251,236,1,5,129,77,93,214,46,166,253,98,78,148]},
			{priv, usmNoPrivProtocol}],
	ok = snmpm:register_agent("ct", "ct", AgentConf),
	ok = snmpm:register_usm_user("md5NoPrivAgent", "ct", USMConf),
	Config;
%% @hidden
init_per_testcase(send_trap_md5_des, Config) ->
	ok = init_snmp(Config),
	{ok, [Port | _]} = application:get_env(snmp_collector, manager_ports),
	AgentConf = [{engine_id, "md5DesAgent"}, {taddress, {127,0,0,1}}, {port, Port},
			{community, "public"}, {version, v3}, {sec_model, usm}, {sec_name, "ct"},
			{sec_level, authPriv}],
	USMConf = [{sec_name, "ct"}, {auth, usmHMACMD5AuthProtocol},
			{auth_key, [150,218,224,221,106,20,27,9,240,41,39,104,98,233,201,64]},
			{priv, usmDESPrivProtocol},
			{priv_key, [3,124,226,35,140,216,89,34,199,59,42,224,119,119,221,203]}],
	ok = snmpm:register_agent("ct", "ct", AgentConf),
	ok = snmpm:register_usm_user("md5DesAgent", "ct", USMConf),
	Config;
%% @hidden
init_per_testcase(send_trap_md5_aes, Config) ->
	ok = init_snmp(Config),
	{ok, [Port | _]} = application:get_env(snmp_collector, manager_ports),
	AgentConf = [{engine_id, "md5AesAgent"}, {taddress, {127,0,0,1}}, {port, Port},
			{community, "public"}, {version, v3}, {sec_model, usm}, {sec_name, "ct"},
			{sec_level, authPriv}],
	USMConf = [{sec_name, "ct"}, {auth, usmHMACMD5AuthProtocol},
			{auth_key, [150,218,224,221,106,20,27,9,240,41,39,104,98,233,201,64]},
			{priv, usmAesCfb128Protocol},
			{priv_key, [3,124,226,35,140,216,89,34,199,59,42,224,119,119,221,203]}],
	ok = snmpm:register_agent("ct", "ct", AgentConf),
	ok = snmpm:register_usm_user("md5AesAgent", "ct", USMConf),
	Config;
%% @hidden
init_per_testcase(send_trap_sha_nopriv, Config) ->
	ok = init_snmp(Config),
	{ok, [Port | _]} = application:get_env(snmp_collector, manager_ports),
	AgentConf = [{engine_id, "shaNoPrivAgent"}, {taddress, {127,0,0,1}}, {port, Port},
			{community, "public"}, {version, v3}, {sec_model, usm}, {sec_name, "ct"},
			{sec_level, authNoPriv}],
	USMConf = [{sec_name, "ct"}, {auth, usmHMACSHAAuthProtocol},
			{auth_key, [200,5,156,82,224,214,56,36,184,163,243,248,155,60,145,230,193,85,79,56]},
			{priv, usmNoPrivProtocol}],
	ok = snmpm:register_agent("ct", "ct", AgentConf),
	ok = snmpm:register_usm_user("shaNoPrivAgent", "ct", USMConf),
	Config;
%% @hidden
init_per_testcase(send_trap_sha_aes, Config) ->
	ok = init_snmp(Config),
	{ok, [Port | _]} = application:get_env(snmp_collector, manager_ports),
	AgentConf = [{engine_id, "shaAesAgent"}, {taddress, {127,0,0,1}}, {port, Port},
			{community, "public"}, {version, v3}, {sec_model, usm}, {sec_name, "ct"},
			{sec_level, authPriv}],
	USMConf = [{sec_name, "ct"}, {auth, usmHMACSHAAuthProtocol},
			{auth_key, [92,190,104,116,195,101,135,104,245,246,7,28,102,197,54,167,253,137,6,106]},
			{priv, usmAesCfb128Protocol},
			{priv_key, [209,37,70,147,151,193,76,5,93,165,118,155,223,32,41,120]}],
	ok = snmpm:register_agent("ct", "ct", AgentConf),
	ok = snmpm:register_usm_user("shaAesAgent", "ct", USMConf),
	Config;
%% @hidden
init_per_testcase(send_trap_sha_des, Config) ->
	ok = init_snmp(Config),
	{ok, [Port | _]} = application:get_env(snmp_collector, manager_ports),
	AgentConf = [{engine_id, "shaDesAgent"}, {taddress, {127,0,0,1}}, {port, Port},
			{community, "public"}, {version, v3}, {sec_model, usm}, {sec_name, "ct"},
			{sec_level, authPriv}],
	Conf = [{sec_name, "ct"}, {auth, usmHMACSHAAuthProtocol},
			{auth_key, [194,201,46,39,15,87,217,62,119,36,22,76,81,97,190,154,22,149,188,143]},
			{priv, usmDESPrivProtocol},
			{priv_key, [119,87,246,135,183,207,228,153,251,116,222,87,177,14,40,208]}],
	ok = snmpm:register_agent("ct", "ct", AgentConf),
	ok = snmpm:register_usm_user("shaDesAgent", "ct", Conf),
	Config;
%% @hidden
init_per_testcase(_, Config) ->
	Config.

-spec end_per_testcase(TestCase :: atom(), Config :: [tuple()]) -> any().
%% Cleanup after each test case.
%%
end_per_testcase(_TestCase, Config) ->
	{ok, snmp_user_removed} = snmp_collector:remove_snmp_user("ct"),
	ok = snmp_collector_test_lib:stop(),
	ok = ct_snmp:stop(Config).

-spec sequences() -> Sequences :: [{SeqName :: atom(), Testcases :: [atom()]}].
%% Group test cases into a test sequence.
%%
sequences() ->
	[].

-spec all() -> TestCases :: [Case :: atom()].
%% Returns a list of all test cases in this test suite.
%%
all() ->
	[send_trap_v1, send_trap_v2, send_trap_noauth_nopriv, send_trap_md5_nopriv, send_trap_md5_des,
		send_trap_md5_aes, send_trap_sha_nopriv, send_trap_sha_aes, send_trap_sha_des].

%%---------------------------------------------------------------------
%%  Test cases
%%---------------------------------------------------------------------

send_trap_v1() ->
	Port = rand:uniform(64511) + 1024,
	[{userdata, [{doc, "Test suite for SNMP manager in SigScale SNMP Collector"}]},
	{require, snmp_mgr_agent, snmp},
	{default_config, snmp,
			[{start_agent, true},
			{agent_notify_type, trap},
			{agent_engine_id, "snmpv1trap"},
			{agent_vsns, [v1]},
			{agent_community, [{"public", "public", "ct", "", ""}]},
			{agent_vacm,
					[{vacmSecurityToGroup, usm, "ct", "ct"},
					{vacmSecurityToGroup, v2c, "ct", "ct"},
					{vacmAccess, "ct", "", any, noAuthNoPriv, exact, "restricted", "", "restricted"},
					{vacmAccess, "ct", "", usm, authNoPriv, exact, "internet", "internet", "internet"},
					{vacmAccess, "ct", "", usm, authPriv, exact, "internet", "internet", "internet"},
					{vacmViewTreeFamily, "internet", [1,3,6,1], included, null},
					{vacmViewTreeFamily, "restricted", [1,3,6,1], included, null}]},
			{agent_notify_def, [{"cttrap", "ct_tag", trap}]},
			{agent_target_address_def, [{"ct_trap", transportDomainUdpIpv4, {[127,0,0,1], Port},
					1500, 3, "ct_tag", "ct_params", "noAuthNoPrivAgent", [], 2048}]},
			{agent_target_param_def, [{"ct_params", v1, usm, "ct", noAuthNoPriv}]},
			{start_manager, true},
			{mgr_port, 56673},
			{users,[{"ct", [snmp_collector_snmpm_cb, self()]}]}]},
	{require, snmp_app},
	{default_config, snmp_app,
			[{manager,
					[{config, [{verbosity, silence}]},
					{server, [{verbosity, silence}]},
					{notestore, [{verbosity, silence}]},
					{net_if, [{verbosity, silence}]}]},
			{agent,
					[{config, [{verbosity, silence}]},
					{agent_verbosity, silence},
					{net_if, [{verbosity, silence}]}]}]}].

send_trap_v1(_Config) ->
	ok = snmpa:send_notification(snmp_master_agent, ctTrap1, no_receiver),
	receive
		ok ->
			ok;
		{error, Reason} ->
			ct:fail(Reason)
	after
		4000 ->
			ct:fail(timeout)
	end.

send_trap_v2() ->
	Port = rand:uniform(64511) + 1024,
	[{userdata, [{doc, "Test suite for SNMP manager in SigScale SNMP Collector"}]},
	{require, snmp_mgr_agent, snmp},
	{default_config, snmp,
			[{start_agent, true},
			{agent_notify_type, trap},
			{agent_engine_id, "snmpv2trap"},
			{agent_vsns, [v2]},
			{agent_community, [{"public", "public", "ct", "", ""}]},
			{agent_vacm,
					[{vacmSecurityToGroup, usm, "ct", "ct"},
					{vacmSecurityToGroup, v2c, "ct", "ct"},
					{vacmAccess, "ct", "", any, noAuthNoPriv, exact, "restricted", "", "restricted"},
					{vacmAccess, "ct", "", usm, authNoPriv, exact, "internet", "internet", "internet"},
					{vacmAccess, "ct", "", usm, authPriv, exact, "internet", "internet", "internet"},
					{vacmViewTreeFamily, "internet", [1,3,6,1], included, null},
					{vacmViewTreeFamily, "restricted", [1,3,6,1], included, null}]},
			{agent_notify_def, [{"cttrap", "ct_tag", trap}]},
			{agent_target_address_def, [{"ct_trap", transportDomainUdpIpv4, {[127,0,0,1], Port},
					1500, 3, "ct_tag", "ct_params", "noAuthNoPrivAgent", [], 2048}]},
			{agent_target_param_def, [{"ct_params", v2c, v2c, "ct", noAuthNoPriv}]},
			{start_manager, true},
			{mgr_port, 56673},
			{users,[{"ct", [snmp_collector_snmpm_cb, self()]}]}]},
	{require, snmp_app},
	{default_config, snmp_app,
			[{manager,
					[{config, [{verbosity, silence}]},
					{server, [{verbosity, silence}]},
					{notestore, [{verbosity, silence}]},
					{net_if, [{verbosity, silence}]}]},
			{agent,
					[{config, [{verbosity, silence}]},
					{agent_verbosity, silence},
					{net_if, [{verbosity, silence}]}]}]}].

send_trap_v2(_Config) ->
	ok = snmpa:send_notification(snmp_master_agent, ctTrap1, no_receiver),
	receive
		ok ->
			ok;
		{error, Reason} ->
			ct:fail(Reason)
	after
		4000 ->
			ct:fail(timeout)
	end.

send_trap_noauth_nopriv() ->
	Port = rand:uniform(64511) + 1024,
	[{userdata, [{doc, "Test suite for SNMP manager in SigScale SNMP Collector"}]},
	{require, snmp_mgr_agent, snmp},
	{default_config, snmp,
			[{start_agent, true},
			{agent_engine_id, "noAuthNoPrivAgent"},
			{agent_notify_type, trap},
			{agent_vsns, [v3]},
			{agent_community, [{"public", "public", "ct", "", ""}]},
			{agent_vacm,
					[{vacmSecurityToGroup, usm, "ct", "ct"},
					{vacmSecurityToGroup, v2c, "ct", "ct"},
					{vacmAccess, "ct", "", any, noAuthNoPriv, exact, "restricted", "", "restricted"},
					{vacmAccess, "ct", "", usm, authNoPriv, exact, "internet", "internet", "internet"},
					{vacmAccess, "ct", "", usm, authPriv, exact, "internet", "internet", "internet"},
					{vacmViewTreeFamily, "internet", [1,3,6,1], included, null},
					{vacmViewTreeFamily, "restricted", [1,3,6,1], included, null}]},
			{agent_notify_def, [{"cttrap", "ct_tag", trap}]},
			{agent_target_address_def, [{"ct_trap", transportDomainUdpIpv4, {[127,0,0,1], Port},
					1500, 3, "ct_tag", "ct_params", "noAuthNoPrivAgent", [], 2048}]},
			{agent_target_param_def, [{"ct_params", v3, usm, "ct", noAuthNoPriv}]},
			{agent_usm, [{"noAuthNoPrivAgent","ct","ct",
					zeroDotZero,usmNoAuthProtocol,[],[],usmNoPrivProtocol,
					[],[],[], "", ""}]},
			{start_manager, true},
			{mgr_port, 56673},
			{users,[{"ct", [snmp_collector_snmpm_cb, self()]}]}]},
	{require, snmp_app},
	{default_config, snmp_app,
			[{manager,
					[{config, [{verbosity, silence}]},
					{server, [{verbosity, silence}]},
					{notestore, [{verbosity, silence}]},
					{net_if, [{verbosity, silence}]}]},
			{agent,
					[{config, [{verbosity, silence}]},
					{agent_verbosity, silence},
					{net_if, [{verbosity, silence}]}]}]}].

send_trap_noauth_nopriv(_Config) ->
	ok = snmpa:send_notification(snmp_master_agent, ctTrap1, no_receiver),
	receive
		ok ->
			ok;
		{error, Reason} ->
			ct:fail(Reason)
	after
		4000 ->
			ct:fail(timeout)
	end.

send_trap_md5_nopriv() ->
	Port = rand:uniform(64511) + 1024,
	[{userdata, [{doc, "Test suite for SNMP manager in SigScale SNMP Collector"}]},
	{require, snmp_mgr_agent, snmp},
	{default_config, snmp,
			[{start_agent, true},
			{agent_engine_id, "md5NoPrivAgent"},
			{agent_notify_type, trap},
			{agent_vsns, [v3]},
			{agent_community, [{"public", "public", "ct", "", ""}]},
			{agent_vacm,
					[{vacmSecurityToGroup, usm, "ct", "ct"},
					{vacmSecurityToGroup, v2c, "ct", "ct"},
					{vacmAccess, "ct", "", any, noAuthNoPriv, exact, "restricted", "", "restricted"},
					{vacmAccess, "ct", "", usm, authNoPriv, exact, "internet", "internet", "internet"},
					{vacmAccess, "ct", "", usm, authPriv, exact, "internet", "internet", "internet"},
					{vacmViewTreeFamily, "internet", [1,3,6,1], included, null},
					{vacmViewTreeFamily, "restricted", [1,3,6,1], included, null}]},
			{agent_notify_def, [{"cttrap", "ct_tag", trap}]},
			{agent_target_address_def, [{"ct_trap", transportDomainUdpIpv4, {[127,0,0,1], Port},
					1500, 3, "ct_tag", "ct_params", "md5NoPrivAgent", [], 2048}]},
			{agent_target_param_def, [{"ct_params", v3, usm, "ct", authNoPriv}]},
			{agent_usm, [{"md5NoPrivAgent","ct","ct",
					zeroDotZero,usmHMACMD5AuthProtocol,[],[],usmNoPrivProtocol,
					[],[],[],
					[14,62,241,145,186,143,207,151,106,249,124,123,157,214,53,98], ""}]},
			{start_manager, true},
			{mgr_port, 56673},
			{users,[{"ct", [snmp_collector_snmpm_cb, self()]}]}]},
	{require, snmp_app},
	{default_config, snmp_app,
			[{manager,
					[{config, [{verbosity, silence}]},
					{server, [{verbosity, silence}]},
					{notestore, [{verbosity, silence}]},
					{net_if, [{verbosity, silence}]}]},
			{agent,
					[{config, [{verbosity, silence}]},
					{agent_verbosity, silence},
					{net_if, [{verbosity, silence}]}]}]}].

send_trap_md5_nopriv(_Config) ->
	ok = snmpa:send_notification(snmp_master_agent, ctTrap1, no_receiver),
	receive
		ok ->
			ok;
		{error, Reason} ->
			ct:fail(Reason)
	after
		4000 ->
			ct:fail(timeout)
	end.

send_trap_md5_des() ->
	Port = rand:uniform(64511) + 1024,
	[{userdata, [{doc, "Test suite for SNMP manager in SigScale SNMP Collector"}]},
	{require, snmp_mgr_agent, snmp},
	{default_config, snmp,
			[{start_agent, true},
			{agent_engine_id, "md5DesAgent"},
			{agent_notify_type, trap},
			{agent_vsns, [v3]},
			{agent_community, [{"public", "public", "ct", "", ""}]},
			{agent_vacm,
					[{vacmSecurityToGroup, usm, "ct", "ct"},
					{vacmSecurityToGroup, v2c, "ct", "ct"},
					{vacmAccess, "ct", "", any, noAuthNoPriv, exact, "restricted", "", "restricted"},
					{vacmAccess, "ct", "", usm, authNoPriv, exact, "internet", "internet", "internet"},
					{vacmAccess, "ct", "", usm, authPriv, exact, "internet", "internet", "internet"},
					{vacmViewTreeFamily, "internet", [1,3,6,1], included, null},
					{vacmViewTreeFamily, "restricted", [1,3,6,1], included, null}]},
			{agent_notify_def, [{"cttrap", "ct_tag", trap}]},
			{agent_target_address_def, [{"ct_trap", transportDomainUdpIpv4, {[127,0,0,1], Port},
					1500, 3, "ct_tag", "ct_params", "md5DesAgent", [], 2048}]},
			{agent_target_param_def, [{"ct_params", v3, usm, "ct", authPriv}]},
			{agent_usm, [{"md5DesAgent","ct","ct",
					zeroDotZero,usmHMACMD5AuthProtocol,[],[],usmDESPrivProtocol,
					[],[],[],
					[150,218,224,221,106,20,27,9,240,41,39,104,98,233,201,64],
					[3,124,226,35,140,216,89,34,199,59,42,224,119,119,221,203]}]},
			{start_manager, true},
			{mgr_port, 56673},
			{users,[{"ct", [snmp_collector_snmpm_cb, self()]}]}]},
	{require, snmp_app},
	{default_config, snmp_app,
			[{manager,
					[{config, [{verbosity, silence}]},
					{server, [{verbosity, silence}]},
					{notestore, [{verbosity, silence}]},
					{net_if, [{verbosity, silence}]}]},
			{agent,
					[{config, [{verbosity, silence}]},
					{agent_verbosity, silence},
					{net_if, [{verbosity, silence}]}]}]}].

send_trap_md5_des(_Config) ->
	ok = snmpa:send_notification(snmp_master_agent, ctTrap1, no_receiver),
	receive
		ok ->
			ok;
		{error, Reason} ->
			ct:fail(Reason)
	after
		4000 ->
			ct:fail(timeout)
	end.

send_trap_md5_aes() ->
	Port = rand:uniform(64511) + 1024,
	[{userdata, [{doc, "Test suite for SNMP manager in SigScale SNMP Collector"}]},
	{require, snmp_mgr_agent, snmp},
	{default_config, snmp,
			[{start_agent, true},
			{agent_engine_id, "md5AesAgent"},
			{agent_notify_type, trap},
			{agent_vsns, [v3]},
			{agent_community, [{"public", "public", "ct", "", ""}]},
			{agent_vacm,
					[{vacmSecurityToGroup, usm, "ct", "ct"},
					{vacmSecurityToGroup, v2c, "ct", "ct"},
					{vacmAccess, "ct", "", any, noAuthNoPriv, exact, "restricted", "", "restricted"},
					{vacmAccess, "ct", "", usm, authNoPriv, exact, "internet", "internet", "internet"},
					{vacmAccess, "ct", "", usm, authPriv, exact, "internet", "internet", "internet"},
					{vacmViewTreeFamily, "internet", [1,3,6,1], included, null},
					{vacmViewTreeFamily, "restricted", [1,3,6,1], included, null}]},
			{agent_notify_def, [{"cttrap", "ct_tag", trap}]},
			{agent_target_address_def, [{"ct_trap", transportDomainUdpIpv4, {[127,0,0,1], Port},
					1500, 3, "ct_tag", "ct_params", "md5AesAgent", [], 2048}]},
			{agent_target_param_def, [{"ct_params", v3, usm, "ct", authPriv}]},
			{agent_usm, [{"md5AesAgent","ct","ct",
					zeroDotZero,usmHMACMD5AuthProtocol,[],[],usmAesCfb128Protocol,
					[],[],[],
					[129,219,3,169,35,37,190,140,167,154,166,148,15,128,163,116],
					[191,182,136,50,249,76,224,16,8,70,14,213,41,148,142,59]}]},
			{start_manager, true},
			{mgr_port, 56673},
			{users,[{"ct", [snmp_collector_snmpm_cb, self()]}]}]},
	{require, snmp_app},
	{default_config, snmp_app,
			[{manager,
					[{config, [{verbosity, silence}]},
					{server, [{verbosity, silence}]},
					{notestore, [{verbosity, silence}]},
					{net_if, [{verbosity, silence}]}]},
			{agent,
					[{config, [{verbosity, silence}]},
					{agent_verbosity, silence},
					{net_if, [{verbosity, silence}]}]}]}].

send_trap_md5_aes(_Config) ->
	ok = snmpa:send_notification(snmp_master_agent, ctTrap1, no_receiver),
	receive
		ok ->
			ok;
		{error, Reason} ->
			ct:fail(Reason)
	after
		4000 ->
			ct:fail(timeout)
	end.

send_trap_sha_nopriv() ->
	Port = rand:uniform(64511) + 1024,
	[{userdata, [{doc, "Test suite for SNMP manager in SigScale SNMP Collector"}]},
	{require, snmp_mgr_agent, snmp},
	{default_config, snmp,
			[{start_agent, true},
			{agent_engine_id, "shaNoPrivAgent"},
			{agent_notify_type, trap},
			{agent_vsns, [v3]},
			{agent_community, [{"public", "public", "ct", "", ""}]},
			{agent_vacm,
					[{vacmSecurityToGroup, usm, "ct", "ct"},
					{vacmSecurityToGroup, v2c, "ct", "ct"},
					{vacmAccess, "ct", "", any, noAuthNoPriv, exact, "restricted", "", "restricted"},
					{vacmAccess, "ct", "", usm, authNoPriv, exact, "internet", "internet", "internet"},
					{vacmAccess, "ct", "", usm, authPriv, exact, "internet", "internet", "internet"},
					{vacmViewTreeFamily, "internet", [1,3,6,1], included, null},
					{vacmViewTreeFamily, "restricted", [1,3,6,1], included, null}]},
			{agent_notify_def, [{"cttrap", "ct_tag", trap}]},
			{agent_target_address_def, [{"ct_trap", transportDomainUdpIpv4, {[127,0,0,1], Port},
					1500, 3, "ct_tag", "ct_params", "shaNoPrivAgent", [], 2048}]},
			{agent_target_param_def, [{"ct_params", v3, usm, "ct", authNoPriv}]},
			{agent_usm, [{"shaNoPrivAgent","ct","ct",
					zeroDotZero,usmHMACSHAAuthProtocol,[],[],usmNoPrivProtocol,
					[],[],[],
					[200,5,156,82,224,214,56,36,184,163,243,248,155,60,145,230,193,85,79,56], ""}]},
			{start_manager, true},
			{mgr_port, 56673},
			{users,[{"ct", [snmp_collector_snmpm_cb, self()]}]}]},
	{require, snmp_app},
	{default_config, snmp_app,
			[{manager,
					[{config, [{verbosity, silence}]},
					{server, [{verbosity, silence}]},
					{notestore, [{verbosity, silence}]},
					{net_if, [{verbosity, silence}]}]},
			{agent,
					[{config, [{verbosity, silence}]},
					{agent_verbosity, silence},
					{net_if, [{verbosity, silence}]}]}]}].

send_trap_sha_nopriv(_Config) ->
	ok = snmpa:send_notification(snmp_master_agent, ctTrap1, no_receiver),
	receive
		ok ->
			ok;
		{error, Reason} ->
			ct:fail(Reason)
	after
		4000 ->
			ct:fail(timeout)
	end.

send_trap_sha_aes() ->
	Port = rand:uniform(64511) + 1024,
	[{userdata, [{doc, "Test suite for SNMP manager in SigScale SNMP Collector"}]},
	{require, snmp_mgr_agent, snmp},
	{default_config, snmp,
			[{start_agent, true},
			{agent_engine_id, "shaAesAgent"},
			{agent_notify_type, trap},
			{agent_vsns, [v3]},
			{agent_community, [{"public", "public", "ct", "", ""}]},
			{agent_vacm,
					[{vacmSecurityToGroup, usm, "ct", "ct"},
					{vacmSecurityToGroup, v2c, "ct", "ct"},
					{vacmAccess, "ct", "", any, noAuthNoPriv, exact, "restricted", "", "restricted"},
					{vacmAccess, "ct", "", usm, authNoPriv, exact, "internet", "internet", "internet"},
					{vacmAccess, "ct", "", usm, authPriv, exact, "internet", "internet", "internet"},
					{vacmViewTreeFamily, "internet", [1,3,6,1], included, null},
					{vacmViewTreeFamily, "restricted", [1,3,6,1], included, null}]},
			{agent_notify_def, [{"cttrap", "ct_tag", trap}]},
			{agent_target_address_def, [{"ct_trap", transportDomainUdpIpv4, {[127,0,0,1], Port},
					1500, 3, "ct_tag", "ct_params", "shaAesAgent", [], 2048}]},
			{agent_target_param_def, [{"ct_params", v3, usm, "ct", authPriv}]},
			{agent_usm, [{"shaAesAgent","ct","ct",
					zeroDotZero,usmHMACSHAAuthProtocol,[],[],usmAesCfb128Protocol,
					[],[],[],
					[92,190,104,116,195,101,135,104,245,246,7,28,102,197,54,167,253,137,6,106],
					[209,37,70,147,151,193,76,5,93,165,118,155,223,32,41,120]}]},
			{start_manager, true},
			{mgr_port, 56673},
			{users,[{"ct", [snmp_collector_snmpm_cb, self()]}]}]},
	{require, snmp_app},
	{default_config, snmp_app,
			[{manager,
					[{config, [{verbosity, silence}]},
					{server, [{verbosity, silence}]},
					{notestore, [{verbosity, silence}]},
					{net_if, [{verbosity, silence}]}]},
			{agent,
					[{config, [{verbosity, silence}]},
					{agent_verbosity, silence},
					{net_if, [{verbosity, silence}]}]}]}].

send_trap_sha_aes(_Config) ->
	ok = snmpa:send_notification(snmp_master_agent, ctTrap1, no_receiver),
	receive
		ok ->
			ok;
		{error, Reason} ->
			ct:fail(Reason)
	after
		4000 ->
			ct:fail(timeout)
	end.

send_trap_sha_des() ->
	Port = rand:uniform(64511) + 1024,
	[{userdata, [{doc, "Test suite for SNMP manager in SigScale SNMP Collector"}]},
	{require, snmp_mgr_agent, snmp},
	{default_config, snmp,
			[{start_agent, true},
			{agent_engine_id, "shaDesAgent"},
			{agent_notify_type, trap},
			{agent_vsns, [v3]},
			{agent_community, [{"public", "public", "ct", "", ""}]},
			{agent_vacm,
					[{vacmSecurityToGroup, usm, "ct", "ct"},
					{vacmSecurityToGroup, v2c, "ct", "ct"},
					{vacmAccess, "ct", "", any, noAuthNoPriv, exact, "restricted", "", "restricted"},
					{vacmAccess, "ct", "", usm, authNoPriv, exact, "internet", "internet", "internet"},
					{vacmAccess, "ct", "", usm, authPriv, exact, "internet", "internet", "internet"},
					{vacmViewTreeFamily, "internet", [1,3,6,1], included, null},
					{vacmViewTreeFamily, "restricted", [1,3,6,1], included, null}]},
			{agent_notify_def, [{"cttrap", "ct_tag", trap}]},
			{agent_target_address_def, [{"ct_trap", transportDomainUdpIpv4, {[127,0,0,1], Port},
					1500, 3, "ct_tag", "ct_params", "shaDesAgent", [], 2048}]},
			{agent_target_param_def, [{"ct_params", v3, usm, "ct", authPriv}]},
			{agent_usm, [{"shaDesAgent","ct","ct",
					zeroDotZero,usmHMACSHAAuthProtocol,[],[],usmDESPrivProtocol,
					[],[],[],
					[194,201,46,39,15,87,217,62,119,36,22,76,81,97,190,154,22,149,188,143],
					[119,87,246,135,183,207,228,153,251,116,222,87,177,14,40,208]}]},
			{start_manager, true},
			{mgr_port, 56673},
			{users,[{"ct", [snmp_collector_snmpm_cb, self()]}]}]},
	{require, snmp_app},
	{default_config, snmp_app,
			[{manager,
					[{config, [{verbosity, silence}]},
					{server, [{verbosity, silence}]},
					{notestore, [{verbosity, silence}]},
					{net_if, [{verbosity, silence}]}]},
			{agent,
					[{config, [{verbosity, silence}]},
					{agent_verbosity, silence},
					{net_if, [{verbosity, silence}]}]}]}].

send_trap_sha_des(_Config) ->
	ok = snmpa:send_notification(snmp_master_agent, ctTrap1, no_receiver),
	receive
		ok ->
			ok;
		{error, Reason} ->
			ct:fail(Reason)
	after
		4000 ->
			ct:fail(timeout)
	end.

%%---------------------------------------------------------------------
%%  Internal functions
%%---------------------------------------------------------------------

%% Create a unique SNMP EngineID for SigScale Enterprise.
engine_id() ->
	PEN = binary_to_list(<<1:1, ?sigscalePEN:31>>),
	engine_id(PEN, []).
engine_id(PEN, Acc) when length(Acc) == 27 ->
	PEN ++ [5 | Acc];
engine_id(PEN, Acc) ->
   engine_id(PEN, [rand:uniform(255) | Acc]).

init_snmp(Config) ->
	PrivDir = ?config(priv_dir, Config),
	DbDir = PrivDir ++ "db",
	case file:make_dir(DbDir) of
		ok ->
			ok = application:set_env(mnesia, dir, DbDir),
			init_snmp1(Config);
		{error, eexist} ->
			ok = application:set_env(mnesia, dir, DbDir),
			init_snmp1(Config);
		{error, Reason} ->
			{error, Reason}
	end.
init_snmp1(Config) ->
	DataDir = ?config(data_dir, Config),
	TrapMib = DataDir ++ "CT-TRAP-MIB.bin",
	ok = snmp_collector_test_lib:initialize_db(Config),
	ok = ct_snmp:start(Config, snmp_mgr_agent, snmp_app),
	ok = snmpa:load_mib(TrapMib),
	ok = snmp_collector_test_lib:start(Config),
	{ok, snmp_user_added} = snmp_collector:add_snmp_user("ct", "BigBrownFox#1", "BigBlackCat#1"),
	ok.

