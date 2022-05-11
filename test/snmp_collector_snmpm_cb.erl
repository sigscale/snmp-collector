%% snmp_collector_snmpm_cb.erl
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
%%%  @doc This {@link //snmp/snmpm_user, snmpm_user} behaviour callback
%%% 	module implements SNMP manager functions for test SUITES in the
%%% 	{@link //snmp_collector. snmp_collector} application.
%%%
-module(snmp_collector_snmpm_cb).
-copyright('Copyright (c) 2016 - 2019 SigScale Global Inc.').

-export([handle_error/3, handle_agent/5, handle_pdu/4,
		handle_trap/3, handle_inform/3, handle_report/3,
		handle_invalid_result/2]).

-behaviour(snmpm_user).

%%----------------------------------------------------------------------
%%  The snmp_user callbacks
%%----------------------------------------------------------------------

-spec handle_error(ReqId, Reason, UserData) -> any()
	when
		ReqId :: integer(),
		Reason :: {unexpected_pdu, SnmpInfo}
				| {invalid_sec_info, SecurityInfo, SnmpInfo}
				| {empty_message, Address, Port} | term(),
		SnmpInfo :: snmpm_user:snmp_gen_info(),
		SecurityInfo :: term(),
		Address :: inet:ip_address(),
		Port :: inet:port(),
		UserData :: pid().
%% @doc Called when the manager needs to communicate an "asynchronous"
%% 	error to the user.
handle_error(ReqId,
		{unexpected_pdu, {Status, Index, Varbinds}} = Reason, UserData) ->
	error_logger:error_report(["SNMP Manager: Error",
			{reqid, ReqId}, {error, unexpected_pdu},
			{status, Status}, {index, Index},
			{varbinds, Varbinds}, {userdata, UserData}]),
	UserData ! {error, Reason}; 
handle_error(ReqId,
		{invalid_sec_info, SecurityInfo, {Status, Index, Varbinds}} = Reason, UserData) ->
	error_logger:error_report(["SNMP Manager: Error",
			{reqid, ReqId}, {error, invalid_sec_info},
			{sec_info, SecurityInfo}, {status, Status},
			{index, Index}, {varbinds, Varbinds},
			{userdata, UserData}]),
	UserData ! {error, Reason}; 
handle_error(ReqId, {empty_message, Address, Port} = Reason, UserData) ->
	error_logger:error_report(["SNMP Manager: Error",
			{reqid, ReqId}, {error, empty_message},
			{address, Address}, {port, Port},
			{userdata, UserData}]),
	UserData ! {error, Reason}; 
handle_error(ReqId, Other, UserData) ->
	error_logger:error_report(["SNMP Manager: Error",
			{reqid, ReqId}, {error, Other},
			{userdata, UserData}]),
	UserData ! {error, Other}. 

-spec handle_agent(Domain, Address, Type, SnmpInfo, UserData) -> Reply
	when
		Domain :: transportDomainUdpIpv4 | transportDomainUdpIpv6,
		Address :: {inet:ip_address(), inet:port_number()},
		Type :: pdu | trap | report | inform,
		SnmpInfo :: SnmpPduInfo | SnmpTrapInfo | SnmpReportInfo | SnmpInformInfo,
		SnmpPduInfo :: snmpm_user:snmp_gen_info(),
		SnmpTrapInfo :: snmpm_user:snmp_v1_trap_info(),
		SnmpReportInfo :: snmpm_user:snmp_gen_info(),
		SnmpInformInfo :: snmpm_user:snmp_gen_info(),
		UserData :: term(),
		Reply :: ignore | {register, UserId, TargetName, AgentConfig},
		UserId :: term(),
		TargetName :: snmpm:target_name(),
		AgentConfig :: [snmpm:agent_config()].
%% @doc Called when a message is received from an unknown agent.
handle_agent(_Domain, {IpAddress, Port} = _Address, Type,
		{Enteprise, Generic, Spec, Timestamp, Varbinds}, UserData) ->
	error_logger:error_report(["SNMP Manager: Unknown Agent",
			{address, IpAddress}, {port, Port}, {type, Type},
			{enterprise, Enteprise}, {generic, Generic}, {spec, Spec},
			{timestamp, Timestamp}, {varbinds, Varbinds},
			{userdata, UserData}]),
	UserData ! {error, unknown_agent},
    ignore;
handle_agent(_Domain, {IpAddress, Port} = _Address, Type,
		{Status, Index, Varbinds} = _SnmpInfo, UserData) ->
	error_logger:error_report(["SNMP Manager: Unknown Agent",
			{address, IpAddress}, {port, Port}, {type, Type},
			{status, Status}, {index, Index}, {varbinds, Varbinds},
			{userdata, UserData}]),
	UserData ! {error, unknown_agent},
    ignore.

-spec handle_pdu(TargetName, ReqId, SnmpPduInfo, UserData) -> any()
	when
		TargetName :: snmpm:target_name(),
		ReqId :: term(),
		SnmpPduInfo :: snmp_user:snmp_gen_info(),
		UserData :: term().
%% @doc Handle the reply to an asynchronous request (e.g. `snmpm:async_get/3').
handle_pdu(TargetName, ReqId,
		{Status, Index, Varbinds} = _SnmpPduInfo, UserData) ->
	error_logger:error_report(["SNMP Manager: PDU Reply",
			{target_name, TargetName}, {reqid, ReqId},
			{status, Status}, {index, Index}, {varbinds, Varbinds},
			{userdata, UserData}]),
	{self, Self} = lists:keyfind(self, 1, UserData),
	Self ! ok,
	ignore.

-spec handle_trap(TargetName, SnmpTrapInfo, UserData) -> Reply
	when
		TargetName :: snmpm:target_name(),
		SnmpTrapInfo :: snmpm_user:snmp_v1_trap_info()
				| snmpm_user:snmp_gen_info(),
		UserData :: term(),
		Reply :: ignore | unregister
				| {register, UserId, TargetName, AgentConfig},
		UserId :: term(),
		AgentConfig :: [snmpm:agent_config()].
%% @doc Handle a trap/notification message from an agent.
handle_trap(TargetName,
		{Status, Index, Varbinds} = _SnmpTrapInfo, UserData) ->
	error_logger:error_report(["SNMP Manager: Received Trap",
			{target_name, TargetName},
			{status, Status}, {index, Index}, {varbinds, Varbinds},
			{userdata, UserData}]),
	{self, Self} = lists:keyfind(self, 1, UserData),
	Self ! ok,
	ignore;
handle_trap(TargetName,
		 {Enteprise, Generic, Spec, Timestamp, Varbinds}, UserData) ->
	error_logger:error_report(["SNMP Manager: Received Trap",
			{target_name, TargetName},
			{enterprise, Enteprise}, {generic, Generic}, {spec, Spec},
			{timestamp, Timestamp}, {varbinds, Varbinds},
			{userdata, UserData}]),
	{self, Self} = lists:keyfind(self, 1, UserData),
	Self ! ok,
	ignore.

-spec handle_inform(TargetName, SnmpInformInfo, UserData) -> Reply
	when
		TargetName :: snmpm:target_name(),
		SnmpInformInfo :: snmpm_user:snmp_gen_info(),
		UserData :: term(),
		Reply :: ignore | no_reply | unregister
				| {register, UserId, TargetName, AgentConfig},
		UserId :: term(),
		AgentConfig :: [snmpm:agent_config()].
%% @doc Handle an inform message.
handle_inform(TargetName,
		{Status, Index, Varbinds} = _SnmpInformInfo, UserData) ->
	error_logger:error_report(["SNMP Manager: Received Inform",
			{target_name, TargetName},
			{status, Status}, {index, Index}, {varbinds, Varbinds},
			{userdata, UserData}]),
	{self, Self} = lists:keyfind(self, 1, UserData),
	Self ! ok,
	no_reply.

-spec handle_report(TargetName, SnmpReportInfo, UserData) -> Reply
	when
		TargetName :: snmpm:target_name(),
		SnmpReportInfo :: snmpm_user:snmp_gen_info(),
		UserData :: term(),
		Reply :: ignore | unregister
				| {register, UserId, TargetName, AgentConfig},
		UserId :: term(),
		AgentConfig :: [snmpm:agent_config()].
%% @doc Handle a report message.
handle_report(TargetName,
		{Status, Index, Varbinds} = _SnmpReportInfo, UserData) ->
	error_logger:error_report(["SNMP Manager: Received Report",
			{target_name, TargetName},
			{status, Status}, {index, Index}, {varbinds, Varbinds},
			{userdata, UserData}]),
	{self, Self} = lists:keyfind(self, 1, UserData),
	Self ! ok,
	ignore.

-spec handle_invalid_result(In, Out) -> any()
	when
		In :: {Function, Args},
		Function :: atom(),
		Args :: list(),
		Out :: {crash, CrashInfo} | {result, InvalidResult},
		CrashInfo :: {ErrorType, Error, Stacktrace},
		ErrorType :: atom(),
		Error :: term(),
		Stacktrace :: list(),
		InvalidResult :: term().
%% @doc Called if any of the other callback functions crashes.
handle_invalid_result({Function, Args} = _In,
		{crash, {ErrorType, Error, Stacktrace} = _CrashInfo} = _Out) ->
	error_logger:error_report(["SNMP Manager: User Callback Crashed",
			{module, ?MODULE}, {function, Function}, {args, Args},
			{error_type, ErrorType}, {error, Error},
			{stacktrace, Stacktrace}]);
handle_invalid_result({Function, Args} = _In,
		{result, Result} = _Out) ->
	error_logger:error_report(["SNMP Manager: User Callback Invalid Result",
			{module, ?MODULE}, {function, Function}, {args, Args},
			{result, Result}]).

%%----------------------------------------------------------------------
%%  internal functions
%%----------------------------------------------------------------------

