%%% snmp_collector_sup.erl
%%% vim: ts=3
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% @copyright 2016 - 2017 SigScale Global Inc.
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
%%% @docfile "{@docsrc supervision.edoc}"
%%%
-module(snmp_collector_sup).
-copyright('Copyright (c) 2016 - 2017 SigScale Global Inc.').

-behaviour(supervisor).

%% export the callback needed for supervisor behaviour
-export([init/1]).

%%----------------------------------------------------------------------
%%  The supervisor callback
%%----------------------------------------------------------------------

-spec init(Args) -> Result
	when
		Args :: [term()],
			Result :: {ok, {{supervisor:strategy(), non_neg_integer(), pos_integer()},
			[supervisor:child_spec()]}} | ignore.
%% @doc Initialize the {@module} supervisor.
%% @see //stdlib/supervisor:init/1
%% @private
%%
init([]) ->
	ChildSpecs = [supervisor(snmp_collector_manager_sup_sup, []),
			supervisor(snmp_collector_debug_sup, []),
			supervisor(snmp_collector_get_sup, [])],
	{ok, {{one_for_one, 10, 60}, ChildSpecs}}.

%%----------------------------------------------------------------------
%%  internal functions
%%----------------------------------------------------------------------

-spec supervisor(StartMod, Args) -> Result
	when
		StartMod :: atom(),
		Args :: [term()],
		Result :: supervisor:child_spec().
%% @doc Build a supervisor child specification for a
%%      {@link //stdlib/supervisor. supervisor} behaviour.
%% @private
%%
supervisor(StartMod, Args) ->
	StartArgs = [{local, StartMod}, StartMod, Args],
	StartFunc = {supervisor, start_link, StartArgs},
	{StartMod, StartFunc, permanent, infinity, supervisor, [StartMod]}.

