%%% snmp_collector_debug_sup.erl
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
-module(snmp_collector_debug_sup).
-copyright('Copyright (c) 2016 - 2017 SigScale Global Inc.').

-behaviour(supervisor).

%% export the callback needed for supervisor behaviour
-export([init/1]).

%%----------------------------------------------------------------------
%%  The supervisor callback
%%----------------------------------------------------------------------

-spec init(Args) -> Result
	when
		Args :: [],
		Result :: {ok,{{RestartStrategy, MaxR, MaxT}, [ChildSpec]}} | ignore,
		RestartStrategy :: simple_one_for_one,
		MaxR :: non_neg_integer(),
		MaxT :: pos_integer(),
		ChildSpec :: supervisor:child_spec().
%% @doc Initialize the {@module} supervisor.
%% @see //stdlib/supervisor:init/1
%% @private
%%
init([]) ->
	StartMod = snmp_collector_debug_fsm,
	StartFunc = {gen_fsm, start_link, [StartMod]},
erlang:display({?MODULE, ?LINE, StartFunc}),
	ChildSpec = {StartMod, StartFunc, transient, 4000, worker, [StartMod]},
	{ok, {{simple_one_for_one, 10, 60}, [ChildSpec]}}.


