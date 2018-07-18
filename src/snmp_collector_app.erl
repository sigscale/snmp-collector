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
%%% 	module starts and stops the
%%% 	{@link //sigcale_snmp_collector. sigscale_snmp_collector} application.
%%%
-module(snmp_collector_app).
-copyright('Copyright (c) 2018 SigScale Global Inc.').

-behaviour(application).

%% callbacks needed for application behaviour
-export([start/2, stop/1, config_change/3]).
%% optional callbacks for application behaviour
-export([prep_stop/1, start_phase/3]).

-include("snmp_collector.hrl").

-record(state, {}).

%%----------------------------------------------------------------------
%%  The snmp_collector_app aplication callbacks
%%----------------------------------------------------------------------

-type start_type() :: normal | {takeover, node()} | {failover, node()}.
-spec start(StartType, StartArgs) -> Result
	when
		StartType :: start_type(),
		StartArgs :: term(),
		Result :: {'ok', pid()} | {'ok', pid(), State} | {'error', Reason},
		State :: #state{},
		Reason :: term().
%% @doc Starts the application processes.
%% @see //kernel/application:start/1
%% @see //kernel/application:start/2
%%
start(normal = _StartType, _Args) ->
	{error, not_implemented}.

%%----------------------------------------------------------------------
%%  The snmp_collector_app private API
%%----------------------------------------------------------------------

