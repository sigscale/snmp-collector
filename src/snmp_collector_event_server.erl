%%% snmp_collector_event_server.erl
%%% vim: ts=3
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% @copyright 2020 SigScale Global Inc.
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
%%% @doc This {@link //stdlib/gen_server. gen_server} behaviour callback
%%%     module implements an event handler supervisor of the
%%%     {@link //snmp_collector. snmp_collector} application.
%%%
-module(snmp_collector_event_server).
-copyright('Copyright (c) 2020 SigScale Global Inc.').

-behaviour(gen_server).

%% export the snmp_collector_event_server API
-export([]).

%% export the callbacks needed for gen_server behaviour
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
			terminate/2, code_change/3]).

-record(state,{}).

%%----------------------------------------------------------------------
%%  The snmp_collector_event_server API
%%----------------------------------------------------------------------

%%----------------------------------------------------------------------
%%  The snmp_collector_event_server gen_server callbacks
%%----------------------------------------------------------------------

-spec init(Args) -> Result
	when
		Args :: [term()],
		Result :: {ok, State}
		| {ok, State, Timeout}
		| {stop, Reason} | ignore,
		State :: #state{},
		Timeout :: timeout(),
		Reason :: term().
%% @doc Initialize the {@module} server.
%% @see //stdlib/gen_server:init/1
%% @private
%%
init([]) ->
	{ok, #state{}, 0}.

-spec handle_call(Request, From, State) -> Result
	when
		Request :: term(),
		From :: {pid(), Tag :: any()},
		State :: #state{},
		Result :: {reply, Reply :: term(), NewState :: #state{}}
		| {reply, Reply :: term(), NewState :: #state{}, timeout() | hibernate}
		| {noreply, NewState :: #state{}}
		| {noreply, NewState :: #state{}, timeout() | hibernate}
		| {stop, Reason :: term(), Reply :: term(), NewState :: #state{}}
		| {stop, Reason :: term(), NewState :: #state{}}.
%% @doc Handle a request sent using {@link //stdlib/gen_server:call/2.
%%      gen_server:call/2,3} or {@link //stdlib/gen_server:multi_call/2.
%%      gen_server:multi_call/2,3,4}.
%% @see //stdlib/gen_server:handle_call/3
%% @private
%%
handle_call(_Request, _From, _State) ->
	{stop, not_implemented, _State}.

-spec handle_cast(Request, State) -> Result
	when
		Request :: term(),
		State :: #state{},
		Result :: {noreply, NewState :: #state{}}
		| {noreply, NewState :: #state{}, timeout() | hibernate}
		| {stop, Reason :: term(), NewState :: #state{}}.
%% @doc Handle a request sent using {@link //stdlib/gen_server:cast/2.
%%      gen_server:cast/2} or {@link //stdlib/gen_server:abcast/2.
%%      gen_server:abcast/2,3}.
%% @see //stdlib/gen_server:handle_cast/2
%% @private
%%
handle_cast(stop, State) ->
	{stop, normal, State}.

-spec handle_info(Info, State) -> Result
	when
		Info :: timeout | term(),
		State:: #state{},
		Result :: {noreply, NewState :: #state{}}
		| {noreply, NewState :: #state{}, timeout() | hibernate}
		| {stop, Reason :: term(), NewState :: #state{}}.
%% @doc Handle a received message.
%% @see //stdlib/gen_server:handle_info/2
%% @private
%%
handle_info(timeout = _Info, State) ->
	case gen_event:add_sup_handler(snmp_collector_event,
			snmp_collector_event_log, []) of
		ok ->
			case application:get_env(ves_url) of
				{ok, []} ->
					{noreply, State};
				{ok, _URI} ->
					case gen_event:add_sup_handler(snmp_collector_event,
							snmp_collector_event_ves, []) of
						ok ->
							{noreply, State};
						{Error, Reason} when Error == error; Error == 'EXIT' ->
							{stop, Reason}
					end
			end;
		{Error, Reason} when Error == error; Error == 'EXIT' ->
			{stop, Reason}
	end;
handle_info({gen_event_EXIT, _Handler, Reason}, _State)
		when Reason == normal; Reason == shutdown ->
	{stop, Reason};
handle_info({gen_event_EXIT, Handler, Reason}, State) ->
	case gen_event:add_sup_handler(snmp_collector_event, Handler, []) of
		ok ->
			error_logger:error_report(["Event handler EXIT",
					{handler, Handler}, {reason, Reason}]),
			{noreply, State};
		{Error, Reason} when Error == error; Error == 'EXIT' ->
			{stop, Reason}
	end.

-spec terminate(Reason, State) -> any()
	when
		Reason :: normal | shutdown | {shutdown, term()} | term(),
		State::#state{}.
%% @doc Cleanup and exit.
%% @see //stdlib/gen_server:terminate/3
%% @private
%%
terminate(_Reason, _State) ->
	ok.

-spec code_change(OldVsn, State, Extra) -> Result
	when
		OldVsn :: term() | {down, term()},
		State :: #state{},
		Extra :: term(),
		Result :: {ok, NewState :: #state{}} | {error, Reason :: term()}.
%% @doc Update internal state data during a release upgrade&#047;downgrade.
%% @see //stdlib/gen_server:code_change/3
%% @private
%%
code_change(_OldVsn, State, _Extra) ->
	{ok, State}.

%%----------------------------------------------------------------------
%%  internal functions
%%----------------------------------------------------------------------

