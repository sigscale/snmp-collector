%%% snmp_collector_event_ves.erl
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
%%% @doc This {@link //stdlib/gen_event. gen_event} behaviour callback
%%% 	module implements an event handler of the
%%% 	{@link //snmp_collector. snmp_collector} application.
%%%
-module(snmp_collector_event_ves).
-copyright('Copyright (c) 2020 SigScale Global Inc.').

-behaviour(gen_event).

%% export the snmp_collector_event_ves API
-export([]).

%% export the callbacks needed for gen_event behaviour
-export([init/1, handle_call/2, handle_event/2, handle_info/2,
			terminate/2, code_change/3]).

-include("snmp_collector_log.hrl").

-record(state,
		{authorization :: tuple(),
		uri :: string(),
		profile :: atom(),
		delay :: non_neg_integer(),
		buffer = [] :: [fault_event()],
		timer :: reference() | undefined,
		sync = true :: boolean()}).
-type state() :: #state{}.

%% support deprecated_time_unit()
-define(MILLISECOND, milli_seconds).
%-define(MILLISECOND, millisecond).

%%----------------------------------------------------------------------
%%  The snmp_collector_event_ves API
%%----------------------------------------------------------------------

%%----------------------------------------------------------------------
%%  The snmp_collector_event_ves gen_event callbacks
%%----------------------------------------------------------------------

-spec init(Args) -> Result
	when
		Args :: [any()],
		Result :: {ok, State}
			| {ok, State, hibernate}
			| {error, Reason},
		State :: state(),
		Reason :: term().
%% @doc Initialize the {@module} server.
%% @see //stdlib/gen_event:init/1
%% @private
%%
init([] = _Args) ->
	{ok, UserName} = application:get_env(snmp_collector, ves_username),
	{ok, Password} = application:get_env(snmp_collector, ves_password),
	{ok, Url} = application:get_env(snmp_collector, ves_url),
	{ok, Profile} = application:get_env(snmp_collector, ves_profile),
	{ok, Delay} = application:get_env(snmp_collector, ves_reorder_delay),
	EncodeKey = "Basic" ++ base64:encode_to_string(string:concat(UserName ++ ":", Password)),
	Authorization = {"authorization", EncodeKey},
	{ok, #state{authorization = Authorization,
			uri = Url, profile = Profile, delay = Delay}}.

-spec handle_event(Event, State) -> Result
	when
		Event :: term(),
		State :: state(),
		Result :: {ok, NewState}
				| {ok, NewState, hibernate}
				| {swap_handler, Args1, NewState, Handler2, Args2}
				| remove_handler,
		NewState :: term(),
		Args1 :: term(),
		Args2 :: term(),
		Handler2 :: Module2 | {Module2, Id},
		Module2 :: atom(),
		Id :: term().
%% @doc Handle a request sent using {@link //stdlib/genevent:handle_event/2.
%% 	gen_event:notify/2, gen_event:sync_notify/2}.
%% @private
%%
handle_event(Event, #state{delay = 0} = State) ->
	post(Event, State);
handle_event(Event, #state{timer = Timer} = State)
		when is_reference(Timer) ->
	erlang:cancel_timer(Timer),
	handle_event(Event, State#state{timer = undefined});
handle_event({Now, _, _, _, _} = Event,
		#state{delay = Delay, buffer = Buffer} = State) ->
	F = fun({TS, _, _, _, _}) when (Now - TS) < Delay ->
				true;
			(_) ->
				false
	end,
	{Events, #state{buffer = NewBuffer} = NewState}
			= gather(lists:dropwhile(F, Buffer), State),
	post(Events, NewState#state{buffer = [Event | NewBuffer]}).

-spec handle_call(Request, State) -> Result
	when
		Request :: term(),
		State :: state(),
		Result :: {ok, Reply :: term(), NewState :: state()}
			| {ok, Reply :: term(), NewState :: state(), hibernate}
			| {swap_handler, Reply :: term(), Args1 :: term(), NewState :: state(),
				Handler2 :: Module2 | {Module2, Id}, Args2 :: term()}
			| {remove_handler, Reply :: term()},
		Module2 :: atom(),
		Id :: term().
%% @doc Handle a request sent using {@link //stdlib/gen_event:call/3.
%% 	gen_event:call/3,4}.
%% @see //stdlib/gen_event:handle_call/3
%% @private
%%
handle_call(_Request, _State) ->
	{remove_handler, not_implementedd}.

-spec handle_info(Info, State) -> Result
	when
		Info :: term(),
		State :: state(),
		Result :: {ok, NewState :: term()}
			| {ok, NewState :: term(), hibernate}
			| {swap_handler, Args1 :: term(), NewState :: term(),
			Handler2, Args2 :: term()} | remove_handler,
		Handler2 :: Module2 | {Module2, Id},
		Module2 :: atom(),
		Id :: term().
%% @doc Handle a received message.
%% @see //stdlib/gen_event:handle_info/2
%% @private
%%
handle_info({timeout, Timer, []} = Info,
		#state{timer = LastTimer} = State)
		when is_reference(LastTimer), LastTimer /= Timer ->
	erlang:cancel_timer(LastTimer),
	handle_info(Info, State#state{timer = undefined});
handle_info({timeout, _Timer, []} = _Info,
		#state{delay = Delay, buffer = Buffer} = State) ->
	Now = erlang:system_time(?MILLISECOND),
	F = fun({TS, _, _, _, _}) when (Now - TS) < Delay ->
				true;
			(_) ->
				false
	end,
	{Events, #state{buffer = NewBuffer} = NewState}
			= gather(lists:dropwhile(F, Buffer), State),
	post(Events, NewState#state{timer = undefined, buffer = NewBuffer}).

-spec terminate(Arg, State) -> term()
	when
		Arg :: Args :: term() | {stop, Reson :: term()} | {error, term()}
				| stop | remove_handler | {error,{'EXIT', Reason :: term()}},
      State :: state().
%% @doc Cleanup and exit.
%% @see //stdlib/gen_event:terminate/3
%% @private
%%
terminate(_Reason, _State) ->
	ok.

-spec code_change(OldVsn, State, Extra) -> Result
	when
		OldVsn :: term() | {down, term()},
		State :: term(),
		Extra :: term(),
		Result :: {ok, NewState :: term()}.
%% @doc Update internal state data during a release upgrade&#047;downgrade.
%% @see //stdlib/gen_event:code_change/3
%% @private
%%
code_change(_OldVsn, State, _Extra) ->
	{ok, State}.

%%----------------------------------------------------------------------
%%  internal functions
%%----------------------------------------------------------------------

-spec gather(Events, State) -> Result
	when
		Events :: [fault_event()],
		State :: state(),
		Result :: {Events, State}.
%% @doc Gather all events for alarmIds ready to send.
%% @private
gather(Events, State) ->
	gather(Events, State, []).
%% @hidden
gather([{_, _, _, #{"domain" := "fault", "reportingEntityId" := AgentId},
		#{"alarmAdditionalInformation" := #{"alarmId" := AlarmId}}} | T],
		#state{buffer = Buffer} = State, Acc) ->
	F = fun({_, _, _, #{"reportingEntityId" := Agent},
					#{"alarmAdditionalInformation" := #{"alarmId" := ID}}})
					when Agent == AgentId, ID == AlarmId ->
				true;
			(_) ->
				false
	end,
	{Events, NewBuffer} = lists:partition(F, Buffer),
	gather(T, State#state{buffer  = NewBuffer}, [lists:reverse(Events) | Acc]);
gather([{_, _, _, #{"domain" := "fault", "reportingEntityName" := AgentName},
		#{"alarmAdditionalInformation" := #{"alarmId" := AlarmId}}} | T],
		#state{buffer = Buffer} = State, Acc) ->
	F = fun({_, _, _, #{"reportingEntityName" := Agent},
					#{"alarmAdditionalInformation" := #{"alarmId" := ID}}})
					when Agent == AgentName, ID == AlarmId ->
				true;
			(_) ->
				false
	end,
	{Events, NewBuffer} = lists:partition(F, Buffer),
	gather(T, State#state{buffer  = NewBuffer}, [lists:reverse(Events) | Acc]);
gather([H | T], State, Acc) ->
	gather(T, State, [H | Acc]);
gather([], State, Acc) ->
	gather1(Acc, State, []).
%% @hidden
gather1([H | T], State, Acc) when is_list(H) ->
	F = fun({_, _, _, #{"eventName" := notifyNewAlarm}, _}, _) ->
				true;
			({_, _, _, #{"eventName" := notifyChangedAlarm}, _},
					{_, _, _, #{"eventName" := notifyClearedAlarm}, _}) ->
				true;
			({_, _, _, _, _}, {_, _, _, _, _}) ->
				false
	end,
	gather1(T, State, [lists:sort(F, H) | Acc]);
gather1([H | T], State, Acc) ->
	gather1(T, State, [H | Acc]);
gather1([], State, Acc) ->
	{lists:flatten(Acc), State}.

-spec post(Events, State) -> Result
	when
		Events :: [fault_event()],
		State :: state(),
		Result :: {ok, State}.
%% @doc POST VES events on northbound interface to ves_collector.
%% @private
post({_TS, _N, _Node, #{"domain" := Domain} = CH, OF}, State) ->
	post1(#{"event" => #{"commonEventHeader" => CH,
			Domain ++ "Fields" => OF}}, State);
post([{_TS, _N, _Node, #{"domain" := Domain} = CH, OF}], State) ->
	post1(#{"event" => #{"commonEventHeader" => CH,
			Domain ++ "Fields" => OF}}, State);
post(Events, State) when is_list(Events) ->
	post(Events, State, []).
%% @hidden
post([{_TS, _N, _Node, #{"domain" := Domain} = CH, OF} | T], State, Acc) ->
	post(T, State,
			[#{"commonEventHeader" => CH, Domain ++ "Fields" => OF} | Acc]);
post([], #state{delay = 0} = State, []) ->
	{ok, State};
post([], #state{delay = Delay} = State, []) ->
	{ok, State#state{timer = erlang:start_timer(Delay, self(), [])}};
post([], State, Acc) ->
	post1(#{"eventList" => Acc}, State).
%% @hidden
post1(VES, #state{sync = true, authorization = Authorization,
		uri = Url, profile = Profile, delay = Delay} = State) ->
	ContentType = "application/json",
	RequestBody = zj:encode(VES),
	Path = Url ++ "/eventListener/v5",
	Request = {Path, [Authorization], ContentType, RequestBody},
	HTTPOptions =  [{timeout, 4000}],
	Options = [{sync, true}],
	case httpc:request(post, Request, HTTPOptions, Options, Profile) of
		{error, Reason} ->
			error_logger:error_report(["VES POST Failed",
					{url, Path}, {profile, Profile},
					{sync, true}, {error, Reason}]),
			exit(Reason);
		{ok, {{_Version, Status, _Reason}, _Headers, _Body}}
				when Status >=  200, Status < 300, Delay =:= 0 ->
			{ok, State#state{sync = false}};
		{ok, {{_Version, Status, _Reason}, _Headers, _Body}}
				when Status >=  200, Status < 300 ->
			{ok, State#state{sync = false,
					timer = erlang:start_timer(Delay, self(), [])}};
		{ok, {{_Version, _Status, _Reason}, _Headers, _Body}} when Delay =:= 0 ->
			{ok, State#state{sync = false}};
		{ok, {{Version, Status, Reason}, _Headers, _Body}} ->
			error_logger:warning_report(["VES POST Failed",
					{url, Path}, {profile, Profile},
					{sync, true}, {version, Version},
					{status, Status}, {reason, Reason}]),
			{ok, State#state{sync = false,
					timer = erlang:start_timer(Delay, self(), [])}}
	end;
post1(VES, #state{sync = false, authorization = Authorization,
		uri = Url, profile = Profile, delay = Delay} = State) ->
	ContentType = "application/json",
	RequestBody = zj:encode(VES),
	Path = Url ++ "/eventListener/v5",
	Request = {Path, [Authorization], ContentType, RequestBody},
	HTTPOptions =  [{timeout, 4000}],
	Options = [{sync, false}, {receiver, fun check_response/1}],
	case httpc:request(post, Request, HTTPOptions, Options, Profile) of
		{error, Reason} ->
			error_logger:error_report(["VES POST Failed",
					{url, Path}, {profile, Profile},
					{sync, false}, {error, Reason}]),
			exit(Reason);
		{ok, _RequestID} when Delay =:= 0 ->
			{ok, State};
		{ok, _RequestID} ->
			{ok, State#state{timer = erlang:start_timer(Delay, self(), [])}}
	end.

-spec check_response(ReplyInfo) -> any()
	when
		ReplyInfo :: tuple().
%% @doc Check the response of a httpc request.
%% @hidden
check_response({_RequestId, {error, Reason}}) ->
	error_logger:warning_report(["VES POST Failed",
			{error, Reason}]);
check_response({_RequestId, {{_Version, Status, _Reason}, _Headers, _Body}})
		when Status >=  200, Status < 300 ->
	ok;
check_response({_RequestId, {{Version, Status, Reason}, _Headers, _Body}}) ->
	error_logger:warning_report(["VES POST Failed",
			{version, Version}, {status, Status}, {reason, Reason}]).

