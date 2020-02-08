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

-record(state,
		{authorization :: tuple(),
		uri :: string(),
		options :: list()}).
-type state() :: #state{}.

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
	{ok, Options} = application:get_env(snmp_collector, ves_options),
	{ok, Url} = application:get_env(snmp_collector, ves_url),
	EncodeKey = "Basic" ++ base64:encode_to_string(string:concat(UserName ++ ":", Password)),
	Authorization = {"authorization", EncodeKey},
	{ok, #state{authorization = Authorization, uri = Url, options = Options}}.

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
handle_event({_TS, _N, _Node,
		#{"domain" := Domain} = CommonEventHeader, OtherFields} = _Event,
		#state{authorization = Authorization,
		uri = Url, options = Options} = State) when is_map(OtherFields) ->
	ContentType = "application/json",
	Accept = {"accept", "application/json"},
	F = fun(Key, Value, Acc) ->
				[#{"name" => Key, "value" => Value} | Acc]
	end,
	Event1 = #{"event" => #{"commonEventHeader" => CommonEventHeader,
			Domain ++ "Fields" => maps:fold(F, [], OtherFields)}},
	RequestBody = zj:encode(Event1),
	Request = {Url ++ "/eventListener/v5",
			[Accept, Authorization], ContentType, RequestBody},
	NewOptions = [{sync, false}, {receiver, fun check_response/1} | Options],
	case httpc:request(post, Request, [], NewOptions) of
		{error, Reason} ->
			error_logger:info_report(["SNMP Manager POST Failed",
					{error, Reason}]);
		_RequestID ->
			{ok, State}
	end.

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
handle_info(_Info, _State) ->
	remove_handler.

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

-spec check_response(ReplyInfo) -> any()
	when
		ReplyInfo :: tuple().
%% @doc Check the response of a httpc request.
check_response({_RequestId, {error, Reason}}) ->
	error_logger:warning_report(["SNMP Manager POST Failed",
			{error, Reason}]);
check_response({_RequestId, {{"HTTP/1.1", 400, _BadRequest},_ , _}}) ->
	error_logger:warning_report(["SNMP Manager POST Failed",
			{error, "400, bad_request"}]);
check_response({_RequestId, {{"HTTP/1.1", 500, _InternalError},_ , _}}) ->
	error_logger:warning_report(["SNMP Manager POST Failed",
			{error, "500, internal_server_error"}]);
check_response({_RequestId, {{"HTTP/1.1", 502, _GateWayError},_ , _}}) ->
	error_logger:warning_report(["SNMP Manager POST Failed",
			{error, "502, bad_gateway"}]);
check_response({_RequestId, {{"HTTP/1.1", 201, _Created},_ , _}}) ->
	void.

