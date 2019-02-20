%%% snmp_collector_rest_res_ves.erl
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
%%%
-module(snmp_collector_rest_res_ves).
-copyright('Copyright (c) 2016 - 2019 SigScale Global Inc.').

-export([content_types_accepted/0, content_types_provided/0,
		post_event/1]).

-include_lib("inets/include/mod_auth.hrl").
-include("snmp_collector.hrl").
-include_lib("snmp/include/snmp_types.hrl").

%% support deprecated_time_unit()
-define(MILLISECOND, milli_seconds).
%-define(MILLISECOND, millisecond).

-spec content_types_accepted() -> ContentTypes
	when
		ContentTypes :: list().
%% @doc Provides list of resource representations accepted.
content_types_accepted() ->
	["application/json", "application/json-patch+json", "text/plain"].

-spec content_types_provided() -> ContentTypes
	when
		ContentTypes :: list().
%% @doc Provides list of resource representations available.
content_types_provided() ->
	["application/json", "text/plain"].

-spec post_event(RequestBody) -> Result
	when
		RequestBody :: map(),
		Result :: {ok, Headers :: [tuple()], Body :: iolist()}
				| {error, ErrorCode :: integer()}.
%% @doc Respond to `POST /snmp/v1/ves' and add a new event
% resource.
post_event(RequestBody) ->
	StringifyedBody = snmp_collector_utils:stringify(RequestBody),
	case catch zj:encode(StringifyedBody) of 
		Body when is_list(Body)->
			Href = "ves/v2/events",
			Headers = [{location, Href},
			{content_type, "application/json"}],
			{ok, Headers, Body};
		{'EXIT', _Reason} ->
			{error, 400}
	end.

%%----------------------------------------------------------------------
%%  internal functions
%%----------------------------------------------------------------------

