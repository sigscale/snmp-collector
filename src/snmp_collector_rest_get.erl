%%% snmp_collector_rest_get.erl
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

-module(snmp_collector_rest_get).
-copyright('Copyright (c) 2016 - 2019 SigScale Global Inc.').

-export([do/1]).

-include_lib("inets/include/httpd.hrl").

-spec do(ModData) -> Result when
	ModData :: #mod{},
	Result :: {proceed, OldData} | {proceed, NewData} | {break, NewData} | done,
	OldData :: list(),
	NewData :: [{response,{StatusCode,Body}}] | [{response,{response,Head,Body}}]
			| [{response,{already_sent,StatusCode,Size}}],
	StatusCode :: integer(),
	Body :: list() | nobody | {Fun, Arg},
	Head :: [HeaderOption],
	HeaderOption :: {Option, Value} | {code, StatusCode},
	Option :: accept_ranges | allow
			| cache_control | content_MD5
			| content_encoding | content_language
			| content_length | content_location
			| content_range | content_type | date
			| etag | expires | last_modified
			| location | pragma | retry_after
			| server | trailer | transfer_encoding,
	Value :: string(),
	Size :: term(),
	Fun :: fun((Arg) -> sent| close | Body),
	Arg :: [term()].
%% @doc Erlang web server API callback function.
do(#mod{method = Method, parsed_header = Headers, request_uri = Uri,
		data = Data} = ModData) ->
	case Method of
		"GET" ->
			case proplists:get_value(status, Data) of
				{_StatusCode, _PhraseArgs, _Reason} ->
					{proceed, Data};
				undefined ->
					case proplists:get_value(response, Data) of
						undefined ->
							case lists:keyfind(resource, 1, Data) of
								false ->
									{proceed, Data};
								{_, Resource} ->
									Path = http_uri:decode(Uri),
									content_type_available(Headers, Path, Resource, ModData)
							end;
						_Response ->
							{proceed,  Data}
					end
			end;
		_ ->
			{proceed, Data}
	end.

%% @hidden
content_type_available(Headers, Uri, Resource, #mod{data = Data} = ModData) ->
	case lists:keyfind("accept", 1, Headers) of
		{_, RequestingType} ->
			AvailableTypes = Resource:content_types_provided(),
			case lists:member(RequestingType, AvailableTypes) of
				true ->
					parse_query(Resource, ModData, httpd_util:split_path(Uri));
				false ->
					Response = "<h2>HTTP Error 415 - Unsupported Media Type</h2>",
					{proceed, [{response, {415, Response}} | Data]}
			end;
		_ ->
			parse_query(Resource, ModData, httpd_util:split_path(Uri))
	end.

%% @hidden
parse_query(Resource, ModData, {Path, []}) ->
	do_get(Resource, ModData, string:tokens(Path, "/"), []);
parse_query(Resource, ModData, {Path, "?" ++ Query}) ->
	do_get(Resource, ModData, string:tokens(Path, "/"),
		snmp_collector_rest:parse_query(Query));
parse_query(_R, #mod{data = Data} = ModData, _Q) ->
	Response = "<h2>HTTP Error 404 - Not Found</h2>",
	{proceed, [{response, {404, Response}} | Data]}.

%% @hidden
do_get(Resource, #mod{parsed_header = _Headers} = ModData,
		["snmp", "v1", "mibs"], Query) ->
	do_response(ModData, Resource:get_mibs(Query));
do_get(Resource, ModData, ["snmp", "v1", "mibs", Id], Query) ->
	do_response(ModData, Resource:get_mib(Id, Query));
do_get(Resource, #mod{parsed_header = Headers} = ModData,
		["partyManagement", "v1", "individual"], Query) ->
	do_response(ModData, Resource:get_users(Query, Headers));
do_get(Resource, ModData, ["partyManagement", "v1", "individual", Id], Query) ->
	do_response(ModData, Resource:get_user(Id, Query));
do_get(Resource, #mod{parsed_header = Headers} = ModData,
		["eventManagement", "v1", "event"], Query) ->
	do_response(ModData, Resource:get_events(Query, Headers));
do_get(Resource, #mod{parsed_header = Headers} = ModData,
		["snmp", "v1", "log", "http"], Query) ->
	do_response(ModData, Resource:get_http());
do_get(Resource, ModData, ["eventManagement", "v1", "event", Id], Query) ->
	do_response(ModData, Resource:get_event(Id, Query));
do_get(_, #mod{data = Data} = ModData, _, _) ->
	Response = "<h2>HTTP Error 404 - Not Found</h2>",
	{proceed, [{response, {404, Response}} | Data]}.

%% @hidden
do_response(#mod{data = Data} = ModData, {ok, Headers, ResponseBody}) ->
	Size = integer_to_list(iolist_size(ResponseBody)),
	NewHeaders = Headers ++ [{content_length, Size}],
	send(ModData, 200, NewHeaders, ResponseBody),
	{proceed,[{response,{already_sent, 200, Size}} | Data]};
do_response(#mod{data = Data} = ModData, {error, 400}) ->
	Response = "<h2>HTTP Error 400 - Bad Request</h2>",
	{proceed, [{response, {400, Response}} | Data]};
do_response(#mod{data = Data} = ModData, {error, 404}) ->
	Response = "<h2>HTTP Error 404 - Not Found</h2>",
	{proceed, [{response, {404, Response}} | Data]};
do_response(#mod{data = Data} = ModData, {error, 412}) ->
	Response = "<h2>HTTP Error 412 - Precondition Failed</h2>",
	{proceed, [{response, {412, Response}} | Data]};
do_response(#mod{data = Data} = ModData, {error, 416}) ->
	Response = "<h2>HTTP Error 416 - Range Not Satisfiable</h2>",
	{proceed, [{response, {416, Response}} | Data]};
do_response(#mod{data = Data} = ModData, {error, 500}) ->
	Response = "<h2>HTTP Error 500 - Server Error</h2>",
	{proceed, [{response, {500, Response}} | Data]}.


%% @hidden
send(#mod{socket = Socket, socket_type = SocketType} = ModData,
		StatusCode, Headers, ResponseBody) ->
	httpd_response:send_header(ModData, StatusCode, Headers),
	httpd_socket:deliver(SocketType, Socket, ResponseBody).

