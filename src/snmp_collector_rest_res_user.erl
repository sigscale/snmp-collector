%%% snmp_collector_rest_res_user.erl
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
%%% @doc This library module implements resource handling functions for a
%%% 	REST server in the {@link //snmp_collector. snmp_collector} application.
%%%
-module(snmp_collector_rest_res_user).
-copyright('Copyright (c) 2016 - 2019 SigScale Global Inc.').

-export([content_types_accepted/0, content_types_provided/0, get_params/0,
		get_user/2, get_users/2, post_user/1, delete_user/1, user/1]).

-include_lib("inets/include/mod_auth.hrl").

-spec content_types_accepted() -> ContentTypes
	when
		ContentTypes :: list().
%% @doc Provides list of resource representations accepted.
content_types_accepted() ->
	["application/json", "application/json-patch+json"].

-spec content_types_provided() -> ContentTypes
	when
		ContentTypes :: list().
%% @doc Provides list of resource representations available.
content_types_provided() ->
	["application/json"].

-spec get_users(Query, Headers) -> Result
	when
		Query :: [{Key :: string(), Value :: string()}],
		Headers :: [tuple()],
		Result :: {ok, Headers :: [tuple()], Body :: iolist()}
				| {error, ErrorCode :: integer()}.
%% @doc Body producing function for `GET /partyManagement/v1/individual'
%% requests.
get_users(Query, Headers) ->
	case lists:keytake("fields", 1, Query) of
		{value, {_, Filters}, NewQuery} ->
			get_users1(NewQuery, Filters, Headers);
		false ->
			get_users1(Query, [], Headers)
	end.
%% @hidden
get_users1(Query, Filters, Headers) ->
	case {lists:keyfind("if-match", 1, Headers),
			lists:keyfind("if-range", 1, Headers),
			lists:keyfind("range", 1, Headers)} of
		{{"if-match", Etag}, false, {"range", Range}} ->
			case global:whereis_name(Etag) of
				undefined ->
					{error, 412};
				PageServer ->
					case snmp_collector_rest:range(Range) of
						{error, _} ->
							{error, 400};
						{ok, {Start, End}} ->
							query_page(PageServer, Etag, Query, Filters, Start, End)
					end
			end;
		{{"if-match", Etag}, false, false} ->
			case global:whereis_name(Etag) of
				undefined ->
					{error, 412};
				PageServer ->
					query_page(PageServer, Etag, Query, Filters, undefined, undefined)
			end;
		{false, {"if-range", Etag}, {"range", Range}} ->
			case global:whereis_name(Etag) of
				undefined ->
					case snmp_collector_rest:range(Range) of
						{error, _} ->
							{error, 400};
						{ok, {Start, End}} ->
							query_start(Query, Filters, Start, End)
					end;
				PageServer ->
					case snmp_collector_rest:range(Range) of
						{error, _} ->
							{error, 400};
						{ok, {Start, End}} ->
							query_page(PageServer, Etag, Query, Filters, Start, End)
					end
			end;
		{{"if-match", _}, {"if-range", _}, _} ->
			{error, 400};
		{_, {"if-range", _}, false} ->
			{error, 400};
		{false, false, {"range", Range}} ->
			case snmp_collector_rest:range(Range) of
				{error, _} ->
					{error, 400};
				{ok, {Start, End}} ->
					query_start(Query, Filters, Start, End)
			end;
		{false, false, false} ->
			query_start(Query, Filters, undefined, undefined)
	end.

-spec get_user(Id, Query) -> Result
	when
		Id :: string(),
		Query :: [{Key :: string(), Value :: string()}],
		Result :: {ok, Headers :: [tuple()], Body :: iolist()}
				| {error, ErrorCode :: integer()}.
%% @doc Body producing function for `GET /partyManagement/v1/individual/{id}'
%% requests.
get_user(Id, Query) ->
	case lists:keytake("fields", 1, Query) of
		{value, {_, L}, NewQuery} ->
			get_user(Id, NewQuery, string:tokens(L, ","));
		false ->
			get_user(Id, Query, [])
	end.
%% @hidden
get_user(Id, [] = _Query, _Filters) ->
	case snmp_collector:get_user(Id) of
		{ok, #httpd_user{user_data = UserData} = UserRec} ->
			UserMap = user(UserRec),
			Chars = maps:get("characteristic", UserMap),
			F = fun(#{"name" := "password"}) ->
						false;
					(_) ->
						true
			end,
			NewChars = lists:filter(F, Chars),
			NewUser = UserMap#{"characteristic" => NewChars},
			Headers1 = case lists:keyfind(last_modified, 1, UserData) of
				{_, LastModified} ->
					[{etag, snmp_collector_rest:etag(LastModified)}];
				false ->
					[]
			end,
			Headers2 = [{content_type, "application/json"} | Headers1],
			Body = zj:encode(NewUser),
			{ok, Headers2, Body};
		{error, _Reason} ->
			{error, 404}
	end;
get_user(_, _, _) ->
	{error, 400}.

-spec post_user(RequestBody) -> Result
	when
		RequestBody :: list(),
		Result :: {ok, Headers :: [tuple()], Body :: iolist()}
			| {error, ErrorCode :: integer()}.
%% @doc Respond to `POST /partyManagement/v1/individual' and add a new `User'
%% resource.
post_user(RequestBody) ->
	try
		{ok, JSON} = zj:decode(RequestBody),
		User = user(JSON),
		{Username, _, _, _} = User#httpd_user.username,
		Password = User#httpd_user.password,
		Locale = case lists:keyfind(locale, 1, User#httpd_user.user_data) of
			{_, Loc} ->
				Loc;
			false ->
				"en"
		end,
		case snmp_collector:add_user(Username, Password, Locale) of
			{ok, LastModified} ->
				Body = zj:encode(user(User)),
				Location = "/partyManagement/v1/individual/" ++ Username,
				Headers = [{location, Location}, {etag, snmp_collector_rest:etag(LastModified)}],
				{ok, Headers, Body};
			{error, _Reason} ->
				{error, 400}
		end
	catch
		_:_ ->
			{error, 400}
	end.

-spec delete_user(Id) -> Result
	when
		Id :: string(),
		Result :: {ok, Headers :: [tuple()], Body :: iolist()}
				| {error, ErrorCode :: integer()} .
%% @doc Respond to `DELETE /snmp/v1/subscriber/{id}' request and deletes
%% a `subscriber' resource. If the deletion is succeeded return true.
delete_user(Id) ->
	case snmp_collector:delete_user(Id) of
		ok ->
			{ok, [], []};
		{error, _Reason} ->
			{error, 400}
	end.

-spec get_params() -> Result
	when
		Result :: {Port, Address, Directory, Group},
		Port :: integer(),
		Address :: string(),
		Directory :: string(),
		Group :: string().
%% @doc Get {@link //inets/httpd. httpd} configuration parameters.
get_params() ->
	{_, _, Info} = lists:keyfind(httpd, 1, inets:services_info()),
	{_, Port} = lists:keyfind(port, 1, Info),
	{_, Address} = lists:keyfind(bind_address, 1, Info),
	{ok, EnvObj} = application:get_env(inets, services),
	{httpd, HttpdObj} = lists:keyfind(httpd, 1, EnvObj),
	{directory, {Directory, AuthObj}} = lists:keyfind(directory, 1, HttpdObj),
	case lists:keyfind(require_group, 1, AuthObj) of
		{require_group, [Group | _T]} ->
			{Port, Address, Directory, Group};
		false ->
			exit(not_found)
	end.

-spec user(User) -> User
	when
		User :: #httpd_user{} | map().
%% @doc CODEC for HTTP server users.
user(#httpd_user{username = {ID, _, _, _}} = HttpdUser) ->
	user(HttpdUser#httpd_user{username  = ID});
user(#httpd_user{username = ID, password = Password, user_data = Chars})
		when is_list(ID), is_list(Password), is_list(Chars) ->
	C1 = [#{"name" => "username", "value" => ID},
			#{"name" => "password", "value" => Password}],
	C2 = case lists:keyfind(locale, 1, Chars) of
		{_, Locale} ->
			[#{"name" => "locale", "value" => Locale} | C1];
		false ->
			C1
	end,
	#{"id" => ID,
			"href" => "/partyManagement/v1/individual/" ++ ID,
			"characteristic" => C2};
user(#{"id" := ID, "characteristic" := Chars})
		when is_list(ID), is_list(Chars) ->
	{Port, Address, Directory, _Group} = get_params(),
	Username = {ID, Address, Port, Directory},
	user1(Chars, #httpd_user{username = Username, user_data = []}).
%% @hidden
user1([#{"name" := "username", "value" := Username} | T], Acc)
		when is_list(Username) ->
	{Port, Address, Directory, _Group} = get_params(),
	user1(T, Acc#httpd_user{username = {Username, Address, Port, Directory}});
user1([#{"name" := "password", "value" := Password} | T], Acc)
		when is_list(Password) ->
	user1(T, Acc#httpd_user{password = Password});
user1([#{"name" := "locale", "value" := Locale} | T],
		#httpd_user{user_data = Data} = Acc) when is_list(Locale) ->
	user1(T, Acc#httpd_user{user_data = [{locale, Locale} | Data]});
user1([_H | T], Acc) ->
	user1(T, Acc);
user1([], Acc) ->
	Acc.

%%----------------------------------------------------------------------
%%  internal functions
%%----------------------------------------------------------------------

%% @hidden
query_start(Query, Filters, RangeStart, RangeEnd) ->
	try
		case lists:keyfind("filter", 1, Query) of
			{_, String} ->
				{ok, Tokens, _} = snmp_collector_rest_query_scanner:string(String),
				case snmp_collector_rest_query_parser:parse(Tokens) of
					{ok, [{array, [{complex, [{"id", like, [Id]},
							{"characteristic", contains, Contains}]}]}]} ->
						[{"language", {like, [Locale]}}] = char(Contains, '_'),
						{{like, Id}, {like, Locale}};
					{ok, [{array, [{complex, [{"id", like, [Id]}]}]}]} ->
						{{like, Id}, '_'}
				end;
			false ->
				{'_', '_'}
		end
	of
		{MatchId, MatchLocale} ->
			MFA = [snmp_collector, query_users, [MatchId, MatchLocale]],
			case supervisor:start_child(snmp_collector_rest_pagination_sup, [MFA]) of
				{ok, PageServer, Etag} ->
					query_page(PageServer, Etag, Query, Filters, RangeStart, RangeEnd);
				{error, _Reason} ->
					{error, 500}
			end
	catch
		_:_ ->
			{error, 400}
	end.

%% @hidden
query_page(PageServer, Etag, _Query, Filters, Start, End) ->
	case gen_server:call(PageServer, {Start, End}) of
		{error, Status} ->
			{error, Status};
		{Events, ContentRange} ->
			Users = query_page1(lists:map(fun user/1, Events), Filters, []),
			Body = zj:encode(Users),
			Headers = [{content_type, "application/json"},
					{etag, Etag}, {accept_ranges, "items"},
					{content_range, ContentRange}],
			{ok, Headers, Body}
	end.
%% @hidden
query_page1([#{"characteristic" := Chars} = U | T], Filters, Acc) ->
	F = fun(#{"name" := "password"}) ->
				false;
			(_) ->
				true
	end,
	NewChars = lists:filter(F, Chars),
	query_page1(T, Filters, [U#{"characteristic" => NewChars} | Acc]);
query_page1([], [], Acc) ->
	lists:reverse(Acc);
query_page1([], Filters, Acc) ->
	query_page2(Acc, Filters, []).
%% @hidden
query_page2([_U | T], Filters, Acc) ->
	% @todo: filters
	% query_page2(T, Filters, [snmp_collector_rest:fields(Filters, U) | Acc]);
	query_page2(T, Filters, Acc);
query_page2([], _, Acc) ->
	Acc.

%% @hidden
char([{complex, L1} | T], Chars) ->
	case lists:keytake("name", 1, L1) of
		{_, Name, L2} ->
			case lists:keytake("value", 1, L2) of
				{_, Value, []} ->
					char(Name, Value, T, Chars);
				_ ->
					throw({error, 400})
			end;
		false ->
			throw({error, 400})
	end;
char([], Chars) ->
	rev(Chars).
%% @hidden
char({"name", exact, "language"}, {"value", exact, Lang}, T, Chars)
			when is_list(Lang) ->
		Obj = add_char(Chars, {"language", {exact, Lang}}),
		char(T, Obj);
char({"name", exact, "language"}, {"value", like, Like}, T, Chars)
			when is_list(Like) ->
		Obj = add_char(Chars, {"language", {like, Like}}),
		char(T, Obj).

%% @hidden
add_char('_', AttributeMatch) ->
	[AttributeMatch];
add_char(Attributes, AttributeMatch) when is_list(Attributes) ->
	[AttributeMatch | Attributes].

%% @hidden
rev('_') ->
	'_';
rev(Attributes) when is_list(Attributes) ->
	lists:reverse(Attributes).

