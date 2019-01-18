%% snmp_collector_test_lib.erl
%%% vim: ts=3
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% @copyright 2019 SigScale Global Inc.
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
%%%  @doc Test suite for SNMP manager of the
%%% 	{@link //snmp_collector. snmp_collector} application.
%%%
-module(snmp_collector_test_lib).
-copyright('Copyright (c) 2019 SigScale Global Inc.').

%% common_test required callbacks
-export([initialize_db/0, start/0, stop/0]).

%% Note: This directive should only be used in test suites.
-compile(export_all).

-include("snmp_collector.hrl").

%%---------------------------------------------------------------------
%%  Test server callback functions
%%---------------------------------------------------------------------

initialize_db() ->
	case mnesia:system_info(is_running) of
		no ->
			ok = application:start(mnesia),
			initialize_db();
		S when S == starting; S == stopping ->
			receive
				after 1000 ->
					initialize_db()
			end;
		yes ->
			Tables = [snmp_user, http_group, http_user], 
			case mnesia:wait_for_tables(Tables, 1000) of
				{timeout, _} ->
					ok = application:stop(mnesia),
					{ok, Tables} = snmp_collector_app:install(),
					F = fun(T) ->
							lists:member(T, Tables)
					end,
					true = lists:all(F, Tables),
					initialize_db();
				ok ->
					ok
			end
	end.

start() ->
	start([crypto, inets, asn1, public_key, ssl, snmp_collector]).
%% @hidden
start([H | T]) ->
	case application:start(H) of
		ok  ->
			start(T);
	{error, {already_started, H}} ->
		start(T);
	{error, Reason} ->
		{error, Reason}
	end;
start([]) ->
	ok.

%%---------------------------------------------------------------------
%%  Internal functions
%%---------------------------------------------------------------------

