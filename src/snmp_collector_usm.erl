%%% snmp_collector_usm.erl
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
%%% @doc This library module implements functions for the
%%%	User-based Security Model (USM) for SNMPv3 (RFC3414) in the
%%% 	{@link //snmp_collector. snmp_collector} application.
%%%
%%% @reference <a href="http://tools.ietf.org/html/rfc3414">
%%% 	RFC3414 -  User-based Security Model (USM) for version 3 of the
%%%              Simple Network Management Protocol (SNMPv3) </a>
%%%

-module(snmp_collector_usm).
-copyright('Copyright (c) 2016 - 2019 SigScale Global Inc.').

-export([ku_md5/1, ku_sha/1, kul_md5/2, kul_sha/2]).
-on_load(init/0).

%%----------------------------------------------------------------------
%%  The snmp_collector_usm public API
%%----------------------------------------------------------------------

-spec ku_md5(Password) -> Ku
	when
		Password :: string(),
		Ku :: binary().
%% @doc Password to key (Ku) algorithm (MD5).
ku_md5(_Password) ->
	erlang:nif_error(nif_library_not_loaded).

-spec ku_sha(Password) -> Ku
	when
		Password :: string(),
		Ku :: binary().
%% @doc Password to key (Ku) algorithm (SHA).
ku_sha(_Password) ->
	erlang:nif_error(nif_library_not_loaded).

-spec kul_md5(Ku, EngineID) -> Kul
	when
		Ku :: binary(),
		EngineID :: [byte()],
		Kul :: [byte()].
%% @doc Localized key (Kul) algorithm (MD5).
kul_md5(_Ku, _EngineID) ->
	erlang:nif_error(nif_library_not_loaded).

-spec kul_sha(Ku, EngineID) -> Kul
	when
		Ku :: binary(),
		EngineID :: [byte()],
		Kul :: [byte()].
%% @doc Localized key (Kul) algorithm (SHA).
kul_sha(_Ku, _EngineID) ->
	erlang:nif_error(nif_library_not_loaded).

%%----------------------------------------------------------------------
%%  The internal functions
%%----------------------------------------------------------------------

-spec init() -> ok.
%% @doc When this module is loaded this function is called to load NIF library.
%% @hidden
init() ->
	{ok, Application} = application:get_application(?MODULE),
	PrivDir = case code:priv_dir(Application) of
		{error, bad_name} ->
			BEAM = atom_to_list(?MODULE) ++ ".beam",
			Ebin = filename:dirname(code:where_is_file(BEAM)),
			filename:dirname(Ebin) ++ "/priv";
		Path ->
			Path
	end,
	ok = erlang:load_nif(PrivDir ++ "/lib/snmp_collector_usm", 0).

