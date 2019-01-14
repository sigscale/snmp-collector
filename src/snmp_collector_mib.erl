%%% snmp_collector_mib.erl
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
-module(snmp_collector_mib).
-copyright('Copyright (c) 2016 - 2019 SigScale Global Inc.').

%% export the snmp_collector_mib_loader public API
-export[load_default_mibs/0, load_mibs/0].

 -include_lib("kernel/include/file.hrl").

%%----------------------------------------------------------------------
%%  The snmp_collector_mib_loader public API
%%----------------------------------------------------------------------

-spec load_default_mibs() -> Result
	when
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Load default MIBs for the snmp collector.
load_default_mibs() ->
	{ok, Dir} = application:get_env(default_bin_dir, snmp_collector),
	{ok, MibList} = file:list_dir(Dir),
	load_default_mibs(Dir, MibList).
%% @hidden
load_default_mibs(Dir, [Mib | Rest]) ->
	MibPath = Dir ++ Mib,
	case snmpm:load_mib(MibPath) of
		ok ->
			load_default_mibs(Dir, Rest);
		{error, already_loaded} ->
			load_default_mibs(Dir, Rest)
	end;
load_default_mibs(_, []) ->
	ok.

-spec load_mibs() -> Result
	when
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Load all MIBs into the SNMP Manager.
load_mibs() ->
	case compile_mibs() of
		ok ->
			load_mibs1();
		{error, Reason} ->
			error_logger:info_msg(["SNMP MIB Compilation Failed",
				{error, Reason}]),
			{error, Reason}
	end.
%% @hidden
load_mibs1() ->
	{ok, BinDir} = application:get_env(snmp_collector, bin_dir),
	{ok, BinList} = file:list_dir(BinDir),
	load_mibs2(BinDir, BinList).
%% @hidden
load_mibs2(BinDir, [BinFile | Rest]) ->
	BinPath = BinDir ++ BinFile,
	case snmpm:load_mib(BinPath) of
		ok ->
			load_default_mibs(BinDir, Rest);
		{error, already_loaded} ->
			load_default_mibs(BinDir, Rest)
	end.


	

%%----------------------------------------------------------------------
%%  The internal functions
%%----------------------------------------------------------------------

-spec compile_mibs() -> Result
	when
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Compile all MIBs in the Mib directory.
compile_mibs() ->
	{ok, MibDir} = application:get_env(mib_dir, snmp_collector),
	{ok, BinDir} = application:get_env(bin_dir, snmp_collector),
	{ok, MibList} = file:list_dir(MibDir),
	{ok, BinList} = file:list_dir(BinDir),
	compile_mibs(MibDir, BinDir ,MibList, BinList).
%% @hidden
compile_mibs(MibDir, BinDir ,[Mib | T], BinList) ->
	MibPath = MibDir ++ Mib,
	case file:read_file(MibPath) of
		{ok, File} ->
			MibName = snmp_collector_utils:get_name(binary_to_list(File)) ++ ".bin",
			BinPath = BinDir ++ MibName,
			case lists:member(MibName, BinList) of
				true ->
					case file:read_file_info(MibPath, [{time, local}]) of
						{ok, #file_info{mtime = MibTimeStamp}} ->
							case file:read_file_info(BinPath, [{time, local}]) of
								{ok, #file_info{mtime = BinTimeStamp}} ->
									case MibTimeStamp > BinTimeStamp	of 
										true ->
											case snmpc:compile(MibName, [module_identity,
													{outdir, BinDir}, {group_check, false}]) of
												{ok, BinFileName} ->
													case load_mib(BinFileName) of
														ok ->
															error_logger:info_msg(["SNMP Collector MIB Compiled",
																		{mib_name, MibName}]),
															compile_mibs(MibDir, BinDir, T, BinList);
														{error, Reason} ->
															error_logger:error_msg(["SNMP Collector MIB Compilation Failed",
																		{error, Reason},		
																		{mib_name, MibName}]),
															compile_mibs(MibDir, BinDir, T, BinList)
													end;
												{error, Reason} ->
													{error, Reason}
											end;
										false ->
											compile_mibs(MibDir, BinDir, T, BinList)
									end;
								{error, Reason} ->
									{error, Reason}
							end;
						{error, Reason} ->
							{error, Reason}
					end;
				false ->
					compile_mibs(MibDir, BinDir, T, BinList)
			end;
		{error, Reason} ->
			{error, Reason}
	end;
%% @hidden
compile_mibs(_, _, [], _) ->
	ok.

-spec load_mib(BinPath) -> Result
	when
		BinPath :: string(),
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Load a mib into the SNMP Manager.
load_mib(BinPath) 
		when is_list(BinPath) ->
	case snmpm:load_mib(BinPath) of
		ok ->
			ok;
		{error, Reason} ->
			{error, Reason}
	end.
