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
-export[load_default_mibs/0, load_manager_mibs/2].

 -include_lib("kernel/include/file.hrl").

%%----------------------------------------------------------------------
%%  The snmp_collector_mib_loader public API
%%----------------------------------------------------------------------

-spec load_default_mibs() -> ok.
%% @doc Load default SNMP MIBs.
load_default_mibs() ->
	DefaultMibDir = code:priv_dir(snmp) ++ "/mibs",
	{ok, MibList} = file:list_dir(DefaultMibDir),
	load_default_mibs(DefaultMibDir, MibList).
%% @hidden
load_default_mibs(Dir, [Mib | Rest]) ->
	MibPath = Dir ++ "/" ++ Mib,
	case snmpm:load_mib(MibPath) of
		ok ->
			load_default_mibs(Dir, Rest);
		{error, already_loaded} ->
			load_default_mibs(Dir, Rest);
		{error, Reason} ->
			error_logger:info_report(["SNMP MIB Failed To Load Mib",
				{mib, Mib},
				{error, Reason}]),
			load_default_mibs(Dir, Rest)
	end;
load_default_mibs(_, []) ->
	ok.

-spec load_manager_mibs(MibDir, BinDir) -> Result
	when
		MibDir :: string(),
		BinDir :: string(),
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Load all MIBs into the SNMP Manager.
load_manager_mibs(MibDir, BinDir) ->
	case file:list_dir(MibDir) of
		{ok, []} ->
			{error, mib_directory_empty};
		{ok, MibList} ->
			case file:list_dir(BinDir) of
				{ok, BinList} ->
					case compile_mibs(MibDir, BinDir, MibList, BinList) of
						ok ->
							case load_mibs(BinDir) of
								ok ->
									ok;
								{error, Reason} ->
									{error, Reason}
							end;
						{error ,Reason} ->
							{error, Reason}
					end;
				{error, Reason} ->
					{error, Reason}
			end;
		{error, Reason} ->
			error_logger:info_report(["SNMP Manager Failed To Load Mib Directory",
				{error, Reason}]),
			{error, Reason}
	end.

%%----------------------------------------------------------------------
%%  The internal functions
%%----------------------------------------------------------------------

-spec compile_mibs(MibDir, BinDir, MibList, BinList) -> Result
	when
		MibDir :: string(),
		BinDir :: string(),
		MibList :: list(),
		BinList :: list(),
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Compile all MIBs in the Mib directory.
compile_mibs(MibDir, BinDir, ["bin" | T], BinList) ->
	compile_mibs(MibDir, BinDir, T, BinList);
%% @hidden
compile_mibs(MibDir, BinDir ,[Mib | T], BinList) ->
	MibPath = MibDir ++ "/" ++ Mib,
	case file:read_file(MibPath) of
		{ok, File} ->
			BinName = snmp_collector_utils:get_name(binary_to_list(File)) ++ ".bin",
			BinPath = BinDir ++ "/" ++ BinName,
			case lists:member(BinName, BinList) of
				true ->
					case file:read_file_info(MibPath, [{time, local}]) of
						{ok, #file_info{mtime = MibTimeStamp}} ->
							case file:read_file_info(BinPath, [{time, local}]) of
								{ok, #file_info{mtime = BinTimeStamp}} ->
									case MibTimeStamp > BinTimeStamp of
										true ->
											case snmpc:compile(MibPath, [module_identity,
													{outdir, BinDir}, {group_check, false}, {warnings, false},
													{i, [BinDir]}, {il, ["snmp/priv/mibs/"]}]) of
												{ok, BinFileName} ->
													error_logger:info_report(["SNMP Manager Complied MIB",
															{mib, BinFileName}]),
													compile_mibs(MibDir, BinDir, T, BinList);
												{error, Reason} ->
													error_logger:warning_report(["SNMP Collector MIB Compilation Failed",
															{error, Reason},
															{mib_name, Mib}]),
													compile_mibs(MibDir, BinDir, T ++ [Mib], BinList)
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
					case snmpc:compile(MibPath, [module_identity,
						{outdir, BinDir}, {group_check, false}, {warnings, false},
								{i, [BinDir]}, {il, ["snmo/priv/mibs/"]}]) of
							{ok, BinFileName} ->
								error_logger:info_report(["SNMP Manager Complied MIB",
										{mib, BinFileName}]),
								compile_mibs(MibDir, BinDir, T, BinList);
							{error, Reason} ->
								error_logger:warning_report(["SNMP Collector MIB Compilation Failed",
										{error, Reason},
										{mib_name, Mib}]),
								compile_mibs(MibDir, BinDir, T ++ [Mib], BinList)
					end
			end;
		{error, Reason} ->
			{error, Reason}
	end;
%% @hidden
compile_mibs(_, _, [], _) ->
	ok.

-spec load_mibs(BinDir) -> Result
	when
		BinDir :: string(),
		Result :: ok | {error, Reason},
		Reason :: term().
%% @doc Load a mib into the SNMP Manager.
load_mibs(BinDir)
		when is_list(BinDir) ->
	case file:list_dir(BinDir) of
		{ok, BinList} ->
			case load_mibs1(BinDir, BinList) of
				ok ->
					ok;
				{error, Reason} ->
					{error ,Reason}
			end;
		{error, Reason} ->
			{error, Reason}
	end.
%% @hidden
load_mibs1(BinDir, [BinFile | Rest]) ->
	BinPath = BinDir ++ "/" ++ BinFile,
	case snmpm:load_mib(BinPath) of
		ok ->
			load_mibs1(BinDir, Rest);
		{error, {already_loaded, _, _}} ->
			load_mibs1(BinDir, Rest);
		{error, already_loaded} ->
			load_mibs1(BinDir, Rest);
		{error, Reason} ->
			{error, Reason}
	end;
%% @hidden
load_mibs1(_, []) ->
	ok.

