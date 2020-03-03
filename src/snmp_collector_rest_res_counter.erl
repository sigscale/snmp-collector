%%% snmp_collector_rest_res_counter.erl
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
%%% @doc This library module implements resource handling functions for a
%%%   REST server in the {@link //snmp_collector. snmp_collector} application.
%%%
-module(snmp_collector_rest_res_counter).
-copyright('Copyright (c) 2020 SigScale Global Inc.').


-export([content_types_accepted/0, content_types_provided/0, get_counters/0]).

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

-spec get_counters() -> Result
   when
      Result :: {ok, Headers :: [tuple()], Body :: iolist()}
            | {error, ErrorCode :: integer()}.
%% @doc Body producing function for `GET /counters/v1/snmp'
%% requests.
get_counters() ->
	TotalCount = snmp_collector:get_count(),
%	Total = #{total => TotalCount},

	MetricList = [communicationsAlarm, processingErrorAlarm, environmentalAlarm, qualityofServiceAlarm, equipmentAlarm, integrityViolation, operationalViolation, physicalViolation, securityServiceOrMechanismViolation, timeDomainViolation],
	F = fun(F, [Metric | T], Acc) ->
				F(F, T, maps:merge(Acc, snmp_collector:get_count(Metric)));
			(_F, [], Acc) ->
				Acc
	end,
%	Metric = #{eventType => F(F, MetricList, #{})},
	Metric = F(F, MetricList, #{}),

	MetricSeverity = [major, minor, critical],
	F1 = fun(F1, [Severity | T], Acc) ->
				F1(F1, T, maps:merge(Acc, snmp_collector:get_count(Severity)));
			(_F1, [], Acc) ->
				Acc
	end,
	Severity = F1(F1, MetricSeverity, #{}),
%	Severity = #{perceivedSeverity => F1(F1, MetricSeverity, #{})},

	VendorCountHuw = snmp_collector:get_vendor_count(huawei),
	VendorCountNok = snmp_collector:get_vendor_count(nokia),
	VendorCountZte = snmp_collector:get_vendor_count(zte),
	VendorCountSum = VendorCountHuw + VendorCountNok + VendorCountZte,
%	VendorCount = #{total => VendorCountSum},

	MetricVendor = [huawei, nokia, zte],
	MatchSpecAgent = ets:select(counters, [{'_', [], ['$_']}]),
	F2 = fun(F2, [huawei | T1], MatchSpecAgent1, MetricList1, MetricSeverity1, Acc) ->
		F3 = fun(F3, [Met | T], Sum, Acc1) ->
				Result = snmp_collector:get_vendor_count(huawei, Met),
				#{Met := N} = Result,
				F3(F3, T, Sum + N, maps:merge(Result, Acc1));
			(_F3, [], Sum, Acc1) ->
				{Sum, Acc1}
		end,
		AgentList = lists:usort(ets:select(counters, [{{{huawei, '$1', '_'}, '_'}, [], ['$1']}])),
		FAgent = fun F5([Age | TAgent], MList, SList, AgentAcc) ->
				F4 = fun Fmet([Met | T], Acc1) ->
						Fmet(T, maps:merge(Acc1,
						snmp_collector:get_agent_count(huawei, Age, Met)));
					Fmet([], Acc1) ->
						Acc1
				end,
				MapEvent = F4(MList, #{}),
				MapSeverity = F4(SList, #{}),
				F5(TAgent, MList, SList, [#{name => Age,
						total => snmp_collector:get_agent_count(huawei, Age),
						eventType => MapEvent, perceivedSeverity => MapSeverity} | AgentAcc]);
			F5([], _MList, _SList, AgentAcc) ->
					AgentAcc
		end,
		AgentMaps = FAgent(AgentList, MetricList1, MetricSeverity1, []),
		{Sum1, MapEvent} = F3(F3, MetricList1, 0, #{}),
		{Sum2, MapSever} = F3(F3, MetricSeverity1, Sum1, #{}),
		VenEve = #{total => Sum2, eventType => MapEvent, perceivedSeverity=> MapSever,
					agent => AgentMaps},
		F2(F2, T1, MatchSpecAgent1, MetricList1, MetricSeverity1, Acc#{huawei => VenEve});
		(F2, [nokia | T1], MatchSpecAgent1, MetricList1, MetricSeverity1, Acc) ->
			F3 = fun(F3, [Met | T], Sum, Acc1) ->
					Result = snmp_collector:get_vendor_count(nokia, Met),
					#{Met := N} = Result,
					F3(F3, T, Sum + N, maps:merge(Result, Acc1));
				(_F3, [], Sum, Acc1) ->
					{Sum, Acc1}
			end,
			AgentList = lists:usort(ets:select(counters, [{{{nokia, '$1', '_'}, '_'}, [], ['$1']}])),
			FAgent = fun F5([Age | TAgent], MList, SList, AgentAcc) ->
			F4 = fun Fmet([Met | T], Acc1) ->
					Fmet(T, maps:merge(Acc1, snmp_collector:get_agent_count(nokia, Age, Met)));
				Fmet([], Acc1) ->
					Acc1
			end,
			MapEvent = F4(MList, #{}),
			MapSeverity = F4(SList, #{}),
			F5(TAgent, MList, SList, [#{name => Age,
						total => snmp_collector:get_agent_count(nokia, Age),
						eventType => MapEvent, perceivedSeverity => MapSeverity} | AgentAcc]);
				F5([], _MList, _SList, AgentAcc) ->
					AgentAcc
				end,
				AgentMaps = FAgent(AgentList, MetricList1, MetricSeverity1, []),
				{Sum1, MapEvent} = F3(F3, MetricList1, 0, #{}),
				{Sum2, MapSever} = F3(F3, MetricSeverity1, Sum1, #{}),
				VenEve = #{total => Sum2, eventType => MapEvent, perceivedSeverity=> MapSever,
					agent => AgentMaps},
			F2(F2, T1, MatchSpecAgent1, MetricList1, MetricSeverity1, Acc#{nokia => VenEve});
			(F2, [zte | T1], MatchSpecAgent1, MetricList1, MetricSeverity1, Acc) ->
				F3 = fun(F3, [Met | T], Sum, Acc1) ->
						Result = snmp_collector:get_vendor_count(zte, Met),
						#{Met := N} = Result,
						F3(F3, T, Sum + N, maps:merge(Result, Acc1));
					(_F3, [], Sum, Acc1) ->
						{Sum, Acc1}
				end,
				AgentList = lists:usort(ets:select(counters, [{{{zte, '$1', '_'}, '_'}, [], ['$1']}])),
				FAgent = fun F5([Age | TAgent], MList, SList, AgentAcc) ->
				F4 = fun Fmet([Met | T], Acc1) ->
						Fmet(T, maps:merge(Acc1, snmp_collector:get_agent_count(zte, Age, Met)));
					Fmet([], Acc1) ->
						Acc1
				end,
				MapEvent = F4(MList, #{}),
				MapSeverity = F4(SList, #{}),
				F5(TAgent, MList, SList, [#{name => Age,
							total => snmp_collector:get_agent_count(zte, Age),
							eventType => MapEvent, perceivedSeverity => MapSeverity} | AgentAcc]);
					F5([], _MList, _SList, AgentAcc) ->
						AgentAcc
				end,
				AgentMaps = FAgent(AgentList, MetricList1, MetricSeverity1, []),
				{Sum1, MapEvent} = F3(F3, MetricList1, 0, #{}),
				{Sum2, MapSever} = F3(F3, MetricSeverity1, Sum1, #{}),
				VenEve = #{total => Sum2, eventType => MapEvent, perceivedSeverity=> MapSever,
					agent => AgentMaps},
			F2(F2, T1, MatchSpecAgent1, MetricList1, MetricSeverity1, Acc#{zte => VenEve});
			(_F2, [], _MatchSpecAgent1, _MetricList1, _MetricSeverity1, Acc) ->
		Acc
	end,
	VendorMetric = F2(F2, MetricVendor, MatchSpecAgent, MetricList, MetricSeverity, #{}),
	JsonObj = #{total => TotalCount, eventType => Metric, perceivedSeverity => Severity,
		vendor => maps:merge(#{total => VendorCountSum}, VendorMetric)},
	Body = zj:encode(JsonObj),
	Headers = [{"content_type", "application/json"}],
	{ok, Headers, Body}.

%%----------------------------------------------------------------------
%%  internal functions
%%----------------------------------------------------------------------
