%% 
%% %CopyrightBegin%
%%
%% Copyright Ericsson AB 2004-2013. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%
%% %CopyrightEnd%
%% 
%% AES: RFC 3826
%% 
%% @doc This is a patched copy of {@link //snmp/snmp_usm. snmp_usm} from OTP.

-module(snmp_collector_snmp_usm).

-export([auth_in/4]).

-include_lib("snmp/include/SNMP-USER-BASED-SM-MIB.hrl").

-define(twelwe_zeros, [0,0,0,0,0,0,0,0,0,0,0,0]).

%%-----------------------------------------------------------------
%% Auth and priv algorithms
%%-----------------------------------------------------------------

auth_in(usmHMACMD5AuthProtocol, AuthKey, AuthParams, Packet) ->
	md5_auth_in(AuthKey, AuthParams, Packet);
auth_in(?usmHMACMD5AuthProtocol, AuthKey, AuthParams, Packet) ->
	md5_auth_in(AuthKey, AuthParams, Packet);
auth_in(usmHMACSHAAuthProtocol, AuthKey, AuthParams, Packet) ->
	sha_auth_in(AuthKey, AuthParams, Packet);
auth_in(?usmHMACSHAAuthProtocol, AuthKey, AuthParams, Packet) ->
	sha_auth_in(AuthKey, AuthParams, Packet).

md5_auth_in(AuthKey, AuthParams, Packet) when length(AuthParams) == 12 ->
	Packet2 = patch_packet(Packet),
	MAC = binary_to_list(crypto:hmac(md5, AuthKey, Packet2, 12)),
	MAC == AuthParams;
md5_auth_in(_AuthKey, _AuthParams, _Packet) ->
	false.

sha_auth_in(AuthKey, AuthParams, Packet) when length(AuthParams) =:= 12 ->
	Packet2 = patch_packet(Packet),
	MAC = binary_to_list(crypto:hmac(sha, AuthKey, Packet2, 12)),
	MAC == AuthParams;
sha_auth_in(_AuthKey, _AuthParams, _Packet) ->
	false.

%%-----------------------------------------------------------------
%% Utility functions
%%-----------------------------------------------------------------

patch_packet([48 | T]) ->
	{Len1, [2 | T1]} = split_len(T),
	{Len2, [Vsn,48|T2]} = split_len(T1),
	{Len3, T3} = split_len(T2),
	[48,Len1,2,Len2,Vsn,48,Len3|pp2(dec_len(Len3),T3)].
%% @hidden
pp2(0,[4|T]) ->
	{Len1,[48|T1]} = split_len(T),
	{Len2,[4|T2]} = split_len(T1),
	{Len3,T3} = split_len(T2),
	[4,Len1,48,Len2,4,Len3|pp3(dec_len(Len3),T3)];
pp2(N,[H|T]) ->
	[H|pp2(N-1,T)].
%% @hidden
pp3(0,[2|T]) ->
	{Len1,T1} = split_len(T),
	[2,Len1|pp4(dec_len(Len1),T1)];
pp3(N,[H|T]) ->
	[H|pp3(N-1,T)].
%% @hidden
pp4(0,[2|T]) ->
	{Len1,T1} = split_len(T),
	[2,Len1|pp5(dec_len(Len1),T1)];
pp4(N,[H|T]) ->
	[H|pp4(N-1,T)].
%% @hidden
pp5(0,[4|T]) ->
	{Len1,T1} = split_len(T),
	[4,Len1|pp6(dec_len(Len1),T1)];
pp5(N,[H|T]) ->
	[H|pp5(N-1,T)].
%% @hidden
pp6(0,[4|T]) ->
	{Len1,[_,_,_,_,_,_,_,_,_,_,_,_|T1]} = split_len(T),
	12 = dec_len(Len1),
	[4,Len1,?twelwe_zeros|T1];
pp6(N,[H|T]) ->
	[H|pp6(N-1,T)].

split_len([Hd|Tl]) ->
	case is8set(Hd) of
		0 -> 
			{Hd,Tl};
		1 -> 
			No = clear(Hd, 8),
			{DigList,Rest} = head(No,Tl),
			{[Hd | DigList], Rest}
	end.

dec_len(D) when is_integer(D) ->
	D;
dec_len([_LongOctet|T]) ->
	dl(T).
dl([D]) ->
	D;
dl([A,B]) ->
	(A bsl 8) bor B;
dl([A,B,C]) ->
	(A bsl 16) bor (B bsl 8) bor C;
dl([0 | T]) ->
	dl(T).

head(L,List) when length(List) == L -> {List,[]};
head(L,List) ->
	head(L,List,[]).

head(0,L,Res) ->
	{lists:reverse(Res),L};

head(Int,[H|Tail],Res) ->
	head(Int-1,Tail,[H|Res]).

clear(Byte, 8) -> 
	Byte band 127.

is8set(Byte) ->
	if
		Byte > 127 -> 1;
		true -> 0
	end.

