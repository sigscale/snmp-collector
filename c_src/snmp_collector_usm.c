/* snmp_collector_usm.c
*** vim: ts=3
*****************************************************************************
*** Copyright 2016 - 2019 SigScale Global Inc.
*** 
*** Licensed under the Apache License, Version 2.0 (the "License");
*** you may not use this file except in compliance with the License.
*** You may obtain a copy of the License at
***
***     http://www.apache.org/licenses/LICENSE-2.0
***
*** Unless required by applicable law or agreed to in writing, software
*** distributed under the License is distributed on an "AS IS" BASIS,
*** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*** See the License for the specific language governing permissions and
*** limitations under the License.
*****************************************************************************
*** This module implements NIFs for the User-based Security Model (USM)
*** for SNMPv3 (RFC2274).
***/

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "erl_nif.h"

/* Password to Key Algorithm (MD5)
 * RFC2274 A.2.1.
 */
static void
password_to_key_md5(uint8_t *password, int password_len,
		uint8_t *engineID, int engineID_len, uint8_t *result, int result_len)
{
}

/* Password to Key Algorithm (SHA)
 * RFC2274 A.2.2.
 */
static void
password_to_key_sha(uint8_t *password, int password_len,
		uint8_t *engineID, int engine_len, uint8_t *result, int result_len)
{
}

static ERL_NIF_TERM
password_to_key_md5_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary password, engineID, res;

	if (!enif_inspect_iolist_as_binary(env, argv[0], &password)
			|| !enif_inspect_iolist_as_binary(env, argv[1], &engineID))
		return enif_make_badarg(env);
	if (!enif_alloc_binary(160, &res))
		return enif_raise_exception(env, enif_make_atom(env, "ealloc"));
	password_to_key_md5(password.data, password.size, engineID.data, engineID.size, res.data, res.size);
	return enif_make_binary(env, &res);
}

static ERL_NIF_TERM
password_to_key_sha_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary password, engineID, res;

	if (!enif_inspect_iolist_as_binary(env, argv[0], &password)
			|| !enif_inspect_iolist_as_binary(env, argv[1], &engineID))
		return enif_make_badarg(env);
	if (!enif_alloc_binary(160, &res))
		return enif_raise_exception(env, enif_make_atom(env, "ealloc"));
	password_to_key_sha(password.data, password.size, engineID.data, engineID.size, res.data, res.size);
	return enif_make_binary(env, &res);
}

static ErlNifFunc nif_funcs[] = {
	{"password_to_key_md5", 2, password_to_key_md5_nif},
	{"password_to_key_sha", 2, password_to_key_sha_nif}
};

ERL_NIF_INIT(snmp_collector_usm, nif_funcs, NULL, NULL, NULL, NULL)

