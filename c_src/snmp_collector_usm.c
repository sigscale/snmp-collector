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

#include <openssl/evp.h>
#include <string.h>
#include "erl_nif.h"

/* Password to Key Algorithm (MD5)
 * RFC2274 A.2.1.
 */
int
password_to_key_md5(uint8_t *password, int password_len,
		uint8_t *engine, int engine_len, uint8_t *key, int key_len)
{
	EVP_MD_CTX *context;
	u_char *cp, *buf;
	u_long index = 0;
	u_long count = 0, i;

	if (((context = (EVP_MD_CTX *) malloc(sizeof(EVP_MD_CTX))) == NULL)
			|| ((buf = (u_char *) malloc(engine_len > 64 ? engine_len : 64)) == NULL))
		return -1;
	EVP_DigestInit(context, EVP_md5());
	while (count < 1048576) {
		cp = buf;
		for (i = 0; i < 64; i++) {
			*cp++ = password[index++ % password_len];
		}
		EVP_DigestUpdate(context, buf, 64);
		count += 64;
	}
	EVP_DigestFinal(context, (unsigned char *) key, (unsigned int *) &key_len);
	memcpy(buf, key, 16);
	memcpy(buf + 16, engine, engine_len);
	memcpy(buf + engine_len, key, 16);
	EVP_DigestInit(context, EVP_md5());
	EVP_DigestUpdate(context, buf, 32 + engine_len);
	EVP_DigestFinal(context, (unsigned char *) key, (unsigned int *) &key_len);
	free(context);
	free(buf);
	return 0;
}

/* Password to Key Algorithm (SHA)
 * RFC2274 A.2.2.
 */
int
password_to_key_sha(uint8_t *password, int password_len,
		uint8_t *engine, int engine_len, uint8_t *key, int key_len)
{
	EVP_MD_CTX *context;
	u_char *cp, *buf;
	u_long index = 0;
	u_long count = 0, i;

	if (((context = (EVP_MD_CTX *) malloc(sizeof(EVP_MD_CTX))) == NULL)
			|| ((buf = (u_char *) malloc(engine_len > 72 ? engine_len : 72)) == NULL))
		return -1;
	EVP_DigestInit(context, EVP_md5());
	while (count < 1048576) {
		cp = buf;
		for (i = 0; i < 64; i++) {
			*cp++ = password[index++ % password_len];
		}
		EVP_DigestUpdate(context, buf, 64);
		count += 64;
	}
	EVP_DigestFinal(context, (unsigned char *) key, (unsigned int *) &key_len);
	memcpy(buf, key, 20);
	memcpy(buf + 20, engine, engine_len);
	memcpy(buf + engine_len, key, 20);
	EVP_DigestInit(context, EVP_md5());
	EVP_DigestUpdate(context, buf, 40 + engine_len);
	EVP_DigestFinal(context, (unsigned char *) key, (unsigned int *) &key_len);
	free(context);
	free(buf);
	return 0;
}

static ERL_NIF_TERM
password_to_key_md5_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary password, engine, key;

	if (!enif_inspect_iolist_as_binary(env, argv[0], &password)
			|| !enif_inspect_iolist_as_binary(env, argv[1], &engine))
		return enif_make_badarg(env);
	if (!enif_alloc_binary(16, &key))
		return enif_raise_exception(env, enif_make_atom(env, "ealloc"));
	if (!password_to_key_md5(password.data, password.size,
			engine.data, engine.size, key.data, key.size))
		return enif_raise_exception(env, enif_make_atom(env, "ealloc"));
	return enif_make_binary(env, &key);
}

static ERL_NIF_TERM
password_to_key_sha_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary password, engine, key;

	if (!enif_inspect_iolist_as_binary(env, argv[0], &password)
			|| !enif_inspect_iolist_as_binary(env, argv[1], &engine))
		return enif_make_badarg(env);
	if (!enif_alloc_binary(20, &key))
		return enif_raise_exception(env, enif_make_atom(env, "ealloc"));
	if (!password_to_key_sha(password.data, password.size,
			engine.data, engine.size, key.data, key.size))
		return enif_raise_exception(env, enif_make_atom(env, "ealloc"));
	return enif_make_binary(env, &key);
}

static ErlNifFunc nif_funcs[] = {
	{"password_to_key_md5", 2, password_to_key_md5_nif},
	{"password_to_key_sha", 2, password_to_key_sha_nif}
};

ERL_NIF_INIT(snmp_collector_usm, nif_funcs, NULL, NULL, NULL, NULL)

