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
*** for SNMPv3 (RFC3414).
***/

#include <arpa/inet.h>
#include <openssl/evp.h>
#include <string.h>
#include "erl_nif.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L

static EVP_MD_CTX *
EVP_MD_CTX_new(void)
{
	return EVP_MD_CTX_create();
}

void
EVP_MD_CTX_reset(EVP_MD_CTX *context)
{
	EVP_MD_CTX_cleanup(context);
}

void
EVP_MD_CTX_free(EVP_MD_CTX *context)
{
	EVP_MD_CTX_destroy(context);
}

#endif /* OpenSSL < v1.1.0 */

/* Password to Key Algorithm (MD5)
 * RFC3414 A.2.1.
 */
int
password_to_key_md5(uint8_t *password, size_t password_len,
		uint8_t *engine, size_t engine_len, uint8_t *key, size_t key_len)
{
	EVP_MD_CTX *context;
	uint8_t *buf, buf_len, i;
	uint32_t count = 0;

	buf_len = password_len + 64;
	if (((context = EVP_MD_CTX_new()) == NULL)
			|| ((buf = (uint8_t *) malloc(buf_len)) == NULL))
		return -1;
	EVP_DigestInit_ex(context, EVP_md5(), NULL);
	for (i = 0; i < buf_len; i += password_len) {
		memcpy(&buf[i], password, password_len);
	}
	i = 0;
	while (count < 1048576) {
		EVP_DigestUpdate(context, (const void *) &buf[i], 64);
		i = (i + 64) % password_len;
		count += 64;
	}
	EVP_DigestFinal_ex(context, (uint8_t *) key, (unsigned int *) &key_len);
	memcpy(buf, key, key_len);
	memcpy(&buf[key_len], engine, engine_len);
	memcpy(&buf[key_len + engine_len], key, key_len);
	EVP_MD_CTX_reset(context);
	EVP_DigestInit_ex(context, EVP_md5(), NULL);
	EVP_DigestUpdate(context, buf, (key_len * 2) + engine_len);
	EVP_DigestFinal_ex(context, (uint8_t *) key, (unsigned int *) &key_len);
	EVP_MD_CTX_destroy(context);
	return 1;
}

/* Password to Key Algorithm (SHA)
 * RFC3414 A.2.2.
 */
int
password_to_key_sha(uint8_t *password, size_t password_len,
		uint8_t *engine, size_t engine_len, uint8_t *key, size_t key_len)
{
	EVP_MD_CTX *context;
	uint8_t *buf, buf_len, i;
	uint32_t count = 0;

	buf_len = password_len + 64;
	if (((context = EVP_MD_CTX_new()) == NULL)
			|| ((buf = (uint8_t *) malloc(buf_len)) == NULL))
		return -1;
	EVP_DigestInit_ex(context, EVP_sha1(), NULL);
	for (i = 0; i < buf_len; i += password_len) {
		memcpy(&buf[i], password, password_len);
	}
	i = 0;
	while (count < 1048576) {
		EVP_DigestUpdate(context, (const void *) &buf[i], 64);
		i = (i + 64) % password_len;
		count += 64;
	}
	EVP_DigestFinal_ex(context, (uint8_t *) key, (unsigned int *) &key_len);
	memcpy(buf, key, key_len);
	memcpy(&buf[key_len], engine, engine_len);
	memcpy(&buf[key_len + engine_len], key, key_len);
	EVP_MD_CTX_reset(context);
	EVP_DigestInit_ex(context, EVP_sha1(), NULL);
	EVP_DigestUpdate(context, buf, (key_len * 2) + engine_len);
	EVP_DigestFinal_ex(context, (uint8_t *) key, (unsigned int *) &key_len);
	EVP_MD_CTX_destroy(context);
	return 1;
}

static ERL_NIF_TERM
password_to_key_md5_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary password, engine;
	size_t key_len = 16;
	uint8_t i, key[key_len];
	ERL_NIF_TERM result[key_len];

	if (!enif_inspect_iolist_as_binary(env, argv[0], &password)
			|| !enif_inspect_iolist_as_binary(env, argv[1], &engine)
			|| engine.size > 32)
		return enif_make_badarg(env);
	if (!password_to_key_md5(password.data, password.size,
			engine.data, engine.size, key, key_len))
		return enif_raise_exception(env, enif_make_atom(env, "ealloc"));
	for (i = 0; i < key_len; i++)
		result[i] = enif_make_uint(env, key[i]);
	return enif_make_list_from_array(env, result, key_len);
}

static ERL_NIF_TERM
password_to_key_sha_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary password, engine;
	size_t key_len = 20;
	uint8_t i, key[key_len];
	ERL_NIF_TERM result[key_len];


	if (!enif_inspect_iolist_as_binary(env, argv[0], &password)
			|| !enif_inspect_iolist_as_binary(env, argv[1], &engine)
			|| engine.size > 32)
		return enif_make_badarg(env);
	if (!password_to_key_sha(password.data, password.size,
			engine.data, engine.size, key, key_len))
		return enif_raise_exception(env, enif_make_atom(env, "ealloc"));
	for (i = 0; i < key_len; i++)
		result[i] = enif_make_uint(env, key[i]);
	return enif_make_list_from_array(env, result, key_len);
}

static ErlNifFunc nif_funcs[] = {
	{"password_to_key_md5", 2, password_to_key_md5_nif},
	{"password_to_key_sha", 2, password_to_key_sha_nif}
};

ERL_NIF_INIT(snmp_collector_usm, nif_funcs, NULL, NULL, NULL, NULL)

