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

/* Password to Key (Ku) Algorithm (MD5)
 * RFC3414 A.2.1.
 */
int
ku_md5(uint8_t *password, size_t password_len, uint8_t *ku, size_t ku_len)
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
	EVP_DigestFinal_ex(context, (uint8_t *) ku, (unsigned int *) &ku_len);
	EVP_MD_CTX_destroy(context);
	free(buf);
	return 1;
}

/* Password to Key (Ku) Algorithm (SHA)
 * RFC3414 A.2.2.
 */
int
ku_sha(uint8_t *password, size_t password_len, uint8_t *ku, size_t ku_len)
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
	EVP_DigestFinal_ex(context, (uint8_t *) ku, (unsigned int *) &ku_len);
	EVP_MD_CTX_destroy(context);
	free(buf);
	return 1;
}

/* Key (Ku) to localized key (Kul) Algorithm (MD5)
 * RFC3414 A.2.1.
 */
int
kul_md5(uint8_t *ku, size_t ku_len,
		uint8_t *engine, size_t engine_len, uint8_t *kul, size_t kul_len)
{
	EVP_MD_CTX *context;
	uint8_t *buf, buf_len;

	buf_len = engine_len + 32;
	if (((context = EVP_MD_CTX_new()) == NULL)
			|| ((buf = (uint8_t *) malloc(buf_len)) == NULL))
		return -1;
	EVP_DigestInit_ex(context, EVP_md5(), NULL);
	memcpy(buf, ku, 16);
	memcpy(&buf[16], engine, engine_len);
	memcpy(&buf[16 + engine_len], ku, 16);
	EVP_DigestInit_ex(context, EVP_md5(), NULL);
	EVP_DigestUpdate(context, buf, 32 + engine_len);
	EVP_DigestFinal_ex(context, (uint8_t *) kul, (unsigned int *) &kul_len);
	EVP_MD_CTX_destroy(context);
	free(buf);
	return 1;
}

/* Key (Ku) to localized key (Kul) Algorithm (SHA)
 * RFC3414 A.2.2.
 */
int
kul_sha(uint8_t *ku, size_t ku_len,
		uint8_t *engine, size_t engine_len, uint8_t *kul, size_t kul_len)
{
	EVP_MD_CTX *context;
	uint8_t *buf, buf_len;

	buf_len = engine_len + 40;
	if (((context = EVP_MD_CTX_new()) == NULL)
			|| ((buf = (uint8_t *) malloc(buf_len)) == NULL))
		return -1;
	EVP_DigestInit_ex(context, EVP_sha1(), NULL);
	memcpy(buf, ku, 20);
	memcpy(&buf[20], engine, engine_len);
	memcpy(&buf[20 + engine_len], ku, 20);
	EVP_DigestInit_ex(context, EVP_sha1(), NULL);
	EVP_DigestUpdate(context, buf, 40 + engine_len);
	EVP_DigestFinal_ex(context, (uint8_t *) kul, (unsigned int *) &kul_len);
	EVP_MD_CTX_destroy(context);
	free(buf);
	return 1;
}

static ERL_NIF_TERM
ku_md5_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary password, ku;

	if (!enif_inspect_iolist_as_binary(env, argv[0], &password))
		return enif_make_badarg(env);
	if (!enif_alloc_binary(16, &ku))
		return enif_raise_exception(env, enif_make_atom(env, "ealloc"));
	if (!ku_md5(password.data, password.size, ku.data, ku.size))
		return enif_raise_exception(env, enif_make_atom(env, "ealloc"));
	return enif_make_binary(env, &ku);
}

static ERL_NIF_TERM
kul_md5_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary engine, ku;
	size_t kul_len = 16;
	uint8_t i, kul[kul_len];
	ERL_NIF_TERM result[kul_len];

	if (!enif_inspect_iolist_as_binary(env, argv[0], &ku)
			|| !enif_inspect_iolist_as_binary(env, argv[1], &engine)
			|| engine.size > 32)
		return enif_make_badarg(env);
	if (!kul_md5(ku.data, ku.size,
			engine.data, engine.size, kul, kul_len))
		return enif_raise_exception(env, enif_make_atom(env, "ealloc"));
	for (i = 0; i < kul_len; i++)
		result[i] = enif_make_uint(env, kul[i]);
	return enif_make_list_from_array(env, result, kul_len);
}

static ERL_NIF_TERM
ku_sha_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary password, ku;

	if (!enif_inspect_iolist_as_binary(env, argv[0], &password))
		return enif_make_badarg(env);
	if (!enif_alloc_binary(20, &ku))
		return enif_raise_exception(env, enif_make_atom(env, "ealloc"));
	if (!ku_sha(password.data, password.size, ku.data, ku.size))
		return enif_raise_exception(env, enif_make_atom(env, "ealloc"));
	return enif_make_binary(env, &ku);
}

static ERL_NIF_TERM
kul_sha_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary engine, ku;
	size_t kul_len = 20;
	uint8_t i, kul[kul_len];
	ERL_NIF_TERM result[kul_len];

	if (!enif_inspect_iolist_as_binary(env, argv[0], &ku)
			|| !enif_inspect_iolist_as_binary(env, argv[1], &engine)
			|| engine.size > 32)
		return enif_make_badarg(env);
	if (!kul_sha(ku.data, ku.size,
			engine.data, engine.size, kul, kul_len))
		return enif_raise_exception(env, enif_make_atom(env, "ealloc"));
	for (i = 0; i < kul_len; i++)
		result[i] = enif_make_uint(env, kul[i]);
	return enif_make_list_from_array(env, result, kul_len);
}

static ErlNifFunc nif_funcs[] = {
	{"ku_md5", 1, ku_md5_nif},
	{"ku_sha", 1, ku_sha_nif},
	{"kul_md5", 2, kul_md5_nif},
	{"kul_sha", 2, kul_sha_nif}
};

ERL_NIF_INIT(snmp_collector_usm, nif_funcs, NULL, NULL, NULL, NULL)

