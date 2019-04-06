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
#include <sys/time.h>
#include "erl_nif.h"

typedef struct {
	ErlNifResourceType *type;
} PrivData;

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

int
kul_md5(uint8_t *ku, size_t ku_len,
		uint8_t *engine, size_t engine_len, uint8_t *kul, size_t kul_len)
{
	EVP_MD_CTX *context;
	uint8_t *buf, buf_len;

	buf_len = engine_len + 32;
	if (((context = EVP_MD_CTX_new()) == NULL)
			|| ((buf = (uint8_t *) enif_alloc(buf_len)) == NULL))
		return -1;
	EVP_DigestInit_ex(context, EVP_md5(), NULL);
	memcpy(buf, ku, 16);
	memcpy(&buf[16], engine, engine_len);
	memcpy(&buf[16 + engine_len], ku, 16);
	EVP_DigestInit_ex(context, EVP_md5(), NULL);
	EVP_DigestUpdate(context, buf, 32 + engine_len);
	EVP_DigestFinal_ex(context, (uint8_t *) kul, (unsigned int *) &kul_len);
	EVP_MD_CTX_destroy(context);
	enif_free(buf);
	return 1;
}

int
kul_sha(uint8_t *ku, size_t ku_len,
		uint8_t *engine, size_t engine_len, uint8_t *kul, size_t kul_len)
{
	EVP_MD_CTX *context;
	uint8_t *buf, buf_len;

	buf_len = engine_len + 40;
	if (((context = EVP_MD_CTX_new()) == NULL)
			|| ((buf = (uint8_t *) enif_alloc(buf_len)) == NULL))
		return -1;
	EVP_DigestInit_ex(context, EVP_sha1(), NULL);
	memcpy(buf, ku, 20);
	memcpy(&buf[20], engine, engine_len);
	memcpy(&buf[20 + engine_len], ku, 20);
	EVP_DigestInit_ex(context, EVP_sha1(), NULL);
	EVP_DigestUpdate(context, buf, 40 + engine_len);
	EVP_DigestFinal_ex(context, (uint8_t *) kul, (unsigned int *) &kul_len);
	EVP_MD_CTX_destroy(context);
	enif_free(buf);
	return 1;
}

static ERL_NIF_TERM
ku_cont_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	PrivData *priv_data;
	EVP_MD_CTX *context;
	ErlNifBinary buf, ku;
	int ku_len, password_len, count, i, percent;
	struct timeval start, stop, slice;
	ERL_NIF_TERM sched_argv[6];
	
	gettimeofday(&start, NULL);
	priv_data = (PrivData *) enif_priv_data(env);
	if ((!enif_get_int(env, argv[0], &ku_len))
			|| (!enif_get_resource(env, argv[1], priv_data->type, (void **) &context))
			|| (!enif_inspect_iolist_as_binary(env, argv[2], &buf))
			|| (!enif_get_int(env, argv[3], &password_len))
			|| (!enif_get_int(env, argv[4], &count))
			|| (!enif_get_int(env, argv[5], &i)))
		return enif_make_badarg(env);
	while (count < 1048576) {
		EVP_DigestUpdate(context, (const void *) &buf.data[i], 64);
		i = (i + 64) % password_len;
		count += 64;
		gettimeofday(&stop, NULL);
		timersub(&stop, &start, &slice);
		percent = (int) ((slice.tv_sec * 1000000 + slice.tv_usec + 1) / 10);
		if (percent > 100)
			percent = 100;
		if (enif_consume_timeslice(env, percent)) {
			sched_argv[0] = argv[0],
			sched_argv[1] = argv[1],
			sched_argv[2] = enif_make_binary(env, &buf);
			sched_argv[3] = enif_make_int(env, password_len);
			sched_argv[4] = enif_make_int(env, count);
			sched_argv[5] = enif_make_int(env, i);
			return enif_schedule_nif(env,
					"ku_cont_nif", 0, ku_cont_nif, 6, sched_argv);
		}
	}
	if (!enif_alloc_binary(ku_len, &ku))
		return enif_raise_exception(env, enif_make_atom(env, "ealloc"));
	EVP_DigestFinal_ex(context, (uint8_t *) ku.data, (unsigned int *) &ku.size);
	return enif_make_binary(env, &ku);
}

/* Password to Key (Ku) Algorithm (MD5)
 * RFC3414 A.2.1.
 */
static ERL_NIF_TERM
ku_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	PrivData *priv_data;
	char digest_type[4];
	EVP_MD_CTX *context;
	ErlNifBinary password, buf;
	int i = 0;
	int count = 0;
	ERL_NIF_TERM sched_argv[6];
	
	priv_data = (PrivData *) enif_priv_data(env);
	if ((enif_get_atom(env, argv[0], digest_type, 4, ERL_NIF_LATIN1) == 0)
		|| !enif_inspect_iolist_as_binary(env, argv[1], &password))
		return enif_make_badarg(env);
	if ((!enif_alloc_binary(password.size + 64, &buf)) 
			|| ((context = enif_alloc_resource(priv_data->type,
			sizeof(EVP_MD_CTX))) == NULL))
		return enif_raise_exception(env, enif_make_atom(env, "ealloc"));
	EVP_MD_CTX_init(context);
	if (strcmp(digest_type, "md5") == 0) {
		EVP_DigestInit_ex(context, EVP_md5(), NULL);
		sched_argv[0] = enif_make_int(env, 16);
	} else if(strcmp(digest_type, "sha") == 0) {
		EVP_DigestInit_ex(context, EVP_sha1(), NULL);
		sched_argv[0] = enif_make_int(env, 20);
	} else return enif_make_badarg(env);
	sched_argv[1] = enif_make_resource(env, context);
	for (i = 0; i < buf.size; i += password.size) {
		memcpy(&buf.data[i], password.data, password.size);
	}
	sched_argv[2] = enif_make_binary(env, &buf);
	sched_argv[3] = enif_make_int(env, password.size);
	sched_argv[4] = enif_make_int(env, count);
	sched_argv[5] = enif_make_int(env, 0);
	enif_release_resource(context);
	return enif_schedule_nif(env,
			"ku_cont_nif", 0, ku_cont_nif, 6, sched_argv);
}

/* Key (Ku) to localized key (Kul) Algorithm
 * RFC3414 A.2
 */
static ERL_NIF_TERM
kul_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	char digest_type[4];
	ErlNifBinary engine, ku;
	uint8_t i, kul[20], kul_len;
	ERL_NIF_TERM result[20];

	if ((enif_get_atom(env, argv[0], digest_type, 4, ERL_NIF_LATIN1) == 0)
			|| !enif_inspect_iolist_as_binary(env, argv[1], &ku)
			|| !enif_inspect_iolist_as_binary(env, argv[2], &engine)
			|| engine.size > 32)
		return enif_make_badarg(env);
	if (strcmp(digest_type, "md5") == 0) {
		kul_len = 16;
		if (!kul_md5(ku.data, ku.size, engine.data, engine.size, kul, kul_len))
			return enif_raise_exception(env, enif_make_atom(env, "ealloc"));
	} else if(strcmp(digest_type, "sha") == 0) {
		kul_len = 20;
		if (!kul_sha(ku.data, ku.size, engine.data, engine.size, kul, kul_len))
			return enif_raise_exception(env, enif_make_atom(env, "ealloc"));
	} else return enif_make_badarg(env);
	for (i = 0; i < kul_len; i++)
		result[i] = enif_make_uint(env, kul[i]);
	return enif_make_list_from_array(env, result, kul_len);
}

int
load(ErlNifEnv *env, void **priv_datap, ERL_NIF_TERM load_info)
{
	PrivData *priv_data;

	if (((priv_data = enif_alloc(sizeof(PrivData))) == NULL)
			|| ((priv_data->type = enif_open_resource_type(env,
			NULL, "EVP_MD_CTX", NULL, ERL_NIF_RT_CREATE, NULL)) == NULL))
		return 1;
	*priv_datap = (void **) priv_data;
	return 0;
}

static ErlNifFunc nif_funcs[] = {
	{"ku", 2, ku_nif},
	{"ku_cont", 6, ku_cont_nif},
	{"kul", 3, kul_nif}
};

ERL_NIF_INIT(snmp_collector_usm, nif_funcs, load, NULL, NULL, NULL)

