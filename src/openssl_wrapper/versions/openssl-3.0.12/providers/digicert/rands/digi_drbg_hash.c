/*
 * digi_drbg_hash.c ADAPTED FROM OPENSSL CODE
 *
 * NIST DRBG HASH implementations for OSSL 3.0 provider
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */
/*
 * Copyright 2011-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include "../../../src/common/moptions.h"
#include "../../../src/common/mtypes.h"
#include "../../../src/common/mdefs.h"
#include "../../../src/common/merrors.h"
#include "../../../src/common/mstdlib.h"
#include "../../../src/common/random.h"
#include "../../../src/crypto/nist_drbg_hash.h"
#include "../../../src/crypto_interface/crypto_interface_nist_drbg_hash.h"

#include "mocana_glue.h"
#include "digicert_common.h"
#include "digiprov.h"

#include "openssl/err.h"
#include "openssl/proverr.h"
#include "openssl/rand.h"
#include "openssl/crypto.h"
#include "crypto/modes.h"
#include "internal/thread_once.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "../../implementations/rands/drbg_local.h"
#include "internal/deprecated.h"
#include "crypto/rand.h"
#include "crypto/cryptlib.h"
#include "prov/seeding.h"
#include "crypto/rand_pool.h"

#include "digi_drbg_common.h"

/* 888 bits from SP800-90Ar1 10.1 table 2 */
#define HASH_PRNG_MAX_SEEDLEN    (888/8)

/* 440 bits from SP800-90Ar1 10.1 table 2 */
#define HASH_PRNG_SMALL_SEEDLEN   (440/8)

/* Determine what seedlen to use based on the block length */
#define MAX_BLOCKLEN_USING_SMALL_SEEDLEN (256/8)
#define INBYTE_IGNORE ((unsigned char)0xFF)

/*
 * The state of a DRBG HASH
 */
typedef struct _rand_drbg_hash_st 
{   
    char digestName[9]; /* big enough for "SHA3_512" */
    BulkHashAlgo *pBHAlgo;
    NIST_HASH_DRBG_Ctx *pRandCtx;
    size_t outlen;

} DP_DRBG_HASH;

static int digiprov_drbg_hash_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static int digiprov_drbg_hash_instantiate(PROV_DRBG *drbg, const unsigned char *ent, size_t ent_len,
                                          const unsigned char *nonce, size_t nonce_len,
                                          const unsigned char *pstr, size_t pstr_len)
{
    MSTATUS status = OK;
    DP_DRBG_HASH *hash = (DP_DRBG_HASH *)drbg->data;
    NIST_HASH_DRBG_Ctx *pNewCtx = NULL;

    status = CRYPTO_INTERFACE_NIST_HASHDRBG_newSeededContext(&pNewCtx, (ubyte *) ent, (ubyte4) ent_len, (ubyte *) nonce, (ubyte4) nonce_len,
                                                             (ubyte *) pstr, (ubyte4) pstr_len, hash->pBHAlgo->digestFunc, (ubyte4) hash->outlen);
    if (OK == status)
    {
        if (NULL != hash->pRandCtx)
        {
            status = CRYPTO_INTERFACE_NIST_HASHDRBG_deleteContext(&hash->pRandCtx);
            if (OK != status)
            {
                (void) CRYPTO_INTERFACE_NIST_HASHDRBG_deleteContext(&pNewCtx);
                return 0;
            }
        }
        hash->pRandCtx = pNewCtx; pNewCtx = NULL;
        return 1;
    }
 
    return 0;
}

static int digiprov_drbg_hash_instantiate_wrapper(void *vdrbg, unsigned int strength,
                                                  int prediction_resistance,
                                                  const unsigned char *pstr,
                                                  size_t pstr_len,
                                                  const OSSL_PARAM params[])
{
    PROV_DRBG *drbg = (PROV_DRBG *)vdrbg;

    if ( !digiprov_is_running() || !digiprov_drbg_hash_set_ctx_params(drbg, params))
        return 0;
    return digiprov_prov_drbg_instantiate(drbg, strength, prediction_resistance, pstr, pstr_len);
}

static int digiprov_drbg_hash_reseed(PROV_DRBG *drbg,
                                     const unsigned char *ent, size_t ent_len,
                                     const unsigned char *adin, size_t adin_len)
{
    MSTATUS status = OK;
    DP_DRBG_HASH *hash = (DP_DRBG_HASH *)drbg->data;

    if (ent == NULL)
        return 0;

    status = CRYPTO_INTERFACE_NIST_HASHDRBG_reSeed(hash->pRandCtx, (ubyte *) ent, (ubyte4) ent_len,
                                                   (ubyte *) adin, (ubyte4) adin_len);
    if (OK != status)
        return 0;

    return 1;
}

static int digiprov_drbg_hash_reseed_wrapper(void *vdrbg, int prediction_resistance,
                                             const unsigned char *ent, size_t ent_len,
                                             const unsigned char *adin, size_t adin_len)
{
    PROV_DRBG *drbg = (PROV_DRBG *)vdrbg;

    return digiprov_prov_drbg_reseed(drbg, prediction_resistance, ent, ent_len, adin, adin_len);
}

static int digiprov_drbg_hash_generate(PROV_DRBG *drbg,
                                       unsigned char *out, size_t outlen,
                                       const unsigned char *adin, size_t adin_len)
{
    MSTATUS status = OK;
    DP_DRBG_HASH *hash = (DP_DRBG_HASH *)drbg->data;
   
    status = CRYPTO_INTERFACE_NIST_HASHDRBG_generate(hash->pRandCtx, (ubyte *) adin, (ubyte4) adin_len, 
                                                     (ubyte *) out, (ubyte4) outlen);
    if (OK != status)
        return 0;
    
    return 1;
}

static int digiprov_drbg_hash_generate_wrapper
    (void *vdrbg, unsigned char *out, size_t outlen, unsigned int strength,
     int prediction_resistance, const unsigned char *adin, size_t adin_len)
{
    PROV_DRBG *drbg = (PROV_DRBG *)vdrbg;

    return digiprov_prov_drbg_generate(drbg, out, outlen, strength, prediction_resistance, adin, adin_len);
}

static int digiprov_drbg_hash_uninstantiate(PROV_DRBG *drbg)
{
    MSTATUS status = OK;
    DP_DRBG_HASH *hash = (DP_DRBG_HASH *)drbg->data;

    if (NULL != hash->pRandCtx)
    {
        status = CRYPTO_INTERFACE_NIST_HASHDRBG_deleteContext(&hash->pRandCtx);
        if (OK != status)
            return 0;
    }

    if (!digiprov_prov_drbg_uninstantiate(drbg))
        return 0;

    return 1;
}

static int digiprov_drbg_hash_uninstantiate_wrapper(void *vdrbg)
{
    return digiprov_drbg_hash_uninstantiate((PROV_DRBG *)vdrbg);
}

static int digiprov_drbg_hash_verify_zeroization(void *vdrbg)
{
    /* no exposed API to check in nanocrypto layer, but zeroization is done */
    return 1;
}

static int digiprov_drbg_hash_new(PROV_DRBG *ctx)
{
    MSTATUS status = OK;
    DP_DRBG_HASH *hash = NULL;

    status = DIGI_CALLOC((void **) &hash, 1, sizeof(*hash));
    if (OK != status)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    
    ctx->data = (void *) hash;
    ctx->seedlen = HASH_PRNG_MAX_SEEDLEN;
    ctx->max_entropylen = DRBG_MAX_LENGTH;
    ctx->max_noncelen = DRBG_MAX_LENGTH;
    ctx->max_perslen = DRBG_MAX_LENGTH;
    ctx->max_adinlen = DRBG_MAX_LENGTH;

    /* Maximum number of bits per request = 2^19  = 2^16 bytes */
    ctx->max_request = 1 << 16;
    return 1;
}

static void *digiprov_drbg_hash_new_wrapper(void *provctx, void *parent,
                                            const OSSL_DISPATCH *parent_dispatch)
{
    return digiprov_rand_drbg_new(provctx, parent, parent_dispatch, &digiprov_drbg_hash_new,
                                  &digiprov_drbg_hash_instantiate, &digiprov_drbg_hash_uninstantiate,
                                  &digiprov_drbg_hash_reseed, &digiprov_drbg_hash_generate);
}

static void digiprov_drbg_hash_free(void *vdrbg)
{
    PROV_DRBG *drbg = (PROV_DRBG *)vdrbg;
    DP_DRBG_HASH *hash;

    if (NULL != drbg)
    {
        hash = (DP_DRBG_HASH *) drbg->data;
        if (NULL != hash)
        {
            if (NULL != hash->pRandCtx)
            {
                (void) CRYPTO_INTERFACE_NIST_HASHDRBG_deleteContext(&hash->pRandCtx);
            }

            (void) DIGI_MEMSET_FREE((ubyte **) &hash, sizeof(*hash));
        }
    }

    digiprov_rand_drbg_free(drbg);
}

static int digiprov_drbg_hash_get_ctx_params(void *vdrbg, OSSL_PARAM params[])
{
    PROV_DRBG *drbg = (PROV_DRBG *)vdrbg;
    DP_DRBG_HASH *hash = (DP_DRBG_HASH *)drbg->data;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_DIGEST);
    if (p != NULL) 
    {
        if (!OSSL_PARAM_set_utf8_string(p, hash->digestName))
            return 0;
    }

    return digiprov_drbg_get_ctx_params(drbg, params);
}

static const OSSL_PARAM *digiprov_drbg_hash_gettable_ctx_params(ossl_unused void *vctx,
                                                                ossl_unused void *p_ctx)
{
    static const OSSL_PARAM digiprov_known_gettable_ctx_params[] =
    {
        OSSL_PARAM_utf8_string(OSSL_DRBG_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_DRBG_GETTABLE_CTX_COMMON,
        OSSL_PARAM_END
    };
    return digiprov_known_gettable_ctx_params;
}

static int digiprov_drbg_hash_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_DRBG *ctx = (PROV_DRBG *) vctx;
    OSSL_PARAM *p;

    p = (OSSL_PARAM *) OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_DIGEST);
    if (NULL != p)
    {
        MSTATUS status = OK;
        DP_DRBG_HASH *hash = (DP_DRBG_HASH *) ctx->data;
        ubyte4 outSize = 0;

        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;

        if (p->data_size > 8)
            return 0;

        status = digiprov_get_digest_data((const char *) p->data, &hash->pBHAlgo, &outSize, NULL);
        if (OK != status)
            return 0;

        status = DIGI_MEMCPY((sbyte *) hash->digestName, (const sbyte *) p->data, (int) p->data_size);
        if (OK != status)
            return 0;

        hash->digestName[p->data_size] = '\0';

        hash->outlen = (size_t) outSize;

        /* See SP800-57 Part1 Rev4 5.6.1 Table 3 */
        /* this formula gives the correct result, note "blocklen" in openssl impl is actually outlen */
        ctx->strength = 64 * ((hash->outlen) >> 3);
        if (ctx->strength > 256)
            ctx->strength = 256;

        if (hash->outlen > MAX_BLOCKLEN_USING_SMALL_SEEDLEN)
            ctx->seedlen = HASH_PRNG_MAX_SEEDLEN;
        else
            ctx->seedlen = HASH_PRNG_SMALL_SEEDLEN;

        ctx->min_entropylen = ctx->strength / 8;
        ctx->min_noncelen = ctx->min_entropylen / 2;
    }

    return digiprov_drbg_set_ctx_params(ctx, params);
}

static const OSSL_PARAM *digiprov_drbg_hash_settable_ctx_params(ossl_unused void *vctx,
                                                                ossl_unused void *p_ctx)
{
    static const OSSL_PARAM digiprov_known_settable_ctx_params[] =
    {
        OSSL_PARAM_utf8_string(OSSL_DRBG_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_DRBG_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_DRBG_SETTABLE_CTX_COMMON,
        OSSL_PARAM_END
    };
    return digiprov_known_settable_ctx_params;
}

const OSSL_DISPATCH digiprov_drbg_hash_functions[] =
{
    { OSSL_FUNC_RAND_NEWCTX,              (void(*)(void))digiprov_drbg_hash_new_wrapper },
    { OSSL_FUNC_RAND_FREECTX,             (void(*)(void))digiprov_drbg_hash_free },
    { OSSL_FUNC_RAND_INSTANTIATE,         (void(*)(void))digiprov_drbg_hash_instantiate_wrapper },
    { OSSL_FUNC_RAND_UNINSTANTIATE,       (void(*)(void))digiprov_drbg_hash_uninstantiate_wrapper },
    { OSSL_FUNC_RAND_GENERATE,            (void(*)(void))digiprov_drbg_hash_generate_wrapper },
    { OSSL_FUNC_RAND_RESEED,              (void(*)(void))digiprov_drbg_hash_reseed_wrapper },
    { OSSL_FUNC_RAND_ENABLE_LOCKING,      (void(*)(void))digiprov_drbg_enable_locking },
    { OSSL_FUNC_RAND_LOCK,                (void(*)(void))digiprov_drbg_lock },
    { OSSL_FUNC_RAND_UNLOCK,              (void(*)(void))digiprov_drbg_unlock },
    { OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS, (void(*)(void))digiprov_drbg_hash_settable_ctx_params },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS,      (void(*)(void))digiprov_drbg_hash_set_ctx_params },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void(*)(void))digiprov_drbg_hash_gettable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS,      (void(*)(void))digiprov_drbg_hash_get_ctx_params },
    { OSSL_FUNC_RAND_VERIFY_ZEROIZATION,  (void(*)(void))digiprov_drbg_hash_verify_zeroization },
    { OSSL_FUNC_RAND_GET_SEED,            (void(*)(void))digiprov_drbg_get_seed },
    { OSSL_FUNC_RAND_CLEAR_SEED,          (void(*)(void))digiprov_drbg_clear_seed },
    { 0, NULL }
};
