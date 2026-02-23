/*
 * digi_drbg_ctr.c ADAPTED FROM OPENSSL CODE
 *
 * NIST DRBG CTR implementations for OSSL 3.0 provider
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
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/*---------------------------------------------------------------------------------------------------------*/

#include "../../../src/common/moptions.h"
#include "../../../src/common/mtypes.h"
#include "../../../src/common/mdefs.h"
#include "../../../src/common/merrors.h"
#include "../../../src/common/mstdlib.h"
#include "../../../src/common/random.h"
#include "../../../src/crypto/nist_rng.h"
#include "../../../src/crypto_interface/crypto_interface_nist_ctr_drbg.h"

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

/*
 * The state of a DRBG AES-CTR.
 */
typedef struct _rand_drbg_ctr_st 
{
    char cipher[12]; /* big enough for "AES-128-CTR" */
    size_t keylen;
    int use_df;
    randomContext *pRandCtx;
    size_t blocklen;

} DP_DRBG_CTR;

static int digiprov_drbg_ctr_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static int digiprov_drbg_ctr_instantiate(PROV_DRBG *drbg,
                                         const unsigned char *entropy, size_t entropylen,
                                         const unsigned char *nonce, size_t noncelen,
                                         const unsigned char *pers, size_t perslen)
{
    MSTATUS status = OK;
    DP_DRBG_CTR *ctr = (DP_DRBG_CTR *)drbg->data;
    randomContext *pNewRand = NULL;

    if (entropy == NULL)
        return 0;

    if (ctr->use_df)
    {
        status = CRYPTO_INTERFACE_NIST_CTRDRBG_newDFContext(
            &pNewRand, (ubyte4) ctr->keylen, (ubyte4) ctr->blocklen, (ubyte *) entropy, (ubyte4) entropylen,
            (ubyte *) nonce, (ubyte4) noncelen, (ubyte *) pers, (ubyte4) perslen);
    }
    else
    {
        status = CRYPTO_INTERFACE_NIST_CTRDRBG_newContext(
            &pNewRand, (ubyte *) entropy, (ubyte4) ctr->keylen, (ubyte4) ctr->blocklen, 
            (ubyte *) pers, (ubyte4) perslen);
    }
    if (OK == status)
    {
        if (NULL != ctr->pRandCtx)
        {
            status = CRYPTO_INTERFACE_NIST_CTRDRBG_deleteContext(&ctr->pRandCtx);
            if (OK != status)
            {
                (void) CRYPTO_INTERFACE_NIST_CTRDRBG_deleteContext(&pNewRand);
                return 0;
            }
        }
        ctr->pRandCtx = pNewRand; pNewRand = NULL;
        return 1;
    }

    return 0;
}

static int digiprov_drbg_ctr_instantiate_wrapper(void *vdrbg, unsigned int strength,
                                                 int prediction_resistance,
                                                 const unsigned char *pstr,
                                                 size_t pstr_len,
                                                 const OSSL_PARAM params[])
{
    PROV_DRBG *drbg = (PROV_DRBG *)vdrbg;

    if (!digiprov_is_running() || !digiprov_drbg_ctr_set_ctx_params(drbg, params))
        return 0;

    return digiprov_prov_drbg_instantiate(drbg, strength, prediction_resistance, pstr, pstr_len);
}

static int digiprov_drbg_ctr_reseed(PROV_DRBG *drbg,
                                    const unsigned char *entropy, size_t entropylen,
                                    const unsigned char *adin, size_t adinlen)
{
    MSTATUS status = OK;
    DP_DRBG_CTR *ctr = (DP_DRBG_CTR *)drbg->data;

    if (entropy == NULL)
        return 0;

    status = CRYPTO_INTERFACE_NIST_CTRDRBG_reseed(ctr->pRandCtx, (const ubyte *) entropy, (ubyte4) entropylen,
                                                  (ubyte *) adin, (ubyte4) adinlen);
    if (OK != status)
        return 0;

    return 1;
}

static int digiprov_drbg_ctr_reseed_wrapper(void *vdrbg, int prediction_resistance,
                                            const unsigned char *ent, size_t ent_len,
                                            const unsigned char *adin, size_t adin_len)
{
    PROV_DRBG *drbg = (PROV_DRBG *)vdrbg;

    return digiprov_prov_drbg_reseed(drbg, prediction_resistance, ent, ent_len, adin, adin_len);
}

static int digiprov_drbg_ctr_generate(PROV_DRBG *drbg,
                                      unsigned char *out, size_t outlen,
                                      const unsigned char *adin, size_t adinlen)
{
    MSTATUS status = OK;
    DP_DRBG_CTR *ctr = (DP_DRBG_CTR *)drbg->data;
   
    status = CRYPTO_INTERFACE_NIST_CTRDRBG_generate(ctr->pRandCtx, (const ubyte *) adin, (ubyte4) adinlen,
                                                    (ubyte *) out, (ubyte4) 8*outlen);
    if (OK != status)
        return 0;
    
    return 1;
}

static int digiprov_drbg_ctr_generate_wrapper
    (void *vdrbg, unsigned char *out, size_t outlen,
     unsigned int strength, int prediction_resistance,
     const unsigned char *adin, size_t adin_len)
{
    PROV_DRBG *drbg = (PROV_DRBG *)vdrbg;

    return digiprov_prov_drbg_generate(drbg, out, outlen, strength, prediction_resistance, adin, adin_len);
}

static int digiprov_drbg_ctr_uninstantiate(PROV_DRBG *drbg)
{
    DP_DRBG_CTR *ctr = (DP_DRBG_CTR *)drbg->data;

    if (NULL != ctr->pRandCtx)
    {
        MSTATUS status = CRYPTO_INTERFACE_NIST_CTRDRBG_deleteContext(&ctr->pRandCtx);
        if (OK != status)
            return 0;
    }

    if (!digiprov_prov_drbg_uninstantiate(drbg))
        return 0;

    return 1;
}

static int digiprov_drbg_ctr_uninstantiate_wrapper(void *vdrbg)
{
    return digiprov_drbg_ctr_uninstantiate((PROV_DRBG *)vdrbg);
}

static int digiprov_drbg_ctr_verify_zeroization(void *vdrbg)
{
    /* no exposed API to check in nanocrypto layer, but zeroization is done */
    return 1;
}

static int digiprov_drbg_ctr_init_lengths(PROV_DRBG *drbg)
{
    DP_DRBG_CTR *ctr = (DP_DRBG_CTR *)drbg->data;
    int res = 1;

    /* Maximum number of bits per request = 2^19  = 2^16 bytes */
    drbg->max_request = 1 << 16;
    if (ctr->use_df) 
    {
        drbg->min_entropylen = 0;
        drbg->max_entropylen = DRBG_MAX_LENGTH;
        drbg->min_noncelen = 0;
        drbg->max_noncelen = DRBG_MAX_LENGTH;
        drbg->max_perslen = DRBG_MAX_LENGTH;
        drbg->max_adinlen = DRBG_MAX_LENGTH;

        if (ctr->keylen > 0) 
        {
            drbg->min_entropylen = ctr->keylen;
            drbg->min_noncelen = drbg->min_entropylen / 2;
        }
    }
    else 
    {
        const size_t len = ctr->keylen > 0 ? drbg->seedlen : DRBG_MAX_LENGTH;

        drbg->min_entropylen = len;
        drbg->max_entropylen = len;
        /* Nonce not used */
        drbg->min_noncelen = 0;
        drbg->max_noncelen = 0;
        drbg->max_perslen = len;
        drbg->max_adinlen = len;
    }
    return res;
}

static int digiprov_drbg_ctr_new(PROV_DRBG *drbg)
{
    MSTATUS status = OK;
    DP_DRBG_CTR *ctr = NULL;

    status = DIGI_CALLOC((void **) &ctr, 1, sizeof(*ctr));
    if (OK != status)
    {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    
    ctr->use_df = 1;
    drbg->data = (void *) ctr;
    return digiprov_drbg_ctr_init_lengths(drbg);
}

static void *digiprov_drbg_ctr_new_wrapper(void *provctx, void *parent,
                                           const OSSL_DISPATCH *parent_dispatch)
{
    return digiprov_rand_drbg_new(provctx, parent, parent_dispatch, &digiprov_drbg_ctr_new,
                                  &digiprov_drbg_ctr_instantiate, &digiprov_drbg_ctr_uninstantiate,
                                  &digiprov_drbg_ctr_reseed, &digiprov_drbg_ctr_generate);
}

static void digiprov_drbg_ctr_free(void *vdrbg)
{
    PROV_DRBG *drbg = (PROV_DRBG *)vdrbg;
    DP_DRBG_CTR *ctr;

    if (NULL != drbg)
    {
        ctr = (DP_DRBG_CTR *) drbg->data;
        if (NULL != ctr)
        {
            if (NULL != ctr->pRandCtx)
            {
                (void) CRYPTO_INTERFACE_NIST_CTRDRBG_deleteContext(&ctr->pRandCtx);
            }

            (void) DIGI_MEMSET_FREE((ubyte **) &ctr, sizeof(*ctr));
        }
    }

    digiprov_rand_drbg_free(drbg);
}

static int digiprov_drbg_ctr_get_ctx_params(void *vdrbg, OSSL_PARAM params[])
{
    PROV_DRBG *drbg = (PROV_DRBG *)vdrbg;
    DP_DRBG_CTR *ctr = (DP_DRBG_CTR *)drbg->data;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_USE_DF);
    if (p != NULL && !OSSL_PARAM_set_int(p, ctr->use_df))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_DRBG_PARAM_CIPHER);
    if (p != NULL) 
    {
        if (!OSSL_PARAM_set_utf8_string(p, ctr->cipher))
            return 0;
    }

    return digiprov_drbg_get_ctx_params(drbg, params);
}

static const OSSL_PARAM *digiprov_drbg_ctr_gettable_ctx_params(ossl_unused void *vctx,
                                                               ossl_unused void *provctx)
{
    static const OSSL_PARAM digiprov_known_gettable_ctx_params[] = 
    {
        OSSL_PARAM_utf8_string(OSSL_DRBG_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_int(OSSL_DRBG_PARAM_USE_DF, NULL),
        OSSL_PARAM_DRBG_GETTABLE_CTX_COMMON,
        OSSL_PARAM_END
    };
    return digiprov_known_gettable_ctx_params;
}

static int digiprov_drbg_ctr_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    MSTATUS status = OK;
    PROV_DRBG *ctx = (PROV_DRBG *)vctx;
    DP_DRBG_CTR *ctr = (DP_DRBG_CTR *)ctx->data;
    const OSSL_PARAM *p;
    int i;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_USE_DF)) != NULL
            && OSSL_PARAM_get_int(p, &i)) {
        /* FIPS errors out in the drbg_ctr_init() call later */
        ctr->use_df = i != 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_DRBG_PARAM_CIPHER)) != NULL)
    {
        const char *base = (const char *)p->data;
        
        /* min is "TDES-CTR" and max is "AES-128-CTR" */
        if (p->data_type != OSSL_PARAM_UTF8_STRING || p->data_size < 8 || p->data_size > 11)
            return 0;
        
        /* last 3 need to be CTR */
        if (OPENSSL_strcasecmp("CTR", base + p->data_size - 3) != 0) 
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_REQUIRE_CTR_MODE_CIPHER);
            return 0;
        }

        if (OPENSSL_strncasecmp("AES", base, 3) == 0)
        {
            if(OPENSSL_strncasecmp("128", base + 4, 3) == 0)
            {
                ctr->keylen = 16;
                ctr->blocklen = 16;
            }
            else if(OPENSSL_strncasecmp("192", base + 4, 3) == 0)
            {
                ctr->keylen = 24;
                ctr->blocklen = 16;
            }
            else if(OPENSSL_strncasecmp("256", base + 4, 3) == 0)
            {
                ctr->keylen = 32;
                ctr->blocklen = 16;
            }
            else
            {
                return 0;
            }
        }
        else if (OPENSSL_strncasecmp("TDES", base, 3) == 0)
        {
            ctr->keylen = 21;
            ctr->blocklen = 8;
        }

        status = DIGI_MEMCPY(ctr->cipher, base, p->data_size);
        if (OK != status)
            return 0;

        ctr->cipher[p->data_size] = '\0';

        ctx->strength = ctr->keylen * 8;
        ctx->seedlen = ctr->keylen + 16;
    }

    if(!digiprov_drbg_ctr_init_lengths(ctx))
        return 0;

    return digiprov_drbg_set_ctx_params(ctx, params);
}

static const OSSL_PARAM *digiprov_drbg_ctr_settable_ctx_params(ossl_unused void *vctx,
                                                               ossl_unused void *provctx)
{
    static const OSSL_PARAM digiprov_known_settable_ctx_params[] = 
    {
        OSSL_PARAM_utf8_string(OSSL_DRBG_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_DRBG_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_int(OSSL_DRBG_PARAM_USE_DF, NULL),
        OSSL_PARAM_DRBG_SETTABLE_CTX_COMMON,
        OSSL_PARAM_END
    };
    return digiprov_known_settable_ctx_params;
}

const OSSL_DISPATCH digiprov_drbg_ctr_functions[] =
{
    { OSSL_FUNC_RAND_NEWCTX,              (void(*)(void))digiprov_drbg_ctr_new_wrapper },
    { OSSL_FUNC_RAND_FREECTX,             (void(*)(void))digiprov_drbg_ctr_free },
    { OSSL_FUNC_RAND_INSTANTIATE,         (void(*)(void))digiprov_drbg_ctr_instantiate_wrapper },
    { OSSL_FUNC_RAND_UNINSTANTIATE,       (void(*)(void))digiprov_drbg_ctr_uninstantiate_wrapper },
    { OSSL_FUNC_RAND_GENERATE,            (void(*)(void))digiprov_drbg_ctr_generate_wrapper },
    { OSSL_FUNC_RAND_RESEED,              (void(*)(void))digiprov_drbg_ctr_reseed_wrapper },
    { OSSL_FUNC_RAND_ENABLE_LOCKING,      (void(*)(void))digiprov_drbg_enable_locking },
    { OSSL_FUNC_RAND_LOCK,                (void(*)(void))digiprov_drbg_lock },
    { OSSL_FUNC_RAND_UNLOCK,              (void(*)(void))digiprov_drbg_unlock },
    { OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS, (void(*)(void))digiprov_drbg_ctr_settable_ctx_params },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS,      (void(*)(void))digiprov_drbg_ctr_set_ctx_params },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, (void(*)(void))digiprov_drbg_ctr_gettable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS,      (void(*)(void))digiprov_drbg_ctr_get_ctx_params },
    { OSSL_FUNC_RAND_VERIFY_ZEROIZATION,  (void(*)(void))digiprov_drbg_ctr_verify_zeroization },
    { OSSL_FUNC_RAND_GET_SEED,            (void(*)(void))digiprov_drbg_get_seed },
    { OSSL_FUNC_RAND_CLEAR_SEED,          (void(*)(void))digiprov_drbg_clear_seed },
    { 0, NULL }
};
