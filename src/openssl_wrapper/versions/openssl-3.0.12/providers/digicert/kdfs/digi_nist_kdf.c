/*
 * digi_nist_kdf.c
 *
 * NISTKDF (sp800-108) implementation for OSSL 3.0 provider. ADAPTED from OPENSSL code
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
 * Copyright 2019-2022 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2019 Red Hat, Inc.
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
#include "../../../src/crypto/hw_accel.h"
#include "../../../src/crypto/md5.h"
#include "../../../src/crypto/sha1.h"
#include "../../../src/crypto/sha256.h"
#include "../../../src/crypto/sha512.h"
#include "../../../src/crypto/crypto.h"
#include "../../../src/crypto/aes.h"
#include "../../../src/crypto/aes_cmac.h"
#include "../../../src/crypto/hmac.h"
#include "../../../src/crypto/nist_prf.h"
#include "../../../src/crypto/nist_kdf.h"

#include "../../../src/crypto_interface/crypto_interface_nist_kdf.h"
#include "../../../src/crypto_interface/crypto_interface_aes_cmac.h"
#include "../../../src/crypto_interface/crypto_interface_hmac.h"

#define HMAC_CTX HMAC_CTX_OSSL
#include "mocana_glue.h"
#include "digicert_common.h"
#undef HMAC_CTX

#include "prov/names.h"
#include "openssl/params.h"
#include "openssl/provider.h"
#include "openssl/err.h"
#include "openssl/proverr.h"
#include "openssl/core_names.h"
#include "openssl/evp.h"
#include "openssl/obj_mac.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"

#include "digiprov.h"

#include "internal/deprecated.h"

/* our implementation supports these but openssl does not have the flags to set set them */
#define DIGI_NIST_KDF_CTR_SIZE 4
#define DIGI_NIST_KDF_KE_SIZE 4
#define DIGI_NIST_KDF_LE 0 /* false */

typedef enum 
{
    COUNTER = 0,
    FEEDBACK = 1,
    PIPELINE = 2
} kbkdf_mode;

/* Our context structure. */
typedef struct 
{
    kbkdf_mode mode;
    PRF_NIST_108 *pPRF;
    BulkHashAlgo *pBHAlgo;  /* for HMAC */ 
   
    union
    {
        HMAC_CTX    *ctx_hmac_init;
        AESCMAC_Ctx *ctx_cmac_init;
    };

    /* Names are lowercased versions of those found in SP800-108. */
    unsigned char *ki;
    size_t ki_len;
    unsigned char *label;
    size_t label_len;
    unsigned char *context;
    size_t context_len;
    unsigned char *iv;
    size_t iv_len;

} DP_NKDF_CTX;

static int digiprov_kbkdf_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

static void *digiprov_kbkdf_new(void *provctx)
{
    MSTATUS status = OK;
    DP_NKDF_CTX *ctx = NULL;

    MOC_UNUSED(provctx);

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **) &ctx, 1, sizeof(DP_NKDF_CTX));
    if (OK != status)
        return NULL;

    return ctx;
}

static void digiprov_kbkdf_reset(void *vctx)
{
    DP_NKDF_CTX *ctx = (DP_NKDF_CTX *)vctx;

    if (NULL == ctx)
        return;

    if (NULL != ctx->pPRF && NULL != ctx->ctx_hmac_init)
    {
        if ((uintptr) &NIST_PRF_Hmac == (uintptr) ctx->pPRF)
        {
            (void) CRYPTO_INTERFACE_HmacDelete(&ctx->ctx_hmac_init);
        }
        else if ((uintptr) &NIST_PRF_AesCmac == (uintptr) ctx->pPRF)
        {
            (void) CRYPTO_INTERFACE_AESCMAC_clear(ctx->ctx_cmac_init);
            (void) DIGI_FREE((void **) &ctx->ctx_cmac_init); /* it's already zeroed out */
        }
    }
    
    if (NULL != ctx->context)
        (void) DIGI_MEMSET_FREE(&ctx->context, ctx->context_len);
    
    if (NULL != ctx->label)
        (void) DIGI_MEMSET_FREE(&ctx->label, ctx->label_len);
    
    if (NULL != ctx->ki)
        (void) DIGI_MEMSET_FREE(&ctx->ki, ctx->ki_len);
    
    if (NULL != ctx->iv)
        (void) DIGI_MEMSET_FREE(&ctx->iv, ctx->iv_len);

    (void) DIGI_MEMSET((ubyte *) ctx, 0, sizeof(DP_NKDF_CTX));
}

static void digiprov_kbkdf_free(void *vctx)
{
    DP_NKDF_CTX *ctx = (DP_NKDF_CTX *)vctx;

    if (NULL != ctx) 
    {
        digiprov_kbkdf_reset(ctx);
        (void) DIGI_FREE((void **) &ctx);
    }
}

static int digiprov_kbkdf_derive(void *vctx, unsigned char *key, size_t keylen, const OSSL_PARAM params[])
{
    MSTATUS status = OK;
    DP_NKDF_CTX *ctx = (DP_NKDF_CTX *)vctx;
  
    if (!digiprov_is_running())
        return 0;

    /* Fail if the output length is zero */
    if (0 == keylen) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return 0;
    }

    if (!digiprov_kbkdf_set_ctx_params(ctx, params))
        return 0;

    if (NULL == ctx->ki)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (NULL == ctx->pPRF || NULL == ctx->ctx_hmac_init)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_MAC);
        return 0;
    }

    switch (ctx->mode)
    {
      case COUNTER:
        status = CRYPTO_INTERFACE_KDF_NIST_CounterMode(DIGI_NIST_KDF_CTR_SIZE, (void *) ctx->ctx_hmac_init, ctx->pPRF, 
                                      ctx->label, (ubyte4) ctx->label_len, ctx->context, (ubyte4) ctx->context_len,
                                      DIGI_NIST_KDF_KE_SIZE, DIGI_NIST_KDF_LE, key, (ubyte4) keylen);
        break;
      case FEEDBACK:          
        status = CRYPTO_INTERFACE_KDF_NIST_FeedbackMode(DIGI_NIST_KDF_CTR_SIZE, (void *) ctx->ctx_hmac_init, ctx->pPRF,
                                       ctx->iv, (ubyte4) ctx->iv_len,
                                       ctx->label, (ubyte4) ctx->label_len, ctx->context, (ubyte4) ctx->context_len,
                                       DIGI_NIST_KDF_KE_SIZE, DIGI_NIST_KDF_LE, key, (ubyte4) keylen);
        break;
      case PIPELINE:
        status = CRYPTO_INTERFACE_KDF_NIST_DoublePipelineMode(DIGI_NIST_KDF_CTR_SIZE, (void *) ctx->ctx_hmac_init, ctx->pPRF, 
                                             ctx->label, (ubyte4) ctx->label_len,
                                             ctx->context, (ubyte4) ctx->context_len,
                                             DIGI_NIST_KDF_KE_SIZE, DIGI_NIST_KDF_LE, key, (ubyte4) keylen); 
        break;
      default:
        return 0;
    }

    if (OK != status)
    {
        (void) DIGI_MEMSET(key, 0x00, (int) keylen);
        return 0;
    }

    return 1;
}

static int digiprov_kbkdf_set_buffer(unsigned char **out, size_t *out_len, const OSSL_PARAM *p)
{
    if (p->data == NULL || p->data_size == 0)
        return 1;

    (void) DIGI_MEMSET_FREE(out, (ubyte4) *out_len);
    *out = NULL;
    return digiprov_get_octet_string(p, (void **)out, 0, out_len);
}

static int digiprov_kbkdf_mac_init(DP_NKDF_CTX *ctx)
{
    MSTATUS status = OK;

    if ((uintptr) &NIST_PRF_Hmac == (uintptr) ctx->pPRF)
    {
        /* delete an old context if there */
        if (NULL != ctx->ctx_hmac_init)
        {
            status = CRYPTO_INTERFACE_HmacDelete(&ctx->ctx_hmac_init);
            if (OK != status)
                return 0;
        }

        status = CRYPTO_INTERFACE_HmacCreate(&ctx->ctx_hmac_init, ctx->pBHAlgo);
        if (OK != status)
            return 0;

        status = CRYPTO_INTERFACE_HmacKey(ctx->ctx_hmac_init, (ubyte *) ctx->ki, (ubyte4) ctx->ki_len);
        if (OK != status)
        {
            (void) CRYPTO_INTERFACE_HmacDelete(&ctx->ctx_hmac_init);
            return 0;
        }
    }
    else if ((uintptr) &NIST_PRF_AesCmac == (uintptr) ctx->pPRF)
    {
        /* delete an old context if there */
        if (NULL != ctx->ctx_cmac_init)
        {
            status = CRYPTO_INTERFACE_AESCMAC_clear(ctx->ctx_cmac_init);
            if (OK != status)
                return 0;

            status = DIGI_FREE((void **) &ctx->ctx_cmac_init);
            if (OK != status)
                return 0;
        }

        status = DIGI_CALLOC((void **)&ctx->ctx_cmac_init, 1, sizeof(AESCMAC_Ctx));
        if (OK != status)
            return 0;

        status = CRYPTO_INTERFACE_AESCMAC_init((ubyte *) ctx->ki, (sbyte4) ctx->ki_len, ctx->ctx_cmac_init);
        if (OK != status)
        {
            (void) DIGI_FREE((void **) &ctx->ctx_cmac_init);
            return 0;
        }
    }

    return 1;
}

static int digiprov_kbkdf_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    MSTATUS status = OK;
    DP_NKDF_CTX *ctx = (DP_NKDF_CTX *)vctx;
    const OSSL_PARAM *p;
    int temp = 0;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_MAC);
    if (NULL != p)
    {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;

        if (0 == DIGI_STRCMP((const sbyte *) p->data, (const sbyte *) "HMAC"))
        {
            ctx->pPRF = (PRF_NIST_108 *) &NIST_PRF_Hmac;
        }
        else if (0 == DIGI_STRCMP((const sbyte *) p->data, (const sbyte *) "CMAC"))
        {
            ctx->pPRF = (PRF_NIST_108 *) &NIST_PRF_AesCmac;
        }
        else
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MAC);
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_DIGEST);
    if (NULL != p)
    {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;

        status = digiprov_get_digest_data((const char *) p->data, &ctx->pBHAlgo, NULL, NULL);
        if (OK != status)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_MODE);
    if (p != NULL && OPENSSL_strncasecmp("counter", p->data, p->data_size) == 0)
    {
        ctx->mode = COUNTER;
    } 
    else if (p != NULL && OPENSSL_strncasecmp("feedback", p->data, p->data_size) == 0)
    {
        ctx->mode = FEEDBACK;
    } 
    else if (p != NULL && OPENSSL_strncasecmp("double-pipeline", p->data, p->data_size) == 0)
    {
        ctx->mode = PIPELINE;
    } 
    else if (p != NULL) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_MODE);
        return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KEY);
    if (p != NULL && !digiprov_kbkdf_set_buffer(&ctx->ki, &ctx->ki_len, p))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SALT);
    if (p != NULL && !digiprov_kbkdf_set_buffer(&ctx->label, &ctx->label_len, p))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_INFO);
    if (p != NULL && !digiprov_kbkdf_set_buffer(&ctx->context, &ctx->context_len, p))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SEED);
    if (p != NULL && !digiprov_kbkdf_set_buffer(&ctx->iv, &ctx->iv_len, p))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KBKDF_USE_L);
    if (p != NULL)
    {  
        if(!OSSL_PARAM_get_int(p, &temp) || 0 == temp) /* NO SUPPORT FOR USE_L = FALSE */
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR);
    if (p != NULL)
    {   
        if(!OSSL_PARAM_get_int(p, &temp) || 0 == temp) /* NO SUPPORT FOR USE_SEP = FALSE */
            return 0;
    }

    /* Set up mac context, if we can */
    if (ctx->ki_len != 0 && ((uintptr) &NIST_PRF_AesCmac == (uintptr) ctx->pPRF || 
                            ((uintptr) &NIST_PRF_Hmac == (uintptr) ctx->pPRF && NULL != ctx->pBHAlgo)))
    {
        if (!digiprov_kbkdf_mac_init(ctx))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM *digiprov_kbkdf_settable_ctx_params(ossl_unused void *ctx,
                                                            ossl_unused void *provctx)
{
    static const OSSL_PARAM digiprov_known_settable_ctx_params[] = 
    {
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_INFO, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SALT, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_SEED, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MAC, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_MODE, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_int(OSSL_KDF_PARAM_KBKDF_USE_L, NULL),
        OSSL_PARAM_int(OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR, NULL),
        OSSL_PARAM_END,
    };
    return digiprov_known_settable_ctx_params;
}

static int digiprov_kbkdf_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE);
    if (p == NULL)
        return -2;

    /* KBKDF can produce results as large as you like. */
    return OSSL_PARAM_set_size_t(p, SIZE_MAX);
}

static const OSSL_PARAM *digiprov_kbkdf_gettable_ctx_params(ossl_unused void *ctx,
                                                            ossl_unused void *provctx)
{
    static const OSSL_PARAM digiprov_known_gettable_ctx_params[] =
        { OSSL_PARAM_size_t(OSSL_KDF_PARAM_SIZE, NULL), OSSL_PARAM_END };
    return digiprov_known_gettable_ctx_params;
}

const OSSL_DISPATCH digiprov_nist_kdf_functions[] = 
{
    { OSSL_FUNC_KDF_NEWCTX,              (void(*)(void)) digiprov_kbkdf_new },
    { OSSL_FUNC_KDF_FREECTX,             (void(*)(void)) digiprov_kbkdf_free },
    { OSSL_FUNC_KDF_RESET,               (void(*)(void)) digiprov_kbkdf_reset },
    { OSSL_FUNC_KDF_DERIVE,              (void(*)(void)) digiprov_kbkdf_derive },
    { OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS, (void(*)(void)) digiprov_kbkdf_settable_ctx_params },
    { OSSL_FUNC_KDF_SET_CTX_PARAMS,      (void(*)(void)) digiprov_kbkdf_set_ctx_params },
    { OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, (void(*)(void)) digiprov_kbkdf_gettable_ctx_params },
    { OSSL_FUNC_KDF_GET_CTX_PARAMS,      (void(*)(void)) digiprov_kbkdf_get_ctx_params },
    { 0, NULL },
};
