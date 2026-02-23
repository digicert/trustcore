/*
 * digi_cipher_chacha20.c
 *
 * Provider for OSSL 3.0 Adapted from OpenSSL provider code.
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
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for chacha20 cipher */

#include "../../../src/common/moptions.h"
#include "../../../src/common/mtypes.h"
#include "../../../src/common/mdefs.h"
#include "../../../src/common/merrors.h"
#include "../../../src/common/mstdlib.h"
#include "../../../src/crypto/hw_accel.h"

#include "mocana_glue.h"
#include "digicert_common.h"

#ifdef ASN1_ITEM
#undef ASN1_ITEM
#endif

#ifdef AES_BLOCK_SIZE
#undef AES_BLOCK_SIZE
#endif

#include "openssl/proverr.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "digi_ciphercommon.h"
#include "crypto/chacha.h"

#include "digiprov.h"

#define CHACHA20_KEYLEN (CHACHA_KEY_SIZE)
#define CHACHA20_BLKLEN (1)
#define CHACHA20_IVLEN (CHACHA_CTR_SIZE)
#define CHACHA20_FLAGS (PROV_CIPHER_FLAG_CUSTOM_IV)

static int digiprov_chacha20_initctx(DP_CIPHER_CTX *ctx)
{
    digiprov_cipher_generic_initkey(ctx, CHACHA20_KEYLEN * 8, CHACHA20_BLKLEN * 8, CHACHA20_IVLEN * 8, 0,
                                    CHACHA20_FLAGS, NULL, NULL);

    if(!digiprov_cipher_newevp(&ctx->pEvpCtx))
        return 0;   

    ctx->pEvpCtx->key_len = CHACHA20_KEYLEN;
    ctx->pEvpCtx->iv_len = CHACHA20_IVLEN;
    ctx->need_iv = 1;
    ctx->need_dir = 0;

    if (NULL != ctx->pEvpCtx->cipher)
    {
        EVP_CIPHER *pCipher = (EVP_CIPHER *) ctx->pEvpCtx->cipher;
        if (NULL != pCipher)
        {
            pCipher->nid = NID_chacha20;
            return 1;
        }
    }

    /* else error case */
    digiprov_cipher_freeevp(&ctx->pEvpCtx);
    return 0;
}

static void *digiprov_chacha20_newctx(void *provctx)
{
    MSTATUS status = OK;
    DP_CIPHER_CTX *ctx = NULL;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **) &ctx, 1, sizeof(DP_CIPHER_CTX));
    if (OK != status)
        return NULL;

    digiprov_chacha20_initctx(ctx);
    return ctx;
}

static void digiprov_chacha20_freectx(void *vctx)
{
    DP_CIPHER_CTX *ctx = (DP_CIPHER_CTX *)vctx;

    if (ctx != NULL) 
    {
        digiprov_cipher_generic_reset_ctx(ctx);
        digiprov_cipher_freeevp(&ctx->pEvpCtx);
        (void) DIGI_MEMSET_FREE((ubyte **) &vctx, sizeof(DP_CIPHER_CTX));
    }
}

static int digiprov_chacha20_get_params(OSSL_PARAM params[])
{
    return digiprov_cipher_generic_get_params(params, 0, CHACHA20_FLAGS,
                                              CHACHA20_KEYLEN * 8,
                                              CHACHA20_BLKLEN * 8,
                                              CHACHA20_IVLEN * 8);
}

static int digiprov_chacha20_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, CHACHA20_IVLEN)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, CHACHA20_KEYLEN)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    return 1;
}

static const OSSL_PARAM digiprov_chacha20_known_gettable_ctx_params[] =
{
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_chacha20_gettable_ctx_params(ossl_unused void *cctx,
                                                        ossl_unused void *provctx)
{
    return digiprov_chacha20_known_gettable_ctx_params;
}

static int digiprov_chacha20_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    size_t len;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (len != CHACHA20_KEYLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (len != CHACHA20_IVLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
    }
    return 1;
}

static const OSSL_PARAM digiprov_chacha20_known_settable_ctx_params[] =
{
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_chacha20_settable_ctx_params(ossl_unused void *cctx,
                                                        ossl_unused void *provctx)
{
    return digiprov_chacha20_known_settable_ctx_params;
}

static int digiprov_chacha20_einit(void *vctx, const unsigned char *key, size_t keylen,
                                   const unsigned char *iv, size_t ivlen,
                                   const OSSL_PARAM params[])
{
    int ret;

    /* The generic function checks for digiprov_is_running() */
    ret = digiprov_cipher_generic_einit(vctx, key, keylen, iv, ivlen, NULL);

    if (ret && !digiprov_chacha20_set_ctx_params(vctx, params))
        ret = 0;
    return ret;
}

static int digiprov_chacha20_dinit(void *vctx, const unsigned char *key, size_t keylen,
                                   const unsigned char *iv, size_t ivlen,
                                   const OSSL_PARAM params[])
{
    int ret;

    /* The generic function checks for digiprov_is_running() */
    ret = digiprov_cipher_generic_dinit(vctx, key, keylen, iv, ivlen, NULL);

    if (ret && !digiprov_chacha20_set_ctx_params(vctx, params))
        ret = 0;
    return ret;
}

/* digiprov_chacha20_functions */
const OSSL_DISPATCH digiprov_chacha20_functions[] =
{
    { OSSL_FUNC_CIPHER_NEWCTX,              (void (*)(void))digiprov_chacha20_newctx },
    { OSSL_FUNC_CIPHER_FREECTX,             (void (*)(void))digiprov_chacha20_freectx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT,        (void (*)(void))digiprov_chacha20_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT,        (void (*)(void))digiprov_chacha20_dinit },
    { OSSL_FUNC_CIPHER_UPDATE,              (void (*)(void))digiprov_cipher_generic_stream_update },
    { OSSL_FUNC_CIPHER_FINAL,               (void (*)(void))digiprov_cipher_generic_stream_final },
    { OSSL_FUNC_CIPHER_CIPHER,              (void (*)(void))digiprov_cipher_generic_cipher},
    { OSSL_FUNC_CIPHER_GET_PARAMS,          (void (*)(void))digiprov_chacha20_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,     (void (*)(void))digiprov_cipher_generic_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,      (void (*)(void))digiprov_chacha20_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))digiprov_chacha20_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,      (void (*)(void))digiprov_chacha20_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))digiprov_chacha20_settable_ctx_params },
    { 0, NULL }
};
