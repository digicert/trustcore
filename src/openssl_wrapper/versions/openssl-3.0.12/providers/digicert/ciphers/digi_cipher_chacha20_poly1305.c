/*
 * digi_cipher_chacha20_poly1305.c
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

/* Dispatch functions for chacha20_poly1305 cipher */

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

#define CHACHA20_POLY1305_KEYLEN CHACHA_KEY_SIZE
#define CHACHA20_POLY1305_BLKLEN 1
#define CHACHA20_POLY1305_MAX_IVLEN 12
#define CHACHA20_POLY1305_MODE 0
#define CHACHA20_POLY1305_FLAGS (PROV_CIPHER_FLAG_AEAD | PROV_CIPHER_FLAG_CUSTOM_IV)

int DIGI_EVP_CHACHAPOLY_cipherInit(EVP_CIPHER_CTX *pCtx, const unsigned char *pKey,
                                  const unsigned char *pIv, int isEncrypt);
int DIGI_EVP_CHACHAPOLY_doCipher(EVP_CIPHER_CTX *pCtx, unsigned char *pOut, const unsigned char *pIn, size_t inlen);
int DIGI_EVP_CHACHAPOLY_ctrl(EVP_CIPHER_CTX *pCtx, int type, int arg, void *pPtr);
int DIGI_EVP_CHACHAPOLY_cipherCleanup(EVP_CIPHER_CTX *pCtx);

static void *digiprov_chacha20_poly1305_newctx(void *provctx)
{
    MSTATUS status = OK;
    DP_CHACHAPOLY_CTX *ctx = NULL;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **) &ctx, 1, sizeof(DP_CHACHAPOLY_CTX));
    if (OK != status)
        return NULL;

    if (!digiprov_cipher_newevp(&ctx->pEvpCtx))
    {
        (void) DIGI_FREE((void **) &ctx);
        return NULL;
    }

    if (NULL != ctx->pEvpCtx->cipher)
    {
        EVP_CIPHER *pCipher = (EVP_CIPHER *) ctx->pEvpCtx->cipher;
        if (NULL != pCipher)
        {
            pCipher->nid = NID_chacha20_poly1305;
        }
    }

    ctx->pEvpCtx->iv_len = CHACHA20_POLY1305_IVLEN;
    ctx->pEvpCtx->key_len = CHACHA20_POLY1305_KEYLEN;
    ctx->nonce_len = CHACHA20_POLY1305_IVLEN;
    ctx->tls_payload_length = NO_TLS_PAYLOAD_LENGTH;
    ctx->key_set = 0;
    ctx->iv_set = 0;
    ctx->ctx_init = 0;
    
    return (void *) ctx;
}

static void digiprov_chacha20_poly1305_freectx(void *vctx)
{
    DP_CHACHAPOLY_CTX *ctx = (DP_CHACHAPOLY_CTX *)vctx;

    if (ctx != NULL) 
    {
        if (NULL != ctx->pEvpCtx)
        {
            (void) DIGI_EVP_CHACHAPOLY_cipherCleanup(ctx->pEvpCtx);
            (void) digiprov_cipher_freeevp(&ctx->pEvpCtx);
        }
        
        (void) DIGI_MEMSET_FREE((ubyte **) &ctx, sizeof(*ctx));
    }
}

static int digiprov_chacha20_poly1305_get_params(OSSL_PARAM params[])
{
    return digiprov_cipher_generic_get_params(params, 0, CHACHA20_POLY1305_FLAGS,
                                              CHACHA20_POLY1305_KEYLEN * 8,
                                              CHACHA20_POLY1305_BLKLEN * 8,
                                              CHACHA20_POLY1305_IVLEN * 8);
}

static int digiprov_chacha20_poly1305_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    DP_CHACHAPOLY_CTX *ctx = (DP_CHACHAPOLY_CTX *)vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) 
    {
        if (!OSSL_PARAM_set_size_t(p, ctx->nonce_len))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, CHACHA20_POLY1305_KEYLEN))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->tag_len))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->tls_aad_pad_sz)) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL)
    {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
        if (!ctx->enc) 
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_SET);
            return 0;
        }
        if (p->data_size == 0 || p->data_size > POLY1305_BLOCK_SIZE) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG_LENGTH);
            return 0;
        }

        if(!DIGI_EVP_CHACHAPOLY_ctrl(ctx->pEvpCtx, EVP_CTRL_AEAD_GET_TAG, (int) p->data_size, p->data))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM digiprov_chacha20_poly1305_known_gettable_ctx_params[] =
{
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *digiprov_chacha20_poly1305_gettable_ctx_params
    (ossl_unused void *cctx, ossl_unused void *provctx)
{
    return digiprov_chacha20_poly1305_known_gettable_ctx_params;
}

static int digiprov_chacha20_poly1305_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    size_t len;
    DP_CHACHAPOLY_CTX *ctx = (DP_CHACHAPOLY_CTX *)vctx;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) 
    {
        if (!OSSL_PARAM_get_size_t(p, &len))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (len != CHACHA20_POLY1305_KEYLEN)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL) 
    {
        if (!OSSL_PARAM_get_size_t(p, &len)) 
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (len == 0 || len != CHACHA20_POLY1305_MAX_IVLEN) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        ctx->nonce_len = len;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL) 
    {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (p->data_size == 0 || p->data_size > POLY1305_BLOCK_SIZE) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG_LENGTH);
            return 0;
        }
        if (p->data != NULL) 
        {
            if (ctx->enc)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_NEEDED);
                return 0;
            }

            if(!DIGI_EVP_CHACHAPOLY_ctrl(ctx->pEvpCtx, EVP_CTRL_AEAD_SET_TAG, (int) p->data_size, p->data))
                return 0;
        }
        ctx->tag_len = p->data_size;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
    if (p != NULL) 
    {
        return 0; /* not supported 
        if (p->data_type != OSSL_PARAM_OCTET_STRING) 
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        len = hw->tls_init(&ctx->base, p->data, p->data_size);
        if (len == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
            return 0;
        }
        ctx->tls_aad_pad_sz = len; */
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED);
    if (p != NULL) 
    {
        return 0; /* not supported 
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (hw->tls_iv_set_fixed(&ctx->base, p->data, p->data_size) == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        } */
    }

    return 1;
}

static int digiprov_chacha20_pol1305_init(void *vctx, const unsigned char *key,
                                          size_t keylen, const unsigned char *iv,
                                          size_t ivlen, const OSSL_PARAM params[], 
                                          unsigned int enc)
{
    DP_CHACHAPOLY_CTX *ctx = (DP_CHACHAPOLY_CTX *) vctx;
 
    if (!digiprov_is_running())
        return 0;

    if (NULL != iv)
    {
        (void) DIGI_MEMCPY(ctx->iv, iv, ivlen);
        ctx->iv_set = 1;
    }

    if (NULL != key)
    {
        (void) DIGI_MEMCPY(ctx->key, key, keylen);
        ctx->key_set = 1;    
    }

    ctx->enc = enc;
    
    if (!ctx->ctx_init && ctx->key_set && ctx->iv_set)
    {
        if (!DIGI_EVP_CHACHAPOLY_cipherInit(ctx->pEvpCtx, ctx->key, ctx->iv, ctx->enc))
            return 0;
        
        /* remove copy of cached key right away */
        (void) DIGI_MEMSET(ctx->key, 0x00, MAX_CIPHER_KEY_SIZE/2); /* 32 */
        ctx->ctx_init = 1;
    }

    if (!digiprov_chacha20_poly1305_set_ctx_params(vctx, params))
        return 0;

    return 1;                 
}

static int digiprov_chacha20_poly1305_einit(void *vctx, const unsigned char *key,
                                            size_t keylen, const unsigned char *iv,
                                            size_t ivlen, const OSSL_PARAM params[])
{
    return digiprov_chacha20_pol1305_init(vctx, key, keylen, iv, ivlen, params, 1);
}

static int digiprov_chacha20_poly1305_dinit(void *vctx, const unsigned char *key,
                                            size_t keylen, const unsigned char *iv,
                                            size_t ivlen, const OSSL_PARAM params[])
{
    return digiprov_chacha20_pol1305_init(vctx, key, keylen, iv, ivlen, params, 0);
}

static int digiprov_chacha20_poly1305_cipher(void *vctx, unsigned char *out,
                                             size_t *outl, size_t outsize,
                                             const unsigned char *in, size_t inl)
{
    DP_CHACHAPOLY_CTX *ctx = (DP_CHACHAPOLY_CTX *) vctx;
    int ret = 0;

    if (!digiprov_is_running())
        return 0;

    if (inl == 0) 
    {
        *outl = 0;
        return 1;
    }

    if (NULL != out && outsize < inl) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    ret = DIGI_EVP_CHACHAPOLY_doCipher(ctx->pEvpCtx, out, in, inl);
    if (ret < 0)
    {
        return 0;
    }
    else
    {
        *outl = (size_t) ret;
    }

    return 1;
}

static int digiprov_chacha20_poly1305_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize)
{
    DP_CHACHAPOLY_CTX *ctx = (DP_CHACHAPOLY_CTX *) vctx;
    int ret = 0;

    if (!digiprov_is_running())
        return 0;

    ret = DIGI_EVP_CHACHAPOLY_doCipher(ctx->pEvpCtx, out, NULL, 0);
    if (ret < 0)
    {
        return 0;
    }

    *outl = 0;
    return 1;
}

/* digiprov_chacha20_poly1305_functions */
const OSSL_DISPATCH digiprov_chacha20_poly1305_functions[] =
{
    { OSSL_FUNC_CIPHER_NEWCTX,              (void (*)(void))digiprov_chacha20_poly1305_newctx },
    { OSSL_FUNC_CIPHER_FREECTX,             (void (*)(void))digiprov_chacha20_poly1305_freectx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT,        (void (*)(void))digiprov_chacha20_poly1305_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT,        (void (*)(void))digiprov_chacha20_poly1305_dinit },
    { OSSL_FUNC_CIPHER_UPDATE,              (void (*)(void))digiprov_chacha20_poly1305_cipher },
    { OSSL_FUNC_CIPHER_FINAL,               (void (*)(void))digiprov_chacha20_poly1305_final },
    { OSSL_FUNC_CIPHER_CIPHER,              (void (*)(void))digiprov_chacha20_poly1305_cipher },
    { OSSL_FUNC_CIPHER_GET_PARAMS,          (void (*)(void))digiprov_chacha20_poly1305_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,     (void (*)(void))digiprov_cipher_generic_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,      (void (*)(void))digiprov_chacha20_poly1305_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))digiprov_chacha20_poly1305_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,      (void (*)(void))digiprov_chacha20_poly1305_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))digiprov_cipher_aead_settable_ctx_params },
    { 0, NULL }
};

