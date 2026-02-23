/*
 * digi_cipher_aes_gcm.c
 *
 * AES-GCM implementations for OSSL 3.0 provider ADAPTED FROM openssl code
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

/*
 * AES low level APIs are deprecated for public use, but still ok for internal
 * use where we're using them to implement the higher level EVP interface, as is
 * the case here.
 */
/* Dispatch functions for AES GCM mode */

#include "../../../src/common/moptions.h"
#include "../../../src/common/mtypes.h"
#include "../../../src/common/mdefs.h"
#include "../../../src/common/merrors.h"

#include "mocana_glue.h"
#include "digicert_common.h"

#ifdef ASN1_ITEM
#undef ASN1_ITEM
#endif

#ifdef AES_BLOCK_SIZE
#undef AES_BLOCK_SIZE
#endif

#include "internal/deprecated.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "digi_ciphercommon.h"
#include "digiprov.h"
#include "openssl/proverr.h"
#include "openssl/evp.h"
#include "prov/provider_ctx.h"

int DIGI_EVP_AES_GCM_cipherInit(EVP_CIPHER_CTX *pCtx, const unsigned char *pKey, const unsigned char *pIv,
                               int isEncrypt);
int DIGI_EVP_AES_GCM_doCipher(EVP_CIPHER_CTX *pCtx, unsigned char *pOut, const unsigned char *pIn,
                             size_t inLen);
int DIGI_EVP_AES_GCM_cipherCtxCtrl(EVP_CIPHER_CTX *pCtx, int type, int arg, void *pPtr);
int DIGI_EVP_AES_GCM_cipherCleanup(EVP_CIPHER_CTX *pCtx);

static int digiprov_gcm_set_ctx_params(void *vctx, const OSSL_PARAM params[]);

/*
 * Called from EVP_CipherInit when there is currently no context via
 * the new_ctx() function
 */
static void digiprov_gcm_initctx(void *provctx, DP_GCM_CTX *ctx, size_t keybits, const void *hw)
{
    ctx->pad = 1;
    ctx->mode = EVP_CIPH_GCM_MODE;
    ctx->taglen = UNINITIALISED_SIZET;
    ctx->tls_aad_len = UNINITIALISED_SIZET;
    ctx->ivlen = (EVP_GCM_TLS_FIXED_IV_LEN + EVP_GCM_TLS_EXPLICIT_IV_LEN);
    ctx->keylen = keybits / 8;
    ctx->libctx = PROV_LIBCTX_OF(provctx);
    ctx->key_set = 0;
    ctx->iv_state = 0;
    ctx->dir_set = 0;
    ctx->ctx_init = 0;
}

/*
 * Called by EVP_CipherInit via the _einit and _dinit functions
 */
static int digiprov_gcm_init(void *vctx, const unsigned char *key, size_t keylen,
                             const unsigned char *iv, size_t ivlen,
                             const OSSL_PARAM params[], int enc)
{
    DP_GCM_CTX *ctx = (DP_GCM_CTX *)vctx;

    if (!digiprov_is_running())
        return 0;

    ctx->enc = enc;
    ctx->pEvpCtx->encrypt = enc;

    if (iv != NULL) 
    {
        if (ivlen == 0 || ivlen > sizeof(ctx->iv)) 
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        ctx->ivlen = ivlen;
        (void) DIGI_MEMCPY(ctx->iv, iv, ivlen);
        ctx->iv_state = IV_STATE_BUFFERED;
    }

    if (key != NULL) 
    {
        if (keylen != ctx->keylen) 
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }

        (void) DIGI_MEMCPY(ctx->key, key, keylen);
        ctx->key_set = 1;
    }

    if (enc > -1) /* if enc = -1 direction may already be set, we don't change ctx->dir_set */
    {
        ctx->dir_set = 1;
    }

    if (!ctx->ctx_init && (IV_STATE_BUFFERED == ctx->iv_state || ctx->iv_gen) && ctx->key_set && ctx->dir_set)
    {
        /* set the iv len again*/
        if (IV_STATE_BUFFERED == ctx->iv_state)
        {
            if (!DIGI_EVP_AES_GCM_cipherCtxCtrl(ctx->pEvpCtx, EVP_CTRL_GCM_SET_IVLEN, ctx->ivlen, NULL))
                return 0;
        }

        if(!DIGI_EVP_AES_GCM_cipherInit(ctx->pEvpCtx, ctx->key, ctx->iv, ctx->enc))
            return 0;

        /* remove copy of cached key right away */
        (void) DIGI_MEMSET(ctx->key, 0x00, ctx->keylen);
        ctx->tls_enc_records = 0;
        ctx->ctx_init = 1;
    }

    return digiprov_gcm_set_ctx_params(ctx, params);
}

static int digiprov_gcm_einit(void *vctx, const unsigned char *key, size_t keylen,
                              const unsigned char *iv, size_t ivlen,
                              const OSSL_PARAM params[])
{
    return digiprov_gcm_init(vctx, key, keylen, iv, ivlen, params, 1);
}

static int digiprov_gcm_dinit(void *vctx, const unsigned char *key, size_t keylen,
                              const unsigned char *iv, size_t ivlen,
                              const OSSL_PARAM params[])
{
    return digiprov_gcm_init(vctx, key, keylen, iv, ivlen, params, 0);
}

static int digiprov_gcm_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    DP_GCM_CTX *ctx = (DP_GCM_CTX *)vctx;
    OSSL_PARAM *p;
    size_t sz;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->ivlen)) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen)) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL) 
    {
        size_t taglen = (ctx->taglen != UNINITIALISED_SIZET) ? ctx->taglen :
                         GCM_TAG_MAX_SIZE;

        if (!OSSL_PARAM_set_size_t(p, taglen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_SUPPORTED);
        return 0;
#if 0
        if (ctx->iv_state == IV_STATE_UNINITIALISED)
            return 0;
        if (ctx->ivlen > p->data_size) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        if (!OSSL_PARAM_set_octet_string(p, ctx->iv, ctx->ivlen)
            && !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivlen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
#endif
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL)
    {
        /* This code is here to pass the evp unit tests. All test vectors
         * check if the updated iv is the same as the original. So even
         * though this isnt really the updated IV it passes tests, and is
         * also consistent with the openssl gcm implementation */
        if (ctx->iv_state == IV_STATE_UNINITIALISED)
            return 0;
        if (ctx->ivlen > p->data_size) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        if (!OSSL_PARAM_set_octet_string(p, ctx->iv, ctx->ivlen)
            && !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivlen)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
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
        sz = p->data_size;
        if (sz == 0 || sz > EVP_GCM_TLS_TAG_LEN || !ctx->enc || ctx->taglen == UNINITIALISED_SIZET)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG);
            return 0;
        }

        if (!DIGI_EVP_AES_GCM_cipherCtxCtrl(ctx->pEvpCtx, EVP_CTRL_GCM_GET_TAG,
                                           (int) p->data_size, p->data))
            return 0;
    }
    
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN);
    if (p != NULL)
    {
        if (p->data == NULL || p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;

        if (!DIGI_EVP_AES_GCM_cipherCtxCtrl(ctx->pEvpCtx, EVP_CTRL_GCM_IV_GEN, (int) p->data_size, p->data))
            return 0;
        
        ctx->iv_state = IV_STATE_BUFFERED;
        ctx->iv_gen_rand = 1;
    }

    return 1;
}

static int digiprov_gcm_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    DP_GCM_CTX *ctx = (DP_GCM_CTX *)vctx;
    const OSSL_PARAM *p;
    size_t sz = 0;
    void *vp;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL)
    {
        vp = ctx->buf;
        if (!digiprov_get_octet_string(p, &vp, EVP_GCM_TLS_TAG_LEN, &sz))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (sz == 0 || ctx->enc)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_TAG);
            return 0;
        }
        ctx->taglen = sz;

        if (!DIGI_EVP_AES_GCM_cipherCtxCtrl(ctx->pEvpCtx, EVP_CTRL_GCM_SET_TAG, (int) sz, vp))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_IVLEN);
    if (p != NULL)
    {
        if (!OSSL_PARAM_get_size_t(p, &sz)) 
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (sz == 0 || sz > sizeof(ctx->iv))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        ctx->ivlen = sz;

        if (!DIGI_EVP_AES_GCM_cipherCtxCtrl(ctx->pEvpCtx, EVP_CTRL_GCM_SET_IVLEN, (int) sz, NULL))
            return 0;
    }
 
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
    if (p != NULL)
    {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }

        if (!digiprov_is_running() || EVP_AEAD_TLS1_AAD_LEN != p->data_size)
            return 0;
        
        if (!DIGI_EVP_AES_GCM_cipherCtxCtrl(ctx->pEvpCtx, EVP_CTRL_AEAD_TLS1_AAD, (int) p->data_size, p->data))
            return 0;

        ctx->tls_aad_pad_sz = EVP_GCM_TLS_TAG_LEN;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED);
    if (p != NULL)
    {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
 
        if (!DIGI_EVP_AES_GCM_cipherCtxCtrl(ctx->pEvpCtx, EVP_CTRL_GCM_SET_IV_FIXED, (int) p->data_size, p->data))
            return 0;

        ctx->iv_gen = 1;
        ctx->iv_state = IV_STATE_BUFFERED;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV);
    if (p != NULL)
    {
        if (p->data == NULL || p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;

        if (!DIGI_EVP_AES_GCM_cipherCtxCtrl(ctx->pEvpCtx, EVP_CTRL_GCM_SET_IV_INV, (int) p->data_size, p->data))
            return 0;

        ctx->iv_state = IV_STATE_BUFFERED;
    }

    return 1;
}

static int digiprov_gcm_stream_update(void *vctx, unsigned char *out, size_t *outl,
                                      size_t outsize, const unsigned char *in, size_t inl)
{
    int ret = 0;
    DP_GCM_CTX *ctx = (DP_GCM_CTX *)vctx;

    if (inl == 0) 
    {
        *outl = 0;
        return 1;
    }

    if (outsize < inl)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (!ctx->ctx_init || ctx->iv_state == IV_STATE_FINISHED)
        return 0;

    if (ctx->iv_state == IV_STATE_UNINITIALISED) 
    {
        if (!ctx->enc)
            return 0;

        if (!DIGI_EVP_AES_GCM_cipherCtxCtrl(ctx->pEvpCtx, EVP_CTRL_GCM_IV_GEN, 0, NULL))
            return 0;

        ctx->iv_state = IV_STATE_BUFFERED;
        ctx->iv_gen_rand = 1;
    }

    /* The tag must be set before actually decrypting data */
    if (NULL != out && !ctx->enc && ctx->taglen == UNINITIALISED_SIZET)
        return 0;

    ret = DIGI_EVP_AES_GCM_doCipher(ctx->pEvpCtx, out, in, inl);
    if (ret < 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    *outl = (size_t) ret;

    return 1;
}

static int digiprov_gcm_stream_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize)
{
    DP_GCM_CTX *ctx = (DP_GCM_CTX *)vctx;
    int ret = 0;

    if (!digiprov_is_running())
        return 0;

    /* The tag must be set before actually decrypting data */
    if (!ctx->enc && ctx->taglen == UNINITIALISED_SIZET)
        return 0;

    ret = DIGI_EVP_AES_GCM_doCipher(ctx->pEvpCtx, out, NULL, 0);
    if (ret < 0)
        return 0;

    if (ctx->enc) ctx->taglen = GCM_TAG_MAX_SIZE;
    ctx->iv_state = IV_STATE_FINISHED; /* Don't reuse the IV */

    *outl = 0;
    return 1;
}

static int digiprov_gcm_cipher(void *vctx, unsigned char *out, size_t *outl, size_t outsize,
                               const unsigned char *in, size_t inl)
{
    DP_GCM_CTX *ctx = (DP_GCM_CTX *)vctx;
    int ret = 0;

    if (!digiprov_is_running())
        return 0;

    if (NULL != out && outsize < inl) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if ((NULL != out) && (!ctx->ctx_init || ctx->iv_state == IV_STATE_FINISHED))
        return 0;

    if (ctx->iv_state == IV_STATE_UNINITIALISED) 
    {
        if (!ctx->enc)
            return 0;

        if (!DIGI_EVP_AES_GCM_cipherCtxCtrl(ctx->pEvpCtx, EVP_CTRL_GCM_IV_GEN, 0, NULL))
            return 0;

        ctx->iv_state = IV_STATE_BUFFERED;
        ctx->iv_gen_rand = 1;
    }

    /* The tag must be set before actually decrypting data */
    if (NULL == in && NULL != out && !ctx->enc && ctx->taglen == UNINITIALISED_SIZET)
        return 0;

    ret = DIGI_EVP_AES_GCM_doCipher(ctx->pEvpCtx, out, in, inl);
    if (ret < 0)
        return 0;

    /* It might just be AAD data input so far, don't change the state */
    if (NULL != out)
    {
        if (ctx->enc) ctx->taglen = GCM_TAG_MAX_SIZE;
    }

    if (NULL == in)
    {
        ctx->iv_state = IV_STATE_FINISHED; /* Don't reuse the IV */
    }

    *outl = (size_t) ret;
    return 1;
}

static void digiprov_gcm_freeevp(EVP_CIPHER_CTX **ppCtx)
{
    if(NULL != ppCtx && NULL != *ppCtx)
    {
        EVP_CIPHER_CTX *pCtx = *ppCtx;

        (void) DIGI_EVP_AES_GCM_cipherCleanup(pCtx);
        if (NULL != pCtx->cipher)
        {
            (void) DIGI_MEMSET_FREE((ubyte **)&pCtx->cipher, sizeof(EVP_CIPHER));
        }
        if (NULL != pCtx->cipher_data)
        {
            (void) DIGI_MEMSET_FREE((ubyte **)&pCtx->cipher_data, sizeof(MOC_EVP_CIPHER_CTX));
        }

        (void) DIGI_MEMSET_FREE((ubyte **)ppCtx, sizeof(EVP_CIPHER_CTX));
    }
}

static void digiprov_aes_gcm_freectx(void *vctx)
{
    DP_GCM_CTX *pShell = (DP_GCM_CTX *) vctx;

    if (NULL != pShell)
    {
        digiprov_gcm_freeevp(&pShell->pEvpCtx);
    }
    (void) DIGI_MEMSET_FREE((ubyte **) &vctx, sizeof(DP_GCM_CTX));
}

static int digiprov_gcm_set_mode(EVP_CIPHER_CTX *pCtx, size_t kbits, size_t ivbits)
{
    EVP_CIPHER *pCipher = NULL;
    
    if (NULL == pCtx)
        return 0;

    pCtx->iv_len = (int) ivbits/8;

    pCipher = (EVP_CIPHER *) pCtx->cipher;
    if (NULL == pCipher)
        return 0;

    pCipher->iv_len = pCtx->iv_len;
    switch(kbits)
    {
        case 128:
            pCtx->key_len = MOC_AES_128_KEY_LEN;
            pCipher->nid = NID_aes_128_gcm;
            break;
        case 192:
            pCtx->key_len = MOC_AES_192_KEY_LEN;
            pCipher->nid = NID_aes_192_gcm;
            break;
        case 256:
            pCtx->key_len = MOC_AES_256_KEY_LEN;
            pCipher->nid = NID_aes_256_gcm;
            break;   
        default:
            return 0;         
    }

    return DIGI_EVP_AES_GCM_cipherCtxCtrl(pCtx, EVP_CTRL_INIT, 0, NULL);
}

static void *digiprov_aes_gcm_newctx(void *provctx, size_t keybits, size_t ivbits)
{
    MSTATUS status = OK;
    DP_GCM_CTX *ctx = NULL;

    if (!digiprov_is_running())
        return NULL;
    
    status = DIGI_CALLOC((void **) &ctx, 1, sizeof(*ctx));
    if (OK != status)
        return NULL;
    
    digiprov_gcm_initctx(provctx, ctx, keybits, NULL);

    if (!digiprov_cipher_newevp(&ctx->pEvpCtx))
    {
        digiprov_aes_gcm_freectx(ctx);
        return NULL;
    }

    if (!digiprov_gcm_set_mode(ctx->pEvpCtx, keybits, ivbits))
    {
        digiprov_aes_gcm_freectx(ctx); ctx = NULL;
    }

    return ctx;
}

/* digiprov_aes128gcm_functions */
IMPLEMENT_aead_cipher(aes, gcm, GCM, AEAD_FLAGS, 128, 8, 96);
/* digiprov_aes192gcm_functions */
IMPLEMENT_aead_cipher(aes, gcm, GCM, AEAD_FLAGS, 192, 8, 96);
/* digiprov_aes256gcm_functions */
IMPLEMENT_aead_cipher(aes, gcm, GCM, AEAD_FLAGS, 256, 8, 96);
