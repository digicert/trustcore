/*
 * digi_cipher_aes_ccm.c
 *
 * AES-CCM implementations for OSSL 3.0 provider ADAPTED FROM openssl code
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
#include "../../../src/common/moptions.h"
#include "../../../src/common/mtypes.h"
#include "../../../src/common/mdefs.h"
#include "../../../src/common/merrors.h"

#include "mocana_glue.h"

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

#include "internal/deprecated.h"

/* Dispatch functions for AES CCM mode */

int DIGI_EVP_cipherInit(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv,
                       int isEncrypt);
int DIGI_EVP_doCipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
int DIGI_EVP_cipherCtxCtrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
int DIGI_EVP_cipherGetIv(EVP_CIPHER_CTX *ctx, unsigned char *pIv, size_t ivLen, int isRc5);

#if 0
static int ccm_tls_init(DP_CCM_CTX *ctx, unsigned char *aad, size_t alen)
{
    size_t len;

    if (!digiprov_is_running() || alen != EVP_AEAD_TLS1_AAD_LEN)
        return 0;

    /* Save the aad for later use. */
    memcpy(ctx->buf, aad, alen);
    ctx->tls_aad_len = alen;

    len = ctx->buf[alen - 2] << 8 | ctx->buf[alen - 1];
    if (len < EVP_CCM_TLS_EXPLICIT_IV_LEN)
        return 0;

    /* Correct length for explicit iv. */
    len -= EVP_CCM_TLS_EXPLICIT_IV_LEN;

    if (!ctx->enc) {
        if (len < ctx->m)
            return 0;
        /* Correct length for tag. */
        len -= ctx->m;
    }
    ctx->buf[alen - 2] = (unsigned char)(len >> 8);
    ctx->buf[alen - 1] = (unsigned char)(len & 0xff);

    /* Extra padding: tag appended to record. */
    return ctx->m;
}

static int ccm_tls_iv_set_fixed(DP_CCM_CTX *ctx, unsigned char *fixed,
                                size_t flen)
{
    if (flen != EVP_CCM_TLS_FIXED_IV_LEN)
        return 0;

    /* Copy to first part of the iv. */
    (void) DIGI_MEMCPY(ctx->iv, fixed, flen);
    return 1;
}
#endif

static size_t ccm_get_ivlen(DP_CCM_CTX *ctx)
{
    return 15 - ctx->l;
}

static int digiprov_ccm_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    DP_CCM_CTX *ctx = (DP_CCM_CTX *)vctx;
    const OSSL_PARAM *p;
    size_t sz;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TAG);
    if (p != NULL)
    {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if ((p->data_size & 1) || (p->data_size < 4) || p->data_size > 16)
        {
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
            (void) DIGI_MEMCPY(ctx->buf, p->data, p->data_size);
            ctx->tag_set = 1;
        }
        ctx->m = p->data_size;

        if (!DIGI_EVP_cipherCtxCtrl(ctx->pEvpCtx, EVP_CTRL_CCM_SET_TAG, (int) p->data_size, (void *) p->data))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_IVLEN);
    if (p != NULL)
    {
        size_t ivlen;

        if (!OSSL_PARAM_get_size_t(p, &sz))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        ivlen = 15 - sz;
        if (ivlen < 2 || ivlen > 8)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        ctx->l = ivlen;

        if (!DIGI_EVP_cipherCtxCtrl(ctx->pEvpCtx, EVP_CTRL_CCM_SET_IVLEN, (int) sz, NULL))
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD);
    if (p != NULL)
    {
        return 0; /* not supported */
/*      if (p->data_type != OSSL_PARAM_OCTET_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        sz = ccm_tls_init(ctx, p->data, p->data_size);
        if (sz == 0)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
            return 0;
        }
        ctx->tls_aad_pad_sz = sz;
*/
    }

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED);
    if (p != NULL)
    {
        return 0; /* not supported */

/*      if (p->data_type != OSSL_PARAM_OCTET_STRING) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        if (ccm_tls_iv_set_fixed(ctx, p->data, p->data_size) == 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
*/
    }

    return 1;
}

static int digiprov_ccm_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    DP_CCM_CTX *ctx = (DP_CCM_CTX *)vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ccm_get_ivlen(ctx)))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD_TAGLEN);
    if (p != NULL)
    {
        size_t m = ctx->m;

        if (!OSSL_PARAM_set_size_t(p, m))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL)
    {
        if (ccm_get_ivlen(ctx) > p->data_size)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        if (!OSSL_PARAM_set_octet_string(p, ctx->iv, p->data_size)
            && !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, p->data_size)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL)
    {
        if (ccm_get_ivlen(ctx) > p->data_size)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        if (!OSSL_PARAM_set_octet_string(p, ctx->iv, p->data_size)
            && !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, p->data_size))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen))
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
        if (!ctx->enc || !ctx->tag_set)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_TAG_NOT_SET);
            return 0;
        }
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;
        }

        if (!DIGI_EVP_cipherCtxCtrl(ctx->pEvpCtx, EVP_CTRL_CCM_GET_TAG, (int) p->data_size, (void *) p->data))
            return 0;

        ctx->tag_set = 0;
        ctx->iv_set = 0;
        ctx->len_set = 0;
    }
    return 1;
}

static int digiprov_ccm_init(void *vctx, const unsigned char *key, size_t keylen,
                             const unsigned char *iv, size_t ivlen,
                             const OSSL_PARAM params[], int enc)
{
    DP_CCM_CTX *ctx = (DP_CCM_CTX *)vctx;

    if (!digiprov_is_running())
        return 0;

    ctx->enc = enc;
    ctx->pEvpCtx->encrypt = enc;

    if (iv != NULL)
    {
        if (ivlen != ccm_get_ivlen(ctx))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }
        (void) DIGI_MEMCPY(ctx->iv, iv, ivlen);
        ctx->iv_set = 1;
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

    if (!ctx->ctx_init && ctx->iv_set && ctx->key_set && ctx->dir_set)
    {
        /* set the iv len and tag len again*/
        if (!DIGI_EVP_cipherCtxCtrl(ctx->pEvpCtx, EVP_CTRL_CCM_SET_IVLEN, (int) ccm_get_ivlen(ctx), NULL))
            return 0;

        if (!DIGI_EVP_cipherCtxCtrl(ctx->pEvpCtx, EVP_CTRL_CCM_SET_TAG, (int) ctx->m, NULL))
            return 0;

        if (!DIGI_EVP_cipherInit(ctx->pEvpCtx, ctx->key, ctx->iv, ctx->enc))
            return 0;

        /* remove copy of cached key right away */
        (void) DIGI_MEMSET(ctx->key, 0x00, ctx->keylen);
        ctx->ctx_init = 1;
    }

    return digiprov_ccm_set_ctx_params(ctx, params);
}

static int digiprov_ccm_einit(void *vctx, const unsigned char *key, size_t keylen,
                              const unsigned char *iv, size_t ivlen,
                              const OSSL_PARAM params[])
{
    return digiprov_ccm_init(vctx, key, keylen, iv, ivlen, params, 1);
}

static int digiprov_ccm_dinit(void *vctx, const unsigned char *key, size_t keylen,
                              const unsigned char *iv, size_t ivlen,
                              const OSSL_PARAM params[])
{
    return digiprov_ccm_init(vctx, key, keylen, iv, ivlen, params, 0);
}

static int digiprov_ccm_stream_update(void *vctx, unsigned char *out, size_t *outl,
                                      size_t outsize, const unsigned char *in,
                                      size_t inl)
{
    DP_CCM_CTX *ctx = (DP_CCM_CTX *)vctx;
    int ret = 0;

    if (outsize < inl)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (!ctx->iv_set)
        return 0;

    /* The tag must be set before actually decrypting data */
    if (NULL != out && !ctx->enc && !ctx->tag_set)
        return 0;

    ret = DIGI_EVP_doCipher(ctx->pEvpCtx, out, in, inl);
    if (ret < 0)
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    if (!DIGI_EVP_cipherGetIv(ctx->pEvpCtx, ctx->iv, ccm_get_ivlen(ctx), 0))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    *outl = (size_t) ret;
    return 1;
}

static int digiprov_ccm_stream_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize)
{
    DP_CCM_CTX *ctx = (DP_CCM_CTX *)vctx;
    int ret = 0;

    if (!digiprov_is_running())
        return 0;

    /* The tag must be set before actually decrypting data */
    if (!ctx->enc && !ctx->tag_set)
        return 0;

    ret = DIGI_EVP_doCipher(ctx->pEvpCtx, out, NULL, 0);
    if (ret < 0)
        return 0;

    if (!DIGI_EVP_cipherGetIv(ctx->pEvpCtx, ctx->iv, ccm_get_ivlen(ctx), 0))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }
    
    if (ctx->enc)
    {
        ctx->tag_set = 1;
    }
    else
    {
        ctx->tag_set = 0;
    }
    ctx->iv_set = 0;
    ctx->len_set = 0;

    *outl = 0;
    return 1;
}

static int digiprov_ccm_cipher(void *vctx, unsigned char *out, size_t *outl, size_t outsize,
                               const unsigned char *in, size_t inl)
{
    DP_CCM_CTX *ctx = (DP_CCM_CTX *)vctx;
    int ret = 0;

    if (!digiprov_is_running())
        return 0;

    /* The tag must be set before actually decrypting data */
    if (NULL != out && !ctx->enc && !ctx->tag_set)
        return 0;

    if (outsize < inl) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (!ctx->iv_set)
        return 0;

    ret = DIGI_EVP_doCipher(ctx->pEvpCtx, out, in, inl);
    if (ret < 0)
        return 0;

    if (!DIGI_EVP_cipherGetIv(ctx->pEvpCtx, ctx->iv, ccm_get_ivlen(ctx), 0))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    /* It might just be AAD data input so far, don't change the state */
    if (NULL != out)
    {
        if (ctx->enc)
        {
            ctx->tag_set = 1;
        }
        else
        {
            ctx->tag_set = 0;
        }
        ctx->iv_set = 0;
        ctx->len_set = 0;
    }

    *outl = (size_t) ret;
    return 1;
}

#if 0

/* Copy the buffered iv */
static int ccm_set_iv(DP_CCM_CTX *ctx, size_t mlen)
{
    const PROV_CCM_HW *hw = ctx->hw;

    if (!hw->setiv(ctx, ctx->iv, ccm_get_ivlen(ctx), mlen))
        return 0;
    ctx->len_set = 1;
    return 1;
}

static int ccm_tls_cipher(DP_CCM_CTX *ctx,
                          unsigned char *out, size_t *padlen,
                          const unsigned char *in, size_t len)
{
    int rv = 0;
    size_t olen = 0;

    if (!digiprov_is_running())
        goto err;

    /* Encrypt/decrypt must be performed in place */
    if (in == NULL || out != in || len < EVP_CCM_TLS_EXPLICIT_IV_LEN + ctx->m)
        goto err;

    /* If encrypting set explicit IV from sequence number (start of AAD) */
    if (ctx->enc)
        memcpy(out, ctx->buf, EVP_CCM_TLS_EXPLICIT_IV_LEN);
    /* Get rest of IV from explicit IV */
    memcpy(ctx->iv + EVP_CCM_TLS_FIXED_IV_LEN, in, EVP_CCM_TLS_EXPLICIT_IV_LEN);
    /* Correct length value */
    len -= EVP_CCM_TLS_EXPLICIT_IV_LEN + ctx->m;
    if (!ccm_set_iv(ctx, len))
        goto err;

    /* Use saved AAD */
    if (!ctx->hw->setaad(ctx, ctx->buf, ctx->tls_aad_len))
        goto err;

    /* Fix buffer to point to payload */
    in += EVP_CCM_TLS_EXPLICIT_IV_LEN;
    out += EVP_CCM_TLS_EXPLICIT_IV_LEN;
    if (ctx->enc) {
        if (!ctx->hw->auth_encrypt(ctx, in, out, len,  out + len, ctx->m))
            goto err;
        olen = len + EVP_CCM_TLS_EXPLICIT_IV_LEN + ctx->m;
    } else {
        if (!ctx->hw->auth_decrypt(ctx, in, out, len,
                                   (unsigned char *)in + len, ctx->m))
            goto err;
        olen = len;
    }
    rv = 1;
err:
    *padlen = olen;
    return rv;
}
#endif

static void digiprov_ccm_initctx(DP_CCM_CTX *ctx, size_t keybits, void *hw)
{
    ctx->keylen = keybits / 8;
    ctx->key_set = 0;
    ctx->iv_set = 0;
    ctx->dir_set = 0;
    ctx->ctx_init = 0;
    ctx->tag_set = 0;
    ctx->len_set = 0;
    ctx->l = 8;
    ctx->m = 12;
    ctx->tls_aad_len = UNINITIALISED_SIZET;
}

static void digiprov_aes_ccm_freectx(void *vctx)
{
    DP_CCM_CTX *pShell = (DP_CCM_CTX *) vctx;

    if (NULL != pShell)
    {
        digiprov_cipher_freeevp(&pShell->pEvpCtx);
    }
    (void) DIGI_MEMSET_FREE((ubyte **) &vctx, sizeof(DP_CCM_CTX));
}

static int digiprov_ccm_set_mode(EVP_CIPHER_CTX *pCtx, size_t kbits, size_t ivbits)
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
            pCipher->nid = NID_aes_128_ccm;
            break;
        case 192:
            pCtx->key_len = MOC_AES_192_KEY_LEN;
            pCipher->nid = NID_aes_192_ccm;
            break;
        case 256:
            pCtx->key_len = MOC_AES_256_KEY_LEN;
            pCipher->nid = NID_aes_256_ccm;
            break;   
        default:
            return 0;         
    }

    return 1;
}

static void *digiprov_aes_ccm_newctx(void *provctx, size_t keybits, size_t ivbits)
{
    MSTATUS status = OK;
    DP_CCM_CTX *ctx = NULL;

    if (!digiprov_is_running())
        return NULL;
    
    status = DIGI_CALLOC((void **) &ctx, 1, sizeof(*ctx));
    if (OK != status)
        return NULL;
    
    digiprov_ccm_initctx(ctx, keybits, NULL);

    if (!digiprov_cipher_newevp(&ctx->pEvpCtx))
    {
        digiprov_aes_ccm_freectx(ctx); return NULL;
    }

    if (!digiprov_ccm_set_mode(ctx->pEvpCtx, keybits, ivbits))
    {
        digiprov_aes_ccm_freectx(ctx); return NULL;
    }

    return ctx;
}

/* digiprov_aes128ccm_functions */
IMPLEMENT_aead_cipher(aes, ccm, CCM, AEAD_FLAGS, 128, 8, 96);
/* digiprov_aes192ccm_functions */
IMPLEMENT_aead_cipher(aes, ccm, CCM, AEAD_FLAGS, 192, 8, 96);
/* digiprov_aes256ccm_functions */
IMPLEMENT_aead_cipher(aes, ccm, CCM, AEAD_FLAGS, 256, 8, 96);
