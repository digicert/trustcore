/*
 * digi_cipher_aes_keywrap.c
 *
 * AES keywrap implementations for OSSL 3.0 provider ADAPTED FROM openssl code
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
/*---------------------------------------------------------------------------------------------------------*/
/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
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
/* Dispatch functions for AES cipher modes ecb, cbc, ofb, cfb, ctr */

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
#include "internal/deprecated.h"

static OSSL_FUNC_cipher_encrypt_init_fn   digiprov_aes_wrap_einit;
static OSSL_FUNC_cipher_decrypt_init_fn   digiprov_aes_wrap_dinit;
static OSSL_FUNC_cipher_update_fn         digiprov_aes_wrap_cipher;
static OSSL_FUNC_cipher_final_fn          digiprov_aes_wrap_final;
static OSSL_FUNC_cipher_freectx_fn        digiprov_aes_wrap_freectx;
static OSSL_FUNC_cipher_set_ctx_params_fn digiprov_aes_wrap_set_ctx_params;

/* AES wrap with padding has IV length of 4, without padding 8 */
#define AES_WRAP_PAD_IVLEN   4
#define AES_WRAP_NOPAD_IVLEN 8

#define WRAP_FLAGS (PROV_CIPHER_FLAG_CUSTOM_IV)
#define WRAP_FLAGS_INV (WRAP_FLAGS | PROV_CIPHER_FLAG_INVERSE_CIPHER)

int DIGI_EVP_AESWrapInit(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                             const unsigned char *iv, int enc);

int DIGI_EVP_doAESWrapCipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t inlen, int pad, ubyte transform);                       

static void *digiprov_aes_wrap_newctx(void *provctx, size_t kbits, size_t blkbits,
                             size_t ivbits, unsigned int mode, uint64_t flags)
{
    MSTATUS status = OK;                                                      
    DP_CIPHER_CTX *ctx = NULL;

    if (!digiprov_is_running())
        return 0;

    status = DIGI_CALLOC((void **) &ctx, 1, sizeof(*ctx));                     
    if (OK != status)                                                         
        return NULL;                                                          
    digiprov_cipher_generic_initkey(ctx, kbits, blkbits, ivbits,
                                    mode, flags,
                                    NULL, provctx);
    if (!digiprov_cipher_newevp(&ctx->pEvpCtx))
    {
        digiprov_cipher_generic_freectx(ctx); ctx = NULL;
    }
    if (!digiprov_aes_set_mode(ctx, kbits, ivbits, mode))
    {                                                                         
        digiprov_cipher_generic_freectx(ctx); ctx = NULL;
    }

    if (NULL != ctx)
        ctx->pad = (ctx->ivlen == AES_WRAP_PAD_IVLEN);

    return ctx;
}

static void digiprov_aes_wrap_freectx(void *vctx)
{
    return digiprov_cipher_generic_freectx(vctx);
}

static int digiprov_aes_wrap_init(void *vctx, const unsigned char *key,
                         size_t keylen, const unsigned char *iv,
                         size_t ivlen, const OSSL_PARAM params[], int enc)
{
    DP_CIPHER_CTX *ctx = (DP_CIPHER_CTX *)vctx;

    if (!digiprov_is_running())
        return 0;

    if (NULL == ctx)
        return 0;

    ctx->enc = enc ? 1 : 0;
    
    if (NULL != key)
    {
        ctx->keylen = keylen;
        ctx->pEvpCtx->key_len = (int) keylen;
        ctx->pEvpCtx->encrypt = ctx->enc;

        if (1 != DIGI_EVP_AESWrapInit(ctx->pEvpCtx, key, iv, enc))
            return 0;
    }

    return digiprov_aes_wrap_set_ctx_params(ctx, params);
}

static int digiprov_aes_wrap_einit(void *ctx, const unsigned char *key, size_t keylen,
                          const unsigned char *iv, size_t ivlen,
                          const OSSL_PARAM params[])
{
    return digiprov_aes_wrap_init(ctx, key, keylen, iv, ivlen, params, 1);
}

static int digiprov_aes_wrap_dinit(void *ctx, const unsigned char *key, size_t keylen,
                          const unsigned char *iv, size_t ivlen,
                          const OSSL_PARAM params[])
{
    return digiprov_aes_wrap_init(ctx, key, keylen, iv, ivlen, params, 0);
}

static int digiprov_aes_wrap_cipher_internal(void *vctx, unsigned char *out,
                                             const unsigned char *in, size_t inlen)
{
    DP_CIPHER_CTX *ctx = (DP_CIPHER_CTX *)vctx;
    int pad;
    ubyte transform = 0;

    if (!digiprov_is_running())
        return 0;

    if (NULL == ctx)
        return 0;

    pad = ctx->pad;

    /* No final operation so always return zero length */
    if (in == NULL)
        return 0;

    /* Input length must always be non-zero */
    if (inlen == 0) {
        return -1;
    }

    /* If decrypting need at least 16 bytes and multiple of 8 */
    if (!ctx->enc && (inlen < 16 || inlen & 0x7)) {
        return -1;
    }

    /* If not padding input must be multiple of 8 */
    if (!pad && inlen & 0x7) {
        return -1;
    }

    if (out == NULL) {
        if (ctx->enc) {
            /* If padding round up to multiple of 8 */
            if (pad)
                inlen = (inlen + 7) / 8 * 8;
            /* 8 byte prefix */
            return inlen + 8;
        } else {
            /*
             * If not padding output will be exactly 8 bytes smaller than
             * input. If padding it will be at least 8 bytes smaller but we
             * don't know how much.
             */
            return inlen - 8;
        }
    }

    if (ctx->inverse_cipher == 0)
        transform = ctx->enc;
    else
        transform = !ctx->enc;

    ctx->pEvpCtx->encrypt = ctx->enc;

    return DIGI_EVP_doAESWrapCipher(ctx->pEvpCtx, out, in, inlen, pad, transform);
}

static int digiprov_aes_wrap_final(void *vctx, unsigned char *out, size_t *outl,
                          size_t outsize)
{
    if (!digiprov_is_running())
        return 0;

    *outl = 0;
    return 1;
}

static int digiprov_aes_wrap_cipher(void *vctx,
                           unsigned char *out, size_t *outl, size_t outsize,
                           const unsigned char *in, size_t inl)
{
    DP_CIPHER_CTX *ctx = (DP_CIPHER_CTX *)vctx;
    size_t len;

    if (!digiprov_is_running())
        return 0;

    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    if (outsize < inl) {
        return 0;
    }

    len = digiprov_aes_wrap_cipher_internal(ctx, out, in, inl);
    if (len <= 0)
        return 0;

    *outl = len;
    return 1;
}

static int digiprov_aes_wrap_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    DP_CIPHER_CTX *ctx = (DP_CIPHER_CTX *)vctx;
    const OSSL_PARAM *p;
    size_t keylen = 0;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &keylen)) {
            return 0;
        }
        ctx->keylen = keylen;
    }
    return 1;
}

#define IMPLEMENT_cipher(mode, fname, UCMODE, flags, kbits, blkbits, ivbits)   \
    static OSSL_FUNC_cipher_get_params_fn aes_##kbits##_##fname##_get_params;  \
    static int aes_##kbits##_##fname##_get_params(OSSL_PARAM params[])         \
    {                                                                          \
        return digiprov_cipher_generic_get_params(params, EVP_CIPH_##UCMODE##_MODE,\
                                              flags, kbits, blkbits, ivbits);  \
    }                                                                          \
    static OSSL_FUNC_cipher_newctx_fn aes_##kbits##fname##_newctx;             \
    static void *aes_##kbits##fname##_newctx(void *provctx)                    \
    {                                                                          \
        return digiprov_aes_##mode##_newctx(provctx, kbits, blkbits, ivbits,                     \
                                   EVP_CIPH_##UCMODE##_MODE, flags);           \
    }                                                                          \
    const OSSL_DISPATCH digiprov_##aes##kbits##fname##_functions[] = {             \
        { OSSL_FUNC_CIPHER_NEWCTX,                                             \
            (void (*)(void))aes_##kbits##fname##_newctx },                     \
        { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))digiprov_aes_##mode##_einit }, \
        { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))digiprov_aes_##mode##_dinit }, \
        { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))digiprov_aes_##mode##_cipher },      \
        { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))digiprov_aes_##mode##_final },        \
        { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))digiprov_aes_##mode##_freectx },    \
        { OSSL_FUNC_CIPHER_GET_PARAMS,                                         \
            (void (*)(void))aes_##kbits##_##fname##_get_params },              \
        { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                    \
            (void (*)(void))digiprov_cipher_generic_gettable_params },             \
        { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                     \
            (void (*)(void))digiprov_cipher_generic_get_ctx_params },              \
        { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                     \
            (void (*)(void))digiprov_aes_wrap_set_ctx_params },                         \
        { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                \
            (void (*)(void))digiprov_cipher_generic_gettable_ctx_params },         \
        { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                \
            (void (*)(void))digiprov_cipher_var_keylen_settable_ctx_params },         \
        { 0, NULL }                                                            \
    }

IMPLEMENT_cipher(wrap, wrap, WRAP, WRAP_FLAGS, 256, 64, AES_WRAP_NOPAD_IVLEN * 8);
IMPLEMENT_cipher(wrap, wrap, WRAP, WRAP_FLAGS, 192, 64, AES_WRAP_NOPAD_IVLEN * 8);
IMPLEMENT_cipher(wrap, wrap, WRAP, WRAP_FLAGS, 128, 64, AES_WRAP_NOPAD_IVLEN * 8);
IMPLEMENT_cipher(wrap, wrappad, WRAP, WRAP_FLAGS, 256, 64, AES_WRAP_PAD_IVLEN * 8);
IMPLEMENT_cipher(wrap, wrappad, WRAP, WRAP_FLAGS, 192, 64, AES_WRAP_PAD_IVLEN * 8);
IMPLEMENT_cipher(wrap, wrappad, WRAP, WRAP_FLAGS, 128, 64, AES_WRAP_PAD_IVLEN * 8);

IMPLEMENT_cipher(wrap, wrapinv, WRAP, WRAP_FLAGS_INV, 256, 64, AES_WRAP_NOPAD_IVLEN * 8);
IMPLEMENT_cipher(wrap, wrapinv, WRAP, WRAP_FLAGS_INV, 192, 64, AES_WRAP_NOPAD_IVLEN * 8);
IMPLEMENT_cipher(wrap, wrapinv, WRAP, WRAP_FLAGS_INV, 128, 64, AES_WRAP_NOPAD_IVLEN * 8);
IMPLEMENT_cipher(wrap, wrappadinv, WRAP, WRAP_FLAGS_INV, 256, 64, AES_WRAP_PAD_IVLEN * 8);
IMPLEMENT_cipher(wrap, wrappadinv, WRAP, WRAP_FLAGS_INV, 192, 64, AES_WRAP_PAD_IVLEN * 8);
IMPLEMENT_cipher(wrap, wrappadinv, WRAP, WRAP_FLAGS_INV, 128, 64, AES_WRAP_PAD_IVLEN * 8);
