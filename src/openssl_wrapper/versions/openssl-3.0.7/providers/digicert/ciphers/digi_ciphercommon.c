/*
 * digi_ciphercommon.c
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

/*
 * Generic dispatch table functions for ciphers.
 */

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

/* For SSL3_VERSION */
#include "openssl/prov_ssl.h"
#include "openssl/proverr.h"
#ifndef OPENSSL_NO_RC5
#include "openssl/rc5.h"
#endif
#include "digi_ciphercommon.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"

#include "digiprov.h"

size_t digiprov_cipher_fillblock(unsigned char *buf, size_t *buflen, size_t blocksize,
                                 const unsigned char **in, size_t *inlen);
void digiprov_cipher_padblock(unsigned char *buf, size_t *buflen, size_t blocksize);
int digiprov_cipher_unpadblock(unsigned char *buf, size_t *buflen, size_t blocksize);
int digiprov_cipher_tlsunpadblock(OSSL_LIB_CTX *libctx, unsigned int tlsversion,
                              unsigned char *buf, size_t *buflen, size_t blocksize,
                              unsigned char **mac, int *alloced, size_t macsize, int aead);


int DIGI_EVP_RC5_cipherInit(EVP_CIPHER_CTX *pCtx, const unsigned char *pKey,
                                  const unsigned char *pIv, int isEncrypt);
int DIGI_EVP_RC5_ctrl(EVP_CIPHER_CTX *pCtx, int type, int arg, void *pPtr);
int DIGI_EVP_RC5_doCipher(EVP_CIPHER_CTX *pCtx, unsigned char *pOut, const unsigned char *pIn, size_t inlen);
int DIGI_EVP_RC5_cipherCleanup(EVP_CIPHER_CTX *pCtx);

int DIGI_EVP_cipherInit(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int isEncrypt);
int DIGI_EVP_ThreeDesInit(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int isEncrypt);

int DIGI_EVP_cipherGetIv(EVP_CIPHER_CTX *ctx, unsigned char *pIv, size_t ivLen, int isRc5);
int DIGI_EVP_doCipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
int DIGI_EVP_cipherCleanup(EVP_CIPHER_CTX *ctx);
int DIGI_EVP_CIPHER_copyCtx(EVP_CIPHER_CTX *pCtx, EVP_CIPHER_CTX *pCtxCopy);

/*-
 * Generic cipher functions for OSSL_PARAM gettables and settables
 */
static const OSSL_PARAM cipher_known_gettable_params[] = 
{
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CTS, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, NULL),
    OSSL_PARAM_END
};
const OSSL_PARAM *digiprov_cipher_generic_gettable_params(ossl_unused void *provctx)
{
    return cipher_known_gettable_params;
}

int digiprov_cipher_generic_get_params(OSSL_PARAM params[], unsigned int md, uint64_t flags,
                                       size_t kbits, size_t blkbits, size_t ivbits)
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, md)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_AEAD) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_CUSTOM_IV) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_CTS) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_TLS1_MULTIBLOCK) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_HAS_RAND_KEY);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_RAND_KEY) != 0)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, kbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blkbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ivbits / 8)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    return 1;
}

CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_START(digiprov_cipher_generic)
{ OSSL_CIPHER_PARAM_TLS_MAC, OSSL_PARAM_OCTET_PTR, NULL, 0, OSSL_PARAM_UNMODIFIED },
CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_END(digiprov_cipher_generic)

CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_START(digiprov_cipher_generic)
OSSL_PARAM_uint(OSSL_CIPHER_PARAM_USE_BITS, NULL),
OSSL_PARAM_uint(OSSL_CIPHER_PARAM_TLS_VERSION, NULL),
OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_TLS_MAC_SIZE, NULL),
CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_END(digiprov_cipher_generic)

/*
 * Variable key length cipher functions for OSSL_PARAM settables
 */
int digiprov_cipher_var_keylen_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    DP_CIPHER_CTX *ctx = (DP_CIPHER_CTX *)vctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    if (!digiprov_cipher_generic_set_ctx_params(vctx, params))
        return 0;
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL)
    {
        size_t keylen;

        if (!OSSL_PARAM_get_size_t(p, &keylen))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        ctx->keylen = keylen;
        if (NULL != ctx->pEvpCtx)
        {
            ctx->pEvpCtx->key_len = (int) keylen;
        }
    }

    /* for rc5 only */
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_ROUNDS);
    if (p != NULL) 
    {
#ifndef OPENSSL_NO_RC5
        unsigned int rounds = 0;

        if (ctx->isRc5)
        {
            if (!OSSL_PARAM_get_uint(p, &rounds))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                return 0;
            }

            if (rounds != RC5_8_ROUNDS && rounds != RC5_12_ROUNDS && rounds != RC5_16_ROUNDS) 
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_UNSUPPORTED_NUMBER_OF_ROUNDS);
                return 0;
            }

            if(!DIGI_EVP_RC5_ctrl(ctx->pEvpCtx, EVP_CTRL_SET_RC5_ROUNDS, (int) rounds, NULL))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
                return 0;
            }
            ctx->rounds = rounds;
        }
        else
#endif
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
    }

    return 1;
}

CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_START(digiprov_cipher_var_keylen)
OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
OSSL_PARAM_uint(OSSL_CIPHER_PARAM_ROUNDS, NULL),
CIPHER_DEFAULT_SETTABLE_CTX_PARAMS_END(digiprov_cipher_var_keylen)

/*-
 * AEAD cipher functions for OSSL_PARAM gettables and settables
 */
static const OSSL_PARAM cipher_aead_known_gettable_ctx_params[] = 
{
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN, NULL, 0),
    OSSL_PARAM_END
};
const OSSL_PARAM *digiprov_cipher_aead_gettable_ctx_params(
        ossl_unused void *cctx, ossl_unused void *provctx
    )
{
    return cipher_aead_known_gettable_ctx_params;
}

static const OSSL_PARAM cipher_aead_known_settable_ctx_params[] = 
{
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV, NULL, 0),
    OSSL_PARAM_END
};
const OSSL_PARAM *digiprov_cipher_aead_settable_ctx_params(
        ossl_unused void *cctx, ossl_unused void *provctx
    )
{
    return cipher_aead_known_settable_ctx_params;
}

void digiprov_cipher_generic_reset_ctx(DP_CIPHER_CTX *ctx)
{
    if (ctx != NULL && ctx->alloced) {
        OPENSSL_free(ctx->tlsmac);
        ctx->alloced = 0;
        ctx->tlsmac = NULL;
    }
}

static int cipher_generic_init_internal(DP_CIPHER_CTX *ctx,
                                        const unsigned char *key, size_t keylen,
                                        const unsigned char *iv, size_t ivlen,
                                        const OSSL_PARAM params[], int enc)
{
    MSTATUS status = -1;
    ctx->num = 0;
    ctx->bufsz = 0;
    ctx->updated = 0;
    ctx->enc = enc ? 1 : 0;

    if (!digiprov_is_running())
        return 0;

    if (iv != NULL && ctx->mode != EVP_CIPH_ECB_MODE) 
    {
        if (!digiprov_cipher_generic_initiv(ctx, iv, ivlen))
            return 0;
    }
    if (iv == NULL && ctx->iv_set
        && (ctx->mode == EVP_CIPH_CBC_MODE
            || ctx->mode == EVP_CIPH_CFB_MODE
            || ctx->mode == EVP_CIPH_OFB_MODE))
        /* reset IV for these modes to keep compatibility with 1.1.1 */
        (void) DIGI_MEMCPY(ctx->iv, ctx->oiv, ctx->ivlen);

    if (key != NULL)
    {
        int nid = 0;
        if (ctx->variable_keylength == 0) 
        {
            if (keylen != ctx->keylen) 
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
                return 0;
            }
        } 
        else 
        {
            ctx->keylen = keylen;
            ctx->pEvpCtx->key_len = (int) keylen;
        }

        ctx->pEvpCtx->encrypt = ctx->enc;
        nid = ((EVP_CIPHER *)(ctx->pEvpCtx->cipher))->nid;

        /* for xts encrypt we check the two keys don't match (underlying impl may not) */
        if (ctx->enc && (NID_aes_128_xts == nid || NID_aes_256_xts == nid))
        {
            sbyte4 cmp = -1;

            status = DIGI_MEMCMP(key, key + keylen/2, keylen/2, &cmp);
            if (OK != status)
                return 0;

            if (!cmp)
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
                return 0;
            }
        }

        (void) DIGI_MEMCPY(ctx->key, key, keylen);
        ctx->key_set = 1;
    }

    if (enc > -1) /* if enc = -1 direction may already be set, we don't change ctx->dir_set */
    {
        ctx->pEvpCtx->encrypt = ctx->enc = enc;
        ctx->dir_set = 1;
    }

    if (!ctx->ctx_init && (ctx->iv_set || !ctx->need_iv) && ctx->key_set && (ctx->dir_set || !ctx->need_dir))
    {
        int nid = ((EVP_CIPHER *)(ctx->pEvpCtx->cipher))->nid;
        if (NID_des_ede3_ecb == nid || NID_des_ede3_cbc == nid || NID_des_ede_ecb == nid || NID_des_ede_cbc == nid)
        {
            if (!DIGI_EVP_ThreeDesInit(ctx->pEvpCtx, ctx->key, ctx->iv, ctx->enc))
                return 0;
        }
#ifndef OPENSSL_NO_RC5
        else if (NID_rc5_ecb == nid || NID_rc5_cbc == nid)
        {
            if (!DIGI_EVP_RC5_ctrl(ctx->pEvpCtx, EVP_CTRL_INIT, 0, NULL))
                return 0;
            
            if (ctx->rounds > 0)
            {
                if (!DIGI_EVP_RC5_ctrl(ctx->pEvpCtx, EVP_CTRL_SET_RC5_ROUNDS, (int) ctx->rounds, NULL))
                    return 0;
            }

            if (!DIGI_EVP_RC5_cipherInit(ctx->pEvpCtx, ctx->key, ctx->iv, ctx->enc))
                return 0;
        }
#endif
        else
        {
            if (!DIGI_EVP_cipherInit(ctx->pEvpCtx, ctx->key, ctx->iv, ctx->enc))
                return 0;
        }

        /* remove copy of cached key right away */
        (void) DIGI_MEMSET(ctx->key, 0x00, ctx->keylen);
        ctx->ctx_init = 1;
    }
    return digiprov_cipher_generic_set_ctx_params(ctx, params);
}

int digiprov_cipher_generic_einit(void *vctx, const unsigned char *key,
                              size_t keylen, const unsigned char *iv,
                              size_t ivlen, const OSSL_PARAM params[])
{
    return cipher_generic_init_internal((DP_CIPHER_CTX *)vctx, key, keylen,
                                        iv, ivlen, params, 1);
}

int digiprov_cipher_generic_dinit(void *vctx, const unsigned char *key,
                              size_t keylen, const unsigned char *iv,
                              size_t ivlen, const OSSL_PARAM params[])
{
    return cipher_generic_init_internal((DP_CIPHER_CTX *)vctx, key, keylen,
                                        iv, ivlen, params, 0);
}

/* Max padding including padding length byte */
#define MAX_PADDING 256

int digiprov_cipher_generic_block_update(void *vctx, unsigned char *out,
                                         size_t *outl, size_t outsize,
                                         const unsigned char *in, size_t inl)
{
    size_t outlint = 0;
    DP_CIPHER_CTX *ctx = (DP_CIPHER_CTX *)vctx;
    size_t blksz = ctx->blocksize;
    size_t nextblocks;
    
    if (ctx->tlsversion > 0) {
        /*
         * Each update call corresponds to a TLS record and is individually
         * padded
         */

        /* Sanity check inputs */
        if (in == NULL
                || in != out
                || outsize < inl
                || !ctx->pad) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }

        if (ctx->enc) {
            unsigned char padval;
            size_t padnum, loop;

            /* Add padding */

            padnum = blksz - (inl % blksz);

            if (outsize < inl + padnum) {
                ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
                return 0;
            }

            if (padnum > MAX_PADDING) {
                ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
                return 0;
            }
            padval = (unsigned char)(padnum - 1);
            if (ctx->tlsversion == SSL3_VERSION) {
                if (padnum > 1)
                    memset(out + inl, 0, padnum - 1);
                *(out + inl + padnum - 1) = padval;
            } else {
                /* we need to add 'padnum' padding bytes of value padval */
                for (loop = inl; loop < inl + padnum; loop++)
                    out[loop] = padval;
            }
            inl += padnum;
        }

        if ((inl % blksz) != 0) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }

        /* Shouldn't normally fail */
        if (ctx->isRc5)
        {
            if (!DIGI_EVP_RC5_doCipher(ctx->pEvpCtx, out, in, inl))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
                return 0;
            }            
        }
        else
        {
            if (!DIGI_EVP_doCipher(ctx->pEvpCtx, out, in, inl))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
                return 0;
            }
        }

        if (EVP_CIPH_ECB_MODE != ctx->mode)
        {
            if (!DIGI_EVP_cipherGetIv(ctx->pEvpCtx, ctx->iv, ctx->ivlen, ctx->isRc5))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
                return 0;            
            }
        }

        if (ctx->alloced) 
        {
            OPENSSL_free(ctx->tlsmac);
            ctx->alloced = 0;
            ctx->tlsmac = NULL;
        }

        /* This only fails if padding is publicly invalid */
        *outl = inl;
        if (!ctx->enc
            && !digiprov_cipher_tlsunpadblock(ctx->libctx, ctx->tlsversion,
                                          out, outl,
                                          blksz, &ctx->tlsmac, &ctx->alloced,
                                          ctx->tlsmacsize, 0)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
        return 1;
    }

    if (ctx->bufsz != 0)
        nextblocks = digiprov_cipher_fillblock(ctx->buf, &ctx->bufsz, blksz, &in, &inl);
    else
        nextblocks = inl & ~(blksz-1);

    /*
     * If we're decrypting and we end an update on a block boundary we hold
     * the last block back in case this is the last update call and the last
     * block is padded.
     */
    if (ctx->bufsz == blksz && (ctx->enc || inl > 0 || !ctx->pad))
    {
        if (outsize < blksz)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
    
        if (ctx->isRc5)
        {
            if (!DIGI_EVP_RC5_doCipher(ctx->pEvpCtx, out, ctx->buf, blksz))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
                return 0;
            }            
        }
        else
        {
            if (!DIGI_EVP_doCipher(ctx->pEvpCtx, out, ctx->buf, blksz))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
                return 0;
            }
        }
        ctx->bufsz = 0;
        outlint = blksz;
        out += blksz;
    }
    if (nextblocks > 0) 
    {
        if (!ctx->enc && ctx->pad && nextblocks == inl)
        {
            if (!ossl_assert(inl >= blksz)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
                return 0;
            }
            nextblocks -= blksz;
        }
        outlint += nextblocks;
        if (outsize < outlint)
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }
    }
    if (nextblocks > 0) 
    {
        if (ctx->isRc5)
        {
            if (!DIGI_EVP_RC5_doCipher(ctx->pEvpCtx, out, in, nextblocks))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
                return 0;
            }            
        }
        else
        {
            if (!DIGI_EVP_doCipher(ctx->pEvpCtx, out, in, nextblocks))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
                return 0;
            }
        }
        in += nextblocks;
        inl -= nextblocks;
    }
    if (inl != 0 && !digiprov_cipher_trailingdata(ctx->buf, &ctx->bufsz, blksz, &in, &inl)) 
    {
        /* ERR_raise already called */
        return 0;
    }

    if (EVP_CIPH_ECB_MODE != ctx->mode)
    {
        /* update our copy of the IV*/
        if (!DIGI_EVP_cipherGetIv(ctx->pEvpCtx, ctx->iv, ctx->ivlen, ctx->isRc5))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;            
        }
    }

    *outl = outlint;
    return inl == 0;
}

int digiprov_cipher_generic_block_final(void *vctx, unsigned char *out,
                                        size_t *outl, size_t outsize)
{
    DP_CIPHER_CTX *ctx = (DP_CIPHER_CTX *)vctx;
    size_t blksz = ctx->blocksize;
 
    if (!digiprov_is_running())
        return 0;

    if (ctx->tlsversion > 0) {
        /* We never finalize TLS, so this is an error */
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    if (ctx->enc) 
    {
        if (ctx->pad)
        {
            digiprov_cipher_padblock(ctx->buf, &ctx->bufsz, blksz);
        } 
        else if (ctx->bufsz == 0) 
        {
            *outl = 0;
            return 1;
        } 
        else if (ctx->bufsz != blksz) 
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
            return 0;
        }

        if (outsize < blksz) 
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
            return 0;
        }

        if (ctx->isRc5)
        {
            if (!DIGI_EVP_RC5_doCipher(ctx->pEvpCtx, out, ctx->buf, blksz))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
                return 0;
            }            
        }
        else
        {
            if (!DIGI_EVP_doCipher(ctx->pEvpCtx, out, ctx->buf, blksz))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
                return 0;
            }
        }

        if (EVP_CIPH_ECB_MODE != ctx->mode)
        {
            if (!DIGI_EVP_cipherGetIv(ctx->pEvpCtx, ctx->iv, ctx->ivlen, ctx->isRc5))
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
                return 0;            
            }
        }
        ctx->bufsz = 0;
        *outl = blksz;
        return 1;
    }

    /* Decrypting */
    if (ctx->bufsz != blksz) 
    {
        if (ctx->bufsz == 0 && !ctx->pad) 
        {
            *outl = 0;
            return 1;
        }
        ERR_raise(ERR_LIB_PROV, PROV_R_WRONG_FINAL_BLOCK_LENGTH);
        return 0;
    }
    
    if (ctx->isRc5)
    {
        if (!DIGI_EVP_RC5_doCipher(ctx->pEvpCtx, ctx->buf, ctx->buf, blksz))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }            
    }
    else
    {
        if (!DIGI_EVP_doCipher(ctx->pEvpCtx, ctx->buf, ctx->buf, blksz))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;
        }
    }

    if (EVP_CIPH_ECB_MODE != ctx->mode)
    {
        if (!DIGI_EVP_cipherGetIv(ctx->pEvpCtx, ctx->iv, ctx->ivlen, ctx->isRc5))
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
            return 0;            
        }
    }

    if (ctx->pad && !digiprov_cipher_unpadblock(ctx->buf, &ctx->bufsz, blksz))
    {
        /* ERR_raise already called */
        return 0;
    }

    if (outsize < ctx->bufsz) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    (void) DIGI_MEMCPY(out, ctx->buf, ctx->bufsz);
    *outl = ctx->bufsz;
    ctx->bufsz = 0;
    return 1;
}

int digiprov_cipher_generic_stream_update(void *vctx, unsigned char *out,
                                          size_t *outl, size_t outsize,
                                          const unsigned char *in, size_t inl)
{
    DP_CIPHER_CTX *ctx = (DP_CIPHER_CTX *)vctx;

    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    if (outsize < inl) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
    
    if (!DIGI_EVP_doCipher(ctx->pEvpCtx, out, in, inl))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;
    }

    *outl = inl;

    if (!DIGI_EVP_cipherGetIv(ctx->pEvpCtx, ctx->iv, ctx->ivlen, 0))
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_CIPHER_OPERATION_FAILED);
        return 0;            
    }
    
    if (!ctx->enc && ctx->tlsversion > 0) {
        /*
        * Remove any TLS padding. Only used by cipher_aes_cbc_hmac_sha1_hw.c and
        * cipher_aes_cbc_hmac_sha256_hw.c
        */
        if (ctx->removetlspad) {
            /*
             * We should have already failed in the cipher() call above if this
             * isn't true.
             */
            if (!ossl_assert(*outl >= (size_t)(out[inl - 1] + 1)))
                return 0;
            /* The actual padding length */
            *outl -= out[inl - 1] + 1;
        }

        /* TLS MAC and explicit IV if relevant. We should have already failed
         * in the cipher() call above if *outl is too short.
         */
        if (!ossl_assert(*outl >= ctx->removetlsfixed))
            return 0;
        *outl -= ctx->removetlsfixed;

        /* Extract the MAC if there is one */
        if (ctx->tlsmacsize > 0) {
            if (*outl < ctx->tlsmacsize)
                return 0;

            ctx->tlsmac = out + *outl - ctx->tlsmacsize;
            *outl -= ctx->tlsmacsize;
        }
    }

    return 1;
}
int digiprov_cipher_generic_stream_final(void *vctx, unsigned char *out,
                                     size_t *outl, size_t outsize)
{
    if (!digiprov_is_running())
        return 0;

    *outl = 0;
    return 1;
}

int digiprov_cipher_generic_cipher(void *vctx, unsigned char *out, size_t *outl,
                                   size_t outsize, const unsigned char *in,
                                   size_t inl)
{
    DP_CIPHER_CTX *ctx = (DP_CIPHER_CTX *)vctx;
    size_t updateLen = 0;
    size_t finalLen = 0;
    
    if (!digiprov_is_running())
        return 0;

    if (outsize < inl || (ctx->enc && ctx->pad && (EVP_CIPH_CBC_MODE == ctx->mode || EVP_CIPH_ECB_MODE == ctx->mode) 
                          && outsize < (inl + ctx->blocksize - (inl % ctx->blocksize)) )) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (EVP_CIPH_CBC_MODE == ctx->mode || EVP_CIPH_ECB_MODE == ctx->mode)
    {
        if(!digiprov_cipher_generic_block_update(vctx, out, &updateLen, outsize, in, inl))
            return 0;

        if(!digiprov_cipher_generic_block_final(vctx, out + updateLen, &finalLen, outsize - updateLen))
            return 0;
    }
    else
    {
        if(!digiprov_cipher_generic_stream_update(vctx, out, &updateLen, outsize, in, inl))
            return 0;

        if(!digiprov_cipher_generic_stream_final(vctx, out + updateLen, &finalLen, outsize - updateLen))
            return 0;
    }

    *outl = (updateLen + finalLen);
    return 1;
}

int digiprov_cipher_generic_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    DP_CIPHER_CTX *ctx = (DP_CIPHER_CTX *)vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->ivlen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->pad)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(p, &ctx->oiv, ctx->ivlen)
        && !OSSL_PARAM_set_octet_string(p, &ctx->oiv, ctx->ivlen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivlen)
        && !OSSL_PARAM_set_octet_string(p, &ctx->iv, ctx->ivlen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->num)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS_MAC);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(p, ctx->tlsmac, ctx->tlsmacsize)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }

    /* for rc5 only */
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_ROUNDS);
    if (p != NULL)
    {
#ifndef OPENSSL_NO_RC5
        /* sanity check that it is rc5 */
        if (ctx->isRc5)
        {
            if(!OSSL_PARAM_set_uint(p, ctx->rounds)) 
            {
                ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
                return 0;
            }
            }
        else
#endif
        {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
            return 0;                
        }
    }

    return 1;
}

int digiprov_cipher_generic_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    DP_CIPHER_CTX *ctx = (DP_CIPHER_CTX *)vctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL) {
        unsigned int pad;

        if (!OSSL_PARAM_get_uint(p, &pad)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        ctx->pad = pad ? 1 : 0;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_USE_BITS);
    if (p != NULL) {
        unsigned int bits;

        if (!OSSL_PARAM_get_uint(p, &bits)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        ctx->use_bits = bits ? 1 : 0;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_VERSION);
    if (p != NULL) {
        if (!OSSL_PARAM_get_uint(p, &ctx->tlsversion)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_MAC_SIZE);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &ctx->tlsmacsize)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL) {
        unsigned int num;

        if (!OSSL_PARAM_get_uint(p, &num)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER);
            return 0;
        }
        ctx->num = num;
    }
    
    return 1;
}

int digiprov_cipher_generic_initiv(DP_CIPHER_CTX *ctx, const unsigned char *iv,
                               size_t ivlen)
{
    if (ivlen != ctx->ivlen || ivlen > sizeof(ctx->iv)) 
    {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
        return 0;
    }

    if (NULL != ctx->pEvpCtx && !ctx->isRc5)
    {
        MOC_EVP_CIPHER_CTX *pMocCtx = (MOC_EVP_CIPHER_CTX *)ctx->pEvpCtx->cipher_data;
        if (NULL != pMocCtx)
        {
            DIGI_MEMCPY(pMocCtx->wIv, iv, ivlen);
            DIGI_MEMCPY(pMocCtx->oIv, iv, ivlen);
            pMocCtx->init = 0;
        }
    }
    ctx->iv_set = 1;
    (void) DIGI_MEMCPY(ctx->iv, iv, ivlen);
    (void) DIGI_MEMCPY(ctx->oiv, iv, ivlen);
    return 1;
}

void digiprov_cipher_generic_initkey(void *vctx, size_t kbits, size_t blkbits,
                                     size_t ivbits, unsigned int mode,
                                     uint64_t flags, void *hw,
                                     void *provctx)
{
    DP_CIPHER_CTX *ctx = (DP_CIPHER_CTX *)vctx;

    MOC_UNUSED(hw);

    if ((flags & PROV_CIPHER_FLAG_INVERSE_CIPHER) != 0)
        ctx->inverse_cipher = 1;
    if ((flags & PROV_CIPHER_FLAG_VARIABLE_LENGTH) != 0)
        ctx->variable_keylength = 1;

    ctx->pad = 1;
    ctx->keylen = kbits/8;
    ctx->ivlen = ivbits/8;
    ctx->mode = mode;
    ctx->blocksize = blkbits/8;
    if (provctx != NULL)
        ctx->libctx = PROV_LIBCTX_OF(provctx); /* used for rand */
}

int digiprov_cipher_newevp(EVP_CIPHER_CTX **ppCtx)
{
    MSTATUS status = OK;
    MOC_EVP_CIPHER_CTX *pMocCtx = NULL;
    EVP_CIPHER_CTX *pCtx = NULL;
    EVP_CIPHER *pCipher = NULL;

    if (NULL == ppCtx)
        return 0;

    status = DIGI_CALLOC((void **)&pCtx, 1, sizeof(EVP_CIPHER_CTX));
    if (OK != status)
        goto exit;

    status = DIGI_CALLOC((void **)&pCipher, 1, sizeof(EVP_CIPHER));
    if (OK != status)
        goto exit;

    status = DIGI_CALLOC((void **)&pMocCtx, 1, sizeof(MOC_EVP_CIPHER_CTX));
    if (OK != status)
        goto exit;

    /* clear any previous context */
    if (NULL != *ppCtx)
    {
        digiprov_cipher_freeevp(ppCtx);
    }

    pCtx->cipher = pCipher; pCipher = NULL;
    pCtx->cipher_data = pMocCtx; pMocCtx = NULL;
    *ppCtx = pCtx; pCtx = NULL;
    
exit:

    if (NULL != pCtx)
    {
        (void) DIGI_MEMSET_FREE((ubyte **)&pCtx, sizeof(*pCtx));
    }
    if (NULL != pCipher)
    {
        (void) DIGI_MEMSET_FREE((ubyte **)&pCipher, sizeof(*pCipher));
    }
    if (NULL != pMocCtx)
    {
        (void) DIGI_MEMSET_FREE((ubyte **)&pMocCtx, sizeof(*pMocCtx));
    }

    return (OK == status) ? 1 : 0;
}

void digiprov_cipher_freeevp(EVP_CIPHER_CTX **ppCtx)
{
    if(NULL != ppCtx && NULL != *ppCtx)
    {
        EVP_CIPHER_CTX *pCtx = *ppCtx;

#ifndef OPENSSL_NO_RC5
        if (NULL != pCtx->cipher && (NID_rc5_ecb == (((EVP_CIPHER *) pCtx->cipher)->nid) || 
                                    (NID_rc5_cbc == (((EVP_CIPHER *) pCtx->cipher)->nid))))
        {
            (void) DIGI_EVP_RC5_cipherCleanup(pCtx);
        }
        else
#endif
        {
            (void) DIGI_EVP_cipherCleanup(pCtx);
        }
        
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

void digiprov_cipher_generic_freectx(void *vctx)
{
    DP_CIPHER_CTX *pShell = (DP_CIPHER_CTX *) vctx;

    if (NULL != pShell)
    {
        digiprov_cipher_freeevp(&pShell->pEvpCtx);
    }
    (void) DIGI_MEMSET_FREE((ubyte **) &vctx, sizeof(DP_CIPHER_CTX));
}

void *digiprov_cipher_generic_dupctx(void *vctx)
{
    MSTATUS status = OK;
    DP_CIPHER_CTX *pRet = NULL;
    DP_CIPHER_CTX *pShell = (DP_CIPHER_CTX *) vctx;

    if (!digiprov_is_running())
        return NULL;

    status = DIGI_CALLOC((void **) &pRet, 1, sizeof(*pRet));
    if (OK != status)
        return NULL;

    *pRet = *pShell;

    /* set EvpCtx to NULL so old one doesn't get freed */
    pRet->pEvpCtx = NULL;

    if (!digiprov_cipher_newevp(&pRet->pEvpCtx))
    {
        (void) DIGI_MEMSET_FREE((ubyte **) &pRet, sizeof(*pRet));
        return NULL;
    }

    if (!DIGI_EVP_CIPHER_copyCtx(pShell->pEvpCtx, pRet->pEvpCtx))
    {
        (void) digiprov_cipher_generic_freectx((void *) pRet);
        return NULL;
    }
 
    return (void *) pRet;
}
