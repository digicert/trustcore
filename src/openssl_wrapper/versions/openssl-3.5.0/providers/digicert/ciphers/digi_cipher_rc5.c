/*
 * digi_cipher_rc5.c
 *
 * RC5 implementations for OSSL 3.0 provider ADAPTED FROM openssl code
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

/* Dispatch functions for RC5 cipher modes ecb, cbc, ofb, cfb */

/*
 * RC5 low level APIs are deprecated for public use, but still ok for internal
 * use.
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
#include "openssl/proverr.h"
#include "digi_ciphercommon.h"
#include "digiprov.h"
#include "internal/deprecated.h"

#define RC5_FLAGS PROV_CIPHER_FLAG_VARIABLE_LENGTH
int DIGI_EVP_RC5_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

/* RC4 is a stream cipher, there is no "mode" but we use CTR as a placeholder */
int digiprov_rc5_set_mode(void *vctx, size_t kbits, size_t ivbits, unsigned int mode)
{
    DP_CIPHER_CTX *pShell = (DP_CIPHER_CTX *) vctx;
    EVP_CIPHER_CTX *pCtx = NULL;
    EVP_CIPHER *pCipher = NULL;

    if (NULL == vctx)
        return 0;
    
    pCtx = pShell->pEvpCtx;
    if (NULL == pCtx)
        return 0;

    pCtx->key_len = (int) kbits/8;
    pCtx->iv_len = (int) ivbits/8;

    pCipher = (EVP_CIPHER *) pCtx->cipher;
    if (NULL == pCipher)
        return 0;

    switch(mode)
    {
        case EVP_CIPH_ECB_MODE:
            pCipher->nid = NID_rc5_ecb;
            pCipher->iv_len = 0;
            pCipher->block_size = 8;
            pShell->need_iv = 0;
            pShell->need_dir = 1;
            break;
        
        case EVP_CIPH_CBC_MODE:
            pCipher->nid = NID_rc5_cbc;
            pCipher->iv_len = 8;
            pCipher->block_size = 8;
            pShell->need_iv = 1;
            pShell->need_dir = 1;
            break;
 
        default:
            return 0;
    }
    
    /* We also set a copy of the flag in the outer shell context */
    pShell->isRc5 = 1;

    return 1;
}

static void *digiprov_rc5_dupctx(void *ctx)
{
    MSTATUS status = OK;
    DP_CIPHER_CTX *pRet = NULL;
    DP_CIPHER_CTX *pShell = (DP_CIPHER_CTX *)ctx;

    if (!digiprov_is_running())
        return NULL;

    if (ctx == NULL)
        return NULL;

    status = DIGI_CALLOC((void **)&pRet, 1, sizeof(*pRet));
    if (OK != status)
        return NULL;

    *pRet = *pShell;

    pRet->pEvpCtx = NULL;
    
    if (!digiprov_cipher_newevp(&pRet->pEvpCtx))
    {
        (void)DIGI_MEMSET_FREE((ubyte **)&pRet, sizeof(*pRet));
        return NULL;
    }

    if (!digiprov_rc5_set_mode(pRet, pShell->keylen * 8, pShell->ivlen * 8, pShell->mode))
    {
        (void ) digiprov_cipher_generic_freectx((void *) pRet);
        return NULL;
    }

    if (!DIGI_EVP_RC5_ctrl(pShell->pEvpCtx, EVP_CTRL_COPY, 0, pRet->pEvpCtx))
    {
        (void) digiprov_cipher_generic_freectx((void *) pRet);
        return NULL;
    }

    return pRet;
}

/* Custom macro for RC5 with its own dupctx */
#define IMPLEMENT_rc5_cipher_func(alg, UCALG, lcmode, UCMODE, flags,    \
                                         kbits, blkbits, ivbits, typ)          \
const OSSL_DISPATCH digiprov_##alg##kbits##lcmode##_functions[] = {                \
    { OSSL_FUNC_CIPHER_NEWCTX,                                                 \
      (void (*)(void)) alg##_##kbits##_##lcmode##_newctx },                    \
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) digiprov_cipher_generic_freectx }, \
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void)) digiprov_##alg##_dupctx }, \
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))digiprov_cipher_generic_einit },\
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))digiprov_cipher_generic_dinit },\
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))digiprov_cipher_generic_##typ##_update },\
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))digiprov_cipher_generic_##typ##_final },  \
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))digiprov_cipher_generic_cipher },   \
    { OSSL_FUNC_CIPHER_GET_PARAMS,                                             \
      (void (*)(void)) alg##_##kbits##_##lcmode##_get_params },                \
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,                                         \
      (void (*)(void))digiprov_cipher_generic_get_ctx_params },                    \
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,                                         \
      (void (*)(void))digiprov_cipher_var_keylen_set_ctx_params },                 \
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,                                        \
      (void (*)(void))digiprov_cipher_generic_gettable_params },                   \
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,                                    \
      (void (*)(void))digiprov_cipher_generic_gettable_ctx_params },               \
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,                                    \
     (void (*)(void))digiprov_cipher_var_keylen_settable_ctx_params },             \
    { 0, NULL }                                                                \
};

#define IMPLEMENT_rc5_cipher(alg, UCALG, lcmode, UCMODE, flags, kbits,  \
                                    blkbits, ivbits, typ)                      \
IMPLEMENT_generic_cipher_genfn(alg, UCALG, lcmode, UCMODE, flags, kbits,       \
                               blkbits, ivbits, typ)                           \
IMPLEMENT_rc5_cipher_func(alg, UCALG, lcmode, UCMODE, flags, kbits,     \
                                 blkbits, ivbits, typ)

/* digiprov_rc5128ecb_functions */
IMPLEMENT_rc5_cipher(rc5, RC5, ecb, ECB, RC5_FLAGS, 128, 64, 0, block)
/* digiprov_rc5128cbc_functions */
IMPLEMENT_rc5_cipher(rc5, RC5, cbc, CBC, RC5_FLAGS, 128, 64, 64, block)

#if 0
/* digiprov_rc5128ofb64_functions */
IMPLEMENT_cipher(rc5, RC5, ofb64, OFB, RC5_FLAGS, 128, 8, 64, stream)
/* digiprov_rc5128cfb64_functions */
IMPLEMENT_cipher(rc5, RC5, cfb64,  CFB, RC5_FLAGS, 128, 8, 64, stream)
#endif
