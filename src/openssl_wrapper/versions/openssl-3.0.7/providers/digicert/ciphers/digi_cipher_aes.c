/*
 * digi_cipher_aes.c
 *
 * AES implementations for OSSL 3.0 provider ADAPTED FROM openssl code
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

#define AES_XTS_FLAGS PROV_CIPHER_FLAG_CUSTOM_IV

int digiprov_aes_set_mode(void *vctx, size_t kbits, size_t ivbits, unsigned int mode)
{
    DP_CIPHER_CTX *pShell = (DP_CIPHER_CTX *) vctx;
    EVP_CIPHER_CTX *pCtx = NULL;
    EVP_CIPHER *pCipher = NULL;
    
    if (NULL == vctx)
        return 0;
    
    pCtx = pShell->pEvpCtx;
    if (NULL == pCtx)
        return 0;

    pCtx->iv_len = (int) ivbits/8;
    
    pCipher = (EVP_CIPHER *) pCtx->cipher;
    if (NULL == pCipher)
        return 0;

    switch(mode)
    {
        case EVP_CIPH_ECB_MODE:
            switch (kbits)
            {
                case 128:
                    pCtx->key_len = MOC_AES_128_KEY_LEN;
                    pCipher->nid = NID_aes_128_ecb;
                    break;
                case 192:
                    pCtx->key_len = MOC_AES_192_KEY_LEN;
                    pCipher->nid = NID_aes_192_ecb;
                    break;
                case 256:
                    pCtx->key_len = MOC_AES_256_KEY_LEN;
                    pCipher->nid = NID_aes_256_ecb;
                    break;   
                default:
                    return 0;         
            }
            pShell->need_iv = 0;
            pShell->need_dir = 1;
            break;

        case EVP_CIPH_CBC_MODE:
            switch (kbits)
            {
                case 128:
                    pCtx->key_len = MOC_AES_128_KEY_LEN;
                    pCipher->nid = NID_aes_128_cbc;
                    break;
                case 192:
                    pCtx->key_len = MOC_AES_192_KEY_LEN;
                    pCipher->nid = NID_aes_192_cbc;
                    break;
                case 256:
                    pCtx->key_len = MOC_AES_256_KEY_LEN;
                    pCipher->nid = NID_aes_256_cbc;
                    break; 
                default:
                    return 0;              
            }
            pShell->need_iv = 0; /* KRB5KDF uses AES-CBC with its own IV generation */
            pShell->need_dir = 1;
            break;

        case EVP_CIPH_OFB_MODE:
            switch (kbits)
            {
                case 128:
                    pCtx->key_len = MOC_AES_128_KEY_LEN;
                    pCipher->nid = NID_aes_128_ofb128;
                    break;
                case 192:
                    pCtx->key_len = MOC_AES_192_KEY_LEN;
                    pCipher->nid = NID_aes_192_ofb128;
                    break;
                case 256:
                    pCtx->key_len = MOC_AES_256_KEY_LEN;
                    pCipher->nid = NID_aes_256_ofb128;
                    break;
                default:
                    return 0; 
            }
            pShell->need_iv = 1;
            pShell->need_dir = 0;
            break;

        case EVP_CIPH_CFB_MODE:
            switch (kbits)
            {
                case 128:
                    pCtx->key_len = MOC_AES_128_KEY_LEN;
                    pCipher->nid = NID_aes_128_cfb128;
                    break;
                case 192:
                    pCtx->key_len = MOC_AES_192_KEY_LEN;
                    pCipher->nid = NID_aes_192_cfb128;
                    break;
                case 256:
                    pCtx->key_len = MOC_AES_256_KEY_LEN;
                    pCipher->nid = NID_aes_256_cfb128;
                    break;  
                default:
                    return 0;             
            }
            pShell->need_iv = 1;
            pShell->need_dir = 0;
            break;

        case EVP_CIPH_CTR_MODE:
            switch (kbits)
            {
                case 128:
                    pCtx->key_len = MOC_AES_128_KEY_LEN;
                    pCipher->nid = NID_aes_128_ctr;
                    break;
                case 192:
                    pCtx->key_len = MOC_AES_192_KEY_LEN;
                    pCipher->nid = NID_aes_192_ctr;
                    break;
                case 256:
                    pCtx->key_len = MOC_AES_256_KEY_LEN;
                    pCipher->nid = NID_aes_256_ctr;
                    break;   
                default:
                    return 0;         
            }
            pShell->need_iv = 1;
            pShell->need_dir = 0;
            break;

        case EVP_CIPH_XTS_MODE:
            switch (kbits)
            {
                case 256:
                    pCtx->key_len = 2 * MOC_AES_128_KEY_LEN;
                    pCipher->nid = NID_aes_128_xts;
                    break;
                case 512:
                    pCtx->key_len = 2 * MOC_AES_256_KEY_LEN;
                    pCipher->nid = NID_aes_256_xts;
                    break;   
                default:
                    return 0;         
            }
            pShell->need_iv = 1;
            pShell->need_dir = 1;
            break;

        case EVP_CIPH_WRAP_MODE:
            switch (kbits)
            {
                case 128:
                    pCtx->key_len = MOC_AES_128_KEY_LEN;
                    pCipher->nid = NID_id_aes128_wrap;
                    break;
                case 192:
                    pCtx->key_len = MOC_AES_192_KEY_LEN;
                    pCipher->nid = NID_id_aes192_wrap;
                    break;
                case 256:
                    pCtx->key_len = MOC_AES_256_KEY_LEN;
                    pCipher->nid = NID_id_aes256_wrap;
                    break;   
                default:
                    return 0;         
            }
            pShell->need_iv = 0;
            pShell->need_dir = 1;
            break;

        default:
            return 0;
    }

    return 1;
}

/* digiprov_aes256ecb_functions */
IMPLEMENT_generic_cipher(aes, AES, ecb, ECB, 0, 256, 128, 0, block)
/* digiprov_aes192ecb_functions */
IMPLEMENT_generic_cipher(aes, AES, ecb, ECB, 0, 192, 128, 0, block)
/* digiprov_aes128ecb_functions */
IMPLEMENT_generic_cipher(aes, AES, ecb, ECB, 0, 128, 128, 0, block)
/* digiprov_aes256cbc_functions */
IMPLEMENT_generic_cipher(aes, AES, cbc, CBC, 0, 256, 128, 128, block)
/* digiprov_aes192cbc_functions */
IMPLEMENT_generic_cipher(aes, AES, cbc, CBC, 0, 192, 128, 128, block)
/* digiprov_aes128cbc_functions */
IMPLEMENT_generic_cipher(aes, AES, cbc, CBC, 0, 128, 128, 128, block)
/* digiprov_aes256ofb_functions */
IMPLEMENT_generic_cipher(aes, AES, ofb, OFB, 0, 256, 8, 128, stream)
/* digiprov_aes192ofb_functions */
IMPLEMENT_generic_cipher(aes, AES, ofb, OFB, 0, 192, 8, 128, stream)
/* digiprov_aes128ofb_functions */
IMPLEMENT_generic_cipher(aes, AES, ofb, OFB, 0, 128, 8, 128, stream)
/* digiprov_aes256cfb_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb,  CFB, 0, 256, 8, 128, stream)
/* digiprov_aes192cfb_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb,  CFB, 0, 192, 8, 128, stream)
/* digiprov_aes128cfb_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb,  CFB, 0, 128, 8, 128, stream)
/* digiprov_aes256cfb1_functions */
#if 0
IMPLEMENT_generic_cipher(aes, AES, cfb1, CFB, 0, 256, 8, 128, stream)
/* digiprov_aes192cfb1_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb1, CFB, 0, 192, 8, 128, stream)
/* digiprov_aes128cfb1_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb1, CFB, 0, 128, 8, 128, stream)
/* digiprov_aes256cfb8_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb8, CFB, 0, 256, 8, 128, stream)
/* digiprov_aes192cfb8_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb8, CFB, 0, 192, 8, 128, stream)
/* digiprov_aes128cfb8_functions */
IMPLEMENT_generic_cipher(aes, AES, cfb8, CFB, 0, 128, 8, 128, stream)

#endif
/* digiprov_aes256ctr_functions */
IMPLEMENT_generic_cipher(aes, AES, ctr, CTR, 0, 256, 8, 128, stream)
/* digiprov_aes192ctr_functions */
IMPLEMENT_generic_cipher(aes, AES, ctr, CTR, 0, 192, 8, 128, stream)
/* digiprov_aes128ctr_functions */
IMPLEMENT_generic_cipher(aes, AES, ctr, CTR, 0, 128, 8, 128, stream)

/* XTS requires 2 keys, so kbits is double the usual value */

/* digiprov aes512xts_functions */
IMPLEMENT_generic_cipher(aes, AES, xts, XTS, AES_XTS_FLAGS, 512, 8, 128, stream)
/* digiprov aes256xts_functions */
IMPLEMENT_generic_cipher(aes, AES, xts, XTS, AES_XTS_FLAGS, 256, 8, 128, stream)

/* #include "cipher_aes_cts.inc" Cipher Text Stealing not supported */
