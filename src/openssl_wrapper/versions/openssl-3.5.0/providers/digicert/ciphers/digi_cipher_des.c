/*
 * digi_cipher_des.c
 *
 * DES implementations for OSSL 3.0 provider ADAPTED FROM openssl code
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
 * DES low level APIs are deprecated for public use, but still ok for internal
 * use.
 */
#define DES_FLAGS 0

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

int digiprov_des_set_mode(void *vctx, size_t kbits, size_t ivbits, unsigned int mode)
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
                case 64:
                    pCtx->key_len = 64/8;
                    pCipher->nid = NID_des_ecb;
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
                case 64:
                    pCtx->key_len = 64/8;
                    pCipher->nid = NID_des_cbc;
                    break;
                default:
                    return 0;         
            }
            pShell->need_iv = 1;
            pShell->need_dir = 1;
            break;
        default:
            return 0;
    }

    return 1;
}

/* digiprov_des_ecb_functions */
IMPLEMENT_generic_cipher(des, DES, ecb, ECB, DES_FLAGS, 64, 64, 0, block);
/* digiprov_des_cbc_functions */
IMPLEMENT_generic_cipher(des, DES, cbc, CBC, DES_FLAGS, 64, 64, 64, block);

#if 0
/* digiprov_des_ofb64_functions */
IMPLEMENT_des_cipher(des, ofb64, OFB, DES_FLAGS, 64, 8, 64, stream);
/* digiprov_des_cfb64_functions */
IMPLEMENT_des_cipher(des, cfb64, CFB, DES_FLAGS, 64, 8, 64, stream);
/* digiprov_des_cfb1_functions */
IMPLEMENT_des_cipher(des, cfb1, CFB, DES_FLAGS, 64, 8, 64, stream);
/* digiprov_des_cfb8_functions */
IMPLEMENT_des_cipher(des, cfb8, CFB, DES_FLAGS, 64, 8, 64, stream);
#endif
