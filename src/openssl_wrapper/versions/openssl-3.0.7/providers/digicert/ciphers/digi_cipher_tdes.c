/*
 * digi_cipher_tdes.c
 *
 * TDES implementations for OSSL 3.0 provider ADAPTED FROM openssl code
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

#define TDES_FLAGS 0

int digiprov_tdes_set_mode(void *vctx, size_t kbits, size_t ivbits, unsigned int mode)
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
                    pCtx->key_len = 128/8;
                    pCipher->nid = NID_des_ede_ecb;
                    break;
                case 192:
                    pCtx->key_len = 192/8;
                    pCipher->nid = NID_des_ede3_ecb;
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
                    pCtx->key_len = 128/8;
                    pCipher->nid = NID_des_ede_cbc;
                    break;
                case 192:
                    pCtx->key_len = 192/8;
                    pCipher->nid = NID_des_ede3_cbc;
                    break;
                default:
                    return 0;
            }
            pShell->need_iv = 0; /* KRB5KDF uses DES-EDE3-CBC with its own IV generation */
            pShell->need_dir = 1;
            break;
        default:
            return 0;
    }

    return 1;
}

/* digiprov_tdes192ecb_functions */
IMPLEMENT_generic_cipher(tdes, EDE3, ecb, ECB, TDES_FLAGS, 192, 64, 0, block);
/* digiprov_tdes192cbc_functions */
IMPLEMENT_generic_cipher(tdes, EDE3, cbc, CBC, TDES_FLAGS, 192, 64, 64, block);

/* digiprov_tdes128ecb_functions */
IMPLEMENT_generic_cipher(tdes, EDE2, ecb, ECB, TDES_FLAGS, 128, 64, 0, block);
/* digiprov_tdes128cbc_functions */
IMPLEMENT_generic_cipher(tdes, EDE2, cbc, CBC, TDES_FLAGS, 128, 64, 64, block);
