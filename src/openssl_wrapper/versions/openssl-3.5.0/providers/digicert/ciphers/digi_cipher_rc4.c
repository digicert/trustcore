/*
 * digi_cipher_rc4.c
 *
 * RC4 implementations for OSSL 3.0 provider ADAPTED FROM openssl code
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

/* Dispatch functions for RC4 ciphers */

/*
 * RC4 low level APIs are deprecated for public use, but still ok for internal
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

#define RC4_FLAGS PROV_CIPHER_FLAG_VARIABLE_LENGTH

/* RC4 is a stream cipher, there is no "mode" but we use CTR as a placeholder */
int digiprov_rc4_set_mode(void *vctx, size_t kbits, size_t ivbits, unsigned int mode)
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
        case EVP_CIPH_CTR_MODE:
            switch (kbits)
            {
                case 40:
                    pCtx->key_len = 40/8;
                    pCipher->nid = NID_rc4_40;
                    break;
                case 128:
                    pCtx->key_len = 128/8;
                    pCipher->nid = NID_rc4;
                    break;
                default:
                    return 0;         
            }
            pShell->need_iv = 0;
            pShell->need_dir = 0;
            break;
 
        default:
            return 0;
    }

    return 1;
}

/* ossl_rc440_functions */
IMPLEMENT_var_keylen_cipher(rc4, RC4, ctr, CTR, RC4_FLAGS, 40, 8, 0, stream)
/* ossl_rc4128_functions */
IMPLEMENT_var_keylen_cipher(rc4, RC4, ctr, CTR, RC4_FLAGS, 128, 8, 0, stream)
