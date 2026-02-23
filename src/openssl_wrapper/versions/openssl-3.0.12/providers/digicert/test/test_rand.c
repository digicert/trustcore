/**
 * test_rand.c
 *
 * Test of the digicert OSSL 3.0 provider
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

#include "../../common/moptions.h"

#ifdef __ENABLE_DIGI_PROVIDER_TEST__

#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mdefs.h"
#include "../../common/mstdlib.h"
#include "../../crypto/hw_accel.h"
#include "../../crypto/crypto.h"
#include "../../crypto/aes.h"

#include "openssl/evp.h"
#include "openssl/provider.h"
#include "openssl/core_names.h"

#include <stdio.h>

int test_rand(OSSL_LIB_CTX *pLibCtx, const char *pRng, const char *pCipherOrDigest)
{
    MSTATUS status = ERR_GENERAL;
    int ret = 1;    
    unsigned char out[40] = {0}; 
    unsigned char zeros[40] = {0};
    sbyte4 cmp = 0;
 
    OSSL_PARAM params[2];
    EVP_RAND *rand = NULL;
    EVP_RAND_CTX *drbg = NULL;

    if (0 == DIGI_STRCMP("CTR-DRBG", pRng))
    {
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER, (char *) pCipherOrDigest, 0);
    }
    else
    {
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST, (char *) pCipherOrDigest, 0);
    }
    params[1] = OSSL_PARAM_construct_end();

    rand = EVP_RAND_fetch(pLibCtx, pRng, NULL);
    if (NULL == rand)
    {
        printf("ERROR EVP_RAND_fetch\n");
        goto exit;
    }

    drbg = EVP_RAND_CTX_new(rand, NULL);
    if (NULL == drbg)
    {
        printf("ERROR EVP_RAND_CTX_new\n");
        goto exit;
    }

    if (1 != EVP_RAND_CTX_set_params(drbg, params))
    {
        printf("ERROR EVP_RAND_CTX_set_params\n");
        goto exit;
    }
        
    if (1 != EVP_RAND_generate(drbg, out, sizeof(out), 1, 0, NULL, 0))
    {
        printf("ERROR EVP_RAND_generate\n");
        goto exit;
    }

    (void) DIGI_MEMCMP(out, zeros, sizeof(out), &cmp);

    if (cmp)
    {
        ret = 0;
    }
    else
    {
        printf("ERROR RNG returned just zeros.\n");
    }

exit:

    if (NULL != drbg)
    {
        EVP_RAND_CTX_free(drbg);
        drbg = NULL;
    }
    if (NULL != rand)
    {
        EVP_RAND_free(rand);    
    }

    return ret;
}
#endif
