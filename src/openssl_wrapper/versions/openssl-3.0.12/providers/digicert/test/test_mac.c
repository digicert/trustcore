/**
 * test_mac.c
 *
 * Test of the digicert MACs OSSL 3.0 provider
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

#include "openssl/evp.h"
#include "openssl/provider.h"

#include <stdio.h>

int test_mac(OSSL_LIB_CTX *pLibCtx, char *pAlg, char *pDigest)
{
    MSTATUS status = ERR_GENERAL;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *ctx = NULL;
    int ret = 0;
    unsigned char pKey[32] = {0};
    size_t keylen = 32;
    unsigned char *pSig = NULL;
    unsigned char *pData = (unsigned char *)"012345678901234501234567890123450123456789012345";
    size_t dataLen = 48;
    size_t sigLen = 0;
    int i = 0;
    int funcRet;

    OSSL_PARAM params[2] = {0};

    if (0 == DIGI_STRCMP("HMAC", pAlg))
    {
        params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *) pDigest, 0);
        params[1] = OSSL_PARAM_construct_end();
    }
    else
    {
        params[0] = OSSL_PARAM_construct_end();
    }

    for (i = 0; i < keylen; i++)
    {
        pKey[i] = (ubyte)(i+2 & 0xff);
    }

    mac = EVP_MAC_fetch(pLibCtx, pAlg, NULL);
    if (NULL == mac)
    {
        printf("ERROR fetching mac algo\n");
        ret = 1;
        goto exit;
    }    

    ctx = EVP_MAC_CTX_new(mac);
    if (NULL == ctx)
    {
        printf("ERROR fetching mac ctx\n");
        ret = 1;
        goto exit;
    }  

    funcRet = EVP_MAC_init(ctx, (unsigned char *) pKey, keylen, params);
#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
    if ( (1 == EVP_default_properties_is_fips_enabled(NULL)) &&
         (NULL != pDigest) )
    {
        if ( (0 == DIGI_STRCMP(pDigest, "MD4")) )
        {
            if (funcRet == 1)
            {
                printf("ERROR EVP_MAC_init FIPS expected failure\n");
                ret = 1;
            }
            goto exit;
        }
    }
#endif
    if (1 != funcRet)
    {
        printf("ERROR EVP_MAC_init\n");
        ret = 1;
        goto exit;
    }

    if (1 != EVP_MAC_update(ctx, pData, dataLen))
    {
        printf("ERROR EVP_MAC_update\n");
        ret = 1;
        goto exit;     
    }

    if (1 != EVP_MAC_final(ctx, NULL, &sigLen, 0))
    {
        printf("ERROR EVP_MAC_final\n");
        ret = 1;
        goto exit;
    }

    if (OK != DIGI_MALLOC((void **) &pSig, sigLen))
    {
        printf("ERROR DIGI_MALLOC\n");
        ret = 1;
        goto exit;
    }

    if (1 != EVP_MAC_final(ctx, pSig, &sigLen, sigLen))
    {
        printf("ERROR EVP_MAC_final\n");
        ret = 1;
    }

exit:

    if (NULL != pSig)
    {
        DIGI_FREE((void **)&pSig);
    }
    if (NULL != mac)
    {
        EVP_MAC_free(mac);
    }
    if (NULL != ctx)
    {
        EVP_MAC_CTX_free(ctx);
    }

    return ret;
}
#endif
