/**
 * test_kdf.c
 *
 * Test of the digicert KDFs OSSL 3.0 provider
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
#include "openssl/kdf.h"
#include "openssl/provider.h"

#include <stdio.h>

int test_nist_kdf(OSSL_LIB_CTX *pLibCtx, char *pMode, char *pMac, char *pDigest)
{
    int ret = 0;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *ctx = NULL;
    size_t reqKeySize = 64;
    int funcRet;

    ubyte pKey[32] = {0x31,0x30,0x29,0x28,0x27,0x26,0x25,0x24,0x23,0x22,0x21,0x20,0x19,0x18,0x17,0x16,
                      0x15,0x14,0x13,0x12,0x11,0x10,0x09,0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x00};
    ubyte pSalt[16] = {0x31,0x30,0x29,0x28,0x27,0x26,0x25,0x24,0x15,0x14,0x13,0x12,0x11,0x10,0x09,0x08};
    ubyte pInfo[8] = {0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x00};
    ubyte pSeed[16] = {0x31,0x30,0x29,0x28,0x27,0x26,0x25,0x24,0x23,0x22,0x21,0x20,0x19,0x18,0x17,0x16};

    ubyte pOut[64] = {0};

    OSSL_PARAM params[8] = {0};

    params[0] = OSSL_PARAM_construct_utf8_string("mode", (char *) pMode, 0);
    params[1] = OSSL_PARAM_construct_utf8_string("mac", (char *) pMac, 0);
    params[2] = OSSL_PARAM_construct_octet_string("key", pKey, sizeof(pKey));
    params[3] = OSSL_PARAM_construct_octet_string("salt", pSalt, sizeof(pSalt));
    params[4] = OSSL_PARAM_construct_octet_string("info", pInfo, sizeof(pInfo));
    params[5] = OSSL_PARAM_construct_octet_string("seed", pSeed, sizeof(pSeed));

    if (0 == DIGI_STRCMP("HMAC", pMac))
    {
        params[6] = OSSL_PARAM_construct_utf8_string("digest", (char *) pDigest, 0);
        params[7] = OSSL_PARAM_construct_end();
    }
    else
    {
        params[6] = OSSL_PARAM_construct_end();
    }

    kdf = EVP_KDF_fetch(pLibCtx, "KBKDF", NULL);
    if (NULL == kdf)
    {
        printf("ERROR fetching nist-kdf (kbkdf) algo\n");
        ret = 1;
        goto exit;    
    }

    ctx = EVP_KDF_CTX_new(kdf);
    if (NULL == ctx)
    {
        printf("ERROR EVP_KDF_CTX_new\n");
        ret = 1;
        goto exit;         
    }

    funcRet = EVP_KDF_CTX_set_params(ctx, params);
#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
    if ( (1 == EVP_default_properties_is_fips_enabled(NULL)) &&
         (NULL != pDigest) )
    {
        if ( (0 == DIGI_STRCMP(pDigest, "MD4")) )
        {
            if (funcRet == 1)
            {
                printf("ERROR EVP_KDF_CTX_set_params FIPS expected failure\n");
                ret = 1;
            }
            goto exit;
        }
    }
#endif
    if (1 != funcRet)
    {
        printf("ERROR EVP_KDF_CTX_set_params\n");
        ret = 1;
        goto exit;
    }

    if (0 > EVP_KDF_derive(ctx, pOut, reqKeySize, NULL)) 
    {
        printf("ERROR EVP_KDF_derive\n");
        ret = 1;
        goto exit;
    }

    /* 3 select bytes being 0x00 still is enough to indicate a failure */
    if (0 == pOut[0] && 0 == pOut[1] && 0 == pOut[reqKeySize-1])
    {
        printf("ERROR NIST_KDF didn't derive a key\n");
        ret = 1;      
    }

exit:

    if (NULL != ctx)
        EVP_KDF_CTX_free(ctx);

    if (NULL != kdf)
        EVP_KDF_free(kdf);

    return ret;
}

int test_hmac_kdf(OSSL_LIB_CTX *pLibCtx, char *pMode, char *pDigest, ubyte4 digestOutLen)
{
    int ret = 0;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *ctx = NULL;
    int funcRet;

    ubyte pKey[32] = {0x31,0x30,0x29,0x28,0x27,0x26,0x25,0x24,0x23,0x22,0x21,0x20,0x19,0x18,0x17,0x16,
                      0x15,0x14,0x13,0x12,0x11,0x10,0x09,0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x00};
    ubyte pSalt[16] = {0x31,0x30,0x29,0x28,0x27,0x26,0x25,0x24,0x15,0x14,0x13,0x12,0x11,0x10,0x09,0x08};
    ubyte pPrefix[16] = {0x31,0x30,0x29,0x28,0x27,0x26,0x25,0x24,0x23,0x22,0x21,0x20,0x19,0x18,0x17,0x16};

    ubyte pOut[64] = {0};

    OSSL_PARAM params[6] = {0};

    params[0] = OSSL_PARAM_construct_utf8_string("mode", (char *) pMode, 0);
    params[1] = OSSL_PARAM_construct_utf8_string("digest", (char *) pDigest, 0);
    params[2] = OSSL_PARAM_construct_octet_string("key", pKey, sizeof(pKey));
    params[3] = OSSL_PARAM_construct_octet_string("salt", pSalt, sizeof(pSalt));
    params[4] = OSSL_PARAM_construct_octet_string("prefix", pPrefix, sizeof(pPrefix));
    params[5] = OSSL_PARAM_construct_end();

    kdf = EVP_KDF_fetch(pLibCtx, "HKDF", NULL);
    if (NULL == kdf)
    {
        printf("ERROR fetching hmac-kdf (hkdf) algo\n");
        ret = 1;
        goto exit;    
    }

    ctx = EVP_KDF_CTX_new(kdf);
    if (NULL == ctx)
    {
        printf("ERROR EVP_KDF_CTX_new\n");
        ret = 1;
        goto exit;         
    }

    funcRet = EVP_KDF_CTX_set_params(ctx, params);
#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
    if ( (1 == EVP_default_properties_is_fips_enabled(NULL)) &&
         (NULL != pDigest) )
    {
        if ( (0 == DIGI_STRCMP(pDigest, "MD4")) )
        {
            if (funcRet == 1)
            {
                printf("ERROR EVP_KDF_CTX_set_params FIPS expected failure\n");
                ret = 1;
            }
            goto exit;
        }
    }
#endif
    if (1 != funcRet)
    {
        printf("ERROR EVP_KDF_CTX_set_params\n");
        ret = 1;
        goto exit;
    }

    if (0 == DIGI_STRCMP("EXTRACT_ONLY", pMode))
    {
        if (0 > EVP_KDF_derive(ctx, pOut, (size_t) digestOutLen, NULL)) 
        {
            printf("ERROR EVP_KDF_derive\n");
            ret = 1;
            goto exit;
        }

        /* 3 select bytes being 0x00 still is enough to indicate a failure */
        if (0 == pOut[0] && 0 == pOut[1] && 0 == pOut[digestOutLen-1])
        {
            printf("ERROR HMAC_KDF EXTRACT ONLY didn't derive a key\n");
            ret = 1;      
        }
    }
    else /* We can do multiple calls of arb length */
    {
        if (0 > EVP_KDF_derive(ctx, pOut, 20, NULL)) 
        {
            printf("ERROR EVP_KDF_derive\n");
            ret = 1;
            goto exit;
        }

        if (0 > EVP_KDF_derive(ctx, pOut + 20, 44, NULL)) 
        {
            printf("ERROR EVP_KDF_derive\n");
            ret = 1;
            goto exit;
        }

        /* 3 select bytes being 0x00 still is enough to indicate a failure */
        if (0 == pOut[0] && 0 == pOut[20] && 0 == pOut[63])
        {
            printf("ERROR HMAC_KDF didn't derive a key\n");
            ret = 1;      
        }
    }

exit:

    if (NULL != ctx)
        EVP_KDF_CTX_free(ctx);

    if (NULL != kdf)
        EVP_KDF_free(kdf);

    return ret;
}

int test_x963_kdf(OSSL_LIB_CTX *pLibCtx, char *pDigest)
{
    int ret = 0;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *ctx = NULL;
    int funcRet;

    ubyte pSecret[32] = {0x31,0x30,0x29,0x28,0x27,0x26,0x25,0x24,0x23,0x22,0x21,0x20,0x19,0x18,0x17,0x16,
                      0x15,0x14,0x13,0x12,0x11,0x10,0x09,0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x00};
    ubyte pInfo[16] = {0x31,0x30,0x29,0x28,0x27,0x26,0x25,0x24,0x15,0x14,0x13,0x12,0x11,0x10,0x09,0x08};
    ubyte pOut[64] = {0};

    OSSL_PARAM params[4] = {0};

    params[0] = OSSL_PARAM_construct_utf8_string("digest", (char *) pDigest, 0);
    params[1] = OSSL_PARAM_construct_octet_string("secret", pSecret, sizeof(pSecret));
    params[2] = OSSL_PARAM_construct_octet_string("info", pInfo, sizeof(pInfo));
    params[3] = OSSL_PARAM_construct_end();

    kdf = EVP_KDF_fetch(pLibCtx, "X963KDF", NULL);
    if (NULL == kdf)
    {
        printf("ERROR fetching hmac-kdf (hkdf) algo\n");
        ret = 1;
        goto exit;    
    }

    ctx = EVP_KDF_CTX_new(kdf);
    if (NULL == ctx)
    {
        printf("ERROR EVP_KDF_CTX_new\n");
        ret = 1;
        goto exit;         
    }

    funcRet = EVP_KDF_CTX_set_params(ctx, params);
#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
    if ( (1 == EVP_default_properties_is_fips_enabled(NULL)) &&
         (NULL != pDigest) )
    {
        if ( (0 == DIGI_STRCMP(pDigest, "MD4")) )
        {
            if (funcRet == 1)
            {
                printf("ERROR EVP_KDF_CTX_set_params FIPS expected failure\n");
                ret = 1;
            }
            goto exit;
        }
    }
#endif
    if (1 != funcRet)
    {
        printf("ERROR EVP_KDF_CTX_set_params\n");
        ret = 1;
        goto exit;
    }

    if (0 > EVP_KDF_derive(ctx, pOut, 20, NULL)) 
    {
        printf("ERROR EVP_KDF_derive\n");
        ret = 1;
        goto exit;
    }

    if (0 > EVP_KDF_derive(ctx, pOut + 20, 44, NULL)) 
    {
        printf("ERROR EVP_KDF_derive\n");
        ret = 1;
        goto exit;
    }

    /* 3 select bytes being 0x00 still is enough to indicate a failure */
    if (0 == pOut[0] && 0 == pOut[20] && 0 == pOut[63])
    {
        printf("ERROR X963 didn't derive a key\n");
        ret = 1;      
    }

exit:

    if (NULL != ctx)
        EVP_KDF_CTX_free(ctx);

    if (NULL != kdf)
        EVP_KDF_free(kdf);

    return ret;
}
#endif
