/**
 * test_dsa_sign.c
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

#include "openssl/evp.h"
#include "openssl/provider.h"
#include "openssl/dsa.h"

#include <stdio.h>

int test_dsa_sign(OSSL_LIB_CTX *pLibCtx, int pbits, int qbits, const char *pDigest)
{
    MSTATUS status = ERR_GENERAL;
    EVP_MD_CTX *pMdCtx = NULL;
    EVP_MD *pMd = NULL;
    EVP_PKEY *key = NULL;
    size_t len = 0;
    unsigned char *pSig = NULL;
    unsigned char *pData = (unsigned char *)"0123456789012345";
    size_t dataLen = 16;
    unsigned int sigLen = 0;
    int gindex = 1;
    OSSL_PARAM params[5];
    EVP_PKEY *param_key = NULL;
    EVP_PKEY_CTX *keyCtx = NULL;
    EVP_PKEY_CTX *kg_ctx = NULL;
    /* ubyte pSeed[8] = {0xde, 0xca, 0xfc, 0x0f, 0xfe, 0xee, 0x12, 0x23}; */

    params[0] = OSSL_PARAM_construct_uint("pbits", &pbits);
    params[1] = OSSL_PARAM_construct_uint("qbits", &qbits);
    params[2] = OSSL_PARAM_construct_int("gindex", &gindex);
    params[3] = OSSL_PARAM_construct_utf8_string("digest", (char *) pDigest, 0);
    params[4] = OSSL_PARAM_construct_end();

    keyCtx = EVP_PKEY_CTX_new_from_name(pLibCtx, "DSA", NULL);
    if (NULL == keyCtx)
    {
        printf("ERROR fetching DSA algo\n");
        return 1;
    }

    if (1 != EVP_PKEY_paramgen_init(keyCtx))
    {
        printf("ERROR EVP_PKEY_paramgen_init\n");
        goto exit;
    }

    if (1 != EVP_PKEY_CTX_set_params(keyCtx, params))
    {
        printf("ERROR EVP_PKEY_CTX_set_params\n");
        goto exit;
    }

/*  We don't currently support seed setting 
    if (1 != EVP_PKEY_CTX_set_dsa_paramgen_seed(keyCtx, pSeed, sizeof(pSeed)))
    {
        printf("ERROR EVP_PKEY_CTX_set_dsa_paramgen_seed\n");
        goto exit;
    }
*/

    if (1 != EVP_PKEY_paramgen(keyCtx, &param_key))
    {
        printf("ERROR EVP_PKEY_paramgen\n");
        goto exit;
    }

    kg_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, param_key, NULL);
    if (NULL == kg_ctx)
    {
        printf("ERROR EVP_PKEY_CTX_new_from_pkey\n");
        goto exit;
    }
    
    if (1 != EVP_PKEY_keygen_init(kg_ctx))
    {
        printf("ERROR EVP_PKEY_keygen_init\n");
        goto exit;
    }

    if (1 != EVP_PKEY_generate(kg_ctx, &key))
    {
        printf("ERROR EVP_PKEY_generate\n");
        goto exit;
    }

    pMdCtx = EVP_MD_CTX_new();
    if (pMdCtx == NULL)
        goto exit;

    pMd = EVP_MD_fetch(pLibCtx, pDigest, NULL);
    if (pMd == NULL)
    {
        printf("ERROR fetching MD\n");
        goto exit;
    }
  
    if (1 != EVP_SignInit(pMdCtx, pMd))
    {
        printf("ERROR EVP signinit\n");
        goto exit;
    }

    if (1 != EVP_SignUpdate(pMdCtx, (const void *)pData, dataLen))
    {
        printf("ERROR EVP signupdate\n");
        goto exit;
    }

    if (1 != EVP_SignFinal(pMdCtx, NULL, &sigLen, key))
    {
        printf("ERROR EVP signfinal getting sig len\n");
        goto exit;
    }

    (void) DIGI_MALLOC((void **)&pSig, sigLen);
    if (NULL == pSig)
    {
        printf("ERROR DIGI_MALLOC\n");
        goto exit;
    }

    if (1 != EVP_SignFinal(pMdCtx, pSig, &sigLen, key))
    {
        printf("ERROR EVP signfinal\n");
        goto exit;
    }

    if(pMdCtx) EVP_MD_CTX_destroy(pMdCtx);

    pMdCtx = EVP_MD_CTX_new();
    if (pMdCtx == NULL)
        goto exit;

    if (1 != EVP_VerifyInit(pMdCtx, pMd))
    {
        printf("ERROR EVP EVP_VerifyInit\n");
        goto exit;
    }

    if (1 != EVP_VerifyUpdate(pMdCtx, (const void *)pData, dataLen))
    {
        printf("ERROR EVP EVP_VerifyUpdate\n");
        goto exit;
    }

    if (1 != EVP_VerifyFinal(pMdCtx, pSig, sigLen, key))
    {
        printf("ERROR EVP EVP_VerifyFinal\n");
        goto exit;
    }

    status = OK;

exit:

    if(pMdCtx) EVP_MD_CTX_destroy(pMdCtx);
    
    if (NULL != pSig)
    {
        DIGI_FREE((void **)&pSig);
    }
    if (NULL != keyCtx)
    {
        EVP_PKEY_CTX_free(keyCtx);
    }
    if (NULL != kg_ctx)
    {
        EVP_PKEY_CTX_free(kg_ctx);
    }
    if (NULL != pMd)
    {
        EVP_MD_free(pMd);
    }
    if (NULL != key)
    {
        EVP_PKEY_free(key);
    }
    if (NULL != param_key)
    {
        EVP_PKEY_free(param_key);
    }
    
    return (status == OK) ? 0 : 1;
}
#endif
