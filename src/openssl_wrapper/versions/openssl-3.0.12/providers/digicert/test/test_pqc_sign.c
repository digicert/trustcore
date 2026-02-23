/**
 * test_pqc_sign.c
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

#if defined(__ENABLE_DIGI_PROVIDER_TEST__) && defined(__ENABLE_DIGICERT_PQC__)

#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mdefs.h"
#include "../../common/mstdlib.h"

#include "openssl/evp.h"
#include "openssl/provider.h"
#include "openssl/pem.h"
#include "openssl/core_names.h"
#include "internal/deprecated.h"

#include <stdio.h>

int test_pqc_sign_standard(OSSL_LIB_CTX *pLibCtx, const char *pAlg)
{
    MSTATUS status = ERR_GENERAL;
    EVP_PKEY *pSignKey = NULL;
    EVP_PKEY *pVKey = NULL;
    int ret = 0;
    unsigned char *pSig = NULL;
    unsigned char *pData = (unsigned char *)"0123456789012345";
    size_t dataLen = 16;
    size_t sigLen = 0;
    OSSL_PARAM params[2];
    char pPub[2592]; /* big enough for all modes */ 
    EVP_PKEY_CTX *pSignCtx = NULL;
    EVP_PKEY_CTX *pVCtx = NULL;
    
    EVP_PKEY_CTX *pGenCtx = EVP_PKEY_CTX_new_from_name(pLibCtx, pAlg, NULL);
    if (NULL == pGenCtx)
    {
        printf("ERROR fetching %s algo\n", pAlg);
        goto exit;
    }

    if (1 != EVP_PKEY_keygen_init(pGenCtx))
    {
        printf("ERROR EVP_PKEY_keygen_init\n");
        goto exit;
    }

    if (1 != EVP_PKEY_keygen(pGenCtx, &pSignKey))
    {
        printf("ERROR EVP_PKEY_keygen\n");
        goto exit;
    }

    pSignCtx = EVP_PKEY_CTX_new(pSignKey, NULL);
    if (NULL == pSignCtx)
    {
        printf("ERROR fetching %s algo\n", pAlg);
        goto exit;
    }

    if (1 != EVP_PKEY_sign_init(pSignCtx))
    {
        printf("ERROR EVP_PKEY_sign_init\n");
        goto exit;        
    }

    if (1 != EVP_PKEY_sign(pSignCtx, NULL, &sigLen, pData, dataLen))
    {
        printf("ERROR EVP_PKEY_sign\n");
        goto exit;
    }

    (void) DIGI_MALLOC((void **)&pSig, sigLen);
    if (NULL == pSig)
    {
        printf("ERROR DIGI_MALLOC\n");
        goto exit;
    }

    if (1 != EVP_PKEY_sign(pSignCtx, pSig, &sigLen, pData, dataLen))
    {
        printf("ERROR EVP_PKEY_sign\n");
        goto exit;
    }

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pPub, sizeof(pPub));
    params[1] = OSSL_PARAM_construct_end();

    if (1 != EVP_PKEY_get_params(pSignKey, params))
    {
        printf("ERROR EVP_PKEY_get_params\n");
        goto exit;
    }

    params[0].data_size = params[0].return_size;

    /* Done with pSignKey, now set the params in a public key */
    pVKey = EVP_PKEY_new_raw_public_key_ex(pLibCtx, pAlg, NULL, pPub, params[0].return_size);
    if (NULL == pVKey)
    {
        printf("ERROR fetching %s algo\n", pAlg);
        goto exit; 
    }

    pVCtx = EVP_PKEY_CTX_new(pVKey, NULL);
    if (NULL == pVCtx)
    {
        printf("ERROR fetching %s algo\n", pAlg);
        goto exit;
    }

    if (1 != EVP_PKEY_verify_init(pVCtx))
    {
        printf("ERROR EVP_PKEY_verify_init\n");
        goto exit;        
    }

    if (1 != EVP_PKEY_verify(pVCtx, pSig, sigLen, pData, dataLen))
    {
        printf("ERROR EVP_PKEY_verify\n");
        goto exit;
    }

    status = OK;

exit:

    if (NULL != pSig)
    {
        DIGI_FREE((void **)&pSig);
    }
    if (NULL != pGenCtx)
    {
        EVP_PKEY_CTX_free(pGenCtx);
    }
    if (NULL != pSignCtx)
    {
        EVP_PKEY_CTX_free(pSignCtx);
    }
    if (NULL != pVCtx)
    {
        EVP_PKEY_CTX_free(pVCtx);
    }
    if (NULL != pSignKey)
    {
        EVP_PKEY_free(pSignKey);
    }
    if (NULL != pVKey)
    {
        EVP_PKEY_free(pVKey);
    }

    return (status == OK) ? 0 : 1;
}

int test_pqc_sign_one_key(OSSL_LIB_CTX *pLibCtx, const char *pAlg)
{
    MSTATUS status = ERR_GENERAL;
    EVP_PKEY *pKey = NULL;
    int ret = 0;
    unsigned char *pSig = NULL;
    unsigned char *pData = (unsigned char *)"0123456789012345";
    size_t dataLen = 16;
    size_t sigLen = 0;
    EVP_PKEY_CTX *pCtx = NULL;
    
    EVP_PKEY_CTX *pGenCtx = EVP_PKEY_CTX_new_from_name(pLibCtx, pAlg, NULL);
    if (NULL == pGenCtx)
    {
        printf("ERROR fetching %s algo\n", pAlg);
        goto exit;
    }

    if (1 != EVP_PKEY_keygen_init(pGenCtx))
    {
        printf("ERROR EVP_PKEY_keygen_init\n");
        goto exit;
    }

    if (1 != EVP_PKEY_keygen(pGenCtx, &pKey))
    {
        printf("ERROR EVP_PKEY_keygen\n");
        goto exit;
    }

    /* key is no longer associated with pGenCtx, so we make a new EVP_CTX */
    pCtx = EVP_PKEY_CTX_new(pKey, NULL);
    if (NULL == pCtx)
    {
        printf("ERROR fetching %s algo\n", pAlg);
        goto exit;
    }

    if (1 != EVP_PKEY_sign_init(pCtx))
    {
        printf("ERROR EVP_PKEY_sign_init\n");
        goto exit;        
    }

    if (1 != EVP_PKEY_sign(pCtx, NULL, &sigLen, pData, dataLen))
    {
        printf("ERROR EVP_PKEY_sign\n");
        goto exit;
    }

    (void) DIGI_MALLOC((void **)&pSig, sigLen);
    if (NULL == pSig)
    {
        printf("ERROR DIGI_MALLOC\n");
        goto exit;
    }

    if (1 != EVP_PKEY_sign(pCtx, pSig, &sigLen, pData, dataLen))
    {
        printf("ERROR EVP_PKEY_sign\n");
        goto exit;
    }

    /* Use the same ctx (and key) to verify */
    if (1 != EVP_PKEY_verify_init(pCtx))
    {
        printf("ERROR EVP_PKEY_verify_init\n");
        goto exit;        
    }

    if (1 != EVP_PKEY_verify(pCtx, pSig, sigLen, pData, dataLen))
    {
        printf("ERROR EVP_PKEY_verify\n");
        goto exit;
    }

    status = OK;

exit:

    if (NULL != pSig)
    {
        DIGI_FREE((void **)&pSig);
    }
    if (NULL != pGenCtx)
    {
        EVP_PKEY_CTX_free(pGenCtx);
    }
    if (NULL != pCtx)
    {
        EVP_PKEY_CTX_free(pCtx);
    }
    if (NULL != pKey)
    {
        EVP_PKEY_free(pKey);
    }

    return (status == OK) ? 0 : 1;
}

int test_pqc_sign_digest_standard(OSSL_LIB_CTX *pLibCtx, const char *pAlg, const char *pDigest, byteBoolean setPubImmediate)
{
    MSTATUS status = ERR_GENERAL;
    EVP_PKEY *pSignKey = NULL;
    EVP_PKEY *pVKey = NULL;
    EVP_MD_CTX *pMdCtx = NULL;
    EVP_MD *pMd = NULL;
    int ret = 0;
    unsigned char *pSig = NULL;
    unsigned char *pData = (unsigned char *)"0123456789012345";
    size_t dataLen = 16;
    unsigned int sigLen = 0;
    OSSL_PARAM params[2];
    char pPub[2592]; /* big enough for all modes TODO CHANGE FOR SLH-DSA */ 

    EVP_PKEY_CTX *pGenCtx = EVP_PKEY_CTX_new_from_name(pLibCtx, pAlg, NULL);
    if (NULL == pGenCtx)
    {
        printf("ERROR fetching %s algo\n", pAlg);
        goto exit;
    }

    if (1 != EVP_PKEY_keygen_init(pGenCtx))
    {
        printf("ERROR EVP_PKEY_keygen_init\n");
        goto exit;
    }

    if (1 != EVP_PKEY_keygen(pGenCtx, &pSignKey))
    {
        printf("ERROR EVP_PKEY_keygen\n");
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

    if (1 != EVP_SignFinal(pMdCtx, NULL, &sigLen, pSignKey))
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

    if (1 != EVP_SignFinal(pMdCtx, pSig, &sigLen, pSignKey))
    {
        printf("ERROR EVP signfinal\n");
        goto exit;
    }

    if(pMdCtx) EVP_MD_CTX_destroy(pMdCtx);

    pMdCtx = EVP_MD_CTX_new();
    if (pMdCtx == NULL)
        goto exit;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pPub, sizeof(pPub));
    params[1] = OSSL_PARAM_construct_end();

    if (1 != EVP_PKEY_get_params(pSignKey, params))
    {
        printf("ERROR EVP_PKEY_get_params\n");
        goto exit;
    }

    params[0].data_size = params[0].return_size;

    if (setPubImmediate)
    {
        /* Done with pSignKey, now set the params in a public key */
        pVKey = EVP_PKEY_new_raw_public_key_ex(pLibCtx, pAlg, NULL, pPub, params[0].data_size);
        if (NULL == pVKey)
        {
            printf("ERROR fetching %s algo and setting pub immediately\n", pAlg);
            goto exit; 
        }
    }
    else
    {
        pVKey = EVP_PKEY_new_raw_public_key_ex(pLibCtx, pAlg, NULL, NULL, 0);
        if (NULL == pVKey)
        {
            printf("ERROR fetching %s algo for new public key\n", pAlg);
            goto exit; 
        }

        if (1 != EVP_PKEY_set_params(pVKey, params))
        {
            printf("ERROR EVP_PKEY_CTX_set_params\n");
            goto exit;
        }
    }

    if (1 != EVP_VerifyInit(pMdCtx, pMd))
    {
        printf("ERROR EVP verifyinit\n");
        goto exit;
    }

    if (1 != EVP_VerifyUpdate(pMdCtx, (const void *)pData, dataLen))
    {
        printf("ERROR EVP verifyupdate\n");
        goto exit;
    }

    if (1 != EVP_VerifyFinal(pMdCtx, pSig, sigLen, pVKey))
    {
        printf("ERROR EVP verifyfinal\n");
        goto exit;
    }

    status = OK;

exit:

    if (NULL != pSig)
    {
        DIGI_FREE((void **)&pSig);
    }
    if (NULL != pGenCtx)
    {
        EVP_PKEY_CTX_free(pGenCtx);
    }
    if (NULL != pSignKey)
    {
        EVP_PKEY_free(pSignKey);
    }
    if (NULL != pVKey)
    {
        EVP_PKEY_free(pVKey);
    }
    if( NULL != pMdCtx) 
    {
        EVP_MD_CTX_destroy(pMdCtx);
    }
    if (NULL != pMd)
    {
        EVP_MD_free(pMd);
    }

    return (status == OK) ? 0 : 1;
}

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
int test_pqc_sign_import_export(OSSL_LIB_CTX *pLibCtx, const char *pAlg, int selection)
{
    MSTATUS status = ERR_GENERAL;
    EVP_PKEY *pKey = NULL;
    int ret = 1;
    OSSL_PARAM *pParams = NULL;
    EVP_PKEY_CTX *pRecCtx = NULL;
    EVP_PKEY_CTX *pValidateCtx = NULL;
    EVP_PKEY *pRecKey = NULL;

    EVP_PKEY_CTX *pGenCtx = EVP_PKEY_CTX_new_from_name(pLibCtx, pAlg, NULL);
    if (NULL == pGenCtx)
    {
        printf("ERROR fetching %s algo\n", pAlg);
        goto exit;
    }

    if (1 != EVP_PKEY_keygen_init(pGenCtx))
    {
        printf("ERROR EVP_PKEY_keygen_init\n");
        goto exit;
    }

    if (1 != EVP_PKEY_keygen(pGenCtx, &pKey))
    {
        printf("ERROR EVP_PKEY_keygen\n");
        goto exit;
    }

    pValidateCtx = EVP_PKEY_CTX_new_from_pkey(pLibCtx, pKey, NULL);
    if (NULL == pValidateCtx)
    {
        printf("ERROR EVP_PKEY_CTX_new_from_pkey\n");
        goto exit;        
    }

    /* Also test key validation */
    if (1 != EVP_PKEY_pairwise_check(pValidateCtx))
    {
        printf("ERROR EVP_PKEY_pairwise_check\n");
        goto exit;
    }

    if (1 != EVP_PKEY_todata(pKey, selection, &pParams))
    {
        printf("ERROR EVP_PKEY_todata\n");
        goto exit;
    }

    pRecCtx = EVP_PKEY_CTX_new_from_name(pLibCtx, pAlg, NULL);
    if (NULL == pRecCtx)
    {
        printf("ERROR fetching %s algo\n", pAlg);
        goto exit;
    }
    
    if (1 != EVP_PKEY_fromdata_init(pRecCtx))
    {
        printf("ERROR EVP_PKEY_fromdata_init\n");
        goto exit;        
    }

    if (1 != EVP_PKEY_fromdata(pRecCtx, &pRecKey, selection, pParams))
    {
        printf("ERROR EVP_PKEY_fromdata\n");
        goto exit;
    }

    if (1 != EVP_PKEY_cmp(pKey, pRecKey))
    {
        printf("ERROR EVP_PKEY_cmp\n");
        goto exit;
    }

    ret = 0;

exit:

    if (NULL != pParams)
    {
        OSSL_PARAM_free(pParams); 
    }

    if (NULL != pGenCtx)
    {
        EVP_PKEY_CTX_free(pGenCtx);
    }
    if (NULL != pRecCtx)
    {
        EVP_PKEY_CTX_free(pRecCtx);
    }
    if (NULL != pValidateCtx)
    {
        EVP_PKEY_CTX_free(pValidateCtx);
    }

    if (NULL != pKey)
    {
        EVP_PKEY_free(pKey);
    }
    if (NULL != pRecKey)
    {
        EVP_PKEY_free(pRecKey);
    }

    return ret;
}

int test_pqc_sign(OSSL_LIB_CTX *pLibCtx, const char *pAlg, const char *pDigest)
{
    int ret = 0;

    if (NULL == pDigest)
    {
        ret += test_pqc_sign_standard(pLibCtx, pAlg);
        ret += test_pqc_sign_one_key(pLibCtx, pAlg);
    }
    else
    {
        ret += test_pqc_sign_digest_standard(pLibCtx, pAlg, pDigest, FALSE);
        ret += test_pqc_sign_digest_standard(pLibCtx, pAlg, pDigest, TRUE);
    }
    
    /* for now just test ML-DSA for import/export, change once SLH-DSA has support */
    if ('M' == pAlg[0])
    {
       ret += test_pqc_sign_import_export(pLibCtx, pAlg, EVP_PKEY_KEYPAIR);
       ret += test_pqc_sign_import_export(pLibCtx, pAlg, EVP_PKEY_PUBLIC_KEY);
    }

    return ret;
}
#endif
