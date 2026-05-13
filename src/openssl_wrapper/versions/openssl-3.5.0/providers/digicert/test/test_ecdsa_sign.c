/**
 * test_ecdsa_sign.c
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
#include "openssl/ec.h"
#include "openssl/pem.h"

#include <stdio.h>

int my_pem_password_cb(char *buf, int size, int rwflag, void *userdata);

int test_ecdsa_sign(OSSL_LIB_CTX *pLibCtx, int curve, const char *pDigest)
{
    MSTATUS status = ERR_GENERAL;
    EVP_MD_CTX *pMdCtx = NULL;
    EVP_MD *pMd = NULL;
    EVP_PKEY *key = NULL;
    int ret = 0;
    size_t len = 0;
    unsigned char *pSig = NULL;
    unsigned char *pData = (unsigned char *)"0123456789012345";
    size_t dataLen = 16;
    unsigned int sigLen = 0;

    EVP_PKEY_CTX *keyCtx = EVP_PKEY_CTX_new_from_name(pLibCtx, "EC", NULL);
    if (NULL == keyCtx)
    {
        printf("ERROR fetching ECDSA algo\n");
        return 1;
    }

    if (1 != EVP_PKEY_keygen_init(keyCtx))
    {
        printf("ERROR EVP_PKEY_keygen_init\n");
        goto exit;
    }

    if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(keyCtx, curve))
    {
        printf("ERROR EVP_PKEY_CTX_set_ec_paramgen_curve_nid\n");
        goto exit;
    }

    if (1 != EVP_PKEY_keygen(keyCtx, &key))
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
        printf("ERROR EVP verifyinit\n");
        goto exit;
    }

    if (1 != EVP_VerifyUpdate(pMdCtx, (const void *)pData, dataLen))
    {
        printf("ERROR EVP verifyupdate\n");
        goto exit;
    }

    if (1 != EVP_VerifyFinal(pMdCtx, pSig, sigLen, key))
    {
        printf("ERROR EVP verifyfinal\n");
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
    if (NULL != pMd)
    {
        EVP_MD_free(pMd);
    }
    if (NULL != key)
    {
        EVP_PKEY_free(key);
    }

    return (status == OK) ? 0 : 1;
}

int test_ecdsa_sign_pem(OSSL_LIB_CTX *pLibCtx, char *pPemFile)
{
    MSTATUS status = ERR_GENERAL;
    EVP_MD_CTX *pMdCtx = NULL;
    EVP_MD *pMd = NULL;
    EVP_PKEY *key = NULL;
    int ret = 0;
    size_t len = 0;
    unsigned char *pSig = NULL;
    unsigned char *pData = (unsigned char *)"0123456789012345";
    size_t dataLen = 16;
    unsigned int sigLen = 0;

    FILE *fp_priv = NULL;

    if (NULL == pPemFile)
    {
        printf("ERROR, NULL input file\n");
        return 1;
    }

    fp_priv = fopen(pPemFile, "r");
    if (NULL == fp_priv)
    {
        printf("ERROR, Can't open %s\n", pPemFile);
        return 1;
    }

    key = PEM_read_PrivateKey(fp_priv, NULL, my_pem_password_cb, NULL);
    if (NULL == key)
    {
        printf("ERROR PEM_read_PrivateKey\n");
        return 1;
    }   

    pMdCtx = EVP_MD_CTX_new();
    if (pMdCtx == NULL)
        goto exit;

    pMd = EVP_MD_fetch(pLibCtx, "SHA-256", NULL);
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
        printf("ERROR EVP verifyinit\n");
        goto exit;
    }

    if (1 != EVP_VerifyUpdate(pMdCtx, (const void *)pData, dataLen))
    {
        printf("ERROR EVP verifyupdate\n");
        goto exit;
    }

    if (1 != EVP_VerifyFinal(pMdCtx, pSig, sigLen, key))
    {
        printf("ERROR EVP verifyfinal\n");
        goto exit;
    }

    status = OK;

exit:

    if(pMdCtx) EVP_MD_CTX_destroy(pMdCtx);
    
    if (NULL != pSig)
    {
        DIGI_FREE((void **)&pSig);
    }
    if (NULL != pMd)
    {
        EVP_MD_free(pMd);
    }
    if (NULL != key)
    {
        EVP_PKEY_free(key);
    }
    if (NULL != fp_priv)
    {
        fclose(fp_priv);
    }

    return (status == OK) ? 0 : 1;
}
#endif
