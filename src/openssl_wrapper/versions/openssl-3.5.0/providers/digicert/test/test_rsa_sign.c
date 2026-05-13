/**
 * test_rsa_sign.c
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
#include "openssl/rsa.h"
#include "openssl/pem.h"

#include <stdio.h>

int my_pem_password_cb(char *buf, int size, int rwflag, void *userdata);

int test_rsa_sign(OSSL_LIB_CTX *pLibCtx, int bits, byteBoolean isPss)
{
    MSTATUS status = ERR_GENERAL;
    EVP_MD_CTX *pMdCtx = NULL;
    EVP_MD *pMd = NULL;
    EVP_PKEY *key = NULL;
    unsigned char *pSig = NULL;
    unsigned char *pData = (unsigned char *)"0123456789012345";
    size_t dataLen = 16;
    size_t sigLen = 0;
    unsigned int sigLen2 = 0;

    EVP_PKEY_CTX *keyCtx = EVP_PKEY_CTX_new_from_name(pLibCtx, "RSA", NULL);
    if (NULL == keyCtx)
    {
        printf("ERROR fetching RSA algo\n");
        return 1;
    }

    if (1 != EVP_PKEY_keygen_init(keyCtx))
    {
        printf("ERROR EVP_PKEY_keygen_init\n");
        goto exit;
    }

    if (1 != EVP_PKEY_CTX_set_rsa_keygen_bits(keyCtx, bits))
    {
        printf("ERROR EVP_PKEY_CTX_set_rsa_keygen_bits\n");
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
   
    if (isPss)
    {
        /* free old keyCtx, we'll get a new one */
        EVP_PKEY_CTX_free(keyCtx);
        
        if (1 != EVP_DigestSignInit_ex(pMdCtx, &keyCtx, "SHA-256", pLibCtx, NULL, key, NULL))
        {
            printf("ERROR EVP_DigestSignInit_ex\n");
            goto exit;
        }

        if (1 != EVP_PKEY_CTX_set_rsa_padding(keyCtx, RSA_PKCS1_PSS_PADDING))
        {
            printf("ERROR EVP_PKEY_CTX_set_rsa_padding\n");
            goto exit;   
        }

#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
        if (1 != EVP_PKEY_CTX_set_rsa_pss_saltlen(keyCtx, RSA_PSS_SALTLEN_DIGEST))
        {
            printf("ERROR EVP_PKEY_CTX_set_rsa_pss_saltlen\n");
            goto exit;
        }
#endif

        if (1 != EVP_DigestSignUpdate(pMdCtx, (const void *)pData, dataLen))
        {
            printf("ERROR EVP signupdate\n");
            goto exit;
        }

        if (1 != EVP_DigestSignFinal(pMdCtx, NULL, &sigLen))
        {
            printf("ERROR EVP signfinal getting sig len\n");
            goto exit;
        }

        (void) DIGI_MALLOC((void **)&pSig, (ubyte4) sigLen);
        if (NULL == pSig)
        {
            printf("ERROR DIGI_MALLOC\n");
            goto exit;
        }

        if (1 != EVP_DigestSignFinal(pMdCtx, pSig, &sigLen))
        {
            printf("ERROR EVP signfinal\n");
            goto exit;
        }
    }
    else
    {
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

        if (1 != EVP_SignFinal(pMdCtx, NULL, &sigLen2, key))
        {
            printf("ERROR EVP signfinal getting sig len\n");
            goto exit;
        }

        (void) DIGI_MALLOC((void **)&pSig, sigLen2);
        if (NULL == pSig)
        {
            printf("ERROR DIGI_MALLOC\n");
            goto exit;
        }

        if (1 != EVP_SignFinal(pMdCtx, pSig, &sigLen2, key))
        {
            printf("ERROR EVP signfinal\n");
            goto exit;
        }
    }

    if(pMdCtx) EVP_MD_CTX_destroy(pMdCtx);

    pMdCtx = EVP_MD_CTX_new();
    if (pMdCtx == NULL)
        goto exit;

    if (isPss)
    {
        /* dont't free old keyCtx, was freed in EVP_MD_CTX_destroy above */
        if (1 != EVP_DigestVerifyInit_ex(pMdCtx, &keyCtx, "SHA-256", pLibCtx, NULL, key, NULL))
        {
            printf("ERROR EVP_DigestVerifyInit_ex");
            goto exit;
        }

        if (1 != EVP_PKEY_CTX_set_rsa_padding(keyCtx, RSA_PKCS1_PSS_PADDING))
        {
            printf("ERROR EVP_PKEY_CTX_set_rsa_padding");
            goto exit;   
        }
        
        if (1 != EVP_DigestVerifyUpdate(pMdCtx, (const void *)pData, dataLen))
        {
            printf("ERROR EVP_DigestVerifyUpdate\n");
            goto exit;
        }

        if (1 != EVP_DigestVerifyFinal(pMdCtx, pSig, sigLen))
        {
            printf("ERROR EVP_DigestVerifyFinal\n");
            goto exit;
        }
    }
    else
    {
        if (1 != EVP_VerifyInit(pMdCtx, pMd))
        {
            printf("ERROR EVP verifyinit\n");
            goto exit;
        }

        if (1 != EVP_VerifyUpdate(pMdCtx, (const void *) pData, dataLen))
        {
            printf("ERROR EVP verifyupdate\n");
            goto exit;
        }

        if (1 != EVP_VerifyFinal(pMdCtx, pSig, sigLen2, key))
        {
            printf("ERROR EVP verifyfinal\n");
            goto exit;
        }
    }

    status = OK;

exit:
    if(pMdCtx) EVP_MD_CTX_destroy(pMdCtx);
    if (NULL != pSig)
    {
        DIGI_FREE((void **)&pSig);
    }
    if (NULL != keyCtx && !isPss)
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

int test_rsa_sign_pem(OSSL_LIB_CTX *pLibCtx, char *pPemFile, byteBoolean isPss)
{
    MSTATUS status = ERR_GENERAL;
    EVP_MD_CTX *pMdCtx = NULL;
    EVP_MD *pMd = NULL;
    EVP_PKEY *key = NULL;
    unsigned char *pSig = NULL;
    unsigned char *pData = (unsigned char *)"0123456789012345";
    size_t dataLen = 16;
    size_t sigLen = 0;
    unsigned int sigLen2 = 0;
    FILE *fp_priv = NULL;
    EVP_PKEY_CTX *keyCtx = NULL;

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

    if (isPss)
    {        
        if (1 != EVP_DigestSignInit_ex(pMdCtx, &keyCtx, "SHA-256", pLibCtx, NULL, key, NULL))
        {
            printf("ERROR EVP_DigestSignInit_ex\n");
            goto exit;
        }

        if (1 != EVP_PKEY_CTX_set_rsa_padding(keyCtx, RSA_PKCS1_PSS_PADDING))
        {
            printf("ERROR EVP_PKEY_CTX_set_rsa_padding\n");
            goto exit;   
        }

#if defined(__ENABLE_DIGICERT_FIPS_MODULE__)
        if (1 != EVP_PKEY_CTX_set_rsa_pss_saltlen(keyCtx, RSA_PSS_SALTLEN_DIGEST))
        {
            printf("ERROR EVP_PKEY_CTX_set_rsa_pss_saltlen\n");
            goto exit;  
        }
#endif

        if (1 != EVP_DigestSignUpdate(pMdCtx, (const void *)pData, dataLen))
        {
            printf("ERROR EVP signupdate\n");
            goto exit;
        }

        if (1 != EVP_DigestSignFinal(pMdCtx, NULL, &sigLen))
        {
            printf("ERROR EVP signfinal getting sig len\n");
            goto exit;
        }

        (void) DIGI_MALLOC((void **)&pSig, (ubyte4) sigLen);
        if (NULL == pSig)
        {
            printf("ERROR DIGI_MALLOC\n");
            goto exit;
        }

        if (1 != EVP_DigestSignFinal(pMdCtx, pSig, &sigLen))
        {
            printf("ERROR EVP signfinal\n");
            goto exit;
        }
    }
    else
    {
        keyCtx = EVP_PKEY_CTX_new(key, NULL);
        if (NULL == keyCtx)
        {
            printf("ERROR fetching RSA algo\n");
            return 1;
        }

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

        if (1 != EVP_SignFinal(pMdCtx, NULL, &sigLen2, key))
        {
            printf("ERROR EVP signfinal getting sig len\n");
            goto exit;
        }

        (void) DIGI_MALLOC((void **)&pSig, sigLen2);
        if (NULL == pSig)
        {
            printf("ERROR DIGI_MALLOC\n");
            goto exit;
        }

        if (1 != EVP_SignFinal(pMdCtx, pSig, &sigLen2, key))
        {
            printf("ERROR EVP signfinal\n");
            goto exit;
        }
    }

    if(pMdCtx) EVP_MD_CTX_destroy(pMdCtx);

    pMdCtx = EVP_MD_CTX_new();
    if (pMdCtx == NULL)
        goto exit;

    if (isPss)
    {
        /* dont't free old keyCtx, was freed in EVP_MD_CTX_destroy above */
        if (1 != EVP_DigestVerifyInit_ex(pMdCtx, &keyCtx, "SHA-256", pLibCtx, NULL, key, NULL))
        {
            printf("ERROR EVP_DigestVerifyInit_ex");
            goto exit;
        }

        if (1 != EVP_PKEY_CTX_set_rsa_padding(keyCtx, RSA_PKCS1_PSS_PADDING))
        {
            printf("ERROR EVP_PKEY_CTX_set_rsa_padding");
            goto exit;   
        }
        
        if (1 != EVP_DigestVerifyUpdate(pMdCtx, (const void *)pData, dataLen))
        {
            printf("ERROR EVP_DigestVerifyUpdate\n");
            goto exit;
        }

        if (1 != EVP_DigestVerifyFinal(pMdCtx, pSig, sigLen))
        {
            printf("ERROR EVP_DigestVerifyFinal\n");
            goto exit;
        }
    }
    else
    {
        if (1 != EVP_VerifyInit(pMdCtx, pMd))
        {
            printf("ERROR EVP verifyinit\n");
            goto exit;
        }

        if (1 != EVP_VerifyUpdate(pMdCtx, (const void *) pData, dataLen))
        {
            printf("ERROR EVP verifyupdate\n");
            goto exit;
        }

        if (1 != EVP_VerifyFinal(pMdCtx, pSig, sigLen2, key))
        {
            printf("ERROR EVP verifyfinal\n");
            goto exit;
        }
    }

    status = OK;

exit:
    if(pMdCtx) EVP_MD_CTX_destroy(pMdCtx);
    if (NULL != pSig)
    {
        DIGI_FREE((void **)&pSig);
    }
    if (NULL != keyCtx && !isPss)
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

    if (NULL != fp_priv)
    {
        fclose(fp_priv);
    }

    return (status == OK) ? 0 : 1;
}
#endif
