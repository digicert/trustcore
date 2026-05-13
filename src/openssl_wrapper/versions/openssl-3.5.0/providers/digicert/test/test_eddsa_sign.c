/**
 * test_eddsa_sign.c
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

#include <stdio.h>

int test_eddsa_sign(OSSL_LIB_CTX *pLibCtx, const char *pCurve)
{
    MSTATUS status = ERR_GENERAL;
    EVP_MD_CTX *pMdCtx = NULL;
    EVP_PKEY *key = NULL;
    unsigned char *pData = (unsigned char *)"01234567890123456789012345678901";
    size_t dataLen = 16;
    unsigned char res[114] = {0}; /* big enough for either curve */
    size_t resLen = sizeof(res); 

    EVP_PKEY_CTX *keyCtx = EVP_PKEY_CTX_new_from_name(pLibCtx, pCurve, NULL);
    if (NULL == keyCtx)
    {
        printf("ERROR fetching %s algo\n", pCurve);
        return 1;
    }

    if (1 != EVP_PKEY_keygen_init(keyCtx))
    {
        printf("ERROR EVP_PKEY_keygen_init\n");
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

    /* clear keyCtx to reuse */
    EVP_PKEY_CTX_free(keyCtx);

    if (1 != EVP_DigestSignInit_ex(pMdCtx, &keyCtx, NULL, pLibCtx, NULL, key, NULL))
    {
        printf("ERROR EVP_DigestSignInit\n");
        goto exit;
    }

    if (1 != EVP_DigestSign(pMdCtx, res, &resLen, pData, dataLen))
    {
        printf("ERROR EVP_DigestSign\n");
        goto exit;
    }

    if ('2' == pCurve[2] && resLen != 64)
    {
        printf("ERROR Invalid returned signature length for curve 25519\n");
    }
    else if ('4' == pCurve[2] && resLen != 114)
    {
        printf("ERROR Invalid returned signature length for curve 448\n");
    }

    if(pMdCtx) EVP_MD_CTX_destroy(pMdCtx);

    pMdCtx = EVP_MD_CTX_new();
    if (pMdCtx == NULL)
        goto exit;
    
    if (1 != EVP_DigestVerifyInit_ex(pMdCtx, &keyCtx, NULL, pLibCtx, NULL, key, NULL))
    {
        printf("ERROR EVP_DigestVerifyInit\n");
        goto exit;
    }

    if (1 != EVP_DigestVerify(pMdCtx, res, resLen, pData, dataLen))
    {
        printf("ERROR EVP_DigestVerify\n");
        goto exit;
    }

    status = OK;

exit:

    if(pMdCtx) EVP_MD_CTX_destroy(pMdCtx);

    /* keyCtx freed by the above EVP_MD_CTX_destroy call */

    if (NULL != key)
    {
        EVP_PKEY_free(key);
    }

    return (status == OK) ? 0 : 1;
}
#endif
