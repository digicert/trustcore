/**
 * test_pqc_kem.c
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

#include <stdio.h>

int test_pqc_kem_standard(OSSL_LIB_CTX *pLibCtx, const char *pAlg)
{
    MSTATUS status = ERR_GENERAL;
    EVP_PKEY *pEncapsKey = NULL;
    EVP_PKEY *pDecapsKey = NULL;
    OSSL_PARAM params[2];
    int ret = 0;
    sbyte4 cmp = -1;

    char pPub[1568]; /* big enough for all modes */ 
    
    unsigned char *pCipher = NULL;
    size_t cipherLen = 0;
    
    unsigned char pSS1[32];   /* big enough for all modes */
    unsigned char pSS2[32];   /* big enough for all modes */
    size_t ssLen = 0;

    EVP_PKEY_CTX *pEncapsCtx = NULL;
    EVP_PKEY_CTX *pDecapsCtx = NULL;
    
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

    if (1 != EVP_PKEY_keygen(pGenCtx, &pDecapsKey))
    {
        printf("ERROR EVP_PKEY_keygen\n");
        goto exit;
    }
    
    /* get the public key */
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pPub, sizeof(pPub));
    params[1] = OSSL_PARAM_construct_end();

    if (1 != EVP_PKEY_get_params(pDecapsKey, params))
    {
        printf("ERROR EVP_PKEY_get_params\n");
        goto exit;
    }

    /* send to the other guy */
    pEncapsKey = EVP_PKEY_new_raw_public_key_ex(pLibCtx, pAlg, NULL, pPub, params[0].return_size);
    if (NULL == pEncapsKey)
    {
        printf("ERROR fetching %s algo\n", pAlg);
        goto exit; 
    }

    /* encapsulate */
    pEncapsCtx = EVP_PKEY_CTX_new(pEncapsKey, NULL);
    if (NULL == pEncapsCtx)
    {
        printf("ERROR fetching %s algo\n", pAlg);
        goto exit;
    }

    if (1 != EVP_PKEY_encapsulate_init(pEncapsCtx, NULL))
    {
        printf("ERROR EVP_PKEY_encapsulate_init\n");
        goto exit;        
    }

    /* get the cipherLen and ssLen */
    if (1 != EVP_PKEY_encapsulate(pEncapsCtx, NULL, &cipherLen, NULL, &ssLen))
    {
        printf("ERROR EVP_PKEY_encapsulate\n");
        goto exit;         
    }

    /* sanity check the ssLen */
    if (ssLen != 32)
    {
        printf("ERROR invalid shared secret len\n");
        goto exit;         
    }

    (void) DIGI_MALLOC((void **) &pCipher, cipherLen);
    if (NULL == pCipher)
    {
        printf("ERROR DIGI_MALLOC\n");
        goto exit;
    }

    if (1 != EVP_PKEY_encapsulate(pEncapsCtx, pCipher, &cipherLen, pSS1, &ssLen))
    {
        printf("ERROR EVP_PKEY_encapsulate\n");
        goto exit;         
    }

    /* send over the ciphertext and decapsulate on the other end */
    pDecapsCtx = EVP_PKEY_CTX_new(pDecapsKey, NULL);
    if (NULL == pDecapsCtx)
    {
        printf("ERROR fetching %s algo\n", pAlg);
        goto exit;
    }

    if (1 != EVP_PKEY_decapsulate_init(pDecapsCtx, NULL))
    {
        printf("ERROR EVP_PKEY_decapsulate_init\n");
        goto exit;        
    }

    if (1 != EVP_PKEY_decapsulate(pDecapsCtx, pSS2, &ssLen, pCipher, cipherLen))
    {
        printf("ERROR EVP_PKEY_decapsulate\n");
        goto exit;         
    }

    (void) DIGI_MEMCMP(pSS1, pSS2, ssLen, &cmp);

    if (cmp)
    {
        printf("ERROR secrets don't match\n");
        goto exit;         
    }

    status = OK;

exit:

    if (NULL != pCipher)
    {
        (void) DIGI_FREE((void **) &pCipher);
    }

    if (NULL != pGenCtx)
    {
        EVP_PKEY_CTX_free(pGenCtx);
    }
    if (NULL != pEncapsCtx)
    {
        EVP_PKEY_CTX_free(pEncapsCtx);
    }
    if (NULL != pDecapsCtx)
    {
        EVP_PKEY_CTX_free(pDecapsCtx);
    }
    if (NULL != pEncapsKey)
    {
        EVP_PKEY_free(pEncapsKey);
    }
    if (NULL != pDecapsKey)
    {
        EVP_PKEY_free(pDecapsKey);
    }

    return (status == OK) ? 0 : 1;
}

int test_pqc_kem_one_key(OSSL_LIB_CTX *pLibCtx, const char *pAlg)
{
    MSTATUS status = ERR_GENERAL;
    EVP_PKEY *pKey = NULL;
    int ret = 0;
    sbyte4 cmp = -1;

    unsigned char pCipher[1568]; /* big enough for all modes */
    size_t cipherLen = 0;
    
    unsigned char pSS1[32];   /* big enough for all modes */
    unsigned char pSS2[32];   /* big enough for all modes */
    size_t ssLen = 0;

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

    /* encapsulate */
    pCtx = EVP_PKEY_CTX_new(pKey, NULL);
    if (NULL == pCtx)
    {
        printf("ERROR fetching %s algo\n", pAlg);
        goto exit;
    }

    if (1 != EVP_PKEY_encapsulate_init(pCtx, NULL))
    {
        printf("ERROR EVP_PKEY_encapsulate_init\n");
        goto exit;        
    }

    if (1 != EVP_PKEY_encapsulate(pCtx, pCipher, &cipherLen, pSS1, &ssLen))
    {
        printf("ERROR EVP_PKEY_encapsulate\n");
        goto exit;         
    }

    /* send over the ciphertext and decapsulate on the other end */
    if (1 != EVP_PKEY_decapsulate_init(pCtx, NULL))
    {
        printf("ERROR EVP_PKEY_decapsulate_init\n");
        goto exit;        
    }

    if (1 != EVP_PKEY_decapsulate(pCtx, pSS2, &ssLen, pCipher, cipherLen))
    {
        printf("ERROR EVP_PKEY_decapsulate\n");
        goto exit;         
    }

    (void) DIGI_MEMCMP(pSS1, pSS2, ssLen, &cmp);

    if (cmp)
    {
        printf("ERROR secrets don't match\n");
        goto exit;         
    }

    status = OK;

exit:

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

int test_pqc_kem(OSSL_LIB_CTX *pLibCtx, const char *pAlg)
{
    int ret = 0;

    ret += test_pqc_kem_standard(pLibCtx, pAlg);
    ret += test_pqc_kem_one_key(pLibCtx, pAlg);

    return ret;
}
#endif
