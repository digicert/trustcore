/**
 * test_dh.c
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
#include "openssl/dh.h"

#include <stdio.h>

int test_dh(OSSL_LIB_CTX *pLibCtx, const char *pCipher, int curve, int group)
{
    MSTATUS status = ERR_GENERAL;
    EVP_PKEY *keyA = NULL;
    EVP_PKEY *keyB = NULL;
    char secretA[1024] = {0x00}; /* big enough for DH 8192 */
    char secretB[1024] = {0x01}; /* make different on purpose */
    size_t keylenA = 0;
    size_t keylenB = 0;
    int cmp = -1;
    EVP_PKEY_CTX *keyCtxA = NULL;
    EVP_PKEY_CTX *keyCtxB = NULL;

    /* perform A's keygen */
    keyCtxA = EVP_PKEY_CTX_new_from_name(pLibCtx, pCipher, NULL);
    if (NULL == keyCtxA)
    {
        printf("ERROR fetching %s algo\n", pCipher);
        return 1;
    }

    if (1 != EVP_PKEY_keygen_init(keyCtxA))
    {
        printf("ERROR EVP_PKEY_keygen_init\n");
        goto exit;
    }

    if (0 != curve)
    {
        if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(keyCtxA, curve))
        {
            printf("ERROR EVP_PKEY_CTX_set_ec_paramgen_curve_nid\n");
            goto exit;
        }
    }
    else if (0 != group)
    {
        if (1 != EVP_PKEY_CTX_set_dh_nid(keyCtxA, group))
        {
            printf("ERROR EVP_PKEY_CTX_set_dh_nid\n");
            goto exit;
        }        
    }

    if (1 != EVP_PKEY_keygen(keyCtxA, &keyA))
    {
        printf("ERROR EVP_PKEY_keygen\n");
        goto exit;
    }

    /* perform B's keygen */
    keyCtxB = EVP_PKEY_CTX_new_from_name(pLibCtx, pCipher, NULL);
    if (NULL == keyCtxB)
    {
        printf("ERROR fetching %s algo\n", pCipher);
        return 1;
    }

    if (1 != EVP_PKEY_keygen_init(keyCtxB))
    {
        printf("ERROR EVP_PKEY_keygen_init\n");
        goto exit;
    }

    if (0 != curve)
    {
        if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(keyCtxB, curve))
        {
            printf("ERROR EVP_PKEY_CTX_set_ec_paramgen_curve_nid\n");
            goto exit;
        }
    }
    else if (0 != group)
    {
        if (1 != EVP_PKEY_CTX_set_dh_nid(keyCtxB, group))
        {
            printf("ERROR EVP_PKEY_CTX_set_dh_nid\n");
            goto exit;
        }        
    }

    if (1 != EVP_PKEY_keygen(keyCtxB, &keyB))
    {
        printf("ERROR EVP_PKEY_keygen\n");
        goto exit;
    }

    /* derive A's secret */
    EVP_PKEY_CTX_free(keyCtxA);

    keyCtxA = EVP_PKEY_CTX_new_from_pkey(pLibCtx, keyA, NULL);
    if (NULL == keyCtxA)
    {
        printf("ERROR EVP_PKEY_CTX_new_from_pkey\n");
        goto exit;        
    }
                                        
    if (1 != EVP_PKEY_derive_init(keyCtxA))
    {
        printf("ERROR EVP_PKEY_derive_init\n");
        goto exit;
    }

    if (1 != EVP_PKEY_derive_set_peer(keyCtxA, keyB))
    {
        printf("ERROR EVP_PKEY_derive_set_peer\n");
        goto exit;    
    }

    if (1 != EVP_PKEY_derive(keyCtxA, NULL, &keylenA))
    {
        printf("ERROR EVP_PKEY_derive\n");
        goto exit;   
    }

    if (1 != EVP_PKEY_derive(keyCtxA, secretA, &keylenA))
    {
        printf("ERROR EVP_PKEY_derive\n");
        goto exit;   
    }

    /* derive B's secret */
    EVP_PKEY_CTX_free(keyCtxB);

    keyCtxB = EVP_PKEY_CTX_new_from_pkey(pLibCtx, keyB, NULL);
    if (NULL == keyCtxB)
    {
        printf("ERROR EVP_PKEY_CTX_new_from_pkey\n");
        goto exit;        
    }

    if (1 != EVP_PKEY_derive_init(keyCtxB))
    {
        printf("ERROR EVP_PKEY_derive_init\n");
        goto exit;
    }

    if (1 != EVP_PKEY_derive_set_peer(keyCtxB, keyA))
    {
        printf("ERROR EVP_PKEY_derive_set_peer\n");
        goto exit;    
    }

    if (1 != EVP_PKEY_derive(keyCtxB, NULL, &keylenB))
    {
        printf("ERROR EVP_PKEY_derive\n");
        goto exit;
    }

    if (1 != EVP_PKEY_derive(keyCtxB, secretB, &keylenB))
    {
        printf("ERROR EVP_PKEY_derive\n");
        goto exit;   
    }

    if (keylenB != keylenA)
    {
        printf("ERROR secret lengths don't match\n");
        goto exit;     
    }

    (void) DIGI_MEMCMP(secretA, secretB, keylenB, &cmp);

    if (cmp)
    {
        printf("ERROR secrets don't match\n");
        goto exit;         
    }

    status = OK;

exit:

    if (NULL != keyA)
    {
        EVP_PKEY_free(keyA);
    }

    if (NULL != keyB)
    {
        EVP_PKEY_free(keyB);
    }

    if (NULL != keyCtxA)
    {
        EVP_PKEY_CTX_free(keyCtxA);
    }

    if (NULL != keyCtxB)
    {
        EVP_PKEY_CTX_free(keyCtxB);
    }

    return (status == OK) ? 0 : 1;
}
#endif
