/*
 * crypto_interface_dh_example.c
 *
 * Crypto Interface DH Example Code
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"
#include "../../common/random.h"
#include "../../crypto/dh.h"
#include "../../crypto_interface/crypto_interface_dh.h"

#define CI_DH_EXAMPLE_GROUP_NUM 17
#define MOCANA_DH_group17_keyLen 44

static MSTATUS crypto_interface_dh_example_server (
    diffieHellmanContext **ppCtx,
    ubyte **ppPublicKey,
    ubyte4 *pPublicKeyLen
    )
{
    MSTATUS status;
    diffieHellmanContext *pCtx = NULL;
    ubyte *pNewPublicKey = NULL;
    ubyte4 newPublicKeyLen = 0;

    if ( (NULL == ppCtx) || (NULL == ppPublicKey) || (NULL == pPublicKeyLen) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Allocate the DH context, this will also compute the public key */
    status = CRYPTO_INTERFACE_DH_allocateServer(g_pRandomContext, &pCtx, CI_DH_EXAMPLE_GROUP_NUM);
    if (OK != status)
        goto exit;

    /* Get the newly generated public key for the client to use */
    status = CRYPTO_INTERFACE_DH_getPublicKey(pCtx, &pNewPublicKey, &newPublicKeyLen);
    if (OK != status)
        goto exit;

    *ppCtx = pCtx;
    *ppPublicKey = pNewPublicKey;
    *pPublicKeyLen = newPublicKeyLen;
    pCtx = NULL;
    pNewPublicKey = NULL;

exit:

    if (NULL != pCtx)
    {
        (void) CRYPTO_INTERFACE_DH_freeDhContext(&pCtx, NULL);
    }
    if (NULL != pNewPublicKey)
    {
        (void) DIGI_FREE((void **)&pNewPublicKey);
    }

    return status;
}


static MSTATUS crypto_interface_dh_example_client (
    diffieHellmanContext **ppCtx,
    ubyte **ppPublicKey,
    ubyte4 *pPublicKeyLen
    )
{
    MSTATUS status;
    diffieHellmanContext *pCtx = NULL;
    ubyte *pNewPublicKey = NULL;
    ubyte4 newPublicKeyLen = 0;
    MDhKeyTemplate template = {0};

    /* Allocate the client DH context, we use CRYPTO_INTERFACE_DH_allocate and CRYPTO_INTERFACE_DH_setKeyParameters
       to set the groupNum, ie domain params, so that CRYPTO_INTERFACE_DH_generateKeyPair can be called to generate
       the actual key pair. Using CRYPTO_INTERFACE_DH_allocateClient will generate just a private key and no public key */
    status = CRYPTO_INTERFACE_DH_allocate(&pCtx);
    if (OK != status)
        goto exit;

    template.groupNum = CI_DH_EXAMPLE_GROUP_NUM;
    status = CRYPTO_INTERFACE_DH_setKeyParameters (pCtx, &template);
    if (OK != status)
        goto exit;

    /* Compute the public key */
    status = CRYPTO_INTERFACE_DH_generateKeyPair(pCtx, g_pRandomContext, MOCANA_DH_group17_keyLen);
    if (OK != status)
        goto exit;

    /* Get the newly generated public key */
    status = CRYPTO_INTERFACE_DH_getPublicKey(pCtx, &pNewPublicKey, &newPublicKeyLen);
    if (OK != status)
        goto exit;

    *ppCtx = pCtx;
    *ppPublicKey = pNewPublicKey;
    *pPublicKeyLen = newPublicKeyLen;
    pCtx = NULL;
    pNewPublicKey = NULL;

exit:

    /* No need to call CRYPTO_INTERFACE_DH_freeKeyTemplate on the template since only
       the groupNum field was used */

    if (NULL != pCtx)
    {
        (void) CRYPTO_INTERFACE_DH_freeDhContext(&pCtx, NULL);
    }
    if (NULL != pNewPublicKey)
    {
       (void)  DIGI_FREE((void **)&pNewPublicKey);
    }

    return status;
}

static MSTATUS crypto_interface_dh_example_key_exchange()
{
    MSTATUS status;
    diffieHellmanContext *pServerCtx = NULL;
    diffieHellmanContext *pClientCtx = NULL;
    ubyte *pServerPublicKey = NULL;
    ubyte4 serverPublicKeyLen = 0;
    ubyte *pClientPublicKey = NULL;
    ubyte4 clientPublicKeyLen = 0;
    ubyte *pServerSharedSecret = NULL;
    ubyte4 serverSharedSecretLen = 0;
    ubyte *pClientSharedSecret = NULL;
    ubyte4 clientSharedSecretLen = 0;
    sbyte4 cmp = 0;

    /* Initialize the server side DH, getting back the new DH context and
     * the public key for client use */
    status = crypto_interface_dh_example_server (
        &pServerCtx, &pServerPublicKey, &serverPublicKeyLen);
    if (OK != status)
        goto exit;

    /* Initialize the client side DH, getting back the new DH context and
     * the public key for server use */
    status = crypto_interface_dh_example_client (
        &pClientCtx, &pClientPublicKey, &clientPublicKeyLen);
    if (OK != status)
        goto exit;

    /* Compute the server side DH shared secret */
    status = CRYPTO_INTERFACE_DH_computeKeyExchangeEx (
        pServerCtx, NULL, pClientPublicKey, clientPublicKeyLen,
        &pServerSharedSecret, &serverSharedSecretLen);
    if (OK != status)
        goto exit;

    /* Compute the client side DH shared secret */
    status = CRYPTO_INTERFACE_DH_computeKeyExchangeEx (
        pClientCtx, NULL, pServerPublicKey, serverPublicKeyLen,
        &pClientSharedSecret, &clientSharedSecretLen);
    if (OK != status)
        goto exit;

    if (serverSharedSecretLen == 0)
    {
        status = ERR_CMP;
        goto exit;
    }

    if (serverSharedSecretLen != clientSharedSecretLen)
    {
        status = ERR_CMP;
        goto exit;
    }

    /* Ensure the shared secrets match */
    status = DIGI_MEMCMP (
        (const ubyte *)pServerSharedSecret,
        (const ubyte *)pClientSharedSecret,
        serverSharedSecretLen, &cmp);
    if (OK != status)
        goto exit;

    if (0 != cmp)
    {
        status = ERR_CMP;
        goto exit;
    }

exit:

    if (NULL != pServerCtx)
    {
        (void) CRYPTO_INTERFACE_DH_freeDhContext(&pServerCtx, NULL);
    }
    if (NULL != pClientCtx)
    {
        (void) CRYPTO_INTERFACE_DH_freeDhContext(&pClientCtx, NULL);
    }
    if (NULL != pServerPublicKey)
    {
        (void) DIGI_FREE((void **)&pServerPublicKey);
    }
    if (NULL != pClientPublicKey)
    {
        (void) DIGI_FREE((void **)&pClientPublicKey);
    }
    if (NULL != pServerSharedSecret)
    {
        (void) DIGI_FREE((void **)&pServerSharedSecret);
    }
    if (NULL != pClientSharedSecret)
    {
        (void) DIGI_FREE((void **)&pClientSharedSecret);
    }

    return status;
}

MOC_EXTERN MSTATUS crypto_interface_dh_example()
{
    return crypto_interface_dh_example_key_exchange();
}