/*
 * crypto_interface_ecdh_example.c
 *
 * Crypto Interface ECDH Example Code
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

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC__

#include "../../common/mtypes.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"
#include "../../common/random.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/ecc.h"
#include "../../crypto_interface/crypto_interface_ecc.h"

#define CI_ECC_P256_KEY_FILE   "eccp256.pem"
#define CI_ECC_P256_KEY_FILE_2 "eccp256-2.pem"

static MSTATUS crypto_interface_ecdh_example_key_from_file (
    AsymmetricKey *pKey,
    const sbyte *pFilename
    )
{
    MSTATUS status = OK;
    ubyte *pSerializedKeyData = NULL;
    ubyte4 serializedKeyDataLen = 0;

    status = DIGICERT_readFile(
        pFilename, &pSerializedKeyData, &serializedKeyDataLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_deserializeAsymKey (
        pSerializedKeyData, serializedKeyDataLen, NULL, pKey);

exit:

    if (NULL != pSerializedKeyData)
    {
        DIGI_FREE((void **)&pSerializedKeyData);
    }

    return status;
}


MOC_EXTERN MSTATUS crypto_interface_ecdh_example()
{
    MSTATUS status = OK;
    sbyte4 compare = -1;
    AsymmetricKey asymKeyServer = {0};
    ubyte *pServerPub = NULL;
    ubyte4 serverPubLen = 0;
    ubyte *pServerSS = NULL;
    ubyte4 serverSSLen = 0;

    AsymmetricKey asymKeyClient = {0};
    ubyte *pClientPub = NULL;
    ubyte4 clientPubLen = 0;
    ubyte *pClientSS = NULL;
    ubyte4 clientSSLen = 0;

    /* Server obtains its private key */
    status = crypto_interface_ecdh_example_key_from_file(&asymKeyServer, CI_ECC_P256_KEY_FILE);
    if (OK != status)
        goto exit;

    /* Likewise the client obtains its private key */
    status = crypto_interface_ecdh_example_key_from_file(&asymKeyClient, CI_ECC_P256_KEY_FILE_2);
    if (OK != status)
        goto exit;

    /* Server obtains its public key in order to later send it to the client */
    status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAllocAux (asymKeyServer.key.pECC, &pServerPub, &serverPubLen);
    if (OK != status)
        goto exit;

    /* Client obtains its public key in order to later send it to the server */
    status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAllocAux (asymKeyClient.key.pECC, &pClientPub, &clientPubLen);
    if (OK != status)
        goto exit;

    /* Server and Client now exchange their public keys */

    /* The server can now compute its copy of the shared secret using its private key and the client's public key 
       The 1 in the second to last parameter indicates the standard mode of computing just the x coordinate  */
    status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux (asymKeyServer.key.pECC, pClientPub, clientPubLen, &pServerSS, &serverSSLen, 1, NULL);
     if (OK != status)
        goto exit;

    /* The client can now compute its copy of the shared secret using its private key and the server's public key */
    status = CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux (asymKeyClient.key.pECC, pServerPub, serverPubLen, &pClientSS, &clientSSLen, 1, NULL);
     if (OK != status)
        goto exit;

    /* For illustration purposes, we'll check that the shared secrets match */
    if (serverSSLen != clientSSLen)
    {
        status = ERR_CMP;
        goto exit;
    }

    status = DIGI_MEMCMP ( (const ubyte *) pServerSS, (const ubyte *) pClientSS, serverSSLen, &compare);
    if (OK != status)
        goto exit;

    if (0 != compare)
    {
        status = ERR_CMP;
        goto exit;
    }

    /* Remember to not use the shared secrets directly, but to pass them through a hashing routine or a key derivation function */

exit:

    /* Cleanup all keys and buffers. All shared secrets should always be zero'd out when finished with them */

    (void) CRYPTO_uninitAsymmetricKey(&asymKeyServer, NULL);
    (void) CRYPTO_uninitAsymmetricKey(&asymKeyClient, NULL);

    if (NULL != pServerPub)
    {
        (void) DIGI_MEMSET_FREE(&pServerPub, serverPubLen);
    }

    if (NULL != pClientPub)
    {
        (void) DIGI_MEMSET_FREE(&pClientPub, clientPubLen);
    }

    if (NULL != pServerSS)
    {
        (void) DIGI_MEMSET_FREE(&pServerSS, serverSSLen);
    }

    if (NULL != pClientSS)
    {
        (void) DIGI_MEMSET_FREE(&pClientSS, clientSSLen);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC__ */
