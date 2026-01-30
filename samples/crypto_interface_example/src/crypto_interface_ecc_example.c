/*
 * crypto_interface_ecc_example.c
 *
 * Crypto Interface ECC Example Code
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
#include "../../common/vlong.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/sha256.h"
#include "../../crypto_interface/crypto_interface_sha256.h"
#include "../../crypto/ecc.h"
#include "../../crypto_interface/cryptointerface.h"
#include "../../crypto_interface/crypto_interface_ecc.h"

#define CI_ECC_P256_KEY_FILE "eccp256.pem"
#define CI_ECC_MSG_LEN       32

#ifdef __ENABLE_DIGICERT_TAP__
#include "crypto_interface_tap_example.h"
#include "../../crypto/mocasymkeys/tap/ecctap.h"
#endif

#ifndef __ENABLE_DIGICERT_TAP__
static MSTATUS crypto_interface_ecc_example_key_from_file (
    AsymmetricKey *pKey,
    const sbyte *pFilename
    )
{
    MSTATUS status;
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
#endif

/* -------------------------------------------------------------------------------------*/

static MSTATUS crypto_interface_ecc_example_sign_verify(ECCKey *pPrivKey, ECCKey *pPubKey)
{
    MSTATUS status;
    ubyte4 elementLen, signatureLen;
    ubyte pHash[SHA256_RESULT_SIZE];
    ubyte *pSignature = NULL;
    ubyte pMessage[CI_ECC_MSG_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    ubyte4 messageLen = CI_ECC_MSG_LEN;
    sbyte4 vfy = 0;

    /* For this example we will hash the message using SHA-256 then sign
     * the hash with a P-256 ECC key */
    status = CRYPTO_INTERFACE_SHA256_completeDigest (
        (const ubyte *)pMessage, messageLen, pHash);
    if (OK != status)
        goto exit;

    /* The signature output will always be 2 * elementLen */
    status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(pPrivKey, &elementLen);
    if (OK != status)
        goto exit;

    signatureLen = 2 * elementLen;

    /* Allocate the signature buffer */
    status = DIGI_MALLOC((void **)&pSignature, signatureLen);
    if (OK != status)
        goto exit;

    /* Sign the hash of the message with the private key */
    status = CRYPTO_INTERFACE_ECDSA_signDigestAux (
        pPrivKey, RANDOM_rngFun, g_pRandomContext, pHash, SHA256_RESULT_SIZE,
        pSignature, signatureLen, &signatureLen);
    if (OK != status)
        goto exit;

    /* Verify the signature with the public key */
    status = CRYPTO_INTERFACE_ECDSA_verifySignatureDigestAux (
        pPubKey, pHash, SHA256_RESULT_SIZE, pSignature, elementLen,
        pSignature + elementLen, elementLen, &vfy);
    if (OK != status)
        goto exit;

    if (0 != vfy)
    {
        status = ERR_ECDSA_VERIFICATION_FAILED;
        goto exit;
    }

exit:

    if (NULL != pSignature)
    {
        DIGI_FREE((void **)&pSignature);
    }

    return status;
}

/* -------------------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS crypto_interface_ecc_example()
{
    MSTATUS status = OK;
    AsymmetricKey asymPrivKey = {0};
    ECCKey *pPubKey = NULL;
    ubyte *pPubBuf = NULL;
    ubyte4 pubBufLen = 0;

    /* An ECC key can be generated or read from a file. We illustrate generating a key for the TAP case 
       and will illustrate reading a key from a file for the non-TAP case */

#ifdef __ENABLE_DIGICERT_TAP__
    ECCKey *pPrivKey = NULL;
    MEccTapKeyGenArgs eccTapArgs = {0}; /* structure defined in ecctap.h */
 
    /* fill in the eccTapArgs with the global values initialized via the tap_example_init() call near the top of main() */
    eccTapArgs.keyUsage = TAP_KEY_USAGE_SIGNING;
    eccTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    eccTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    eccTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    eccTapArgs.algKeyInfo.eccInfo.sigScheme = TAP_SIG_SCHEME_ECDSA_SHA256;  /* We'll use curve P256 */

    /* Call generate key, we can pass a NULL rngFun and rngArg since the key is generated by the hardware device */
    status = CRYPTO_INTERFACE_EC_generateKeyPairAlloc(cid_EC_P256, (void **) &pPrivKey, NULL, NULL, akt_tap_ecc, &eccTapArgs);
    if (OK != status)
        goto exit;

    /* We'll wrap the ECCKey in an AsymmetricKey structure for symmetry with the non-TAP case and for ease in obtaining the public key */
    status = CRYPTO_initAsymmetricKey(&asymPrivKey);
    if (OK != status)
        goto exit;

    status = CRYPTO_loadAsymmetricKey(&asymPrivKey, akt_tap_ecc, (void **) &pPrivKey);
    if (OK != status)
        goto exit;

#else

    /* non-TAP case, read the P256 key in from a file */
    status = crypto_interface_ecc_example_key_from_file(&asymPrivKey, CI_ECC_P256_KEY_FILE);
    if (OK != status)
        goto exit;

#endif /* __ENABLE_DIGICERT_TAP__ */

    /* Create a new key shell for the public key. If we did not know it was P256 a priori,
       one could call CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux on asymPrivKey.key.pECC to get the curve Id */
    status = CRYPTO_INTERFACE_EC_newKeyAux(cid_EC_P256, &pPubKey);
    if (OK != status)
        goto exit;

    /* Get the public key from the private key */
    status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAllocAux(asymPrivKey.key.pECC, &pPubBuf, &pubBufLen);
    if (OK != status)
        goto exit;

    /* Set the value into the public key */
    status = CRYPTO_INTERFACE_EC_setKeyParametersAux (pPubKey, pPubBuf, pubBufLen, NULL, 0);
    if (OK != status)
        goto exit;

    /* Perform the sign verify example, we'll pass in the private and public key in ECCKey form */
    status = crypto_interface_ecc_example_sign_verify(asymPrivKey.key.pECC, pPubKey);
 
exit:

    /* uninit-ing the Asymmetric key will free the interally held private ECCKey too */ 
    (void) CRYPTO_uninitAsymmetricKey(&asymPrivKey, NULL);

    /* Also delete our public key and buffer */
    if (NULL != pPubKey)
    {
        (void) CRYPTO_INTERFACE_EC_deleteKeyAux(&pPubKey);
    }

    if (NULL != pPubBuf)
    {
        (void) DIGI_MEMSET_FREE(&pPubBuf, pubBufLen);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC__ */
