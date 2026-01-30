/*
 * crypto_interface_rsa_example.c
 *
 * Crypto Interface RSA Example Code
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
#include "../../common/vlong.h"
#include "../../crypto/pubcrypto.h"
#include "../../crypto/sha256.h"
#include "../../crypto_interface/crypto_interface_sha256.h"
#include "../../crypto/rsa.h"
#include "../../crypto_interface/cryptointerface.h"
#include "../../crypto_interface/crypto_interface_rsa.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "crypto_interface_tap_example.h"
#include "../../crypto/mocasymkeys/tap/rsatap.h"
#endif

#define CI_RSA_2048_KEY_FILE "rsa2048.pem"
#define CI_RSA_MSG_LEN       32

#ifndef __ENABLE_DIGICERT_TAP__
static MSTATUS crypto_interface_rsa_example_key_from_file(AsymmetricKey *pKey)
{
    MSTATUS status;
    ubyte *pSerializedKeyData = NULL;
    ubyte4 serializedKeyDataLen = 0;

    status = DIGICERT_readFile(
        CI_RSA_2048_KEY_FILE, &pSerializedKeyData, &serializedKeyDataLen);
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

static MSTATUS crypto_interface_rsa_example_sign_verify(RSAKey *pPrivKey, RSAKey *pPubKey)
{
    MSTATUS status;
    ubyte4 signatureLen;
    ubyte pHash[SHA256_RESULT_SIZE];
    ubyte *pSignature = NULL;
    ubyte *pDigestInfo = NULL;
    ubyte4 digestInfoLen = 0;

    ubyte pMessage[CI_RSA_MSG_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    ubyte4 messageLen = CI_RSA_MSG_LEN;
    intBoolean isValid = FALSE;

    /* For this example we will hash the message using SHA-256 then sign
     * the digestInfo of the hash with a 2048-bit RSA key */
    status = CRYPTO_INTERFACE_SHA256_completeDigest (
        (const ubyte *)pMessage, messageLen, pHash);
    if (OK != status)
        goto exit;

    /* Construct the digestInfo to sign */
    status = ASN1_buildDigestInfoAlloc(pHash, SHA256_RESULT_SIZE, ht_sha256, &pDigestInfo, &digestInfoLen);
    if (OK != status)
        goto exit;

    /* Determine how long the signature output will be */
    status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(pPrivKey, &signatureLen);
    if (OK != status)
        goto exit;

    /* Allocate the signature buffer */
    status = DIGI_MALLOC((void **)&pSignature, signatureLen);
    if (OK != status)
        goto exit;

    /* Sign the digestInfo of the message, we can use the general signMessageAux API */
    status = CRYPTO_INTERFACE_RSA_signMessageAux (
        pPrivKey, pDigestInfo, digestInfoLen, pSignature, NULL);
    if (OK != status)
        goto exit;

    /* Verify the digestInfo. We use the verifyDigest API even though we're passing a digestInfo */
    status = CRYPTO_INTERFACE_RSA_verifyDigest(pPubKey, pDigestInfo, digestInfoLen, pSignature, signatureLen, &isValid, NULL);
    if (OK != status)
        goto exit;

    /* Verify that it matches the original hash */
    if (!isValid)
    {
        status = ERR_RSA;
    }

exit:

    if (NULL != pSignature)
    {
        DIGI_FREE((void **)&pSignature);
    }

    if (NULL != pDigestInfo)
    {
        DIGI_FREE((void **)&pDigestInfo);
    }

    return status;
}

/* -------------------------------------------------------------------------------------*/

static MSTATUS crypto_interface_rsa_example_encrypt_decrypt(RSAKey *pPrivKey, RSAKey *pPubKey)
{
    MSTATUS status;
    ubyte4 cipherLen, plainLen;
    ubyte *pPlain = NULL;
    ubyte *pCipher = NULL;
    ubyte pMessage[CI_RSA_MSG_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    ubyte4 messageLen = CI_RSA_MSG_LEN;
    sbyte4 cmp = 0;

    /* Determine how long the ciphertext output will be */
    status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(pPubKey, &cipherLen);
    if (OK != status)
        goto exit;

    /* Allocate the ciphertext buffer */
    status = DIGI_MALLOC((void **)&pCipher, cipherLen);
    if (OK != status)
        goto exit;

    /* Encrypt the message with the public key */
    status = CRYPTO_INTERFACE_RSA_encryptAux (
        pPubKey, pMessage, messageLen, pCipher, RANDOM_rngFun, g_pRandomContext, NULL);
    if (OK != status)
        goto exit;

    /* Allocate a buffer for the recovered plaintext. In theory we may not know it's length 
       but it'll be no bigger than the cipherLen */
    status = DIGI_MALLOC((void **)&pPlain, cipherLen);
    if (OK != status)
        goto exit;

    /* Decrypt the ciphertext  */
    status = CRYPTO_INTERFACE_RSA_decryptAux (
        pPrivKey, pCipher, pPlain, &plainLen, RANDOM_rngFun, g_pRandomContext, NULL);
    if (OK != status)
        goto exit;

    /* Ensure the decrypted plaintext matches the original message */
    if (plainLen != messageLen)
    {
        status = ERR_CMP;
        goto exit;
    }

    status = DIGI_MEMCMP((void *)pMessage, (void *)pPlain, plainLen, &cmp);
    if (OK != status)
        goto exit;

    if (0 != cmp)
    {
        status = ERR_CMP;
    }

exit:

    if (NULL != pCipher)
    {
        DIGI_FREE((void **)&pCipher);
    }

    if (NULL != pPlain)
    {
        DIGI_FREE((void **)&pPlain);
    }

    return status;
}

/* -------------------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS crypto_interface_rsa_example()
{
    MSTATUS status = OK;
    AsymmetricKey asymPrivKey = {0};
    RSAKey *pPubKey = NULL;

    /* An RSA key can be generated or read from a file. We illustrate generating a key for the TAP case 
       and will illustrate reading a key from a file for the non-TAP case. */

#ifdef __ENABLE_DIGICERT_TAP__
    RSAKey *pPrivKey = NULL;
    MRsaTapKeyGenArgs rsaTapArgs = {0};   /* structure defined in rsatap.h */
   
    /* fill in the rsaTapArgs with the global values initialized via the tap_example_init() call near the top of main() */
    rsaTapArgs.algKeyInfo.rsaInfo.sigScheme = TAP_SIG_SCHEME_PKCS1_5; /* TAP_SIG_SCHEME_NONE will also default to pkcs1.5 padding */
    rsaTapArgs.algKeyInfo.rsaInfo.encScheme = TAP_ENC_SCHEME_NONE;
    rsaTapArgs.keyUsage = TAP_KEY_USAGE_SIGNING;   /* A Tap key may be used for signing or encryption but not both */
    rsaTapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    rsaTapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    rsaTapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    
    /* Call generate key, we can pass a NULL random context since the key is generated by the hardware device */
    status = CRYPTO_INTERFACE_RSA_generateKeyAlloc(NULL, (void **) &pPrivKey, 2048, NULL, akt_tap_rsa, &rsaTapArgs);
    if (OK != status)
        goto exit;
    
    /* We'll wrap the RSAKey in an AsymmetricKey structure for symmetry with the non-TAP case and for ease in obtaining the public key */
    status = CRYPTO_initAsymmetricKey(&asymPrivKey);
    if (OK != status)
        goto exit;

    status = CRYPTO_loadAsymmetricKey(&asymPrivKey, akt_tap_rsa, (void **) &pPrivKey);
    if (OK != status)
        goto exit;

#else

    /* non-TAP case, read the key in from a file */
    status = crypto_interface_rsa_example_key_from_file(&asymPrivKey);
    if (OK != status)
        goto exit;

#endif /* __ENABLE_DIGICERT_TAP__ */

    /* Get the public key */
    status = CRYPTO_INTERFACE_getRSAPublicKey(&asymPrivKey, &pPubKey);
    if (OK != status)
        goto exit;

    /* Perform the sign verify example, we'll pass in the private and public key in RSAKey form */
    status = crypto_interface_rsa_example_sign_verify(asymPrivKey.key.pRSA, pPubKey);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_TAP__
    
    /* For the TAP use case we need a new private/public key pair with usage TAP_KEY_USAGE_DECRYPT */

    /* Clear the existing private and public keys */ 
    status = CRYPTO_uninitAsymmetricKey(&asymPrivKey, NULL);
    if (OK != status)
        goto exit;

    /* pPrivKey's memory was freed in the above call but reset the copy of its pointer */
    pPrivKey = NULL;

    CRYPTO_INTERFACE_RSA_freeKeyAux(&pPubKey, NULL);
    if (OK != status)
        goto exit;

    /* fill in the rsaTapArgs with the global values initialized via the tap_example_init() call near the top of main() */
    rsaTapArgs.algKeyInfo.rsaInfo.sigScheme = TAP_SIG_SCHEME_NONE; 
    rsaTapArgs.algKeyInfo.rsaInfo.encScheme = TAP_ENC_SCHEME_PKCS1_5; /* TAP_ENC_SCHEME_NONE will also default to pkcs1.5 padding */
    rsaTapArgs.keyUsage = TAP_KEY_USAGE_DECRYPT;   /* A Tap key may be used for signing or encryption but not both */
    
    /* rsaTapArgs.pTapCtx, rsaTapArgs.pEntityCredentials, rsaTapArgs.pKeyCredentials are still set to the correct pointers */
    
    /* Call generate key, we can pass a NULL random context since the key is generated by the hardware device */
    status = CRYPTO_INTERFACE_RSA_generateKeyAlloc(NULL, (void **) &pPrivKey, 2048, NULL, akt_tap_rsa, &rsaTapArgs);
    if (OK != status)
        goto exit;
    
    /* We'll wrap the RSAKey in an AsymmetricKey structure for symmetry with the non-TAP case and for ease in obtaining the public key */
    status = CRYPTO_initAsymmetricKey(&asymPrivKey);
    if (OK != status)
        goto exit;

    status = CRYPTO_loadAsymmetricKey(&asymPrivKey, akt_tap_rsa, (void **) &pPrivKey);
    if (OK != status)
        goto exit;

    /* Get the public key */
    status = CRYPTO_INTERFACE_getRSAPublicKey(&asymPrivKey, &pPubKey);
    if (OK != status)
        goto exit;

#endif /* __ENABLE_DIGICERT_TAP__ */

    /* Perform the encrypt/decrypt example, we'll pass in the private and public key in RSAKey form */
    status = crypto_interface_rsa_example_encrypt_decrypt(asymPrivKey.key.pRSA, pPubKey);

exit:

    /* uninit-ing the Asymmetric key will free the interally held RSAKeys too */ 
    (void) CRYPTO_uninitAsymmetricKey(&asymPrivKey, NULL);

#ifdef __ENABLE_DIGICERT_TAP__
     /* Also free the public key since it's now not wrapped by asymPrivKey */
    if (NULL != pPubKey)
    {
        (void) CRYPTO_INTERFACE_RSA_freeKeyAux(&pPubKey, NULL);
    }
#endif

    return status;
}
