/*
 * crypto_interface_rsa_pss_example.c
 *
 * Crypto Interface RSA-PSS Example Code
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
#include "../../crypto_interface/crypto_interface_rsa.h"
#include "../../crypto/pkcs1.h"
#include "../../crypto_interface/crypto_interface_pkcs1.h"
#include "../../crypto_interface/cryptointerface.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "crypto_interface_tap_example.h"
#include "../../crypto/mocasymkeys/tap/rsatap.h"
#endif

#define CI_RSA_PSS_2048_KEY_FILE "rsa2048.pem"
#define CI_RSA_PSS_MSG_LEN       32

#ifndef __ENABLE_DIGICERT_TAP__
static MSTATUS crypto_interface_rsa_pss_example_key_from_file(AsymmetricKey *pKey)
{
    MSTATUS status;
    ubyte *pSerializedKeyData = NULL;
    ubyte4 serializedKeyDataLen = 0;

    status = DIGICERT_readFile(
        CI_RSA_PSS_2048_KEY_FILE, &pSerializedKeyData, &serializedKeyDataLen);
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

static MSTATUS crypto_interface_rsa_pss_example_sign_verify(RSAKey *pPrivKey, RSAKey *pPubKey)
{
    MSTATUS status;
    ubyte4 signatureLen;
    ubyte *pSignature = NULL;
    ubyte pMessage[CI_RSA_PSS_MSG_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    ubyte4 messageLen = CI_RSA_PSS_MSG_LEN;
    ubyte hashAlgo = ht_sha256;
    sbyte4 saltLen = SHA256_RESULT_SIZE;
    sbyte4 vfy = 0;

    /* Sign the data using the private key. Note for nearly all cases of PSS use, the
     * hash algo and MGF hash algo are the same. It is also common to use the
     * underlying hash length as the salt length. Unlike traditional RSA
     * signature scheme, PSS actually takes in the message instead of the digest
     * of the message and performs the hashing as part of the signing process.
     * For software keys the RNG is absolutely needed as PSS uses random data to produce a
     * non-deterministic signature. For TAP keys the RNG, mgfAlgo, mgfHash are not used
     * as they are specified at key generation time, and hashAlgo is not used but will be
     * validated. */
    status = CRYPTO_INTERFACE_PKCS1_rsaPssSign (MOC_RSA(0)
        g_pRandomContext, pPrivKey, hashAlgo, MOC_PKCS1_ALG_MGF1, hashAlgo,
        pMessage, messageLen, (ubyte4) saltLen, &pSignature, &signatureLen);
    if (OK != status)
        goto exit;

    /* For TPM2 the above passed in saltLen is actually ignored. In the verify API below
       a value of -1 will indicate that we recover the saltLen rather than validate it */
#ifdef __ENABLE_DIGICERT_TPM2__
    saltLen = -1;
#endif

    /* Verify the signature using the public key. Note that a return code of OK does not mean
     * the signature verified, only that the function was able to determine
     * if it verified or not. We must check the status of vfy to determine
     * if the signature was actually verified. */
    status = CRYPTO_INTERFACE_PKCS1_rsaPssVerify (MOC_RSA(0)
        pPubKey, hashAlgo, MOC_PKCS1_ALG_MGF1, hashAlgo, pMessage, messageLen,
        pSignature, signatureLen, saltLen, &vfy);
    if (OK != status)
        goto exit;

    if (0 != vfy)
    {
        status = ERR_RSA_BAD_SIGNATURE;
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

MOC_EXTERN MSTATUS crypto_interface_rsa_pss_example()
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
    rsaTapArgs.algKeyInfo.rsaInfo.sigScheme = TAP_SIG_SCHEME_PSS_SHA256; /* pss */
    rsaTapArgs.algKeyInfo.rsaInfo.encScheme = TAP_ENC_SCHEME_NONE;
    rsaTapArgs.keyUsage = TAP_KEY_USAGE_SIGNING;
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

    status = crypto_interface_rsa_pss_example_key_from_file(&asymPrivKey);
    if (OK != status)
        goto exit;

#endif /* __ENABLE_DIGICERT_TAP__ */

    /* Get the public key */
    status = CRYPTO_INTERFACE_getRSAPublicKey(&asymPrivKey, &pPubKey);
    if (OK != status)
        goto exit;

    status = crypto_interface_rsa_pss_example_sign_verify(asymPrivKey.key.pRSA, pPubKey);

exit:

    /* uninit-ing the Asymmetric key will free the interally held private RSAKey too */ 
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
