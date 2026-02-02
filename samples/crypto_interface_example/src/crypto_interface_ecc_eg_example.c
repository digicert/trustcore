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
#include "../../crypto/pubcrypto.h"
#include "../../crypto/ecc.h"
#include "../../crypto_interface/crypto_interface_ecc_eg.h"
#include "../../crypto_interface/cryptointerface.h"

#define CI_ECC_P256_KEY_FILE "eccp256.pem"
#define CI_ECC_MSG_LEN       16
#define CI_ECC_KEY_LEN       32

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

/* -------------------------------------------------------------------------------------*/

static MSTATUS crypto_interface_ecc_example_enc_dec(ECCKey *pPubKey, ECCKey *pPrivKey)
{
    MSTATUS status = OK;
    sbyte4 compare = -1;

    /* We encrypt a 16 byte message, say an AES-128 key for example */
    ubyte pMessage[CI_ECC_MSG_LEN] = 
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    ubyte4 messageLen = CI_ECC_MSG_LEN;

    /* Cipher text will come out to 4 coordinates or 4 times the (private) key size */
    ubyte pCipher[CI_ECC_KEY_LEN * 4] = {0};

    /* Enough space for the recovered message */
    ubyte pRecoveredMessage[CI_ECC_MSG_LEN] = {0};

    /* We'll use the pkcs #1 v1.5 APIs which will take care of padding for us. The output lengths need to be known a priori */
    
    /* Encrypt with the public key */
    status = CRYPTO_INTERFACE_ECEG_encryptPKCSv1p5(pPubKey, RANDOM_rngFun, g_pRandomContext, pMessage, messageLen, pCipher, NULL);
    if (OK != status)
        goto exit;

    /* Decrypt with the private key */
    status = CRYPTO_INTERFACE_ECEG_decryptPKCSv1p5(pPrivKey, pCipher, CI_ECC_KEY_LEN * 4, pRecoveredMessage, NULL);
    if (OK != status)
        goto exit;

    /* Test to see if we got the correct message back */
    status = DIGI_MEMCMP(pRecoveredMessage, pMessage, CI_ECC_MSG_LEN, &compare);
    if (OK != status)
        goto exit;

    if (0 != compare)
    {
        status = ERR_CMP;
    }    

exit:

    return status;
}

/* -------------------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS crypto_interface_ecc_eg_example()
{
    MSTATUS status = OK;
    AsymmetricKey asymPrivKey = {0};
    ECCKey *pPubKey = NULL;
    ubyte *pPubBuf = NULL;
    ubyte4 pubBufLen = 0;

    /* An ECC key can be generated or read from a file. We illustrate reading a key from a file for the non-TAP case */

    /* read the P256 private key in from a file */
    status = crypto_interface_ecc_example_key_from_file(&asymPrivKey, CI_ECC_P256_KEY_FILE);
    if (OK != status)
        goto exit;

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

    /* Perform the enc/dec example, we'll pass in the public and private key in ECCKey form */
    status = crypto_interface_ecc_example_enc_dec(pPubKey, asymPrivKey.key.pECC);

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
