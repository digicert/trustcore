/*
 * crypto_interface_aes_gcm_example.c
 *
 * Crypto Interface AES-GCM Example Code
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

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_GCM__

#include "../../common/mtypes.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/mocana.h"
#include "../../common/random.h"
#include "../../crypto/hw_accel.h"
#include "../../crypto/aes.h"
#include "../../crypto/aes_ctr.h"
#include "../../crypto/gcm.h"
#include "../../crypto_interface/crypto_interface_aes_gcm.h"

#ifdef __ENABLE_DIGICERT_SMP_PKCS11__
#include "crypto_interface_tap_example.h"
#include "../../crypto/mocsymalgs/tap/symtap.h"
#include "../../crypto_interface/crypto_interface_aes_gcm_tap.h"
#endif

#define CI_AES_GCM_MSG_LEN 32
#define CI_AES_GCM_AAD_LEN 10
#define CI_AES_GCM_TAG_LEN 16

MOC_EXTERN MSTATUS crypto_interface_aes_gcm_example()
{
    MSTATUS status = OK;
    BulkCtx pCtx = NULL;

    /* For AES-GCM your result buffer for encryption must contain space for one extra
     * AES block, this is where the GCM authentication tag will be written */
    ubyte pResult[CI_AES_GCM_MSG_LEN + AES_BLOCK_SIZE] = {0};
    ubyte pMessage[CI_AES_GCM_MSG_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    ubyte pNonce[AES_BLOCK_SIZE] = {
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    ubyte pAad[CI_AES_GCM_AAD_LEN] = {
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    };
    ubyte4 messageLen = CI_AES_GCM_MSG_LEN;
    ubyte4 aadLen = CI_AES_GCM_AAD_LEN;
    ubyte4 nonceLen = AES_BLOCK_SIZE;
    sbyte4 cmp = 0;
    /* resultLen is also CI_AES_GCM_MSG_LEN */

    /* For TAP we will generate a 256 symmetric bit hardware key */ 

#ifdef __ENABLE_DIGICERT_SMP_PKCS11__

    SymmetricKey *pSymKey = NULL;
    MSymTapKeyGenArgs tapArgs = {0}; /* structure in symtap.h */
    ubyte *pSerKey = NULL;
    ubyte4 serLen = 0;

    /* fill in the tapArgs with the global values initialized via the tap_example_init() call near the top of main() */
    tapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    tapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    tapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    tapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_AES;

    /* generate a 256 bit key */
    status = CRYPTO_INTERFACE_TAP_GenerateSymKey(&pSymKey, MOC_AES_256_KEY_LEN * 8, &tapArgs);
    if (OK != status)
        goto exit;

    /* we will need another SymmetricKey for decryption, so serialize this one so later we can make another copy */
    status = CRYPTO_INTERFACE_TAP_serializeSymKey(pSymKey, &pSerKey, &serLen);
    if (OK != status)
        goto exit;

    /* Now get an AES-GCM context containing the TAP key for encryption */
    status = CRYPTO_INTERFACE_TAP_getAesGcmCtxFromSymmetricKeyAlloc(pSymKey, &pCtx, GCM_MODE_4K, MOCANA_SYM_TAP_ENCRYPT);
    if (OK != status)
        goto exit;
    
#else /* For non-TAP we generate a 256 bit key using the global RNG */

    ubyte pKeyData[MOC_AES_256_KEY_LEN];
    ubyte4 keyDataLen = MOC_AES_256_KEY_LEN;

    /* Load the newly created key material into an AES-GCM context and prepare
     * the key for encryption. GCM comes in 3 modes of operation, each producing
     * identical results using a different speed/memory tradeoff. For this example
     * we will use GCM-4k. */
    pCtx = CRYPTO_INTERFACE_GCM_createCtx_4k(pKeyData, (sbyte4)keyDataLen, TRUE);
    if (NULL == pCtx)
    {
        status = ERR_AES;
        goto exit;
    }

#endif /* __ENABLE_DIGICERT_SMP_PKCS11__ */


    /* The encryption operation is in place, copy the message to be encrypted into
     * the buffer for the resulting ciphertext + tag data. */
    status = DIGI_MEMCPY((void *)pResult, (void *)pMessage, messageLen);
    if (OK != status)
        goto exit;

    /* Encrypt the data in place and write out the GCM tag */
    status = CRYPTO_INTERFACE_GCM_cipher_4k (
        pCtx, pNonce, nonceLen, pAad, aadLen, pResult, messageLen,
        CI_AES_GCM_TAG_LEN, TRUE);
    if (OK != status)
        goto exit;

    /* The data is now encrypted, check against the original message to
     * prove it */
    status = DIGI_MEMCMP (
        (const ubyte *)pMessage, (const ubyte *)pResult, messageLen, &cmp);
    if (OK != status)
        goto exit;

    if (0 == cmp)
    {
        status = ERR_CMP;
        goto exit;
    }

    /* We need to recreate the context for decryption, delete the old one first */
    status = CRYPTO_INTERFACE_GCM_deleteCtx_4k(&pCtx);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_SMP_PKCS11__
   
    /* pSymKey was transferred to the deleted pCtx, but out of good practice we can still delete it so it can be re-used */
    status = CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymKey);
    if (OK != status)
        goto exit;
        
    /* deserialize */
    status = CRYPTO_INTERFACE_TAP_deserializeSymKey(&pSymKey, pSerKey, serLen, &tapArgs);
    if (OK != status)
        goto exit;

    /* Now get an AES-GCM context containing the TAP key for decryption */
    status = CRYPTO_INTERFACE_TAP_getAesGcmCtxFromSymmetricKeyAlloc(pSymKey, &pCtx, GCM_MODE_4K, MOCANA_SYM_TAP_DECRYPT);
    if (OK != status)
        goto exit;

#else

    pCtx = CRYPTO_INTERFACE_GCM_createCtx_4k(pKeyData, (sbyte4)keyDataLen, FALSE);
    if (NULL == pCtx)
    {
        status = ERR_AES;
        goto exit;
    }

#endif /* __ENABLE_DIGICERT_SMP_PKCS11__ */

    /* Decrypt the data in place, note that pResult contains the encrypted
     * message and the GCM authentication tag. If the tag does not match
     * this function will return ERR_CRYPTO_AEAD_FAIL */
    status = CRYPTO_INTERFACE_GCM_cipher_4k (
        pCtx, pNonce, nonceLen, pAad, aadLen, pResult, messageLen, CI_AES_GCM_TAG_LEN, FALSE);
    if (OK != status)
        goto exit;

    /* Compare the result to the original message to ensure it worked */
    status = DIGI_MEMCMP (
        (const ubyte *)pMessage, (const ubyte *)pResult, messageLen, &cmp);
    if (OK != status)
        goto exit;

    if (0 != cmp)
    {
        status = ERR_CMP;
        goto exit;
    }

exit:

    /* Clean up the context when finished */
    if (NULL != pCtx)
    {
        CRYPTO_INTERFACE_GCM_deleteCtx_4k(&pCtx);
    }

#ifdef __ENABLE_DIGICERT_SMP_PKCS11__
    /* The symmetric key will be transfered to aes ctx on success, but in case of error
       we still want to have a delete call on it here in the exit block */

    if (NULL != pSymKey)
    {
        (void) CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymKey);
    }

    if (NULL != pSerKey)
    {
        (void) DIGI_MEMSET_FREE(&pSerKey, serLen);
    }
#endif

    return status;
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_GCM__ */
