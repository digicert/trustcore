/*
 * crypto_interface_tdes_example.c
 *
 * Crypto Interface TDES Example Code
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
#include "../../common/random.h"
#include "../../crypto/hw_accel.h"
#include "../../crypto/des.h"
#include "../../crypto/three_des.h"
#include "../../crypto_interface/crypto_interface_tdes.h"

#ifdef __ENABLE_DIGICERT_SMP_PKCS11__
#include "crypto_interface_tap_example.h"
#include "../../crypto/mocsymalgs/tap/symtap.h"
#include "../../crypto_interface/crypto_interface_tdes_tap.h"
#endif

#define CI_DES_CBC_MSG_LEN 16

MOC_EXTERN MSTATUS crypto_interface_tdes_example()
{
    MSTATUS status = OK;
    BulkCtx pCtx = NULL;
    ubyte pIvCopy[THREE_DES_BLOCK_SIZE];
    ubyte pResult[CI_DES_CBC_MSG_LEN];
    ubyte pMessage[CI_DES_CBC_MSG_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    ubyte pIv[THREE_DES_BLOCK_SIZE] = {
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    ubyte4 messageLen = CI_DES_CBC_MSG_LEN;
    sbyte4 cmp = 0;
    /* resultLen is CI_DES_CBC_MSG_LEN */
    /* ivLen is THREE_DES_BLOCK_SIZE */
    
    /* For TAP we will generate a 192 symmetric bit hardware key */ 

#ifdef __ENABLE_DIGICERT_SMP_PKCS11__

    SymmetricKey *pSymKey = NULL;
    MSymTapKeyGenArgs tapArgs = {0}; /* structure in symtap.h */
    ubyte *pSerKey = NULL;
    ubyte4 serLen = 0;

    /* fill in the tapArgs with the global values initialized via the tap_example_init() call near the top of main() */
    tapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    tapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    tapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    tapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_TDES;

    /* generate a 192 ()= 24 * 8) bit key */
    status = CRYPTO_INTERFACE_TAP_GenerateSymKey(&pSymKey, THREE_DES_KEY_LENGTH * 8, &tapArgs);
    if (OK != status)
        goto exit;

    /* we will need another SymmetricKey for decryption, so serialize this one so later we can make another copy */
    status = CRYPTO_INTERFACE_TAP_serializeSymKey(pSymKey, &pSerKey, &serLen);
    if (OK != status)
        goto exit;

    /* Now get an TDES-CBC context containing the TAP key for encryption */
    status = CRYPTO_INTERFACE_TAP_getTDesCbcCtxFromSymmetricKeyAlloc(pSymKey, &pCtx, MOCANA_SYM_TAP_ENCRYPT);
    if (OK != status)
        goto exit;
    
#else /* For non-TAP we generate a 192 bit key using the global RNG */

    ubyte pKeyData[THREE_DES_KEY_LENGTH];
    ubyte4 keyDataLen = THREE_DES_KEY_LENGTH;

    /* Generate 256 bits of key material using a random number generator.
     * The global RNG context was initialized during DIGICERT_initDigicert() */
    status = RANDOM_numberGenerator(g_pRandomContext, pKeyData, keyDataLen);
    if (OK != status)
        goto exit;

    /* Load the newly created key material into an TDES-CBC context and prepare
     * the key for encryption */
    pCtx = CRYPTO_INTERFACE_Create3DESCtx(pKeyData, (sbyte4)keyDataLen, TRUE);
    if (NULL == pCtx)
    {
        status = ERR_3DES;
        goto exit;
    }

#endif /* __ENABLE_DIGICERT_SMP_PKCS11__ */

    /* The encryption operation is in place, copy the message to be encrypted into
     * the buffer for the resulting ciphertext. */
    status = DIGI_MEMCPY((void *)pResult, (void *)pMessage, messageLen);
    if (OK != status)
        goto exit;

    /* The encryption operation modifies the IV buffer (for non-TAP), so save a copy for the
     * decryption operation if necessary */
    status = DIGI_MEMCPY((void *)pIvCopy, (void *)pIv, THREE_DES_BLOCK_SIZE);
    if (OK != status)
        goto exit;

    /* Encrypt the first block of data in place, Note pIV is updated for software keys but NOT updated for TAP keys */
    status = CRYPTO_INTERFACE_Do3DES(pCtx, pResult, THREE_DES_BLOCK_SIZE, TRUE, pIv);
    if (OK != status)
        goto exit;

    /* The buffer now contains the first encrypted block and the second plaintext
     * block that has not ben processed. For software keys pIv has also been updated
     * but for TAP keys pIv has not been updated. The internal state including the IV is
     * uodated correctly internally however, and the pIv now passed in here is ignored.  */
    status = CRYPTO_INTERFACE_Do3DES(pCtx, pResult + THREE_DES_BLOCK_SIZE, THREE_DES_BLOCK_SIZE, TRUE, pIv);
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
    status = CRYPTO_INTERFACE_Delete3DESCtx(&pCtx);
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

    /* Now get an TDES-CBC context containing the TAP key for decryption */
    status = CRYPTO_INTERFACE_TAP_getTDesCbcCtxFromSymmetricKeyAlloc(pSymKey, &pCtx, MOCANA_SYM_TAP_DECRYPT);
    if (OK != status)
        goto exit;

#else

    /* Create a new software context for decryption */
    pCtx = CRYPTO_INTERFACE_Create3DESCtx(pKeyData, (sbyte4)keyDataLen, FALSE);
    if (NULL == pCtx)
    {
        status = ERR_3DES;
        goto exit;
    }

#endif

    /* Decrypt the first block of data in place, using the IV copy we made earlier */
    status = CRYPTO_INTERFACE_Do3DES (
        pCtx, pResult, THREE_DES_BLOCK_SIZE, FALSE, pIvCopy);
    if (OK != status)
        goto exit;

    /* Decrypt the second block (remember pIvCopy is not updated or used here for TAP keys) */
    status = CRYPTO_INTERFACE_Do3DES (
        pCtx, pResult + THREE_DES_BLOCK_SIZE, THREE_DES_BLOCK_SIZE, FALSE, pIvCopy);
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
        CRYPTO_INTERFACE_Delete3DESCtx(&pCtx);
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
