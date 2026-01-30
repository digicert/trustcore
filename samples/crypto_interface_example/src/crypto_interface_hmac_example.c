/*
 * crypto_interface_hmac_example.c
 *
 * Crypto Interface HMAC Example Code
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
#include "../../crypto/crypto.h"
#include "../../crypto/md5.h"
#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../../crypto/hmac.h"
#include "../../crypto_interface/crypto_interface_hmac.h"

#ifdef __ENABLE_DIGICERT_SMP_PKCS11__
#include "crypto_interface_tap_example.h"
#include "../../crypto/mocsymalgs/tap/symtap.h"
#include "../../crypto_interface/crypto_interface_hmac_tap.h"
#endif

#define CI_HMAC_EXAMPLE_KEY_LEN 32
#define CI_HMAC_MSG_LEN         32

MOC_EXTERN MSTATUS crypto_interface_hmac_example()
{
    MSTATUS status = OK;
    HMAC_CTX *pCtx = NULL;

    ubyte pResult[SHA256_RESULT_SIZE];
    ubyte pMessage[CI_HMAC_MSG_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    ubyte4 messageLen = CI_HMAC_MSG_LEN;

    /* For TAP we will generate a 256 symmetric bit hardware key */ 

#ifdef __ENABLE_DIGICERT_SMP_PKCS11__

    SymmetricKey *pSymKey = NULL;
    MSymTapKeyGenArgs tapArgs = {0}; /* structure in symtap.h */

    /* fill in the tapArgs with the global values initialized via the tap_example_init() call near the top of main() */
    tapArgs.pTapCtx = TAP_EXAMPLE_getTapContext(1);
    tapArgs.pEntityCredentials = TAP_EXAMPLE_getEntityCredentialList(1);
    tapArgs.pKeyCredentials = TAP_EXAMPLE_getCredentialList(1);
    tapArgs.keyAlgorithm = TAP_KEY_ALGORITHM_HMAC; /* hmac with sha256 */
    tapArgs.hashAlg = TAP_HASH_ALG_SHA256;

    /* generate a 256 bit key */
    status = CRYPTO_INTERFACE_TAP_GenerateSymKey(&pSymKey, 256, &tapArgs);
    if (OK != status)
        goto exit;

    /* Now get an HMAC context containing the TAP key */
    status = CRYPTO_INTERFACE_TAP_getHmacCtxFromSymmetricKeyAlloc(pSymKey, &pCtx);
    if (OK != status)
        goto exit;
    
#else /* For non-TAP we generate a 256 bit key using the global RNG */

    const BulkHashAlgo *pBulkHashAlgo = NULL;
    ubyte pKeyData[CI_HMAC_EXAMPLE_KEY_LEN];
    ubyte4 keyDataLen = CI_HMAC_EXAMPLE_KEY_LEN;

    /* Generate 32 bytes of key material using a random number generator.
     * The global RNG context was initialized during DIGICERT_initDigicert() */
    status = RANDOM_numberGenerator(g_pRandomContext, pKeyData, keyDataLen);
    if (OK != status)
        goto exit;

    /* For this example we will be using HMAC with SHA-256, first we need a
     * reference to the SHA-256 BulkHashAlgo */
    status = CRYPTO_getRSAHashAlgo(ht_sha256, &pBulkHashAlgo);
    if (OK != status)
        goto exit;

    /* Create the HMAC context, specifying the SHA-256 hash algorithm */
    status = CRYPTO_INTERFACE_HmacCreate(&pCtx, pBulkHashAlgo);
    if (OK != status)
        goto exit;

    /* Load the key data into the HMAC context */
    status = CRYPTO_INTERFACE_HmacKey(pCtx, pKeyData, keyDataLen);
    if (OK != status)
        goto exit;

#endif /* __ENABLE_DIGICERT_SMP_PKCS11__ */

    /* Update the data to be processed by the HMAC, this may be called as many
     * times as needed to add data before finalizing to recieve the computed MAC */
    status = CRYPTO_INTERFACE_HmacUpdate(pCtx, pMessage, messageLen);
    if (OK != status)
        goto exit;

    /* Finalize the operation and write the computed MAC value to the result
     * buffer. The result size is equal to the output size of the underlying
     * hash algorithm. */
    status = CRYPTO_INTERFACE_HmacFinal(pCtx, pResult);

exit:

    /* Clean up the context when finished */
    if (NULL != pCtx)
    {
        (void) CRYPTO_INTERFACE_HmacDelete(&pCtx);
    }

#ifdef __ENABLE_DIGICERT_SMP_PKCS11__
    /* The symmetric key will be transfered to hmac ctx on success, but in case of error
       we still want to have a delete call on it here in the exit block */

    if (NULL != pSymKey)
    {
        (void) CRYPTO_INTERFACE_TAP_deleteSymKey(&pSymKey);
    }

#endif

    return status;
}
