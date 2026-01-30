/*
 * crypto_interface_sha3_example.c
 *
 * Crypto Interface SHA3 Example Code
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

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA3__

#include "../../common/mtypes.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/mocana.h"
#include "../../common/random.h"
#include "../../crypto/hw_accel.h"
#include "../../crypto/sha3.h"
#include "../../crypto_interface/crypto_interface_sha3.h"

#define CI_SHA3_MSG_LEN 64
#define CI_SHA3_256_OUT_LEN 32
#define CI_SHAKE256_DESIRED_OUT_LEN 128

static MSTATUS crypto_interface_sha3_256_example()
{
    MSTATUS status = OK;
    ubyte pResult[CI_SHA3_256_OUT_LEN];
    ubyte pMessage[CI_SHA3_MSG_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    };
    ubyte4 messageLen = CI_SHA3_MSG_LEN;

    /* We'll illustrate the one step API with this example 
       The mode MOCANA_SHA3_MODE_SHA3_256 is not an extendable
       output mode so the last parameter, desiredOutputLen, is ignored */
    status = CRYPTO_INTERFACE_SHA3_completeDigest(
        MOCANA_SHA3_MODE_SHA3_256, pMessage, messageLen, pResult, 0);
    if (OK != status)
        goto exit;

    /* The SHA3-256 hash of the message is now contained in
     * the pResult buffer of length CI_SHA3_256_OUT_LEN, ie 32 bytes (256 bits) */

exit:
    return status;
}

static MSTATUS crypto_interface_shake256_example()
{
    MSTATUS status = OK;
    BulkCtx pCtx = NULL;
    ubyte pResult[CI_SHAKE256_DESIRED_OUT_LEN];
    ubyte pMessage[CI_SHA3_MSG_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    };

    /* We'll illustrate the multi step APIs with this example 
       and use the extendable output mode SHAKE256. We can request
       the output length to be any number of bytes and we'll choose
       CI_SHAKE256_DESIRED_OUT_LEN which is set to 128 */

    /* Create a new SHA3 context */
    status = CRYPTO_INTERFACE_SHA3_allocDigest(&pCtx);
    if (OK != status)
        goto exit;

    /* Initialize the digest operation for mode SHAKE256 */
    status = CRYPTO_INTERFACE_SHA3_initDigest(pCtx, MOCANA_SHA3_MODE_SHAKE256);
    if (OK != status)
        goto exit;

    /* Update the digest operation with the first half of the data. The
     * update call can be made any amount of times with any amount of data */
    status = CRYPTO_INTERFACE_SHA3_updateDigest (
        pCtx, pMessage, (CI_SHA3_MSG_LEN / 2));
    if (OK != status)
        goto exit;

    /* Update the context with the second half of the message */
    status = CRYPTO_INTERFACE_SHA3_updateDigest (
        pCtx, pMessage + (CI_SHA3_MSG_LEN / 2), (CI_SHA3_MSG_LEN / 2));
    if (OK != status)
        goto exit;

    /* Finalize the operation and recieve the computed digest of the desired output length */
    status = CRYPTO_INTERFACE_SHA3_finalDigest(pCtx, pResult, CI_SHAKE256_DESIRED_OUT_LEN);
    if (OK != status)
        goto exit;

    /* The SHAKE256 hash of the message is now contained in
     * the pResult buffer of length CI_SHAKE256_DESIRED_OUT_LEN */

exit:

    /* Clean up the context when finished */
    if (NULL != pCtx)
    {
        (void) CRYPTO_INTERFACE_SHA3_freeDigest(&pCtx);
    }

    return status;
}


MOC_EXTERN MSTATUS crypto_interface_sha3_example()
{
    MSTATUS status;

    status = crypto_interface_sha3_256_example();
    if (OK != status)
        goto exit;

    status = crypto_interface_shake256_example();
    if (OK != status)
        goto exit;

exit:
    return status;
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA3__ */
