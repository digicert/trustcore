/*
 * crypto_interface_sha2_example.c
 *
 * Crypto Interface SHA256 Example Code
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
#include "../../crypto/sha256.h"
#include "../../crypto_interface/crypto_interface_sha256.h"

#define CI_SHA2_MSG_LEN 32

static MSTATUS crypto_interface_sha2_example_single_part()
{
    MSTATUS status = OK;
    ubyte pResult[SHA256_RESULT_SIZE];
    ubyte pMessage[CI_SHA2_MSG_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    ubyte4 messageLen = CI_SHA2_MSG_LEN;

    /* We can compute the digest directly in one step */
    status = CRYPTO_INTERFACE_SHA256_completeDigest (
        pMessage, messageLen, pResult);
    if (OK != status)
        goto exit;

    /* The SHA-256 hash of the message is now contained in
     * the pResult buffer of length SHA256_RESULT_SIZE */

exit:
    return status;
}

static MSTATUS crypto_interface_sha2_example_multi_part()
{
    MSTATUS status = OK;
    BulkCtx pCtx = NULL;
    ubyte pResult[SHA256_RESULT_SIZE];
    ubyte pMessage[CI_SHA2_MSG_LEN] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    /* Create a new SHA256 context */
    status = CRYPTO_INTERFACE_SHA256_allocDigest(&pCtx);
    if (OK != status)
        goto exit;

    /* Initialize the digest operation */
    status = CRYPTO_INTERFACE_SHA256_initDigest(pCtx);
    if (OK != status)
        goto exit;

    /* Update the digest operation with the first half of the data. The
     * update call can be made any amount of times with any amount of data */
    status = CRYPTO_INTERFACE_SHA256_updateDigest (
        pCtx, pMessage, (CI_SHA2_MSG_LEN / 2));
    if (OK != status)
        goto exit;

    /* Update the context with the second half of the message */
    status = CRYPTO_INTERFACE_SHA256_updateDigest (
        pCtx, pMessage + (CI_SHA2_MSG_LEN / 2), (CI_SHA2_MSG_LEN / 2));
    if (OK != status)
        goto exit;

    /* Finalize the operation and recieve the computed digest */
    status = CRYPTO_INTERFACE_SHA256_finalDigest(pCtx, pResult);
    if (OK != status)
        goto exit;

    /* The SHA-256 hash of the message is now contained in
     * the pResult buffer of length SHA256_RESULT_SIZE */

exit:

    /* Clean up the context when finished */
    if (NULL != pCtx)
    {
        (void) CRYPTO_INTERFACE_SHA256_freeDigest(&pCtx);
    }

    return status;
}

MOC_EXTERN MSTATUS crypto_interface_sha2_example()
{
    MSTATUS status;

    status = crypto_interface_sha2_example_single_part();
    if (OK != status)
        goto exit;

    status = crypto_interface_sha2_example_multi_part();
    if (OK != status)
        goto exit;

exit:
    return status;
}
