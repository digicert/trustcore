/*
 * crypto_interface_random_example.c
 *
 * Crypto Interface Random Example Code
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
#include "../../cap/capsym.h"
#include "../../common/random.h"
#include "../../crypto/hw_accel.h"
#include "../../crypto_interface/crypto_interface_random.h"
#include "../../crypto_interface/crypto_interface_nist_ctr_drbg.h"

#define CI_RNG_EXAMPLE_LEN 38
#define CI_RNG_EXAMPLE_ENTROPY_LEN 8

MOC_EXTERN MSTATUS crypto_interface_random_example()
{
    MSTATUS status = OK;
    randomContext *pRandCtx = NULL;
    ubyte pRandomData[CI_RNG_EXAMPLE_LEN];
    ubyte4 randomDataLen = CI_RNG_EXAMPLE_LEN;
    ubyte pNewEntropy[CI_RNG_EXAMPLE_ENTROPY_LEN] = 
        {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}; /*illustrative only, don't use this seed! */
    ubyte4 newEntropyLen = CI_RNG_EXAMPLE_ENTROPY_LEN;

    /* Instantiate a new random context implementing a CTR-DRBG*/
    status = CRYPTO_INTERFACE_RANDOM_acquireContextEx(&pRandCtx, MODE_DRBG_CTR);
    if (OK != status)
        goto exit;

    /* Generate random data with the newly created RNG */
    status = RANDOM_numberGenerator(pRandCtx, pRandomData, (sbyte4)randomDataLen);
    if (OK != status && ERR_NIST_RNG_DBRG_RESEED_NEEDED != status)
        goto exit;

    /* pRandomData is now filled with random data */

    /* Per NIST SP800-90A 10.1 table 2, this DRBG must be reseeded
     * after 2^48 requests. In such case ERR_NIST_RNG_DBRG_RESEED_NEEDED is returned for status.
     * One may wish to reseed much more often. To reseed, code would look like the following...

    if (ERR_NIST_RNG_DBRG_RESEED_NEEDED == status)
    {
        Acquire seeding material in some manner. One manner may be to re-launch the mocana thread
        racing condition. Remember that this may take up a few seconds so one may want to 
        do this in another thread

        status = RANDOM_getAutoSeedBytes(pNewEntropy, newEntropyLen);
        if (OK != status)
            goto exit;

    */   
        /* Now call the reseeding routine for NIST CTR-DRBG */
        status = CRYPTO_INTERFACE_NIST_CTRDRBG_reseed(pRandCtx, pNewEntropy, newEntropyLen, NULL, 0);
        if (OK != status)
            goto exit;
    /* 
    } */

    /* Continue generating random data as needed */
    status = RANDOM_numberGenerator(pRandCtx, pRandomData, (sbyte4)randomDataLen);
    if (OK != status && ERR_NIST_RNG_DBRG_RESEED_NEEDED != status)
        goto exit;

exit:

    /* Clean up the context when finished */
    if (NULL != pRandCtx)
    {
        CRYPTO_INTERFACE_RANDOM_releaseContextEx(&pRandCtx);
    }

    return status;
}
