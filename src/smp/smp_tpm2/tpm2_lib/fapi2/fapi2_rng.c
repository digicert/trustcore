/**
 * @file fapi2_rng.c
 * @brief This file contains functions to use the TPM2 random number
 * generator.
 * @flags
 *  To enable this file's functions, the following flags must be defined in
 * moptions.h:
 *
 *  + \c \__ENABLE_DIGICERT_TPM2__
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

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../../../../common/mtypes.h"
#include "../../../../common/merrors.h"
#include "../../../../common/mocana.h"
#include "../../../../common/mdefs.h"
#include "../../../../common/mstdlib.h"
#include "../../../../crypto/hw_accel.h"
#include "../../../../common/debug_console.h"
#include "../tpm_common/tpm_error_utils.h"
#include "fapi2.h"
#include "fapi2_internal.h"

/*
 * Use this function to get random data from the TPM. The number of
 * bytes returned by the TPM will be no larger than the digest
 * produced by the largest digest algorithm supported by the TPM.
 */
TSS2_RC FAPI2_RNG_getRandomData(
        FAPI2_CONTEXT *pCtx,
        RngGetRandomDataIn *pIn,
        RngGetRandomDataOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    GetRandomIn getRandomIn = { 0 };
    GetRandomOut getRandomOut = { 0 };

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    getRandomIn.bytesRequested = pIn->bytesRequested;
    rc = SAPI2_RNG_GetRandom(pCtx->pSapiCtx, &getRandomIn, &getRandomOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get random bytes, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->randomBytes = getRandomOut.randomBytes;

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

/*
 * This function can be used to add additional state to the TPM
 * RNG.
 */
TSS2_RC FAPI2_RNG_stirRNG(
        FAPI2_CONTEXT *pCtx,
        RngStirRNGIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    StirRandomIn stirRandomIn = { 0 };

    if (!pCtx || !pIn)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->additionalData, 128);
    stirRandomIn.pInData = &pIn->additionalData;

    rc = SAPI2_RNG_StirRandom(pCtx->pSapiCtx, &stirRandomIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to stir TPM RNG, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
