/**
 * @file fapi2_testing.c
 * @brief This file contains code and structures required for testing
 * the TPM2.
 *
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
#include "fapi2_testing.h"

/*
 * This function gets a 32 bit value indicating the PCR's that are
 * available for a particular hash algorithm.
 */
TSS2_RC FAPI2_TESTING_SelfTest(
        FAPI2_CONTEXT *pCtx,
        TestingSelfTestIn *pIn,
        TestingSelfTestOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    SelfTestIn testIn = { 0 };

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (0 == pIn->getResultsOnly)
    {
        testIn.fullTest = pIn->fullTest;

        rc = SAPI2_TESTING_SelfTest(pCtx->pSapiCtx, &testIn);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed SAPI2_TESTING_SelfTest,"
                    "rc 0x%02x = %s\n", __FUNCTION__,__LINE__, rc,
                    tss2_err_string(rc));
            goto exit;
        }
    }

    rc = FAPI2_TESTING_getTestResult(pCtx, pOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed SAPI2_TESTING_GetTestResult,"
                "rc 0x%02x = %s\n", __FUNCTION__,__LINE__, rc,
                tss2_err_string(rc));
        goto exit;
    }

    if (pOut->testResult != TSS2_RC_SUCCESS )
    {
        DB_PRINT("%s.%d Selftest returned,"
                "rc 0x%02x = %s\n", __FUNCTION__,__LINE__, rc,
                tss2_err_string(rc));
        goto exit;
    }


    rc = TSS2_RC_SUCCESS;

exit:
    return rc;
}

/*
 * This function is a direct map of the TPM2_GetCapability command. Its
 * use and input parameter values are documented in the TPM2 library
 * specifications. It is recommended to use wrapper/helper functions
 * for capability to simply application programming. This is provided
 * for advanced tpm users.
 */
TSS2_RC FAPI2_TESTING_getTestResult(
        FAPI2_CONTEXT *pCtx,
        TestingSelfTestOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    MSTATUS status = OK;
    GetTestResultOut getTestResultOut = { 0 };

    if (!pCtx || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = SAPI2_TESTING_GetTestResult(pCtx->pSapiCtx, &getTestResultOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed SAPI2_TESTING_GetTestResult,"
                "rc 0x%02x = %s\n", __FUNCTION__,__LINE__, rc,
                tss2_err_string(rc));
        goto exit;
    }

    pOut->testResult = getTestResultOut.testResult;
    status = DIGI_MEMSET(pOut->outData.buffer, 0, sizeof(pOut->outData.buffer));
    if (OK != status)
    {
        /* Log the error, but don't fail */
        DB_PRINT("%s.%d Failed DIGI_MEMSET,"
                "status %d = %s\n", __FUNCTION__,__LINE__, status,
                MERROR_lookUpErrorCode(status));
    }
    status = DIGI_MEMCPY(pOut->outData.buffer, getTestResultOut.outData.buffer, getTestResultOut.outData.size);
    if (OK != status)
    {
        rc = TSS2_FAPI_RC_IO_ERROR;
        DB_PRINT("%s.%d Failed DIGI_MEMCPY,"
                "status %d = %s\n", __FUNCTION__,__LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }
    pOut->outData.size = getTestResultOut.outData.size;

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
