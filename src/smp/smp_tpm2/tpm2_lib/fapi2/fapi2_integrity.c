/**
 * @file fapi2_integrity.c
 * @brief This file contains functions that manipulate PCRs.
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
 * This API resets the specified PCR index in the TPM.
 * The owner hierarchy authValue is expected to be set
 * appropriately in the FAPI2_CONTEXT to successfully execute
 * this API.
 */
TSS2_RC FAPI2_INTEGRITY_pcrReset(
        FAPI2_CONTEXT *pCtx,
        IntegrityPcrResetIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    PCRResetIn pcrResetIn = { 0 };
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;

    if (!pCtx || !pIn)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pIn->pcrIndex > TPM2_PCR_LAST)
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid PCR index specified, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&(pIn->pcrAuth), pCtx->nameAlgSize);

    pcrResetIn.pcrHandle = pIn->pcrIndex;
    pcrResetIn.pAuthPcrHandle = &pIn->pcrAuth;

    rc = FAPI2_UTILS_startSession(pCtx, &pAuthSession);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to Start session."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pcrResetIn.pAuthSession = pAuthSession;

    rc = SAPI2_INTEGRITY_PCRReset(pCtx->pSapiCtx, &pcrResetIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to reset PCR."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    if (pAuthSession)
        exit_rc = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

/*
 * This API reads PCR value.
 */
TSS2_RC FAPI2_INTEGRITY_pcrRead(
        FAPI2_CONTEXT *pCtx,
        IntegrityPcrReadIn *pIn,
        IntegrityPcrReadOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    PCRReadIn pcrReadIn = { 0 };
    PCRReadOut pcrReadOut = { 0 };
    TPML_PCR_SELECTION pcrSelectionList = { 0 };
    ubyte4 pcrSelection = 0;
    MgmtGetPcrSelectionIn getPcrSelectionIn = { 0 };
    MgmtGetPcrSelectionOut getPcrSelectionOut = { 0 };
    ubyte count = 0;

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pIn->pcrSelection == 0)
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d No PCR's selected, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * ensure no more than 8 bits are set in pcrSelection
     */
    pcrSelection = pIn->pcrSelection;

    while (pcrSelection)
    {
        pcrSelection &= (pcrSelection - 1);
        count++;
    }

    if (count > 8)
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d More than 8 PCR's selected, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pIn->hashAlg != TPM2_ALG_SHA1) &&
            (pIn->hashAlg != TPM2_ALG_SHA256) &&
            (pIn->hashAlg != TPM2_ALG_SHA384) &&
            (pIn->hashAlg != TPM2_ALG_SHA512))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid hash algorithm specified, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Validate the pcrSelection provided.
     * if a pcr that does not exist is selected, return an error.
     */

    getPcrSelectionIn.hashAlg = pIn->hashAlg;
    rc = FAPI2_MGMT_getPCRSelection(pCtx, &getPcrSelectionIn,
            &getPcrSelectionOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get TPM pcr infromation."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pIn->pcrSelection & ~(getPcrSelectionOut.pcrSelection))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid pcr selection specified."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * For now we support only 1 PCR bank. Cannot see a use
     * for multiple for the forseeable future!
     */
    if (pIn->pcrSelection != 0)
    {
        pcrSelectionList.count = 1;
        pcrSelectionList.pcrSelections[0].hash = pIn->hashAlg;
        pcrSelectionList.pcrSelections[0].sizeofSelect =
                getPcrSelectionOut.numBytesPcrSelection;
        DIGI_MEMCPY(pcrSelectionList.pcrSelections[0].pcrSelect,
                &pIn->pcrSelection,
                sizeof(pcrSelectionList.pcrSelections[0].pcrSelect));
    }

    pcrReadIn.pPcrSelectionIn = &pcrSelectionList;

    rc = SAPI2_INTEGRITY_PCRRead(pCtx->pSapiCtx, &pcrReadIn, &pcrReadOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to read pcr index."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->pcrUpdateCount = pcrReadOut.pcrUpdateCounter;
    pOut->pcrDigests = pcrReadOut.pcrValues;

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

/*
 * This API updates a PCR value.
 */
TSS2_RC FAPI2_INTEGRITY_pcrExtend(
        FAPI2_CONTEXT *pCtx,
        IntegrityPcrExtendIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    PCRExtendIn pcrExtendIn = { 0 };
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;
    TPML_DIGEST_VALUES digests = { 0 };

    if (!pCtx || !pIn)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pIn->pcrIndex > TPM2_PCR_LAST)
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid PCR index specified, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&(pIn->pcrAuth), pCtx->nameAlgSize);
    TPM2B_SIZE_CHECK(&(pIn->digest), TPM2B_MAX_SIZE(&(pIn->digest)));

    if ((pIn->hashAlg != TPM2_ALG_SHA1) &&
            (pIn->hashAlg != TPM2_ALG_SHA256) &&
            (pIn->hashAlg != TPM2_ALG_SHA384) &&
            (pIn->hashAlg != TPM2_ALG_SHA512))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid hash algorithm specified, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = FAPI2_UTILS_startSession(pCtx, &pAuthSession);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to Start session."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    digests.count = 1;
    digests.digests[0].hashAlg = pIn->hashAlg;
    DIGI_MEMCPY(digests.digests[0].digest.sha512, pIn->digest.buffer,
            pIn->digest.size);

    pcrExtendIn.pcrHandle = pIn->pcrIndex;
    pcrExtendIn.pAuthPcrHandle = &pIn->pcrAuth;
    pcrExtendIn.pAuthSession = pAuthSession;
    pcrExtendIn.pDigests = &digests;

    rc = SAPI2_INTEGRITY_PCRExtend(pCtx->pSapiCtx, &pcrExtendIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to read pcr index."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    if (pAuthSession)
        exit_rc = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
