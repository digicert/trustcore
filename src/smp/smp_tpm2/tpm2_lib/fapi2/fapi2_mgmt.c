/**
 * @file fapi2_mgmt.c
 * @brief This file contains code and structures required for managing
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

/*
 * This function gets a 32 bit value indicating the PCR's that are
 * available for a particular hash algorithm.
 */
TSS2_RC FAPI2_MGMT_getPCRSelection(
        FAPI2_CONTEXT *pCtx,
        MgmtGetPcrSelectionIn *pIn,
        MgmtGetPcrSelectionOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    MgmtCapabilityIn capabilityIn = { 0 };
    MgmtCapabilityOut capabilityOut = { 0 };
    ubyte4 i = 0;
    ubyte j = 0;
    TPML_PCR_SELECTION *pPcrSelectionList = NULL;
    TPMS_PCR_SELECTION *pPcrSelection = NULL;
    ubyte4 pcrSelectionOut = 0;

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    capabilityIn.capability = TPM2_CAP_PCRS;
    capabilityIn.property = TPM2_PT_NONE;
    capabilityIn.propertyCount = 256;

    rc = FAPI2_MGMT_getCapability(pCtx,
            &capabilityIn, &capabilityOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed FAPI2_MGMT_getCapability,"
                "rc 0x%02x = %s\n", __FUNCTION__,__LINE__, rc,
                tss2_err_string(rc));
        goto exit;
    }

    if (capabilityOut.capabilityData.capability != TPM2_CAP_PCRS)
    {
        DB_PRINT("%s.%d Invalid capability returned,"
                "rc 0x%02x = %s\n", __FUNCTION__,__LINE__, rc,
                tss2_err_string(rc));
        goto exit;
    }

    pPcrSelectionList = &capabilityOut.capabilityData.data.assignedPCR;

    if (pPcrSelectionList->count > TPM2_NUM_PCR_BANKS)
    {
        rc = TSS2_SYS_RC_MALFORMED_RESPONSE;
        DB_PRINT("%s.%d Number of PCR banks is 0. Unexpected,"
                "rc 0x%02x = %s\n", __FUNCTION__,__LINE__, rc,
                tss2_err_string(rc));
        goto exit;
    }

    /*
     * Convert TPML_PCR_SELECTION for the hashAlg into a ubyte4
     */
    for (i = 0; i < pPcrSelectionList->count; i++)
    {
        pPcrSelection = &(pPcrSelectionList->pcrSelections[i]);
        if (pPcrSelection->hash != pIn->hashAlg)
            continue;

        if (pPcrSelection->sizeofSelect > TPM2_PCR_SELECT_MAX)
        {
            rc = TSS2_SYS_RC_MALFORMED_RESPONSE;
            DB_PRINT("%s.%d Number of PCRs is 0. Unexpected,"
                    "rc 0x%02x = %s\n", __FUNCTION__,__LINE__, rc,
                    tss2_err_string(rc));
            goto exit;
        }

        for (j = 0; j < pPcrSelection->sizeofSelect; j++)
        {
            pcrSelectionOut |= pPcrSelection->pcrSelect[j] << (j * 8);
        }
    }

    if (pcrSelectionOut == 0)
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d No PCRS implemented. Unexpected,"
                "rc 0x%02x = %s\n", __FUNCTION__,__LINE__, rc,
                tss2_err_string(rc));
        goto exit;
    }

    pOut->pcrSelection = pcrSelectionOut;
    pOut->numBytesPcrSelection = pPcrSelection->sizeofSelect;

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
TSS2_RC FAPI2_MGMT_getCapability(
        FAPI2_CONTEXT *pCtx,
        MgmtCapabilityIn *pIn,
        MgmtCapabilityOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    GetCapabilityIn getCapabilityIn = { 0 };
    GetCapabilityOut getCapabilityOut = { 0 };

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    getCapabilityIn.capability = pIn->capability;
    getCapabilityIn.property = pIn->property;
    getCapabilityIn.propertyCount = pIn->propertyCount;

    rc = SAPI2_CAPABILITY_GetCapability(pCtx->pSapiCtx,
            &getCapabilityIn, &getCapabilityOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed SAPI2_CAPABILITY_GetCapability,"
                "rc 0x%02x = %s\n", __FUNCTION__,__LINE__, rc,
                tss2_err_string(rc));
        goto exit;
    }

    pOut->moreData = getCapabilityOut.moreData;
    pOut->capabilityData = getCapabilityOut.capabilityData;

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

/*
 * This function persists and object at the provided index. The function looks
 * up the transient object using the provided key name and stores it at the
 * index provided by the caller.
 */
TSS2_RC FAPI2_MGMT_persistObject(
    FAPI2_CONTEXT *pCtx,
    TPM2B_NAME *pKeyName,
    ubyte4 objectId
    )
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE, exit_rc;
    FAPI2_OBJECT *pKey = NULL;
    MOCTPM2_OBJECT_HANDLE *pKeyHandle = NULL;
    MOCTPM2_OBJECT_HANDLE *pAuthSession = { 0 };
    EvictControlIn evictControlIn = { 0 };
    EvictControlOut evictControlOut = { 0 };
    ContextFlushObjectIn flushObjectIn = { 0 };

    rc = FAPI2_CONTEXT_lookupObject(pCtx, pKeyName, &pKey);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Unable to find key object, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = FAPI2_UTILS_loadObjectTree(pCtx, pKey, &pKeyHandle);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to create handle for child key."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = FAPI2_UTILS_startSession(
        pCtx, &pAuthSession);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to Start session."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    evictControlIn.authHandle = TPM2_RH_OWNER;
    evictControlIn.pObjectHandle = pKeyHandle;
    evictControlIn.persistentHandle = objectId;
    evictControlIn.pAuthAuthHandle = &pCtx->authValues.ownerAuth;
    evictControlIn.pAuthSession = pAuthSession;

    rc = SAPI2_CTX_MGMT_EvictControl(pCtx->pSapiCtx,
            &evictControlIn, &evictControlOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to make primary key persistent."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:

    if (pKey)
    {
        flushObjectIn.objName = pKey->objectName;
        exit_rc = FAPI2_CONTEXT_flushObject(pCtx, &flushObjectIn);
    }

    if (evictControlOut.pPersistentHandle)
    {
        exit_rc = FAPI2_UTILS_destroyHandle(pCtx, &evictControlOut.pPersistentHandle);
        if (TSS2_RC_SUCCESS != exit_rc)
        {
            DB_PRINT("%s.%d Failed to destroy persistent key handle."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, exit_rc, tss2_err_string(exit_rc));
            if (TSS2_RC_SUCCESS == rc)
                rc = exit_rc;
        }
    }

    if (pAuthSession)
        exit_rc = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);

    if (pKeyHandle)
        exit_rc = FAPI2_UTILS_destroyHandle(pCtx, &pKeyHandle);

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
