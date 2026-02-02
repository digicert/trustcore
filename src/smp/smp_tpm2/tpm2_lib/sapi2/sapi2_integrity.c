/**
 * @file sapi2_integrity.c
 * @brief This file contains code required to execute PCR related commands.
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
#include "sapi2_handles.h"
#include "sapi2_utils.h"
#include "sapi2_integrity.h"

TSS2_RC SAPI2_INTEGRITY_PCRSetAuthValue(
        SAPI2_CONTEXT *pSapiContext,
        PCRSetAuthValueIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2B_NAME pcrHandleName = { 0 };

    /* TPM2_PCRSetAuthValue has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { &pcrHandleName };

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pIn->pAuthSession) ||
            (NULL == pIn->pAuthPcrHandle) ||
            (NULL == pIn->pNewAuth))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = SAPI2_UTILS_getObjectName(pIn->pcrHandle,
            NULL,
            &pcrHandleName);
    if (rc != TSS2_RC_SUCCESS)
    {
        DB_PRINT("%s.%d Failed SAPI2_UTILS_getObjectName(),"
                " rc 0x%02x = %s\n", __FUNCTION__, __LINE__,
                rc, tss2_err_string(rc));
        goto exit;
    }

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_PCR_SetAuthValue;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(pIn->pcrHandle));
    cmdDesc.UnserializedHandlesSize = sizeof(pIn->pcrHandle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPMI_DH_PCR;
    cmdDesc.pUnserializedParameters = (ubyte *)(pIn->pNewAuth);
    cmdDesc.UnserializedParametersSize = sizeof(*(pIn->pNewAuth));
    cmdDesc.parametersType = SAPI2_ST_TPM2B_DIGEST;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthPcrHandle);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_PCR_SetAuthValue;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = NULL;
    rspDesc.UnserializedParametersSize = 0;
    rspDesc.parametersType = SAPI2_ST_START;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pNewAuth);
    rspDesc.numSessionHandlesAndAuthValues = 1;

    rc = SAPI2_CONTEXT_executeCommand(pSapiContext, &cmdDesc, &rspDesc);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute command, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC SAPI2_INTEGRITY_PCRReset(
        SAPI2_CONTEXT *pSapiContext,
        PCRResetIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2B_NAME pcrHandleName = { 0 };

    /* TPM2_PCRReset has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { &pcrHandleName };

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pIn->pAuthSession) ||
            (NULL == pIn->pAuthPcrHandle))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = SAPI2_UTILS_getObjectName(pIn->pcrHandle,
            NULL,
            &pcrHandleName);
    if (rc != TSS2_RC_SUCCESS)
    {
        DB_PRINT("%s.%d Failed SAPI2_UTILS_getObjectName(),"
                " rc 0x%02x = %s\n", __FUNCTION__, __LINE__,
                rc, tss2_err_string(rc));
        goto exit;
    }

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_PCR_Reset;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(pIn->pcrHandle));
    cmdDesc.UnserializedHandlesSize = sizeof(pIn->pcrHandle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPMI_DH_PCR;
    cmdDesc.pUnserializedParameters = NULL;
    cmdDesc.UnserializedParametersSize = 0;
    cmdDesc.parametersType = SAPI2_ST_START;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthPcrHandle);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_PCR_Reset;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = NULL;
    rspDesc.UnserializedParametersSize = 0;
    rspDesc.parametersType = SAPI2_ST_START;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pAuthPcrHandle);
    rspDesc.numSessionHandlesAndAuthValues = 1;

    rc = SAPI2_CONTEXT_executeCommand(pSapiContext, &cmdDesc, &rspDesc);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute command, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC SAPI2_INTEGRITY_PCRExtend(
        SAPI2_CONTEXT *pSapiContext,
        PCRExtendIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2B_NAME pcrHandleName = { 0 };

    /* TPM2_PCRExtend has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { &pcrHandleName };

    TPML_DIGEST_VALUES digests = { 0 };

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pIn->pAuthSession) ||
            (NULL == pIn->pAuthPcrHandle) ||
            (NULL == pIn->pDigests))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = SAPI2_UTILS_getObjectName(pIn->pcrHandle,
            NULL,
            &pcrHandleName);
    if (rc != TSS2_RC_SUCCESS)
    {
        DB_PRINT("%s.%d Failed SAPI2_UTILS_getObjectName(),"
                " rc 0x%02x = %s\n", __FUNCTION__, __LINE__,
                rc, tss2_err_string(rc));
        goto exit;
    }

    digests = *(pIn->pDigests);

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_PCR_Extend;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(pIn->pcrHandle));
    cmdDesc.UnserializedHandlesSize = sizeof(pIn->pcrHandle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPMI_DH_PCR;
    cmdDesc.pUnserializedParameters = (ubyte *)(&digests);
    cmdDesc.UnserializedParametersSize = sizeof(digests);
    cmdDesc.parametersType = SAPI2_ST_TPML_DIGEST_VALUES;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthPcrHandle);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_PCR_Extend;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = NULL;
    rspDesc.UnserializedParametersSize = 0;
    rspDesc.parametersType = SAPI2_ST_START;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pAuthPcrHandle);
    rspDesc.numSessionHandlesAndAuthValues = 1;

    rc = SAPI2_CONTEXT_executeCommand(pSapiContext, &cmdDesc, &rspDesc);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute command, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC SAPI2_INTEGRITY_PCRRead(
        SAPI2_CONTEXT *pSapiContext,
        PCRReadIn *pIn,
        PCRReadOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPML_PCR_SELECTION pcrSelection = { 0 };
    TPM2_PCR_READ_RSP_PARAMS rspParams = { 0 };

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pOut) ||
            (NULL == pIn->pPcrSelectionIn))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pcrSelection = *(pIn->pPcrSelectionIn);

    cmdHeader.tag = TPM2_ST_NO_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_PCR_Read;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = NULL;
    cmdDesc.UnserializedHandlesSize = 0;
    cmdDesc.ppNames = NULL;
    cmdDesc.numHandlesAndNames = 0;
    cmdDesc.handlesType = SAPI2_ST_START;
    cmdDesc.pUnserializedParameters = (ubyte *)(&pcrSelection);
    cmdDesc.UnserializedParametersSize = sizeof(pcrSelection);
    cmdDesc.parametersType = SAPI2_ST_TPML_PCR_SELECTION;
    cmdDesc.ppSessionHandles = NULL;
    cmdDesc.ppAuthValues = NULL;
    cmdDesc.numSessionHandlesAndAuthValues = 0;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_PCR_Read;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = (ubyte *)(&rspParams);
    rspDesc.UnserializedParametersSize = sizeof(rspParams);
    rspDesc.parametersType = SAPI2_ST_TPM2_PCR_READ_RSP_PARAMS;
    rspDesc.ppSessionHandles = NULL;
    rspDesc.ppAuthValues = NULL;
    rspDesc.numSessionHandlesAndAuthValues = 0;

    rc = SAPI2_CONTEXT_executeCommand(pSapiContext, &cmdDesc, &rspDesc);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute command, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->pcrSelectionOut = rspParams.pcrSelectionOut;
    pOut->pcrUpdateCounter = rspParams.pcrUpdateCounter;
    pOut->pcrValues = rspParams.pcrValues;

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC SAPI2_INTEGRITY_PCREvent(
        SAPI2_CONTEXT *pSapiContext,
        PCREventIn *pIn,
        PCREventOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2B_NAME pcrHandleName = { 0 };

    /* TPM2_PCREvent has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { &pcrHandleName };
    TPM2B_EVENT eventData = { 0 };
    TPML_DIGEST_VALUES digests = { 0 };

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pOut) ||
            (NULL == pIn->pAuthPcrHandle) ||
            (NULL == pIn->pEventData) ||
            (NULL == pIn->pAuthSession))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = SAPI2_UTILS_getObjectName(pIn->pcrHandle,
            NULL,
            &pcrHandleName);
    if (rc != TSS2_RC_SUCCESS)
    {
        DB_PRINT("%s.%d Failed SAPI2_UTILS_getObjectName(),"
                " rc 0x%02x = %s\n", __FUNCTION__, __LINE__,
                rc, tss2_err_string(rc));
        goto exit;
    }

    eventData = *(pIn->pEventData);

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_PCR_Event;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&pIn->pcrHandle);
    cmdDesc.UnserializedHandlesSize = sizeof(pIn->pcrHandle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPMI_DH_PCR;
    cmdDesc.pUnserializedParameters = (ubyte *)(&eventData);
    cmdDesc.UnserializedParametersSize = sizeof(eventData);
    cmdDesc.parametersType = SAPI2_ST_TPM2B_EVENT;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthPcrHandle);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_PCR_Event;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = (ubyte *)(&digests);
    rspDesc.UnserializedParametersSize = sizeof(digests);
    rspDesc.parametersType = SAPI2_ST_TPML_DIGEST_VALUES;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pAuthPcrHandle);
    rspDesc.numSessionHandlesAndAuthValues = 1;

    rc = SAPI2_CONTEXT_executeCommand(pSapiContext, &cmdDesc, &rspDesc);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute command, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->digests = digests;

    rc = TSS2_RC_SUCCESS;
exit:

    return rc;
}

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
