/**
 * @file sapi2_sequence.c
 * @brief This file contains code required to execute TPM2 sequence commands such as hash
 * and hmac
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
#include "sapi2_sequence.h"

TSS2_RC SAPI2_SEQUENCE_HashSequenceStart(
        SAPI2_CONTEXT *pSapiContext,
        HashSequenceStartIn *pIn,
        HashSequenceStartOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_HASH_SEQUENCE_START_CMD_PARAMS cmdParams = { 0 };
    TPMI_DH_OBJECT sequenceHandle = TPM2_RH_UNASSIGNED;

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pOut) || (NULL == pIn->pSequenceAuth))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    cmdHeader.tag = TPM2_ST_NO_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_HashSequenceStart;

    cmdParams.auth = *(pIn->pSequenceAuth);
    cmdParams.hashAlg = pIn->hashAlg;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = NULL;
    cmdDesc.UnserializedHandlesSize = 0;
    cmdDesc.ppNames = NULL;
    cmdDesc.numHandlesAndNames = 0;
    cmdDesc.handlesType = SAPI2_ST_START;
    cmdDesc.pUnserializedParameters = (ubyte*)&cmdParams;
    cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
    cmdDesc.parametersType = SAPI2_ST_TPM2_SHADOW_TPM2_HASH_SEQUENCE_START_CMD_PARAMS;
    cmdDesc.ppSessionHandles = NULL;
    cmdDesc.ppAuthValues = 0;
    cmdDesc.numSessionHandlesAndAuthValues = 0;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_HashSequenceStart;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = (ubyte *)(&sequenceHandle);
    rspDesc.UnserializedHandlesSize = sizeof(sequenceHandle);
    rspDesc.handlesType = SAPI2_ST_TPMI_DH_OBJECT;
    rspDesc.pUnserializedParameters = NULL;
    rspDesc.UnserializedParametersSize = 0;
    rspDesc.parametersType = SAPI2_ST_START;
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

    pOut->pHashSequenceHandle = NULL;
    rc = SAPI2_HANDLES_createObjectHandle(sequenceHandle,
            NULL, &pOut->pHashSequenceHandle);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to create object handle for object, "
                "rc 0x%02x = %s\n", __FUNCTION__, __LINE__, rc,
                tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    if (TSS2_RC_SUCCESS != rc)
    {
        if (pOut && pOut->pHashSequenceHandle)
        {
            SAPI2_HANDLES_destroyHandle(&pOut->pHashSequenceHandle, TRUE);
            pOut->pHashSequenceHandle = NULL;
        }
    }

    return rc;
}

TSS2_RC SAPI2_SEQUENCE_SequenceUpdate(
        SAPI2_CONTEXT *pSapiContext,
        SequenceUpdateIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    /*
     * Sequence handle name is the EmptyBuffer
     */
    TPM2B_NAME sequenceHandleName = { 0 };

    /* This command has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { &sequenceHandleName };

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pIn->pHashSequenceHandle) || (NULL == pIn->pSequenceAuth) ||
            (NULL == pIn->pMaxBuffer) || (NULL == pIn->pAuthSession))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_SequenceUpdate;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)&(pIn->pHashSequenceHandle->tpm2Handle);
    cmdDesc.UnserializedHandlesSize = sizeof(pIn->pHashSequenceHandle->tpm2Handle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPM2_HANDLE;
    cmdDesc.pUnserializedParameters = (ubyte *)pIn->pMaxBuffer;
    cmdDesc.UnserializedParametersSize = sizeof(*pIn->pMaxBuffer);
    cmdDesc.parametersType = SAPI2_ST_TPM2B_MAX_BUFFER;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pSequenceAuth);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_SequenceUpdate;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = NULL;
    rspDesc.UnserializedParametersSize = 0;
    rspDesc.parametersType = SAPI2_ST_START;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pSequenceAuth);
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

TSS2_RC SAPI2_SEQUENCE_SequenceComplete(
        SAPI2_CONTEXT *pSapiContext,
        SequenceCompleteIn *pIn,
        SequenceCompleteOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_SEQUENCE_COMPLETE_CMD_PARAMS cmdParams = { 0 };
    TPM2_SEQUENCE_COMPLETE_RSP_PARAMS rspParams = { 0 };

    /*
     * Sequence handle name is the EmptyBuffer
     */
    TPM2B_NAME sequenceHandleName = { 0 };

    /* This command has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { &sequenceHandleName };

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pIn->ppHashSequenceHandle) || (NULL == pIn->pSequenceAuth) ||
            (NULL == pIn->pMaxBuffer) || (NULL == pIn->pAuthSession) ||
            (NULL == *(pIn->ppHashSequenceHandle)) || (NULL == pOut))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_SequenceComplete;

    cmdParams.buffer = *(pIn->pMaxBuffer);
    cmdParams.hierarchy = pIn->hierarchy;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)&((*(pIn->ppHashSequenceHandle))->tpm2Handle);
    cmdDesc.UnserializedHandlesSize = sizeof((*(pIn->ppHashSequenceHandle))->tpm2Handle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPM2_HANDLE;
    cmdDesc.pUnserializedParameters = (ubyte *)&cmdParams;
    cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
    cmdDesc.parametersType = SAPI2_ST_TPM2_SHADOW_TPM2_SEQUENCE_COMPLETE_CMD_PARAMS;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pSequenceAuth);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_SequenceComplete;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = (ubyte *)&(rspParams);
    rspDesc.UnserializedParametersSize = sizeof(rspParams);
    rspDesc.parametersType = SAPI2_ST_TPM2_SHADOW_TPM2_SEQUENCE_COMPLETE_RSP_PARAMS;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pSequenceAuth);
    rspDesc.numSessionHandlesAndAuthValues = 1;

    rc = SAPI2_CONTEXT_executeCommand(pSapiContext, &cmdDesc, &rspDesc);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute command, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = SAPI2_HANDLES_destroyHandle(pIn->ppHashSequenceHandle, TRUE);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to free object handle(memory leak)"
                ", rc 0x%02x = %s\n",
                __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    *(pIn->ppHashSequenceHandle) = NULL;

    pOut->result = rspParams.digest;
    pOut->validation = rspParams.validation;

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
