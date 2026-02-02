/**
 * @file sapi2_enhanced_auth.c
 * @brief This file contains code required to execute TPM2 enhanced authorization
 * commands.
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
#include "sapi2_enhanced_auth.h"
#include "sapi2_session.h"

TSS2_RC SAPI2_EA_PolicyGetDigest(
        SAPI2_CONTEXT *pSapiContext,
        PolicyGetDigestIn *pIn,
        PolicyGetDigestOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    /* This command has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { 0 };

    if (!pSapiContext || !pIn || !pOut || !pIn->pPolicySession)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pHandleNames[0] = &(pIn->pPolicySession->objectName);

    cmdHeader.tag = TPM2_ST_NO_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_PolicyGetDigest;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(pIn->pPolicySession->tpm2Handle));
    cmdDesc.UnserializedHandlesSize = sizeof(pIn->pPolicySession->tpm2Handle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPM2_HANDLE;
    cmdDesc.pUnserializedParameters = NULL;
    cmdDesc.UnserializedParametersSize = 0;
    cmdDesc.parametersType = SAPI2_ST_START;
    cmdDesc.ppSessionHandles = NULL;
    cmdDesc.ppAuthValues = NULL;
    cmdDesc.numSessionHandlesAndAuthValues = 0;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_PolicyGetDigest;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = (ubyte *)(&(pOut->policyDigest));
    rspDesc.UnserializedParametersSize = sizeof(pOut->policyDigest);
    rspDesc.parametersType = SAPI2_ST_TPM2B_DIGEST;
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

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC SAPI2_EA_PolicyAuthValue(
        SAPI2_CONTEXT *pSapiContext,
        PolicyAuthValueIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    /* This command has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { 0 };
    MOCTPM2_SESSION *pSession = NULL;

    if (!pSapiContext || !pIn || !pIn->pPolicySession)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pIn->pPolicySession->type != MOCTPM2_OBJ_METADATA_TYPE_SESSION) ||
            (pIn->pPolicySession->metaDataSize != sizeof(MOCTPM2_SESSION)))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid session handle rc 0x%02x = %s\n",
                       __FUNCTION__, __LINE__, rc,
                       tss2_err_string(TSS2_SYS_RC_BAD_REFERENCE));
        goto exit;
    }

    pHandleNames[0] = &(pIn->pPolicySession->objectName);

    cmdHeader.tag = TPM2_ST_NO_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_PolicyAuthValue;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(pIn->pPolicySession->tpm2Handle));
    cmdDesc.UnserializedHandlesSize = sizeof(pIn->pPolicySession->tpm2Handle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPM2_HANDLE;
    cmdDesc.pUnserializedParameters = NULL;
    cmdDesc.UnserializedParametersSize = 0;
    cmdDesc.parametersType = SAPI2_ST_START;
    cmdDesc.ppSessionHandles = NULL;
    cmdDesc.ppAuthValues = NULL;
    cmdDesc.numSessionHandlesAndAuthValues = 0;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_PolicyAuthValue;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
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

    pSession = (MOCTPM2_SESSION *)pIn->pPolicySession->pMetadata;
    pSession->sessionHaspolicyAuthValue = TRUE;

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC SAPI2_EA_PolicyAuthorize(
        SAPI2_CONTEXT *pSapiContext,
        PolicyAuthorizeIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_POLICY_AUTHORIZE_CMD_PARAMS cmdParams = { 0 };

    /* This command has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { 0 };

    if (!pSapiContext || !pIn || !pIn->pPolicySession ||
            !pIn->pApprovedPolicy || !pIn->pCheckTicket || !pIn->pKeySign ||
            !pIn->pKeySign || !pIn->pPolicyRef)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pHandleNames[0] = &(pIn->pPolicySession->objectName);

    cmdParams.approvedPolicy = *(pIn->pApprovedPolicy);
    cmdParams.checkTicket = *(pIn->pCheckTicket);
    cmdParams.keySign = *(pIn->pKeySign);
    cmdParams.policyRef = *(pIn->pPolicyRef);

    cmdHeader.tag = TPM2_ST_NO_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_PolicyAuthorize;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(pIn->pPolicySession->tpm2Handle));
    cmdDesc.UnserializedHandlesSize = sizeof(pIn->pPolicySession->tpm2Handle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPM2_HANDLE;
    cmdDesc.pUnserializedParameters = (ubyte *)&cmdParams;
    cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
    cmdDesc.parametersType = SAPI2_ST_TPM2_POLICY_AUTHORIZE_CMD_PARAMS;
    cmdDesc.ppSessionHandles = NULL;
    cmdDesc.ppAuthValues = NULL;
    cmdDesc.numSessionHandlesAndAuthValues = 0;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_PolicyAuthorize;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
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

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC SAPI2_EA_PolicyPCR(
        SAPI2_CONTEXT *pSapiContext,
        PolicyPCRIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_POLICY_PCR_CMD_PARAMS cmdParams = { 0 };

    /* This command has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { 0 };

    if (!pSapiContext || !pIn || !pIn->pPolicySession ||
            !pIn->pPCRdigest || !pIn->pPcrs)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pHandleNames[0] = &(pIn->pPolicySession->objectName);

    cmdParams.pcrDigest = *(pIn->pPCRdigest);
    cmdParams.pcrs = *(pIn->pPcrs);

    cmdHeader.tag = TPM2_ST_NO_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_PolicyPCR;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(pIn->pPolicySession->tpm2Handle));
    cmdDesc.UnserializedHandlesSize = sizeof(pIn->pPolicySession->tpm2Handle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPM2_HANDLE;
    cmdDesc.pUnserializedParameters = (ubyte *)&cmdParams;
    cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
    cmdDesc.parametersType = SAPI2_ST_TPM2_POLICY_PCR_CMD_PARAMS;
    cmdDesc.ppSessionHandles = NULL;
    cmdDesc.ppAuthValues = NULL;
    cmdDesc.numSessionHandlesAndAuthValues = 0;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_PolicyPCR;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
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

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}


TSS2_RC SAPI2_EA_PolicyAuthorizeNV(
        SAPI2_CONTEXT *pSapiContext,
        PolicyAuthorizeNVIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_POLICY_AUTHORIZE_NV_CMD_HANDLES cmdHandles = { 0 };

    /* This command has 3 handles */
    TPM2B_NAME *pHandleNames[3] = { 0 };
    TPM2B_NAME hierarchyHandleName = { 0 };

    if (!pSapiContext || !pIn || !pIn->pPolicySession)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((NULL == pIn->pNvIndexHandle) ||
            (NULL == pIn->pAuthHandleAuth) ||
            (NULL == pIn->pAuthSession))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    cmdHandles.policySession = pIn->pPolicySession->tpm2Handle;

    if (pIn->useNvHandleForAuth)
    {
        cmdHandles.authHandle = pIn->pNvIndexHandle->tpm2Handle;
        pHandleNames[0] = &pIn->pNvIndexHandle->objectName;
    }
    else
    {
        if ((pIn->authHandle != TPM2_RH_OWNER) &&
                (pIn->authHandle != TPM2_RH_PLATFORM))
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid authHandle, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        cmdHandles.authHandle = pIn->authHandle;

        rc = SAPI2_UTILS_getObjectName(pIn->authHandle,
                NULL,
                &hierarchyHandleName);
        if (rc != TSS2_RC_SUCCESS)
        {
            DB_PRINT("%s.%d Failed SAPI2_UTILS_getObjectName(),"
                    " rc 0x%02x = %s\n", __FUNCTION__, __LINE__,
                    rc, tss2_err_string(rc));
            goto exit;
        }

        pHandleNames[0] = &hierarchyHandleName;
    }

    pHandleNames[1] = &(pIn->pNvIndexHandle->objectName);
    pHandleNames[2] = &(pIn->pPolicySession->objectName);

    cmdHeader.tag = TPM2_ST_NO_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_PolicyAuthorizeNV;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(cmdHandles));
    cmdDesc.UnserializedHandlesSize = sizeof(cmdHandles);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 3;
    cmdDesc.handlesType = SAPI2_ST_TPM2_POLICY_AUTHORIZE_NV_CMD_HANDLES;
    cmdDesc.pUnserializedParameters = NULL;
    cmdDesc.UnserializedParametersSize = 0;
    cmdDesc.parametersType = SAPI2_ST_START;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthHandleAuth);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_PolicyAuthorizeNV;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
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

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC SAPI2_EA_PolicySecret(
        SAPI2_CONTEXT *pSapiContext,
        PolicySecretIn *pIn,
        PolicySecretOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_POLICY_SECRET_CMD_HANDLES cmdHandles = { 0 };
    TPM2_POLICY_SECRET_CMD_PARAMS cmdParams = { 0 };
    TPM2_POLICY_SECRET_RSP_PARAMS rspParams = { 0 };

    /* This command has 2 handles */
    TPM2B_NAME *pHandleNames[2] = { 0 };

    if (!pSapiContext || !pIn || !pOut ||
            !pIn->pAuthObject || !pIn->pAuthSession ||
            !pIn->pCpHash || !pIn->pNonceTpm || !pIn->pPolicyRef ||
            !pIn->pPolicySession || !pIn->pAuthObjectAuth)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pHandleNames[0] = &(pIn->pAuthObject->objectName);
    pHandleNames[1] = &(pIn->pPolicySession->objectName);

    cmdHandles.authHandle = pIn->pAuthObject->tpm2Handle;
    cmdHandles.policySession = pIn->pPolicySession->tpm2Handle;

    cmdParams.nonceTPM = *(pIn->pNonceTpm);
    cmdParams.cpHashA = *(pIn->pCpHash);
    cmdParams.policyRef = *(pIn->pPolicyRef);
    cmdParams.expiration = pIn->expiration;

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_PolicySecret;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(cmdHandles));
    cmdDesc.UnserializedHandlesSize = sizeof(cmdHandles);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 2;
    cmdDesc.handlesType = SAPI2_ST_TPM2_POLICY_SECRET_CMD_HANDLES;
    cmdDesc.pUnserializedParameters = (ubyte *)&cmdParams;
    cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
    cmdDesc.parametersType = SAPI2_ST_TPM2_POLICY_SECRET_CMD_PARAMS;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthObjectAuth);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_PolicySecret;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = (ubyte *)&rspParams;
    rspDesc.UnserializedParametersSize = sizeof(rspParams);
    rspDesc.parametersType = SAPI2_ST_TPM2_POLICY_SECRET_RSP_PARAMS;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pAuthObjectAuth);
    rspDesc.numSessionHandlesAndAuthValues = 1;

    rc = SAPI2_CONTEXT_executeCommand(pSapiContext, &cmdDesc, &rspDesc);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute command, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->policyTicket = rspParams.policyTicket;
    pOut->timeout = rspParams.timeout;

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC SAPI2_EA_PolicySigned(
        SAPI2_CONTEXT *pSapiContext,
        PolicySignedIn *pIn,
        PolicySignedOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_POLICY_SIGNED_CMD_HANDLES cmdHandles = { 0 };
    TPM2_POLICY_SIGNED_CMD_PARAMS cmdParams = { 0 };
    TPM2_POLICY_SIGNED_RSP_PARAMS rspParams = { 0 };

    /* This command has 2 handles */
    TPM2B_NAME *pHandleNames[2] = { 0 };

    if (!pSapiContext || !pIn || !pOut || !pIn->pAuthObject ||
            !pIn->pCpHash || !pIn->pNonceTpm || !pIn->pPolicyRef ||
            !pIn->pPolicySession || !pIn->pAuth)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pHandleNames[0] = &(pIn->pAuthObject->objectName);
    pHandleNames[1] = &(pIn->pPolicySession->objectName);

    cmdHandles.authObject = pIn->pAuthObject->tpm2Handle;
    cmdHandles.policySession = pIn->pPolicySession->tpm2Handle;

    cmdParams.nonceTPM = *(pIn->pNonceTpm);
    cmdParams.cpHashA = *(pIn->pCpHash);
    cmdParams.policyRef = *(pIn->pPolicyRef);
    cmdParams.expiration = pIn->expiration;
    cmdParams.auth = *(pIn->pAuth);

    cmdHeader.tag = TPM2_ST_NO_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_PolicySigned;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(cmdHandles));
    cmdDesc.UnserializedHandlesSize = sizeof(cmdHandles);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 2;
    cmdDesc.handlesType = SAPI2_ST_TPM2_POLICY_SECRET_CMD_HANDLES;
    cmdDesc.pUnserializedParameters = (ubyte *)&cmdParams;
    cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
    cmdDesc.parametersType = SAPI2_ST_TPM2_POLICY_SECRET_CMD_PARAMS;
    cmdDesc.ppSessionHandles = NULL;
    cmdDesc.ppAuthValues = NULL;
    cmdDesc.numSessionHandlesAndAuthValues = 0;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_PolicySigned;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = (ubyte *)&rspParams;
    rspDesc.UnserializedParametersSize = sizeof(rspParams);
    rspDesc.parametersType = SAPI2_ST_TPM2_POLICY_SECRET_RSP_PARAMS;
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

    pOut->policyTicket = rspParams.policyTicket;
    pOut->timeout = rspParams.timeout;

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC SAPI2_EA_PolicyDuplicationSelect(
        SAPI2_CONTEXT *pSapiContext,
        PolicyDuplicationSelectIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_POLICY_DUPLICATIONSELECT_CMD_PARAMS cmdParams = { 0 };

    /* This command has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { 0 };

    if (!pSapiContext || !pIn || !pIn->pPolicySession)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pHandleNames[0] = &(pIn->pPolicySession->objectName);

    cmdParams.objectName = *(pIn->pObjectName);
    cmdParams.newParentName = *(pIn->pNewParentName);
    cmdParams.includeObject = pIn->includeObject ;

    cmdHeader.tag = TPM2_ST_NO_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_PolicyDuplicationSelect;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(pIn->pPolicySession->tpm2Handle));
    cmdDesc.UnserializedHandlesSize = sizeof(pIn->pPolicySession->tpm2Handle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPM2_HANDLE;
    cmdDesc.pUnserializedParameters = (ubyte *)&cmdParams;
    cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
    cmdDesc.parametersType = SAPI2_ST_TPM2_POLICY_DUPLICATIONSELECT_CMD_PARAMS;
    cmdDesc.ppSessionHandles = NULL;
    cmdDesc.ppAuthValues = NULL;
    cmdDesc.numSessionHandlesAndAuthValues = 0;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_PolicyDuplicationSelect;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
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

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC SAPI2_EA_PolicyCommandCode(
        SAPI2_CONTEXT *pSapiContext,
        PolicyCommandCodeIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_POLICY_COMMANDCODE_CMD_PARAMS cmdParams = { 0 };

    /* This command has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { 0 };

    if (!pSapiContext || !pIn || !pIn->pPolicySession)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pHandleNames[0] = &(pIn->pPolicySession->objectName);

    cmdParams.code = pIn->code;

    cmdHeader.tag = TPM2_ST_NO_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_PolicyCommandCode;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(pIn->pPolicySession->tpm2Handle));
    cmdDesc.UnserializedHandlesSize = sizeof(pIn->pPolicySession->tpm2Handle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPM2_HANDLE;
    cmdDesc.pUnserializedParameters = (ubyte *)&cmdParams;
    cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
    cmdDesc.parametersType = SAPI2_ST_TPM2_POLICY_COMMANDCODE_CMD_PARAMS;
    cmdDesc.ppSessionHandles = NULL;
    cmdDesc.ppAuthValues = NULL;
    cmdDesc.numSessionHandlesAndAuthValues = 0;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_PolicyCommandCode;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
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

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}



#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
