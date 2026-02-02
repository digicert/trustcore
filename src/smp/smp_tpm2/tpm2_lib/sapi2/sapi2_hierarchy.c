/**
 * @file sapi2_hierarchy.c
 * @brief This file contains code required to execute TPM 2 hierarchy commands.
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
#include "sapi2_hierarchy.h"
#include "sapi2_utils.h"

TSS2_RC SAPI2_HIERARCHY_HierarchyChangeAuth(
        SAPI2_CONTEXT *pSapiContext,
        HierarchyChangeAuthIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2B_NAME hierarchyHandleName = { 0 };

    /* TPM2_HierarchyChangeAuth has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { &hierarchyHandleName };

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pIn->pAuthSession) ||
            (NULL == pIn->pCurrentAuth) ||
            (NULL == pIn->pNewAuth))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

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

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_HierarchyChangeAuth;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(pIn->authHandle));
    cmdDesc.UnserializedHandlesSize = sizeof(pIn->authHandle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPMI_RH_HIERARCHY_AUTH;
    cmdDesc.pUnserializedParameters = (ubyte *)(pIn->pNewAuth);
    cmdDesc.UnserializedParametersSize = sizeof(*(pIn->pNewAuth));
    cmdDesc.parametersType = SAPI2_ST_TPM2B_AUTH;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pCurrentAuth);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_HierarchyChangeAuth;
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

TSS2_RC
SAPI2_HIERARCHY_CreatePrimary(
        SAPI2_CONTEXT *pSapiContext,
        CreatePrimaryIn *pIn,
        CreatePrimaryOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2B_NAME hierarchyHandleName = { 0 };

    /* TPM2_HierarchyChangeAuth has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { &hierarchyHandleName };

    TPM2_CREATE_PRIMARY_CMD_PARAMS cmdParams = { 0 };
    TPM2_CREATE_PRIMARY_RSP_PARAMS rspParams = { 0 };
    TPM2_HANDLE newObjectHandle = 0;
    sbyte4 cmpResult = 0;

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pOut))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((NULL == pIn->pInSensitive) || (NULL == pIn->pInPublic) ||
            (NULL == pIn->pOutsideInfo) || (NULL == pIn->pCreationPCR) ||
            (NULL == pIn->pAuthSession) ||
            (NULL == pIn->pAuthPrimaryHandle))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->pObjectHandle = NULL;

    rc = SAPI2_UTILS_getObjectName(pIn->primaryHandle,
            NULL,
            &hierarchyHandleName);
    if (rc != TSS2_RC_SUCCESS)
    {
        DB_PRINT("%s.%d Failed SAPI2_UTILS_getObjectName(),"
                " rc 0x%02x = %s\n", __FUNCTION__, __LINE__,
                rc, tss2_err_string(rc));
        goto exit;
    }

    cmdParams.inSensitive = *(pIn->pInSensitive);
    cmdParams.inPublic = *(pIn->pInPublic);
    cmdParams.outsideInfo = *(pIn->pOutsideInfo);
    cmdParams.creationPCR = *(pIn->pCreationPCR);

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_CreatePrimary;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(pIn->primaryHandle));
    cmdDesc.UnserializedHandlesSize = sizeof(pIn->primaryHandle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPMI_RH_HIERARCHY;
    cmdDesc.pUnserializedParameters = (ubyte *)(&cmdParams);
    cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
    cmdDesc.parametersType = SAPI2_ST_TPM2_CREATE_PRIMARY_CMD_PARAMS;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthPrimaryHandle);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_CreatePrimary;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = (ubyte *)&newObjectHandle;
    rspDesc.UnserializedHandlesSize = sizeof(newObjectHandle);
    rspDesc.handlesType = SAPI2_ST_TPM2_HANDLE;
    rspDesc.pUnserializedParameters = (ubyte *)&rspParams;
    rspDesc.UnserializedParametersSize = sizeof(rspParams);
    rspDesc.parametersType = SAPI2_ST_TPM2_CREATE_PRIMARY_RSP_PARAMS;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pAuthPrimaryHandle);
    rspDesc.numSessionHandlesAndAuthValues = 1;

    rc = SAPI2_CONTEXT_executeCommand(pSapiContext, &cmdDesc, &rspDesc);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute command, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->pObjectHandle = NULL;
    rc = SAPI2_HANDLES_createObjectHandle(newObjectHandle,
            &rspParams.outPublic.publicArea, &pOut->pObjectHandle);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to create object handle for primary object, "
                "rc 0x%02x = %s\n", __FUNCTION__, __LINE__, rc,
                tss2_err_string(rc));
        goto exit;
    }

    if (OK != DIGI_MEMCMP((ubyte *)&pOut->pObjectHandle->objectName,
            (ubyte *)&rspParams.name, sizeof(rspParams.name),
            &cmpResult))
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Name computation from TPM different from"
                " local computation,"
                " rc 0x%02x = %s\n", __FUNCTION__, __LINE__, rc,
                tss2_err_string(rc));
        goto exit;
    }

    if (cmpResult != 0)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Name computation from TPM different from"
                " local computation,"
                " rc 0x%02x = %s\n", __FUNCTION__, __LINE__, rc,
                tss2_err_string(rc));
        goto exit;
    }

    pOut->outPublic = rspParams.outPublic;
    pOut->creationData = rspParams.creationData;
    pOut->creationHash = rspParams.creationHash;
    pOut->creationTicket = rspParams.creationTicket;

    rc = TSS2_RC_SUCCESS;
exit:
    if (TSS2_RC_SUCCESS != rc)
    {
        if (pOut && pOut->pObjectHandle)
        {
            SAPI2_HANDLES_destroyHandle(&pOut->pObjectHandle, TRUE);
            pOut->pObjectHandle = NULL;
        }
    }
    return rc;
}

TSS2_RC
SAPI2_HIERARCHY_HierarchyControl(
        SAPI2_CONTEXT *pSapiContext,
        HierarchyControlIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2B_NAME hierarchyHandleName = { 0 };

    /* TPM2_HierarchyChangeAuth has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { &hierarchyHandleName };

    TPM2_HIERARCHY_CONTROL_CMD_PARAMS cmdParams = { 0 };

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pIn->pAuthSession) ||
            (NULL == pIn->pAuthPrimaryHandle))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = SAPI2_UTILS_getObjectName(pIn->primaryHandle,
            NULL,
            &hierarchyHandleName);
    if (rc != TSS2_RC_SUCCESS)
    {
        DB_PRINT("%s.%d Failed SAPI2_UTILS_getObjectName(),"
                " rc 0x%02x = %s\n", __FUNCTION__, __LINE__,
                rc, tss2_err_string(rc));
        goto exit;
    }

    cmdParams.enable = pIn->enable;
    cmdParams.state = pIn->state;

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_HierarchyControl;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(pIn->primaryHandle));
    cmdDesc.UnserializedHandlesSize = sizeof(pIn->primaryHandle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPMI_RH_HIERARCHY;
    cmdDesc.pUnserializedParameters = (ubyte *)(&cmdParams);
    cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
    cmdDesc.parametersType = SAPI2_ST_TPM2_HIERARCHY_CONTROL_CMD_PARAMS;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthPrimaryHandle);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_HierarchyControl;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = NULL;
    rspDesc.UnserializedParametersSize = 0;
    rspDesc.parametersType = SAPI2_ST_START;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pAuthPrimaryHandle);
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

TSS2_RC
SAPI2_HIERARCHY_Clear(
        SAPI2_CONTEXT *pSapiContext,
        ClearIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2B_NAME hierarchyHandleName = { 0 };

    /* TPM2_Clear has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { &hierarchyHandleName };
    TPM2B_AUTH LockoutEmptyAuth = { 0 };
    TPM2B_AUTH *pLockoutEmptyAuth = &LockoutEmptyAuth;

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pIn->pAuthSession) ||
            (NULL == pIn->pAuthAuthHandle))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

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

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_Clear;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(pIn->authHandle));
    cmdDesc.UnserializedHandlesSize = sizeof(pIn->authHandle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPMI_RH_CLEAR;
    cmdDesc.pUnserializedParameters = NULL;
    cmdDesc.UnserializedParametersSize = 0;
    cmdDesc.parametersType = SAPI2_ST_START;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthAuthHandle);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_Clear;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = NULL;
    rspDesc.UnserializedParametersSize = 0;
    rspDesc.parametersType = SAPI2_ST_START;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.numSessionHandlesAndAuthValues = 1;

    if (pIn->authHandle == TPM2_RH_LOCKOUT)
        rspDesc.ppAuthValues = &(pLockoutEmptyAuth);
    else
        rspDesc.ppAuthValues = &(pIn->pAuthAuthHandle);

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

TSS2_RC
SAPI2_HIERARCHY_DALockoutReset(
        SAPI2_CONTEXT *pSapiContext,
        DALockoutResetIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2B_NAME hierarchyHandleName = { 0 };

    /* TPM2_DictionaryAttackLockReset has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { &hierarchyHandleName };

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pIn->pAuthSession) ||
            (NULL == pIn->pAuthAuthHandle))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

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

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_DictionaryAttackLockReset;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(pIn->authHandle));
    cmdDesc.UnserializedHandlesSize = sizeof(pIn->authHandle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPMI_RH_CLEAR;
    cmdDesc.pUnserializedParameters = NULL;
    cmdDesc.UnserializedParametersSize = 0;
    cmdDesc.parametersType = SAPI2_ST_START;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthAuthHandle);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_DictionaryAttackLockReset;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = NULL;
    rspDesc.UnserializedParametersSize = 0;
    rspDesc.parametersType = SAPI2_ST_START;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.numSessionHandlesAndAuthValues = 1;
    rspDesc.ppAuthValues = &(pIn->pAuthAuthHandle);

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

TSS2_RC
SAPI2_HIERARCHY_DALockoutParameters(
        SAPI2_CONTEXT *pSapiContext,
        DALockoutParametersIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };
    TPM2_DA_LOCKOUT_PARAMETERS lockoutParameters = {0};

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2B_NAME hierarchyHandleName = { 0 };

    /* TPM2_DictionaryAttackParameters has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { &hierarchyHandleName };

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pIn->pAuthSession) ||
            (NULL == pIn->pAuthAuthHandle))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

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

    lockoutParameters = pIn->lockoutParameters;

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_DictionaryAttackParameters;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(pIn->authHandle));
    cmdDesc.UnserializedHandlesSize = sizeof(pIn->authHandle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPMI_RH_CLEAR;
    cmdDesc.pUnserializedParameters = (ubyte *)&lockoutParameters;
    cmdDesc.UnserializedParametersSize = sizeof(lockoutParameters);
    cmdDesc.parametersType = SAPI2_ST_TPMI_RH_DA_LOCK_PARAMETERS;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthAuthHandle);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_DictionaryAttackParameters;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = NULL;
    rspDesc.UnserializedParametersSize = 0;
    rspDesc.parametersType = SAPI2_ST_START;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.numSessionHandlesAndAuthValues = 1;
    rspDesc.ppAuthValues = &(pIn->pAuthAuthHandle);

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

TSS2_RC
SAPI2_HIERARCHY_ClearControl(
        SAPI2_CONTEXT *pSapiContext,
        ClearControlIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2B_NAME hierarchyHandleName = { 0 };

    /* TPM2_ClearControl has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { &hierarchyHandleName };

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pIn->pAuthSession) ||
            (NULL == pIn->pAuthAuthHandle))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

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

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_ClearControl;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(pIn->authHandle));
    cmdDesc.UnserializedHandlesSize = sizeof(pIn->authHandle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPMI_RH_CLEAR;
    cmdDesc.pUnserializedParameters = (ubyte *)(&(pIn->disable));
    cmdDesc.UnserializedParametersSize = sizeof(pIn->disable);
    cmdDesc.parametersType = SAPI2_ST_TPMI_YES_NO;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthAuthHandle);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_ClearControl;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = NULL;
    rspDesc.UnserializedParametersSize = 0;
    rspDesc.parametersType = SAPI2_ST_START;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pAuthAuthHandle);
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
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
