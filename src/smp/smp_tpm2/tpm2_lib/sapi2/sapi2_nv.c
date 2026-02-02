/**
 * @file sapi2_nv.c
 * @brief This file contains code required to execute TPM 2 nv commands.
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
#include "sapi2_nv.h"

TSS2_RC SAPI2_NV_NVUpdateNameWithAttribute(
        MOCTPM2_OBJECT_HANDLE *pNvIndexHandle,
        TPMA_NV nvAttr
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    /*
     * Update name for the NV index if the NV_WRITTEN bit was not set
     * previously.
     */
    if (!(pNvIndexHandle->publicArea.nvPublicArea.attributes
            & nvAttr))
    {
        pNvIndexHandle->publicArea.nvPublicArea.attributes |=
                nvAttr;

        rc = SAPI2_UTILS_getNvName(pNvIndexHandle->tpm2Handle,
                &pNvIndexHandle->publicArea.nvPublicArea,
                &pNvIndexHandle->objectName);
        if (rc != TSS2_RC_SUCCESS)
        {
            DB_PRINT("%s.%d Failed SAPI2_UTILS_getObjectName(),"
                    " rc 0x%02x = %s\n", __FUNCTION__, __LINE__,
                    rc, tss2_err_string(rc));
            goto exit;
        }
    }

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC SAPI2_NV_NVDefineSpace(
        SAPI2_CONTEXT *pSapiContext,
        NVDefineSpaceIn *pIn,
        NVDefineSpaceOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_NV_DEFINE_SPACE_CMD_PARAMS cmdParams = { 0 };

    TPM2B_NAME hierarchyHandleName = { 0 };

    /* TPM2_NVDefinteSpace has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { &hierarchyHandleName };

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pOut))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((NULL == pIn->pAuthHandleAuth) || (NULL == pIn->pAuthSession) ||
            (NULL == pIn->pNvAuth) || (NULL == pIn->pPublicInfo))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    cmdParams.auth = *(pIn->pNvAuth);
    cmdParams.publicInfo = *(pIn->pPublicInfo);

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
    cmdHeader.commandCode = TPM2_CC_NV_DefineSpace;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(pIn->authHandle));
    cmdDesc.UnserializedHandlesSize = sizeof(pIn->authHandle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPMI_RH_PROVISION;
    cmdDesc.pUnserializedParameters = (ubyte *)(&cmdParams);
    cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
    cmdDesc.parametersType = SAPI2_ST_TPM2_NV_DEFINE_SPACE_CMD_PARAMS;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthHandleAuth);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_NV_DefineSpace;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = NULL;
    rspDesc.UnserializedParametersSize = 0;
    rspDesc.parametersType = SAPI2_ST_START;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pAuthHandleAuth);
    rspDesc.numSessionHandlesAndAuthValues = 1;

    rc = SAPI2_CONTEXT_executeCommand(pSapiContext, &cmdDesc, &rspDesc);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute command, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->pNvIndexHandle = NULL;
    rc = SAPI2_HANDLES_createNvHandle(pIn->pPublicInfo->nvPublic.nvIndex,
            &pIn->pPublicInfo->nvPublic, &pOut->pNvIndexHandle);
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
        if (pOut && pOut->pNvIndexHandle)
        {
            SAPI2_HANDLES_destroyHandle(&pOut->pNvIndexHandle, TRUE);
            pOut->pNvIndexHandle = NULL;
        }
    }

    return rc;
}

TSS2_RC SAPI2_NV_NVUndefineSpace(
        SAPI2_CONTEXT *pSapiContext,
        NVUndefineSpaceIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_NV_UNDEFINE_SPACE_CMD_HANDLES cmdHandles = { 0 };

    TPM2B_NAME hierarchyHandleName = { 0 };

    /* TPM2_NVUndefine space has 2 handles */
    TPM2B_NAME *pHandleNames[2] = { NULL };

    if ((NULL == pIn) || (NULL == pSapiContext))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((NULL == pIn->pAuthHandleAuth) || (NULL == pIn->pAuthSession) ||
            (NULL == pIn->ppNvIndexHandle))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    cmdHandles.authHandle = pIn->authHandle;
    cmdHandles.nvIndex = (*(pIn->ppNvIndexHandle))->tpm2Handle;

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
    pHandleNames[1] = &((*(pIn->ppNvIndexHandle))->objectName);

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_NV_UndefineSpace;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&cmdHandles);
    cmdDesc.UnserializedHandlesSize = sizeof(cmdHandles);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 2;
    cmdDesc.handlesType = SAPI2_ST_TPM2_NV_UNDEFINE_SPACE_CMD_HANDLES;
    cmdDesc.pUnserializedParameters = NULL;
    cmdDesc.UnserializedParametersSize = 0;
    cmdDesc.parametersType = SAPI2_ST_START;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthHandleAuth);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_NV_UndefineSpace;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = NULL;
    rspDesc.UnserializedParametersSize = 0;
    rspDesc.parametersType = SAPI2_ST_START;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pAuthHandleAuth);
    rspDesc.numSessionHandlesAndAuthValues = 1;

    rc = SAPI2_CONTEXT_executeCommand(pSapiContext, &cmdDesc, &rspDesc);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute command, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = SAPI2_HANDLES_destroyHandle(pIn->ppNvIndexHandle, TRUE);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to free object handle(memory leak)"
                ", rc 0x%02x = %s\n",
                __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    *(pIn->ppNvIndexHandle) = NULL;

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC SAPI2_NV_NVWrite(
        SAPI2_CONTEXT *pSapiContext,
        NVWriteIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_NV_WRITE_CMD_HANDLES cmdHandles = { 0 };
    TPM2_NV_WRITE_CMD_PARAMS cmdParams = { 0 };

    TPM2B_NAME hierarchyHandleName = { 0 };

    /* TPM2_NVWrite space has 2 handles */
    TPM2B_NAME *pHandleNames[2] = { NULL };

    if ((NULL == pIn) || (NULL == pSapiContext))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((NULL == pIn->pNvIndexHandle) || (NULL == pIn->pData) ||
            (NULL == pIn->pAuthHandleAuth) ||
            (NULL == pIn->pAuthSession))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

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

    cmdHandles.nvIndex = pIn->pNvIndexHandle->tpm2Handle;
    pHandleNames[1] = &pIn->pNvIndexHandle->objectName;

    cmdParams.data = *(pIn->pData);
    cmdParams.offset = pIn->offset;

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_NV_Write;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&cmdHandles);
    cmdDesc.UnserializedHandlesSize = sizeof(cmdHandles);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 2;
    cmdDesc.handlesType = SAPI2_ST_TPM2_NV_WRITE_CMD_HANDLES;
    cmdDesc.pUnserializedParameters = (ubyte *)(&cmdParams);
    cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
    cmdDesc.parametersType = SAPI2_ST_TPM2_NV_WRITE_CMD_PARAMS;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthHandleAuth);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_NV_Write;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = NULL;
    rspDesc.UnserializedParametersSize = 0;
    rspDesc.parametersType = SAPI2_ST_START;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pAuthHandleAuth);
    rspDesc.numSessionHandlesAndAuthValues = 1;

    rc = SAPI2_CONTEXT_executeCommand(pSapiContext, &cmdDesc, &rspDesc);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute command, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Update name for the NV index if the NV_WRITTEN bit was not set
     * previously.
     */
    rc = SAPI2_NV_NVUpdateNameWithAttribute(pIn->pNvIndexHandle, TPMA_NV_WRITTEN);
    if (rc != TSS2_RC_SUCCESS)
    {
        DB_PRINT("%s.%d Failed to update NV name on write"
                " rc 0x%02x = %s\n", __FUNCTION__, __LINE__,
                rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;

exit:

    return rc;
}

TSS2_RC SAPI2_NV_NVRead(
        SAPI2_CONTEXT *pSapiContext,
        NVReadIn *pIn,
        NVReadOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_NV_READ_CMD_HANDLES cmdHandles = { 0 };
    TPM2_NV_READ_CMD_PARAMS cmdParams = { 0 };

    TPM2B_NAME hierarchyHandleName = { 0 };

    /* TPM2_NVRead space has 2 handles */
    TPM2B_NAME *pHandleNames[2] = { NULL };

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pOut))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((NULL == pIn->pNvIndexHandle) || (NULL == pIn->pAuthHandleAuth) ||
            (NULL == pIn->pAuthSession))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

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

    cmdHandles.nvIndex = pIn->pNvIndexHandle->tpm2Handle;
    pHandleNames[1] = &pIn->pNvIndexHandle->objectName;

    cmdParams.offset = pIn->offset;
    cmdParams.size = pIn->size;

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_NV_Read;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&cmdHandles);
    cmdDesc.UnserializedHandlesSize = sizeof(cmdHandles);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 2;
    cmdDesc.handlesType = SAPI2_ST_TPM2_NV_READ_CMD_HANDLES;
    cmdDesc.pUnserializedParameters = (ubyte *)(&cmdParams);
    cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
    cmdDesc.parametersType = SAPI2_ST_TPM2_NV_READ_CMD_PARAMS;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthHandleAuth);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_NV_Read;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = (ubyte *)(&pOut->data);
    rspDesc.UnserializedParametersSize = sizeof(pOut->data);
    rspDesc.parametersType = SAPI2_ST_TPM2_NV_READ_RSP_PARAMS;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pAuthHandleAuth);
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

TSS2_RC SAPI2_NV_NVReadPublic(
        SAPI2_CONTEXT *pSapiContext,
        NVReadPublicIn *pIn,
        NVReadPublicOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_NV_READ_PUBLIC_RSP_PARAMS rspParams = { 0 };
    MSTATUS status = ERR_GENERAL;
    sbyte4 cmpResult = 0;
    /* This command has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { 0 };
    TPM2B_NAME emptyName = { 0 };
    TPMI_RH_NV_INDEX nvHandle = TPM2_RH_NULL;

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pOut))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    cmdHeader.tag = TPM2_ST_NO_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_NV_ReadPublic;

    if (pIn->pNvIndexHandle)
    {
        pHandleNames[0] = &(pIn->pNvIndexHandle->objectName);
        nvHandle = pIn->pNvIndexHandle->tpm2Handle;
    }
    else
    {
        /*
         * When using TPM2_NV_ReadPublic, it is possible that a caller does not have
         * the name of the nv handle being referred to.
         *  To support this use case, we always assume
         * we dont know the name and set it to an emptyBuffer. This means
         * we cannot use an audit session to force HMAC when talking to a
         * remote TPM. If this is used with a remote TPM, the application
         * will be vulnerable to a MITM attack and the returned name and public
         * area may be spoofed. The worst that can happen with a NV index
         * is that we use the wrong Name for it during HMAC calculation,
         * in which case HMAC verification will fail.This should not matter
         * in our case, since this code must be running on the host system and
         * will not be talking to a remote TPM with an untrusted path.
         * One way for the application to work around this issue is to call
         * TPM2_ReadPublic, get the name, and then call TPM2_ReadPublic again
         * with the obtained name and a salted HMAC session and verify that the
         * name originally received was indeed valid.
         */
        pHandleNames[0] = &emptyName;
        nvHandle = pIn->nvIndex;
    }

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&nvHandle);
    cmdDesc.UnserializedHandlesSize = sizeof(nvHandle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPMI_RH_NV_INDEX;
    cmdDesc.pUnserializedParameters = NULL;
    cmdDesc.UnserializedParametersSize = 0;
    cmdDesc.parametersType = SAPI2_ST_START;
    cmdDesc.ppSessionHandles = NULL;
    cmdDesc.ppAuthValues = 0;
    cmdDesc.numSessionHandlesAndAuthValues = 0;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_NV_ReadPublic;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = (ubyte *)(&rspParams);
    rspDesc.UnserializedParametersSize = sizeof(rspParams);
    rspDesc.parametersType = SAPI2_ST_TPM2_NV_READ_PUBLIC_RSP_PARAMS;
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

    /*
     * Verify name calculated by SAPI2 matches the one returned by
     * the TPM.
     */
    if (pIn->pNvIndexHandle)
    {
        status = DIGI_MEMCMP((const ubyte *)&pIn->pNvIndexHandle->publicArea.nvPublicArea,
                (const ubyte *)&rspParams.nvPublic.nvPublic,
                sizeof(rspParams.nvPublic.nvPublic),
                &cmpResult);
        if ((OK != status) || (cmpResult != 0))
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("%s.%d Public Area from TPM different from"
                    " local computation,"
                    " rc 0x%02x = %s\n", __FUNCTION__, __LINE__, rc,
                    tss2_err_string(rc));
            goto exit;
        }

        status = DIGI_MEMCMP((const ubyte *)&pIn->pNvIndexHandle->objectName,
                (const ubyte *)&rspParams.nvName,
                sizeof(rspParams.nvName.name),
                &cmpResult);
        if ((OK != status) || (cmpResult != 0))
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("%s.%d Name from TPM different from"
                    " local computation,"
                    " rc 0x%02x = %s\n", __FUNCTION__, __LINE__, rc,
                    tss2_err_string(rc));
            goto exit;
        }
    }

    pOut->nvPublic = rspParams.nvPublic;
    pOut->nvName = rspParams.nvName;

    rc = TSS2_RC_SUCCESS;

exit:

    return rc;
}

TSS2_RC SAPI2_NV_NVIncrement(
        SAPI2_CONTEXT *pSapiContext,
        NVIncrementIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_NV_INCREMENT_CMD_HANDLES cmdHandles = { 0 };

    TPM2B_NAME hierarchyHandleName = { 0 };

    /* This command has 2 handles */
    TPM2B_NAME *pHandleNames[2] = { NULL };

    if ((NULL == pIn) || (NULL == pSapiContext))
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

    cmdHandles.nvIndex = pIn->pNvIndexHandle->tpm2Handle;
    pHandleNames[1] = &pIn->pNvIndexHandle->objectName;

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_NV_Increment;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&cmdHandles);
    cmdDesc.UnserializedHandlesSize = sizeof(cmdHandles);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 2;
    cmdDesc.handlesType = SAPI2_ST_TPM2_NV_INCREMENT_CMD_HANDLES;
    cmdDesc.pUnserializedParameters = NULL;
    cmdDesc.UnserializedParametersSize = 0;
    cmdDesc.parametersType = SAPI2_ST_START;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthHandleAuth);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_NV_Increment;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = NULL;
    rspDesc.UnserializedParametersSize = 0;
    rspDesc.parametersType = SAPI2_ST_START;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pAuthHandleAuth);
    rspDesc.numSessionHandlesAndAuthValues = 1;

    rc = SAPI2_CONTEXT_executeCommand(pSapiContext, &cmdDesc, &rspDesc);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute command, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Update name for the NV index if the NV_WRITTEN bit was not set
     * previously.
     */
    rc = SAPI2_NV_NVUpdateNameWithAttribute(pIn->pNvIndexHandle, TPMA_NV_WRITTEN);
    if (rc != TSS2_RC_SUCCESS)
    {
        DB_PRINT("%s.%d Failed to update NV name on write"
                " rc 0x%02x = %s\n", __FUNCTION__, __LINE__,
                rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC SAPI2_NV_NVExtend(
        SAPI2_CONTEXT *pSapiContext,
        NVExtendIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_NV_EXTEND_CMD_HANDLES cmdHandles = { 0 };

    TPM2B_NAME hierarchyHandleName = { 0 };

    /* This command has 2 handles */
    TPM2B_NAME *pHandleNames[2] = { NULL };

    if ((NULL == pIn) || (NULL == pSapiContext))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((NULL == pIn->pNvIndexHandle) ||
            (NULL == pIn->pAuthHandleAuth) ||
            (NULL == pIn->pAuthSession) ||
            (NULL == pIn->pData))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

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

    cmdHandles.nvIndex = pIn->pNvIndexHandle->tpm2Handle;
    pHandleNames[1] = &pIn->pNvIndexHandle->objectName;

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_NV_Extend;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&cmdHandles);
    cmdDesc.UnserializedHandlesSize = sizeof(cmdHandles);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 2;
    cmdDesc.handlesType = SAPI2_ST_TPM2_NV_EXTEND_CMD_HANDLES;
    cmdDesc.pUnserializedParameters = (ubyte *)(pIn->pData);
    cmdDesc.UnserializedParametersSize = sizeof(*(pIn->pData));
    cmdDesc.parametersType = SAPI2_ST_TPM2B_MAX_NV_BUFFER;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthHandleAuth);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_NV_Extend;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = NULL;
    rspDesc.UnserializedParametersSize = 0;
    rspDesc.parametersType = SAPI2_ST_START;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pAuthHandleAuth);
    rspDesc.numSessionHandlesAndAuthValues = 1;

    rc = SAPI2_CONTEXT_executeCommand(pSapiContext, &cmdDesc, &rspDesc);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute command, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Update name for the NV index if the NV_WRITTEN bit was not set
     * previously.
     */
    rc = SAPI2_NV_NVUpdateNameWithAttribute(pIn->pNvIndexHandle, TPMA_NV_WRITTEN);
    if (rc != TSS2_RC_SUCCESS)
    {
        DB_PRINT("%s.%d Failed to update NV name on write"
                " rc 0x%02x = %s\n", __FUNCTION__, __LINE__,
                rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}


TSS2_RC SAPI2_NV_NVSetBits(
        SAPI2_CONTEXT *pSapiContext,
        NVSetBitsIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_NV_SET_BITS_CMD_HANDLES cmdHandles = { 0 };

    TPM2B_NAME hierarchyHandleName = { 0 };

    /* This command has 2 handles */
    TPM2B_NAME *pHandleNames[2] = { NULL };

    if ((NULL == pIn) || (NULL == pSapiContext))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((NULL == pIn->pNvIndexHandle) ||
            (NULL == pIn->pAuthHandleAuth) ||
            (NULL == pIn->pAuthSession) ||
            (NULL == pIn->pBits))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

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

    cmdHandles.nvIndex = pIn->pNvIndexHandle->tpm2Handle;
    pHandleNames[1] = &pIn->pNvIndexHandle->objectName;

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_NV_SetBits;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&cmdHandles);
    cmdDesc.UnserializedHandlesSize = sizeof(cmdHandles);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 2;
    cmdDesc.handlesType = SAPI2_ST_TPM2_NV_SET_BITS_CMD_HANDLES;
    cmdDesc.pUnserializedParameters = (ubyte *)(pIn->pBits);
    cmdDesc.UnserializedParametersSize = sizeof(*(pIn->pBits));
    cmdDesc.parametersType = SAPI2_ST_UBYTE8;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthHandleAuth);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_NV_SetBits;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = NULL;
    rspDesc.UnserializedParametersSize = 0;
    rspDesc.parametersType = SAPI2_ST_START;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pAuthHandleAuth);
    rspDesc.numSessionHandlesAndAuthValues = 1;

    rc = SAPI2_CONTEXT_executeCommand(pSapiContext, &cmdDesc, &rspDesc);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute command, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Update name for the NV index if the NV_WRITTEN bit was not set
     * previously.
     */
    rc = SAPI2_NV_NVUpdateNameWithAttribute(pIn->pNvIndexHandle, TPMA_NV_WRITTEN);
    if (rc != TSS2_RC_SUCCESS)
    {
        DB_PRINT("%s.%d Failed to update NV name on write"
                " rc 0x%02x = %s\n", __FUNCTION__, __LINE__,
                rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC SAPI2_NV_NVWriteLock(
        SAPI2_CONTEXT *pSapiContext,
        NVWriteLockIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_NV_WRITE_LOCK_CMD_HANDLES cmdHandles = { 0 };

    TPM2B_NAME hierarchyHandleName = { 0 };

    /* This command has 2 handles */
    TPM2B_NAME *pHandleNames[2] = { NULL };

    if ((NULL == pIn) || (NULL == pSapiContext))
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

    cmdHandles.nvIndex = pIn->pNvIndexHandle->tpm2Handle;
    pHandleNames[1] = &pIn->pNvIndexHandle->objectName;

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_NV_WriteLock;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&cmdHandles);
    cmdDesc.UnserializedHandlesSize = sizeof(cmdHandles);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 2;
    cmdDesc.handlesType = SAPI2_ST_TPM2_NV_WRITE_LOCK_CMD_HANDLES;
    cmdDesc.pUnserializedParameters = NULL;
    cmdDesc.UnserializedParametersSize = 0;
    cmdDesc.parametersType = SAPI2_ST_START;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthHandleAuth);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_NV_WriteLock;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = NULL;
    rspDesc.UnserializedParametersSize = 0;
    rspDesc.parametersType = SAPI2_ST_START;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pAuthHandleAuth);
    rspDesc.numSessionHandlesAndAuthValues = 1;

    rc = SAPI2_CONTEXT_executeCommand(pSapiContext, &cmdDesc, &rspDesc);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute command, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = SAPI2_NV_NVUpdateNameWithAttribute(pIn->pNvIndexHandle, TPMA_NV_WRITELOCKED);
    if (rc != TSS2_RC_SUCCESS)
    {
        DB_PRINT("%s.%d Failed to update NV name on write"
                " rc 0x%02x = %s\n", __FUNCTION__, __LINE__,
                rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC SAPI2_NV_NVReadLock(
        SAPI2_CONTEXT *pSapiContext,
        NVReadLockIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_NV_READ_LOCK_CMD_HANDLES cmdHandles = { 0 };

    TPM2B_NAME hierarchyHandleName = { 0 };

    /* This command has 2 handles */
    TPM2B_NAME *pHandleNames[2] = { NULL };

    if ((NULL == pIn) || (NULL == pSapiContext))
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

    cmdHandles.nvIndex = pIn->pNvIndexHandle->tpm2Handle;
    pHandleNames[1] = &pIn->pNvIndexHandle->objectName;

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_NV_ReadLock;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&cmdHandles);
    cmdDesc.UnserializedHandlesSize = sizeof(cmdHandles);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 2;
    cmdDesc.handlesType = SAPI2_ST_TPM2_NV_READ_LOCK_CMD_HANDLES;
    cmdDesc.pUnserializedParameters = NULL;
    cmdDesc.UnserializedParametersSize = 0;
    cmdDesc.parametersType = SAPI2_ST_START;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthHandleAuth);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_NV_ReadLock;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = NULL;
    rspDesc.UnserializedParametersSize = 0;
    rspDesc.parametersType = SAPI2_ST_START;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pAuthHandleAuth);
    rspDesc.numSessionHandlesAndAuthValues = 1;

    rc = SAPI2_CONTEXT_executeCommand(pSapiContext, &cmdDesc, &rspDesc);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute command, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = SAPI2_NV_NVUpdateNameWithAttribute(pIn->pNvIndexHandle, TPMA_NV_READLOCKED);
    if (rc != TSS2_RC_SUCCESS)
    {
        DB_PRINT("%s.%d Failed to update NV name on write"
                " rc 0x%02x = %s\n", __FUNCTION__, __LINE__,
                rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC SAPI2_NV_NVGlobalWriteLock(
        SAPI2_CONTEXT *pSapiContext,
        NVGlobalWriteLockIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2B_NAME hierarchyHandleName = { 0 };

    /* This command has 1 handle1 */
    TPM2B_NAME *pHandleNames[1] = { &hierarchyHandleName };

    if ((NULL == pIn) || (NULL == pSapiContext))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((NULL == pIn->pAuthHandleAuth) ||
            (NULL == pIn->pAuthSession))
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
    cmdHeader.commandCode = TPM2_CC_NV_GlobalWriteLock;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(pIn->authHandle));
    cmdDesc.UnserializedHandlesSize = sizeof(pIn->authHandle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPMI_RH_PROVISION;
    cmdDesc.pUnserializedParameters = NULL;
    cmdDesc.UnserializedParametersSize = 0;
    cmdDesc.parametersType = SAPI2_ST_START;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthHandleAuth);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_NV_GlobalWriteLock;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = NULL;
    rspDesc.UnserializedParametersSize = 0;
    rspDesc.parametersType = SAPI2_ST_START;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pAuthHandleAuth);
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
