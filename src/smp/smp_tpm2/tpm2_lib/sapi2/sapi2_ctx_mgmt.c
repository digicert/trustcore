/**
 * @file sapi2_ctx_mgmt.c
 * @brief This file contains code required to execute TPM2 context management
 * commands.
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
#include "sapi2_ctx_mgmt.h"

TSS2_RC SAPI2_CTX_MGMT_FlushContext(
        SAPI2_CONTEXT *pSapiContext,
        FlushContextIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_FLUSH_CONTEXT_CMD_PARAMS cmdParams = { 0 };

    if ((NULL == pIn) || (NULL == pSapiContext))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((NULL == pIn->ppObjectHandle) || (NULL == *(pIn->ppObjectHandle)))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    cmdParams.flushHandle = (*(pIn->ppObjectHandle))->tpm2Handle;

    cmdHeader.tag = TPM2_ST_NO_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_FlushContext;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = NULL;
    cmdDesc.UnserializedHandlesSize = 0;
    cmdDesc.ppNames = NULL;
    cmdDesc.numHandlesAndNames = 0;
    cmdDesc.handlesType = SAPI2_ST_START;
    cmdDesc.pUnserializedParameters = (ubyte *)(&cmdParams);
    cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
    cmdDesc.parametersType = SAPI2_ST_TPM2_FLUSH_CONTEXT_CMD_PARAMS;
    cmdDesc.ppSessionHandles = NULL;
    cmdDesc.ppAuthValues = NULL;
    cmdDesc.numSessionHandlesAndAuthValues = 0;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_FlushContext;
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

    rc = SAPI2_HANDLES_destroyHandle(pIn->ppObjectHandle, TRUE);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to free object handle(memory leak)"
                ", rc 0x%02x = %s\n",
                __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    *(pIn->ppObjectHandle) = NULL;

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC SAPI2_CTX_MGMT_EvictControl(
        SAPI2_CONTEXT *pSapiContext,
        EvictControlIn *pIn,
        EvictControlOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

     TPM2_COMMAND_HEADER cmdHeader = { 0 };
     TPM2_RESPONSE_HEADER rspHeader = { 0 };

     sapi2_cmd_desc cmdDesc = { 0 };
     sapi2_rsp_desc rspDesc = { 0 };

     TPM2B_NAME hierarchyHandleName = { 0 };

     /* TPM2_EvictControl has 2 handle */
     TPM2B_NAME *pHandleNames[2] = { &hierarchyHandleName, NULL };

     TPM2_EVICT_CONTROL_CMD_HANDLES cmdHandles = { 0 };

     if ((NULL == pIn) || (NULL == pSapiContext) ||
             (NULL == pIn->pAuthSession) ||
             (NULL == pIn->pObjectHandle) ||
             (NULL == pIn->pAuthAuthHandle) ||
             (NULL == pOut))
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

     cmdHandles.authHandle = pIn->authHandle;
     cmdHandles.objectHandle = pIn->pObjectHandle->tpm2Handle;

     pHandleNames[1] = &(pIn->pObjectHandle->objectName);

     cmdHeader.tag = TPM2_ST_SESSIONS;
     cmdHeader.commandSize = 0;
     cmdHeader.commandCode = TPM2_CC_EvictControl;

     /* Assemble command descriptor */
     cmdDesc.pUnserializedHeader = &cmdHeader;
     cmdDesc.pUnserializedHandles = (ubyte *)(&cmdHandles);
     cmdDesc.UnserializedHandlesSize = sizeof(cmdHandles);
     cmdDesc.ppNames = pHandleNames;
     cmdDesc.numHandlesAndNames = 2;
     cmdDesc.handlesType = SAPI2_ST_TPM2_EVICT_CONTROL_CMD_HANDLES;
     cmdDesc.pUnserializedParameters = (ubyte *)(&(pIn->persistentHandle));
     cmdDesc.UnserializedParametersSize = sizeof(pIn->persistentHandle);
     cmdDesc.parametersType = SAPI2_ST_TPMI_DH_PERSISTENT;
     cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
     cmdDesc.ppAuthValues = &(pIn->pAuthAuthHandle);
     cmdDesc.numSessionHandlesAndAuthValues = 1;

     /* Assemble response descriptor */
     rspDesc.commandCode = TPM2_CC_EvictControl;
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

     pOut->pPersistentHandle = NULL;

     if (pIn->pObjectHandle->tpm2Handle != pIn->persistentHandle)
     {
         rc = SAPI2_HANDLES_createObjectHandle(pIn->persistentHandle,
                 &pIn->pObjectHandle->publicArea.objectPublicArea,
                 &pOut->pPersistentHandle);
         if (TSS2_RC_SUCCESS != rc)
         {
             DB_PRINT("%s.%d Failed to create object handle for persistent object, "
                     "rc 0x%02x = %s\n", __FUNCTION__, __LINE__, rc,
                     tss2_err_string(rc));
             goto exit;
         }
     }
     else
     {
         rc = SAPI2_HANDLES_destroyHandle(&(pIn->pObjectHandle), TRUE);
         if (TSS2_RC_SUCCESS != rc)
         {
             DB_PRINT("%s.%d Failed to free object handle(memory leak)"
                     ", rc 0x%02x = %s\n",
                     __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
             goto exit;
         }
     }

     rc = TSS2_RC_SUCCESS;

exit:
     if (TSS2_RC_SUCCESS != rc)
     {
         if (pOut && pOut->pPersistentHandle)
         {
             SAPI2_HANDLES_destroyHandle(&pOut->pPersistentHandle, TRUE);
             pOut->pPersistentHandle = NULL;
         }
     }
     return rc;
}
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
