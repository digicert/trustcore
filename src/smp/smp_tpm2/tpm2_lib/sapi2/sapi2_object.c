/**
 * @file sapi2_object.c
 * @brief This file contains code required to execute TPM 2 object commands.
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
#include "sapi2_object.h"

TSS2_RC SAPI2_OBJECT_Create(
        SAPI2_CONTEXT *pSapiContext,
        CreateIn *pIn,
        CreateOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_CREATE_CMD_PARAMS cmdParams = { 0 };
    TPM2_CREATE_RSP_PARAMS rspParams = { 0 };

    /* TPM2_Create has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { 0 };

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
            (NULL == pIn->pAuthParentHandle) ||
            (NULL == pIn->pParentHandle))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    cmdParams.inSensitive = *(pIn->pInSensitive);
    cmdParams.inPublic = *(pIn->pInPublic);
    cmdParams.outsideInfo = *(pIn->pOutsideInfo);
    cmdParams.creationPCR = *(pIn->pCreationPCR);

    pHandleNames[0] = &pIn->pParentHandle->objectName;

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_Create;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(pIn->pParentHandle->tpm2Handle));
    cmdDesc.UnserializedHandlesSize = sizeof(TPMI_DH_OBJECT);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPMI_DH_OBJECT;
    cmdDesc.pUnserializedParameters = (ubyte *)(&cmdParams);
    cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
    cmdDesc.parametersType = SAPI2_ST_TPM2_CREATE_CMD_PARAMS;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthParentHandle);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_Create;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = (ubyte *)&rspParams;
    rspDesc.UnserializedParametersSize = sizeof(rspParams);
    rspDesc.parametersType = SAPI2_ST_TPM2_CREATE_RSP_PARAMS;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pAuthParentHandle);
    rspDesc.numSessionHandlesAndAuthValues = 1;

    rc = SAPI2_CONTEXT_executeCommand(pSapiContext, &cmdDesc, &rspDesc);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute command, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->outPrivate = rspParams.outPrivate;
    pOut->outPublic = rspParams.outPublic;
    pOut->creationData = rspParams.creationData;
    pOut->creationHash = rspParams.creationHash;
    pOut->creationTicket = rspParams.creationTicket;

    rc = TSS2_RC_SUCCESS;

exit:

    return rc;
}

TSS2_RC SAPI2_OBJECT_Load(
        SAPI2_CONTEXT *pSapiContext,
        LoadIn *pIn,
        LoadOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_LOAD_CMD_PARAMS cmdParams = { 0 };
    TPM2_LOAD_RSP_PARAMS rspParams = { 0 };

    /* TPM2_Load has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { 0 };
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

    if ((NULL == pIn->pParentHandle) || (NULL == pIn->pInPrivate) ||
            (NULL == pIn->pInPublic) || (NULL == pIn->pAuthParentHandle) ||
            (NULL == pIn->pAuthSession))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    cmdParams.inPrivate = *(pIn->pInPrivate);
    cmdParams.inPublic = *(pIn->pInPublic);

    pHandleNames[0] = &pIn->pParentHandle->objectName;

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_Load;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(pIn->pParentHandle->tpm2Handle));
    cmdDesc.UnserializedHandlesSize = sizeof(TPMI_DH_OBJECT);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPMI_DH_OBJECT;
    cmdDesc.pUnserializedParameters = (ubyte *)(&cmdParams);
    cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
    cmdDesc.parametersType = SAPI2_ST_TPM2_LOAD_CMD_PARAMS;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthParentHandle);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_Load;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = (ubyte *)&newObjectHandle;
    rspDesc.UnserializedHandlesSize = sizeof(newObjectHandle);
    rspDesc.handlesType = SAPI2_ST_TPM2_HANDLE;
    rspDesc.pUnserializedParameters = (ubyte *)&rspParams;
    rspDesc.UnserializedParametersSize = sizeof(rspParams);
    rspDesc.parametersType = SAPI2_ST_TPM2_LOAD_RSP_PARAMS;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pAuthParentHandle);
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
            &pIn->pInPublic->publicArea, &pOut->pObjectHandle);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to create object handle for object, "
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


TSS2_RC SAPI2_OBJECT_ImportDuplicateKey(
        SAPI2_CONTEXT *pSapiContext,
        ImportIn *pIn,
        ImportOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_IMPORT_CMD_PARAMS cmdParams = { 0 };
    TPM2_IMPORT_RSP_PARAMS rspParams = { 0 };

    /* TPM2_Load has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { 0 };

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pOut))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((NULL == pIn->pParentHandle) || (NULL == pIn->pEncryptionKey) ||
            (NULL == pIn->pObjectPublic) || (NULL == pIn->pDuplicate) ||
            (NULL == pIn->pInSymSeed) || (NULL == pIn->pSymmetricAlg)|| 
            (NULL == pIn->pAuthParentHandle) || (NULL == pIn->pAuthSession))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    cmdParams.encryptionKey = *(pIn->pEncryptionKey);
    cmdParams.objectPublic = *(pIn->pObjectPublic);
    cmdParams.duplicate = *(pIn->pDuplicate) ;
    cmdParams.inSymSeed = *(pIn->pInSymSeed) ;
    cmdParams.symmetricAlg = *(pIn->pSymmetricAlg) ;

    pHandleNames[0] = &pIn->pParentHandle->objectName;

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_Import;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(pIn->pParentHandle->tpm2Handle));
    cmdDesc.UnserializedHandlesSize = sizeof(TPMI_DH_OBJECT);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPMI_DH_OBJECT;
    cmdDesc.pUnserializedParameters = (ubyte *)(&cmdParams);
    cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
    cmdDesc.parametersType = SAPI2_ST_TPM2_IMPORT_CMD_PARAMS;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthParentHandle);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_Import;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = (ubyte *)&rspParams;
    rspDesc.UnserializedParametersSize = sizeof(rspParams);
    rspDesc.parametersType = SAPI2_ST_TPM2_IMPORT_RSP_PARAMS;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pAuthParentHandle);
    rspDesc.numSessionHandlesAndAuthValues = 1;

    rc = SAPI2_CONTEXT_executeCommand(pSapiContext, &cmdDesc, &rspDesc);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute command, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    pOut->outPrivate = rspParams.outPrivate;

exit:
    return rc;
}


TSS2_RC SAPI2_OBJECT_Unseal(
        SAPI2_CONTEXT *pSapiContext,
        UnsealIn *pIn,
        UnsealOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    /* TPM2_Unseal has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { 0 };

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pOut))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((NULL == pIn->pItemHandle) || (NULL == pIn->pAuthItemHandle) ||
            (NULL == pIn->pAuthSession))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pHandleNames[0] = &pIn->pItemHandle->objectName;

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_Unseal;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(pIn->pItemHandle->tpm2Handle));
    cmdDesc.UnserializedHandlesSize = sizeof(TPMI_DH_OBJECT);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPMI_DH_OBJECT;
    cmdDesc.pUnserializedParameters = NULL;
    cmdDesc.UnserializedParametersSize = 0;
    cmdDesc.parametersType = SAPI2_ST_START;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthItemHandle);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_Unseal;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = (ubyte *)(&pOut->outData);
    rspDesc.UnserializedParametersSize = sizeof(pOut->outData);
    rspDesc.parametersType = SAPI2_ST_TPM2B_SENSITIVE_DATA;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pAuthItemHandle);
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

TSS2_RC SAPI2_OBJECT_ReadPublic(
        SAPI2_CONTEXT *pSapiContext,
        ReadPublicIn *pIn,
        ReadPublicOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_READ_PUBLIC_RSP_PARAMS rspParams = { 0 };
    MSTATUS status = ERR_GENERAL;
    sbyte4 cmpResult = 0;

    /* This command has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { 0 };
    TPM2B_NAME emptyName = { 0 };
    TPMI_DH_OBJECT objectHandle = TPM2_RH_NULL;

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
    cmdHeader.commandCode = TPM2_CC_ReadPublic;

    if (pIn->pObjectHandle)
    {
        pHandleNames[0] = &pIn->pObjectHandle->objectName;
        objectHandle = pIn->pObjectHandle->tpm2Handle;
    }
    else
    {
        /*
         * When using TPM2_ReadPublic, it is possible that a caller does not have
         * the name of the object handle being referred to, such as a
         * persistent handle. To support this use case, we always assume
         * we dont know the name and set it to an emptyBuffer. This means
         * we cannot use an audit session to force HMAC when talking to a
         * remote TPM. If this is used with a remote TPM, the application
         * will be vulnerable to a MITM attack and the returned name and public
         * area may be spoofed. The worst that can happen with a persistent object
         * is that we use the wrong Name for it during HMAC calculation,
         * in which case HMAC verification will fail. However, there is no way to
         * tell if you are talking to a real TPM, so if the caller is MITM attacked,
         * the HMAC could succeed and we could be talking to a fake TPM.
         * For a transient object this maybe more problematic.
         * If we try to read the public area for a loaded TPM object,
         * an attacker could present us the Name of a different object, which leaves us
         * open to the same TPM1.2 attack where multiple objects having the same
         * passwords, could be unintentionally authorized. This should not matter
         * in our case, since this code must be running on the host system and
         * will not be talking to a remote TPM with an untrusted path.
         * One way for the application to work around this issue is to call
         * TPM2_ReadPublic, get the name, and then call TPM2_ReadPublic again
         * with the obtained name and a salted HMAC session and verify that the
         * name originally received was indeed valid. However, to be sure that
         * we are talking to a real TPM(ie through salted HMAC session), the salting
         * public key MUST be known out of band and trusted. If we have to read the
         * TPM to get the public key of the salting key, all bets are off, and there
         * is no way to guarantee security.
         */
        pHandleNames[0] = &emptyName;
        objectHandle = pIn->objectHandle;
    }

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&objectHandle);
    cmdDesc.UnserializedHandlesSize = sizeof(TPMI_DH_OBJECT);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPMI_DH_OBJECT;
    cmdDesc.pUnserializedParameters = NULL;
    cmdDesc.UnserializedParametersSize = 0;
    cmdDesc.parametersType = SAPI2_ST_START;
    cmdDesc.ppSessionHandles = NULL;
    cmdDesc.ppAuthValues = NULL;
    cmdDesc.numSessionHandlesAndAuthValues = 0;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_ReadPublic;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = (ubyte *)(&rspParams);
    rspDesc.UnserializedParametersSize = sizeof(rspParams);
    rspDesc.parametersType = SAPI2_ST_TPM2_READ_PUBLIC_RSP_PARAMS;
    rspDesc.ppSessionHandles = NULL;
    rspDesc.ppAuthValues = NULL;
    rspDesc.numSessionHandlesAndAuthValues = 0;

    rc = SAPI2_CONTEXT_executeCommand(pSapiContext, &cmdDesc, &rspDesc);
    if (TSS2_RC_SUCCESS != rc)
    {
        if (!(SAPI2_CONTEXT_inProvision(pSapiContext) && 
                    (0x18b == rc)))
            DB_PRINT("%s.%d Failed to execute command, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));

        goto exit;
    }

    /*
     * Verify name calculated by SAPI2 matches the one returned by
     * the TPM, if MOCTPM2_OBJECT_HANDLE was provided.
     */
    if (pIn->pObjectHandle)
    {
        status = DIGI_MEMCMP((const ubyte *)&pIn->pObjectHandle->publicArea.objectPublicArea,
                (const ubyte *)&rspParams.outPublic.publicArea,
                sizeof(rspParams.outPublic.publicArea),
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

        status = DIGI_MEMCMP((const ubyte *)&pIn->pObjectHandle->objectName,
                (const ubyte *)&rspParams.name,
                sizeof(rspParams.name.name),
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

    pOut->outPublic = rspParams.outPublic;
    pOut->name = rspParams.name;
    pOut->qualifiedName = rspParams.qualifiedName;

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC SAPI2_OBJECT_LoadExternal(
        SAPI2_CONTEXT *pSapiContext,
        LoadExternalIn *pIn,
        LoadExternalOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_LOAD_EXTERNAL_CMD_PARAMS cmdParams = { 0 };
    TPM2_LOAD_EXTERNAL_CMD_PARAMS2 cmdParams2 = { 0 };
    TPM2_HANDLE newObjectHandle = 0;
    TPM2B_NAME newObjectName = { 0 };
    sbyte4 cmpResult = 0;
    byteBoolean useCmdParams2 = FALSE;

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pOut))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ( (NULL == pIn->pInPublic))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (!pIn->pInSensitive || (0 == pIn->pInSensitive->sensitiveArea.sensitiveType))
        useCmdParams2 = TRUE;

    if (useCmdParams2)
    {
        cmdParams2.size0 = 0;
        cmdParams2.inPublic = *(pIn->pInPublic);
        cmdParams2.hierarchy = pIn->hierarchy;
    }
    else
    {
        cmdParams.hierarchy = pIn->hierarchy;
        cmdParams.inPublic = *(pIn->pInPublic);
        cmdParams.inSensitive = *(pIn->pInSensitive);
    }

    cmdHeader.tag = TPM2_ST_NO_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_LoadExternal;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = NULL;
    cmdDesc.UnserializedHandlesSize = 0;
    cmdDesc.ppNames = NULL;
    cmdDesc.numHandlesAndNames = 0;
    cmdDesc.handlesType = SAPI2_ST_START;
    if (useCmdParams2)
    {
        cmdDesc.pUnserializedParameters = (ubyte *)(&cmdParams2);
        cmdDesc.UnserializedParametersSize = sizeof(cmdParams2);
        cmdDesc.parametersType = SAPI2_ST_TPM2_LOAD_EXTERNAL_CMD_PARAMS2;
    }
    else
    {
        cmdDesc.pUnserializedParameters = (ubyte *)(&cmdParams);
        cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
        cmdDesc.parametersType = SAPI2_ST_TPM2_LOAD_EXTERNAL_CMD_PARAMS;
    }
    cmdDesc.ppSessionHandles = NULL;
    cmdDesc.ppAuthValues = NULL;
    cmdDesc.numSessionHandlesAndAuthValues = 0;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_LoadExternal;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = (ubyte *)&newObjectHandle;
    rspDesc.UnserializedHandlesSize = sizeof(newObjectHandle);
    rspDesc.handlesType = SAPI2_ST_TPM2_HANDLE;
    rspDesc.pUnserializedParameters = (ubyte *)&newObjectName;
    rspDesc.UnserializedParametersSize = sizeof(newObjectName);
    rspDesc.parametersType = SAPI2_ST_TPM2B_NAME;
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

    pOut->pObjectHandle = NULL;
    rc = SAPI2_HANDLES_createObjectHandle(newObjectHandle,
            &pIn->pInPublic->publicArea, &pOut->pObjectHandle);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to create object handle for object, "
                "rc 0x%02x = %s\n", __FUNCTION__, __LINE__, rc,
                tss2_err_string(rc));
        goto exit;
    }

    if (OK != DIGI_MEMCMP((ubyte *)&pOut->pObjectHandle->objectName,
            (ubyte *)&newObjectName, sizeof(newObjectName),
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

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC SAPI2_OBJECT_ObjectChangeAuth(
        SAPI2_CONTEXT *pSapiContext,
        ObjectChangeAuthIn *pIn,
        ObjectChangeAuthOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_OBJECT_CHANGE_AUTH_CMD_HANDLES cmdHandles = { 0 };
    /*
     * This command has 2 handles.
     */
    TPM2B_NAME *pHandleNames[2] = { NULL };

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pOut))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((NULL == pIn->pAuthObjectHandle)  ||
            (NULL == pIn->pAuthSession) ||
            (NULL == pIn->pNewAuth) ||
            (NULL == pIn->pObjectHandle) ||
            (NULL == pIn->pParentHandle))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    cmdHandles.parentHandle = pIn->pParentHandle->tpm2Handle;
    cmdHandles.objectHandle = pIn->pObjectHandle->tpm2Handle;

    pHandleNames[0] = &pIn->pObjectHandle->objectName;
    pHandleNames[1] = &pIn->pParentHandle->objectName;

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_ObjectChangeAuth;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(cmdHandles));
    cmdDesc.UnserializedHandlesSize = sizeof(cmdHandles);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 2;
    cmdDesc.handlesType = SAPI2_ST_TPM2_OBJECT_CHANGE_AUTH_CMD_HANDLES;
    cmdDesc.pUnserializedParameters = (ubyte *)(pIn->pNewAuth);
    cmdDesc.UnserializedParametersSize = sizeof(*(pIn->pNewAuth));
    cmdDesc.parametersType = SAPI2_ST_TPM2B_AUTH;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthObjectHandle);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_ObjectChangeAuth;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = (ubyte *)(&(pOut->outPrivate));
    rspDesc.UnserializedParametersSize = sizeof(pOut->outPrivate);
    rspDesc.parametersType = SAPI2_ST_TPM2B_PRIVATE;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pAuthObjectHandle);
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

TSS2_RC SAPI2_OBJECT_MakeCredential(
        SAPI2_CONTEXT *pSapiContext,
        MakeCredentialIn *pIn,
        MakeCredentialOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    /* This command has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { 0 };
    TPM2_MAKE_CREDENTIAL_CMD_PARAMS cmdParams = { 0 };

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pOut) || (NULL == pIn->pCredential) ||
            (NULL == pIn->pName) ||
            (NULL == pIn->pObjectHandle))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    cmdHeader.tag = TPM2_ST_NO_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_MakeCredential;

    pHandleNames[0] = &pIn->pObjectHandle->objectName;
    cmdParams.credential = *(pIn->pCredential);
    cmdParams.name = *(pIn->pName);

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(pIn->pObjectHandle->tpm2Handle));
    cmdDesc.UnserializedHandlesSize = sizeof(pIn->pObjectHandle->tpm2Handle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPMI_DH_OBJECT;
    cmdDesc.pUnserializedParameters = (ubyte *)&cmdParams;
    cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
    cmdDesc.parametersType = SAPI2_ST_TPM2_SHADOW_TPM2_MAKE_CREDENTIAL_CMD_PARAMS;
    cmdDesc.ppSessionHandles = NULL;
    cmdDesc.ppAuthValues = NULL;
    cmdDesc.numSessionHandlesAndAuthValues = 0;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_MakeCredential;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = (ubyte *)(pOut);
    rspDesc.UnserializedParametersSize = sizeof(*pOut);
    rspDesc.parametersType = SAPI2_ST_TPM2_SHADOW_TPM2_MAKE_CREDENTIAL_RSP_PARAMS;
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

TSS2_RC SAPI2_OBJECT_ActivateCredential(
        SAPI2_CONTEXT *pSapiContext,
        ActivateCredentialIn *pIn,
        ActivateCredentialOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_ACTIVATE_CREDENTIAL_CMD_HANDLES cmdHandles = { 0 };
    TPM2_ACTIVATE_CREDENTIAL_CMD_PARAMS cmdParams = { 0 };

    /* This command has 2 handles which require authorization */
    TPM2B_NAME *pHandleNames[2] = { 0 };
    MOCTPM2_OBJECT_HANDLE *pSessionHandles[2] = { 0 };
    TPM2B_AUTH *pAuthValues[2] = { 0 };

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pOut) || (NULL == pIn->pActivateHandle) ||
            (NULL == pIn->pAuthActivateHandle) ||
            (NULL == pIn->pAuthSessionActivateHandle) ||
            (NULL == pIn->pKeyHandle) ||
            (NULL == pIn->pAuthKeyHandle) ||
            (NULL == pIn->pAuthSessionKeyHandle) ||
            (NULL == pIn->pCredentialBlob) ||
            (NULL == pIn->pSecret))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    cmdHandles.activateHandle = pIn->pActivateHandle->tpm2Handle;
    pHandleNames[0] = &pIn->pActivateHandle->objectName;
    pSessionHandles[0] = pIn->pAuthSessionActivateHandle;
    pAuthValues[0] = pIn->pAuthActivateHandle;

    cmdHandles.keyHandle = pIn->pKeyHandle->tpm2Handle;
    pHandleNames[1] = &pIn->pKeyHandle->objectName;
    pSessionHandles[1] = pIn->pAuthSessionKeyHandle;
    pAuthValues[1] = pIn->pAuthKeyHandle;

    cmdParams.credentialBlob = *(pIn->pCredentialBlob);
    cmdParams.secret = *(pIn->pSecret);

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_ActivateCredential;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&cmdHandles);
    cmdDesc.UnserializedHandlesSize = sizeof(cmdHandles);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 2;
    cmdDesc.handlesType = SAPI2_ST_TPM2_ACTIVATE_CREDENTIAL_CMD_HANDLES;
    cmdDesc.pUnserializedParameters = (ubyte *)&cmdParams;
    cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
    cmdDesc.parametersType = SAPI2_ST_TPM2_SHADOW_TPM2_MAKE_CREDENTIAL_RSP_PARAMS;
    cmdDesc.ppSessionHandles = pSessionHandles;
    cmdDesc.ppAuthValues = pAuthValues;
    cmdDesc.numSessionHandlesAndAuthValues = 2;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_ActivateCredential;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = (ubyte *)(&(pOut->certInfo));
    rspDesc.UnserializedParametersSize = sizeof(pOut->certInfo);
    rspDesc.parametersType = SAPI2_ST_TPM2B_DIGEST;
    rspDesc.ppSessionHandles = pSessionHandles;
    rspDesc.ppAuthValues = pAuthValues;
    rspDesc.numSessionHandlesAndAuthValues = 2;

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

TSS2_RC SAPI2_OBJECT_DuplicateKey(
        SAPI2_CONTEXT *pSapiContext,
        DuplicateIn *pIn,
        DuplicateOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_DUPLICATE_CMD_HANDLES cmdHandles = { 0 };
    TPM2_DUPLICATE_CMD_PARAMS cmdParams = { 0 };
    TPM2_DUPLICATE_RSP_PARAMS rspParams = { 0 };

    /* TPM2_Duplicate has 2 handles */
    TPM2B_NAME *pHandleNames[2] = { 0 };

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pOut))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((NULL == pIn->pHandle) || (NULL == pIn->pNewParentHandle) ||
            (NULL == pIn->pEncryptKeyIn) || (NULL == pIn->pSymmetricAlg))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    cmdParams.encryptKeyIn = *(pIn->pEncryptKeyIn);
    cmdParams.symmetricAlg = *(pIn->pSymmetricAlg);

    pHandleNames[0] = &pIn->pHandle->objectName;
    pHandleNames[1] = &pIn->pNewParentHandle->objectName;

    cmdHandles.objectHandle = pIn->pHandle->tpm2Handle ;
    cmdHandles.newParentHandle = pIn->pNewParentHandle->tpm2Handle ;

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_Duplicate;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&(cmdHandles));
    cmdDesc.UnserializedHandlesSize = sizeof(cmdHandles);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 2;
    cmdDesc.handlesType = SAPI2_ST_TPM2_DUPLICATE_CMD_HANDLES;
    cmdDesc.pUnserializedParameters = (ubyte *)(&cmdParams);
    cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
    cmdDesc.parametersType = SAPI2_ST_TPM2_DUPLICATE_CMD_PARAMS;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthHandle);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_Duplicate;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = (ubyte *)&rspParams;
    rspDesc.UnserializedParametersSize = sizeof(rspParams);
    rspDesc.parametersType = SAPI2_ST_TPM2_DUPLICATE_RSP_PARAMS;
    rspDesc.ppSessionHandles = &(pIn->pAuthSession);
    rspDesc.ppAuthValues = &(pIn->pAuthHandle);
    rspDesc.numSessionHandlesAndAuthValues = 1;

    rc = SAPI2_CONTEXT_executeCommand(pSapiContext, &cmdDesc, &rspDesc);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to execute command, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->encryptionKeyOut= rspParams.encryptionKeyOut;
    pOut->duplicate = rspParams.duplicate;
    pOut->outSymSeed= rspParams.outSymSeed;
    rc = TSS2_RC_SUCCESS;

exit:

    return rc;
}



#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
