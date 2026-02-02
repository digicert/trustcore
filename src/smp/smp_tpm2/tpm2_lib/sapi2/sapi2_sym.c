/**
 * @file sapi2_sym.c
 * @brief This file contains code required to execute TPM2 symmetric primitive
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
#include "sapi2_sym.h"

static TSS2_RC SAPI2_SYM_EncryptDecryptVersion(
        SAPI2_CONTEXT *pSapiContext,
        EncryptDecryptIn *pIn,
        EncryptDecryptOut *pOut,
        byteBoolean version2
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_ENCRYPT_DECRYPT_CMD_PARAMS cmdParams = { 0 };
    TPM2_ENCRYPT_DECRYPT2_CMD_PARAMS cmdParams2 = { 0 };
    TPM2_ENCRYPT_DECRYPT_RSP_PARAMS rspParams = { 0 };

    /* This command has 1 handle */
    TPM2B_NAME *pHandleNames[1] = { 0 };

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pOut))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((NULL == pIn->pObjectHandle) || (NULL == pIn->pIvIn) ||
            (NULL == pIn->pInData) || (NULL == pIn->pAuthSession) ||
            (NULL == pIn->pAuthObjectHandle))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    cmdParams.decrypt = pIn->decrypt;
    cmdParams.mode = pIn->mode;
    cmdParams.inData = *(pIn->pInData);
    cmdParams.ivIn = *(pIn->pIvIn);

    cmdParams2.decrypt = pIn->decrypt;
    cmdParams2.mode = pIn->mode;
    cmdParams2.inData = *(pIn->pInData);
    cmdParams2.ivIn = *(pIn->pIvIn);

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;

    pHandleNames[0] = &(pIn->pObjectHandle->objectName);

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&pIn->pObjectHandle->tpm2Handle);
    cmdDesc.UnserializedHandlesSize = sizeof(pIn->pObjectHandle->tpm2Handle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPMI_DH_OBJECT;

    if (version2)
    {
        cmdHeader.commandCode = TPM2_CC_EncryptDecrypt2;
        cmdDesc.pUnserializedParameters = (ubyte *)(&cmdParams2);
        cmdDesc.UnserializedParametersSize = sizeof(cmdParams2);
        cmdDesc.parametersType = SAPI2_ST_TPM2_ENCRYPT_DECRYPT2_CMD_PARAMS;

    }
    else
    {
        cmdHeader.commandCode = TPM2_CC_EncryptDecrypt;
        cmdDesc.pUnserializedParameters = (ubyte *)(&cmdParams);
        cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
        cmdDesc.parametersType = SAPI2_ST_TPM2_ENCRYPT_DECRYPT_CMD_PARAMS;

    }
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthObjectHandle);
    cmdDesc.numSessionHandlesAndAuthValues = 1;


    /* Assemble response descriptor */
    if (version2)
        rspDesc.commandCode = TPM2_CC_EncryptDecrypt2;
    else
        rspDesc.commandCode = TPM2_CC_EncryptDecrypt;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = (ubyte *)(&rspParams);
    rspDesc.UnserializedParametersSize = sizeof(rspParams);
    rspDesc.parametersType = SAPI2_ST_TPM2_ENCRYPT_DECRYPT_RSP_PARAMS;
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

    pOut->IvOut = rspParams.ivOut;
    pOut->outData = rspParams.outData;

    rc = TSS2_RC_SUCCESS;
exit:

    return rc;
}

TSS2_RC SAPI2_SYM_EncryptDecrypt(
        SAPI2_CONTEXT *pSapiContext,
        EncryptDecryptIn *pIn,
        EncryptDecryptOut *pOut
)
{
    return SAPI2_SYM_EncryptDecryptVersion(pSapiContext, pIn, pOut, FALSE);
}

TSS2_RC SAPI2_SYM_EncryptDecrypt2(
        SAPI2_CONTEXT *pSapiContext,
        EncryptDecryptIn *pIn,
        EncryptDecryptOut *pOut
)
{
    return SAPI2_SYM_EncryptDecryptVersion(pSapiContext, pIn, pOut, TRUE);
}

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
