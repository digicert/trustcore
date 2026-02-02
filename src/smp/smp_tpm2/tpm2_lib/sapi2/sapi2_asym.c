/**
 * @file sapi2_asymc.c
 * @brief This file contains code required to execute TPM2 asymmetric primitive
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
#include "sapi2_asym.h"

TSS2_RC SAPI2_ASYM_ECCParameters(
        SAPI2_CONTEXT *pSapiContext,
        ECCParametersIn *pIn,
        ECCParametersOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

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
    cmdHeader.commandCode = TPM2_CC_ECC_Parameters;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = NULL;
    cmdDesc.UnserializedHandlesSize = 0;
    cmdDesc.ppNames = NULL;
    cmdDesc.numHandlesAndNames = 0;
    cmdDesc.handlesType = SAPI2_ST_START;
    cmdDesc.pUnserializedParameters = (ubyte *)(&(pIn->curveID));
    cmdDesc.UnserializedParametersSize = sizeof(pIn->curveID);
    cmdDesc.parametersType = SAPI2_ST_TPMI_ECC_CURVE;
    cmdDesc.ppSessionHandles = NULL;
    cmdDesc.ppAuthValues = NULL;
    cmdDesc.numSessionHandlesAndAuthValues = 0;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_ECC_Parameters;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = (ubyte *)(&pOut->parameters);
    rspDesc.UnserializedParametersSize = sizeof(pOut->parameters);
    rspDesc.parametersType = SAPI2_ST_TPMS_ALGORITHM_DETAIL_ECC;
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

TSS2_RC SAPI2_ASYM_RSAEncrypt(
        SAPI2_CONTEXT *pSapiContext,
        RSAEncryptIn *pIn,
        RSAEncryptOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_RSA_ENCRYPT_CMD_PARAMS cmdParams = { 0 };

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

    if ((NULL == pIn->pObjectHandle) || (NULL == pIn->pMessage) ||
            (NULL == pIn->pInScheme) || (NULL == pIn->pLabel))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    cmdParams.label = *(pIn->pLabel);
    cmdParams.message = *(pIn->pMessage);
    cmdParams.scheme = *(pIn->pInScheme);

    cmdHeader.tag = TPM2_ST_NO_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_RSA_Encrypt;

    pHandleNames[0] = &(pIn->pObjectHandle->objectName);

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&pIn->pObjectHandle->tpm2Handle);
    cmdDesc.UnserializedHandlesSize = sizeof(pIn->pObjectHandle->tpm2Handle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPMI_DH_OBJECT;
    cmdDesc.pUnserializedParameters = (ubyte *)(&cmdParams);
    cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
    cmdDesc.parametersType = SAPI2_ST_TPM2_RSA_ENCRYPT_CMD_PARAMS;
    cmdDesc.ppSessionHandles = NULL;
    cmdDesc.ppAuthValues = NULL;
    cmdDesc.numSessionHandlesAndAuthValues = 0;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_RSA_Encrypt;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = (ubyte *)(&pOut->outData);
    rspDesc.UnserializedParametersSize = sizeof(pOut->outData);
    rspDesc.parametersType = SAPI2_ST_TPM2B_PUBLIC_KEY_RSA;
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

TSS2_RC SAPI2_ASYM_RSADecrypt(
        SAPI2_CONTEXT *pSapiContext,
        RSADecryptIn *pIn,
        RSADecryptOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_RSA_DECRYPT_CMD_PARAMS cmdParams = { 0 };

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

    if ((NULL == pIn->pObjectHandle) || (NULL == pIn->pCipherText) ||
            (NULL == pIn->pInScheme) || (NULL == pIn->pLabel) ||
            (NULL == pIn->pAuthSession) || (NULL == pIn->pAuthObjectHandle))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    cmdParams.label = *(pIn->pLabel);
    cmdParams.cipherText = *(pIn->pCipherText);
    cmdParams.scheme = *(pIn->pInScheme);

    cmdHeader.tag = TPM2_ST_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_RSA_Decrypt;

    pHandleNames[0] = &(pIn->pObjectHandle->objectName);

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = (ubyte *)(&pIn->pObjectHandle->tpm2Handle);
    cmdDesc.UnserializedHandlesSize = sizeof(pIn->pObjectHandle->tpm2Handle);
    cmdDesc.ppNames = pHandleNames;
    cmdDesc.numHandlesAndNames = 1;
    cmdDesc.handlesType = SAPI2_ST_TPMI_DH_OBJECT;
    cmdDesc.pUnserializedParameters = (ubyte *)(&cmdParams);
    cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
    cmdDesc.parametersType = SAPI2_ST_TPM2_RSA_DECRYPT_CMD_PARAMS;
    cmdDesc.ppSessionHandles = &(pIn->pAuthSession);
    cmdDesc.ppAuthValues = &(pIn->pAuthObjectHandle);
    cmdDesc.numSessionHandlesAndAuthValues = 1;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_RSA_Decrypt;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = (ubyte *)(&pOut->message);
    rspDesc.UnserializedParametersSize = sizeof(pOut->message);
    rspDesc.parametersType = SAPI2_ST_TPM2B_PUBLIC_KEY_RSA;
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

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
