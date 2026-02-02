/**
 * @file sapi2_capability.c
 * @brief This file contains code required to execute TPM 2 capability commands.
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
#include "sapi2_capability.h"

TSS2_RC SAPI2_CAPABILITY_GetCapability(
        SAPI2_CONTEXT *pSapiContext,
        GetCapabilityIn *pIn,
        GetCapabilityOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_COMMAND_HEADER cmdHeader = { 0 };
    TPM2_RESPONSE_HEADER rspHeader = { 0 };

    sapi2_cmd_desc cmdDesc = { 0 };
    sapi2_rsp_desc rspDesc = { 0 };

    TPM2_GET_CAPABILITY_CMD_PARAMS cmdParams = { 0 };
    TPM2_GET_CAPABILITY_RSP_PARAMS rspParams = { 0 };

    if ((NULL == pIn) || (NULL == pSapiContext) ||
            (NULL == pOut))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    cmdParams.capability = pIn->capability;
    cmdParams.property = pIn->property;
    cmdParams.propertyCount = pIn->propertyCount;

    cmdHeader.tag = TPM2_ST_NO_SESSIONS;
    cmdHeader.commandSize = 0;
    cmdHeader.commandCode = TPM2_CC_GetCapability;

    /* Assemble command descriptor */
    cmdDesc.pUnserializedHeader = &cmdHeader;
    cmdDesc.pUnserializedHandles = NULL;
    cmdDesc.UnserializedHandlesSize = 0;
    cmdDesc.ppNames = NULL;
    cmdDesc.numHandlesAndNames = 0;
    cmdDesc.handlesType = SAPI2_ST_START;
    cmdDesc.pUnserializedParameters = (ubyte *)(&cmdParams);
    cmdDesc.UnserializedParametersSize = sizeof(cmdParams);
    cmdDesc.parametersType = SAPI2_ST_TPM2_GET_CAPABILITY_CMD_PARAMS;
    cmdDesc.ppSessionHandles = NULL;
    cmdDesc.ppAuthValues = NULL;
    cmdDesc.numSessionHandlesAndAuthValues = 0;

    /* Assemble response descriptor */
    rspDesc.commandCode = TPM2_CC_GetCapability;
    rspDesc.pUnserializedHeader = &rspHeader;
    rspDesc.pUnserializedHandles = NULL;
    rspDesc.UnserializedHandlesSize = 0;
    rspDesc.handlesType = SAPI2_ST_START;
    rspDesc.pUnserializedParameters = (ubyte *)(&rspParams);
    rspDesc.UnserializedParametersSize = sizeof(rspParams);
    rspDesc.parametersType = SAPI2_ST_TPM2_GET_CAPABILITY_RSP_PARAMS;
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

    pOut->moreData = rspParams.moreData;
    pOut->capabilityData = rspParams.capabilityData;

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
