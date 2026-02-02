/**
 * @file sapi2_context.h
 * @brief This file contains code required to maintain state in SAPI2.
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
#ifndef __SAPI2_CONTEXT_H__
#define __SAPI2_CONTEXT_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "sapi2_serialize.h"
#include "sapi2_handles.h"

#define SAPI2_CONTEXT_MAX_CMD_RSP_SIZE 3072

typedef struct _SAPI2_CONTEXT_OPAQUE_BLOB SAPI2_CONTEXT;

typedef struct {
    TPM2_COMMAND_HEADER *pUnserializedHeader;
    ubyte *pUnserializedHandles;
    ubyte4 UnserializedHandlesSize;
    TPM2B_NAME **ppNames;
    ubyte4 numHandlesAndNames;
    SAPI2_SERIALIZE_TYPE handlesType;
    ubyte *pUnserializedParameters;
    ubyte4 UnserializedParametersSize;
    SAPI2_SERIALIZE_TYPE parametersType;
    MOCTPM2_OBJECT_HANDLE **ppSessionHandles;
    TPM2B_AUTH **ppAuthValues;
    ubyte numSessionHandlesAndAuthValues;
} sapi2_cmd_desc;

typedef struct {
    TPM2_CC commandCode;
    TPM2_RESPONSE_HEADER *pUnserializedHeader;
    ubyte *pUnserializedHandles;
    ubyte4 UnserializedHandlesSize;
    SAPI2_SERIALIZE_TYPE handlesType;
    ubyte *pUnserializedParameters;
    ubyte4 UnserializedParametersSize;
    SAPI2_SERIALIZE_TYPE parametersType;
    MOCTPM2_OBJECT_HANDLE **ppSessionHandles;
    TPM2B_AUTH **ppAuthValues;
    ubyte numSessionHandlesAndAuthValues;
} sapi2_rsp_desc;

MOC_EXTERN TSS2_RC SAPI2_CONTEXT_init(SAPI2_CONTEXT **ppSapiContext, ubyte4 serverNameLen, ubyte *pServerName,
        ubyte2 serverPort, void *pReserved);

MOC_EXTERN TSS2_RC SAPI2_CONTEXT_uninit(SAPI2_CONTEXT **ppSapiContext);

TSS2_RC SAPI2_CONTEXT_executeCommand(
SAPI2_CONTEXT *pSapiContext,
sapi2_cmd_desc *pCmdDesc,
sapi2_rsp_desc *pRspDesc
);

TPM2_RC SAPI2_CONTEXT_getLastTpmError(SAPI2_CONTEXT *pSapiContext);

int SAPI2_CONTEXT_inProvision(SAPI2_CONTEXT *pSapiContext);

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /* __SAPI2_CONTEXT_H__ */
