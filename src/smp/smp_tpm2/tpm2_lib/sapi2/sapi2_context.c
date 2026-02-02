/**
 * @file sapi2_context.c
 * @brief This file contains code required to maintain state in SAPI2.
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
#include "../tcti/tcti.h"
#include "../tpm_common/tpm_error_utils.h"
#include "sapi2_context.h"
#include "sapi2_utils.h"
#include "sapi2_errors.h"

typedef struct
{
    TPM2_RC lastTpmError;
    ubyte *pCmdStream;
    ubyte *pRspStream;
    TCTI_CONTEXT *pTctiContext;
#ifdef   __ENABLE_LOOKUP_TABLE__
    char errorString[RESP_STR_SIZE];
#endif
    ubyte provision;
} _SAPI2_CONTEXT_OPAQUE_BLOB;

static TSS2_RC SAPI2_CONTEXT_initTcti(
        ubyte4 serverNameLen,
        ubyte *pServerName,
        ubyte2 serverPort,
        TCTI_CONTEXT **ppTctiContext
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TctiContextInitIn tctiInit = { 0 };

    tctiInit.pServerName = pServerName;
    tctiInit.serverNameLen = serverNameLen;
    tctiInit.serverPort = serverPort;

    rc = TSS2_TCTI_contextInit(&tctiInit, ppTctiContext);
    if ((TSS2_RC_SUCCESS != rc))
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Could not initialize TCTI "
                        "context, rc 0x%02x = %s\n",
                         __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

static TSS2_RC SAPI2_CONTEXT_uninitTcti(TCTI_CONTEXT **ppTctiContext)
{
    return TSS2_TCTI_contextUninit(ppTctiContext);
}

TSS2_RC SAPI2_CONTEXT_init(SAPI2_CONTEXT **ppSapiContext, ubyte4 serverNameLen, ubyte *pServerName,
        ubyte2 serverPort, void *pReserved)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    _SAPI2_CONTEXT_OPAQUE_BLOB *pNewContext = NULL;
    MSTATUS status = ERR_GENERAL;

    if ((NULL == ppSapiContext) || (NULL != *ppSapiContext))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /* Check if initMocana called */
    if (NULL == g_pRandomContext)
    {
        rc = TSS2_SYS_RC_INSUFFICIENT_CONTEXT;
        DB_PRINT("%s.%d DIGICERT_initDigicert() not yet called, random"
                " context not initialized. rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    status = DIGI_CALLOC((void **)&pNewContext, 1, sizeof(_SAPI2_CONTEXT_OPAQUE_BLOB));
    if (OK != status)
    {
        rc = TSS2_SYS_RC_INSUFFICIENT_BUFFER;
        DB_PRINT("%s.%d Failed to allocate memory for SAPI2_CONTEXT"
                ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /* Mark this context as being one created by provisioning tool */
    if ((pReserved && (*(int *)pReserved == 1)))
        pNewContext->provision = 1;

    status = DIGI_CALLOC((void **)&(pNewContext->pCmdStream), 1,
            SAPI2_CONTEXT_MAX_CMD_RSP_SIZE);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_INSUFFICIENT_BUFFER;
        DB_PRINT("%s.%d Failed to allocate memory for cmdStream"
                ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    status = DIGI_CALLOC((void **)&(pNewContext->pRspStream), 1,
            SAPI2_CONTEXT_MAX_CMD_RSP_SIZE);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_INSUFFICIENT_BUFFER;
        DB_PRINT("%s.%d Failed to allocate memory for rspStream"
                ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = SAPI2_CONTEXT_initTcti(serverNameLen, pServerName,
            serverPort, &(pNewContext->pTctiContext));
    if (TSS2_RC_SUCCESS != rc)
    {
        goto exit;
    }

    *ppSapiContext = (SAPI2_CONTEXT *)pNewContext;

    rc = TSS2_RC_SUCCESS;
exit:
    if (TSS2_RC_SUCCESS != rc)
    {
        if (pNewContext)
        {
            if (pNewContext->pTctiContext)
                SAPI2_CONTEXT_uninitTcti(&(pNewContext->pTctiContext));

            if (pNewContext->pCmdStream)
                shredMemory(&(pNewContext->pCmdStream), SAPI2_CONTEXT_MAX_CMD_RSP_SIZE,
                        TRUE);

            if (pNewContext->pRspStream)
                shredMemory(&(pNewContext->pRspStream), SAPI2_CONTEXT_MAX_CMD_RSP_SIZE,
                        TRUE);

            shredMemory((ubyte **)&pNewContext, sizeof(_SAPI2_CONTEXT_OPAQUE_BLOB), TRUE);
        }
    }
    return rc;
}

TSS2_RC SAPI2_CONTEXT_uninit(SAPI2_CONTEXT **ppSapiContext)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    _SAPI2_CONTEXT_OPAQUE_BLOB *pFreeContext = NULL;

    if ((NULL == ppSapiContext) || (NULL == *ppSapiContext))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pFreeContext = (_SAPI2_CONTEXT_OPAQUE_BLOB *)(*ppSapiContext);

    if ((NULL == pFreeContext->pTctiContext) ||
            (NULL == pFreeContext->pCmdStream) ||
            (NULL == pFreeContext->pRspStream))
    {
        DB_PRINT("%s.%d WARNING: Trying to Uninit improper context"
                ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
    }

    if (pFreeContext->pTctiContext)
        SAPI2_CONTEXT_uninitTcti(&(pFreeContext->pTctiContext));

    if (pFreeContext->pCmdStream)
        shredMemory(&(pFreeContext->pCmdStream), SAPI2_CONTEXT_MAX_CMD_RSP_SIZE,
                TRUE);

    if (pFreeContext->pRspStream)
        shredMemory(&(pFreeContext->pRspStream), SAPI2_CONTEXT_MAX_CMD_RSP_SIZE,
                TRUE);

    if (pFreeContext)
        shredMemory((ubyte **)&pFreeContext, sizeof(_SAPI2_CONTEXT_OPAQUE_BLOB), TRUE);

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC SAPI2_CONTEXT_executeCommand(
SAPI2_CONTEXT *pSapiContext,
sapi2_cmd_desc *pCmdDesc,
sapi2_rsp_desc *pRspDesc
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    _SAPI2_CONTEXT_OPAQUE_BLOB *pContext = NULL;
    TPM2_RESPONSE_HEADER *pRspHeader = NULL;

    sapi2_utils_cmd_context utilCmdCtx = { 0 };
    ubyte4 cmdSerializedSize = 0;

    sapi2_utils_rsp_context utilRspCtx = { 0 };

    TctiTransmitRecieveIn transmitRecieveIn = { 0 };
    TctiTransmitRecieveOut transmitRecieveOut = { 0 };

    if ((NULL == pSapiContext) || (NULL == pCmdDesc) ||
            (NULL == pRspDesc))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pContext = (_SAPI2_CONTEXT_OPAQUE_BLOB *)pSapiContext;

    utilCmdCtx.pCmdStreamOut = pContext->pCmdStream;
    utilCmdCtx.cmdStreamOutSize = SAPI2_CONTEXT_MAX_CMD_RSP_SIZE;
    utilCmdCtx.pCmdDesc = pCmdDesc;

    rc = SAPI2_UTILS_getCmdStream(&utilCmdCtx, &cmdSerializedSize);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get command stream, rc 0x%02x = %s\n",
                __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /* Send to and receive from TPM */
    transmitRecieveIn.transmitBufLen = cmdSerializedSize;
    transmitRecieveIn.pTransmitBuf = pContext->pCmdStream;
    transmitRecieveIn.receiveBufLen = SAPI2_CONTEXT_MAX_CMD_RSP_SIZE;
    transmitRecieveIn.pReceiveBuf = pContext->pRspStream;

    rc = TSS2_TCTI_transmitReceive(pContext->pTctiContext, &transmitRecieveIn, &transmitRecieveOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed transmit_receive, rc 0x%02x = %s\n",
                __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    utilRspCtx.pRspStreamIn = pContext->pRspStream;
    utilRspCtx.rspStreamInSize = transmitRecieveOut.recievedLen;
    utilRspCtx.pRspDesc = pRspDesc;

    rc = SAPI2_UTILS_getRspStructures(&utilRspCtx);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get response structures, rc 0x%02x = %s\n",
                __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pRspHeader = pRspDesc->pUnserializedHeader;

    if (pRspHeader->responseCode != TPM2_RC_SUCCESS)
    {
        rc = (TSS2_TPM_RC_LEVEL | pRspHeader->responseCode);

        if (!(pContext->provision && (0x18b == rc)))
        {
        DB_PRINT("%s.%d TPM command failed with error = 0x%x\n"
                , __FUNCTION__, __LINE__, pRspHeader->responseCode);
#ifdef   __ENABLE_LOOKUP_TABLE__
        DB_PRINT("*********************************************\n"
                "TPM2 Error Details: %s\n"
                "*********************************************\n",
                SAPI2_ERRORS_processRespCode(pRspHeader->responseCode, pContext->errorString,
                        sizeof(pContext->errorString)));
#endif
        }
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    if (pContext && pRspHeader)
    {
        pContext->lastTpmError = pRspHeader->responseCode;
    }
    return rc;
}

TPM2_RC SAPI2_CONTEXT_getLastTpmError(SAPI2_CONTEXT *pSapiContext)
{
    _SAPI2_CONTEXT_OPAQUE_BLOB *pContext = NULL;

    if (pSapiContext)
    {
        pContext = (_SAPI2_CONTEXT_OPAQUE_BLOB *)pSapiContext;
#ifdef   __ENABLE_LOOKUP_TABLE__
        DB_PRINT("*********************************************\n"
                "TPM2 Error Details: %s\n"
                "*********************************************\n",
                SAPI2_ERRORS_processRespCode(pContext->lastTpmError, pContext->errorString,
                        sizeof(pContext->errorString)));
#endif
        return pContext->lastTpmError;
    }

    return TPM2_RC_BAD_TAG;
}

int SAPI2_CONTEXT_inProvision(SAPI2_CONTEXT *pSapiContext)
{
    int rc = 0;
    _SAPI2_CONTEXT_OPAQUE_BLOB *pContext = NULL;

    if (pSapiContext)
    {
        pContext = (_SAPI2_CONTEXT_OPAQUE_BLOB *)pSapiContext;

        if (pContext->provision) 
            rc = 1;
    }

    return rc;
}
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
