/*
 * trustedge_https_client.c
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 *
 */

#include "../../common/moptions.h"

#include <stdio.h>

#ifndef __RTOS_FREERTOS__
#include <sys/types.h>
#include <fcntl.h>
#endif
#if defined(__RTOS_VXWORKS__)
#include <ioLib.h>
#endif

#include "../../common/mdefs.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"
#include "../../common/mrtos.h"
#include "../../common/mjson.h"
#include "../../common/mfmgmt.h"
#include "../../common/debug_console.h"
#include "../../common/msg_logger.h"
#include "../../common/common_utils.h"

#include "trustedge_https_client.h"
#include "trustedge_https_util.h"

#ifdef __ENABLE_DIGICERT_UM_SSM__
#include "../../common/base64.h"
#include "um_msg_parser.h"
#endif

#if defined(__RTOS_LINUX__)
#include <unistd.h> /* getpid() */
#elif defined(__RTOS_WIN32__)
#include <process.h> /* _getpid() */
#endif

#define RECV_TEMP_FILE              "receive_body_temp.data"

/*---------------------------------------------------------------------------*/
/* Local Functions */
/*---------------------------------------------------------------------------*/

static MSTATUS initCtx(HttpsClientCtx **ppCtx);
static MSTATUS unInitCtx(HttpsClientCtx *pCtx);

static MSTATUS initCtx(HttpsClientCtx **ppCtx)
{
    MSTATUS status = OK;

    if (NULL != *ppCtx)
    {
        status = unInitCtx(*ppCtx);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_DEBUG,
                           "Cleanup - %s line %d status: %d = %s\n",
                           __func__, __LINE__, status,
                           MERROR_lookUpErrorCode(status));
        }
    }

    status = DIGI_CALLOC((void **) ppCtx, 1, sizeof(HttpsClientCtx));
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS unInitCtx(HttpsClientCtx *pCtx)
{
    MSTATUS status = OK;

    if (NULL != pCtx)
    {
        DIGI_FREE((void **)&pCtx);
        pCtx = NULL;
    }
    return status;
}

static MSTATUS initConfig(HttpsClientCtx *pCtx)
{
    pCtx->serverAddress = NULL;
    pCtx->serverRestPrefix = NULL;
    pCtx->signatureCertFileName = NULL;
    pCtx->signatureKeyFileName = NULL;
    pCtx->httpsTransactionTimeout = DEFAULT_TRANSACTION_TIMEOUT;
    pCtx->httpsDownloadTimeout = DEFAULT_DOWNLOAD_TIMEOUT;
    pCtx->serverRetryMaxCount = DEFAULT_SERVER_RETRY_MAX_CNT;
    pCtx->serverRetryDelaySeconds = DEFAULT_SERVER_RETRY_DELAY_SECS;
    /* */
    pCtx->requireOSCPEnable = FALSE;
    pCtx->mutualAuthEnable = FALSE;
    pCtx->sslServerCertFileName = NULL;
    pCtx->sslClientCertFileName = NULL;
    pCtx->sslClientKeyFileName = NULL;
    pCtx->pTrustStore = NULL;
    /* */
    pCtx->pUserData = NULL;
    pCtx->requestPrepareHeader = NULL;
    pCtx->requestMsg = NULL;
    pCtx->requestMsgLen = 0;
    pCtx->responseParse = NULL;
    pCtx->responseMsg = NULL;
    pCtx->responseMsgLen = 0;
    pCtx->nonce = NULL;
    pCtx->signatureAlgoId = NULL;
    pCtx->excludeChain = FALSE;

    return OK;
}

MOC_EXTERN MSTATUS
TRUSTEDGE_clientHttpsAcquireContext(
        HttpsClientCtx **ppNewContext,
        MSTATUS *umStatus)
{
    MSTATUS            status = OK;
    HttpsClientCtx* pHttpCtx = NULL;

    MSG_LOG_print(MSG_LOG_VERBOSE,
                   "%s", "Entering TRUSTEDGE_clientHttpsAcquireContext\n");

    if (NULL == ppNewContext)
    {
        status =  ERR_NULL_POINTER;
        *umStatus = status;
        MSG_LOG_print(MSG_LOG_ERROR, "%s line %d status: %d = %s\n",
                       __func__, __LINE__, status,
                       MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = initCtx(ppNewContext);
    if (OK != status)
    {
        *umStatus = status;
        MSG_LOG_print(MSG_LOG_ERROR, "%s line %d status: %d = %s\n",
                       __func__, __LINE__, status,
                       MERROR_lookUpErrorCode(status));
        goto exit;
    }
    pHttpCtx = ((HttpsClientCtx *) *ppNewContext);

    status = initConfig(pHttpCtx);
    if (OK != status)
    {
        *umStatus = status;
        MSG_LOG_print(MSG_LOG_ERROR, "%s line %d status: %d = %s\n",
                       __func__, __LINE__, status,
                       MERROR_lookUpErrorCode(status));
        goto exit;
    }

    *ppNewContext = pHttpCtx;
    pHttpCtx = NULL;

    *umStatus = status;

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS TRUSTEDGE_clientGetResponseBodyTempFileName(
    sbyte *pRspDir,
    sbyte *pFileName,
    sbyte **ppRspBodyFullPath)
{
    MSTATUS status = OK;
    sbyte *pTempFileName = NULL;
#if defined(__RTOS_LINUX__) || defined(__RTOS_WIN32__)
    ubyte4 tempFileNameLen = 0;
#endif

    if ((NULL == pRspDir) || (NULL == pFileName) || (NULL == ppRspBodyFullPath))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#if defined(__RTOS_LINUX__)
    tempFileNameLen = snprintf(NULL, 0, "%s.%d", pFileName, getpid());
    status = DIGI_MALLOC((void **) &pTempFileName, tempFileNameLen + 1);
    if (OK != status)
    {
        goto exit;
    }

    snprintf(pTempFileName, tempFileNameLen + 1, "%s.%d", pFileName, getpid());
#elif defined(__RTOS_WIN32__)
    tempFileNameLen = _snprintf(NULL, 0, "%s.%d", pFileName, _getpid());
    status = DIGI_MALLOC((void **) &pTempFileName, tempFileNameLen + 1);
    if (OK != status)
    {
        goto exit;
    }

    _snprintf(pTempFileName, tempFileNameLen + 1, "%s.%d", pFileName, _getpid());
#else
    pTempFileName = RECV_TEMP_FILE;
#endif

    /* Set the path to the HTTPS response file */
    status = COMMON_UTILS_addPathComponent(
        (sbyte *) pRspDir, pTempFileName, (sbyte **) ppRspBodyFullPath);
    if (OK != status)
        goto exit;
exit:
#ifdef __RTOS_LINUX__
    if (NULL != pTempFileName)
    {
        DIGI_FREE((void **) &pTempFileName);
    }
#endif
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS TRUSTEDGE_clientHttpsLocalAcquireContext(
    sbyte *pRspDir,
    HttpsClientCtx **ppNewContext)
{
    MSTATUS status = OK, umStatus = OK;
    HttpsClientCtx *pCtx = NULL;

    MSG_LOG_print(MSG_LOG_VERBOSE,
                   "%s", "Entering TRUSTEDGE_clientHttpsLocalAcquireContext\n");

    if ((NULL == ppNewContext) || (NULL == pRspDir))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Create the HTTPS client context without an UM daemon context or JSON
     * configuration. */
    status = TRUSTEDGE_clientHttpsAcquireContext(&pCtx, &umStatus);
    if (OK == status)
        status = umStatus;

    if (OK != status)
        goto exit;

    /* Set the path to the HTTPS response file */
    status = TRUSTEDGE_clientGetResponseBodyTempFileName(pRspDir, RECV_TEMP_FILE, &(pCtx->responseBodyTempFileName));
    if (OK != status)
        goto exit;

    /* Since this is a HTTPS client local API, set the message type to custom.
     * Caller must set the appropriate callbacks after creating the context */
    pCtx->requestMsgType = TRUSTEDGE_MSG_CUSTOM;

    *ppNewContext = pCtx;
    pCtx = NULL;

exit:

    if (NULL != pCtx)
        TRUSTEDGE_clientHttpsLocalReleaseContext(&pCtx);

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS TRUSTEDGE_clientHttpsReleaseContext(
        HttpsClientCtx **ppContext,
        MSTATUS *umStatus)
{
    MSTATUS status = OK;
    *umStatus = OK;

    MSG_LOG_print(MSG_LOG_VERBOSE,
                   "%s", "Entering TRUSTEDGE_clientHttpsReleaseContext\n");

    HttpsClientCtx *pCtx = *ppContext;

    DIGI_FREE((void **)&pCtx->serverAddress);
    DIGI_FREE((void **)&pCtx->serverIPAddress);
    DIGI_FREE((void **)&pCtx->serverRestPrefix);
    DIGI_FREE((void **)&pCtx->serverURI);
    DIGI_FREE((void **)&pCtx->signatureCertFileName);
    DIGI_FREE((void **)&pCtx->signatureKeyFileName);
    /* */
    DIGI_FREE((void **)&pCtx->sslServerCertFileName);
    DIGI_FREE((void **)&pCtx->sslClientCertFileName);
    DIGI_FREE((void **)&pCtx->sslClientKeyFileName);
    /* */
    DIGI_FREE((void **)&pCtx->authType);
    DIGI_FREE((void **)&pCtx->authValue);
    DIGI_FREE((void **)&pCtx->nonce);
    DIGI_FREE((void **)&pCtx->signatureAlgoId);
    DIGI_FREE((void **)&pCtx->responseMsgFileName);
    DIGI_FREE((void **)&pCtx->responseBodyTempFileName);
    DIGI_FREE((void **)&pCtx->redirectURI);
    DIGI_FREE((void **)&pCtx->serverDownloadAddress);
    DIGI_FREE((void **)&pCtx->serverDownloadURI);

    if( NULL != pCtx->httpThreadRunningLock)
    {
        status = RTOS_mutexFree(&pCtx->httpThreadRunningLock);
    }

    DIGI_FREE((void **)ppContext);

    return status;
}

MOC_EXTERN MSTATUS TRUSTEDGE_clientHttpsLocalReleaseContext(
    HttpsClientCtx **ppContext)
{
    MSTATUS status = OK, umStatus = OK;

    MSG_LOG_print(MSG_LOG_VERBOSE,
                   "%s", "Entering TRUSTEDGE_clientHttpsLocalReleaseContext\n");

    status = TRUSTEDGE_clientHttpsReleaseContext(ppContext, &umStatus);
    if (OK == status)
        status = umStatus;

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS TRUSTEDGE_clientHttpsLocalApplyServerConfig(
        HttpsClientCtx *pCtx,
        sbyte *pHostName,
        ubyte4 port,
        certStorePtr pStore,
        sbyte *pMutualAuthAlias)
{
    MSTATUS status = OK;
    ubyte4 hostNameLen;

    MSG_LOG_print(MSG_LOG_VERBOSE,
                   "%s", "Entering TRUSTEDGE_clientHttpsLocalApplyServerConfig\n");

    if ((NULL == pCtx) || (NULL == pHostName))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Set server address */
    DIGI_FREE((void **) &pCtx->serverAddress);
    hostNameLen = DIGI_STRLEN(pHostName);
    status = DIGI_MALLOC((void **) &pCtx->serverAddress, hostNameLen + 1);
    if (OK != status)
    {
        goto exit;
    }

    DIGI_MEMCPY(pCtx->serverAddress, pHostName, hostNameLen);
    pCtx->serverAddress[hostNameLen] = '\0';

    /* Set server port */
    pCtx->serverPort = port;

    /* Set truststore, used for SSL connection */
    pCtx->pTrustStore = pStore;

    /* Set mutual auth alias. If mutual auth alias is NULL then disable mutual
     * auth for this connection */
    pCtx->sslClientAlias = pMutualAuthAlias;
    pCtx->mutualAuthEnable = pMutualAuthAlias ? TRUE : FALSE;

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS TRUSTEDGE_clientHttpsLocalSetCustomMsg(
    HttpsClientCtx *pCtx,
    ubyte *pMsg,
    ubyte4 msgLen,
    void *pUserData,
    TRUSTEDGE_requestPrepareHeader requestPrepareHeader,
    TRUSTEDGE_responseParse responseParse)
{
    MSTATUS status;

    MSG_LOG_print(MSG_LOG_VERBOSE,
                   "%s", "Entering TRUSTEDGE_clientHttpsLocalSetCustomMsg\n");

    if ((NULL == pCtx) || (NULL == requestPrepareHeader) ||
        (NULL == responseParse))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Set the message, user data, HTTP header callback, and HTTP response
     * callback */
    pCtx->requestMsg = pMsg;
    pCtx->requestMsgLen = msgLen;
    pCtx->pUserData = pUserData;
    pCtx->requestPrepareHeader = requestPrepareHeader;
    pCtx->responseParse = responseParse;

    status = OK;

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS TRUSTEDGE_clientHttpsLocalGetUserData(
    HttpsClientCtx *pCtx,
    void **ppUserData)
{
    MSTATUS status = OK;

    if ((NULL == pCtx) || (NULL == ppUserData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppUserData = pCtx->pUserData;

exit:

    return status;
}

/*---------------------------------------------------------------------------*/
