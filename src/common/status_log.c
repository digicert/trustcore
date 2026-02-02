/*
 * status_loc.c
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */
#include "../common/moptions.h"

#if defined(__ENABLE_DIGICERT_STATUS_LOG__)

#include "../common/status_log.h"
#include "../common/mdefs.h"
#include "../common/mrtos.h"
#include "../common/datetime.h"
#include "../common/mstdlib.h"
#include "../common/mtcp.h"
#include "../common/mocana.h"
#include "../common/mjson.h"
#include "../http/http_context.h"
#include "../http/http_common.h"
#include "../http/http.h"

#include <stdio.h>

#define STATUS_LOG_FILE_PREFIX      "file://"
#define STATUS_LOG_SOCKET_PREFIX    "socket://"

#define STATUS_LOG_SOCKET_PATH      STATUS_LOG_SOCKET_PREFIX "%s:%d"

#define STATUS_LOG_GMT_FORMAT   "[%.*s/%.*s/%.*s %.*s:%.*s:%.*s GMT]"

#define STATUS_LOG_SUCCESS      "success"
#define STATUS_LOG_FAILURE      "failure"

#define JSON_STATUS_FILE_WITH_ERR_STRING \
    "{ \"timeStamp\": \"%s\", \"status\": \"%s\", \"statusCode\": %d, \"errorString\": \"%s\" }"
#define JSON_STATUS_FILE \
    "{ \"timeStamp\": \"%s\", \"status\": \"%s\", \"statusCode\": %d, \"errorString\": null }"

static MSTATUS STATUS_LOG_getGMTTimeStamp(
    sbyte **ppTimeStamp)
{
    MSTATUS status;
    sbyte pTimeBuf[16];
    TimeDate td;
    sbyte *pTime;
    int ret;
    ubyte4 timeStampLen;
    ubyte *pTimeStamp = NULL;

    status = RTOS_timeGMT(&td);
    if (OK != status)
        goto exit;

    status = DATETIME_convertToValidityString(&td, pTimeBuf);
    if (OK != status)
        goto exit;

    /* If its generalized time then offset by 2 */
    pTime = DIGI_STRLEN(pTimeBuf) == 15 ? pTimeBuf + 2 : pTimeBuf;

    ret = snprintf(NULL, 0, STATUS_LOG_GMT_FORMAT,
                    2, pTime + 2, 2, pTime + 4, 2, pTime,
                    2, pTime + 6, 2, pTime + 8, 2, pTime + 10);
    if (0 > ret)
    {
        status = ERR_STATUS_LOG_BUFFER_LENGTH;
        goto exit;
    }
    timeStampLen = ret;

    status = DIGI_MALLOC((void **) &pTimeStamp, timeStampLen + 1);
    if (OK != status)
    {
        goto exit;
    }

    ret = snprintf(pTimeStamp, timeStampLen + 1, STATUS_LOG_GMT_FORMAT,
                    2, pTime + 2, 2, pTime + 4, 2, pTime,
                    2, pTime + 6, 2, pTime + 8, 2, pTime + 10);
    if ( (0 > ret) || (timeStampLen != (ubyte4)ret) )
    {
        status = ERR_STATUS_LOG_BUFFER_CREATION;
        goto exit;
    }

    *ppTimeStamp = pTimeStamp;
    pTimeStamp = NULL;

exit:

    if (NULL != pTimeStamp)
    {
        DIGI_FREE((void **) &pTimeStamp);
    }

    return status;
}

extern MSTATUS STATUS_LOG_report(
    sbyte *pStatusLogPath,
    MSTATUS statusCode,
    sbyte *pErrString)
{
    MSTATUS status;
    int ret;
    sbyte *pTimeStamp = NULL;
    sbyte *pFilename = NULL;
    sbyte *pHostname = NULL;
    sbyte *pHostnameCopy = NULL;
    sbyte *pPort = NULL;
    sbyte4 port = 0;
    sbyte *pStop = NULL;
    sbyte *pIp = NULL;
    TCP_SOCKET statusLogSocket;
    byteBoolean freeStatusLogSocket = FALSE;
    ubyte4 nRet = 0;
    ubyte4 hostnameLen, statusLogLen;
    ubyte *pStatusLog = NULL;

    if (NULL == pStatusLogPath)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == DIGI_STRNCMP(pStatusLogPath, STATUS_LOG_FILE_PREFIX, DIGI_STRLEN(STATUS_LOG_FILE_PREFIX)))
    {
        pFilename = pStatusLogPath + DIGI_STRLEN(STATUS_LOG_FILE_PREFIX);
    }
    else if (0 == DIGI_STRNCMP(pStatusLogPath, STATUS_LOG_SOCKET_PREFIX, DIGI_STRLEN(STATUS_LOG_SOCKET_PREFIX)))
    {
        pHostname = pStatusLogPath + DIGI_STRLEN(STATUS_LOG_SOCKET_PREFIX);
        pPort = pHostname;
        while (*pPort != '\0' && *pPort != ':')
        {
            pPort++;
        }
        if (*pPort == '\0')
        {
            status = ERR_STATUS_LOG_MISSING_PORT;
            goto exit;
        }
        hostnameLen = pPort - pHostname;
        status = DIGI_MALLOC((void **) &pHostnameCopy, hostnameLen + 1);
        if (OK != status)
        {
            goto exit;
        }
        DIGI_MEMCPY(pHostnameCopy, pHostname, hostnameLen);
        pHostnameCopy[hostnameLen] = '\0';
        pPort++;

        port = DIGI_ATOL(pPort, (const sbyte **) &pStop);
        if (*pStop != '\0')
        {
            status = ERR_STATUS_LOG_INVALID_PATH;
            goto exit;
        }
    }
    else
    {
        status = ERR_STATUS_LOG_INVALID_PATH;
        goto exit;
    }

    status = STATUS_LOG_getGMTTimeStamp(&pTimeStamp);
    if (OK != status)
    {
        goto exit;
    }

    if (NULL != pErrString)
    {
        ret = snprintf(NULL, 0, JSON_STATUS_FILE_WITH_ERR_STRING,
                    pTimeStamp,
                    (OK == statusCode) ? STATUS_LOG_SUCCESS : STATUS_LOG_FAILURE,
                    statusCode,
                    pErrString);
    }
    else
    {
        ret = snprintf(NULL, 0, JSON_STATUS_FILE,
                    pTimeStamp,
                    (OK == statusCode) ? STATUS_LOG_SUCCESS : STATUS_LOG_FAILURE,
                    statusCode);
    }
    if (0 > ret)
    {
        status = ERR_STATUS_LOG_BUFFER_LENGTH;
        goto exit;
    }
    statusLogLen = ret;

    status = DIGI_MALLOC((void **) &pStatusLog, statusLogLen + 1);
    if (OK != status)
    {
        goto exit;
    }

    if (NULL != pErrString)
    {
        ret = snprintf(pStatusLog, statusLogLen + 1, JSON_STATUS_FILE_WITH_ERR_STRING,
                    pTimeStamp,
                    (OK == statusCode) ? STATUS_LOG_SUCCESS : STATUS_LOG_FAILURE,
                    statusCode,
                    pErrString);
    }
    else
    {
        ret = snprintf(pStatusLog, statusLogLen + 1, JSON_STATUS_FILE,
                    pTimeStamp,
                    (OK == statusCode) ? STATUS_LOG_SUCCESS : STATUS_LOG_FAILURE,
                    statusCode);
    }
    if ( (0 > ret) || (statusLogLen != (ubyte4)ret) )
    {
        status = ERR_STATUS_LOG_BUFFER_CREATION;
        goto exit;
    }
    pStatusLog[statusLogLen] = '\0';

    if (NULL != pFilename)
    {
        status = DIGICERT_writeFile(pFilename, pStatusLog, statusLogLen);
    }
    else
    {
        status = HTTP_getHostIpAddr(pHostnameCopy, &pIp);
        if (OK != status)
        {
            goto exit;
        }

        status = TCP_CONNECT(&statusLogSocket, pIp, port);
        if (OK != status)
        {
            goto exit;
        }
        freeStatusLogSocket = TRUE;

        TCP_WRITE(statusLogSocket, pStatusLog, statusLogLen, &nRet);
    }

exit:

    if (TRUE == freeStatusLogSocket)
    {
        TCP_CLOSE_SOCKET(statusLogSocket);
    }

    if (NULL != pStatusLog)
    {
        DIGI_FREE((void **) &pStatusLog);
    }

    if (NULL != pTimeStamp)
    {
        DIGI_FREE((void **) &pTimeStamp);
    }

    return status;
}

extern MSTATUS STATUS_LOG_socketPath(
    sbyte *pIp,
    ubyte2 port,
    sbyte **ppPath)
{
    MSTATUS status;
    int ret;
    ubyte4 len;
    ubyte *pPath = NULL;

    if ( (NULL == pIp) || (NULL == ppPath) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    ret = snprintf(NULL, 0, STATUS_LOG_SOCKET_PATH,
                pIp,
                port);
    if (0 > ret)
    {
        status = ERR_STATUS_LOG_BUFFER_LENGTH;
        goto exit;
    }
    len = ret;

    status = DIGI_MALLOC((void **) &pPath, len + 1);
    if (OK != status)
    {
        goto exit;
    }

    ret = snprintf(pPath, len + 1, STATUS_LOG_SOCKET_PATH,
                pIp,
                port);
    if (len != (ubyte4)ret)
    {
        status = ERR_STATUS_LOG_BUFFER_CREATION;
        goto exit;
    }

    *ppPath = pPath;
    pPath = NULL;

exit:

    if (NULL != pPath)
    {
        DIGI_FREE((void **) &pPath);
    }

    return status;
}

extern MSTATUS STATUS_LOG_parseReport(
    ubyte *pJson,
    ubyte4 jsonLen,
    MStatusLogReport *pReport)
{
    MSTATUS status;
    JSON_ContextType *pJCtx = NULL;
    JSON_TokenType token = { 0 };
    ubyte4 numTokens, ndx;

    if ( (NULL == pJson) || (NULL == pReport) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = JSON_acquireContext(&pJCtx);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_parse(pJCtx, pJson, jsonLen, &numTokens);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_getObjectIndex(pJCtx, "status", 0, &ndx, FALSE);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_getToken(pJCtx, ndx + 1, &token);
    if (OK != status)
    {
        goto exit;
    }

    if (JSON_String != token.type)
    {
        status = ERR_JSON_PARSE_FAILED;
        goto exit;
    }

    if (0 == DIGI_STRNCMP("success", token.pStart, token.len))
    {
        pReport->status = STATUS_LOG_STATE_SUCCESS;
    }
    else if (0 == DIGI_STRNCMP("failure", token.pStart, token.len))
    {
        pReport->status = STATUS_LOG_STATE_FAILURE;
    }
    else
    {
        status = ERR_STATUS_INVALID_REPORT;
        goto exit;
    }

    status = JSON_getObjectIndex(pJCtx, "statusCode", 0, &ndx, FALSE);
    if (OK != status)
    {
        goto exit;
    }

    status = JSON_getToken(pJCtx, ndx + 1, &token);
    if (OK != status)
    {
        goto exit;
    }

    if (JSON_Integer != token.type)
    {
        status = ERR_JSON_PARSE_FAILED;
        goto exit;
    }

    pReport->statusCode = token.num.intVal;

exit:

    if (NULL != pJCtx)
    {
        JSON_releaseContext(&pJCtx);
    }

    return status;
}

#endif /* __ENABLE_DIGICERT_STATUS_LOG__ */