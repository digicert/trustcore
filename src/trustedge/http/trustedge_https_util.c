/*
 * trustedge_https_util.c
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

/* For host lookup */
#if (defined(__RTOS_LINUX__) || defined(__RTOS_VXWORKS__) || defined(__RTOS_OSX__) || defined(__FREERTOS_SIMULATOR__) || defined(__RTOS_FREERTOS_ESP32__) || defined(__RTOS_QNX__))
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif
#if defined(__RTOS_WIN32__)
#include <winsock2.h>
#include <WS2tcpip.h>
#pragma comment(lib,"Ws2_32.lib")
#endif

/* For using the response temp file */
#include <stdio.h>
#ifndef __RTOS_FREERTOS__
#include <sys/types.h>
#include <fcntl.h>
#endif

#if defined(__RTOS_FREERTOS__) && !defined(__LWIP_STACK__) && !defined(__FREERTOS_SIMULATOR__)
#include <FreeRTOS.h>
#include "task.h"
#include "semphr.h"
#include <FreeRTOS_IP.h>
#include "FreeRTOS_Sockets.h"
#endif

#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
#include "../../ssl/ssl.h"
#endif
#include "../../common/mdefs.h"
#include "../../common/mrtos.h"
#include "../../common/mtcp.h"
#include "../../common/debug_console.h"
#include "../../common/mstdlib.h"
#include "../../common/utils.h"
#include "../../common/mfmgmt.h"
#include "../../common/msg_logger.h"
#include "../../http/http_context.h"
#include "../../http/http_common.h"
#include "../../http/http.h"
#include "../../http/http_auth.h"
#include "../../http/client/http_request.h"
#include "../../http/client/http_client_process.h"

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
#include "../../crypto/ca_mgmt.h"
#include "../../common/sizedbuffer.h"
#include "../../crypto/cert_store.h"
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */

#include "trustedge_https_client.h"
#include "trustedge_https_util.h"

#ifdef __ENABLE_DIGICERT_DATA_PROTECTION__
#include "../../data_protection/file_protect.h"
#endif

#if defined(__ENABLE_DIGICERT_SSL_PROXY_CONNECT__) && !defined(__ENABLE_DIGICERT_HTTP_PROXY__)
#error Must define __ENABLE_DIGICERT_HTTP_PROXY__ if __ENABLE_DIGICERT_SSL_PROXY_CONNECT__ is defined
#endif

#define MAX_NTRUSTEDGE_SSL_SERVER_SESSION                      (2)
#define MAX_NTRUSTEDGE_HTTP_CLIENT_SESSIONS                    (4)

#ifndef DIGI_TRUSTEDGE_TCP_BUFFER_SIZE
#define DIGI_TRUSTEDGE_TCP_BUFFER_SIZE                        (2048)
#endif

#define TCP_TIMEOUT                                     (200000) /* 200 sec */
#define HTTP_HDR_SIZE                                   (512)

/* NOTE:
 * This code is borrowed from src/examples/ssl_client_example.c
 */

#define RECV_TEMP_FILE          "receive_body.data"

#define REDIRECT                (302) /* Use the provided URI */
#define LOCATION                (5) /* Response header location value */

#define TRUSTEDGE_HTTPS_UTIL_GET_STORE(_pCtx) (_pCtx->pTrustStore)

static sbyte4 TRUSTEDGE_HTTPS_UTIL_performHttpRequest(httpContext *pHttpContext);

/*----------------------------------------------------------------------------*/

ubyte4 TRUSTEDGE_HTTPS_UTIL_getLowestHttpTimeout(HttpsClientCtx *pCtx)
{
    if(pCtx->httpsTransactionTimeout < pCtx->httpsDownloadTimeout)
    {
        return pCtx->httpsTransactionTimeout;
    }
    else
    {
        return pCtx->httpsDownloadTimeout;
    }
}

/*----------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
static sbyte4 myAlertCallback(sbyte4 connectionInstance,
    sbyte4 alertId, sbyte4 alertClass)
{
    MSG_LOG_print(MSG_LOG_DEBUG,
        "AlertClass: %d, AlertId: %d\n", alertClass, alertId);
    return OK;
}
#endif /* __ENABLE_DIGICERT_SSL_ALERTS__ */

/*-------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
static sbyte4
myCertStatusCallback(sbyte4 connectionInstance, intBoolean certStatus)
{
    MSTATUS status = OK;
    HttpsClientCtx *pHttpContext = NULL;

    status = SSL_getCookie( connectionInstance, (void **)&pHttpContext);
    if (OK != status || NULL == pHttpContext)
    {
        if( NULL == pHttpContext)
        {
            status = OK;
            goto exit;
        }
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if( TRUE == pHttpContext->requireOSCPEnable &&
        FALSE == certStatus)
    {
        status = ERR_SSL_EXTENSION_CERTIFICATE_STATUS_RESPONSE;
        pHttpContext->workerStatus = ERR_SSL_EXTENSION_CERTIFICATE_STATUS_RESPONSE;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

exit:
    return status;
}
#endif /* __ENABLE_DIGICERT_OCSP_CLIENT__ */

/*-------------------------------------------------------------------------*/

static sbyte4
TRUSTEDGE_HTTPS_UTIL_HttpTcpSend(httpContext *pHttpContext, TCP_SOCKET socket,
                ubyte *pDataToSend, ubyte4 numBytesToSend,
                ubyte4 *pRetNumBytesSent, sbyte4 isContinueFromBlock)
{
    sbyte4 status = 0;

    MOC_UNUSED(pHttpContext);
    MOC_UNUSED(isContinueFromBlock);

    status = TCP_WRITE(socket, (sbyte *)pDataToSend, numBytesToSend, pRetNumBytesSent);
    if (OK > status)
    {
        return status;
    }
    else
    {
        *pRetNumBytesSent = (ubyte4)status;
        return status;
    }
}

/*-------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
static sbyte4
TRUSTEDGE_HTTPS_UTIL_HttpSslSend(httpContext *pHttpContext, TCP_SOCKET socket,
                          ubyte *pDataToSend, ubyte4 numBytesToSend,
                          ubyte4 *pRetNumBytesSent, sbyte4 isContinueFromBlock)
{
    sbyte4 status = 0;
    HttpsClientCtx *pCtx = NULL;

    MOC_UNUSED(isContinueFromBlock);
    MOC_UNUSED(socket);

    if ((NULL == pHttpContext) || (NULL == pDataToSend) || (NULL == pRetNumBytesSent))
    {
        status = ERR_NULL_POINTER;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = HTTP_getCookie(pHttpContext, (void **) &pCtx);
    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if (NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = SSL_send(pCtx->connectionSSLInstance,
                      (sbyte *)pDataToSend, numBytesToSend);
    if (OK <= status)
    {
        *pRetNumBytesSent = (ubyte4)status;
    }

exit:
    return status;
}
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */

/*-------------------------------------------------------------------------*/

#if !defined(__ENABLE_DIGICERT_SSL_CLIENT__)
static sbyte4
TRUSTEDGE_HTTPS_UTIL_recoverFromTCPSocketError(httpContext *pHttpContext,
                                        sbyte* server, ubyte2 portNo)
{
    MSTATUS status = OK;

    TCP_SOCKET socketServer = pHttpContext->socket;

    HTTP_CONTEXT_resetHTTPResponseHeaders(pHttpContext);

    TCP_CLOSE_SOCKET(socketServer);
    if (OK > (status = TCP_CONNECT(&socketServer, server, portNo)))
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = HTTP_CONTEXT_setSocket(pHttpContext, socketServer);
    if (OK != status)
        goto exit;

    status = HTTP_CONTEXT_resetContext(pHttpContext);
    if (OK != status)
        goto exit;


exit:
    return status;
}
#endif

/*-------------------------------------------------------------------------*/
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
static sbyte4
TRUSTEDGE_HTTPS_UTIL_recoverFromSSLSocketError(httpContext *pHttpContext, HttpsClientCtx *pCtx)
{
    MSTATUS           status = OK;
    TCP_SOCKET        socketServer = 0;
    sbyte             *server;
    ubyte2            portNo;
    sbyte4            sslConnectionInstance;
#ifdef __ENABLE_DIGICERT_HTTP_PROXY__
    sbyte4            proxyTransport = -1;
    TCP_SOCKET        socketProxy = 0;
#endif
#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
    char              *pTrustedResponderCertsPath = NULL;
    ubyte4            trustedRespondercertCount  = 0;
#endif

    if (NULL == pHttpContext || NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    server = pCtx->serverIPAddress;
    portNo = pCtx->serverPort;
    sslConnectionInstance = pCtx->connectionSSLInstance;

    socketServer = pHttpContext->socket;

    HTTP_CONTEXT_resetHTTPResponseHeaders(pHttpContext);
    SSL_closeConnection(sslConnectionInstance);
    TCP_CLOSE_SOCKET(socketServer);

#ifdef __ENABLE_DIGICERT_HTTP_PROXY__
    if (HTTP_PROXY_isProxyUrlSet())
    {                    
        char *pAddrAndPort = NULL;
        ubyte4 addrAndPortLen = 0;
        sbyte *address = NULL;
        ubyte4 port = 0;

        /* First see if we have a download URI to use */
        if (NULL != pCtx->serverDownloadAddress)
        {
            address = pCtx->serverDownloadAddress;
            port =  pCtx->serverDownloadPort;
        }
        else if (NULL != pCtx->serverAddress)
        {
            address = pCtx->serverAddress;
            port =  pCtx->serverPort;
        }
        else
        {
            /* Error */
            status = ERR_URI_INVALID_FORMAT;
            goto exit;
        }

        /* add room for ':' and 5 digit port and '\0' */
        addrAndPortLen = DIGI_STRLEN(address) + 7;

        status = DIGI_CALLOC((void **)&pAddrAndPort, 1, addrAndPortLen);
        if (OK != status)
            goto exit;

        (void) snprintf(pAddrAndPort, addrAndPortLen, "%s:%d", (char *) address, (int) port);

        /* The socketServer is associated with the SSL session the application
         * is going to create. In the case of HTTP proxy, the socketServer is
         * the phsyical socket. In the case of HTTPS proxy, the sockerServer is
         * virtual socket */
        status = HTTP_PROXY_connect( (sbyte *) pAddrAndPort, &socketServer, &socketProxy, &proxyTransport, TRUSTEDGE_HTTPS_UTIL_GET_STORE(pCtx));
        /* free irregarless of status */
        (void) DIGI_FREE((void **) &pAddrAndPort);
        if (OK != status)
            goto exit;
    }
    else
#endif
    {
        if (NULL == server)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        if (OK > (status = TCP_CONNECT(&socketServer, server, portNo)))
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }
    }

#ifdef __ENABLE_DIGICERT_SSL_PROXY_CONNECT__
    if (0 < proxyTransport)
    {
        sslConnectionInstance = SSL_PROXY_connect(
            socketProxy, proxyTransport, SSL_PROXY_send, SSL_PROXY_recv,
            socketServer, 0, NULL, NULL, pCtx->serverAddress,
            TRUSTEDGE_HTTPS_UTIL_GET_STORE(pCtx));
        if (OK < sslConnectionInstance)
        {
            status = sslConnectionInstance;
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            (void) SSL_closeConnection(proxyTransport);
            (void) TCP_CLOSE_SOCKET(socketServer);
            goto exit;
        }
        /* TCP and SSL proxy session stored in SSL session created by
         * SSL_PROXY_connect. Set proxy to invalid value to avoid double close.
         */
        proxyTransport = -1;
    }
    else
#endif
    {
        sslConnectionInstance = SSL_connect(
            socketServer, 0, NULL, NULL, pCtx->serverAddress,
            TRUSTEDGE_HTTPS_UTIL_GET_STORE(pCtx));
        if (OK < sslConnectionInstance)
        {
            status = sslConnectionInstance;
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            TCP_CLOSE_SOCKET(socketServer);
            goto exit;
        }
    }

    if (OK > SSL_setCookie(sslConnectionInstance, (void *)pCtx))
    {
        MSG_LOG_print(MSG_LOG_ERROR, "%s line %d status: %d = %s\n",
                __func__, __LINE__, status, MERROR_lookUpErrorCode(status));
        SSL_closeConnection(sslConnectionInstance);
        TCP_CLOSE_SOCKET(socketServer);
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
    if( TRUE == pCtx->mutualAuthEnable)
    {
        if (OK > SSL_setMutualAuthCertificateAlias(
                sslConnectionInstance,
                (ubyte *)pCtx->sslClientAlias,
                DIGI_STRLEN( (sbyte *)pCtx->sslClientAlias)))
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            SSL_closeConnection(sslConnectionInstance);
            TCP_CLOSE_SOCKET(socketServer);
            goto exit;
        }
    }
#else
    if( TRUE == pCtx->mutualAuthEnable)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                       "%s line %d: %s\n",
                       __func__, __LINE__,
                       "SSL Mutual Authentication is DISABLED!");
        status = ERR_SSL_CONFIG;
        TCP_CLOSE_SOCKET(socketServer);
        goto exit;
    }
#endif

    if (OK > SSL_setServerNameIndication(sslConnectionInstance,
                                         (const char *)pCtx->serverAddress))
    {
        MSG_LOG_print(MSG_LOG_ERROR, "%s line %d status: %d = %s\n",
                       __func__, __LINE__, status, MERROR_lookUpErrorCode(status));
        SSL_closeConnection(sslConnectionInstance);
        TCP_CLOSE_SOCKET(socketServer);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
    if (TRUE == pCtx->requireOSCPEnable)
    {
        status = SSL_setCertifcateStatusRequestExtensions(
            sslConnectionInstance, &pTrustedResponderCertsPath,
            trustedRespondercertCount, NULL, 0);
        if (OK > status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status, MERROR_lookUpErrorCode(status));
            SSL_closeConnection(sslConnectionInstance);
            TCP_CLOSE_SOCKET(socketServer);
            goto exit;
        }
    }
#endif

    if (OK > SSL_negotiateConnection(sslConnectionInstance))
    {
        MSG_LOG_print(MSG_LOG_ERROR, "%s line %d status: %d = %s\n",
                       __func__, __LINE__, status, MERROR_lookUpErrorCode(status));
        SSL_closeConnection(sslConnectionInstance);
        TCP_CLOSE_SOCKET(socketServer);
        goto exit;
    }

    /* Success */
    status = HTTP_CONTEXT_setSocket(pHttpContext, socketServer);
    if (OK != status)
    {
        TCP_CLOSE_SOCKET(socketServer);
        goto exit;
    }
    status = HTTP_CONTEXT_resetContext(pHttpContext);
    if (OK != status)
    {
        TCP_CLOSE_SOCKET(socketServer);
        goto exit;
    }

exit:

#if defined(__ENABLE_DIGICERT_SSL_PROXY_CONNECT__)
    if (OK != status && 0 < proxyTransport)
    {
        (void) SSL_closeConnection(proxyTransport);
        (void) TCP_CLOSE_SOCKET(socketProxy);
    }
#endif

    return status;
}
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */

/*-------------------------------------------------------------------------*/

#if !defined(__ENABLE_DIGICERT_SSL_CLIENT__)
static sbyte4
TRUSTEDGE_HTTPS_UTIL_receiveFromTCPSocket(TCP_SOCKET serverSock,sbyte *pRetBuffer,
                                   ubyte4 bufferSize, ubyte4 *pNumBytesReceived,
                                   ubyte4 timeout)
{
    MSTATUS status = OK;
    status = TCP_READ_AVL(serverSock, pRetBuffer, bufferSize,
                          pNumBytesReceived, timeout);
    return status;
}
#endif

/*-------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
static sbyte4
TRUSTEDGE_HTTPS_UTIL_receiveFromSSLSocket(sbyte4 serverConn,
                                    sbyte *pRetBuffer,
                                    ubyte4 bufferSize,
                                    ubyte4 *pNumBytesReceived,
                                    ubyte4 timeout)
{
    MSTATUS status = OK;
    sbyte4 result = 0;
    sbyte4 bytesReceived = -1;
    result = SSL_recv(serverConn, pRetBuffer, bufferSize,
                      &bytesReceived, timeout);
    if (result >= OK)
    {
        if (bytesReceived == -1)
        {
            status = ERR_TCP_READ_ERROR;
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
        }
        else
        {
            *pNumBytesReceived = bytesReceived;
        }
    }
    else
    {
        status = (MSTATUS) result;
    }
    return status;
}
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */

/*-------------------------------------------------------------------------*/

static sbyte4
TRUSTEDGE_HTTPS_UTIL_prepareHeaderRequest(
    HttpsClientCtx *pCtx, httpContext *pHttpContext)
{
    MSTATUS status = OK;

    if ((NULL == pCtx) || (NULL == pHttpContext))
    {
        status = ERR_NULL_POINTER;
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    /* If a custom message is set then let the caller set the HTTP header
     * through the HTTP header callback */
    if (TRUSTEDGE_MSG_CUSTOM == pCtx->requestMsgType)
    {
        if (NULL == pCtx->requestPrepareHeader)
        {
            status = ERR_NULL_POINTER;
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = pCtx->requestPrepareHeader(pCtx, pHttpContext);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
        }
        else if (NULL != pCtx->requestMsg)
        {
            MSG_LOG_print(MSG_LOG_INFO,
                    "requestMsgLen len = %d, msg = %s\n",
                    pCtx->requestMsgLen, pCtx->requestMsg);
        }
        goto exit;
    }

exit:
    return status;
}

/*-------------------------------------------------------------------------*/

static sbyte4
TRUSTEDGE_HTTPS_UTIL_responseHeaderCallback(httpContext *pHttpContext,
                                      sbyte4 isContinueFromBlock)
{
    int i;
    HTTP_stringDescr* headers = pHttpContext->responses;
    ubyte* pValue = NULL;
    ubyte4 len = 0;
    MSTATUS status = OK;
    FileDescriptor tmpFd = NULL;

    ubyte4 httpStatusCode = 0;
    HttpsClientCtx *pCtx = NULL;

    MOC_UNUSED(isContinueFromBlock);

    status = HTTP_getCookie(pHttpContext, (void **)&pCtx);

    if (OK != status || NULL == pCtx)
    {
        if( NULL == pCtx)
        {
            status = ERR_NULL_POINTER;
        }
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = DIGI_CALLOC((void **)&pValue, 1, HTTP_HDR_SIZE);
    if (OK != status)
    {
        goto exit;
    }

    if (pHttpContext->isHeaderDone)
    {
        MSG_LOG_print(MSG_LOG_DEBUG,
                "(HDR) pHttpContext->pURI = %s\n", pHttpContext->pURI);
    }

    if( 200 == pHttpContext->httpStatusResponse)
    {
        MSG_LOG_print(MSG_LOG_DEBUG,
                       "(HDR) pHttpContext->httpStatusResponse = %d\n",
                       pHttpContext->httpStatusResponse);
    }
    else
    {
        MSG_LOG_print(MSG_LOG_WARNING,
                       "(HDR) pHttpContext->httpStatusResponse = %d\n"
                       ,pHttpContext->httpStatusResponse);
    }
    MSG_LOG_print(MSG_LOG_DEBUG,
                   "(HDR) pHttpContext->contentLength = %d\n",
                   pHttpContext->contentLength);
    MSG_LOG_print(MSG_LOG_VERBOSE,
                   "(HDR) pHttpContext->isHeaderDone = %d\n",
                   pHttpContext->isHeaderDone);
    MSG_LOG_print(MSG_LOG_VERBOSE,
                   "(HDR) pHttpContext->isBodyDone = %d\n",
                   pHttpContext->isBodyDone);
    MSG_LOG_print(MSG_LOG_VERBOSE,
                   "(HDR) pHttpContext->indefiniteLength = %d\n",
                   pHttpContext->indefiniteLength);

    pCtx->responseStatus = pHttpContext->httpStatusResponse;

    FMGMT_remove (pCtx->responseBodyTempFileName, FALSE);

    status = FMGMT_fopen (pCtx->responseBodyTempFileName, "ab", &tmpFd);
    if (OK != status)
    {
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }
    FMGMT_fclose (&tmpFd);

    pCtx->responseMsgLen = pHttpContext->contentLength;

    /* Get the response */
    status = HTTP_REQUEST_getStatusCode (pHttpContext, &httpStatusCode);
    if (OK != status)
      goto exit;

    /* work around for a pre-processor problem */
    DIGI_LTOA(httpStatusCode, (sbyte *)pValue, 512);
    *(pValue+3)= 0;
    MSG_LOG_print(MSG_LOG_INFO, "%s\n", pValue);

    /* Check for a redirect */
    if (200 == httpStatusCode)
    {
        status = OK;
    }
    else if (REDIRECT == httpStatusCode)
    {
        if (0 < headers[LOCATION].httpStringLength)
        {
            pCtx->redirectURILen = headers[LOCATION].httpStringLength;
            status = DIGI_CALLOC((void **)&pCtx->redirectURI, 1,
                                           pCtx->redirectURILen);
            if (OK != status)
            {
                goto exit;
            }
            snprintf((char *)pCtx->redirectURI, pCtx->redirectURILen, "%s",
                    headers[LOCATION].pHttpString);
        }
    }
    else if (500 == pCtx->responseStatus)
    {
        status = ERR_TRUSTEDGE_HTTP_SERVER_ERROR;
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }
    else
    {
        status = ERR_TRUSTEDGE_HTTP_INVALID_REQUEST_MSG;
        goto exit;
    }

    for ( i = 0; i < HTTP_SUPPORTED_RESPONSES; i++)
    {
        if (headers[i].httpStringLength > 0)
        {
            if (i < NUM_HTTP_RESPONSES)
            {
                len = mHttpResponses[i].httpRequestNameLength;
                DIGI_MEMCPY(pValue, mHttpResponses[i].pHttpRequestName, len);
            }
            else if (i < NUM_HTTP_RESPONSES + NUM_HTTP_GENERALHEADERS)
            {
                len = mHttpGeneralHeaders[i -
                          NUM_HTTP_RESPONSES].httpRequestNameLength;
                DIGI_MEMCPY(pValue, mHttpGeneralHeaders[i -
                           NUM_HTTP_RESPONSES].pHttpRequestName, len);
            }
            else
            {
                len = mHttpEntityHeaders[i - NUM_HTTP_RESPONSES -
                               NUM_HTTP_GENERALHEADERS].httpRequestNameLength;
                DIGI_MEMCPY(pValue,
                    mHttpEntityHeaders[i - NUM_HTTP_RESPONSES -
                    NUM_HTTP_GENERALHEADERS].pHttpRequestName, len);
            }
            DIGI_MEMCPY(pValue+len, ": ", 2);
            len += 2;
            DIGI_MEMCPY(pValue+len, headers[i].pHttpString,
                       headers[i].httpStringLength);
            len += headers[i].httpStringLength;
            *(pValue+len)= 0;
            MSG_LOG_print(MSG_LOG_INFO, "%s\n", pValue);
        }
    }

exit:
    DIGI_FREE((void **)&pValue);
    return status;
}

/*-------------------------------------------------------------------------*/

static sbyte4
TRUSTEDGE_HTTPS_UTIL_responseBodyCallback(httpContext *pHttpContext,
                ubyte *pDataReceived,
                ubyte4 dataLength,
                sbyte4 isContinueFromBlock)
{
    FileDescriptor tmpFd = NULL;
    ubyte4 wrote = 0;
    MSTATUS status = OK;
    HttpsClientCtx *pCtx = NULL;

    if( NULL == pHttpContext)
    {
        status = ERR_NULL_POINTER;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = HTTP_getCookie(pHttpContext, (void **)&pCtx);

    if (OK != status)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    if ((NULL == pCtx) ||
        (NULL == pCtx->responseBodyTempFileName))
    {
        status = ERR_NULL_POINTER;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

#ifndef UMCD_DISABLE_LOGGING
    if (pHttpContext->contentLength == 0)
    {
        MSG_LOG_print(MSG_LOG_INFO,
                       "%s", "+++++++++++++++++++++++++++++++++++++++++++++\n");
        MSG_LOG_print(MSG_LOG_VERBOSE,
                       "%s", "TRUSTEDGE_HTTPS_UTIL_responseBodyCallback\n");
        MSG_LOG_print(MSG_LOG_INFO,
                       "(BODY) pHttpContext->pURI = %s\n", pHttpContext->pURI);
        MSG_LOG_print(MSG_LOG_INFO,
                       "(BODY) pHttpContext->httpStatusResponse = %d\n",
                       pHttpContext->httpStatusResponse);
        MSG_LOG_print(MSG_LOG_INFO,
                       "(BODY) pHttpContext->contentLength = %d\n",
                       pHttpContext->contentLength);
        MSG_LOG_print(MSG_LOG_VERBOSE,
                       "(BODY) is continue from block = %d \n",
                       isContinueFromBlock);
        MSG_LOG_print(MSG_LOG_VERBOSE,
                       "(BODY) received dataLen = %d\n",dataLength);
        if (FALSE == pCtx->acceptOctetStream)
        {
            MSG_LOG_print(MSG_LOG_VERBOSE, "%.*s\n", dataLength, pDataReceived);
        }
        MSG_LOG_print(MSG_LOG_VERBOSE,
                       "(BODY) pHttpContext->isHeaderDone = %d\n",
                       pHttpContext->isHeaderDone);
        MSG_LOG_print(MSG_LOG_VERBOSE,
                       "(BODY) pHttpContext->isBodyDone = %d\n",
                       pHttpContext->isBodyDone);
        MSG_LOG_print(MSG_LOG_VERBOSE,
                       "(BODY) pHttpContext->indefiniteLength = %d\n",
                       pHttpContext->indefiniteLength);

        if(NULL != pHttpContext->pHttpVersionDescr)
        {
            MSG_LOG_print(MSG_LOG_VERBOSE,
                           "(BODY) pHttpContext->pHttpVersionDescr = %s\n",
                           pHttpContext->pHttpVersionDescr->pHttpVersionName);
        }
        MSG_LOG_print(MSG_LOG_INFO,
                       "%s", "+++++++++++++++++++++++++++++++++++++++++++++\n");

    }
#endif

    pCtx->responseMsgLen = 0;
    pCtx->responseStatus = pHttpContext->httpStatusResponse;

    /* Collect all data received to a temp file for processing */
    status = FMGMT_fopen (pCtx->responseBodyTempFileName, "r+b", &tmpFd);
    if (OK != status)
    {
        status = ERR_FILE_OPEN_FAILED;
        goto exit;
    }

    status = FMGMT_fseek (tmpFd, 0, MSEEK_END);
    if (OK != status)
    {
        status = ERR_FILE_WRITE_FAILED;
        FMGMT_fclose (&tmpFd);
        goto exit;
    }

    status = FMGMT_fwrite (pDataReceived, 1, dataLength, tmpFd, &wrote);
    if ((OK != status) || (wrote != dataLength))
    {
        status = ERR_FILE_WRITE_FAILED;
        FMGMT_fclose (&tmpFd);
        goto exit;
    }
    FMGMT_fclose (&tmpFd);

    /* If a custom message is set then exit and let the caller process the
     * response when all the data is recieved. */
    if (TRUSTEDGE_MSG_CUSTOM == pCtx->requestMsgType)
    {
        /* Log HTTP response status. */
        MSG_LOG_print(MSG_LOG_VERBOSE,
                       "HTTP Response Status = %d\n", pCtx->responseStatus);
        goto exit;
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------------------*/

static sbyte4
TRUSTEDGE_HTTPS_UTIL_requestBodyCallBack(httpContext *pHttpContext, ubyte **pDataToSend,
                                  ubyte4 *pDataLength, void *pRequestBodyCookie)
{
    MSTATUS status = OK;
    HttpsClientCtx *pCtx = NULL;

    if ((NULL == pRequestBodyCookie) || (NULL == pHttpContext) ||
        (NULL == pDataToSend) || (NULL == pDataLength))
    {
        status = ERR_NULL_POINTER;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    pCtx = (HttpsClientCtx *) pRequestBodyCookie;

    MSG_LOG_print(MSG_LOG_VERBOSE,
                   "TRUSTEDGE_HTTPS_UTIL_requestBodyCallBack: len = %d\n",
                   pCtx->requestMsgLen);

    /* If a message is set then allocate memory for the message and return it,
     * otherwise return NULL to specify there is no request body message. */
    if (0 != pCtx->requestMsgLen)
    {
        status = DIGI_CALLOC((void **)pDataToSend, 1, pCtx->requestMsgLen);
        if (OK != status)
            goto exit;

        DIGI_MEMCPY(*pDataToSend, pCtx->requestMsg, pCtx->requestMsgLen);
    }
    else
    {
        *pDataToSend = NULL;
    }
    *pDataLength = pCtx->requestMsgLen;

    pHttpContext->isBodyDone = TRUE;

exit:
    return status;
}

/*----------------------------------------------------------------------------------------*/

static sbyte4 TRUSTEDGE_HTTPS_UTIL_passwordPrompt(
    httpContext *pHttpContext,
    const ubyte* pChallenge,
    ubyte4 challengeLength,
    ubyte **ppUser,
    ubyte4* pUserLength,
    ubyte **ppPassword,
    ubyte4 *pPasswordLength,
    sbyte4 isContinueFromBlock)
{
    /* Cannot expect to be able to enter a password on a target device */
    MOC_UNUSED(pHttpContext);
    MOC_UNUSED(pChallenge);
    MOC_UNUSED(challengeLength);
    MOC_UNUSED(ppUser);
    MOC_UNUSED(pUserLength);
    MOC_UNUSED(ppPassword);
    MOC_UNUSED(pPasswordLength);
    MOC_UNUSED(isContinueFromBlock);
    return OK;
}

/*----------------------------------------------------------------------------------------*/

MSTATUS
TRUSTEDGE_HTTPS_UTIL_runClient(HttpsClientCtx *pCtx)
{
    sbyte4          status = OK;
    TCP_SOCKET      socketServer = 0;
    sbyte*          address = NULL;
    ubyte4          port = 0;
#ifdef __ENABLE_DIGICERT_HTTP_PROXY__
    sbyte4          proxyTransport = -1;
    TCP_SOCKET      socketProxy = 0;
#endif
#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
    char *pTrustedResponderCertsPath = NULL;
    ubyte4 trustedRespondercertCount  = 0;
#endif

    if (NULL == pCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
    pCtx->connectionSSLInstance = -1;
#endif

    MSG_LOG_print(MSG_LOG_VERBOSE, "%s", "TRUSTEDGE_HTTPS_UTIL_runClient\n");

    /* First see if we have a download URI to use */
    if (NULL != pCtx->serverDownloadAddress)
    {
        address = pCtx->serverDownloadAddress;
        port =  pCtx->serverDownloadPort;
    }
    else if (NULL != pCtx->serverAddress)
    {
        address = pCtx->serverAddress;
        port =  pCtx->serverPort;
    }
    else
    {
        /* Error */
        status = ERR_URI_INVALID_FORMAT;
        goto exit;
    }
    /* Get the IP Address of the server */
    DIGI_FREE((void **)&pCtx->serverIPAddress);

    /* There is a chance that an update package spawned off a TPEC operation
     * that overwrote the global HTTP function pointers.  Make sure the
     * function pointers are set correctly before we proceed. */
    TRUSTEDGE_HTTPS_UTIL_resetFuncPtrs();

#ifdef __ENABLE_DIGICERT_HTTP_PROXY__
    if (HTTP_PROXY_isProxyUrlSet())
    {
        char *pAddrAndPort = NULL;
        /* add room for ':' and 5 digit port and '\0' */
        ubyte4 addrAndPortLen = DIGI_STRLEN((sbyte *) address) + 7;

        status = DIGI_CALLOC((void **)&pAddrAndPort, 1, addrAndPortLen);
        if (OK != status)
            goto exit;

        (void) snprintf(pAddrAndPort, addrAndPortLen, "%s:%d", (char *) address, (int) port);

        /* The socketServer is associated with the SSL session the application
         * is going to create. In the case of HTTP proxy, the socketServer is
         * the phsyical socket. In the case of HTTPS proxy, the sockerServer is
         * virtual socket */
        status = HTTP_PROXY_connect(
            (sbyte *) pAddrAndPort, &socketServer, &socketProxy,
            &proxyTransport, TRUSTEDGE_HTTPS_UTIL_GET_STORE(pCtx));
        if (OK != status)
        {
            pCtx->workerStatus = ERR_TRUSTEDGE_FATAL_CONNECTION_ERROR;
            MSG_LOG_print(MSG_LOG_ERROR,
            "\nCould not connect to the server:port specified by the '%s' "
            "& '%d' attributes in config.json\n"
            "\t- %s line %d status: %d = %s\n",
            (char *) address, port, __func__, __LINE__,
            status, MERROR_lookUpErrorCode(status));
            status = ERR_TRUSTEDGE_HTTP_SERVER_ERROR;
            (void) DIGI_FREE((void **) &pAddrAndPort);
            goto exit;
        }

        (void) DIGI_FREE((void **) &pAddrAndPort);
    }
    else
#endif
    {
        status = HTTP_getHostIpAddr(address, &pCtx->serverIPAddress);    
        if (OK != status)
        {
            pCtx->workerStatus = ERR_TRUSTEDGE_FATAL_CONNECTION_ERROR;
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = TCP_CONNECT(&socketServer,
                            (sbyte *)pCtx->serverIPAddress, port);
        if (0 > status)
        {
            status = TCP_CONNECT(&socketServer,
                                (sbyte *)address, port);
            if (OK != status)
            {
                pCtx->workerStatus = ERR_TRUSTEDGE_FATAL_CONNECTION_ERROR;
                MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                status = ERR_TRUSTEDGE_HTTP_SERVER_ERROR;
                if (0 != socketServer)
                {
                    TCP_CLOSE_SOCKET(socketServer);
                }
                goto exit;
            }
        }
    }
    pCtx->serverSocket = socketServer;

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
#if defined(__ENABLE_DIGICERT_SSL_PROXY_CONNECT__)
    if (0 < proxyTransport)
    {
        pCtx->connectionSSLInstance = SSL_PROXY_connect(
            socketProxy, proxyTransport, SSL_PROXY_send, SSL_PROXY_recv,
            socketServer, 0, NULL, NULL, address,
            TRUSTEDGE_HTTPS_UTIL_GET_STORE(pCtx));
        if (OK > pCtx->connectionSSLInstance)
        {
            status = pCtx->connectionSSLInstance;
            pCtx->workerStatus = ERR_TRUSTEDGE_FATAL_CONNECTION_ERROR;
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            (void) SSL_closeConnection(proxyTransport);
            TCP_CLOSE_SOCKET(socketServer);
            pCtx->serverSocket = 0;
            goto exit;
        }
        /* TCP and SSL proxy session stored in SSL session created by
         * SSL_PROXY_connect. Set proxy to invalid value to avoid double close.
         */
        proxyTransport = -1;
    }
    else
#endif
    {
        pCtx->connectionSSLInstance = SSL_connect(
            socketServer, 0, NULL, NULL, address,
            TRUSTEDGE_HTTPS_UTIL_GET_STORE(pCtx));
        if (OK > pCtx->connectionSSLInstance)
        {
            status = pCtx->connectionSSLInstance;
            pCtx->workerStatus = ERR_TRUSTEDGE_FATAL_CONNECTION_ERROR;
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            TCP_CLOSE_SOCKET(socketServer);
            pCtx->serverSocket = 0;
            goto exit;
        }
    }

    if (OK > SSL_setCookie( pCtx->connectionSSLInstance, (void *)pCtx))
    {
        MSG_LOG_print(MSG_LOG_ERROR, "%s line %d status: %d = %s\n",
                __func__, __LINE__, status, MERROR_lookUpErrorCode(status));
        SSL_closeConnection( pCtx->connectionSSLInstance);
        pCtx->connectionSSLInstance = -1;
        TCP_CLOSE_SOCKET(socketServer);
        pCtx->serverSocket = 0;
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
    if( TRUE == pCtx->mutualAuthEnable)
    {
#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_DATA_PROTECTION__)
        /* Loads in a TAP password. If a password file is found then it will
         * be loaded in, otherwise assume there is no password.
         */
        status = TRUSTEDGE_clientTapLoadCredentialList(
            (const char*)pCtx->sslClientKeyFileName);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "%s line %d status: %d = %s\n",
                __func__, __LINE__, status, MERROR_lookUpErrorCode(status));
            goto exit;
        }
#endif

        if (OK > SSL_setMutualAuthCertificateAlias(
                pCtx->connectionSSLInstance,
                (ubyte *)pCtx->sslClientAlias,
                DIGI_STRLEN( (sbyte *)pCtx->sslClientAlias)))
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            SSL_closeConnection(pCtx->connectionSSLInstance);
            pCtx->connectionSSLInstance = -1;
            TCP_CLOSE_SOCKET(socketServer);
            pCtx->serverSocket = 0;
            goto exit;
        }
    }
#else
    if( TRUE == pCtx->mutualAuthEnable)
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                       "%s line %d: %s\n",
                       __func__, __LINE__,
                       "SSL Mutual Authentication is DISABLED!");
        status = ERR_SSL_CONFIG;
        TCP_CLOSE_SOCKET(socketServer);
        pCtx->serverSocket = 0;
        goto exit;
    }
#endif

    status = SSL_setServerNameIndication(pCtx->connectionSSLInstance,
                                         (const char *)address);
    if (OK > status)
    {
        pCtx->workerStatus = ERR_TRUSTEDGE_HTTP_SERVER_ERROR;
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        status = ERR_TRUSTEDGE_HTTP_SERVER_ERROR;
        SSL_closeConnection(pCtx->connectionSSLInstance);
        pCtx->connectionSSLInstance = -1;
        TCP_CLOSE_SOCKET(socketServer);
        pCtx->serverSocket = 0;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
    if (TRUE == pCtx->requireOSCPEnable)
    {
        status = SSL_setCertifcateStatusRequestExtensions(
            pCtx->connectionSSLInstance, &pTrustedResponderCertsPath,
            trustedRespondercertCount, NULL, 0);
        if (OK > status)
        {
            MSG_LOG_print(MSG_LOG_ERROR, "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status, MERROR_lookUpErrorCode(status));
            SSL_closeConnection(pCtx->connectionSSLInstance);
            pCtx->connectionSSLInstance = -1;
            TCP_CLOSE_SOCKET(socketServer);
            pCtx->serverSocket = 0;
            goto exit;
        }
    }
#endif

    status = SSL_negotiateConnection(pCtx->connectionSSLInstance);
    if (OK > status)
    {
        pCtx->workerStatus = ERR_TRUSTEDGE_FATAL_CONNECTION_ERROR;
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        SSL_closeConnection(pCtx->connectionSSLInstance);
        pCtx->connectionSSLInstance = -1;
        TCP_CLOSE_SOCKET(socketServer);
        pCtx->serverSocket = 0;
        goto exit;
    }
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */

    if (OK > (status = HTTP_connect(&pCtx->pCurrHttpContext, socketServer)))
    {
        pCtx->workerStatus = ERR_TRUSTEDGE_HTTP_SERVER_ERROR;
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
        SSL_closeConnection(pCtx->connectionSSLInstance);
        pCtx->connectionSSLInstance = -1;
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */
        TCP_CLOSE_SOCKET(socketServer);
        pCtx->serverSocket = 0;
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        status = ERR_TRUSTEDGE_HTTP_SERVER_ERROR;
        goto exit;
    }

    /* Set the http context cookie to point the the https client
     * context for use in the callbacks
     */
    status = HTTP_setCookie(pCtx->pCurrHttpContext, (void *) pCtx);
    if (OK != status)
    {
        pCtx->workerStatus = ERR_TRUSTEDGE_HTTP_SERVER_ERROR;
        HTTP_close(&pCtx->pCurrHttpContext);
        pCtx->pCurrHttpContext = NULL;
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
        SSL_closeConnection(pCtx->connectionSSLInstance);
        pCtx->connectionSSLInstance = -1;
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */
        TCP_CLOSE_SOCKET(socketServer);
        pCtx->serverSocket = 0;
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = TRUSTEDGE_HTTPS_UTIL_performHttpRequest(pCtx->pCurrHttpContext);
    if (OK != status)
    {
        if (OK == pCtx->workerStatus)
        {
            pCtx->workerStatus = ERR_TRUSTEDGE_HTTP_SERVER_ERROR;
        }
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
    }

    HTTP_close(&pCtx->pCurrHttpContext);
    pCtx->pCurrHttpContext = NULL;

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
    SSL_closeConnection(pCtx->connectionSSLInstance);
    pCtx->connectionSSLInstance = -1;
#if defined(__ENABLE_DIGICERT_SSL_MUTUAL_AUTH_SUPPORT__)
#if defined(__ENABLE_DIGICERT_TAP__)
#if 0
    TRUSTEDGE_clientTapClearCredentialList();
#endif
#endif
#endif
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */
    TCP_CLOSE_SOCKET(socketServer);
    pCtx->serverSocket = 0;

exit:

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__) && defined(__ENABLE_DIGICERT_SSL_PROXY_CONNECT__)
    if (0 < proxyTransport)
    {
        (void) SSL_closeConnection(proxyTransport);
        (void) TCP_CLOSE_SOCKET(socketProxy);
    }
#endif

    return status;

} /* TRUSTEDGE_HTTPS_UTIL_runClient */

/*----------------------------------------------------------------------------------------*/

void
TRUSTEDGE_HTTPS_UTIL_freeClient(HttpsClientCtx *pHttpsClientCtx)
{
    if (NULL != pHttpsClientCtx)
    {
        if (NULL != pHttpsClientCtx->pCurrHttpContext)
        {
            HTTP_close(&pHttpsClientCtx->pCurrHttpContext);
            pHttpsClientCtx->pCurrHttpContext = NULL;
        }

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
        if (0 <= pHttpsClientCtx->connectionSSLInstance)
        {
            SSL_closeConnection(pHttpsClientCtx->connectionSSLInstance);
            pHttpsClientCtx->connectionSSLInstance = -1;
        }
#endif

        if (0 != pHttpsClientCtx->serverSocket)
        {
            TCP_CLOSE_SOCKET(pHttpsClientCtx->serverSocket);
            pHttpsClientCtx->serverSocket = 0;
        }
    }
} /* TRUSTEDGE_HTTPS_freeClient */

/*----------------------------------------------------------------------------*/
/* Need to build the message and header. Should be similar to the cURL version.
 * Example:
 * https://virtserver.swaggerhub.com/mocana-iot/NanoUM-dev/1.0.0/device/register
 */

static sbyte4
TRUSTEDGE_HTTPS_UTIL_performHttpRequest(httpContext *pHttpContext)
{
    sbyte4      status = OK;
    sbyte       *tcpBuffer = NULL;
    sbyte       *ptrTcpBuffer = NULL;
    ubyte4      nRet = 0;
    ubyte4      httpStatusCode = 0;
    const ubyte *pStatusPhrase = NULL;
    ubyte4      statusPhraseLen = 0;
    byteBoolean shouldRetry = FALSE;
    sbyte4      retryCount = 1;
    sbyte4      insideRetryCount = 1;
    TCP_SOCKET  serverSocket = 0;
    HttpsClientCtx *pCtx = NULL;

    #define MAX_INSIDE_RETRY (10)

    if (NULL == pHttpContext)
    {
        status = ERR_NULL_POINTER;
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    status = HTTP_getCookie(pHttpContext, (void **) &pCtx);

    if (OK != status || NULL == pCtx)
    {
        if( NULL == pCtx)
        {
            status = ERR_NULL_POINTER;
        }
        MSG_LOG_print(MSG_LOG_ERROR,
            "%s line %d status: %d = %s\n",
            __func__, __LINE__, status,
            MERROR_lookUpErrorCode(status));
        goto exit;
    }

    HTTP_CONTEXT_getSocket(pHttpContext, &serverSocket);

    MSG_LOG_print(MSG_LOG_INFO,
                   "%s", "TRUSTEDGE_HTTPS_UTIL_performHttpRequest\n");

    status = DIGI_CALLOC((void **)&tcpBuffer, 1, DIGI_TRUSTEDGE_TCP_BUFFER_SIZE);
    if (OK != status)
    {
        goto exit;
    }

    /* Preserve the original pointer */
    ptrTcpBuffer = tcpBuffer;

    do
    {
        shouldRetry = FALSE;
        status = TRUSTEDGE_HTTPS_UTIL_prepareHeaderRequest(pCtx, pHttpContext);
        if (OK != status)
        {
            MSG_LOG_print(MSG_LOG_ERROR,
                    "%s line %d status: %d = %s\n",
                    __func__, __LINE__, status,
                    MERROR_lookUpErrorCode(status));
            goto exit;
        }

        status = HTTP_recv(pHttpContext, NULL, 0);
        if (OK > status)
        {
            if (status == ERR_TCP_WRITE_ERROR)
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
                status = TRUSTEDGE_HTTPS_UTIL_recoverFromSSLSocketError(pHttpContext, pCtx);
#else
                TRUSTEDGE_HTTPS_UTIL_recoverFromTCPSocketError(pHttpContext,
                            pCtx->serverIPAddress, pCtx->serverPort);
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */
                shouldRetry = TRUE;
                continue;
            }
            else
            {
                goto exit;
            }
        }

        /* finish sending the request via transport... */
        while (FALSE == HTTP_CLIENT_PROCESS_isDoneSendingRequest(pHttpContext))
        {
            MSG_LOG_print(MSG_LOG_VERBOSE,
                 "%s", "HTTP_CLIENT_PROCESS_isDoneSendingRequest returned 'False'\n");
            if (OK > (status = HTTP_continue(pHttpContext)))
            {
                MSG_LOG_print(MSG_LOG_ERROR,
                               "%s line %d status: %d = %s\n",
                               __func__, __LINE__, status, MERROR_lookUpErrorCode(status));
                goto exit;
            }
        }

        MSG_LOG_print(MSG_LOG_VERBOSE,
                       "%s", "HTTP_CLIENT_PROCESS_isDoneSendingRequest is done\n");

        insideRetryCount = MAX_INSIDE_RETRY;
        while (0 < insideRetryCount && (FALSE == pCtx->httpKillClient))
        {

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
            status = TRUSTEDGE_HTTPS_UTIL_receiveFromSSLSocket(
                pCtx->connectionSSLInstance,
                tcpBuffer, DIGI_TRUSTEDGE_TCP_BUFFER_SIZE, &nRet,
                TRUSTEDGE_HTTPS_UTIL_getLowestHttpTimeout(pCtx)*1000);

            MSG_LOG_print(MSG_LOG_VERBOSE,
                       "TRUSTEDGE_HTTPS_UTIL_receiveFromSSLSocket status: %d = %s\n",status, MERROR_lookUpErrorCode(status));
#else
            status = TRUSTEDGE_HTTPS_UTIL_receiveFromTCPSocket(serverSocket,
                tcpBuffer, DIGI_TRUSTEDGE_TCP_BUFFER_SIZE, &nRet,
                TRUSTEDGE_HTTPS_UTIL_getLowestHttpTimeout(pCtx)*1000);
            MSG_LOG_print(MSG_LOG_VERBOSE,
                    "RX from tcp - stat = %d\n",
                    status, MERROR_lookUpErrorCode(status));
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */

            if (status != OK)
            {
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
                TRUSTEDGE_HTTPS_UTIL_recoverFromSSLSocketError(pHttpContext, pCtx);
#else
                TRUSTEDGE_HTTPS_UTIL_recoverFromTCPSocketError(pHttpContext,
                    pCtx->serverIPAddress, pCtx->serverPort);
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */
                shouldRetry = TRUE;
                insideRetryCount = insideRetryCount - 1;
                /* AHW: This seem WRONG. 'continue;' instead? */
                break;
            }

            status = HTTP_recv(pHttpContext, (ubyte *)tcpBuffer, nRet);
            if (OK > status)
            {
                if (OK == HTTP_REQUEST_getStatusCode(
                                pHttpContext, &httpStatusCode))
                {
                    if ( (400 == httpStatusCode) || (404 == httpStatusCode) )
                    {
                        pCtx->workerStatus = ERR_TRUSTEDGE_FATAL_CONNECTION_ERROR;
                    }
                    else if ( (406 == httpStatusCode) &&
                              (ERR_TRUSTEDGE_RETRY_NO_DELAY != pCtx->workerStatus) )
                    {
                        pCtx->workerStatus = ERR_TRUSTEDGE_FATAL_CONNECTION_ERROR;
                    }
                }
                MSG_LOG_print(MSG_LOG_ERROR,
                        "%s line %d status: %d = %s\n",
                        __func__, __LINE__, status,
                        MERROR_lookUpErrorCode(status));
                goto exit;
            }

            /* Custom messages are handled after HTTP_recv call. Checking for
             * client state and HTTP_DONE handles both chunked and non-chunked
             * encodings and ensures the full message is recieved. */
            if ( (TRUSTEDGE_MSG_CUSTOM == pCtx->requestMsgType) &&
                 (HTTP_DONE == status) &&
                 (finishedClientHttpState == HTTP_CLIENT_STATE(pHttpContext)) )
            {
                MSG_LOG_print(MSG_LOG_VERBOSE,
                                "%s", "Process response for custom message\n");

                status = ERR_NULL_POINTER;
                if (NULL != pCtx->responseParse)
                {
                    status = pCtx->responseParse(pCtx);
                }

                /* This file has been consumed in responseParse and is no longer needed. */
                FMGMT_remove(pCtx->responseBodyTempFileName, FALSE);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                            "%s line %d status: %d = %s\n",
                            __func__, __LINE__, status,
                            MERROR_lookUpErrorCode(status));
                    goto exit;
                }
            }

            status = HTTP_REQUEST_getStatusCode (pHttpContext, &httpStatusCode);
            if (OK != status)
              goto exit;

            /* Do not attempt to retry if we are a disabled device, or the URL
             * is invalid */
            if ( (403 == httpStatusCode) || (404 == httpStatusCode) )
            {
                shouldRetry = FALSE;
                insideRetryCount = 0;
                retryCount = 0;
            }

            if (HTTP_CLIENT_STATE(pHttpContext) == finishedClientHttpState)
            {
                if (OK == (status = HTTP_REQUEST_getStatusCode(pHttpContext,
                                                         &httpStatusCode)))
                {
                    if (OK == (status = HTTP_REQUEST_getStatusPhrase(
                              pHttpContext, &pStatusPhrase, &statusPhraseLen)))
                    {

                        if (httpStatusCode == 401)
                        {
                            ubyte4 index;
                            ubyte* pAuthStr = NULL;
                            ubyte4 authStrLen = 0;

                            (void) HTTP_CONTEXT_resetContext(pHttpContext);

                            /* set authorization string if appropriate */
                            if (authStrLen > 0)
                            {
                                if (OK > (status = HTTP_COMMON_setHeaderIfNotSet(
                                                   pHttpContext, index, pAuthStr,
                                                   authStrLen)))
                                {
                                    MSG_LOG_print(MSG_LOG_ERROR,
                                            "%s line %d status: %d = %s\n",
                                            __func__, __LINE__, status,
                                            MERROR_lookUpErrorCode(status));
                                    goto exit;
                                }
                            }
                        }
                    }
                    else
                    {
                        MSG_LOG_print(MSG_LOG_VERBOSE,
                                       "%s", "No passphrase returned\n");
                    }
                }
                break;
            }
            else
            {
                status = HTTP_REQUEST_getStatusCode(pHttpContext, &httpStatusCode);
                if (OK != status)
                {
                    MSG_LOG_print(MSG_LOG_ERROR,
                                   "%s line %d status: %d = %s\n",
                                   __func__, __LINE__, status,
                                   MERROR_lookUpErrorCode(status));
                    goto exit;
                }
            }
        }
        retryCount = retryCount - 1;
    } while ( (TRUE == shouldRetry) && (0 < retryCount) );

exit:

    /* No need to free tcpBuffer since ptrTcpBuffer shares the pointer */
    DIGI_FREE((void **)&ptrTcpBuffer);
    return status;
}

/*-----------------------------------------------------------------------------*/
void
TRUSTEDGE_HTTPS_UTIL_resetFuncPtrs()
{
#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
    SSL_sslSettings()->funcPtrAlertCallback = myAlertCallback;
#endif

#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
    SSL_sslSettings()->funcPtrCertStatusCallback = myCertStatusCallback;
#endif

    HTTP_httpSettings()->funcPtrHttpTcpSend   = TRUSTEDGE_HTTPS_UTIL_HttpTcpSend;
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
    HTTP_httpSettings()->funcPtrHttpTcpSend   = TRUSTEDGE_HTTPS_UTIL_HttpSslSend;
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */

    HTTP_httpSettings()->funcPtrResponseHeaderCallback =
                                       TRUSTEDGE_HTTPS_UTIL_responseHeaderCallback;
    HTTP_httpSettings()->funcPtrResponseBodyCallback =
                                       TRUSTEDGE_HTTPS_UTIL_responseBodyCallback;
    HTTP_httpSettings()->funcPtrPasswordPrompt = TRUSTEDGE_HTTPS_UTIL_passwordPrompt;
    HTTP_httpSettings()->funcPtrRequestBodyCallback =
                                       TRUSTEDGE_HTTPS_UTIL_requestBodyCallBack;
}

/*-----------------------------------------------------------------------------*/
MSTATUS
TRUSTEDGE_HTTPS_UTIL_start(HttpsClientCtx *pHttpsClientCtx)
{
    MSTATUS status = OK;

    MSG_LOG_print(MSG_LOG_VERBOSE,
                   "%s", "============== Start HTTPS ==============\n");

    if (NULL == pHttpsClientCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = HTTP_init()))
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)

    if (OK > (status = SSL_init(MAX_NTRUSTEDGE_SSL_SERVER_SESSION, MAX_NTRUSTEDGE_HTTP_CLIENT_SESSIONS)))
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__,
                status, MERROR_lookUpErrorCode(status));
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_SSL_ALERTS__
    SSL_sslSettings()->funcPtrAlertCallback = myAlertCallback;
#endif

#ifdef __ENABLE_DIGICERT_OCSP_CLIENT__
    SSL_sslSettings()->funcPtrCertStatusCallback = myCertStatusCallback;
#endif

#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */

    if (OK > (status = HTTP_initClient(MAX_NTRUSTEDGE_HTTP_CLIENT_SESSIONS)))
    {
        MSG_LOG_print(MSG_LOG_ERROR,
                "%s line %d status: %d = %s\n",
                __func__, __LINE__, status,
                MERROR_lookUpErrorCode(status));
        goto exit;
    }

    HTTP_httpSettings()->funcPtrHttpTcpSend   = TRUSTEDGE_HTTPS_UTIL_HttpTcpSend;
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
    HTTP_httpSettings()->funcPtrHttpTcpSend   = TRUSTEDGE_HTTPS_UTIL_HttpSslSend;
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */

    HTTP_httpSettings()->funcPtrResponseHeaderCallback =
                                       TRUSTEDGE_HTTPS_UTIL_responseHeaderCallback;
    HTTP_httpSettings()->funcPtrResponseBodyCallback =
                                       TRUSTEDGE_HTTPS_UTIL_responseBodyCallback;
    HTTP_httpSettings()->funcPtrPasswordPrompt = TRUSTEDGE_HTTPS_UTIL_passwordPrompt;
    HTTP_httpSettings()->funcPtrRequestBodyCallback =
                                       TRUSTEDGE_HTTPS_UTIL_requestBodyCallBack;

    MSG_LOG_print(MSG_LOG_INFO,
                   "pHttpsClientCtx->serverAddress    = %s\n",
                   pHttpsClientCtx->serverAddress);
    MSG_LOG_print(MSG_LOG_INFO,
                   "pHttpsClientCtx->serverPort       = %d\n",
                   pHttpsClientCtx->serverPort);
    MSG_LOG_print(MSG_LOG_INFO,
                   "pHttpsClientCtx->requestMsgLen    = %d\n",
                   pHttpsClientCtx->requestMsgLen);
exit:
    return status;
}

/*-------------------------------------------------------------------------*/
MSTATUS
TRUSTEDGE_HTTPS_UTIL_stop(HttpsClientCtx *pHttpsClientCtx)
{
    MSTATUS status = OK;
    MOC_UNUSED(pHttpsClientCtx);
    MSG_LOG_print(MSG_LOG_VERBOSE,
                   "%s", "============== Stop  HTTPS ==============\n");
    HTTP_stop();
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
#ifndef __DISABLE_MOCANA_STACK_SHUTDOWN__
    SSL_shutdownStack();
#endif
#endif
    return status;
}
