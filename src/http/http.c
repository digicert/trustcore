/*
 * http.c
 *
 * HTTP Methods
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

/*! \file http.c HTTP API.
This file contains HTTP API functions.

\since 2.02
\version 5.3 and later

! Flags
To build products using this header file, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$
- $__ENABLE_DIGICERT_HTTPCC_SERVER__$

Whether the following flags are defined determines which additional header files are included:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$
- $__ENABLE_DIGICERT_HTTPCC_SERVER__$

! External Functions
This file contains the following public ($extern$) functions:
- HTTP_close
- HTTP_connect
- HTTP_continue
- HTTP_getCookie
- HTTP_httpSettings
- HTTP_init
- HTTP_isDone
- HTTP_recv
- HTTP_setCookie

*/

#include "../common/moptions.h"

/* For host lookup */
#ifdef __ENABLE_DIGICERT_HTTP_CLIENT__
#if (defined(__RTOS_LINUX__) || defined(__RTOS_VXWORKS__) || defined(__RTOS_OSX__) || defined(__FREERTOS_SIMULATOR__) || defined(__RTOS_FREERTOS_ESP32__) || defined(__RTOS_QNX__))
#if defined(__RTOS_ZEPHYR__)
#include <zephyr/net/socket.h>
#include <zephyr/posix/unistd.h>
#include <zephyr/posix/sys/ioctl.h>
#include <zephyr/posix/sys/select.h>
#else
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#endif /*__RTOS_ZEPHYR__*/

#elif defined(__RTOS_FREERTOS__)
#include <netdb.h>
#endif
#if defined(__RTOS_WIN32__)
#include <winsock2.h>
#include <WS2tcpip.h>
#pragma comment(lib,"Ws2_32.lib")
#endif
#endif

#if (defined(__ENABLE_DIGICERT_HTTP_CLIENT__) || defined(__ENABLE_DIGICERT_HTTPCC_SERVER__))

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mocana.h"
#include "../common/mtcp.h"

#ifdef __ENABLE_DIGICERT_HTTP_PROXY__
#include "../common/base64.h"
#include "../common/uri.h"
#include "../crypto/cert_store.h"
#include "../ssl/ssl.h"
#endif

#include "../http/http_context.h"
#include "../http/http_common.h"
#include "../http/http.h"
#ifdef __ENABLE_DIGICERT_HTTPCC_SERVER__
#include "../http/server/http_process.h"
#endif
#ifdef __ENABLE_DIGICERT_HTTP_CLIENT__

#include <string.h>
#include "../http/client/http_client_process.h"
#include "../http/client/http_request.h"
#endif

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_HTTP_PROXY__

typedef enum
{
    PROXY_HTTP,
    PROXY_HTTPS
} proxyScheme;

typedef struct
{
    proxyScheme scheme;
    ubyte *pEncodedUserInfo;
    ubyte4 encodedUserInfoLen;
    sbyte *pHost;
    sbyte *pIp;
    ubyte2 port;
} proxySettings;

#ifndef HTTP_DEFAULT_PROXY_PORT
#define HTTP_DEFAULT_PROXY_PORT 3128
#endif

#define HTTP_BASIC_STR          "Basic"

static proxySettings *gpProxy = NULL;

#endif

static httpSettings mHttpSettings;

/*------------------------------------------------------------------*/

/*! Initialize HTTP Client/Server internal structures.
This function initializes HTTP Client/Server internal structures. Your
application should call this function before staring the HTTPS and application
servers.

\since 2.45
\version 5.3 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$
- $__ENABLE_DIGICERT_HTTPCC_SERVER__$

@inc_file http.h

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
HTTP_init(void)
{
    MSTATUS status = OK;

#ifndef __DISABLE_DIGICERT_INIT__
    gMocanaAppsRunning++;
#endif

    status = DIGI_MEMSET((ubyte *)(&mHttpSettings), 0x00, sizeof(httpSettings));

    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
HTTP_stop(void)
{
#ifndef __DISABLE_DIGICERT_INIT__
    gMocanaAppsRunning--;
#endif

    return (sbyte4)OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
HTTP_initClient(sbyte4 numClientConnections)
{
    return (sbyte4)OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
HTTP_initServer(sbyte4 numServerConnections)
{
    return (sbyte4)OK;
}


/*------------------------------------------------------------------*/

/*! Create and initialize an HTTP connection context.
This function creates a connection context for an HTTP request-response
pair.

\since 2.45
\version 2.45 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$
- $__ENABLE_DIGICERT_HTTPCC_SERVER__$

@inc_file http.h

\param ppRetHttpContext     On return, pointer to new connection context handle.
\param serverSocket         Socket on which to communicate with the server.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
HTTP_connect(httpContext **ppRetHttpContext, TCP_SOCKET serverSocket)
{
    httpContext*    pHttpContext = NULL;
    MSTATUS         status = OK;
#ifdef __ENABLE_DIGICERT_HTTP_CLIENT__
    if (NULL == ppRetHttpContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppRetHttpContext = NULL;

    if (OK > (status = HTTP_CONTEXT_createContext(&pHttpContext, HTTP_CLIENT)))
        goto exit;

    if (OK > (status = HTTP_CLIENT_PROCESS_initProcess(pHttpContext)))
        goto exit;

    pHttpContext->socket = serverSocket;

    *ppRetHttpContext = pHttpContext;
    pHttpContext      = NULL;

exit:
    if (NULL != pHttpContext)
        HTTP_CONTEXT_releaseContext(&pHttpContext);
#endif
    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
HTTP_accept(httpContext **ppRetHttpContext, TCP_SOCKET clientSocket)
{
    MSTATUS         status =OK;

#ifdef __ENABLE_DIGICERT_HTTPCC_SERVER__
    httpContext*    pHttpContext = NULL;

    if (NULL == ppRetHttpContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppRetHttpContext = NULL;

    if (OK > (status = HTTP_CONTEXT_createContext(&pHttpContext, HTTP_SERVER)))
        goto exit;

    if (OK > (status = HTTP_PROCESS_initProcess(pHttpContext)))
        goto exit;

    pHttpContext->socket = clientSocket;

    *ppRetHttpContext = pHttpContext;
    pHttpContext      = NULL;

exit:
    if (NULL != pHttpContext)
        HTTP_CONTEXT_releaseContext(&pHttpContext);
#endif
    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

/*! Receive and process a TCP response or forward data to a %client.
This function sends data to, or receives and processes data from,
a connected client/server. The direction of transfer depends on the
current state of the HTTP session. This function should not be called
until an HTTP connection is established between the %client and %server.

\since 2.45
\version 2.45 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$
- $__ENABLE_DIGICERT_HTTPCC_SERVER__$

@inc_file http.h

\param pHttpContext     Pointer to connection context handle previously
returned by HTTP_connect.
\param pData            For receiving a response: pointer to TCP-received data to be
processed; for sending a request: NULL.
\param dataLength       For receiving a response: number of bytes in
received buffer ($pData$); for sending a request: undefined.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
HTTP_recv(httpContext *pHttpContext, ubyte *pData, ubyte4 dataLength)
{
    MSTATUS status = OK;

    if (NULL == pHttpContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (pHttpContext->isBlocked)
    {
        status = ERR_HTTP_BLOCKED;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_HTTPCC_SERVER__
    if (pHttpContext->roleType == HTTP_SERVER)
    {
        status = HTTP_PROCESS_incomingData(pHttpContext, pData, dataLength, FALSE);
    }
#endif
#ifdef __ENABLE_DIGICERT_HTTP_CLIENT__
    if (pHttpContext->roleType == HTTP_CLIENT)
    {
        status = HTTP_CLIENT_PROCESS_receiveResponse(pHttpContext, pData, dataLength, FALSE);
    }
#endif

exit:
    return (sbyte4)status;
}


/*------------------------------------------------------------------*/

/*! Continue a previous HTTP send or receive operation.
This function continues a previous HTTP send or receive operation.

\since 2.45
\version 2.45 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$
- $__ENABLE_DIGICERT_HTTPCC_SERVER__$

@inc_file http.h

\param pHttpContext     Pointer to connection context handle previously
returned by HTTP_connect.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
HTTP_continue(httpContext *pHttpContext)
{
    /* used to continue from a block */
    MSTATUS status = OK;

    if (NULL == pHttpContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pHttpContext->isBlocked = FALSE;

#ifdef __ENABLE_DIGICERT_HTTPCC_SERVER__
    if (pHttpContext->roleType == HTTP_SERVER)
    {
        status = HTTP_PROCESS_incomingData(pHttpContext, NULL, 0, TRUE);
    }
#endif
#ifdef __ENABLE_DIGICERT_HTTP_CLIENT__
    if (pHttpContext->roleType == HTTP_CLIENT)
    {
        status = HTTP_CLIENT_PROCESS_receiveResponse(pHttpContext, NULL, 0, TRUE);
    }
#endif

exit:
    return (sbyte4)status;
}

/*------------------------------------------------------------------*/

/*! Determine whether a connection context's communication is complete.
This function determines whether a given connection context's communication
(request and response pair) is complete.

\since 2.45
\version 2.45 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$
- $__ENABLE_DIGICERT_HTTPCC_SERVER__$

@inc_file http.h

\param pHttpContext     Pointer to connection context handle previously
returned by HTTP_connect.

\return $TRUE$ if communication is complete; otherwise $FALSE$.

*/
extern byteBoolean HTTP_isDone(httpContext *pHttpContext)
{
    if (pHttpContext->roleType == HTTP_SERVER)
    {
        return finishedServerHttpState == HTTP_SERVER_STATE(pHttpContext);
    }
    else
    {
        return finishedClientHttpState == HTTP_CLIENT_STATE(pHttpContext);
    }
}

/*------------------------------------------------------------------*/

/*! Close (and release) an HTTP connection context.
This function closes (and releases) an HTTP connection context.

\since 2.45
\version 2.45 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$
- $__ENABLE_DIGICERT_HTTPCC_SERVER__$

@inc_file http.h

\param ppReleaseContext     Pointer to connection context handle previously
returned by HTTP_connect.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
HTTP_close(httpContext **ppReleaseContext)
{
    return (sbyte4)HTTP_CONTEXT_releaseContext(ppReleaseContext);
}


/*------------------------------------------------------------------*/

/*! Get a pointer to current context's configuration settings.
This function returns a pointer to HTTP Client/Server settings that
can be dynamically adjusted during initialization or runtime.

\since 2.45
\version 2.45 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$
- $__ENABLE_DIGICERT_HTTPCC_SERVER__$

@inc_file http.h

\return Pointer to HTTP Client/Server settings that can be
dynamically adjusted during initialization or runtime.

*/
extern httpSettings*
HTTP_httpSettings(void)
{
    return &mHttpSettings;
}


/*------------------------------------------------------------------*/

/*! Get custom information for a connection context.
This function retrieves custom information stored in the connection context.
Your application should not call this function until after calls to
HTTP_setCookie.

\since 2.45
\version 5.3 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$
- $__ENABLE_DIGICERT_HTTPCC_SERVER__$

@inc_file http.h

\param pHttpContext     Pointer to connection context handle previously
returned by HTTP_connect.
\param pCookie          On return, pointer to the cookie pointer to custom
information.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
HTTP_getCookie(httpContext *pHttpContext, void **pCookie)
{
    MSTATUS status = OK;

    if ((NULL == pHttpContext) || (NULL == pCookie))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pCookie = ((httpContext *)pHttpContext)->httpCookie;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/*! Store custom information for a connection context.
This function stores information about the connection context. Your application
should not call this function until after calling HTTP_connect.

\since 2.45
\version 5.3 and later

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$
- $__ENABLE_DIGICERT_HTTPCC_SERVER__$

@inc_file http.h

\param pHttpContext     Pointer to connection context handle previously
returned by HTTP_connect.
\param cookie           Pointer to custom information (cookie data) to store.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
HTTP_setCookie(httpContext *pHttpContext, void *cookie)
{
    MSTATUS status = OK;

    if (NULL == pHttpContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pHttpContext->httpCookie = cookie;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
HTTP_getUserAccessGroups(httpContext *pHttpContext, sbyte4 *pRetGroupAccess)
{
    MSTATUS status = OK;

    if ((NULL == pHttpContext) || (NULL == pRetGroupAccess))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pRetGroupAccess = pHttpContext->groupAccess;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
HTTP_setUserAccessGroups(httpContext *pHttpContext, sbyte4 groupAccess)
{
    MSTATUS status = OK;

    if (NULL == pHttpContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pHttpContext->groupAccess = groupAccess;

exit:
    return status;
}

/*-------------------------------------------------------------------------*/

extern MSTATUS HTTP_getHostIpAddr(sbyte* pHostName, sbyte **ppIpAddr)
{
    MSTATUS status = OK;

#if (defined(__RTOS_LINUX__) || defined(__RTOS_VXWORKS__) || (defined(__RTOS_FREERTOS__) && defined(__LWIP_STACK__)) || defined(__RTOS_OSX__) || defined(__FREERTOS_SIMULATOR__) || defined(__RTOS_QNX__))
    struct addrinfo hints;
    struct addrinfo *info = NULL;
    struct addrinfo *infoAnchor = NULL;
    char *addrstr = NULL;
    void *ptr = NULL;
    sbyte *ip = NULL;

    status = DIGI_CALLOC((void **)&addrstr, 1, 1024);
    if (OK != status)
        goto exit;

    DIGI_MEMSET((ubyte *) &hints, 0, sizeof(struct addrinfo));
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;

    status = getaddrinfo ((const char *)pHostName, NULL, &hints, &info);
    if (OK != status)
    {
        status = ERR_TCP_CONNECT_ERROR;
        goto exit;
    }
    infoAnchor = info;

    /* Currently only taking the first.. while (0 != info) */
    {
        switch (info->ai_family)
        {
            case AF_INET:
                inet_ntop(info->ai_family, (void *)&(((struct sockaddr_in *) info->ai_addr)->sin_addr), addrstr, 100);
                ptr = &((struct sockaddr_in *) info->ai_addr)->sin_addr;
                break;
#ifdef __ENABLE_DIGICERT_IPV6__
            case AF_INET6:
                inet_ntop(info->ai_family, (void *)&(((struct sockaddr_in6 *) info->ai_addr)->sin6_addr), addrstr, 100);
                ptr = &((struct sockaddr_in6 *) info->ai_addr)->sin6_addr;
                break;
#endif
            default:
                status = ERR_TCP;
        }

        if (OK != status)
            goto exit;

        inet_ntop (info->ai_family, ptr, addrstr, 100);

        status = DIGI_CALLOC( (void **)ppIpAddr, 1, DIGI_STRLEN((sbyte *)addrstr) + 1);
        if (OK != status)
        {
            goto exit;
        }

        ip = *ppIpAddr;
        DIGI_MEMCPY(ip, addrstr, DIGI_STRLEN((sbyte *)addrstr));
        ip[DIGI_STRLEN((sbyte *)addrstr)] = '\0';
        info = info->ai_next;
    }
#elif defined (__RTOS_FREERTOS__)
    ubyte4 ulIPAddress = 0;
    char addrstr[100] ;
    sbyte *ip = NULL;
    if( ( *pHostName >= '0' ) && ( *pHostName <= '9' ) )
    {
        ulIPAddress = FreeRTOS_inet_addr( pHostName );
    }
    if(!ulIPAddress)
    {
        ulIPAddress =  FreeRTOS_gethostbyname( (const char *)pHostName );
    }
    if (0 == ulIPAddress)
    {
        status = ERR_TCP_CONNECT_ERROR;
        goto exit;
    }
    FreeRTOS_inet_ntoa ( ulIPAddress, addrstr);

    status = DIGI_CALLOC( (void **)ppIpAddr, 1, DIGI_STRLEN((sbyte *)addrstr) + 1);
    if (OK != status)
    {
        goto exit;
    }

    ip = *ppIpAddr;
    DIGI_MEMCPY(ip, addrstr, DIGI_STRLEN((sbyte *)addrstr));
    ip[DIGI_STRLEN((sbyte *)addrstr)] = '\0';

#elif defined(__RTOS_WIN32__)
    ADDRINFOA Hints, *AddrInfo;
    int       RetVal;
    char *addrstr = NULL;
    void *ptr = NULL;
    sbyte *ip = NULL;

    status = DIGI_CALLOC((void **)&addrstr, 1, 1024);
    if (OK != status)
        goto exit;

    DIGI_MEMSET ((ubyte*)&Hints, 0, sizeof (Hints));

    Hints.ai_family = PF_UNSPEC;
    Hints.ai_socktype = SOCK_STREAM;
    Hints.ai_flags = AI_CANONNAME;

    RetVal = getaddrinfo((const char *)pHostName, NULL, &Hints, &AddrInfo);
    if (RetVal != 0)
    {
        status = ERR_TCP_CONNECT_ERROR;
        return status;
    }

    switch (AddrInfo->ai_family)
    {
        case AF_INET:
            ptr = &((struct sockaddr_in *) AddrInfo->ai_addr)->sin_addr;
            break;
        case AF_INET6:
            ptr = &((struct sockaddr_in6 *) AddrInfo->ai_addr)->sin6_addr;
            break;
        default:
            status = ERR_UM_HTTP_SERVER_ERROR;
            goto exit;
    }

    inet_ntop (AddrInfo->ai_family, ptr, addrstr, 100);

    status = DIGI_CALLOC( (void **)ppIpAddr, 1, DIGI_STRLEN((sbyte *)addrstr) + 1);
    if (OK != status)
    {
        goto exit;
    }

    ip = *ppIpAddr;
    DIGI_MEMCPY (ip, addrstr, DIGI_STRLEN((sbyte *)addrstr));
    ip[DIGI_STRLEN((sbyte *)addrstr)] = '\0';
#elif defined (__RTOS_AZURE__)
    ubyte4 ulIPAddress = 0;
    char addrstr[100] ;
    sbyte *ip = NULL;
    if( ( *pHostName >= '0' ) && ( *pHostName <= '9' ) )
    {
        ulIPAddress = THREADX_inet_addr( pHostName );
    }
    if(!ulIPAddress)
    {
    	THREADX_UDP_getAddressOfHost( (const char *)pHostName, &ulIPAddress);
    }
    if (0 == ulIPAddress)
    {
        status = ERR_TCP_CONNECT_ERROR;
        goto exit;
    }
    THREADX_inet_ntoa ( ulIPAddress, addrstr);

    status = DIGI_CALLOC( (void **)ppIpAddr, 1, DIGI_STRLEN((sbyte *)addrstr) + 1);
    if (OK != status)
    {
        goto exit;
    }

    ip = *ppIpAddr;
    DIGI_MEMCPY(ip, addrstr, DIGI_STRLEN((sbyte *)addrstr));
    ip[DIGI_STRLEN((sbyte *)addrstr)] = '\0';
#else
#error "No implementation for HTTP_getHostIpAddr for this platform"
#endif

exit:
#if (defined(__RTOS_LINUX__) || defined(__RTOS_VXWORKS__) || (defined(__RTOS_FREERTOS__) && defined(__LWIP_STACK__)) || defined(__RTOS_OSX_) || defined(__FREERTOS_SIMULATOR__) || defined(__RTOS_QNX__))
    freeaddrinfo(infoAnchor);
#endif
#if defined(__RTOS_WIN32__)
    freeaddrinfo(AddrInfo);
#endif
#if (defined(__RTOS_LINUX__) || defined(__RTOS_VXWORKS__) || (defined(__RTOS_FREERTOS__) && defined(__LWIP_STACK__)) || defined(__RTOS_WIN32__) || defined(__RTOS_OSX__) || defined(__FREERTOS_SIMULATOR__) || defined(__RTOS_QNX__))
    DIGI_FREE((void **)&addrstr);
#endif

    return status;
}

#ifdef __ENABLE_DIGICERT_HTTP_PROXY__

/*-------------------------------------------------------------------------*/

extern byteBoolean HTTP_PROXY_isProxyUrlSet(void)
{
    if (NULL != gpProxy)
    {
        return TRUE;
    }

    return FALSE;
}

/*-------------------------------------------------------------------------*/

extern MSTATUS HTTP_PROXY_setProxyUrlAndPort(sbyte *pUrl)
{
    MSTATUS status = ERR_NULL_POINTER;
    URI *pUri = NULL;
    sbyte *pScheme = NULL;
    proxyScheme scheme;
    sbyte *pAuthority = NULL;
    sbyte *pIter;
    sbyte4 basicLen;
    sbyte *pUnescaped = NULL;
    ubyte *pEncoded = NULL;
    ubyte4 encodedLen = 0;
    sbyte *pBasicAuth = NULL;
    ubyte4 basicAuthLen = 0;
    sbyte *pHost = NULL;
    sbyte *pIp = NULL;
    proxySettings *pProxy = NULL;
    ubyte2 port;

    if (NULL == pUrl)
        goto exit;

    /* Free existing proxy */
    HTTP_PROXY_freeProxyUrl();

    status = URI_ParseURI(pUrl, &pUri);
    if (OK != status)
        goto exit;

    /* Get proxy scheme */
    status = URI_GetScheme(pUri, &pScheme);
    if (OK != status)
        goto exit;

    if (0 == DIGI_STRCMP((const sbyte *) "http", pScheme))
    {
        scheme = PROXY_HTTP;
    }
    else if (0 == DIGI_STRCMP((const sbyte *) "https", pScheme))
    {
        scheme = PROXY_HTTPS;
    }
    else
    {
        status = ERR_HTTP_PROXY_INVALID_SCHEME;
        goto exit;
    }

    /* Get proxy username and password */
    status = URI_GetAuthority(pUri, &pAuthority);
    if (OK != status)
        goto exit;

    if (NULL != pAuthority)
    {
        pIter = DIGI_STRCHR(pAuthority, '@', DIGI_STRLEN(pAuthority));
        if (NULL != pIter)
        {
            /* Unescape the user and password */
            status = URI_Unescape(pAuthority, pIter - pAuthority, &pUnescaped);
            if (OK != status)
                goto exit;

            /* Found '@' seperator, encode the username/password for HTTP basic
             * authentication */
            status = BASE64_encodeMessage(
                pUnescaped, DIGI_STRLEN(pUnescaped), &pEncoded, &encodedLen);
            if (OK != status)
                goto exit;

            basicLen = DIGI_STRLEN(HTTP_BASIC_STR);

            /* "Basic" + " " + Base64 encoded username and password */
            status = DIGI_MALLOC((void **) &pBasicAuth, basicLen + 1 + encodedLen);
            if (OK != status)
                goto exit;

            DIGI_MEMCPY(pBasicAuth, HTTP_BASIC_STR, basicLen);
            DIGI_MEMCPY(pBasicAuth + basicLen, (const void *) " ", 1);
            DIGI_MEMCPY(pBasicAuth + basicLen + 1, pEncoded, encodedLen);
            basicAuthLen = basicLen + 1 + encodedLen;
        }
    }

    /* Get proxy host */
    status = URI_GetHost(pUri, &pHost);
    if (OK != status)
        goto exit;

    /* Convert proxy host to IP */
    status = HTTP_getHostIpAddr(pHost, &pIp);
    if (OK != status)
        goto exit;

    /* Get proxy port */
    status = URI_GetPort(pUri, &port);
    if (OK != status)
        goto exit;

    /* If proxy port is not provided, use default port */
    if (0 == port)
        port = HTTP_DEFAULT_PROXY_PORT;

    status = DIGI_CALLOC((void **) &pProxy, 1, sizeof(proxySettings));
    if (OK != status)
        goto exit;

    pProxy->scheme = scheme;
    pProxy->pEncodedUserInfo = pBasicAuth;
    pProxy->encodedUserInfoLen = basicAuthLen;
    pBasicAuth = NULL;
    pProxy->pHost = pHost; pHost = NULL;
    pProxy->pIp = pIp; pIp = NULL;
    pProxy->port = port;
    gpProxy = pProxy;

exit:

    /* Error handling for pProxy not required */

    if (NULL != pIp)
        DIGI_FREE((void **) &pIp);

    if (NULL != pHost)
        DIGI_FREE((void **) &pHost);

    if (NULL != pBasicAuth)
        DIGI_FREE((void **) &pBasicAuth);

    if (NULL != pEncoded)
        DIGI_FREE((void **) &pEncoded);

    if (NULL != pUnescaped)
        DIGI_FREE((void **) &pUnescaped);

    if (NULL != pAuthority)
        DIGI_FREE((void **) &pAuthority);

    if (NULL != pScheme)
        DIGI_FREE((void **) &pScheme);

    if (NULL != pUri)
        URI_DELETE(pUri);

    return status;
}

/*-------------------------------------------------------------------------*/

extern MSTATUS HTTP_PROXY_freeProxyUrl(void)
{
    MSTATUS status = OK, fstatus;

    if (NULL != gpProxy)
    {
        if (NULL != gpProxy->pEncodedUserInfo)
        {
            fstatus = DIGI_FREE((void **) &gpProxy->pEncodedUserInfo);
            if (OK == status)
                status = fstatus;
        }

        if (NULL != gpProxy->pHost)
        {
            fstatus = DIGI_FREE((void **) &gpProxy->pHost);
            if (OK == status)
                status = fstatus;
        }

        if (NULL != gpProxy->pIp)
        {
            fstatus = DIGI_FREE((void **) &gpProxy->pIp);
            if (OK == status)
                status = fstatus;
        }

        fstatus = DIGI_FREE((void **) &gpProxy);
        if (OK == status)
            status = fstatus;
    }

    return status;
}

/*-------------------------------------------------------------------------*/

extern sbyte4 SSL_PROXY_send(sbyte4 ssl_id, sbyte *pBuffer, ubyte4 bufferLen, ubyte4 *pRetNumBytesSent)
{
    sbyte4 status = (sbyte4) ERR_NULL_POINTER;

    if (NULL == pRetNumBytesSent)
        goto exit;

    status = SSL_send(ssl_id, pBuffer, (sbyte4) bufferLen);
    if (OK > status)
    {
        *pRetNumBytesSent = 0;
        goto exit;
    }

    *pRetNumBytesSent = (ubyte4) status; status = OK;

exit:

    return status;
}

/*-------------------------------------------------------------------------*/

extern sbyte4 SSL_PROXY_recv(sbyte4 ssl_id, sbyte *pRetBuffer, ubyte4 bufferSize, ubyte4 *pNumBytesReceived, ubyte4 timeout)
{
    return SSL_recv(ssl_id, pRetBuffer, (sbyte4) bufferSize, (sbyte4 *) pNumBytesReceived, timeout);
}

/*-------------------------------------------------------------------------*/

static sbyte4 HTTPS_PROXY_send(httpContext *pHttpContext, TCP_SOCKET socket,
						       ubyte *pDataToSend, ubyte4 numBytesToSend,
						       ubyte4 *pRetNumBytesSent, sbyte4 isContinueFromBlock)
{
    sbyte4 ssl_id = 0;

    MOC_UNUSED(isContinueFromBlock);
    MOC_UNUSED(socket);

    if (NULL == pHttpContext)
        return ERR_NULL_POINTER;

    ssl_id = *((sbyte4 *)(pHttpContext->httpCookie));

    return SSL_PROXY_send(ssl_id, (sbyte *) pDataToSend, numBytesToSend, pRetNumBytesSent);
}

/*-------------------------------------------------------------------------*/

static sbyte4 HTTPS_PROXY_recv(httpContext *pHttpContext, ubyte *pDataReceived, ubyte4 dataLength, ubyte4 *pNumBytesRecv)
{
    sbyte4 ssl_id = 0;

    if (NULL == pHttpContext)
        return ERR_NULL_POINTER;

    ssl_id = *((sbyte4 *)(pHttpContext->httpCookie));

    return SSL_PROXY_recv(ssl_id, (sbyte *) pDataReceived, dataLength, pNumBytesRecv, 5000000);
}

/*-------------------------------------------------------------------------*/

static sbyte4 HTTP_PROXY_HttpTcpSend(httpContext *pHttpContext, TCP_SOCKET socket,
						  ubyte *pDataToSend, ubyte4 numBytesToSend,
						  ubyte4 *pRetNumBytesSent, sbyte4 isContinueFromBlock)
{
    MSTATUS status;
    status = TCP_WRITE(socket, (sbyte *) pDataToSend, numBytesToSend, pRetNumBytesSent);
    return status;
}

/*-------------------------------------------------------------------------*/

/* Proxy Server response doesn't need further action */
static sbyte4 HTTP_PROXY_responseHeaderCallback(httpContext *pHttpContext, sbyte4 isContinueFromBlock)
{
    return 0;
}

/*-------------------------------------------------------------------------*/

/* Proxy Server response doesn't need further action */
static sbyte4 HTTP_PROXY_responseBodyCallback(httpContext *pHttpContext,
                                        ubyte *pDataReceived, ubyte4 dataLength,
                                        sbyte4 isContinueFromBlock)
{
    return 0;
}

/*-------------------------------------------------------------------------*/

extern MSTATUS HTTP_PROXY_connect(sbyte *pUrl, TCP_SOCKET *pServerSocket, TCP_SOCKET *pProxySocket, sbyte4 *pRetSslId, certStorePtr pCertStore)
{
    MSTATUS status = OK;
    httpContext *pHttpContext = NULL;
    ubyte       tcpBuffer[512];
    ubyte4      nRet = 0;
    ubyte4      statusCode = 0;
    httpSettings httpSettingsCopy = {0};
    sbyte4      ssl_id = 0;
   
    /* return before swapping function pointers, on these errors */
    if (NULL == pUrl || NULL == pServerSocket)
        return ERR_NULL_POINTER;

    if (!HTTP_PROXY_isProxyUrlSet())
        return ERR_HTTP_PROXY_URL_NOT_SET;

    if (PROXY_HTTP != gpProxy->scheme && PROXY_HTTPS != gpProxy->scheme)
        return ERR_HTTP_PROXY_INVALID_SCHEME;

    /* copy the old */
    status = DIGI_MEMCPY((ubyte *) &httpSettingsCopy, (ubyte *) HTTP_httpSettings(), sizeof(httpSettings));
    if (OK != status)
        goto exit;

    /* reset */
    status = DIGI_MEMSET((ubyte *) HTTP_httpSettings(), 0x00, sizeof(httpSettings));
    if (OK != status)
        goto exit;

    /* Put in our own, will be either HTTPS or HTTP */
    if (PROXY_HTTPS == gpProxy->scheme)
    {
        HTTP_httpSettings()->funcPtrHttpTcpSend = HTTPS_PROXY_send;
    }
    else
    {
        HTTP_httpSettings()->funcPtrHttpTcpSend = HTTP_PROXY_HttpTcpSend;
    }
    HTTP_httpSettings()->funcPtrResponseHeaderCallback = HTTP_PROXY_responseHeaderCallback;
    HTTP_httpSettings()->funcPtrResponseBodyCallback = HTTP_PROXY_responseBodyCallback;

    /* For HTTP connections, the socket goes directly to the proxy. For HTTPS
     * connections, the socket is created as a virtual socket */
    status = TCP_CONNECT(pServerSocket, gpProxy->pIp, gpProxy->port);
    if (OK != status)
        goto exit;

    if (PROXY_HTTPS == gpProxy->scheme)
    {
        if (NULL == pProxySocket || NULL == pRetSslId)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        /* Create proxy socket */
        status = TCP_CONNECT(pProxySocket, gpProxy->pIp, gpProxy->port);
        if (OK != status)
            goto exit;

        ssl_id = SSL_connect(*pProxySocket, 0, NULL, NULL, gpProxy->pHost, pCertStore);
        if (ssl_id < 0)
        {
            status = (MSTATUS) ssl_id;
            goto exit;
        }
            
        status = SSL_negotiateConnection(ssl_id);
        if (OK != status)
            goto exit;

        /* For HTTPS the return socket will be a virtual socket */
        status = HTTP_connect(&pHttpContext, *pProxySocket);
        if (OK != status)
            goto exit;
    }
    else
    {
        /* For HTTP the return socket will go directly to the proxy */
        status = HTTP_connect(&pHttpContext, *pServerSocket);
        if (OK != status)
            goto exit;
    }

    if (PROXY_HTTPS == gpProxy->scheme)
    {
        pHttpContext->httpCookie = (void *) &ssl_id;
    }

    status = HTTP_REQUEST_setRequestMethodIfNotSet(pHttpContext, &mHttpMethods[CONNECT]);
    if (OK != status)
        goto exit;

    /* Set basic auth header if found */
    if (NULL != gpProxy->pEncodedUserInfo)
    {
        status = HTTP_COMMON_setHeaderIfNotSet(
            pHttpContext, ProxyAuthorization, gpProxy->pEncodedUserInfo,
            gpProxy->encodedUserInfoLen);
        if (OK != status)
            goto exit;
    }

    status = HTTP_REQUEST_setRequestUriIfNotSet(pHttpContext, pUrl);
    if (OK != status)
        goto exit;

    /* 11 is for `HOST: ` */
    status = HTTP_COMMON_setHeaderIfNotSet(pHttpContext, 11, (ubyte *) pUrl, DIGI_STRLEN(pUrl));
    if (OK != status)
        goto exit;

    status = HTTP_recv(pHttpContext, NULL, 0);
    if (OK != status)
        goto exit;

    if (PROXY_HTTPS == gpProxy->scheme)
    {
        status = HTTPS_PROXY_recv(pHttpContext, tcpBuffer, 512, &nRet);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = TCP_READ_AVL(pHttpContext->socket, (sbyte *) tcpBuffer, 512, &nRet, 5000000);
        if (status != OK)
            goto exit;
    }
          
    status = HTTP_recv(pHttpContext, tcpBuffer, nRet);
    if (OK != status)
        goto exit;

    status = HTTP_REQUEST_getStatusCode(pHttpContext, &statusCode);
    if (OK != status)
        goto exit;

    switch (statusCode)
    {
        case 200:
            break;

        case 407:
            status = ERR_HTTP_PROXY_AUTHENTICATION_REQUIRED;
            goto exit;

        default:
            status = ERR_HTTP_PROXY_RESPONSE;
            goto exit;
    }

    if (PROXY_HTTPS == gpProxy->scheme && NULL != pRetSslId)
    {
        *pRetSslId = ssl_id; ssl_id = 0;
    }

exit:

    /* copy back in the old */
    (void) DIGI_MEMCPY((ubyte *) HTTP_httpSettings(), (ubyte *) &httpSettingsCopy, sizeof(httpSettings));

    if (0 < ssl_id)
    {
        (void) SSL_closeConnection(ssl_id);
    }

    if (NULL != pHttpContext)
    {
        (void) HTTP_close(&pHttpContext);
    }

    if (OK != status) /* pSocketServer can't be NULL */
    {
        if (NULL != pProxySocket)
            (void) TCP_CLOSE_SOCKET(*pProxySocket);

        (void) TCP_CLOSE_SOCKET(*pServerSocket);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_HTTP_PROXY__ */
#endif /* (defined(__ENABLE_DIGICERT_HTTP_CLIENT__) || defined(__ENABLE_DIGICERT_HTTPCC_SERVER__)) */
