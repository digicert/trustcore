/*
 * http.h
 *
 * HTTP Header File
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

/*! \file http.h HTTP developer API header.
This header file contains definitions, structures, and function declarations
used by SCEP %client and server API functions to transport the messages.

\since 2.02
\version 5.3 and later

! Flags
There are no flag dependencies in this file.

*/

/*------------------------------------------------------------------*/

#ifndef __HTTP_HEADER__
#define __HTTP_HEADER__

#include "../common/mtcp.h"
#include "../crypto/cert_store.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HTTP_OK                         (0)
#define HTTP_BLOCK                      (1)
#define HTTP_DONE                       (2)

#define HTTP_DEFAULT_TCPIP_PORT         (80)

/*------------------------------------------------------------------*/

struct hashTableOfPtrs;

/* resource service providers need only to implement and register the following */
/*!
\exclude
*/
typedef MSTATUS (* httpResouceFetcher) (httpContext *pHttpContext, ubyte **ppDataToSend, ubyte4 *pDataToSendLength);

/*!
\exclude
*/
typedef MSTATUS (* httpReleaseResource) (resDescr *pResourceDescr);

/* ywang: isContinueFromBlock is passed-in value, is this correct? */
/*! Configuration settings and callback function pointers for HTTP clients and servers.
This structure is used for HTTP %client and server configuration. Which products and
features you've included (by defining the appropriate flags in moptions.h)
determine which data fields are present in this structure.

Each included callback function should be customized for your application and
then registered by assigning it to the appropriate structure function pointer(s).

\since 2.02
\version 2.45 and later

! Flags
There are no flag dependencies to use this structure. Some portions of this
structure are dependent on whether the $__ENABLE_DIGICERT_HTTPCC_SERVER__$ flag
is defined in moptions.h.

*/
typedef struct
{
/*! Send a message to a SCEP server or %client.
This callback function sends a message via TCP to a SCEP server or %client.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

\since 2.45
\version 2.45 and later

! Flags
There are no flag dependencies to use this callback function.

\param pHttpContext         Pointer to context describing current HTTP
session (request-response pair).
\param socket               TCP socket on which to receive SCEP server/%client
communication.
\param pDataToSend          Pointer to data to send buffer.
\param numBytesToSend       Number of bytes in send buffer ($pDataToSend$).
\param pRetNumBytesSent     On return, pointer to number of bytes sent (transmitted).
\param isContinueFromBlock  $TRUE$ if the HTTP session was previously blocked:
for example, if TCP $send()$ could not complete, if waiting for authentication,
or application-specific requirements; otherwise $FALSE$. Typically this argument
can be ignored, but it may be a useful indicator in threadless environments.

\return $OK$ (0) if successful; otherwise a negative number
error code definition from merrors.h. To retrieve a string containing an
English text error identifier corresponding to the function's returned error
status, use the $DISPLAY_ERROR$ macro.

*/
    sbyte4 (*funcPtrHttpTcpSend) (httpContext *pHttpContext, TCP_SOCKET socket, ubyte *pDataToSend, ubyte4 numBytesToSend, ubyte4 *pRetNumBytesSent, sbyte4 isContinueFromBlock);

/*! Get an HTTP user's stored password or password hash.
This callback function gets an HTTP user's stored password or password
hash. After calling this function, the HTTP server can use the retrieved
password (or password hash) to authenticate the user and authorize resource
release.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

\since 2.45
\version 2.45 and later

! Flags
There are no flag dependencies to use this callback function.

\note The corresponding %client function is httpSettings::funcPtrPasswordPrompt.

\param pHttpContext Pointer to context describing current HTTP session (request-response pair).
\param pUser        Pointer to username to authenticate.
\param userLength   Number of bytes in username ($pUser$).
\param pRealm       Pointer to identifier (such as "internal" or "external")
that together with the absolute URI of the HTTP server whose $abs_path$ is empty,
represents the protection domain of the resource concerned.
\param realmLength  Number of bytes in realm identifier ($pRealm$).
\param pScheme      Pointer to authentication scheme: any of the
$httpAuthScheme$ enumerated values (see http_auth.h).
\param ppPassword   Pointer, which on return contains a pointer to the
stored user password.
\param pPasswordLength  On return, pointer to length of the retrieved
password ($ppPassword$).
\param pIsHA1           On return, pointer to $TRUE$ if the retrieved
password points to an HA1 value (as defined in RFC&nbsp;2617); otherwise, pointer
to $FALSE$.
\param isContinueFromBlock  $TRUE$ if the HTTP session was previously blocked:
for example, if TCP $send()$ could not complete, if waiting for authentication,
or application-specific requirements; otherwise $FALSE$. Typically this argument
can be ignored, but it may be a useful indicator in threadless environments.

\return $OK$ (0) if successful; otherwise a negative number
error code definition from merrors.h. To retrieve a string containing an
English text error identifier corresponding to the function's returned error
status, use the $DISPLAY_ERROR$ macro.

*/
    sbyte4 (*funcPtrPasswordAuth)(httpContext *pHttpContext, const ubyte *pUser, ubyte4 userLength, ubyte *pRealm, ubyte4 realmLength, ubyte4 *pScheme, ubyte **ppPassword, ubyte4 *pPasswordLength, intBoolean *pIsHA1, sbyte4 isContinueFromBlock);

/*! Get an HTTP user's password.
This callback function gets an HTTP user's password. After calling this function,
the HTTP %client can send the password in response to a server-issued challenge.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer. Your custom function can prompt the user for the password if
necessary.

\since 2.45
\version 2.45 and later

! Flags
There are no flag dependencies to use this callback function.

\note The corresponding %server function is httpSettings::funcPtrPasswordAuth.

\param pHttpContext         Pointer to context describing current HTTP session (request-response pair).
\param pChallenge           Pointer to challenge phrase sent by the server.
\param chellengeLength      Number of bytes in challenge phrase.
\param ppUser               Pointer, which on return contains a pointer to the user ID.
\param pUserLength          On return, pointer to number of bytes in user ID ($ppUser$).
\param ppPassword           Pointer, which on return contains a pointer to the SCEP %client-provided password.
\param pPasswordLength      On return, pointer to length of returned password ($ppPassword$).
\param isContinueFromBlock  $TRUE$ if the HTTP session was previously blocked:
for example, if TCP $send()$ could not complete, if waiting for authentication,
or application-specific requirements; otherwise $FALSE$. Typically this argument
can be ignored, but it may be a useful indicator in threadless environments.

\return $OK$ (0) if successful; otherwise a negative number
error code definition from merrors.h. To retrieve a string containing an
English text error identifier corresponding to the function's returned error
status, use the $DISPLAY_ERROR$ macro.

*/
    sbyte4 (*funcPtrPasswordPrompt)(httpContext *pHttpContext, const ubyte* pChallenge, ubyte4 challengeLength, ubyte **ppUser, ubyte4* pUserLength, ubyte **ppPassword, ubyte4 *pPasswordLength, sbyte4 isContinueFromBlock);

/*! Get a challenge to send to the HTTP %client.
This server callback function returns a challenge to the HTTP server for it
to send to the HTTP %client. The challenge is returned as part of the
response's $Authenticate$ header (and the status code will be 401, indicating
that authentication is required before the resource can be returned).

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

\since 2.45
\version 2.45 and later

! Flags
There are no flag dependencies to use this callback function.

\param pHttpContext     Pointer to context describing current
HTTP session (request-response pair).
\param pScheme          Pointer to authentication scheme: any of the
$httpAuthScheme$ enumerated values (see http_auth.h).
\param ppRealm          Reference to realm (protection space defined on
the HTTP server for the resources to be accessed) in which the resource of concern
is located.
\param pRealmLen        On return, number of bytes in the realm
identifier ($ppRealm$).
\param ppDomain         (Ignored for basic authentication) Space-separated
list of URIs that define the protection space.
\param pDomainLen       (Ignored for basic authentication) On return,
pointer to number of bytes in the domain ($ppDomain$).
\param ppOpaque         (Ignored for basic authentication) Pointer to
server implementation-specific data (opaque to the %client).
\param pOpaqueLen       (Ignored for basic authentication) On return,
pointer to length of opaque data ($ppOpaque$).

\return $OK$ (0) if successful; otherwise a negative number
error code definition from merrors.h. To retrieve a string containing an
English text error identifier corresponding to the function's returned error
status, use the $DISPLAY_ERROR$ macro.

*/
    sbyte4 (*funcPtrAuthChallenge) (httpContext *pHttpContext, ubyte4 *pScheme, ubyte **ppRealm, ubyte4 *pRealmLen,
                                              ubyte** ppDomain, ubyte4 *pDomainLen, ubyte** ppOpaque, ubyte4 *pOpaqueLen);

/*! Retrieve the body of a request made by an HTTP application.
This callback function gets the body of a request made by an
HTTP application.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

\since 2.45
\version 2.45 and later

! Flags
There are no flag dependencies to use this callback function.

\param pHttpContext         Pointer to context describing current HTTP
session (request-response pair).
\param ppDataToSend         Pointer, which on return contains a pointer to data to send (the HTTP request body).
\param pDataLength          On return, pointer to number of bytes in send buffer ($ppDataToSend$).
\param pRequestBodyCookie   On return, opaque cookie that points to context
information such as bookkeeping or caching data.

\return $OK$ (0) if successful; otherwise a negative number
error code definition from merrors.h. To retrieve a string containing an
English text error identifier corresponding to the function's returned error
status, use the $DISPLAY_ERROR$ macro.

*/
    sbyte4 (*funcPtrRequestBodyCallback) (httpContext *pHttpContext, ubyte **ppDataToSend, ubyte4 *pDataLength, void *pRequestBodyCookie);

/*! Retrieve response header after it has been received from the server and processed.
This callback function (used by the HTTP %client) retrieves a response header
after it has been received from the server and processed.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

\since 2.45
\version 2.45 and later

! Flags
There are no flag dependencies to use this callback function.

\param pHttpContext         Pointer to context describing current HTTP
session (request-response pair).
\param isContinueFromBlock  $TRUE$ if the HTTP session was previously blocked:
for example, if TCP $send()$ could not complete, if waiting for authentication,
or application-specific requirements; otherwise $FALSE$. Typically this argument
can be ignored, but it may be a useful indicator in threadless environments.

\return $OK$ (0) if successful; otherwise a negative number
error code definition from merrors.h. To retrieve a string containing an
English text error identifier corresponding to the function's returned error
status, use the $DISPLAY_ERROR$ macro.

*/
    sbyte4 (*funcPtrResponseHeaderCallback)(httpContext *pHttpContext, sbyte4 isContinueFromBlock);

/*! Retrieve response body from the HTTP %client (for forwarding to the application).
This callback function (used by the HTTP %client) retrieves a response body
after HTTP receives the response from the server and parses it. The response
body can then be forwarded to the application.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

\since 2.45
\version 2.45 and later

! Flags
There are no flag dependencies to use this callback function.

\param pHttpContext         Pointer to context describing current HTTP
session (request-response pair).
\param pDataReceived        Pointer to the response body received.
\param dataLength           Number of bytes in the response body ($pDataReceived$).
\param isContinueFromBlock  $TRUE$ if the HTTP session was previously blocked:
for example, if TCP $send()$ could not complete, if waiting for authentication,
or application-specific requirements; otherwise $FALSE$. Typically this argument
can be ignored, but it may be a useful indicator in threadless environments.

\return $OK$ (0) if successful; otherwise a negative number
error code definition from merrors.h. To retrieve a string containing an
English text error identifier corresponding to the function's returned error
status, use the $DISPLAY_ERROR$ macro.

*/
    sbyte4 (*funcPtrResponseBodyCallback)(httpContext *pHttpContext, ubyte *pDataReceived, ubyte4 dataLength, sbyte4 isContinueFromBlock);

#ifdef __ENABLE_DIGICERT_HTTPCC_SERVER__
/*! Post a request body or retrieve a response body.
This callback function is part of the HTTP server's resource manager. The HTTP
server calls this function to post a request body (fetch a resource to be sent to
the HTTP %client) or to retrieve a response body.

Callback registration happens at session creation and initialization by
assigning your custom callback function (which can have any name) to this
callback pointer.

\since 2.45
\version 2.45 and later

! Flags
To use this callback, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTPCC_SERVER__$

\param pHttpContext     Pointer to context describing current HTTP
session (request-response pair).
\param ppDataToSend     Pointer, which on return contains a pointer to
the request or response body.
\param pDataLength      On return, pointer to number of bytes of data
in the request or response body ($ppDataToSend$).

\return $OK$ (0) if successful; otherwise a negative number
error code definition from merrors.h. To retrieve a string containing an
English text error identifier corresponding to the function's returned error
status, use the $DISPLAY_ERROR$ macro.

*/
    MSTATUS (*funcPtrResourceFetcher) (httpContext *pHttpContext, ubyte **ppDataToSend, ubyte4 *pDataLength);

    /*! (Internal use only)
    (Internal use only)
    \note This field is defined only if the $__ENABLE_DIGICERT_HTTPCC_SERVER__$
    flag is defined in moptions.h.
    */
    struct hashTableOfPtrs* resourceList;
#endif

    /*! (Internal use only)
    (Internal use only)
    */
    sbyte4 (*funcPtrSetVersionCallback)(httpContext *pHttpContext, ubyte4 *version);

} httpSettings;


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS HTTP_init(void);
MOC_EXTERN MSTATUS HTTP_initClient(sbyte4 numClientConnections);
MOC_EXTERN MSTATUS HTTP_initServer(sbyte4 numServerConnections);

MOC_EXTERN MSTATUS HTTP_connect (httpContext **ppRetHttpContext, TCP_SOCKET serverSocket);
MOC_EXTERN MSTATUS HTTP_accept  (httpContext **ppRetHttpContext, TCP_SOCKET clientSocket);
MOC_EXTERN MSTATUS HTTP_recv    (httpContext *pHttpContext, ubyte *pData, ubyte4 dataLength);
MOC_EXTERN MSTATUS HTTP_continue(httpContext *pHttpContext);
MOC_EXTERN MSTATUS HTTP_close   (httpContext **ppReleaseContext);

MOC_EXTERN byteBoolean HTTP_isDone(httpContext *pHttpContext);

MOC_EXTERN httpSettings* HTTP_httpSettings(void);
MOC_EXTERN MSTATUS HTTP_getCookie(httpContext *pHttpContext, void **pCookie);
MOC_EXTERN MSTATUS HTTP_setCookie(httpContext *pHttpContext, void *cookie);

MOC_EXTERN MSTATUS HTTP_getUserAccessGroups(httpContext *pHttpContext, sbyte4 *pRetGroupAccess);
MOC_EXTERN MSTATUS HTTP_setUserAccessGroups(httpContext *pHttpContext, sbyte4 groupAccess);

MOC_EXTERN MSTATUS HTTP_stop(void);

MOC_EXTERN sbyte4 SSL_PROXY_send(sbyte4 ssl_id, sbyte *pBuffer, ubyte4 bufferLen, ubyte4 *pRetNumBytesSent);
MOC_EXTERN sbyte4 SSL_PROXY_recv(sbyte4 ssl_id, sbyte *pRetBuffer, ubyte4 bufferSize, ubyte4 *pNumBytesReceived, ubyte4 timeout);

/*! Gets the ip address for a given hostname. A buffer gets allocated for the ip address
    in string form, and make sure to free this buffer when done with it. 

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$

@inc_file http.h
\param pHostName   The input host name in string form.
\param ppIpAddr    Location that will recieve a string form of the ip address.

\return \c OK if successful and a negative error code otherwise.
*/
MOC_EXTERN MSTATUS HTTP_getHostIpAddr(sbyte* pHostName, sbyte **ppIpAddr);

/*! Determines if the client is initialized to have its CONNECT requests go to a proxy server.

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$

@inc_file http.h

\return \c TRUE if the client is initilized to send CONNECT requests to a proxy server. \c FALSE otherwise.
*/
MOC_EXTERN byteBoolean HTTP_PROXY_isProxyUrlSet(void);

/*! Sets the proxy servers URL and port for further CONNECT requests. Be sure to call
    \c HTTP_PROXY_freeProxyUrl to free the url when finished.

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$

@inc_file http.h
\param pUrl     String representing the url location of the proxy server. This may be a hostname
                or an IP address. The port may be included or will be set to a default if ommitted.
                Example: www.myproxyserver.com:3128

\return \c OK if successful and a negative error code otherwise.
*/
MOC_EXTERN MSTATUS HTTP_PROXY_setProxyUrlAndPort(sbyte *pUrl);

/*! Frees the proxy URL internall stored after a call to \c HTTP_PROXY_setProxyUrlAndPort.

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$

@inc_file http.h

\return \c OK if successful and a negative error code otherwise.
*/
MOC_EXTERN MSTATUS HTTP_PROXY_freeProxyUrl(void);

/*! Makes a CONNECT request to the proxy server and creates a socket that can be used
    to tunnel to a target URL.

! Flags
To enable this function, at least one of the following flags must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$

@inc_file http.h

\param pUrl          The target URL.
\param pServerSocket The return socket used to connect to the proxy.
\param pProxySocket  If the connection to the proxy server is secure, this will be the socket
                     that will be created in order to tunnel through to the target URL for SSL.
\param pRetSslId     If the connection to the proxy server is secure, this will be set to the SSL
                     identifier (ie connection instance).
\param pCertStore    For a secure connection this will be the required certificate store.
\return \c OK if successful and a negative error code otherwise.
*/
MOC_EXTERN MSTATUS HTTP_PROXY_connect(sbyte *pUrl, TCP_SOCKET *pServerSocket, TCP_SOCKET *pProxySocket, sbyte4 *pRetSslId, certStorePtr pCertStore);

#ifdef __cplusplus
}
#endif

#endif /* __HTTP_HEADER__ */
