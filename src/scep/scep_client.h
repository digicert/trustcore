/**
 * @file  scep_client.h
 * @brief SCEP client routines
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert's Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.
 *
 */

/**
@file       scep_client.h
@ingroup    nanoscep_tree
@brief      Nanocert SCEP Client developer API header.
@details    This header file contains definitions, structures, and function
            declarations used by NanoCert SCEP Client developer API functions.

@since 2.02
@version 2.02 and later

@flags      To enable this file's definitions, you must define the following flag in moptions.h:
            + \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@filedoc    scep_client.h
*/
#ifndef __SCEP_CLIENT_HEADER__
#define __SCEP_CLIENT_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/*! @cond */
#ifdef __ENABLE_DIGICERT_SCEP_CLIENT__
/*! @endcond */


/**
@brief      Create and initialize scepContext.

@details    This function creates and initializes a scepContext as specified
            by the parameters.

@ingroup    func_scep_client_comm

@since 2.02
@version 5.3 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file   scep_client.h

@param ppScepContext    On return, pointer to created SCEP context.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_client.h
*/
MOC_EXTERN MSTATUS
SCEP_CLIENT_initContext(scepContext **ppScepContext);


/**
 * @dont_show
 * @internal

@brief      Initialize SCEP context, passing it a cookie which would be returned back in the callbacks.

@details    This function creates and initializes a scepContext as specified
            by the parameters.

@ingroup    func_scep_client_comm

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file   scep_client.h

@param ppScepContext    On return, pointer to created SCEP context.
@param pCookie          On return, pointer to created SCEP context.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_client.h
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
MOC_EXTERN MSTATUS
SCEP_CLIENT_initContextEx(scepContext **ppScepContext, void *pCookie);

/* HTTP callbacks used by SCEP client */

/**
@brief      Retrieve the body of a request made by a SCEP %client via HTTP
            methods.

@details    This HTTP %client callback function gets the body of a request
            made by a SCEP %client via HTTP methods. Your application can
            forward the data to the SCEP server by calling the appropriate HTTP_REQUEST_* functions (see "HTTP Client Functions").

@ingroup    func_scep_client_http

@since 2.45
@version 2.45 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file   scep_client.h

@param pHttpContext         Pointer to HTTP context (returned by HTTP_connect())
                              containing request context and message body.
@param ppDataToSend         On return, pointer to data to send (the HTTP
                              request body).
@param pDataLength          On return, pointer to number of bytes in send buffer
                              (\p ppDataToSend).
@param pRequestBodyCookie   Reference to opaque cookie that points to context
                              information such as bookkeeping or caching data.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_client.h
*/
MOC_EXTERN sbyte4
SCEP_CLIENT_http_requestBodyCallback (httpContext *pHttpContext, ubyte **ppDataToSend, ubyte4 *pDataLength, void *pRequestBodyCookie);

/**
@brief      Retrieve response header after it has been received from the
            server and processed.

@details    This callback function (used by the HTTP %client) retrieves a
            response header after it has been received from the server and processed.

@ingroup    func_scep_client_http

@since 2.45
@version 2.45 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file scep_client.h

@param pHttpContext         Pointer to HTTP context (returned by HTTP_connect())
                              containing request context and message header.
@param isContinueFromBlock  \c TRUE if the HTTP session was previously blocked:
                              for example, if TCP \c send() could not
                              complete, if waiting for authentication, or
                              application-specific requirements; otherwise
                              \c FALSE. Typically this argument can be
                              ignored, but it may be a useful indicator in
                              threadless environments.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_client.h
*/
MOC_EXTERN sbyte4
SCEP_CLIENT_http_responseHeaderCallback(httpContext *pHttpContext, sbyte4 isContinueFromBlock);

/**
@brief      Retrieve response body from the HTTP %client (for forwarding to
            the application).

@details    This callback function (used by the HTTP %client) retrieves a
            response body after HTTP receives the response from the server
            and parses it. The response body can then be forwarded to the
            application.

@ingroup    func_scep_client_http

@since 2.45
@version 2.45 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file scep_client.h

@param pHttpContext         Pointer to HTTP context (returned by HTTP_connect())
                              containing response context and message.
@param pDataReceived        Pointer to the response body received.
@param dataLength           Number of bytes in the response body
                              (\p DataReceived).
@param isContinueFromBlock  \c TRUE if the HTTP session was previously blocked:
                              for example, if TCP \c send() could not
                              complete, if waiting for authentication, or
                              application-specific requirements; otherwise
                              \c FALSE. Typically this argument can be
                              ignored, but it may be a useful indicator in
                              threadless environments.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_client.h
*/
MOC_EXTERN sbyte4
SCEP_CLIENT_http_responseBodyCallback(httpContext *pHttpContext,
                                         ubyte *pDataReceived,
                                         ubyte4 dataLength,
                                         sbyte4 isContinueFromBlock);

/**
@brief      Set \c scepContext operation-specific parameters.

@details    This function sets scepContext operation-specific parameters.

@ingroup    func_scep_client_comm

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file scep_client.h

@param pScepContext     Pointer to SCEP context to set.
@param pReqInfo         Pointer to \c requestInfo structure containing desired parameters.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_client.h
*/
MOC_EXTERN MSTATUS
SCEP_CLIENT_setRequestInfo(scepContext *pScepContext, requestInfo *pRequestInfo);

/**
@brief      Release all resources used by scepContext.

@details    This function releases the resources used by the specified
            \c scepContext.

@ingroup    func_scep_client_comm

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file scep_client.h

@param ppScepContext    Reference to SCEP context containing resources to
                          release (free).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_client.h
*/
MOC_EXTERN MSTATUS
SCEP_CLIENT_releaseContext(scepContext **ppScepContext);

/* send an appropriate SCEP request to server */
/**
@brief      Build (generate) a SCEP request.

@details    This function builds (generates) a SCEP request (for HTTP GET) as
            specified by the \p pScepContext parameter.

@ingroup    func_scep_client_comm

@since 2.45
@version 2.45 and later

@note       This function only builds the request. To send the request, you
            must use this function's results as input to an \c HTTP_REQUEST_*
            function. For details, refer to scep_client_example.c in the examples directory.

@remark     This function replaces the v2.02 \c SCEP_CLIENT_sendRequest
            function.

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file   scep_client.h

@param pScepContext     Pointer to SCEP context containing the %client
                          specification and request context.
@param ppQuery          On return, pointer to fully formed SCEP request.
@param pQueryLen        On return, pointer to number of bytes in SCEP request
                          (\p ppQuery).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa SCEP_CLIENT_generateRequestEx()

@funcdoc    scep_client.h
*/
MOC_EXTERN MSTATUS
SCEP_CLIENT_generateRequest(scepContext *pScepContext, ubyte **ppQuery, ubyte4 *pQueryLen);

/**
@brief      Build (generate) a SCEP request, including HTTP POST information
            if specified.

@details    This function builds (generates) a SCEP request as specified by the
            \p pScepContext and \p useHttpPOST parameters. If HTTP POST mode is
            specified, an opaque cookie must also be provided, which is
            interpreted by the internal SCEP %client implementation.

@ingroup    func_scep_client_comm

@since 2.45
@version 2.45 and later

@note       This function only builds the request. To send the request, you
            must use this function's results as input to an \c HTTP_REQUEST_*
            function. For details, refer to scep_client_example.c in the
            examples directory.

@note       This function can be used to build requests for HTTP POST or
            GET. However, if you are using the GET method, it is simpler to
            use the SCEP_CLIENT_generateRequest() function.

@remark     This function replaces the v2.02 \c SCEP_CLIENT_sendRequestEx
            function.

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file   scep_client.h

@param pScepContext     Pointer to SCEP context containing the %client
                          specification and request context.
@param useHttpPOST      \c TRUE to use HTTP POST; otherwise \c FALSE (for GET).
@param ppQuery          On return, pointer to query portion of the request URL:
                          GET method&mdash;fully formed polling request; POST
                          method&mdash;query portion only.
@param pQueryLen        On return, pointer to number of bytes in request query
                          (\p ppQuery).
@param pBodyLen         (Applicable only to POST method) On return, pointer to
                          the number of bytes in the body of the SCEP request
                          (\p ppQuery).
@param ppCookie         (Applicable only to POST method) Reference to opaque
                          cookie that points to the body portion of the SCEP
                          request, which is interpreted by the internal SCEP
                          %client implementation.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@sa SCEP_CLIENT_generateRequest()

@funcdoc    scep_client.h
*/
MOC_EXTERN MSTATUS
SCEP_CLIENT_generateRequestEx(scepContext *pScepContext, byteBoolean useHttpPOST, ubyte **ppQuery, ubyte4 *pQueryLen, ubyte4 *pBodyLen, void** ppCookie);

/**
@brief      Process a SCEP %server response.

@details    This function processes a response received from a SCEP %server.

@ingroup    func_scep_client_comm

@since 2.02
@version 5.3 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file   scep_client.h

@param pScepContext     Pointer to SCEP context containing the %client
                          specification and request context.
@param contentType      String specifying the type of response; should match an
                          entry in the \c mScepResponseTypes table in scep.c.
@param contentTypeLen   Number of bytes in response type string
                          (\p contentType).
@param pHttpResp        Pointer to bytes received by the transport layer. After
                          the bytes are processed, the result is stored in
                          the \p pScepContext parameter.
@param httpRespLen      Number of bytes in received response (\p pHttpResp).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_client.h
*/
MOC_EXTERN MSTATUS
SCEP_CLIENT_recvResponse(scepContext *pScepContext, ubyte *contentType, ubyte4 contentTypeLen, ubyte *pHttpResp, ubyte4 httpRespLen);

/* In manual certificate enrollment mode, poll the server for certificate issurance status
 * The polling message can be cached by passing in a non-NULL ppPollingCookie parameter
 * to avoid having the generate the message each time.
 */
/**
@brief      Build (generate) a start SCEP %server polling request.

@details    This function builds (generates) a start SCEP %server polling
            request. When %client applications receive a SCEP %server
            response message with a PENDING status, the %client should
            periodically poll the server to determine whether a certificate
            is issued, the certificate enrollment request was denied, or the
            request timed out.

@ingroup    func_scep_client_comm

@since 2.45
@version 2.45 and later

@note       This function only builds the polling request. To begin polling,
            you must use this function's results as input to an
            \c HTTP_REQUEST_* function. For details, refer to
            scep_client_example.c in the examples directory.

@remark     This function replaces the v2.02 \c SCEP_CLIENT_pollServer
            function.

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file scep_client.h

@param pScepContext     Pointer to SCEP context containing the %client
                          specification and request context.
@param ppQuery          On return, pointer to query portion of the request URL:
                          GET method&mdash;fully formed polling request;
                          POST method&mdash;query portion only.
@param pQueryLen        On return, pointer to number of bytes in polling
                          request (\p ppQuery).
@param pBodyLen         (Applicable only for POST method) On return, pointer to
                          the number of bytes in the body of the polling
                          request (\p ppQuery).
@param ppCookie         (Applicable only for POST method; Optional)
                          Reference to opaque cookie, which if non-NULL
                          will contain the body of the polling request
                          message upon return. The message will be generated
                          once and then cached in the cookie for later reuse.
@param ppPollingCookie  (Optional) Reference to opaque cookie, which if
                          non-NULL will contain the polling request message
                          upon return. The message will be generated once
                          and then cached in the cookie for later reuse.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_client.h
*/
MOC_EXTERN MSTATUS
SCEP_CLIENT_generatePollServerRequest(scepContext *pScepContext,
                       ubyte **ppQuery, ubyte4 *pQueryLen, ubyte4 *pBodyLen, void **ppCookie, void **ppPollingCookie);

/**
@brief      Release (free) a request body cookie.

@details    This function releases (frees) the memory used for a request body
            cookie.

@ingroup    func_scep_client_comm

@since 2.45
@version 2.45 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file   scep_client.h

@param pCookieToRelease     Pointer to request body cookie to release (free).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_client.h
*/
MOC_EXTERN MSTATUS
SCEP_CLIENT_releaseCookie(void *pCookieToRelease);

/**
@brief      Release (free) a polling cookie.

@details    This function releases (frees) the memory used for a polling cookie.

@ingroup    func_scep_client_comm

@since 2.45
@version 2.45 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file   scep_client.h

@param pPollCookieToRelease     Pointer to polling cookie to release (free).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_client.h
*/
MOC_EXTERN MSTATUS
SCEP_CLIENT_releasePollCookie(void *pPollCookieToRelease);

/* utility functions to retrieve various SCEP_ClIENT status */
/* return the status of the SCEP response from server */
/**
@brief      Get PKI status of a SCEP %server response.

@details    This function gets the PKI status (\c SUCCESS, \c FAILURE, or
            \c PENDING) of a SCEP operation.

@ingroup    func_scep_ungrouped

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file   scep_client.h

@param pScepContext     Pointer to SCEP context.

@return     PKE status as a \c SCEP_pkiStatus enumerated value (see scep.h).

@funcdoc    scep_client.h
*/
MOC_EXTERN SCEP_pkiStatus
SCEP_CLIENT_getStatus(scepContext *pScepContext);

/* return whether all the response from server has been processed */
/**
@brief      Determine if the SCEP %client is done processing a response
            received from a SCEP %server.

@details    This function determines if the SCEP %client is done processing
            a response received from a SCEP %server.

@ingroup    func_scep_client_comm

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file   scep_client.h

@param pScepContext     Pointer to SCEP context.

@return     \c TRUE if processing is done; otherwise \c FALSE.

@funcdoc    scep_client.h
*/
MOC_EXTERN intBoolean
SCEP_CLIENT_isDoneReceivingResponse(scepContext *pScepContext);

/**
@brief      Get a request message's type.

@details    This function retrieves a requst message's type.

@ingroup    func_scep_client_comm

@since 2.45
@version 2.45 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file   scep_client.h

@param pScepContext     Pointer to SCEP context containing the %client
                          specification and request context.
@param pMessageType     On return, pointer to \c SCEP_messageType enumerated
                          value (see scep.h).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_client.h
*/
MOC_EXTERN MSTATUS
SCEP_CLIENT_getMessageType(scepContext *pScepContext, SCEP_messageType *pMessageType);

/* return the response content */
/**
@brief      Get response contents (or error status if not done receiving
            response).

@details    This function gets the contents of a response received from a
            SCEP %server. If the %client is not done receiving the response, an error is returned.

@ingroup    func_scep_client_comm

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file   scep_client.h

@param pScepContext     Reference to SCEP context.
@param ppRespContent    On return, reference to buffer containing the
                          response contents.
@param pRespContentLen  On return, pointer to number of bytes in
                          \p ppRespContent.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_client.h
*/
MOC_EXTERN MSTATUS
SCEP_CLIENT_getResponseContent(scepContext *pScepContext, ubyte** ppRespContent, ubyte4* pRespContentLen);

/* Deprecated. return the HTTP transport response status code */
/**
@brief      Get HTTP transport status.

@details    This function gets the status code of the HTTP transport layer.

@ingroup    func_scep_client_comm

@since 2.02
@version 2.02

@deprecated     For applications using version 2.45 and later, you should
                not use this function. Instead, call the
                HTTP_REQUEST_getStatusCode() function.

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file scep_client.h

@param pScepContext     Reference to SCEP context.

@return     HTTP response status code (from 200 to 600) as defined in
            RFC&nbsp;2616, <tt>Hypertext Transfer Protocol -- HTTP/1.1</tt>.

@funcdoc    scep_client.h
*/
MOC_EXTERN ubyte4
SCEP_CLIENT_getHTTPStatusCode(scepContext *pScepContext);

/* return the failInfo code when the SCEP response status does not equal to SUCCESS */
/**
@brief      Get the reason for a PKI \c FAILURE status.

@details    This function gets additional information about a previously
            received PKI \c FAILURE status of a SCEP %server response.

@ingroup    func_scep_client_comm

@since 2.02
@version 2.02 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file scep_client.h

@param pScepContext     Pointer to SCEP context.
@param pFailInfo        On return, pointer to one of the following
                          \c SCEP_failInfo enumerated values: \c badAlg,
                          \c badMessageCheck, \c badRequest, \c badTime, or
                          \c badCertId.

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_client.h
*/
MOC_EXTERN MSTATUS
SCEP_CLIENT_getFailInfo(scepContext *pScepContext, SCEP_failInfo *pFailInfo);

/* returns an ID for a message sent in a SCEP context */
/**
 * @dont_show
 * @internal
 *
 * Doc Note: This function is for Mocana internal code use only, and
 * should not be included in the API documentation.
 */
/*
 * obtains the unique value for a message in a context
 */
MOC_EXTERN MSTATUS
SCEP_CLIENT_getTransactionId(scepContext *pScepContext, sbyte **ppTransactionId, ubyte4 *pTransactionIdLen, SCEP_messageType scepMsgType);

/**
@brief      Get a certificate's custom Mocana SoT Platform extension.

@details    This function extracts the Mocana SoT Platform custom extension
            (OID 1.3.6.1.4.1.14421.1) that is embedded in a given certificate.

@ingroup    func_scep_ungrouped

@since 5.3
@version 5.3 and later

@flags
To enable this function, the following flag must be defined in moptions.h:
+ \c \__ENABLE_DIGICERT_SCEP_CLIENT__

@inc_file scep_client.h

@param pCertDer     Pointer to DER-formatted certificate.
@param certLen      Number of byes in the DER-formatted certificate
                      (\p pCertDer).
@param ppExt        On return, pointer to the custom extension.
@param pExtLen      On return, pointer to number of bytes in the custom
                      extension (\p ppExt).

@return     \c OK (0) if successful; otherwise a negative number error code
            definition from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@funcdoc    scep_client.h
*/
MOC_EXTERN MSTATUS
SCEP_CLIENT_getUserPrivilegeExt(ubyte *pCertDer, ubyte4 certLen, ubyte **ppExt, ubyte4 *pExtLen);

#endif /* #ifdef __ENABLE_DIGICERT_SCEP_CLIENT__ */

#ifdef __cplusplus
}
#endif

#endif  /*#ifndef __SCEP_CLIENT_HEADER__ */
