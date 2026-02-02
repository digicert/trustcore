/*
 * http_request.c
 *
 * HTTP Request
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

/*! \file http_request.c HTTP Request API.
This file contains HTTP request functions.

\since 2.02
\version 5.3 and later

! Flags
To build products using this header file, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$

! External Functions
This file contains the following public ($extern$) functions:
- HTTP_REQUEST_getContentType
- HTTP_REQUEST_getResponseContent
- HTTP_REQUEST_getStatusCode
- HTTP_REQUEST_getStatusPhrase
- HTTP_REQUEST_isDoneSendingRequest
- HTTP_REQUEST_setContentLengthIfNotSet
- HTTP_REQUEST_setRequestMethodIfNotSet
- HTTP_REQUEST_setRequestUriIfNotSet

*/

#include "../../common/moptions.h"

#ifdef __ENABLE_DIGICERT_HTTP_CLIENT__

#include "../../common/mdefs.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mtcp.h"
#include "../../common/mstdlib.h"
#include "../../http/http_context.h"
#include "../../http/http_common.h"
#include "../../http/http.h"
#include "../../http/client/http_request.h"



/* return the starting index and length of the host part in URI */
static MSTATUS
getHost(sbyte *pURI, ubyte4 *pIndex, ubyte4* pLength, ubyte4* pPortLength)
{
    ubyte4 i;
    sbyte ch;
    ubyte *pAuthority;
    ubyte4 len;

    *pIndex = 0;
    *pLength = 0;
    *pPortLength = 0;

    if (NULL == pURI)
        goto exit;

    len = DIGI_STRLEN(pURI);
    /* locate scheme part */
    for (i = 0; i < len; i++)
    {
        if (DIGI_STRNICMP((sbyte*)(pURI+i), (sbyte*)"://", 3) == 0)
        {
            break;
        }
    }

    if (i+3 >= len)
        goto exit;

    i += 3;
    pAuthority = (ubyte *)(pURI + i);
    *pIndex = i;
    len = DIGI_STRLEN((sbyte *)pAuthority);
    /* locate host part */
    for (i = 0; i < len; i++)
    {
        if ( DIGI_STRNICMP((sbyte*)(pAuthority+i), (sbyte*)"@", 1) == 0 ||
            DIGI_STRNICMP((sbyte*)(pAuthority+i), (sbyte*)":", 1) == 0 ||
            DIGI_STRNICMP((sbyte*)(pAuthority+i), (sbyte*)"/", 1) == 0)
        {
            break;
        }
    }
    ch = *(pAuthority+i);
    if (ch == '@')
    {
        (*pIndex) += i + 1;
        for (i = (*pIndex); i < len; i++)
        {
            if (DIGI_STRNICMP((sbyte*)(pAuthority+i), (sbyte*)":", 1) == 0 ||
                DIGI_STRNICMP((sbyte*)(pAuthority+i), (sbyte*)"/", 1) == 0)
            {
                (*pLength) = i - (*pIndex);
                ch = *(pAuthority+i);
                break;
            }
        }
    }
    else if (ch == ':' || ch == '/')
    {
        /* pIndex doesn't change */
        (*pLength) = i;
    }

    /* Parse the port field */
    if (ch == ':')
    {
        ubyte4 portOffset = i + 1;

        (*pPortLength) = 1;
        for (i = portOffset; i < len; i++)
        {
            if (DIGI_STRNICMP((sbyte*)(pAuthority+i), (sbyte*)"/", 1) == 0)
            {
                (*pPortLength) += (i - portOffset);
                break;
            }
        }

        if (i == len)
        {
            /* no '/' found, so the port length is the rest of the string */
            (*pPortLength) += (len - portOffset);
        }
    }

exit:
    return OK;
}

/*------------------------------------------------------------------*/

/*! Set an HTTP connection context's request method if it's not already set.
This function sets an HTTP connection context's request method if it's not
already set.

\since 2.45
\version 2.45 and later

\note The default HTTP request method is GET.

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$

@inc_file http_request.h

\param pHttpContext     Pointer to connection context handle previously
returned by HTTP_connect.
\param pMethodDescr     Pointer to predefined HTTP method structure, such as
$mHttpMethods[GET]$ for GET, or $mHttpMethods[POST]$ for POST. (For method
structure definitions, refer to http_common.h.)

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
HTTP_REQUEST_setRequestMethodIfNotSet(httpContext *pHttpContext,
                              HTTP_methodsInfo* pMethodDescr)
{
    if (NULL == pHttpContext)
        return ERR_NULL_POINTER;
        
    if (!pHttpContext->pMethodDescr)
    {
        pHttpContext->pMethodDescr = pMethodDescr;
    }
    return OK;
}


/*------------------------------------------------------------------*/

/*! Set an HTTP connection context request's URI/URL if it's not already set.
This function sets an HTTP connection context request's URI/URL if it's not
already set.

\since 2.45
\version 2.45 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$

@inc_file http_request.h

\param pHttpContext     Pointer to connection context handle previously
returned by HTTP_connect.
\param pURI             Pointer to URI buffer that identifies the resource
the request applies to.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
HTTP_REQUEST_setRequestUriIfNotSet(httpContext *pHttpContext,
                              sbyte* pURI)
{
    MSTATUS status = OK;
    ubyte4 hostIdx;
    ubyte4 hostLen;
    ubyte4 portLen;

    if (!pHttpContext->pURI)
    {
        if (NULL == (pHttpContext->pURI = (sbyte*) MALLOC(DIGI_STRLEN(pURI)+1)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        if (OK > (status = DIGI_MEMCPY(pHttpContext->pURI, pURI, DIGI_STRLEN(pURI))))
            goto exit;
        *(pHttpContext->pURI+DIGI_STRLEN(pURI)) = '\0';
        
        /* set Host: request header. required by HTTP/1.1 */
        getHost(pURI, &hostIdx, &hostLen, &portLen);

        /* If hostLen is 0 then HTTP_COMMON_setHeaderIfNotSet will not set the
         * body Host field in the HTTP request. If this is the case then the
         * full URI must be placed in the HTTP Request-URI field.
         */
        if (0 == hostLen)
        {
            pHttpContext->pURIPath =  (sbyte *)(pHttpContext->pURI);
        }
        else
        {
            pHttpContext->pURIPath =  (sbyte *)(pHttpContext->pURI + hostIdx + hostLen + portLen);
            
            /* HOST is the 11th item in mHttpRequests */
            if (OK > (status = HTTP_COMMON_setHeaderIfNotSet(pHttpContext, 11, (ubyte *)(pURI+hostIdx), hostLen)))
            {
                goto exit;
            }
        }

        if ('\0' == pHttpContext->pURIPath[0])
        {
            /* if URI path is empty, URI path defaults to "/" */
            pHttpContext->pURIPath = (sbyte *) "/";
        }
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
HTTP_REQUEST_formRequestHeader(httpContext *pHttpContext,
                   ubyte **ppRetHttpRequest, ubyte4 *pRetHttpRequestLength)
{
    ubyte*  pHttpRequest = NULL;
    ubyte4  httpRequestLength;
    ubyte4  version = 1;
    MSTATUS status = OK;
    ubyte4 i;
    ubyte4 contentLengthIdx = NUM_HTTP_REQUESTS + NUM_HTTP_GENERALHEADERS + ContentLength;

    if (NULL != HTTP_httpSettings()->funcPtrSetVersionCallback)
    {
        HTTP_httpSettings()->funcPtrSetVersionCallback(pHttpContext, &version);

        /* version == 0 for HTTP/1.0, 1 for HTTP/1.1 */
        pHttpContext->pHttpVersionDescr = HTTP_COMMON_getHttpVersionDescr(version);
    }

    if ((NULL == pHttpContext->pHttpVersionDescr) &&
        (NULL == (pHttpContext->pHttpVersionDescr = HTTP_COMMON_returnHighestHttpVersion())))
    {
        /* someone has mucked with the http version table */
        status = ERR_HTTP_RESPONSE_MISSING_VERSION;
        goto exit;
    }

    *pRetHttpRequestLength = 0;

    if (!pHttpContext->pURI)
    {
        status = ERR_HTTP_MALFORMED_MESSAGE;
        goto exit;
    }

    /* set if not set: Method, default to GET */
    if (OK > (status = HTTP_REQUEST_setRequestMethodIfNotSet(pHttpContext, &mHttpMethods[1])))
        goto exit;

    /* set if not set: User-Agent */
    if (OK > (status = HTTP_COMMON_setHeaderIfNotSet(pHttpContext, 0, (ubyte*)"Mocana HTTP Client", 18)))
    {
        goto exit;
    }

    /* set Transfer-Encoding to chunked if POST and Content_Length is not set */
    if (pHttpContext->pMethodDescr->pHttpMethodName == mHttpMethods[POST].pHttpMethodName &&
        !(pHttpContext->requestBitmask[contentLengthIdx / 8] & (1 << (contentLengthIdx & 7))))
    {
        ubyte4 idx = NUM_HTTP_REQUESTS + TransferEncoding;
        if (OK > (status = HTTP_COMMON_setHeaderIfNotSet(pHttpContext, idx, (ubyte*)"chunked", 7)))
        {
            goto exit;
        }
    }

    /* length of request-line plus the last CRLF */
    httpRequestLength = pHttpContext->pMethodDescr->httpMethodNameLength + 1 +
                        DIGI_STRLEN(pHttpContext->pURIPath) + 1 +
                        pHttpContext->pHttpVersionDescr->httpVersionNameLength + 2 + /* CRLF */
                        2; /* the last CRLF */

    /* add the length of request headers */
    for (i = 0; i < NUM_HTTP_REQUESTS + NUM_HTTP_GENERALHEADERS + NUM_HTTP_ENTITYHEADERS; i++)
    {
        if (pHttpContext->requestBitmask[i / 8] & (1 << (i & 7)))
        {
            if (i < NUM_HTTP_REQUESTS)
            {
                httpRequestLength += mHttpRequests[i].httpRequestNameLength +
                    1 + 1 + /* : SP */
                    pHttpContext->requests[i].httpStringLength +
                    2; /* CRLF */
            }
            else if (i < NUM_HTTP_REQUESTS + NUM_HTTP_GENERALHEADERS )
            {
                    httpRequestLength += mHttpGeneralHeaders[i-NUM_HTTP_REQUESTS].httpRequestNameLength +
                    1 + 1 + /* : SP */
                    pHttpContext->requests[i].httpStringLength +
                    2; /* CRLF */

            }
            else
            {
                httpRequestLength += mHttpEntityHeaders[i-NUM_HTTP_REQUESTS-NUM_HTTP_GENERALHEADERS].httpRequestNameLength +
                    1 + 1 + /* : SP */
                    pHttpContext->requests[i].httpStringLength +
                    2; /* CRLF */
            }
        }
    }

    *pRetHttpRequestLength = httpRequestLength;

    /* will be released when pHttpContext->pPendingData is released */
    if (NULL == (*ppRetHttpRequest = pHttpRequest = MALLOC(httpRequestLength)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* write request-line */
    if (OK > (status = HTTP_COMMON_writeString(&pHttpRequest, &httpRequestLength, pHttpContext->pMethodDescr->pHttpMethodName, pHttpContext->pMethodDescr->httpMethodNameLength)))
        goto exit;

    if (OK > (status = HTTP_COMMON_writeString(&pHttpRequest, &httpRequestLength, (sbyte*)" ", 1)))
        goto exit;

    if (OK > (status = HTTP_COMMON_writeString(&pHttpRequest, &httpRequestLength, (sbyte*)pHttpContext->pURIPath, DIGI_STRLEN(pHttpContext->pURIPath))))
        goto exit;

    if (OK > (status = HTTP_COMMON_writeString(&pHttpRequest, &httpRequestLength, (sbyte*)" ", 1)))
        goto exit;

    if (OK > (status = HTTP_COMMON_writeString(&pHttpRequest, &httpRequestLength, pHttpContext->pHttpVersionDescr->pHttpVersionName, pHttpContext->pHttpVersionDescr->httpVersionNameLength)))
        goto exit;

    if (OK > (status = HTTP_COMMON_writeString(&pHttpRequest, &httpRequestLength, (sbyte*)CRLF, 2)))
        goto exit;
    /* write request headers */
    for (i = 0; i < NUM_HTTP_REQUESTS + NUM_HTTP_GENERALHEADERS + NUM_HTTP_ENTITYHEADERS; i++)
    {
        if (pHttpContext->requestBitmask[i / 8] & (1 << (i & 7)))
        {
            sbyte *pName, *pValue;
            ubyte4 nameLen, valueLen;
            if (i < NUM_HTTP_REQUESTS)
            {
                pName = mHttpRequests[i].pHttpRequestName;
                nameLen = mHttpRequests[i].httpRequestNameLength;
            }
            else if (i < NUM_HTTP_REQUESTS + NUM_HTTP_GENERALHEADERS )
            {
                pName = mHttpGeneralHeaders[i-NUM_HTTP_REQUESTS].pHttpRequestName;
                nameLen = mHttpGeneralHeaders[i-NUM_HTTP_REQUESTS].httpRequestNameLength;
            }
            else
            {
                pName = mHttpEntityHeaders[i-NUM_HTTP_REQUESTS-NUM_HTTP_GENERALHEADERS].pHttpRequestName;
                nameLen = mHttpEntityHeaders[i-NUM_HTTP_REQUESTS-NUM_HTTP_GENERALHEADERS].httpRequestNameLength;
            }
            pValue = (sbyte*)pHttpContext->requests[i].pHttpString;
            valueLen = pHttpContext->requests[i].httpStringLength;
            if (OK > (status = HTTP_COMMON_writeHeader(&pHttpRequest, &httpRequestLength, pName, nameLen, pValue, valueLen)))
                goto exit;

            if (OK > (status = HTTP_COMMON_writeString(&pHttpRequest, &httpRequestLength, (sbyte*)CRLF, 2)))
                goto exit;
        }
    }
    /* write the last CRLF */
    if (OK > (status = HTTP_COMMON_writeString(&pHttpRequest, &httpRequestLength, (sbyte*)CRLF, 2)))
        goto exit;

exit:
    if ((OK > status) && (NULL != *ppRetHttpRequest))
    {
        FREE(*ppRetHttpRequest);
        *ppRetHttpRequest = NULL;
        *pRetHttpRequestLength = 0;
    }

    return status;
}


/*------------------------------------------------------------------*/

/*! Determine whether an HTTP %client is done sending a request to the server.
This function determines whether an HTTP %client is done sending a request
to the server.

\since 2.45
\version 2.45 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$

@inc_file http_request.h

\param pHttpContext     Pointer to connection context handle previously
returned by HTTP_connect.

\return $TRUE$ if the %client is done sending its request; otherwise $FALSE$.

*/
extern byteBoolean
HTTP_REQUEST_isDoneSendingRequest(httpContext *pHttpContext)
{
    return HTTP_CLIENT_STATE(pHttpContext) >= recvHttpStatusResponseState;
}


/*------------------------------------------------------------------*/

/*! Set an HTTP connection context request header's $content_length$ if it's not already set.
This function sets an HTTP connection context request header's $content_length$
if it's not already set.

\since 2.45
\version 2.45 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$

@inc_file http_request.h

\param pHttpContext     Pointer to connection context handle previously
returned by HTTP_connect.
\param contentLength    Number of bytes in the HTTP request body.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
HTTP_REQUEST_setContentLengthIfNotSet(httpContext *pHttpContext, ubyte4 contentLength)
{
    MSTATUS status = OK;
    ubyte buf[5];
    ubyte* retBuf;

    retBuf = (ubyte*)DIGI_LTOA(contentLength, (sbyte*)buf, 5);
    if (OK > (status = HTTP_COMMON_setHeaderIfNotSet(pHttpContext, NUM_HTTP_REQUESTS+NUM_HTTP_GENERALHEADERS+ContentLength,
        buf, (ubyte4)(retBuf-buf))))
        goto exit;

exit:
        return status;
}


/*------------------------------------------------------------------*/

/*! Retrieve an HTTP response's status code.
This function retrieves an HTTP response's status code.

\since 2.45
\version 2.45 and later

\note For response status code definitions and values, refer to RFC&nbsp;2616.

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$

@inc_file http_request.h

\param pHttpContext     Pointer to connection context handle previously
returned by HTTP_connect.
\param pStatusCode      On return, pointer to the status code returned by the
HTTP server. For code definitions and values, refer to RFC&nbsp;2616.

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
HTTP_REQUEST_getStatusCode(httpContext *pHttpContext, ubyte4 *pStatusCode)
{
    if (recvHttpStatusResponseState >= HTTP_CLIENT_STATE(pHttpContext))
        return ERR_HTTP_BAD_STATE;
    *pStatusCode = pHttpContext->httpStatusResponse;
    return OK;
}


/*------------------------------------------------------------------*/

/*! Retrieve an HTTP response's reason phrase.
This function retrieves an HTTP response's }reason phrase}&mdash;a short
textual description of the response status code.

\since 2.45
\version 2.45 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$

@inc_file http_request.h

\param pHttpContext     Pointer to connection context handle previously
returned by HTTP_connect.
\param ppStatusPhrase   Pointer, which on return contains the reason phrase.
\param pStatusPhraseLen On return, pointer to number of bytes in the reason
phrase ($ppStatusPhrase$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
HTTP_REQUEST_getStatusPhrase(httpContext *pHttpContext, const ubyte **ppStatusPhrase, ubyte4 *pStatusPhraseLen)
{
    if (recvHttpStatusResponseState >= HTTP_CLIENT_STATE(pHttpContext))
        return ERR_HTTP_BAD_STATE;

    *ppStatusPhrase = pHttpContext->pReasonPhrase;
    *pStatusPhraseLen = pHttpContext->reasonPhraseLength;
    return OK;
}

/*------------------------------------------------------------------*/

/*! Retrieve an HTTP response's content type.
This function retrieves an HTTP response's content type (the value of the
response header's $content_type$ field, such as "text/html").

\since 2.45
\version 2.45 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$

@inc_file http_request.h

\param pHttpContext     Pointer to connection context handle previously
returned by HTTP_connect.
\param ppContentType   Pointer, which on return contains the content type.
\param pContentTypeLen On return, pointer to number of bytes in the returned
content type ($ppContentType$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
HTTP_REQUEST_getContentType(httpContext *pHttpContext, const ubyte **ppContentType, ubyte4 *pContentTypeLen)
{
    ubyte4 index = NUM_HTTP_RESPONSES+NUM_HTTP_GENERALHEADERS+ContentType;

    if (recvHttpResponseBodyState > HTTP_CLIENT_STATE(pHttpContext))
        return ERR_HTTP_BAD_STATE;

    *ppContentType = pHttpContext->responses[index].pHttpString;
    *pContentTypeLen = pHttpContext->responses[index].httpStringLength;
    return OK;
}


/*------------------------------------------------------------------*/

/*! Retrieve an HTTP response's body.
This function retrieves an HTTP response's body.

\since 2.45
\version 2.45 and later

! Flags
To enable this function, the following flag must be defined in moptions.h:
- $__ENABLE_DIGICERT_HTTP_CLIENT__$

@inc_file http_request.h

\param pHttpContext     Pointer to connection context handle previously
returned by HTTP_connect.
\param ppResponse       Pointer, which on return contains the response body.
\param pResponseLen     On return, pointer to number of bytes in the returned
response ($ppResponse$).

\return $OK$ (0) if successful; otherwise a negative number error code
definition from merrors.h. To retrieve a string containing an English text
error identifier corresponding to the function's returned error status, use the
$DISPLAY_ERROR$ macro.

*/
extern MSTATUS
HTTP_REQUEST_getResponseContent(httpContext *pHttpContext, ubyte **ppResponse, ubyte4 *pResponseLen)
{
    if (!HTTP_isDone(pHttpContext))
        return ERR_HTTP_BAD_STATE;
    *ppResponse = pHttpContext->pReceivedPendingDataFree;
    *pResponseLen = pHttpContext->receivedPendingDataLength;
    pHttpContext->pReceivedPendingDataFree = pHttpContext->pReceivedPendingData = NULL;
    pHttpContext->receivedPendingDataLength = 0;
    return OK;
}


/*------------------------------------------------------------------*/

/* Doc Note: This function is for Mocana internal code use only, and should not
be included in the API documentation.
*/
extern MSTATUS
HTTP_REQUEST_getEntityByIndex(httpContext *pHttpContext, ubyte4 index, const ubyte **ppEntityType, ubyte4 *pEntityTypeLen)
{
    /* index can be determined http_common.h */
    if (recvHttpResponseBodyState > HTTP_CLIENT_STATE(pHttpContext))
        return ERR_HTTP_BAD_STATE;

    *ppEntityType   = pHttpContext->responses[index].pHttpString;
    *pEntityTypeLen = pHttpContext->responses[index].httpStringLength;

    return OK;
}

#endif /* __ENABLE_DIGICERT_HTTP_CLIENT__ */
