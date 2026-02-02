/*
 * http_request.h
 *
 * HTTP Request Header File
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

#ifndef __HTTP_REQUEST_HEADER__
#define __HTTP_REQUEST_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

/*------------------------------------------------------------------*/
MOC_EXTERN MSTATUS
HTTP_REQUEST_setRequestMethodIfNotSet(httpContext *pHttpContext,
                              HTTP_methodsInfo* pMethodDescr);

MOC_EXTERN MSTATUS
HTTP_REQUEST_setRequestUriIfNotSet(httpContext *pHttpContext,
                              sbyte* pURI);

MOC_EXTERN byteBoolean
HTTP_REQUEST_isDoneSendingRequest(httpContext *pHttpContext);

MOC_EXTERN MSTATUS
HTTP_REQUEST_setContentLengthIfNotSet(httpContext *pHttpContext, ubyte4 contentLength);

MOC_EXTERN MSTATUS
HTTP_REQUEST_formRequestHeader(httpContext *pHttpContext, ubyte** ppRetHttpRequest, ubyte4 *pRetHttpRequestLen);

MOC_EXTERN MSTATUS
HTTP_REQUEST_getStatusCode(httpContext *pHttpContext, ubyte4 *pStatusCode);

MOC_EXTERN MSTATUS
HTTP_REQUEST_getStatusPhrase(httpContext *pHttpContext, const ubyte **ppStatusPhrase, ubyte4 *pStatusPhraseLen);

MOC_EXTERN MSTATUS
HTTP_REQUEST_getContentType(httpContext *pHttpContext, const ubyte **ppContentType, ubyte4 *pContentTypeLen);

MOC_EXTERN MSTATUS
HTTP_REQUEST_getResponseContent(httpContext *pHttpContext, ubyte **ppResponse, ubyte4 *pResponseLen);

MOC_EXTERN MSTATUS
HTTP_REQUEST_getEntityByIndex(httpContext *pHttpContext, ubyte4 index, const ubyte **ppEntityType, ubyte4 *pEntityTypeLen);

#ifdef __cplusplus
}
#endif

#endif /* __HTTP_REQUEST_HEADER__ */
