/*
 * http_request.h
 *
 * HTTP Request Header File
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
