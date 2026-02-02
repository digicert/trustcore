/*
 * http_common.h
 *
 * HTTP Common Header File
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

/*------------------------------------------------------------------*/

#ifndef __HTTP_COMMON_HEADER__
#define __HTTP_COMMON_HEADER__

#define HTTP_LINE_MORE          1
#define HTTP_LINE_DONE          2
#define HTTP_LINE_EMPTY         3

#define HTTP_DROP               0
#define HTTP_SAVE               1

#undef DELETE

#ifdef MOC_EXTERN_P
#undef MOC_EXTERN_P
#endif

#ifdef __RTOS_WIN32__

#define MOC_EXTERN_P __declspec(dllimport) extern
#define MOC_EXTERN_D __declspec(dllimport) extern

#ifdef WIN_EXPORT
#undef MOC_EXTERN_P
#define MOC_EXTERN_P __declspec(dllexport)
#endif

#ifdef WIN_EXPORT_HTTP
#undef MOC_EXTERN_D
#define MOC_EXTERN_D __declspec(dllexport)
#endif

#else

#define MOC_EXTERN_P extern
#define MOC_EXTERN_D extern

#endif /* RTOS_WIN32 */

/*------------------------------------------------------------------*/
MOC_EXTERN_D HTTP_methodsInfo mHttpMethods[];
#define NUM_HTTP_METHODS    (sizeof(mHttpMethods)/sizeof(HTTP_methodsInfo))

typedef enum httpMethods
{
    OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE, CONNECT
} httpMethods;

/* NOTE: the orders of the headers are significant:
 * they define the index of the headers.
 * for requests, it is mHttpRequests, then mHttpGeneralHeaders, then mHttpEntityHeaders;
 * for responses, it is mHttpResponses, then mHttpGeneralHeaders, then mHttpEntityHeaders;
 */
/* hard code the number of entries for now until figuring out the precompile trick */
MOC_EXTERN_D HTTP_requestInfo mHttpRequests[];
#define NUM_HTTP_REQUESTS   21
typedef enum httpRequests
{
    UserAgent, TE, Referer, Range, ProxyAuthorization,
    MaxForwards, IfUnmodifiedSince, IfRange, IfNoneMatch, IfModifiedSince,
    IfMatch, Host, From, Expect, Authorization,
    AcceptLanguage, AcceptEncoding, AcceptCharset, Accept, ApiKey,
    ProxyConnection
} httpRequests;

MOC_EXTERN_D HTTP_requestInfo mHttpResponses[];
#define NUM_HTTP_RESPONSES   9

typedef enum httpResponses
{
    WWWAuthenticate, Vary, Server, RetryAfter, ProxyAuthenticate,
    Location, ETag, Age, AcceptRanges
} httpResponses;

MOC_EXTERN_D HTTP_requestInfo mHttpGeneralHeaders[];
#define NUM_HTTP_GENERALHEADERS   11

typedef enum httpGeneralHeaders
{
    Warning, Via, Upgrade, TransferEncoding, ContentTransferEncoding, Trailer,
    Pragma, Date, Connection, Keep_Alive, Cache_Control
} httpGeneralHeaders;


MOC_EXTERN_D HTTP_requestInfo mHttpEntityHeaders[];
#define NUM_HTTP_ENTITYHEADERS   10
typedef enum httpEntityHeaders
{
    LastModified, Expires, ContentType, ContentRange, ContentMD5,
    ContentLocation, ContentLength, ContentLanguage, ContentEncoding, Allow
} httpEntityHeaders;



/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS HTTP_COMMON_lookupMethod(ubyte *pData, ubyte4 dataLength, HTTP_methodsInfo **ppRetMethodDecr);
MOC_EXTERN MSTATUS HTTP_COMMON_lookupVersion(ubyte *pData, ubyte4 dataLength, HTTP_versionInfo **ppRetVersionDecr);
MOC_EXTERN MSTATUS HTTP_COMMON_lookupStatusCode(ubyte *pData, ubyte4 dataLength, ubyte4 *pStatusCode);
MOC_EXTERN MSTATUS HTTP_COMMON_lookupRequestInfo(ubyte *pData, ubyte4 dataLength, HTTP_requestInfo **ppRetRequestDecr, ubyte4* pIndex);
MOC_EXTERN sbyte4  HTTP_COMMON_returnRequestInfoBase(void);
MOC_EXTERN MSTATUS
HTTP_COMMON_lookupResponseInfo(ubyte *pData, ubyte4 dataLength, HTTP_requestInfo **ppRetResponseDecr, ubyte4* pIndex);

MOC_EXTERN HTTP_versionInfo* HTTP_COMMON_getHttpVersionDescr(sbyte4 version);
MOC_EXTERN HTTP_versionInfo* HTTP_COMMON_returnHighestHttpVersion(void);

MOC_EXTERN MSTATUS HTTP_COMMON_copyRequest(httpContext *pHttpContext, ubyte **ppData, ubyte4 *pDataLength, sbyte4 *pRetResult);
MOC_EXTERN intBoolean
HTTP_COMMON_subStringMatch(ubyte *pData, ubyte4 dataLen, sbyte *pSubData, ubyte4 subDataLen);
MOC_EXTERN sbyte4
HTTP_COMMON_getContentLength(httpContext *pHttpContext);

MOC_EXTERN void
HTTP_COMMON_writeInteger(ubyte4 integerValue, ubyte *pBuffer, ubyte4 *pRetLength);

MOC_EXTERN MSTATUS
HTTP_COMMON_writeString(ubyte **ppRetBuffer, ubyte4 *pRetBufSize, sbyte *pCopyThis, sbyte4 copyLen);

MOC_EXTERN MSTATUS
HTTP_COMMON_writeHeader(ubyte **ppRetBuffer, ubyte4 *pRetBufSize, sbyte *pName, sbyte4 nameLen, sbyte *pValue, sbyte4 valueLen);

MOC_EXTERN MSTATUS
HTTP_COMMON_setHeaderIfNotSet(httpContext *pHttpContext,
                              ubyte4 index, ubyte* pValue, ubyte4 valueLength);
MOC_EXTERN MSTATUS
HTTP_COMMON_setHeader(httpContext *pHttpContext,
                      ubyte4 index, ubyte* pValue, ubyte4 valueLength,
                      intBoolean overwrite);
#endif /* __HTTP_COMMON_HEADER__ */
