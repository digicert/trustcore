/*
 * http_context.h
 *
 * HTTP Context Header File
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

#ifndef __HTTP_CONTEXT_HEADER__
#define __HTTP_CONTEXT_HEADER__

#include "../common/mtcp.h"

/*------------------------------------------------------------------*/

/* types of roles */
#define HTTP_CLIENT             ((sbyte4) 0x8f9eadbc)
#define HTTP_SERVER             ((sbyte4) 0xcbdae9f8)

typedef struct resDescr resDescr;

enum httpClientSessionStates
{
    sendHttpRequestHeaderState,
    sendHttpRequestHeaderContinueState,
    sendHttpRequestBodyState,
    sendHttpRequestBodyContinueState,
    recvHttpStatusResponseState,
    recvHttpResponseInfoState,
    recvHttpResponseBodyState,
    finishedClientHttpState
};

enum httpClientSubStates
{
    clientSubStateInit = 0,
    c_recvChunkHeader = 1, /* chunk-size [ chunk-extension ] CRLF */
    c_recvChunkData = 2, /* chunk-data CRLF */
    c_recvChunkCRLF = 3,
    c_recvChunkLF = 4,
    c_recvTrailer = 5, /* *(entity-header CRLF) */
    finishedClientSubState = 100
};


enum httpEolState
{
    http_eol_none,  /* no cr or lf yet */
    http_eol_cr,    /* cr seen */
    http_eol_lf     /* lf seen whether cr seen before or not */
};

#define HTTP_CLIENT_STATE(X)        (X)->httpProcess.client.recvState
#define HTTP_CLIENT_SUBSTATE(X)        (X)->httpProcess.client.subState

enum httpServerSessionStates
{
    recvHttpMethodState,
    recvHttpRequestHeaderState,
    recvHttpRequestBodyState,
    recvHttpFinishedState,
    sendResponseHeader,
    sendResponseHeaderContinue,
    sendResponseBody,
    sendResponseBodyContinue,
    checkAuthentication,
    finishedServerHttpState
};

/* chunk states for server has to be different from client,
   because both client and server share the same decoding routine */
enum httpServerSubStates
{
    serverSubStateInit = 10,
    s_recvChunkHeader = 11, /* chunk-size [ chunk-extension ] CRLF */
    s_recvChunkData = 12, /* chunk-data CRLF */
    s_recvChunkCRLF = 13,
    s_recvChunkLF = 14,
    s_recvTrailer = 15, /* *(entity-header CRLF) */
    postReceiveData = 16,
    postReceiveComplete = 17,
    finishedServerSubState = 200
};

/* simple guard to prevent non-sense errors */
#define HTTP_SERVER_STATE(X)        (X)->httpProcess.server.recvState
#define HTTP_SERVER_SUBSTATE(X)        (X)->httpProcess.server.subState

#define HTTP_CLIENT_STATE(X)        (X)->httpProcess.client.recvState
#define HTTP_CLIENT_SUBSTATE(X)        (X)->httpProcess.client.subState

/* NUM_HTTP_REQUESTS(21) + NUM_HTTP_GENERALHEADERS(11) + NUM_HTTP_ENTITYHEADERS(10) */
#define HTTP_SUPPORTED_REQUESTS   (42)
#define HTTP_SUPPORTED_RESPONSES   (32)

/*  length of request header size is HTTP_SUPPORTED_REQUESTS (42) ,
 *  HTTP_SUPPORTED_REQUESTS_SIZE will be used to create bitmask array to process the http header requests (42),
 *  maximum array size for 8 bit mapping of 42 index's will be 42/8 = 5,ie array index range will be 0 to 5 */

#define HTTP_SUPPORTED_REQUESTS_SIZE   (6)

/* initial size of httpContext.pHeaderData -- dynamically resized */
#define HTTP_REQUEST_DATA_INITIAL_BUFFER_SIZE  (64)
/*------------------------------------------------------------------*/

typedef struct
{
    sbyte*  pHttpVersionName;
    ubyte4  httpVersionNameLength;
    sbyte4  isMultiRequest;
    MSTATUS(*http1_0Handler)(void);
    MSTATUS(*http1_1Handler)(void);

} HTTP_versionInfo;

typedef struct
{
    ubyte*      pHttpString;      /* one or more strings separated by NUL chars */
    ubyte4      httpStringLength; /* total length of strings */

} HTTP_stringDescr;

typedef struct
{
    sbyte*      pHttpMethodName;
    ubyte4      httpMethodNameLength;
    intBoolean  isSupported;

} HTTP_methodsInfo;

typedef struct
{
    sbyte*      pHttpRequestName;
    ubyte4      httpRequestNameLength;
    sbyte4      identifier;
    sbyte4      clone;

} HTTP_requestInfo;

typedef struct
{
    ubyte*      pUsername;
    ubyte*      pPassword;
    ubyte4      usernameLength;
    ubyte4      passwordLength;

} HTTP_authInfo;

typedef struct
{
    /* callback handler for sending data */
    TCP_SOCKET                              socket;

    intBoolean                              isBlocked;          /* blocked waiting for some external event to occur (authentication, etc)*/

    sbyte4                                  roleType;           /* client, server, etc */
    union
    {
        struct clientIncomingDataTag
        {
            enum httpClientSessionStates    recvState;          /* current state */
            enum httpClientSubStates        subState;           /* for inner state loops */

        } client;

        struct serverIncomingDataTag
        {
            enum httpServerSessionStates    recvState;          /* current state */
            enum httpServerSubStates        subState;           /* for inner state loops */

            ubyte4                          userGroupAccess;
            resDescr                        *pResourceDescr; /* resource descriptor */
            void*                           serverCookie;
        } server;

    } httpProcess;

    HTTP_methodsInfo*               pMethodDescr;

    ubyte*                                  pHeaderData;
    ubyte4                                  headerDataOffset;
    ubyte4                                  headerDataIndex;
    ubyte4                                  headerDataBufferSize;

    ubyte4                                  httpStatusResponse;
#ifdef __ENABLE_DIGICERT_HTTP_CLIENT__
    ubyte*                                  pReasonPhrase;
    ubyte4                                  reasonPhraseLength;
#endif
    byteBoolean                             isHeaderDone;
    byteBoolean                             isBodyDone;
    byteBoolean                             isChunkedEncoding;
    ubyte4                                  chunkDataLeft;
    ubyte4                                  contentLength;
    intBoolean                              indefiniteLength;
    HTTP_versionInfo*                       pHttpVersionDescr;
    sbyte*                                  pURI;
    sbyte*                                  pURIPath;

    ubyte                                   requestBitmask[HTTP_SUPPORTED_REQUESTS_SIZE];      /* upto 64 settings, used by both client and server, thus 'received' */
    HTTP_stringDescr                        requests[HTTP_SUPPORTED_REQUESTS];            /* request session context */

    ubyte                                   responseBitmask[HTTP_SUPPORTED_RESPONSES/8];      /* upto 64 settings, used by both client and server, thus 'received' */
    HTTP_stringDescr                        responses[HTTP_SUPPORTED_RESPONSES];            /* request session context */

    union
    {
        enum httpEolState                   eolState;           /* used for determining end of blocks */
        ubyte4                              runLength;          /* used for handling HTTP 1.1 requests */

    } httpCount;

    sbyte4                                  groupAccess;        /* group access permissions for user */

    ubyte*                                  pPendingDataFree;   /* ptr to buffer for free */
    ubyte*                                  pPendingData;       /* pending data for send */
    ubyte4                                  pendingDataLength;  /* number of bytes pending */

    ubyte*                                  pReceivedPendingData;       /* pending received data */
    ubyte*                                  pReceivedPendingDataFree;       /* to be freed */
    ubyte4                                  receivedPendingDataLength;  /* number of bytes pending */

    ubyte4                                  numHttpRequestProcessed;

    void *                                  httpCookie;         /* engineer assignable cookie value */

} httpContext;


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS HTTP_CONTEXT_createContext(httpContext **ppNewContext, sbyte4 roleType);
MOC_EXTERN MSTATUS HTTP_CONTEXT_resetContext(httpContext *pHttpContext);
MOC_EXTERN MSTATUS HTTP_CONTEXT_resetHTTPRequestHeaders(httpContext *pHttpContext);
MOC_EXTERN MSTATUS HTTP_CONTEXT_resetHTTPResponseHeaders(httpContext *pHttpContext);
MOC_EXTERN MSTATUS HTTP_CONTEXT_releaseContext(httpContext **ppReleaseContext);
MOC_EXTERN MSTATUS HTTP_CONTEXT_getSocket(httpContext *pHttpContext, TCP_SOCKET *pRetSocket);
MOC_EXTERN MSTATUS HTTP_CONTEXT_setSocket(httpContext *pHttpContext, TCP_SOCKET socket);

#endif /* __HTTP_CONTEXT_HEADER__ */
