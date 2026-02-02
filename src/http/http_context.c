/*
 * http_context.c
 *
 * HTTP Context
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

#include "../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_HTTP_CLIENT__) || defined(__ENABLE_DIGICERT_HTTPCC_SERVER__))

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../http/http_context.h"
#include "../http/http_common.h"
#include "../http/http.h"
#ifdef __ENABLE_DIGICERT_HTTPCC_SERVER__
#include "../http/server/resmgr.h"
#endif

/*------------------------------------------------------------------*/

extern MSTATUS
HTTP_CONTEXT_createContext(httpContext **ppNewContext, sbyte4 roleType)
{
    MSTATUS status = OK;

    if (NULL == ppNewContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (*ppNewContext = MALLOC(sizeof(httpContext))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    DIGI_MEMSET((ubyte *)(*ppNewContext), 0x00, sizeof(httpContext));

    (*ppNewContext)->roleType = roleType;

exit:
    return status;
}

extern MSTATUS
HTTP_CONTEXT_resetContext(httpContext *pHttpContext)
{
    pHttpContext->headerDataIndex = 0;
    pHttpContext->httpCount.eolState = http_eol_none;
    if (pHttpContext->roleType == HTTP_CLIENT)
    {
        pHttpContext->httpProcess.client.recvState = sendHttpRequestHeaderState;
    } else
    {
        pHttpContext->httpProcess.server.recvState = recvHttpMethodState;
        /* memory mgmt for resource is done through resmgr shutdown */
#ifdef __ENABLE_DIGICERT_HTTPCC_SERVER__
        if (pHttpContext->httpProcess.server.pResourceDescr)
        {
            pHttpContext->httpProcess.server.pResourceDescr = NULL;
        }
#endif
    }
    pHttpContext->isHeaderDone = FALSE;
    pHttpContext->isBodyDone = FALSE;
    pHttpContext->isChunkedEncoding = FALSE;
    pHttpContext->isBlocked = FALSE;
    if (pHttpContext->pURI)
    {
        FREE(pHttpContext->pURI);
        pHttpContext->pURI = NULL;
    }

    if (pHttpContext->pendingDataLength > 0)
    {
        FREE(pHttpContext->pPendingData);
        pHttpContext->pPendingData = NULL;
        pHttpContext->pPendingDataFree = NULL;
        pHttpContext->pendingDataLength = 0;
    }

    if (pHttpContext->receivedPendingDataLength > 0)
    {
        FREE(pHttpContext->pReceivedPendingDataFree);
        pHttpContext->pReceivedPendingDataFree = pHttpContext->pReceivedPendingData = NULL;
        pHttpContext->receivedPendingDataLength = 0;
    }
    if (pHttpContext->httpProcess.server.serverCookie)
    {
        FREE(pHttpContext->httpProcess.server.serverCookie);
        pHttpContext->httpProcess.server.serverCookie = NULL;
    }

    HTTP_CONTEXT_resetHTTPRequestHeaders(pHttpContext);
    HTTP_CONTEXT_resetHTTPResponseHeaders(pHttpContext);

    return OK;
}

extern MSTATUS
HTTP_CONTEXT_resetHTTPRequestHeaders(httpContext *pHttpContext)
{
    ubyte4 i;

    pHttpContext->pMethodDescr = NULL;

    for ( i = 0; i < HTTP_SUPPORTED_REQUESTS; i++)
    {
        if (pHttpContext->requestBitmask[i / 8] & (1 << (i & 7)))
        {
            HTTP_stringDescr *stringDescr = &(pHttpContext->requests[i]);
            if (stringDescr->httpStringLength > 0 && NULL != stringDescr->pHttpString)
            {
                FREE(stringDescr->pHttpString);
                stringDescr->pHttpString = NULL;
                stringDescr->httpStringLength = 0;
            }
        }
    }
    /* reset received RequestBitmask[6] */
    DIGI_MEMSET((ubyte *)pHttpContext->requestBitmask, 0x00, sizeof(ubyte)*(HTTP_SUPPORTED_REQUESTS_SIZE));

    return OK;
}

extern MSTATUS
HTTP_CONTEXT_resetHTTPResponseHeaders(httpContext *pHttpContext)
{
    ubyte4 i;

    pHttpContext->httpStatusResponse = 0;
#ifdef __ENABLE_DIGICERT_HTTP_CLIENT__
    if (pHttpContext->reasonPhraseLength > 0)
    {
        FREE(pHttpContext->pReasonPhrase);
        pHttpContext->pReasonPhrase = NULL;
        pHttpContext->reasonPhraseLength = 0;
    }
#endif
    for ( i = 0; i < HTTP_SUPPORTED_RESPONSES; i++)
    {
        if (pHttpContext->responseBitmask[i / 8] & (1 << (i & 7)))
        {
            HTTP_stringDescr *stringDescr = &(pHttpContext->responses[i]);
            if (stringDescr->httpStringLength > 0 && NULL != stringDescr->pHttpString)
            {
                FREE(stringDescr->pHttpString);
                stringDescr->pHttpString = NULL;
                stringDescr->httpStringLength = 0;
            }
        }
    }
    /* reset receivedRequestBitmask[8] */
    DIGI_MEMSET((ubyte *)pHttpContext->responseBitmask, 0x00, sizeof(ubyte)*(HTTP_SUPPORTED_RESPONSES/8));


    return OK;
}

/*------------------------------------------------------------------*/

extern MSTATUS
HTTP_CONTEXT_releaseContext(httpContext **ppReleaseContext)
{
    MSTATUS status = OK;

    if ((NULL == ppReleaseContext) || (NULL == (*ppReleaseContext)))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    if (NULL != (*ppReleaseContext)->pHeaderData)
    {
        FREE((*ppReleaseContext)->pHeaderData);
        (*ppReleaseContext)->pHeaderData = NULL;
    }

    HTTP_CONTEXT_resetContext(*ppReleaseContext);

    FREE(*ppReleaseContext);
    *ppReleaseContext = NULL;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HTTP_CONTEXT_getSocket(httpContext *pHttpContext, TCP_SOCKET *pRetSocket)
{
    MSTATUS status = OK;

    if ((NULL == pHttpContext) || (NULL == pRetSocket))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pRetSocket = pHttpContext->socket;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS HTTP_CONTEXT_setSocket(httpContext *pHttpContext, TCP_SOCKET socket)
{
    MSTATUS status = OK;

    if ((NULL == pHttpContext))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

   pHttpContext->socket = socket;

exit:
    return status;
}


#endif /* (defined(__ENABLE_DIGICERT_HTTP_CLIENT__) || defined(__ENABLE_DIGICERT_HTTPCC_SERVER__)) */
