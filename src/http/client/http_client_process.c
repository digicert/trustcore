/*
 * http_client_process.c
 *
 * HTTP Client Process
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
#include "../../http/http_transfer_coding.h"
#include "../../http/client/http_request.h"
#include "../../http/client/http_client_process.h"

/*------------------------------------------------------------------*/

extern MSTATUS
HTTP_CLIENT_PROCESS_initProcess(httpContext *pHttpContext)
{
    MSTATUS status = OK;

    if (NULL == pHttpContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pHttpContext->httpProcess.client.recvState = sendHttpRequestHeaderState;

    if (NULL == pHttpContext->pHeaderData)
    {
        pHttpContext->pHeaderData =
            MALLOC(HTTP_REQUEST_DATA_INITIAL_BUFFER_SIZE);

        if (NULL == pHttpContext->pHeaderData)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        pHttpContext->headerDataBufferSize =
            HTTP_REQUEST_DATA_INITIAL_BUFFER_SIZE;
    }

    pHttpContext->headerDataIndex = 0;
    pHttpContext->httpCount.eolState = http_eol_none;
    pHttpContext->httpStatusResponse = 0;

exit:
    return status;
}


/*------------------------------------------------------------------*/

static intBoolean HTTP_IsSpaceChar( ubyte c)
{
    return ('\x20' == c || '\x09' == c) ? TRUE: FALSE;
}


/*------------------------------------------------------------------*/

static MSTATUS
parseStatusLine(httpContext *pHttpContext, ubyte *pData, ubyte4 dataLength)
{
    MSTATUS             status;
    ubyte4              offset = 0;

    /* HTTP/1.1:
     * Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase CRLF
     * extension-code = 3DIGIT
     * Reason-Phrase  = *<TEXT, excluding CR, LF>
     */

    /* parse out http version string */
    if (OK > (status = HTTP_COMMON_lookupVersion(pData, dataLength, &(pHttpContext->pHttpVersionDescr))))
        goto exit;

    if (NULL == pHttpContext->pHttpVersionDescr)
    {
        /* unknown version */
        status = ERR_HTTP;
        goto exit;
    }

    dataLength = dataLength - ( pHttpContext->pHttpVersionDescr->httpVersionNameLength +1); /* skip SP */
    pData = pData + (pHttpContext->pHttpVersionDescr->httpVersionNameLength +1);

    /* parse three digit status code */
    if (OK > (status = HTTP_COMMON_lookupStatusCode(pData, dataLength, &(pHttpContext->httpStatusResponse))))
        goto exit;

    /* is there more data than just a method? */
    /* dataLength should be at least 4 bytes: 3DIGIT + SP */
    if (3 + 1 > dataLength)
    {
        /* bad request */
        status = ERR_HTTP;
        goto exit;
    }
    else if (3 + 1 == dataLength)
    {
        /* no Reason-Phrase */
        pHttpContext->pReasonPhrase = NULL;
        pHttpContext->reasonPhraseLength = 0;
        goto exit;
    }

    /* parse reasonPhrase */
    dataLength = dataLength - 4; /* skip statusCode, plus trailing space */
    pData += 4;

    /* determine length of reasonPhrase */
    /* record reasonPhrase in httpContext */
    while ((0 < dataLength) &&
        (('\x0D' < *(pData+offset)) || ('\x0A' < *(pData+offset))))
    {
        dataLength--;
        offset++;
    }
    pHttpContext->pReasonPhrase = (ubyte*)MALLOC(offset);
    if (!pHttpContext->pReasonPhrase)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    if (OK > (status = DIGI_MEMCPY(pHttpContext->pReasonPhrase, pData, offset)))
        goto exit;
    pHttpContext->reasonPhraseLength = offset;
exit:

    return status;

} /* parseStatusLine */

/*------------------------------------------------------------------*/

static MSTATUS
parseResponseInfo(httpContext *pHttpContext, ubyte *pData, ubyte4 dataLength)
{
    ubyte*              pResponseString = NULL;
    HTTP_requestInfo*   pResponseDescr  = NULL;
    ubyte4              index;
    MSTATUS             status;

    /* error, or nothing to do */
    if ((OK > (status = HTTP_COMMON_lookupResponseInfo(pData, dataLength, &pResponseDescr, &index))) ||
        (NULL == pResponseDescr))
        goto exit;

    pData = pData + pResponseDescr->httpRequestNameLength;
    dataLength = dataLength - pResponseDescr->httpRequestNameLength;

    /* make sure there is more than a colon and space */
    if (    (dataLength <= 2) ||
            (':' != *pData) ||
            !HTTP_IsSpaceChar(*(pData+1)) )
    {
        goto exit;
    }

    /* skip past colon and space */
    pData = pData + 2;
    dataLength = dataLength - 2;
    while (HTTP_IsSpaceChar(*pData) && dataLength > 0)
    {
        pData++;
        dataLength--;
    }

    /* make sure request bit is not already set */
    if (0 == (pHttpContext->responseBitmask[index / 8] & (1 << (index & 7))))
    {
        /* set bit for request context */
        pHttpContext->responseBitmask[index / 8] |= (1 << (index & 7));

        /* if set, clone request header field */
        if (HTTP_SAVE == pResponseDescr->clone)
        {
            /* clone it */
            if (NULL == (pResponseString = MALLOC(dataLength + 1)))
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            /* release memory when resetHttpContext */
            DIGI_MEMCPY(pResponseString, pData, dataLength);
            pResponseString[dataLength] = 0;

            /* store result */
            pHttpContext->responses[index].pHttpString = pResponseString;
            pHttpContext->responses[index].httpStringLength = dataLength;
        }
    }
    else /* allow duplicate headers -- might want to add a flag to HTTP_requestInfo to restrict that
            for some of the entries*/
    {
        /* if set, clone request header field */
        if (HTTP_SAVE == pResponseDescr->clone)
        {
            HTTP_stringDescr* pPrevStringVal = pHttpContext->responses+index;

            /* clone it */
            if (NULL == (pResponseString = MALLOC(dataLength + 1 + pPrevStringVal->httpStringLength)))
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            /* concatenate prev value with new value separated by a 0 char */
            DIGI_MEMCPY(pResponseString, pPrevStringVal->pHttpString,
                    pPrevStringVal->httpStringLength);
            pResponseString[pPrevStringVal->httpStringLength] = 0;
            DIGI_MEMCPY(pResponseString + pPrevStringVal->httpStringLength + 1,
                        pData, dataLength);

            /* store result */
            FREE( pHttpContext->responses[index].pHttpString);
            pHttpContext->responses[index].pHttpString = pResponseString;
            pHttpContext->responses[index].httpStringLength += 1 + dataLength;
        }
    }

exit:

    return status;

} /* parseResponseInfo */

/*------------------------------------------------------------------*/

extern intBoolean
HTTP_CLIENT_PROCESS_isDoneSendingRequest(httpContext *pHttpContext)
{
    return (HTTP_CLIENT_STATE(pHttpContext) >= recvHttpStatusResponseState);
}

/*------------------------------------------------------------------*/

extern MSTATUS
HTTP_CLIENT_PROCESS_receiveResponse(httpContext *pHttpContext,
                          ubyte *pData, ubyte4 dataLength,
                          intBoolean isContinueFromBlock)
{
    sbyte4  lineResult;
    MSTATUS status = OK;
    byteBoolean isDone = FALSE;

    if ((NULL == pHttpContext) ||
        (HTTP_CLIENT_STATE(pHttpContext) >= recvHttpStatusResponseState && !pData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* case where the server close the connection before sending the whole content */
    if ((0 >= dataLength ) && (HTTP_CLIENT_STATE(pHttpContext) >= recvHttpStatusResponseState) && (FALSE == isContinueFromBlock))
    {
        /* maybe it was an indefinite length ? then we are done */
        if ( recvHttpResponseBodyState == HTTP_CLIENT_STATE( pHttpContext) &&
                pHttpContext->indefiniteLength )
        {
            HTTP_CLIENT_STATE(pHttpContext) = finishedClientHttpState;
            status = HTTP_DONE;
            goto exit;
        }
        /* otherwise error */
        status = ERR_HTTP_RECV_LENGTH;
        goto exit;
    }

    do
    {

        switch (HTTP_CLIENT_STATE(pHttpContext))
        {
        case sendHttpRequestHeaderState:

            /* build request header */
            if (OK > (status = HTTP_REQUEST_formRequestHeader(pHttpContext, &pHttpContext->pPendingDataFree, &pHttpContext->pendingDataLength)))
                goto exit;

            pHttpContext->isHeaderDone = TRUE;
            HTTP_TRANSFER_CODING_isChunked(pHttpContext);
            if ( (pHttpContext->pMethodDescr->pHttpMethodName != mHttpMethods[POST].pHttpMethodName) &&
                 (pHttpContext->pMethodDescr->pHttpMethodName != mHttpMethods[PUT].pHttpMethodName) )
            {
                pHttpContext->isBodyDone = TRUE;
            }
            pHttpContext->pPendingData = pHttpContext->pPendingDataFree;
            HTTP_CLIENT_STATE(pHttpContext) = sendHttpRequestHeaderContinueState;
            /* fall through to the next state */

        case sendHttpRequestHeaderContinueState:
            /* send request */
            if (pHttpContext->pendingDataLength > 0)
            {
                ubyte4 numBytesWritten = 0;

                /* do not fail silently if the callback is NULL ! */
                if ( ! HTTP_httpSettings()->funcPtrHttpTcpSend)
                {
                    status = ERR_HTTP_SEND_CALLBACK_NULL;
                    goto exit;
                }

                if (OK > (status = HTTP_httpSettings()->funcPtrHttpTcpSend(pHttpContext, pHttpContext->socket,
                    pHttpContext->pPendingData, pHttpContext->pendingDataLength,
                    &numBytesWritten, isContinueFromBlock)) )
                    goto exit;

                if (numBytesWritten > pHttpContext->pendingDataLength)
                {
                    status = ERR_HTTP_SEND_CALLBACK_OVERRUN;
                    goto exit;
                }

                pHttpContext->pPendingData      += numBytesWritten;
                pHttpContext->pendingDataLength -= numBytesWritten;
                if (0 == pHttpContext->pendingDataLength)
                {
                    FREE(pHttpContext->pPendingDataFree);
                    pHttpContext->pPendingDataFree = pHttpContext->pPendingData = NULL;
                }
            }

            if (pHttpContext->isHeaderDone && 0 == pHttpContext->pendingDataLength)
            {
                HTTP_CLIENT_STATE(pHttpContext) = sendHttpRequestBodyState;
            }
            break;

        case sendHttpRequestBodyState:
            HTTP_CLIENT_STATE(pHttpContext) = sendHttpRequestBodyContinueState;
            /* fall through */
        case sendHttpRequestBodyContinueState:
            /* callback for POST */
            if (!pHttpContext->isBodyDone &&
                0 == pHttpContext->pendingDataLength &&
                ( (pHttpContext->pMethodDescr->pHttpMethodName == mHttpMethods[POST].pHttpMethodName) ||
                  (pHttpContext->pMethodDescr->pHttpMethodName == mHttpMethods[PUT].pHttpMethodName) ) )
            {
                void *cookie;
                if (OK > (status = HTTP_getCookie(pHttpContext, &cookie)))
                    goto exit;

                if (NULL == HTTP_httpSettings()->funcPtrRequestBodyCallback)
                {
                    status = ERR_HTTP_SEND_CALLBACK_NULL;
                    goto exit;
                }

                if (OK > (status = HTTP_httpSettings()->funcPtrRequestBodyCallback(pHttpContext,
                    &pHttpContext->pPendingDataFree, &pHttpContext->pendingDataLength, (void*)cookie)))
                    goto exit;

                /* encode with chunkedEncoding if ContentLength is not set */
                if (pHttpContext->pendingDataLength > 0)
                {
                    if (pHttpContext->isChunkedEncoding)
                    {
                        ubyte *dataToSend = NULL;
                        ubyte4 dataLengthTemp = 0;
                        /* if isDone, send last chunk; else send normal chunk */
                        if (OK > (status = HTTP_TRANSFER_CODING_encodeChunked(pHttpContext, &dataToSend, &dataLengthTemp, pHttpContext->isBodyDone)))
                        {
                            if (NULL != dataToSend)
                            {
                                (void) DIGI_FREE((void**) &dataToSend);
                            }
                            goto exit;
                        }
                        if (pHttpContext->pPendingDataFree)
                        {
                            FREE(pHttpContext->pPendingDataFree);
                            pHttpContext->pPendingData = pHttpContext->pPendingDataFree = NULL;
                            pHttpContext->pendingDataLength = 0;
                        }
                        pHttpContext->pPendingData = pHttpContext->pPendingDataFree = dataToSend;
                        pHttpContext->pendingDataLength = dataLengthTemp;
                        dataToSend = NULL;
                        dataLengthTemp = 0;
                    } else
                    {
                        pHttpContext->pPendingData = pHttpContext->pPendingDataFree;
                    }
                }
            }

            /* send request */
            if (pHttpContext->pendingDataLength > 0)
            {
                ubyte4 numBytesWritten = 0;

                if ( ! HTTP_httpSettings()->funcPtrHttpTcpSend)
                {
                    status = ERR_HTTP_SEND_CALLBACK_NULL;
                    goto exit;
                }

                if (pHttpContext->pendingDataLength > 0)
                {
                    if (OK > (status = HTTP_httpSettings()->funcPtrHttpTcpSend(pHttpContext, pHttpContext->socket,
                        pHttpContext->pPendingData, pHttpContext->pendingDataLength,
                        &numBytesWritten, isContinueFromBlock)) )
                        goto exit;

                    if (numBytesWritten > pHttpContext->pendingDataLength)
                    {
                        status = ERR_HTTP_SEND_CALLBACK_OVERRUN;
                        goto exit;
                    }

                    pHttpContext->pPendingData      += numBytesWritten;
                    pHttpContext->pendingDataLength -= numBytesWritten;
                    if (0 == pHttpContext->pendingDataLength)
                    {
                        FREE(pHttpContext->pPendingDataFree);
                        pHttpContext->pPendingDataFree = pHttpContext->pPendingData = NULL;
                    }
                }
            }
            if (pHttpContext->isBodyDone && 0 == pHttpContext->pendingDataLength)
            {
                HTTP_CLIENT_STATE(pHttpContext) = recvHttpStatusResponseState;
            }
            break;
            case recvHttpStatusResponseState:
            {
                /* receive status line */
                if (OK > (status = HTTP_COMMON_copyRequest(pHttpContext, &pData, &dataLength, &lineResult)))
                    continue;

                if (HTTP_LINE_DONE == lineResult)
                {
                    if (OK > (status = parseStatusLine(pHttpContext, pHttpContext->pHeaderData, pHttpContext->headerDataIndex)))
                        goto exit;

                    HTTP_CLIENT_STATE(pHttpContext) = recvHttpResponseInfoState;

                    pHttpContext->httpCount.eolState = http_eol_none;
                    pHttpContext->headerDataIndex = 0;
                }
                else if (HTTP_LINE_EMPTY == lineResult)
                    status = ERR_HTTP_MALFORMED_MESSAGE;
                else if (0 < dataLength)
                    status = ERR_HTTP_BAD_STATE_CHANGE;

                break;
            }

            case recvHttpResponseInfoState:
            {
                /* receive response header fields */
                if (OK > (status = HTTP_COMMON_copyRequest(pHttpContext, &pData, &dataLength, &lineResult)))
                    continue;

                if (HTTP_LINE_DONE == lineResult)
                {
                    if (OK > (status = parseResponseInfo(pHttpContext, pHttpContext->pHeaderData, pHttpContext->headerDataIndex)))
                        goto exit;

                    pHttpContext->httpCount.eolState = http_eol_none;
                    pHttpContext->headerDataIndex = 0;

                    break;
                }
                else if (HTTP_LINE_EMPTY != lineResult)
                {
                    if (0 < dataLength)
                        status = ERR_HTTP_BAD_STATE_CHANGE;

                    break;
                }
                else /* HTTP_LINE_EMPTY == lineResult */
                {
                    HTTP_CLIENT_STATE(pHttpContext) = recvHttpResponseBodyState;
                    pHttpContext->httpCount.eolState = http_eol_none;
                    pHttpContext->headerDataIndex = 0;

                    HTTP_TRANSFER_CODING_isChunked(pHttpContext);
                    if (pHttpContext->isChunkedEncoding)
                    {
                        HTTP_CLIENT_SUBSTATE(pHttpContext) = c_recvChunkHeader;
                    }
                    else
                    {
                        sbyte4 contentLength = HTTP_COMMON_getContentLength(pHttpContext);
                        if (contentLength < 0)
                        {
                            pHttpContext->indefiniteLength = TRUE;
                        }
                        else
                        {
                            pHttpContext->indefiniteLength = FALSE;
                            pHttpContext->contentLength = (ubyte4) contentLength;
                        }
                    }

                    if (NULL == HTTP_httpSettings()->funcPtrResponseHeaderCallback)
                    {
                        status = ERR_HTTP_SEND_CALLBACK_NULL;
                        goto exit;
                    }

                    HTTP_httpSettings()->funcPtrResponseHeaderCallback(pHttpContext, (sbyte4)isContinueFromBlock);
                    /* fall thru to next state... */
                    if ( 0 == dataLength && pHttpContext->indefiniteLength)
                        break;
                }
            }

            case recvHttpResponseBodyState:
            {
                if (dataLength > 0)
                {
                    /* is tranfer-encoding set to chunked? */
                    if (pHttpContext->isChunkedEncoding) {
                        if ( OK > (status = HTTP_TRANSFER_CODING_decodeChunked(pHttpContext, &pData, &dataLength, &isDone)))
                        {
                            goto exit;
                        }
                    }
                    else
                    {
                        if (pHttpContext->indefiniteLength)
                        {
                            if (NULL == HTTP_httpSettings()->funcPtrResponseBodyCallback)
                            {
                                status = ERR_HTTP_SEND_CALLBACK_NULL;
                                goto exit;
                            }

                            if (OK > (status = HTTP_httpSettings()->funcPtrResponseBodyCallback(pHttpContext, pData, dataLength, (sbyte4)isContinueFromBlock)))
                            {
                                 goto exit;
                            }
                            pData += dataLength;
                            dataLength = 0;
                        }
                        else
                        {
                            if (NULL == HTTP_httpSettings()->funcPtrResponseBodyCallback)
                            {
                                status = ERR_HTTP_SEND_CALLBACK_NULL;
                                goto exit;
                            }

                            pHttpContext->contentLength -= dataLength;
                            if (OK > (status = HTTP_httpSettings()->funcPtrResponseBodyCallback(pHttpContext, pData, dataLength, (sbyte4)isContinueFromBlock)))
                            {
                                goto exit;
                            }
                            pData += dataLength;
                            dataLength = 0;
                            if (pHttpContext->contentLength == 0)
                            {
                                isDone = TRUE;
                            }
                        }
                    }
                }
                else /* no data  left in packet */
                {
                    if (!pHttpContext->isChunkedEncoding && pHttpContext->contentLength == 0 )
                    {
                        isDone = TRUE;
                    }
                }
                /* we are done either
                 * 1. received data length equals the content-length;
                 * or 2. when transfer-encoding is chunked, we've seen the last chunk
                 */
                if (isDone)
                {
                    HTTP_CLIENT_STATE(pHttpContext) = finishedClientHttpState;
                    status = HTTP_DONE;
                    /* continue to finishedClientHttpState */
                } else
                {
                    break;
                }
            }
            case finishedClientHttpState:
            {
                /* pHttpContext->numHttpRequestProcessed++;

                if (TRUE == pHttpContext->pHttpVersionDescr->isMultiRequest)
                {
                     if HTTP/1.1+, reset for looping
                    pHttpContext->headerDataIndex = 0;
                    pHttpContext->httpCount.numCRLF = 0;
                    pHttpContext->httpStatusResponse = 0;

                    !!!! more stuff most likely needs to be reset

                    HTTP_CLIENT_STATE(pHttpContext) = recvHttpStatusResponseState;
                } */
                isDone = FALSE;
                break;
            }

            default:
            {
                /* received data in an unexpected state */
                status = ERR_HTTP_BAD_STATE_CHANGE;
                break;
            }
        }
    }
    while ((OK == status) && ((0 < dataLength) || (HTTP_CLIENT_STATE(pHttpContext) < recvHttpStatusResponseState)) && (FALSE == pHttpContext->isBlocked));

exit:
    return status;

} /* HTTP_CLIENT_PROCESS_receiveResponse */

#endif /* __ENABLE_DIGICERT_HTTP_CLIENT__ */
