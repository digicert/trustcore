/*
 * http_transfer_coding.c
 *
 * HTTP Transfer-Coding
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
#define HTTP_SERVER_FILE

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../common/mstdlib.h"
#include "../http/http_context.h"
#include "../http/http_common.h"
#include "../http/http.h"
#include "../http/http_transfer_coding.h"

#define MAX_CHUNKHEADERSIZE 20

/*------------------------------------------------------------------*/

extern MSTATUS
HTTP_TRANSFER_CODING_isChunked(httpContext *pHttpContext)
{
    MSTATUS status = OK;
    ubyte4 index = 0;
    ubyte *headerBitmask;
    HTTP_stringDescr *headers;

    if (!pHttpContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pHttpContext->isChunkedEncoding = FALSE;

    /* transfer-encoding is in m_HttpGeneralHeaders */
    if (pHttpContext->roleType == HTTP_CLIENT && recvHttpStatusResponseState <= HTTP_CLIENT_STATE(pHttpContext))
    {
        index = NUM_HTTP_RESPONSES + TransferEncoding;
        headerBitmask = pHttpContext->responseBitmask;
        headers = pHttpContext->responses;
    } else
    {
        index = NUM_HTTP_REQUESTS + TransferEncoding;
        headerBitmask = pHttpContext->requestBitmask;
        headers = pHttpContext->requests;
    }

    if ((headerBitmask[index/8] & (1 << (index & 7))) &&
        headers[index].httpStringLength > 0)
    {
        pHttpContext->isChunkedEncoding = HTTP_COMMON_subStringMatch(headers[index].pHttpString,
            headers[index].httpStringLength,
            (sbyte*)"chunked", 7);

    }
exit:
    return status;
}

/*------------------------------------------------------------------*/

/* NOTE: chunk extension is ignored */
static MSTATUS
HTTP_TRANSFER_CODING_parseChunkHeader(httpContext *pHttpContext, ubyte *pData, ubyte4 dataLength, ubyte4* pChunkSize)
{
    MSTATUS status = OK;
    ubyte* chunkSizeStr;
    ubyte4 len = 0, i;
    /* init chunkSize */
    (*pChunkSize) = 0;

    chunkSizeStr = (ubyte*)MALLOC(20);
    if (!chunkSizeStr)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    while (DIGI_ISXDIGIT(*(pData+len)) && len <dataLength )
    {
        *(chunkSizeStr+len) = *(pData+len);
        len++;
    }
    /* converting hex string to decimal number */
    for (i = 0; i < len; i++)
    {
        ubyte ch = *(chunkSizeStr+i);
        ubyte4 val = 0;
        switch (ch)
        {
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
            val = ch - '0';
            break;
        case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
            val = ch - 'a' + 10;
            break;
        case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
            val = ch - 'A' + 10;
            break;
        default:
            /* shouldn't happen */
            ;
        }
        (*pChunkSize) = ((*pChunkSize) << 4) + val;
    }
exit:
    if (chunkSizeStr)
    {
        FREE(chunkSizeStr);
    }
    return status;

} /* parseChunkHeader */

/*------------------------------------------------------------------*/
/* using a state machine to decode chunked transfercoding */
extern MSTATUS
HTTP_TRANSFER_CODING_decodeChunked(httpContext *pHttpContext, ubyte **ppData, ubyte4* pDataLength, byteBoolean *pIsDone)
{
    MSTATUS status = OK;
    sbyte4  lineResult;
    ubyte4 len;

    /* decode chunked body */
    switch (pHttpContext->roleType == HTTP_SERVER ? HTTP_SERVER_SUBSTATE(pHttpContext) : HTTP_CLIENT_SUBSTATE(pHttpContext))
    {
    case c_recvChunkHeader:
    case s_recvChunkHeader:
        /* receive chunk header: chunk-size [ chunk-extension ] CRLF */
        if (OK > (status = HTTP_COMMON_copyRequest(pHttpContext, ppData, pDataLength, &lineResult)))
            break;

        if (HTTP_LINE_DONE == lineResult)
        {
            if (OK > (status = HTTP_TRANSFER_CODING_parseChunkHeader(pHttpContext, pHttpContext->pHeaderData,
                                                                        pHttpContext->headerDataIndex,
                                                                        &pHttpContext->chunkDataLeft)))
            {
                goto exit;
            }
            pHttpContext->httpCount.eolState = http_eol_none;
            pHttpContext->headerDataIndex = 0;

            /* last chunk is indicated by size 0 */
            if ( 0 == pHttpContext->chunkDataLeft)
            {
                if (pHttpContext->roleType == HTTP_SERVER)
                {
                    HTTP_SERVER_SUBSTATE(pHttpContext) = s_recvTrailer;
                }
                else
                {
                    HTTP_CLIENT_SUBSTATE(pHttpContext) = c_recvTrailer;
                }
            }
            else
            {
                if (pHttpContext->roleType == HTTP_SERVER)
                {
                    HTTP_SERVER_SUBSTATE(pHttpContext) = s_recvChunkData;
                }
                else
                {
                    HTTP_CLIENT_SUBSTATE(pHttpContext) = c_recvChunkData;
                }
            }
        }
        else if (HTTP_LINE_EMPTY == lineResult)
        {
            status = ERR_HTTP_MALFORMED_MESSAGE;
            goto exit;
        }
        else if (0 < *pDataLength)
        {
            status = ERR_HTTP_BAD_STATE_CHANGE;
            goto exit;
        }
        break;

    case c_recvChunkData:
    case s_recvChunkData:
        len = (*pDataLength) > pHttpContext->chunkDataLeft? pHttpContext->chunkDataLeft : (*pDataLength);
        HTTP_httpSettings()->funcPtrResponseBodyCallback(pHttpContext, *ppData, len, (sbyte4)FALSE);
        (*ppData) += len;
        (*pDataLength) -= len;
        pHttpContext->chunkDataLeft -= len;

        if (0 == pHttpContext->chunkDataLeft)
        {
            if (pHttpContext->roleType == HTTP_SERVER)
            {
                HTTP_SERVER_SUBSTATE(pHttpContext) = s_recvChunkCRLF;
            } else
            {
                HTTP_CLIENT_SUBSTATE(pHttpContext) = c_recvChunkCRLF;
            }
        }
        break;

    case s_recvChunkCRLF:
    case c_recvChunkCRLF:
        /* read a single CR */
        if (*pDataLength >= 1)
        {
            if (MOC_CR == **ppData)
            {
                (*ppData) += 1;
                (*pDataLength) -= 1;
                if (pHttpContext->roleType == HTTP_SERVER)
                {
                    HTTP_SERVER_SUBSTATE(pHttpContext) = s_recvChunkLF;
                }
                else
                {
                    HTTP_CLIENT_SUBSTATE(pHttpContext) = c_recvChunkLF;
                }
            }
            else /* don't accept LF here cf RFC 2616 */
            {
                status = ERR_HTTP_MALFORMED_MESSAGE;
                goto exit;
            }
        }
        break;

    case s_recvChunkLF:
    case c_recvChunkLF:
        if (*pDataLength >= 1)
        {
            if (LF == **ppData)
            {
                (*ppData) += 1;
                (*pDataLength) -= 1;
                if (pHttpContext->roleType == HTTP_SERVER)
                {
                    HTTP_SERVER_SUBSTATE(pHttpContext) = s_recvChunkHeader;
                }
                else
                {
                    HTTP_CLIENT_SUBSTATE(pHttpContext) = c_recvChunkHeader;
                }
            }
            else /* don't accept any other character here cf RFC 2616 */
            {
                status = ERR_HTTP_MALFORMED_MESSAGE;
                goto exit;
            }
       }
       break;

    case c_recvTrailer:
    case s_recvTrailer:
        if (OK > (status = HTTP_COMMON_copyRequest(pHttpContext, ppData, pDataLength, &lineResult)))
            break;

        if (HTTP_LINE_EMPTY == lineResult)
        {
             (*pIsDone) = TRUE;
            if (pHttpContext->roleType == HTTP_SERVER)
            {
                HTTP_SERVER_SUBSTATE(pHttpContext) = finishedServerSubState;
            }
            else
            {
                HTTP_CLIENT_SUBSTATE(pHttpContext) = finishedClientSubState;
            }
        }
        break;


    default:
        status = ERR_HTTP_BAD_STATE;
        goto exit;
    }
exit:
    return status;
} /* decodeChunkedTransferCoding */

/*------------------------------------------------------------------*/
static MSTATUS
HTTP_TRANSFER_CODING_writeChunkHeader(ubyte4 dataLength, ubyte4 *chunkHeaderLen, ubyte* destBuf)
{
    MSTATUS status;
    ubyte4 remainder = dataLength;
    ubyte digit;
    ubyte chunksize[MAX_CHUNKHEADERSIZE];
    ubyte4 offset = MAX_CHUNKHEADERSIZE - 1;
    while (remainder > 0)
    {
        digit = remainder & 0x0f;

        if (0x0a > digit)
            chunksize[offset--] = (ubyte)(digit + '0');
        else
            chunksize[offset--] = (ubyte)((digit - 10) + 'a');
        if ((MAX_CHUNKHEADERSIZE - 1) < offset)
        {
            status = ERR_HTTP_BUFFER_OVERFLOW;
            goto exit;
        }
        remainder >>= 4;
    }
    offset++;
    *chunkHeaderLen = MAX_CHUNKHEADERSIZE - offset;
    if (OK > (status = DIGI_MEMCPY(destBuf, chunksize+offset, (*chunkHeaderLen))))
        goto exit;
    if (OK > (status = DIGI_MEMCPY(destBuf + (*chunkHeaderLen), CRLF, 2)))
        goto exit;
    *chunkHeaderLen += 2;
exit:
    return status;

}

/*------------------------------------------------------------------*/
extern MSTATUS
HTTP_TRANSFER_CODING_encodeChunked(httpContext *pHttpContext,  ubyte** ppDataToSend, ubyte4 *pDataLength, byteBoolean isDone)
{
    MSTATUS status = OK;
    ubyte4 chunkHeaderLen;
    ubyte   *pData = NULL;
    ubyte   *pPendingData = NULL;

    /* total buffer size is dataLength + (chunkheader size) + (ending CRLF) */
    if (pHttpContext->pendingDataLength == 0 && isDone)
        goto done;

    if (NULL == (*ppDataToSend = (ubyte*)MALLOC(pHttpContext->pendingDataLength + MAX_CHUNKHEADERSIZE +2)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    pPendingData = pHttpContext->pPendingDataFree;

    pData = *ppDataToSend;
    *pDataLength = 0;

    if (OK > (status = HTTP_TRANSFER_CODING_writeChunkHeader(pHttpContext->pendingDataLength, &chunkHeaderLen, pData)))
        goto exit;

    pData += chunkHeaderLen;
    *pDataLength += chunkHeaderLen;

    if (OK > (status = DIGI_MEMCPY(pData, pPendingData, pHttpContext->pendingDataLength)))
        goto exit;
    pData += pHttpContext->pendingDataLength;
    *pDataLength += pHttpContext->pendingDataLength;

    if (OK > (status = DIGI_MEMCPY(pData, CRLF,2)))
        goto exit;
    pData += 2;
    *pDataLength += 2;

done:
    /* create the last chunk: last-chunk = 1*("0") [ chunk-extension] CRLF */
    if (isDone)
    {
        if (*ppDataToSend == NULL)
        {
            if (NULL == (*ppDataToSend = (ubyte*)MALLOC(1+2+2)))
            {
                status = ERR_MEM_ALLOC_FAIL;
                goto exit;
            }
            pData = *ppDataToSend;
        }
        if (OK > (status = DIGI_MEMCPY(pData, "\x00", 1)))
            goto exit;
        pData += 1;
        *pDataLength += 1;
        if (OK > (status = DIGI_MEMCPY(pData, CRLF,2)))
            goto exit;
        pData += 2;
        *pDataLength += 2;
        if (OK > (status = DIGI_MEMCPY(pData, CRLF,2)))
            goto exit;
        *pDataLength += 2;

    }

exit:
    return status;

}


#endif /* (defined(__ENABLE_DIGICERT_HTTP_CLIENT__) || defined(__ENABLE_DIGICERT_HTTPCC_SERVER__)) */
