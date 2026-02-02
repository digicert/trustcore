/*
 * http_common.c
 *
 * HTTP Common
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
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/mtcp.h"
#include "../http/http_context.h"
#include "../http/http_common.h"
#include "../http/http.h"


/*------------------------------------------------------------------*/

static HTTP_versionInfo mHttpVersions[] =
{
    { (sbyte*)"HTTP/1.0", 8, FALSE, NULL, NULL },
    { (sbyte*)"HTTP/1.1", 8, TRUE,  NULL, NULL }
};

#define NUM_HTTP_VERSIONS   (sizeof(mHttpVersions)/sizeof(HTTP_versionInfo))


/*------------------------------------------------------------------*/

HTTP_methodsInfo mHttpMethods[] =
{
    { (sbyte*)"OPTIONS", 7, FALSE },
    { (sbyte*)"GET",     3, TRUE  },
    { (sbyte*)"HEAD",    4, FALSE },
    { (sbyte*)"POST",    4, TRUE },
    { (sbyte*)"PUT",     3, FALSE },
    { (sbyte*)"DELETE",  6, FALSE },
    { (sbyte*)"TRACE",   5, FALSE },
    { (sbyte*)"CONNECT", 7, TRUE }
};

/*------------------------------------------------------------------*/
HTTP_requestInfo mHttpRequests[] =
{
    /* store request header fields in reverse alphabet order */
    { (sbyte*)"User-Agent",          10, __LINE__, HTTP_SAVE },
    { (sbyte*)"TE",                  2,  __LINE__, HTTP_SAVE },
    { (sbyte*)"Referer",             7,  __LINE__, HTTP_SAVE },
    { (sbyte*)"Range",               5,  __LINE__, HTTP_SAVE },
    { (sbyte*)"Proxy-Authorization", 19, __LINE__, HTTP_SAVE },
    { (sbyte*)"Max-Forwards",        12, __LINE__, HTTP_SAVE },
    { (sbyte*)"If-Unmodified-Since", 19, __LINE__, HTTP_SAVE },
    { (sbyte*)"If-Range",            8,  __LINE__, HTTP_SAVE },
    { (sbyte*)"If-None-Match",       13, __LINE__, HTTP_SAVE },
    { (sbyte*)"If-Modified-Since",   17, __LINE__, HTTP_SAVE },
    { (sbyte*)"If-Match",            8,  __LINE__, HTTP_SAVE },
    { (sbyte*)"Host",                4,  __LINE__, HTTP_SAVE },
    { (sbyte*)"From",                4,  __LINE__, HTTP_DROP },
    { (sbyte*)"Expect",              6,  __LINE__, HTTP_SAVE },
    { (sbyte*)"Authorization",       13, __LINE__, HTTP_SAVE },
    { (sbyte*)"Accept-Language",     15, __LINE__, HTTP_SAVE },
    { (sbyte*)"Accept-Encoding",     15, __LINE__, HTTP_SAVE },
    { (sbyte*)"Accept-Charset",      14, __LINE__, HTTP_SAVE },
    { (sbyte*)"Accept",              6,  __LINE__, HTTP_SAVE },
    { (sbyte*)"X-API-Key",           9,  __LINE__, HTTP_SAVE },
    { (sbyte*)"Proxy-Connection",    16, __LINE__, HTTP_SAVE }
};

HTTP_requestInfo mHttpResponses[] =
{
    /* store request header fields in reverse alphabet order */
    { (sbyte*)"WWW-Authenticate",   16, __LINE__, HTTP_SAVE },
    { (sbyte*)"Vary",               4,  __LINE__, HTTP_SAVE },
    { (sbyte*)"Server",             6,  __LINE__, HTTP_SAVE },
    { (sbyte*)"Retry-After",        11,  __LINE__, HTTP_SAVE },
    { (sbyte*)"Proxy-Authenticate", 18, __LINE__, HTTP_SAVE },
    { (sbyte*)"Location",           8, __LINE__, HTTP_SAVE },
    { (sbyte*)"ETag",               4, __LINE__, HTTP_SAVE },
    { (sbyte*)"Age",                3,  __LINE__, HTTP_SAVE },
    { (sbyte*)"Accept-Ranges",      13, __LINE__, HTTP_SAVE }
};

HTTP_requestInfo mHttpGeneralHeaders[] =
{
    /* store request header fields in reverse alphabet order */
    { (sbyte*)"Warning",            7, __LINE__, HTTP_SAVE },
    { (sbyte*)"Via",                3,  __LINE__, HTTP_SAVE },
    { (sbyte*)"Upgrade",            7,  __LINE__, HTTP_SAVE },
    { (sbyte*)"Transfer-Encoding",  17,  __LINE__, HTTP_SAVE },
    { (sbyte*)"Content-Transfer-Encoding",  25,  __LINE__, HTTP_SAVE },
    { (sbyte*)"Trailer",            7, __LINE__, HTTP_SAVE },
    { (sbyte*)"Pragma",             6, __LINE__, HTTP_SAVE },
    { (sbyte*)"Date",               4, __LINE__, HTTP_SAVE },
    { (sbyte*)"Connection",         10,  __LINE__, HTTP_SAVE },
    { (sbyte*)"Keep-Alive",         10,  __LINE__, HTTP_SAVE },
    { (sbyte*)"Cache-Control",      13, __LINE__, HTTP_SAVE }
};

HTTP_requestInfo mHttpEntityHeaders[] =
{
    /* store request header fields in reverse alphabet order */
    { (sbyte*)"Last-Modified",      13, __LINE__, HTTP_SAVE },
    { (sbyte*)"Expires",            7,  __LINE__, HTTP_SAVE },
    { (sbyte*)"Content-Type",       12,  __LINE__, HTTP_SAVE },
    { (sbyte*)"Content-Range",      13,  __LINE__, HTTP_SAVE },
    { (sbyte*)"Content-MD5",        11, __LINE__, HTTP_SAVE },
    { (sbyte*)"Content-Location",   16, __LINE__, HTTP_SAVE },
    { (sbyte*)"Content-Length",     14, __LINE__, HTTP_SAVE },
    { (sbyte*)"Content-Language",   16,  __LINE__, HTTP_SAVE },
    { (sbyte*)"Content-Encoding",   16, __LINE__, HTTP_SAVE },
    { (sbyte*)"Allow",              5, __LINE__, HTTP_SAVE }
};

/*------------------------------------------------------------------*/

extern intBoolean
HTTP_COMMON_subStringMatch(ubyte *pData, ubyte4 dataLen, sbyte *pSubData, ubyte4 subDataLen)
{
    intBoolean  match = FALSE;

    if (subDataLen > dataLen)
        goto exit;

    while (0 < subDataLen)
    {
        if (MTOLOWER((sbyte)(*pData)) != MTOLOWER((sbyte)(*pSubData)))
            goto exit;

        pData++;
        pSubData++;
        subDataLen--;
    }

    match = TRUE;

exit:
    return match;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HTTP_COMMON_lookupMethod(ubyte *pData, ubyte4 dataLength, HTTP_methodsInfo **ppRetMethodDecr)
{
    ubyte4 i;

    *ppRetMethodDecr = NULL;

    for (i = 0; NUM_HTTP_METHODS > i; i++)
    {
        if ((TRUE == mHttpMethods[i].isSupported) &&
            (TRUE == HTTP_COMMON_subStringMatch(pData, dataLength,
                                    mHttpMethods[i].pHttpMethodName, mHttpMethods[i].httpMethodNameLength)))
        {
            *ppRetMethodDecr = &mHttpMethods[i];
            break;
        }
    }

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HTTP_COMMON_lookupVersion(ubyte *pData, ubyte4 dataLength, HTTP_versionInfo **ppRetVersionDecr)
{
    ubyte4 i;

    *ppRetVersionDecr = NULL;

    for (i = 0; NUM_HTTP_VERSIONS > i; i++)
    {
        if (TRUE == HTTP_COMMON_subStringMatch(pData, dataLength,
                                    mHttpVersions[i].pHttpVersionName, mHttpVersions[i].httpVersionNameLength))
        {
            *ppRetVersionDecr = &mHttpVersions[i];
            break;
        }
    }

    return OK;
}

extern MSTATUS HTTP_COMMON_lookupStatusCode(ubyte *pData, ubyte4 dataLength, ubyte4 *pStatusCode)
{
    MSTATUS status = OK;
    ubyte4 i;
    *pStatusCode = 0;

    if (dataLength < 3) /* 3 digit statusCode */
    {
        status = ERR_HTTP_RESPONSE_MISSING_STATUS;
    }

    /*statusCode is 3 digit decimal number */
    for (i = 0; i < 3; i++)
    {
        if (*(pData+i) < '0' || *(pData+i) > '9')
        {
            status = ERR_HTTP_RESPONSE_MISSING_STATUS;
        }
        *pStatusCode = (*pStatusCode) * 10 + (*(pData+i) - '0');
    }

    return status;

}

/*------------------------------------------------------------------*/

extern MSTATUS
HTTP_COMMON_lookupRequestInfo(ubyte *pData, ubyte4 dataLength, HTTP_requestInfo **ppRetRequestDecr, ubyte4 *pIndex)
{
    sbyte4 i;

    *ppRetRequestDecr = NULL;

    for (i = 0; i < NUM_HTTP_REQUESTS + NUM_HTTP_GENERALHEADERS +
        NUM_HTTP_ENTITYHEADERS; i++)
    {
        if ( i < NUM_HTTP_REQUESTS )
        {
            if (TRUE == HTTP_COMMON_subStringMatch(pData, dataLength,
                mHttpRequests[i].pHttpRequestName, mHttpRequests[i].httpRequestNameLength))
            {
                *ppRetRequestDecr = &mHttpRequests[i];
                *pIndex = i;
                break;
            }
        }
        else if (i < NUM_HTTP_REQUESTS + NUM_HTTP_GENERALHEADERS)
        {
            if (TRUE == HTTP_COMMON_subStringMatch(pData, dataLength,
                mHttpGeneralHeaders[i-NUM_HTTP_REQUESTS].pHttpRequestName,
                mHttpGeneralHeaders[i-NUM_HTTP_REQUESTS].httpRequestNameLength))
            {
                *ppRetRequestDecr = &mHttpGeneralHeaders[i-NUM_HTTP_REQUESTS];
                *pIndex = i;
                break;
            }
        }
        else
        {
            if (TRUE == HTTP_COMMON_subStringMatch(pData, dataLength,
                mHttpEntityHeaders[i-NUM_HTTP_REQUESTS-NUM_HTTP_GENERALHEADERS].pHttpRequestName,
                mHttpEntityHeaders[i-NUM_HTTP_REQUESTS-NUM_HTTP_GENERALHEADERS].httpRequestNameLength))
            {
                *ppRetRequestDecr = &mHttpEntityHeaders[i-NUM_HTTP_REQUESTS-NUM_HTTP_GENERALHEADERS];
                *pIndex = i;
                break;
            }

        }
    }

    return OK;
}

/*------------------------------------------------------------------*/

extern MSTATUS
HTTP_COMMON_lookupResponseInfo(ubyte *pData, ubyte4 dataLength, HTTP_requestInfo **ppRetResponseDecr, ubyte4* pIndex)
{
    sbyte4 i;

    *ppRetResponseDecr = NULL;

    for (i = 0; i < NUM_HTTP_RESPONSES + NUM_HTTP_GENERALHEADERS +
        NUM_HTTP_ENTITYHEADERS; i++)
    {
        if (i < NUM_HTTP_RESPONSES)
        {
            if (TRUE == HTTP_COMMON_subStringMatch(pData, dataLength,
                mHttpResponses[i].pHttpRequestName,
                mHttpResponses[i].httpRequestNameLength))
            {
                *ppRetResponseDecr = &mHttpResponses[i];
                *pIndex = i;
                goto exit;
            }
        }
        else if ( i < NUM_HTTP_RESPONSES + NUM_HTTP_GENERALHEADERS)
        {
            if (TRUE == HTTP_COMMON_subStringMatch(pData, dataLength,
                mHttpGeneralHeaders[i-NUM_HTTP_RESPONSES].pHttpRequestName,
                mHttpGeneralHeaders[i-NUM_HTTP_RESPONSES].httpRequestNameLength))
            {
                *ppRetResponseDecr = &mHttpGeneralHeaders[i-NUM_HTTP_RESPONSES];
                *pIndex = i;
                break;
            }
        }
        else
        {
            if (TRUE == HTTP_COMMON_subStringMatch(pData, dataLength,
                mHttpEntityHeaders[i-NUM_HTTP_RESPONSES-NUM_HTTP_GENERALHEADERS].pHttpRequestName,
                mHttpEntityHeaders[i-NUM_HTTP_RESPONSES-NUM_HTTP_GENERALHEADERS].httpRequestNameLength))
            {
                *ppRetResponseDecr = &mHttpEntityHeaders[i-NUM_HTTP_RESPONSES-NUM_HTTP_GENERALHEADERS];
                *pIndex = i;
                break;
            }
        }
    }
exit:

    return OK;
}

/*------------------------------------------------------------------*/

extern sbyte4
HTTP_COMMON_returnRequestInfoBase(void)
{
    return mHttpRequests[0].identifier;
}


/*------------------------------------------------------------------*/

extern HTTP_versionInfo *
HTTP_COMMON_getHttpVersionDescr(sbyte4 version)
{
    /* version: 0 for HTTP/1.0, 1 for HTTP/1.1 */
    return (0 == version) ? (&(mHttpVersions[0])) : (&(mHttpVersions[1]));
}


/*------------------------------------------------------------------*/

extern HTTP_versionInfo *
HTTP_COMMON_returnHighestHttpVersion(void)
{
    return (0 == NUM_HTTP_VERSIONS) ? NULL : (&(mHttpVersions[NUM_HTTP_VERSIONS - 1]));
}


/*------------------------------------------------------------------*/

extern MSTATUS
HTTP_COMMON_copyRequest(httpContext *pHttpContext,
                        ubyte **ppData, ubyte4 *pDataLength,
                        sbyte4 *pRetResult)
{
    ubyte       data;
    MSTATUS     status = OK;

    *pRetResult = HTTP_LINE_MORE;

    while ((0 < (*pDataLength)) && (HTTP_LINE_MORE == (*pRetResult)))
    {
        data = (ubyte)(**ppData);

        if ((MOC_CR != data) && (LF != data) && (http_eol_none == pHttpContext->httpCount.eolState))
        {
            /* enough space? */
            if (pHttpContext->headerDataBufferSize <= pHttpContext->headerDataIndex)
            {
                /* no DIGICERT API for realloc so allocate a new buffer and copy */
                ubyte* newBuffer;

                newBuffer = MALLOC( 2 * pHttpContext->headerDataBufferSize);
                if (! newBuffer)
                {
                    /* don't even try to recover from that */
                    status = ERR_MEM_ALLOC_FAIL;
                    goto exit;
                }
                DIGI_MEMCPY( newBuffer, pHttpContext->pHeaderData, pHttpContext->headerDataBufferSize);
                FREE( pHttpContext->pHeaderData);
                pHttpContext->pHeaderData = newBuffer;
                pHttpContext->headerDataBufferSize *= 2;

            }

            pHttpContext->pHeaderData[pHttpContext->headerDataIndex] = data;
            pHttpContext->headerDataIndex++;
        }
        else
        {
            /* we accept either CRLF or LF as EOL */
            switch (pHttpContext->httpCount.eolState)
            {
            case http_eol_none:
                /* char is either lf or cr */
                if (MOC_CR == data)
                {
                    pHttpContext->httpCount.eolState = http_eol_cr;
                    break;
                }
                /* LF == data -> fall through */

            case http_eol_cr:
                /* char must be lf otherwise (any other char including cr) report error */
                if (LF == data)
                {
                    /* handle end of line case */
                    if (0 == pHttpContext->headerDataIndex)
                        *pRetResult = HTTP_LINE_EMPTY;
                    else
                        *pRetResult = HTTP_LINE_DONE;
                    break;
                }
                /* fall through to error */

            /* should not get in there for any other state */
            default:
                status = ERR_HTTP_MALFORMED_MESSAGE;
                goto exit;
            }
        }

        (*ppData)++;
        (*pDataLength)--;
    }

exit:
    return status;
}



/*------------------------------------------------------------------*/

extern sbyte4
HTTP_COMMON_getContentLength(httpContext *pHttpContext)
{
    ubyte4 index = 0;
    ubyte *headerBitmask;
    HTTP_stringDescr *headers;
    sbyte* content_length_str = NULL;
    sbyte4 contentLength = -1;

    if (!pHttpContext)
    {
        return 0;
    }

    /* content-length is in m_HttpEntityHeaders */
    if (HTTP_SERVER == pHttpContext->roleType)
    {
        contentLength = 0;
        index = NUM_HTTP_REQUESTS + NUM_HTTP_GENERALHEADERS + ContentLength;
        headerBitmask = pHttpContext->requestBitmask;
        headers = pHttpContext->requests;
    }
    else
    {
        index = NUM_HTTP_RESPONSES + NUM_HTTP_GENERALHEADERS + ContentLength;
        headerBitmask = pHttpContext->responseBitmask;
        headers = pHttpContext->responses;
    }

    if ((headerBitmask[index/8] & (1 << (index & 7))) &&
        headers[index].httpStringLength > 0)
    {
        content_length_str = (sbyte*) MALLOC(headers[index].httpStringLength+1);
        if (!content_length_str)
        {
            return contentLength;
        }
        DIGI_MEMCPY(content_length_str, headers[index].pHttpString, headers[index].httpStringLength);
        content_length_str[headers[index].httpStringLength] = 0;

        contentLength = DIGI_ATOL(content_length_str, NULL);

        if (content_length_str)
        {
            FREE(content_length_str);
        }
    }

    /* if there's no content length header and the
       status is > 400, there's no body -> return 0 */
    if (contentLength < 0 && pHttpContext->httpStatusResponse >= 400)
    {
        contentLength = 0;
    }

    return contentLength;
}


/*------------------------------------------------------------------*/

extern void
HTTP_COMMON_writeInteger(ubyte4 integerValue, ubyte *pBuffer, ubyte4 *pRetLength)
{
    ubyte   tempBuf[11];
    ubyte4  index = 0;

    tempBuf[10] = '0';

    while (integerValue > 0)
    {
        tempBuf[10 - index] = (ubyte)((integerValue % 10) + '0');
        integerValue = integerValue / 10;
        index++;
    }

    index = (index) ? index : 1;

    DIGI_MEMCPY(pBuffer, &(tempBuf[11 - index]), index);
    *pRetLength = index;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HTTP_COMMON_writeString(ubyte **ppRetBuffer, ubyte4 *pRetBufSize, sbyte *pCopyThis, sbyte4 copyLen)
{
    MSTATUS status = OK;

    if (*pRetBufSize < (ubyte4)copyLen)
    {
        status = ERR_HTTP_BUFFER_OVERFLOW;
        goto exit;
    }

    DIGI_MEMCPY(*ppRetBuffer, (const ubyte *)pCopyThis, (ubyte4)copyLen);

    *ppRetBuffer += copyLen;
    *pRetBufSize -= copyLen;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HTTP_COMMON_writeHeader(ubyte **ppRetBuffer, ubyte4 *pRetBufSize, sbyte *pName, sbyte4 nameLen, sbyte *pValue, sbyte4 valueLen)
{
    MSTATUS status = OK;

    if (*pRetBufSize < (ubyte4)(nameLen + 2 + valueLen))
    {
        status = ERR_HTTP_BUFFER_OVERFLOW;
        goto exit;
    }

    DIGI_MEMCPY(*ppRetBuffer, (const ubyte *)pName, (ubyte4)nameLen);

    *ppRetBuffer += nameLen;
    *pRetBufSize -= nameLen;

    DIGI_MEMCPY(*ppRetBuffer, (const ubyte *)": ", (ubyte4)2);

    *ppRetBuffer += 2;
    *pRetBufSize -= 2;

    DIGI_MEMCPY(*ppRetBuffer, (const ubyte *)pValue, (ubyte4)valueLen);

    *ppRetBuffer += valueLen;
    *pRetBufSize -= valueLen;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HTTP_COMMON_setHeader(httpContext *pHttpContext,
                      ubyte4 index, ubyte* pValue, ubyte4 valueLength,
                      intBoolean overwrite)
{
    MSTATUS status = OK;
    ubyte* pValueStr;
    ubyte4 totalIdx;
    ubyte *headerBitmask;
    HTTP_stringDescr *headers;

        /* transfer-encoding is in m_HttpGeneralHeaders */
    if (pHttpContext->roleType == HTTP_CLIENT)
    {
        totalIdx = NUM_HTTP_REQUESTS + NUM_HTTP_GENERALHEADERS + NUM_HTTP_ENTITYHEADERS;
        headerBitmask = pHttpContext->requestBitmask;
        headers = pHttpContext->requests;
    } else
    {
        totalIdx = NUM_HTTP_RESPONSES + NUM_HTTP_GENERALHEADERS + NUM_HTTP_ENTITYHEADERS;
        headerBitmask = pHttpContext->responseBitmask;
        headers = pHttpContext->responses;
    }

    if ( (overwrite || !(headerBitmask[index / 8] & (1 << (index & 7)))) &&
        pValue && (valueLength > 0) &&
        (index < totalIdx))
    {
        pValueStr = (ubyte*) MALLOC(valueLength); /* will be released with resetHttpContext */
        if (!pValueStr)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        DIGI_MEMCPY(pValueStr, pValue, valueLength);
        headers[index].pHttpString = pValueStr;
        headers[index].httpStringLength = valueLength;
        /* set request header bitmask */
        headerBitmask[index / 8] |= (1 << (index & 7));
    }
exit:
    return status;
}

/*------------------------------------------------------------------*/
/* method will make a copy of the header value */
extern MSTATUS
HTTP_COMMON_setHeaderIfNotSet(httpContext *pHttpContext,
                              ubyte4 index, ubyte* pValue, ubyte4 valueLength)
{
    return HTTP_COMMON_setHeader(pHttpContext, index, pValue, valueLength, FALSE);
}

#endif /* (defined(__ENABLE_DIGICERT_HTTP_CLIENT__) || defined(__ENABLE_DIGICERT_HTTPCC_SERVER__)) */
