/*
 * mime_parser.c
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

#if defined(__ENABLE_DIGICERT_MIME_PARSER__)

#if defined(__RTOS_LINUX__) || (defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__))
#include <unistd.h>
#endif

#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mfmgmt.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/mime_parser.h"

#define LINE_FEED           '\n'
#define CARRIAGE_RETURN     '\r'

#define CONTENT_TYPE                "Content-Type:"
#define CONTENT_TRANSFER_ENCODING   "Content-Transfer-Encoding:"
#define CONTENT_LENGTH              "Content-Length:"
#define CONTENT_ID                  "Content-ID:"
#define CONTENT_DESCRIPTION         "Content-Description:"
#define CONTENT_DISPOSITION         "Content-Disposition:"
#define BOUNDARY                    "boundary"
#define MIME_BOUNDARY               "boundary="
#define MIME_VERSION                "MIME-Version: 1.0"

static sbyte4 MIME_removeLineBreak(
    sbyte *pString,
    sbyte4 stringLen)
{
    if (NULL == pString || 0 == stringLen)
        return 0;

    /* remove any line ending */
    if (stringLen > 1  && '\r' == pString[stringLen-2] && '\n' == pString[stringLen-1])
    {
        pString[stringLen-2] = '\0';
        stringLen-=2;
    }
    else if (stringLen > 0 && '\n' == pString[stringLen-1])
    {
        pString[stringLen-1] = '\0';
        stringLen-=1;
    }

    return stringLen;
}

static MSTATUS MIME_getLine(
    ubyte **ppIter,
    ubyte4 *pIterLen,
    ubyte **ppLine,
    ubyte4 *pLineLen)
{
    *ppLine = *ppIter;
    *pLineLen = *pIterLen;

    while (*pIterLen > 0)
    {
        if (LINE_FEED == **ppIter)
        {
            *pLineLen = *ppIter - *ppLine;
            (*ppIter)++;
            (*pIterLen)--;
            break;
        }
        else if (*pIterLen > 1 && CARRIAGE_RETURN == **ppIter && (LINE_FEED == (*ppIter)[1]))
        {
            *pLineLen = *ppIter - *ppLine;
            (*ppIter)+=2;
            (*pIterLen)-=2;
            break;
        }
        (*ppIter)++;
        (*pIterLen)--;
    }

    return OK;
}

static MSTATUS MIME_getBoundary(
    ubyte *pLine,
    ubyte4 lineLen,
    sbyte **ppBoundary)
{
    MSTATUS status = ERR_INVALID_INPUT;
    sbyte4 len, cmp;
    ubyte *pIter;
    sbyte4 iterLen;
    sbyte *pStart = NULL, *pEnd = NULL;
    byteBoolean quoted = FALSE;

    pIter = pLine;
    iterLen = lineLen;

    len = DIGI_STRLEN(MIME_BOUNDARY);
    while (iterLen > 0)
    {
        if (iterLen >= len && 0 == DIGI_MEMCMP(pIter, MIME_BOUNDARY, len, &cmp) && 0 == cmp)
        {
            pIter += len;
            iterLen -= len;
            /* boundary can be quoted */
            if (*pIter == '"')
            {
                quoted = TRUE;
                pIter++;
                iterLen--;
            }
            pStart = pIter;
            break;
        }

        pIter++;
        iterLen--;
    }

    if (NULL == pStart)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (TRUE == quoted)
    {
        while (iterLen > 0)
        {
            if ('"' == *pIter)
            {
                pEnd = pIter;
                break;
            }
            pIter++;
            iterLen--;
        }
    }
    else
    {
        pEnd = pIter + iterLen;
    }

    if (NULL == pEnd)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    len = pEnd - pStart;
    len = MIME_removeLineBreak (pStart, len);

    status = DIGI_MALLOC((void **) ppBoundary, 2 + len + 1);
    if (OK != status)
    {
        goto exit;
    }

    (*ppBoundary)[0] = '-';
    (*ppBoundary)[1] = '-';
    DIGI_MEMCPY(*ppBoundary + 2, pStart, len);
    (*ppBoundary)[2 + len] = '\0';

exit:

    return status;
}

static MSTATUS MIME_findNextBoundary(
    ubyte **ppIter,
    ubyte4 *pIterLen,
    ubyte **ppLine,
    ubyte4 *pLineLen,
    sbyte *pBoundary)
{
    MSTATUS status;
    ubyte4 len;
    sbyte4 cmp = -1;

    len = DIGI_STRLEN(pBoundary);

    while (*pIterLen > 0)
    {
        status = MIME_getLine(ppIter, pIterLen, ppLine, pLineLen);
        if (OK != status)
        {
            goto exit;
        }

        if ( (*pLineLen == len && 0 == DIGI_MEMCMP(*ppLine, pBoundary, len, &cmp) && 0 == cmp) ||
             (*pLineLen == len + 2 && 0 == DIGI_MEMCMP(*ppLine, pBoundary, len, &cmp) && 0 == cmp && (*ppLine)[len - 2] == '-' && (*ppLine)[len - 1] == '-') )
        {
            break;
        }
    }

    if (0 != cmp)
    {
        status = ERR_NOT_FOUND;
    }

exit:

    return status;
}

static MSTATUS MIME_addPart(
    MimeContentType contentType,
    MimeContentTransferEncoding contentTransferEncoding,
    ubyte *pData,
    ubyte4 dataLen,
    FileDescriptor pFile,
    ubyte4 fileOffset,
    sbyte **ppId,
    sbyte **ppDescription,
    sbyte **ppDisposition,
    MimePart **ppMimePart)
{
    MSTATUS status;

    status = DIGI_MALLOC((void **) ppMimePart, sizeof(MimePart));
    if (OK != status)
    {
        goto exit;
    }

    (*ppMimePart)->contentType = contentType;
    (*ppMimePart)->contentTransferEncoding = contentTransferEncoding;
    (*ppMimePart)->pData = pData;
    (*ppMimePart)->pFile = pFile;
    (*ppMimePart)->fileOffset = fileOffset;
    (*ppMimePart)->dataLen = dataLen;
    (*ppMimePart)->pId = *ppId; *ppId = NULL;
    (*ppMimePart)->pDescription = *ppDescription; *ppDescription = NULL;
    (*ppMimePart)->pDisposition = *ppDisposition; *ppDisposition = NULL;
    (*ppMimePart)->pNext = NULL;

exit:

    return status;
}

extern MSTATUS MIME_deletePart(
    MimePart **ppMimeParts)
{
    MSTATUS status = OK, fstatus;
    MimePart *pPart, *pNext;

    if (NULL != ppMimeParts && NULL != *ppMimeParts)
    {
        pPart = *ppMimeParts;

        while (NULL != pPart)
        {
            pNext = pPart->pNext;

            DIGI_FREE((void **) &(pPart->pId));
            DIGI_FREE((void **) &(pPart->pDescription));
            DIGI_FREE((void **) &(pPart->pDisposition));
            fstatus = DIGI_FREE((void **) &pPart);
            if (OK == status)
                status = fstatus;

            pPart = pNext;
        }
    }

    return status;
}

/* RFC 2045, section 6: data with lines no longer than 1000 characters including any trailing
   CRLF line separator. */
#define LINELEN 1000
static MSTATUS MIME_parsePart(
    MimePayload *pPayloadData,
    sbyte *pLine,
    sbyte4 maxLineLen,
    sbyte *pBoundary,
    funcPtrMimePartProcess func,
    MimePartProcessArg *pArgs,
    sbyte4 *pBytesProcessed
)
{
    MSTATUS status;
    sbyte4 len;
    MimeContentType contentType = MIME_CONTENT_TYPE_NONE;
    MimeContentTransferEncoding contentTransferEncoding = MIME_CONTENT_TRANSFER_ENCODING_NONE;
    intBoolean headerDone = FALSE;
    sbyte4 contentLength = 0;
    sbyte *pBodyData = NULL;
    sbyte *pTmp;
    sbyte *pContentID = NULL;
    sbyte *pContentDescription = NULL;
    sbyte *pContentDisposition = NULL;
    ubyte4 bytesRead = 0;
    sbyte4 totalBytes = 0;
    MimePart *pMimePart = NULL;
    intBoolean hasLength = FALSE;
    sbyte4 dataStart;
    sbyte4 lineLen;
    ubyte *pData;
    ubyte4 dataLen;
    FileDescriptor pFile = NULL;
    ubyte4 fileOffset = 0;

    if (NULL == pPayloadData)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pData = pPayloadData->pPayLoad;
    dataLen = pPayloadData->payloadLen;
    pFile = pPayloadData->pFile;

    /* we are at the beginning of a PART */
    status = OK;
    while (FALSE == headerDone &&
          ((NULL != pFile && FMGMT_fgets(pLine, maxLineLen, pFile)) ||
           (NULL == pFile && dataLen > 0 && OK == (status = MIME_getLine(&pData, &dataLen, (ubyte **) &pLine, &lineLen)))))
    {
        if (NULL != pFile)
        {
            len = DIGI_STRLEN(pLine);
            totalBytes += len;
            lineLen = MIME_removeLineBreak (pLine, len);
        }
        else
        {
            len = lineLen;
            totalBytes += lineLen;
        }

        if (0 == lineLen)
        {
            /* completed reading header */
            if (NULL == pFile) pBodyData = pData;
            headerDone = TRUE;
            continue;
        }

        pTmp = pLine;
        if (0 == DIGI_STRNCMP(pLine, CONTENT_TYPE, DIGI_STRLEN(CONTENT_TYPE)))
        {
            pTmp += DIGI_STRLEN(CONTENT_TYPE);
            len -= DIGI_STRLEN(CONTENT_TYPE);
            while (len > 0)
            {
                if (*pTmp != ' ')
                    break;

                pTmp++;
                len--;
            }

            if (0 == DIGI_STRNICMP(pTmp, "application/json", DIGI_STRLEN("application/json")))
            {
                contentType = MIME_CONTENT_TYPE_JSON;
            }
            else if (0 == DIGI_STRNICMP(pTmp, "application/pkcs7-mime; smime-type=CMC-response", DIGI_STRLEN("application/pkcs7-mime; smime-type=CMC-response")))
            {
                contentType = MIME_CONTENT_TYPE_CMC;
            }
            else if (0 == DIGI_STRNICMP(pTmp, "application/pkcs7-mime", DIGI_STRLEN("application/pkcs7-mime")))
            {
                contentType = MIME_CONTENT_TYPE_PKCS7_MIME;
            }
            else if (0 == DIGI_STRNICMP(pTmp, "application/pkcs8", DIGI_STRLEN("application/pkcs8")))
            {
                contentType = MIME_CONTENT_TYPE_PKCS8;
            }
            else if (0 == DIGI_STRNICMP(pTmp, "application/octet-stream", DIGI_STRLEN("application/octet-stream")))
            {
                contentType = MIME_CONTENT_TYPE_OCTET_STREAM;
            }
            else
            {
                /* TODO: content type not supported */
                status = ERR_MIME_CONTENT_TYPE_NOT_SUPPORTED;
                goto exit;
            }
        }
        else if (0 == DIGI_STRNCMP(pLine, CONTENT_TRANSFER_ENCODING, DIGI_STRLEN(CONTENT_TRANSFER_ENCODING)))
        {
            pTmp += DIGI_STRLEN(CONTENT_TRANSFER_ENCODING);
            len -= DIGI_STRLEN(CONTENT_TRANSFER_ENCODING);
            while (len > 0)
            {
                if (*pTmp != ' ')
                    break;

                pTmp++;
                len--;
            }

            if (0 == DIGI_STRNICMP(pTmp, "base64", DIGI_STRLEN("base64")))
            {
                contentTransferEncoding = MIME_CONTENT_TRANSFER_ENCODING_BASE64;
            }
            else if (0 == DIGI_STRNICMP(pTmp, "8bit", DIGI_STRLEN("8bit")))
            {
                contentTransferEncoding = MIME_CONTENT_TRANSFER_ENCODING_8BIT;
            }
            else if (0 == DIGI_STRNICMP(pTmp, "binary", DIGI_STRLEN("binary")))
            {
                contentTransferEncoding = MIME_CONTENT_TRANSFER_ENCODING_BINARY;
            }
            else
            {
                /* encoding type not supported */
                status = ERR_MIME_CONTENT_TRANSFER_ENCODING_NOT_SUPPORTED;
                goto exit;
            }

        }
        else if (0 == DIGI_STRNCMP(pLine, CONTENT_LENGTH , DIGI_STRLEN(CONTENT_LENGTH)))
        {
            pTmp += DIGI_STRLEN(CONTENT_LENGTH);
            len -= DIGI_STRLEN(CONTENT_LENGTH);
            while (len > 0)
            {
                if (*pTmp != ' ')
                    break;

                pTmp++;
                len--;
            }

            contentLength = DIGI_ATOL(pTmp, NULL);
            hasLength = TRUE;
        }
        else if (0 == DIGI_STRNCMP(pLine, CONTENT_ID, DIGI_STRLEN(CONTENT_ID)))
        {
            pTmp += DIGI_STRLEN(CONTENT_ID);
            len -= DIGI_STRLEN(CONTENT_ID);
            while (len > 0)
            {
                if (*pTmp != ' ')
                    break;

                pTmp++;
                len--;
            }

            status = DIGI_MALLOC((void **) &pContentID, len + 1);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pContentID, pTmp, len);
            if (OK != status)
                goto exit;

            pTmp[len] = '\0';
            /* Ignore return value, still need to call MIME_removeLineBreak so
             * pContentID is properly NULL terminated */
            (void) MIME_removeLineBreak (pContentID, len);
        }
        else if (0 == DIGI_STRNCMP(pLine, CONTENT_DESCRIPTION, DIGI_STRLEN(CONTENT_DESCRIPTION)))
        {
            pTmp += DIGI_STRLEN(CONTENT_DESCRIPTION);
            len -= DIGI_STRLEN(CONTENT_DESCRIPTION);
            while (len > 0)
            {
                if (*pTmp != ' ')
                    break;

                pTmp++;
                len--;
            }

            status = DIGI_MALLOC((void **) &pContentDescription, len + 1);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY (pContentDescription, pTmp, len);
            if (OK != status)
                goto exit;

            pContentDescription[len] = '\0';
            /* Ignore return value, still need to call MIME_removeLineBreak so
             * pContentDescription is properly NULL terminated */
            (void) MIME_removeLineBreak (pContentDescription, len);
        }
        else if (0 == DIGI_STRNCMP(pLine, CONTENT_DISPOSITION, DIGI_STRLEN(CONTENT_DISPOSITION)))
        {
            pTmp += DIGI_STRLEN(CONTENT_DISPOSITION);
            len -= DIGI_STRLEN(CONTENT_DISPOSITION);
            while (len > 0)
            {
                if (*pTmp != ' ')
                    break;

                pTmp++;
                len--;
            }

            status = DIGI_MALLOC((void **) &pContentDisposition, len + 1);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY (pContentDisposition, pTmp, len);
            if (OK != status)
                goto exit;

            pContentDisposition[len] = '\0';
            /* Ignore return value, still need to call MIME_removeLineBreak so
             * pContentDisposition is properly NULL terminated */
            (void) MIME_removeLineBreak (pContentDisposition, len);
        }

        if ((NULL == pFile) &&  (0 < dataLen && 0 != contentLength && (sbyte4)(dataLen - 1) == contentLength))
        {
            pBodyData = pData;
            break;
        }
    }
    if (OK != status)
    {
        goto exit;
    }

    if (FALSE == headerDone)
    {
        status = ERR_MIME_INCOMPLETE_HEADER;
        goto exit;
    }

    if (NULL != pFile)
    {
        if (!hasLength)
        {
            /* if we have binary data, length field is mandatory */
            if (MIME_CONTENT_TRANSFER_ENCODING_BINARY == contentTransferEncoding)
            {
                status = ERR_MIME_MISSING_LENGTH;
                goto exit;
            }

            status = FMGMT_ftell (pFile, &dataStart);
            if (OK != status)
                goto exit;

            bytesRead = 0;
            while (FMGMT_fgets(pLine, LINELEN, pFile))
            {
                pTmp = pLine;
                bytesRead += DIGI_STRLEN(pLine);
                if (0 == DIGI_STRNCMP(pLine, pBoundary, DIGI_STRLEN(pBoundary)))
                {
                    bytesRead -= DIGI_STRLEN(pLine);
                    status = FMGMT_fseek(pFile, dataStart, 0);
                    if (OK != status)
                        goto exit;

                    break;
                }
            }

            contentLength = bytesRead;
        }

        status = FMGMT_ftell(pFile, &fileOffset);
        if (OK != status)
            goto exit;

        status = FMGMT_fseek(pFile, contentLength, MSEEK_CUR);
        if (OK != status)
            goto exit;

        bytesRead = contentLength;

        dataLen = bytesRead;
    }

    totalBytes += dataLen;
    (*pBytesProcessed) += totalBytes;

    status = MIME_addPart(
        contentType, contentTransferEncoding, pBodyData, dataLen, pFile, fileOffset,
        &pContentID, &pContentDescription, &pContentDisposition, &pMimePart);
    if (OK != status)
        goto exit;

    status = func(pMimePart, pArgs);
    if (OK != status)
        goto exit;

exit:

    MIME_deletePart(&pMimePart);
    DIGI_FREE((void **) &pContentDescription);
    DIGI_FREE((void **) &pContentDisposition);
    DIGI_FREE((void **) &pContentID);
    if (NULL != pFile) DIGI_FREE((void **) &pBodyData);
    return status;
}

extern MSTATUS MIME_getBoundaryFromLine(
    ubyte *pContentType,
    ubyte4 contentTypeLen,
    sbyte **ppBoundary)
{
    /*Ex: contentType: multipart/mixed; boundary=boundary-text */
    MSTATUS    status       = OK;
    ubyte4        pos          = 0;
    ubyte4       boundaryTxtLen = 0;

    if (NULL == pContentType)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    while(pos < contentTypeLen)
    {
        if (0 == DIGI_STRNICMP((const sbyte*)BOUNDARY, (const sbyte*)(pContentType+pos), DIGI_STRLEN((const sbyte*)BOUNDARY)))
        {
            pos = pos + DIGI_STRLEN((const sbyte*)BOUNDARY) + 1;
            boundaryTxtLen = contentTypeLen - pos;
            /* Add -- at prefix */
            boundaryTxtLen = boundaryTxtLen + 2;
            if (OK > (status = DIGI_MALLOC((void**)ppBoundary, (boundaryTxtLen)+1)))
            {
                goto exit;
            }
            if (OK > (status = DIGI_MEMSET(*ppBoundary, 0x00, boundaryTxtLen+1)))
            {
                goto exit;
            }
            *((*ppBoundary) + 0) = '-';
            *((*ppBoundary) + 1) = '-';
            if (OK > (status = DIGI_MEMCPY((*ppBoundary)+2, pContentType+pos, boundaryTxtLen-2)))
            {
                goto exit;
            }
            break;
        }
        pos++;
    }
exit:
    return status;
}

extern MSTATUS MIME_processBody(
    MimePayload *pInput,
    sbyte *pBoundary,
    funcPtrMimePartProcess func,
    MimePartProcessArg *pArgs)
{
    MSTATUS status;
    ubyte *pIter;
    ubyte4 iterLen;
    ubyte *pStart, *pEnd;

    sbyte *pLine = NULL;
    ubyte4 lineLen = 1000;
    sbyte *pTmp;
    sbyte4 len, cmp;
    intBoolean headerDone = FALSE;
    intBoolean validMimeVersion = FALSE;
    intBoolean hasLength = FALSE;
    sbyte4 calculatedMessageLen = 0;
    sbyte4 expectedMessageLen = 0;
    MimePayload payloadData;

    if (NULL == pInput)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != pInput->pFile)
    {
        status = DIGI_MALLOC((void **) &pLine, LINELEN);
        if (OK != status)
            goto exit;

        while(FMGMT_fgets(pLine, LINELEN, pInput->pFile))
        {
            calculatedMessageLen += DIGI_STRLEN(pLine);
            if (0 == DIGI_STRNCMP(pLine, pBoundary, DIGI_STRLEN(pBoundary)))
            {
                if (0 == DIGI_STRNCMP(pLine + DIGI_STRLEN(pBoundary), "--", DIGI_STRLEN("--")))
                {
                    goto exit;
                }

                payloadData.pFile = pInput->pFile;
                payloadData.pPayLoad = NULL;
                payloadData.payloadLen = 0;
                status = MIME_parsePart (&payloadData,
                    pLine, LINELEN, pBoundary, func, pArgs, &calculatedMessageLen);
                if (OK != status)
                    goto exit;
            }
        }
    }
    else
    {
        pIter = pInput->pPayLoad;
        iterLen = pInput->payloadLen;

        status = MIME_findNextBoundary(&pIter, &iterLen, (ubyte **) &pLine, &lineLen, pBoundary);
        if (OK != status)
        {
            goto exit;
        }

        while (iterLen > 0)
        {
            pStart = pIter;

            status = MIME_findNextBoundary(&pIter, &iterLen, (ubyte **) &pLine, &lineLen, pBoundary);
            if (OK != status)
            {
                goto exit;
            }

            pEnd = pLine;
            payloadData.pPayLoad = pStart;
            payloadData.payloadLen = pEnd - pStart;
            payloadData.pFile = NULL;
            status = MIME_parsePart (
                &payloadData, NULL, 0, NULL, func, pArgs, &calculatedMessageLen);
            if (OK != status)
            {
                goto exit;
            }
        }
    }

exit:

    if (NULL != pInput && NULL != pInput->pFile) DIGI_FREE((void **) &pLine);
    return status;
}

extern MSTATUS MIME_process(
    MimePayload *pInput,
    funcPtrMimePartProcess func,
    MimePartProcessArg *pArgs)
{
    MSTATUS status;
    ubyte *pIter;
    ubyte4 iterLen;
    ubyte *pStart, *pEnd;

    sbyte *pLine = NULL;
    ubyte4 lineLen = 1000;
    sbyte *pTmp;
    sbyte4 len, cmp;
    intBoolean headerDone = FALSE;
    intBoolean validMimeVersion = FALSE;
    intBoolean hasLength = FALSE;
    sbyte4 calculatedMessageLen = 0;
    sbyte4 expectedMessageLen = 0;
    MimePayload payloadData;

    sbyte *pBoundary = NULL;

    if (NULL == pInput)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* After header processing this function should be changed to call
     * MIME_processBody to reduce code size */

    if (NULL != pInput->pFile)
    {
        status = DIGI_MALLOC((void **) &pLine, LINELEN);
        if (OK != status)
            goto exit;

        /* process entity header */
        while (FALSE == headerDone && FMGMT_fgets(pLine, LINELEN, pInput->pFile))
        {
            if ((1 == DIGI_STRLEN(pLine) && '\n' == *pLine) ||
                (2 == DIGI_STRLEN(pLine) && '\r' == *pLine && '\n' == *(pLine+1) ))
            {
                /* completed reading header */
                headerDone = TRUE;
                continue;
            }

            if (0 == DIGI_STRNCMP(pLine, MIME_VERSION, DIGI_STRLEN(MIME_VERSION)))
            {
                validMimeVersion = TRUE;
            }
            else if (0 == DIGI_STRNCMP(pLine, CONTENT_TYPE, DIGI_STRLEN(CONTENT_TYPE)))
            {
                len = DIGI_STRLEN(pLine);
                pTmp = pLine;
                pTmp += DIGI_STRLEN(CONTENT_TYPE);
                len -= DIGI_STRLEN(CONTENT_TYPE);
                while (len > 0)
                {
                    if (*pTmp != ' ')
                        break;

                    pTmp++;
                    len--;
                }

                /* we only support multipart/mixed type messages */
                if (0 != DIGI_STRNCMP(pTmp, "multipart/mixed", DIGI_STRLEN("multipart/mixed")))
                {
                    status = ERR_MIME_CONTENT_TYPE_NOT_SUPPORTED;
                    goto exit;
                }

                pTmp += DIGI_STRLEN("multipart/mixed");
                len -= DIGI_STRLEN("multipart/mixed");

                status = MIME_getBoundary(pTmp, len, &pBoundary);
                if (OK != status)
                    goto exit;
            }
            else if (0 == DIGI_STRNCMP(pLine, CONTENT_LENGTH, DIGI_STRLEN(CONTENT_LENGTH)))
            {
                len = DIGI_STRLEN(pLine);
                pTmp = pLine;
                pTmp += DIGI_STRLEN(CONTENT_LENGTH);
                len -= DIGI_STRLEN(CONTENT_LENGTH);
                while (len > 0)
                {
                    if (*pTmp != ' ')
                        break;

                    pTmp++;
                    len--;
                }

                expectedMessageLen = DIGI_ATOL(pTmp, NULL);
                hasLength = TRUE;
            }
        }

        /* check we finshed reading header, and a supported MIME version */
        if (FALSE == headerDone || FALSE == validMimeVersion)
        {
            status = ERR_MIME_FORMAT_INVALID;
            goto exit;
        }

        while(FMGMT_fgets(pLine, LINELEN, pInput->pFile))
        {
            calculatedMessageLen += DIGI_STRLEN(pLine);
            if (0 == DIGI_STRNCMP(pLine, pBoundary, DIGI_STRLEN(pBoundary)))
            {
                if (0 == DIGI_STRNCMP(pLine + DIGI_STRLEN(pBoundary), "--", DIGI_STRLEN("--")))
                {
                    goto exit;
                }

                payloadData.pFile = pInput->pFile;
                payloadData.pPayLoad = NULL;
                payloadData.payloadLen = 0;
                status = MIME_parsePart (&payloadData,
                    pLine, LINELEN, pBoundary, func, pArgs, &calculatedMessageLen);
                if (OK != status)
                    goto exit;
            }
        }

        if (hasLength && calculatedMessageLen != expectedMessageLen)
        {
            status = ERR_MIME_CONTENT_LENGTH_MISMATCH;
            goto exit;
        }
    }
    else
    {
        pIter = pInput->pPayLoad;
        iterLen = pInput->payloadLen;

        len  = DIGI_STRLEN(CONTENT_TYPE);
        while (iterLen > 0)
        {
            status = MIME_getLine(&pIter, &iterLen, (ubyte **) &pLine, &lineLen);
            if (OK != status)
            {
                goto exit;
            }

            if ((sbyte4)lineLen >= len && 0 == DIGI_MEMCMP(pLine, CONTENT_TYPE, len, &cmp) && 0 == cmp)
            {
                status = MIME_getBoundary(pLine, lineLen, &pBoundary);
                if (OK != status)
                {
                    goto exit;
                }
                break;
            }
        }

        status = MIME_findNextBoundary(&pIter, &iterLen, (ubyte **) &pLine, &lineLen, pBoundary);
        if (OK != status)
        {
            goto exit;
        }

        while (iterLen > 0)
        {
            pStart = pIter;

            status = MIME_findNextBoundary(&pIter, &iterLen, (ubyte **) &pLine, &lineLen, pBoundary);
            if (OK != status)
            {
                goto exit;
            }

            pEnd = pLine;
            payloadData.pPayLoad = pStart;
            payloadData.payloadLen = pEnd - pStart;
            payloadData.pFile = NULL;
            status = MIME_parsePart (
                &payloadData, NULL, 0, NULL, func, pArgs, &calculatedMessageLen);
            if (OK != status)
            {
                goto exit;
            }
        }
    }

exit:

    DIGI_FREE((void **) &pBoundary);
    if (NULL != pInput && NULL != pInput->pFile) DIGI_FREE((void **) &pLine);
    return status;
}

#endif /* __ENABLE_DIGICERT_MIME_PARSER__ */