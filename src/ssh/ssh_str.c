/*
 * ssh_str.c
 *
 * SSH String Methods
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../common/moptions.h"

#if defined(__ENABLE_MOCANA_SSH_SERVER__) || defined(__ENABLE_MOCANA_SSH_CLIENT__)

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/memory_debug.h"
#include "../ssh/ssh_str.h"


/*------------------------------------------------------------------*/

#ifdef __ENABLE_MOCANA_PQC__
#define MAX_SSH_STRING_SIZE     2097152
#else
#ifdef __ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__
#define MAX_SSH_STRING_SIZE     8192
#else
#define MAX_SSH_STRING_SIZE     2048
#endif /* __ENABLE_MOCANA_SSH_X509V3_RFC_6187_SUPPORT__ */
#endif /* __ENABLE_MOCANA_PQC__ */

/*------------------------------------------------------------------*/

extern MSTATUS
SSH_STR_makeStringBuffer(sshStringBuffer **ppRetString, ubyte4 strLen)
{
    MSTATUS status = OK;

    if (NULL == ppRetString)
    {
        status = ERR_NULL_POINTER;
        goto bad;
    }

    if (NULL == ((*ppRetString) = MALLOC(sizeof(sshStringBuffer))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (0 < strLen)
    {
        if (NULL == ((*ppRetString)->pString = MALLOC(strLen)))
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
    }
    else
    {
        (*ppRetString)->pString = NULL;
    }

    (*ppRetString)->stringLen = strLen;

exit:
    if (ERR_MEM_ALLOC_FAIL == status)
        if (NULL != *ppRetString)
        {
            FREE(*ppRetString); *ppRetString = NULL;
        }

bad:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_STR_freeStringBuffer(sshStringBuffer **ppRetString)
{
    MSTATUS status = ERR_NULL_POINTER;

    if ((NULL != ppRetString) && (NULL != *ppRetString))
    {
        if (NULL != (*ppRetString)->pString)
        {
            FREE((*ppRetString)->pString); (*ppRetString)->pString = NULL;
        }

        FREE(*ppRetString);
        *ppRetString = NULL;
        status = OK;
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_STR_copyStringToPayload(ubyte *pBuffer, ubyte4 bufSize, ubyte4 *bufIndex,
                            sshStringBuffer *pAppendToBuffer)
{
    MSTATUS status = OK;

    if ((NULL == bufIndex) || (NULL == pAppendToBuffer) || (NULL == pBuffer) ||
        ((NULL == pAppendToBuffer->pString) && (0 < pAppendToBuffer->stringLen)))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((bufSize <= (*bufIndex)) || ((4 + pAppendToBuffer->stringLen) > (bufSize - (*bufIndex))))
    {
        /* not enough room to copy string */
        status = ERR_BUFFER_OVERFLOW;
        goto exit;
    }

    pBuffer += *bufIndex;

    pBuffer[0] = (ubyte)((pAppendToBuffer->stringLen) >> 24);
    pBuffer[1] = (ubyte)((pAppendToBuffer->stringLen) >> 16);
    pBuffer[2] = (ubyte)((pAppendToBuffer->stringLen) >> 8);
    pBuffer[3] = (ubyte)((pAppendToBuffer->stringLen));

    if (0 < pAppendToBuffer->stringLen)
        MOC_MEMCPY(&(pBuffer[4]), pAppendToBuffer->pString, pAppendToBuffer->stringLen);

    *bufIndex += (4 + pAppendToBuffer->stringLen);

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_STR_copyStringToPayload2(ubyte *pBuffer, ubyte4 bufSize, ubyte4 *bufIndex,
                             ubyte *pAppendToBuffer, ubyte4 appendLen)
{
    MSTATUS status = OK;

    if ((NULL == bufIndex) || (NULL == pAppendToBuffer) || (NULL == pBuffer))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((bufSize <= (*bufIndex)) || ((4 + appendLen) > (bufSize - (*bufIndex))))
    {
        /* not enough room to copy string */
        status = ERR_BUFFER_OVERFLOW;
        goto exit;
    }

    pBuffer += *bufIndex;

    pBuffer[0] = (ubyte)(appendLen >> 24);
    pBuffer[1] = (ubyte)(appendLen >> 16);
    pBuffer[2] = (ubyte)(appendLen >> 8);
    pBuffer[3] = (ubyte)(appendLen);

    if (0 < appendLen)
        MOC_MEMCPY(pBuffer + 4, pAppendToBuffer, appendLen);

    *bufIndex += 4 + appendLen;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_STR_copyStringToPayload3(ubyte *pBuffer, ubyte4 bufSize, ubyte4 *bufIndex,
                             sshStringBuffer *pAppendToBuffer)
{
    /* copies a string-store's string (i.e. length encapsulated) to a payload */
    MSTATUS status = OK;

    if ((NULL == bufIndex) || (NULL == pAppendToBuffer) || (NULL == pBuffer) ||
        ((NULL == pAppendToBuffer->pString) && (0 < pAppendToBuffer->stringLen)))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((bufSize <= (*bufIndex)) || ((pAppendToBuffer->stringLen) > (bufSize - (*bufIndex))))
    {
        /* not enough room to copy string */
        status = ERR_BUFFER_OVERFLOW;
        goto exit;
    }

    pBuffer += *bufIndex;

    if (0 < pAppendToBuffer->stringLen)
        MOC_MEMCPY(pBuffer, pAppendToBuffer->pString, pAppendToBuffer->stringLen);

    *bufIndex += (pAppendToBuffer->stringLen);

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_STR_copyFromString(ubyte *pBuffer, ubyte4 *bufIndex,
                       sshStringBuffer *pAppendToBuffer, intBoolean copyToBuffer)
{
    MSTATUS status = OK;

    if ((NULL == bufIndex) || (NULL == pAppendToBuffer) ||
        ((TRUE == copyToBuffer) && (NULL == pBuffer)) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (TRUE == copyToBuffer)
        MOC_MEMCPY(&(pBuffer[*bufIndex]), pAppendToBuffer->pString, pAppendToBuffer->stringLen);

    *bufIndex += pAppendToBuffer->stringLen;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_STR_walkStringInPayload(const ubyte *pBuffer, ubyte4 bufSize, ubyte4 *pBufIndex)
{
    ubyte4  stringLen;
    MSTATUS status = OK;

    if ((NULL == pBufIndex) || (NULL == pBuffer))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (*pBufIndex == bufSize)
    {
        status = ERR_PAYLOAD_EMPTY;
        goto exit;
    }

    if (bufSize < ((*pBufIndex) + 4))
    {
        status = ERR_SSH_STRING_TOO_LONG;
        goto exit;
    }

    stringLen  = (ubyte4)pBuffer[(*pBufIndex)];   stringLen <<= 8;
    stringLen |= (ubyte4)pBuffer[(*pBufIndex)+1]; stringLen <<= 8;
    stringLen |= (ubyte4)pBuffer[(*pBufIndex)+2]; stringLen <<= 8;
    stringLen |= (ubyte4)pBuffer[(*pBufIndex)+3];

    if ((MAX_SSH_STRING_SIZE < stringLen) || (bufSize < ((*pBufIndex) + stringLen)))
    {
        status = ERR_SSH_STRING_TOO_LONG;
        goto exit;
    }

    (*pBufIndex) += stringLen + 4;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_STR_copyStringFromPayload(ubyte *pBuffer, ubyte4 bufSize,
                              ubyte4 *pBufIndex, sshStringBuffer **ppRetString)
{
    ubyte4  stringLen;
    MSTATUS status;

    if ((NULL == pBufIndex) || (NULL == pBuffer) || (NULL == ppRetString))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (*pBufIndex == bufSize)
    {
        status = ERR_PAYLOAD_EMPTY;
        goto exit;
    }

    stringLen  = (ubyte4)pBuffer[(*pBufIndex)];   stringLen <<= 8;
    stringLen |= (ubyte4)pBuffer[(*pBufIndex)+1]; stringLen <<= 8;
    stringLen |= (ubyte4)pBuffer[(*pBufIndex)+2]; stringLen <<= 8;
    stringLen |= (ubyte4)pBuffer[(*pBufIndex)+3];

    if ((MAX_SSH_STRING_SIZE < stringLen) || (bufSize < ((*pBufIndex) + stringLen)))
    {
        status = ERR_SSH_STRING_TOO_LONG;
        goto exit;
    }

    status = SSH_STR_makeStringBuffer(ppRetString, stringLen+4);

    if(NULL != ppRetString)
    {
        DEBUG_RELABEL_MEMORY(*ppRetString);
        DEBUG_RELABEL_MEMORY((*ppRetString)->pString);
    }

    if (OK <= status)
    {
        MOC_MEMCPY((*ppRetString)->pString, &(pBuffer[*pBufIndex]), stringLen+4);
        (*ppRetString)->stringLen = stringLen + 4;
    }

    (*pBufIndex) += stringLen + 4;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_STR_copyStringFromPayload2(ubyte *pBuffer, ubyte4 bufSize,
                               ubyte4 *pBufIndex, sshStringBuffer **ppRetString)
{
    /* copies a ssh string from a payload, without the inband four-byte length field */
    ubyte4  stringLen;
    MSTATUS status;

    if ((NULL == pBufIndex) || (NULL == pBuffer) || (NULL == ppRetString))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (*pBufIndex == bufSize)
    {
        status = ERR_PAYLOAD_EMPTY;
        goto exit;
    }

    pBuffer += *pBufIndex;

    stringLen  = (ubyte4)pBuffer[0]; stringLen <<= 8;
    stringLen |= (ubyte4)pBuffer[1]; stringLen <<= 8;
    stringLen |= (ubyte4)pBuffer[2]; stringLen <<= 8;
    stringLen |= (ubyte4)pBuffer[3];

    if ((MAX_SSH_STRING_SIZE < stringLen) || (bufSize < ((*pBufIndex) + stringLen)))
    {
        status = ERR_SSH_STRING_TOO_LONG;
        goto exit;
    }

    status = SSH_STR_makeStringBuffer(ppRetString, stringLen);
   
    if(NULL != ppRetString)
    {
        DEBUG_RELABEL_MEMORY(*ppRetString);
        DEBUG_RELABEL_MEMORY((*ppRetString)->pString);
    }

    if ((OK <= status) && (0 < stringLen))
        status = MOC_MEMCPY((*ppRetString)->pString, 4 + pBuffer, stringLen);

    (*pBufIndex) += stringLen + 4;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_STR_copyStringFromPayload3(ubyte *pBuffer, ubyte4 bufSize,
                               ubyte4 *pBufIndex, ubyte **ppRetString)
{
    /* copies a ssh string from a payload, into a C string */
    ubyte4  stringLen;
    MSTATUS status;

    if ((NULL == pBufIndex) || (NULL == pBuffer) || (NULL == ppRetString))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (*pBufIndex == bufSize)
    {
        status = ERR_PAYLOAD_EMPTY;
        goto exit;
    }

    pBuffer += *pBufIndex;

    stringLen  = (ubyte4)pBuffer[0]; stringLen <<= 8;
    stringLen |= (ubyte4)pBuffer[1]; stringLen <<= 8;
    stringLen |= (ubyte4)pBuffer[2]; stringLen <<= 8;
    stringLen |= (ubyte4)pBuffer[3];

    if ((MAX_SSH_STRING_SIZE < stringLen) || (bufSize < ((*pBufIndex) + stringLen)))
    {
        status = ERR_SSH_STRING_TOO_LONG;
        goto exit;
    }

    if (NULL == (*ppRetString = MALLOC(1 + stringLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    status = MOC_MEMCPY((*ppRetString), 4 + pBuffer, stringLen);
    (*ppRetString)[stringLen] = '\0';

    (*pBufIndex) += stringLen + 4;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_STR_getOption(sshStringBuffer *pString, ubyte4 *pStringNextIndex,
                  ubyte **ppRetOption, ubyte4 *pRetOptionLength)
{
    ubyte*  pTempString;
    ubyte4  stringLen;
    MSTATUS status = OK;

    /* first time called, *pStringNextIndex should be 4 */
    if ((NULL == pString) || (NULL == pStringNextIndex) ||
        (NULL == ppRetOption) || (NULL == pRetOptionLength))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    stringLen = (pString->stringLen) - (*pStringNextIndex);

    if (0 == stringLen)
    {
        /* no more options */
        *pRetOptionLength = 0;
        *ppRetOption      = NULL;
        goto exit;
    }

    if (NULL == (*ppRetOption = pTempString = MALLOC(stringLen)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    *pRetOptionLength = 0;

    /* skip past leading ',' */
    if ((0 < stringLen) && (',' == (pString->pString)[*pStringNextIndex]))
    {
        stringLen--;
        (*pStringNextIndex)++;
    }

    while (0 < stringLen)
    {
        /* copy one byte at a time */
        if (',' == (*pTempString = (pString->pString)[(*pStringNextIndex) + *pRetOptionLength]))
            break;

        stringLen--;
        (*pRetOptionLength)++;
        pTempString++;
    }

    (*pStringNextIndex) += (*pRetOptionLength);

exit:
    return status;

} /* SSH_STR_getOption */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_STR_findOption(sshStringBuffer *pSourceString, ubyte *pOption,
                   ubyte4 optionLen, intBoolean *pInString, ubyte4 *pWordIndex)
{
    ubyte*  pSrcString;
    ubyte4  srcStringLen;
    ubyte4  index;
    MSTATUS status = OK;

    if ((NULL == pSourceString) || (NULL == pOption) || (NULL == pInString) || (NULL == pWordIndex))
    {
        status = ERR_NULL_POINTER;
        goto bad;
    }

    *pInString   = FALSE;

    if (NULL == pSourceString->pString)
        goto exit;

    pSrcString   = (pSourceString->pString) + 4;
    srcStringLen = (pSourceString->stringLen) - 4;
    *pWordIndex  = 1;

    do
    {
        if (srcStringLen < optionLen)
        {
            /* search string is bigger than source string */
            goto exit;
        }

        /* check for option */
        for (index = 0; index < optionLen; index++)
        {
            if (pSrcString[index] != pOption[index])
            {
                pSrcString   += index;
                srcStringLen -= index;
                break;
            }
        }

        if (index == optionLen)
        {
            if ((srcStringLen == optionLen) || (',' == pSrcString[index]))
            {
                *pInString = TRUE;
                goto exit;
            }
        }

        /* skip to next option */
        while ((0 < srcStringLen) && (',' != *pSrcString))
        {
            pSrcString++;
            srcStringLen--;
        }

        /* skip redundant commas */
        while ((0 < srcStringLen) && (',' == *pSrcString))
        {
            pSrcString++;
            srcStringLen--;
        }

        (*pWordIndex)++;

    } while (0 < srcStringLen);

exit:
    if (FALSE == *pInString)
        (*pWordIndex) = 0;

bad:
    return status;

} /* SSH_STR_findOption */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_STR_locateOption(sshStringBuffer *pClientString, sshStringBuffer *pServerString, ubyte4 *pWordIndex)
{
    ubyte*      pOption = NULL;
    ubyte4      optionLen;
    ubyte4      wordIndex   = 0;
    ubyte4      stringIndex = 4;
    intBoolean  inString    = FALSE;
    MSTATUS     status;

    *pWordIndex = 0;

    if (stringIndex > pClientString->stringLen)
    {
        status = ERR_SSH_STR_BAD_LEN;
        goto exit;
    }

    do
    {
        status = SSH_STR_getOption(pClientString, &stringIndex, &pOption, &optionLen);
        if (OK > status)
            goto exit;

        if (NULL == pOption)
            break;

        status = SSH_STR_findOption(pServerString, pOption, optionLen, &inString, &wordIndex);
        if (OK > status)
            goto exit;

        FREE(pOption);
        pOption = NULL;
    }
    while (FALSE == inString);

    if (TRUE == inString)
        *pWordIndex = wordIndex;

exit:
    if (NULL != pOption)
        FREE(pOption);

    return status;

} /* SSH_STR_locateOption */


/*------------------------------------------------------------------*/

extern MSTATUS
SSH_STR_locateOption1(sshStringBuffer *pClientString, sshStringBuffer *pServerString, ubyte4 *pWordIndex)
{
    ubyte*      pOption = NULL;
    ubyte4      optionLen;
    ubyte4      srvrWordIndex = 0;
    ubyte4      clientWordIndex = 0;
    ubyte4      stringIndex = 4;
    intBoolean  inString    = FALSE;
    MSTATUS     status;

    *pWordIndex = 0;

    if (stringIndex > pClientString->stringLen)
    {
        status = ERR_SSH_STR_BAD_LEN;
        goto exit;
    }

    do
    {
        status = SSH_STR_getOption(pClientString, &stringIndex, &pOption, &optionLen);
        if (OK > status)
            goto exit;

        if (NULL == pOption)
            break;

        status = SSH_STR_findOption(pServerString, pOption, optionLen, &inString, &srvrWordIndex);
        if (OK > status)
            goto exit;

        FREE(pOption);
        pOption = NULL;

        clientWordIndex++;
    }
    while (FALSE == inString);

    if (TRUE == inString)
        *pWordIndex = clientWordIndex;

exit:
    if (NULL != pOption)
        FREE(pOption);

    return status;

} /* SSH_STR_locateOption1 */


/*------------------------------------------------------------------*/

/*
 * This avoids having to convert the byte array to an sshString before
 * inserting into the payload.
 */
extern MSTATUS
SSH_STR_copyBytesAsStringToPayload(ubyte *pBuffer, ubyte4 bufSize, ubyte4 *bufIndex,
                                    ubyte *pAppendToBuffer, ubyte4 appendLen)
{
    MSTATUS status = OK;

    if ((NULL == bufIndex) || (NULL == pAppendToBuffer) || (NULL == pBuffer))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if ((bufSize <= (*bufIndex)) || ((4 + appendLen) > (bufSize - (*bufIndex))))
    {
        /* not enough room to copy string */
        status = ERR_BUFFER_OVERFLOW;
        goto exit;
    }

    pBuffer += *bufIndex;

    pBuffer[0] = (ubyte)(appendLen >> 24);
    pBuffer[1] = (ubyte)(appendLen >> 16);
    pBuffer[2] = (ubyte)(appendLen >> 8);
    pBuffer[3] = (ubyte)(appendLen);

    if (0 < appendLen)
        MOC_MEMCPY(pBuffer + 4, pAppendToBuffer, appendLen);

    *bufIndex += 4 + appendLen;

exit:
    return status;
}

#endif /* (__ENABLE_MOCANA_SSH_SERVER__) || defined(__ENABLE_MOCANA_SSH_CLIENT__) */
