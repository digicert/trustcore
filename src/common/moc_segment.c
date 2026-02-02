/*
 * moc_segment.c
 *
 * Segmented Buffer
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
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/debug_console.h"
#include "../common/moc_segment.h"


/*------------------------------------------------------------------*/

extern ubyte4
SEG_findSegment(const mocSegDescr **ppSrcBufSeg, ubyte4 offset)
{
    const mocSegDescr* pCurSeg = *ppSrcBufSeg;

    while ((NULL != pCurSeg) && (0 != offset))
    {
        if (GET_SEG_BUFFER_LEN(pCurSeg) > offset)
        {
            break;
        }

        offset = offset - GET_SEG_BUFFER_LEN(pCurSeg);
        pCurSeg = GET_NEXT_SEG(pCurSeg);
    }

    *ppSrcBufSeg = pCurSeg;

    return offset;
}


/*------------------------------------------------------------------*/

#if 0
extern ubyte4
SEG_strCpy(const sbyte* pSrcBuf, sbyte* pDestBuf, sbyte4 destBufLen)
{
    ubyte4 i = 0;

    if (NULL == pSrcBuf || NULL == pDestBuf || 0 >= destBufLen)
    {
        return 0;
    }

    while (i < destBufLen)
    {
        if ('\0' == (pDestBuf[i] = *pSrcBuf++))
            break;

        ++i;
    }

    return i;
}
#endif


/*------------------------------------------------------------------*/

extern MSTATUS
DIGI_memsetSeg(mocSegDescr *pSrcBufSeg, ubyte valueToSet, ubyte4 numBytesToSet, ubyte4 offset)
{
    MSTATUS         status = OK;
    mocSegDescr*    pCurSeg = pSrcBufSeg;
    ubyte4          numBytesLeft;

    if (NULL == pCurSeg)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    offset = SEG_findSegment((const mocSegDescr **)&pCurSeg, offset);

    if (NULL == pCurSeg)
        goto exit;

    numBytesLeft = GET_SEG_BUFFER_LEN(pCurSeg) - offset;

    if (numBytesToSet > numBytesLeft)
    {
        DIGI_MEMSET(GET_SEG_BUFFER(pCurSeg) + offset, valueToSet, GET_SEG_BUFFER_LEN(pCurSeg) - offset);
        numBytesToSet = numBytesToSet - numBytesLeft;
    }
    else
    {
        DIGI_MEMSET(GET_SEG_BUFFER(pCurSeg) + offset, valueToSet, numBytesToSet);
        goto exit;
    }

    while (NULL != (pCurSeg = GET_NEXT_SEG(pCurSeg)))
    {
        if (numBytesToSet > GET_SEG_BUFFER_LEN(pCurSeg))
        {
            DIGI_MEMSET(GET_SEG_BUFFER(pCurSeg), valueToSet, GET_SEG_BUFFER_LEN(pCurSeg));
        }
        else
        {
            DIGI_MEMSET(GET_SEG_BUFFER(pCurSeg), valueToSet, numBytesToSet);
            break;
        }

        numBytesToSet = numBytesToSet - GET_SEG_BUFFER_LEN(pCurSeg);
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern sbyte4
DIGI_copyToSegEx(const ubyte* pSrcBuf, ubyte4 srcBufLen,
                mocSegDescr *pDestBufSeg, ubyte4 offset,
                mocSegDescr** ppNewBufSeg, ubyte4* pNewOff)
{
    sbyte4          status = OK;
    mocSegDescr*    pCurSeg = pDestBufSeg;
    ubyte4          numBytesLeft;
    ubyte4          retOffset = 0;
    const ubyte*    pBuf = pSrcBuf;

    if ((NULL == pCurSeg) || (NULL == pSrcBuf))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    offset = SEG_findSegment((const mocSegDescr **)&pCurSeg, offset);

    if (NULL == pCurSeg)
        goto exit;

    if ((NULL != ppNewBufSeg) && (NULL != pNewOff))
    {
        *ppNewBufSeg = NULL;
        *pNewOff = 0;
    }

    numBytesLeft = GET_SEG_BUFFER_LEN(pCurSeg) - offset;

    if (srcBufLen >= numBytesLeft)
    {
        DIGI_MEMCPY(GET_SEG_BUFFER(pCurSeg) + offset, pBuf, numBytesLeft);
        srcBufLen = srcBufLen - numBytesLeft;
        pBuf = pBuf + numBytesLeft;
        GET_SEG_BYTES_USED(pCurSeg) = GET_SEG_BUFFER_LEN(pCurSeg);
    }
    else
    {
        DIGI_MEMCPY(GET_SEG_BUFFER(pCurSeg) + offset, pBuf, srcBufLen);
        if ( offset + srcBufLen > GET_SEG_BYTES_USED(pCurSeg))
        {
            GET_SEG_BYTES_USED(pCurSeg) = offset + srcBufLen;
        }

        pBuf = pBuf + srcBufLen;
        retOffset = offset + srcBufLen;
        goto done;
    }

    while ((NULL != (pCurSeg = GET_NEXT_SEG(pCurSeg))) && (0 != srcBufLen))
    {
        if (srcBufLen >= GET_SEG_BUFFER_LEN(pCurSeg))
        {
            DIGI_MEMCPY(GET_SEG_BUFFER(pCurSeg), pBuf, GET_SEG_BUFFER_LEN(pCurSeg));
            pBuf = pBuf + GET_SEG_BUFFER_LEN(pCurSeg);
            srcBufLen = srcBufLen - GET_SEG_BUFFER_LEN(pCurSeg);
            GET_SEG_BYTES_USED(pCurSeg) = GET_SEG_BUFFER_LEN(pCurSeg);
        }
        else
        {
            DIGI_MEMCPY(GET_SEG_BUFFER(pCurSeg), pBuf, srcBufLen);
            if (srcBufLen > GET_SEG_BYTES_USED(pCurSeg))
            {
                GET_SEG_BYTES_USED(pCurSeg) = srcBufLen;
            }
            pBuf = pBuf + srcBufLen;
            break;
        }
    }

    retOffset = srcBufLen;

done:
    /* return next byte which is not copied */
    if ((NULL != pCurSeg) && (NULL != ppNewBufSeg) && (NULL != pNewOff))
    {
        *ppNewBufSeg = (mocSegDescr*) pCurSeg;
        *pNewOff = retOffset;
    }

    status = (sbyte4)(pBuf - pSrcBuf);

exit:

    return status;
}


/*------------------------------------------------------------------*/

extern sbyte4
DIGI_copyToSeg(const ubyte* pSrcBuf, ubyte4 srcBufLen, mocSegDescr *pDestBufSeg, ubyte4 offset)
{
    return DIGI_copyToSegEx(pSrcBuf, srcBufLen, pDestBufSeg, offset, NULL, NULL);
}


/*------------------------------------------------------------------*/

extern sbyte4
DIGI_copyFromSegEx(const mocSegDescr *pSrcBufSeg, ubyte4 offset,
                  ubyte* pDestBuf, ubyte4 destBufLen,
                  mocSegDescr** ppNewBufSeg, ubyte4* pNewOff)
{
    sbyte4              status = OK;
    ubyte4              numBytesLeft;
    ubyte4              retOffset = 0;
    ubyte*              pBuf = pDestBuf;
    const mocSegDescr*  pCurSeg = pSrcBufSeg;

    if ((NULL == pCurSeg) || (NULL == pDestBuf))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    offset = SEG_findSegment(&pCurSeg, offset);

    if (NULL == pCurSeg)
        goto exit;

    if ((NULL != ppNewBufSeg) && (NULL != pNewOff))
    {
        *ppNewBufSeg = NULL;
        *pNewOff = 0;
    }

    numBytesLeft = GET_SEG_BUFFER_LEN(pCurSeg) - offset;

    if (destBufLen >= numBytesLeft)
    {
        DIGI_MEMCPY(pBuf, GET_SEG_BUFFER(pCurSeg) + offset, numBytesLeft);
        pBuf = pBuf + numBytesLeft;
        destBufLen = destBufLen - numBytesLeft;
    }
    else
    {
        DIGI_MEMCPY(pBuf, GET_SEG_BUFFER(pCurSeg) + offset, destBufLen);

        pBuf = pBuf + destBufLen;
        retOffset = offset + destBufLen;
        goto done;
    }

    while ( (NULL != (pCurSeg = GET_NEXT_SEG(pCurSeg))) && (0 != destBufLen) )
    {
        if (destBufLen >= GET_SEG_BUFFER_LEN(pCurSeg))
        {
            DIGI_MEMCPY(pBuf, GET_SEG_BUFFER(pCurSeg), GET_SEG_BUFFER_LEN(pCurSeg));
            pBuf = pBuf + GET_SEG_BUFFER_LEN(pCurSeg);
            destBufLen = destBufLen - GET_SEG_BUFFER_LEN(pCurSeg);
        }
        else
        {
            DIGI_MEMCPY(pBuf, GET_SEG_BUFFER(pCurSeg), destBufLen);

            pBuf = pBuf + destBufLen;
            break;
        }
    }

    retOffset = destBufLen;

done:
    /* return next byte which is not copied */
    if ((NULL != pCurSeg) && (NULL != ppNewBufSeg) && (NULL != pNewOff))
    {
        *ppNewBufSeg = (mocSegDescr*) pCurSeg;
        *pNewOff = retOffset;
    }

    status = (sbyte4)(pBuf - pDestBuf);

exit:

    return status;
}


/*------------------------------------------------------------------*/

extern sbyte4
DIGI_copyFromSeg(const mocSegDescr *pSrcBufSeg, ubyte4 offset, ubyte* pDestBuf, ubyte4 destBufLen)
{
    return DIGI_copyFromSegEx(pSrcBufSeg, offset, pDestBuf, destBufLen, NULL, NULL);
}


/*------------------------------------------------------------------*/

extern MSTATUS
DIGI_freeTestSeg(mocSegDescr **ppBufSeg)
{
    mocSegDescr* pTmp = NULL;
    mocSegDescr* pCur = NULL;

    if ((NULL == ppBufSeg) || (NULL == *ppBufSeg))
        return ERR_NULL_POINTER;

    pCur = *ppBufSeg;

    while (NULL != pCur)
    {
        if (NULL != GET_SEG_BUFFER(pCur))
            FREE(GET_SEG_BUFFER(pCur));

        pTmp = pCur;
        pCur = GET_NEXT_SEG(pTmp);

        FREE(pTmp);
    }

    *ppBufSeg = NULL;

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DIGI_createTestSeg(mocSegDescr **ppBufSeg, ubyte4 numSeg, ubyte4 segBufSize)
{
    MSTATUS      status = ERR_NULL_POINTER;
    mocSegDescr* pHead = NULL;
    mocSegDescr* pTmp = NULL;
    mocSegDescr* pCur = NULL;

    if ((NULL != *ppBufSeg) || (0 == segBufSize))
        goto exit;

    while (0 < numSeg)
    {
        pTmp = (mocSegDescr *)MALLOC(sizeof(mocSegDescr));

        if (NULL == pTmp)
        {
            DIGI_freeTestSeg(&pHead);
            goto exit;
        }

        DIGI_MEMSET((ubyte *)pTmp, 0x00, sizeof(mocSegDescr));

        GET_SEG_BUFFER(pTmp) = (ubyte *)MALLOC(segBufSize);

        if (NULL == GET_SEG_BUFFER(pTmp))
        {
            /*  If allocating memory for pTmp->pBuff fails we
                still need to free the memory pointed
                to by pTmp.  At this point pHead doesn't point
                to anything. */
            if (pTmp)
                FREE(pTmp);

            DIGI_freeTestSeg(&pHead);
            goto exit;
        }

        GET_SEG_BUFFER_LEN(pTmp) = segBufSize;

        if (NULL == pHead)
            pHead = pCur = pTmp;
        else
        {
            GET_NEXT_SEG(pCur) = pTmp;
            pCur = GET_NEXT_SEG(pCur);
        }

        pTmp = NULL;

        numSeg--;
    }

    if (NULL != pHead)
    {
        *ppBufSeg = pHead;
        status = OK;
    }

exit:

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DIGI_clearTestSeg(mocSegDescr *pBufSeg)
{
    mocSegDescr* pTmp = pBufSeg;

    while (NULL != pTmp)
    {
        if (NULL != GET_SEG_BUFFER(pTmp))
        {
            DIGI_MEMSET(GET_SEG_BUFFER(pTmp), 0x00, GET_SEG_BUFFER_LEN(pTmp));
        }

        GET_SEG_BYTES_USED(pTmp) = 0;

        pTmp = GET_NEXT_SEG(pTmp);
    }

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
DIGI_setByteInSeg(ubyte value, mocSegDescr *pDestBufSeg, ubyte4 offset)
{
    MSTATUS         status = OK;

    if (NULL == pDestBufSeg)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    offset = SEG_findSegment((const mocSegDescr **)&pDestBufSeg, offset);

    if (NULL == pDestBufSeg)
    {
        status = ERR_BUFFER_OVERFLOW;
        goto exit;
    }

    if (GET_SEG_BYTES_USED(pDestBufSeg) < (1 + offset))
        GET_SEG_BYTES_USED(pDestBufSeg) = (1 + offset);

    (GET_SEG_BUFFER(pDestBufSeg))[offset] = value;

exit:
    return status;
}
