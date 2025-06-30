/*
 * circ_buf.c
 *
 * Circular Buffer Factory
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

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/circ_buf.h"


/*------------------------------------------------------------------*/

extern MSTATUS
CIRC_BUF_create(circBufDescr **ppRetCircBufDescr, ubyte4 buflen)
{
    circBufDescr* pCircBufDescr = NULL;
    MSTATUS       status;

    if (NULL == ppRetCircBufDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (pCircBufDescr = (circBufDescr*) MALLOC(sizeof(circBufDescr))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    status = MOC_MEMSET((ubyte *)pCircBufDescr, 0x00, sizeof(circBufDescr));

    pCircBufDescr->buflen          = buflen;
    pCircBufDescr->head            = 0;
    pCircBufDescr->tail            = 0;
    pCircBufDescr->pBuffer         = NULL;

    *ppRetCircBufDescr  = pCircBufDescr;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
CIRC_BUF_release(circBufDescr **ppFreeCircBufDescr)
{
    MSTATUS status = OK;

    if ((NULL == ppFreeCircBufDescr) || (NULL == *ppFreeCircBufDescr))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != (*ppFreeCircBufDescr)->pBuffer)
    {
        FREE((*ppFreeCircBufDescr)->pBuffer);
    }

    FREE(*ppFreeCircBufDescr);
    *ppFreeCircBufDescr = NULL;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
CIRC_BUF_read(circBufDescr *pCircBufDescr,
              ubyte *pReadBuffer, ubyte4 numBytesToRead, ubyte4 *pRetNumBytesRead)
{
    ubyte*  pBuffer;
    ubyte4  buflen = 0;
    ubyte4  head   = 0;
    ubyte4  tail   = 0;
    ubyte4  numBytesToCopy;
    ubyte4  numBytesCopied;
    ubyte4  totalBytesRead = 0;
    MSTATUS status = OK;

    if (NULL == pCircBufDescr)
    {
        return ERR_NULL_POINTER;
    }

    if (NULL != pRetNumBytesRead)
        *pRetNumBytesRead = 0;

    pBuffer = pCircBufDescr->pBuffer;
    buflen  = pCircBufDescr->buflen;
    head    = pCircBufDescr->head;
    tail    = pCircBufDescr->tail;

    if (tail >= buflen)
        tail = 0;

    if ((head < tail) && (numBytesToRead > 0))
    {
        if (0 < (numBytesToCopy = buflen - tail))
        {
            numBytesCopied = (numBytesToRead > numBytesToCopy) ? numBytesToCopy : numBytesToRead;

            status = MOC_MEMCPY(pReadBuffer, pBuffer + tail, numBytesCopied);

            if (OK > status)
                goto exit;

            pReadBuffer    += numBytesCopied;
            numBytesToRead -= numBytesCopied;

            tail += numBytesCopied;
            totalBytesRead += numBytesCopied;
        }

        if (tail >= buflen)
            tail = 0;
    }

    if ((head > tail) && (numBytesToRead > 0))
    {
        numBytesToCopy = head - tail;

        numBytesCopied = (numBytesToRead > numBytesToCopy) ? numBytesToCopy : numBytesToRead;

        status = MOC_MEMCPY(pReadBuffer, pBuffer + tail, numBytesCopied);

        if (OK > status)
            goto exit;

        pReadBuffer    += numBytesCopied;
        numBytesToRead -= numBytesCopied;

        tail += numBytesCopied;
        totalBytesRead += numBytesCopied;
    }

exit:
    if (NULL != pRetNumBytesRead)
        *pRetNumBytesRead = totalBytesRead;

    if (tail >= buflen)
        tail = 0;

    pCircBufDescr->tail = tail;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
CIRC_BUF_bytesAvail(circBufDescr *pCircBufDescr, ubyte4 *pRetNumBytesPending)
{
    ubyte4  buflen = 0;
    ubyte4  head   = 0;
    ubyte4  tail   = 0;

    if ((NULL == pCircBufDescr) || (NULL == pRetNumBytesPending))
    {
        return ERR_NULL_POINTER;
    }

    buflen  = pCircBufDescr->buflen;
    head    = pCircBufDescr->head;
    tail    = pCircBufDescr->tail;

    if (tail >= buflen)
        tail = 0;

    if (head < tail)
        *pRetNumBytesPending = (buflen - tail) + head;

    if (head >= tail)
        *pRetNumBytesPending = head - tail;

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
CIRC_BUF_write(circBufDescr *pCircBufDescr,
               ubyte *pBuffer, ubyte4 numBytesToWrite, ubyte4 *pRetNumBytesWritten)
{
    ubyte4  numBytesWritten = 0;
    ubyte4  buflen;
    ubyte4  head;
    ubyte4  tail;
    ubyte4  avail;
    ubyte4  count;
    MSTATUS status  = OK;

    if ((NULL == pCircBufDescr) || (NULL == pBuffer))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* we wait until we arrive here before we allocate a circular buffer */
    if ((NULL ==  pCircBufDescr->pBuffer) &&
        (NULL == (pCircBufDescr->pBuffer = (ubyte*) MALLOC(pCircBufDescr->buflen))) )
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (pCircBufDescr->head == pCircBufDescr->tail)
    {
        pCircBufDescr->head = pCircBufDescr->tail = 0;
    }

    buflen  = pCircBufDescr->buflen;
    head    = pCircBufDescr->head;
    tail    = pCircBufDescr->tail;

    if (head >= tail)
    {
        avail = buflen - head;

        if (0 == tail)
            avail--;

        count = (avail < numBytesToWrite) ? avail : numBytesToWrite;

        if (0 < count)
        {
            if (OK > (status = MOC_MEMCPY(pCircBufDescr->pBuffer + head, pBuffer, count)))
                goto exit;

            numBytesWritten += count;
            pBuffer         += count;
            numBytesToWrite -= count;
            head            += count;

            if (head == buflen)
                head = 0;
        }
    }

    if ((head < tail) && numBytesToWrite)
    {
        avail = tail - head - 1;

        if (numBytesToWrite > avail)
            numBytesToWrite = avail;

        count = numBytesToWrite;

        if (OK > (status = MOC_MEMCPY(pCircBufDescr->pBuffer + head, pBuffer, count)))
            goto exit;

        numBytesWritten += count;
        head            += count;

        if (head == buflen)
            head = 0;
    }

    pCircBufDescr->head = head;

exit:
    if (NULL != pRetNumBytesWritten)
        *pRetNumBytesWritten = numBytesWritten;

    return status;
}
