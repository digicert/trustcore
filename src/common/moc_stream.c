/*
 * moc_stream.c
 *
 * Mocana Simple Stream Factory
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
#include "../common/moc_stream.h"


/*------------------------------------------------------------------*/

static MSTATUS
moc_stream_addToBuffer(streamDescr *pStreamDescr,
                       const ubyte *pBuffer, ubyte4 numBytes,
                       ubyte4 *pRetNumBytesWritten)
{
    ubyte4  numBytesWritten = 0;
    ubyte4  buflen;
    ubyte4  head;
    ubyte4  tail;
    ubyte4  avail;
    ubyte4  count;
    MSTATUS status  = OK;

    /* we wait until we arrive here before we allocate a stream buffer */
    if ((NULL ==  pStreamDescr->pBuffer) &&
        (NULL == (pStreamDescr->pBuffer = (ubyte*) MALLOC(pStreamDescr->buflen))) )
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (pStreamDescr->head == pStreamDescr->tail)
    {
        pStreamDescr->head = pStreamDescr->tail = 0;
    }

    buflen  = pStreamDescr->buflen;
    head    = pStreamDescr->head;
    tail    = pStreamDescr->tail;

    if (head >= tail)
    {
        avail = buflen - head;

        if (0 == tail)
            avail--;

        count = (avail < numBytes) ? avail : numBytes;

        if (0 < count)
        {
            if (OK > (status = MOC_MEMCPY(pStreamDescr->pBuffer + head, pBuffer, count)))
                goto exit;

            numBytesWritten += count;
            pBuffer         += count;
            numBytes        -= count;
            head            += count;

            if (head == buflen)
                head = 0;
        }
    }

    if ((head < tail) && numBytes)
    {
        avail = tail - head - 1;

        if (numBytes > avail)
            numBytes = avail;

        count = numBytes;

        if (OK > (status = MOC_MEMCPY(pStreamDescr->pBuffer + head, pBuffer, count)))
            goto exit;

        numBytesWritten += count;
        head            += count;

        if (head == buflen)
            head = 0;
    }

    pStreamDescr->head = head;

exit:
    *pRetNumBytesWritten = numBytesWritten;

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MOC_STREAM_open(streamDescr **ppRetStreamDescr,
                void* outStream, ubyte4 buflen,
                funcStreamWriteData pFuncWriteData)
{
    streamDescr* pStreamDescr = NULL;
    MSTATUS      status;

    if ((NULL == ppRetStreamDescr) || (NULL == pFuncWriteData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (pStreamDescr = (streamDescr*) MALLOC(sizeof(streamDescr))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    status = MOC_MEMSET((ubyte *)pStreamDescr, 0x00, sizeof(streamDescr));

    pStreamDescr->outStream       = outStream;
    pStreamDescr->buflen          = buflen;
    pStreamDescr->head            = 0;
    pStreamDescr->tail            = 0;
    pStreamDescr->pFuncWriteData  = pFuncWriteData;
    pStreamDescr->pBuffer         = NULL;

    *ppRetStreamDescr  = pStreamDescr;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MOC_STREAM_close(streamDescr **ppFreeStreamDescr)
{
    MSTATUS status = OK;

    if ((NULL == ppFreeStreamDescr) || (NULL == *ppFreeStreamDescr))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != (*ppFreeStreamDescr)->pBuffer)
    {
        FREE((*ppFreeStreamDescr)->pBuffer);
    }

    FREE(*ppFreeStreamDescr);
    *ppFreeStreamDescr = NULL;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MOC_STREAM_flush(streamDescr *pStreamDescr,
                 ubyte4 *pRetNumBytesPending, intBoolean *pFlushComplete)
{
/*
 * if pending buffer is completely written out, then *pFlushComplete is set to
 * true upon return, else *pFlushComplete is set to FALSE.
 */
    ubyte*  pBuffer;
    ubyte4  buflen = 0;
    ubyte4  head   = 0;
    ubyte4  tail   = 0;
    ubyte4  numBytesToWrite;
    ubyte4  numBytesWritten;
    MSTATUS status = OK;

    if ((NULL == pStreamDescr) || (NULL == pStreamDescr->pFuncWriteData))
    {
        status = ERR_NULL_POINTER;
        return status;
    }

    pBuffer = pStreamDescr->pBuffer;
    buflen  = pStreamDescr->buflen;
    head    = pStreamDescr->head;
    tail    = pStreamDescr->tail;

    while (head < tail)
    {
        if (0 < (numBytesToWrite = buflen - tail))
        {
            numBytesWritten = 0;

            status = pStreamDescr->pFuncWriteData(pStreamDescr->outStream, pBuffer + tail,
                                                  numBytesToWrite, &numBytesWritten);

            if ((OK > status) || (0 == numBytesWritten))
                goto exit;

            if (numBytesWritten > numBytesToWrite)
            {
                status = ERR_BUFFER_OVERFLOW;
                goto exit;
            }

            tail += numBytesWritten;
        }

        if (tail >= buflen)
            tail = 0;
    }

    while (head > tail)
    {
        numBytesWritten = 0;
        numBytesToWrite = head - tail;

        status = pStreamDescr->pFuncWriteData(pStreamDescr->outStream, pBuffer + tail,
                                              head - tail, &numBytesWritten);

        if ((OK > status) || (0 == numBytesWritten))
            goto exit;

        if (numBytesWritten > numBytesToWrite)
        {
            status = ERR_BUFFER_OVERFLOW;
            goto exit;
        }

        tail += numBytesWritten;
    }

exit:
    if (tail >= buflen)
        tail = 0;

    pStreamDescr->tail = tail;

    if (NULL != pFlushComplete)
        *pFlushComplete = (head == tail) ? TRUE : FALSE;

    if (NULL != pRetNumBytesPending)
        *pRetNumBytesPending = ((head >= tail) ? (head - tail) : (head + (buflen - tail)) );

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MOC_STREAM_write(streamDescr *pStreamDescr,
                 ubyte *pBuffer, ubyte4 numBytesToWrite,
                 ubyte4 *pRetNumBytesWritten)
{
    ubyte4      numBytesWritten;
    ubyte4      bytesVacant;
    intBoolean  flushComplete;
    MSTATUS     status;

    if ((NULL == pStreamDescr) || (NULL == pBuffer) ||
        (NULL == pStreamDescr->pFuncWriteData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (OK > (status = MOC_STREAM_flush(pStreamDescr, &bytesVacant, &flushComplete)))
        goto exit;

    if (FALSE == flushComplete)
    {
        /* flush didn't complete, add the data to the buffer */
        status = moc_stream_addToBuffer(pStreamDescr, pBuffer, numBytesToWrite, pRetNumBytesWritten);
        goto exit;
    }

    if (OK > (status = pStreamDescr->pFuncWriteData(pStreamDescr->outStream,
                                                 pBuffer, numBytesToWrite, pRetNumBytesWritten)))
    {
        goto exit;
    }

    if (*pRetNumBytesWritten != numBytesToWrite)
    {
        numBytesToWrite -= (*pRetNumBytesWritten);
        pBuffer         += (*pRetNumBytesWritten);

        status = moc_stream_addToBuffer(pStreamDescr, pBuffer, numBytesToWrite, &numBytesWritten);

        *pRetNumBytesWritten += numBytesWritten;
    }

exit:
    return status;
}
