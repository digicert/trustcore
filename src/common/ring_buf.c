/*
 * ring_buf.c
 *
 * prefer oldest data - always overwrite oldest data with newest data
 * and always return oldest data first in sequence on reads
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
#include "../common/ring_buf.h"


/*------------------------------------------------------------------*/

extern MSTATUS
RING_BUF_create(ringBufDescr **ppRetRingBufDescr, ubyte4 buflen)
{
    ringBufDescr* pRingBufDescr = NULL;
    MSTATUS       status;

    if (NULL == ppRetRingBufDescr)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL == (pRingBufDescr = (ringBufDescr*) MALLOC(sizeof(ringBufDescr))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    status = DIGI_MEMSET((ubyte *)pRingBufDescr, 0x00, sizeof(ringBufDescr));

    pRingBufDescr->buflen          = buflen;
    pRingBufDescr->head            = 0;
    pRingBufDescr->tail            = 0;
    pRingBufDescr->pBuffer         = NULL;
    pRingBufDescr->empty           = 1;
    pRingBufDescr->full            = 0;

    *ppRetRingBufDescr  = pRingBufDescr;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
RING_BUF_release(ringBufDescr **ppFreeRingBufDescr)
{
    MSTATUS status = OK;

    if ((NULL == ppFreeRingBufDescr) || (NULL == *ppFreeRingBufDescr))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (NULL != (*ppFreeRingBufDescr)->pBuffer)
    {
        FREE((*ppFreeRingBufDescr)->pBuffer);
    }

    FREE(*ppFreeRingBufDescr);
    *ppFreeRingBufDescr = NULL;

exit:
    return status;
}

/*------------------------------------------------------------------*/

static ubyte4 test_increment_counter(ringBufDescr * pRingBufDescr, ubyte4 ctr)
{
    ctr++;
    if (pRingBufDescr->buflen == ctr)
        ctr = 0;

    return ctr;
}

/*------------------------------------------------------------------*/

extern MSTATUS
RING_BUF_increment_head(ringBufDescr * pRingBufDescr)
{

    pRingBufDescr->head = test_increment_counter(pRingBufDescr,
						 pRingBufDescr->head);

    return OK;

}

/*------------------------------------------------------------------*/

extern MSTATUS
RING_BUF_increment_tail(ringBufDescr * pRingBufDescr)
{

    pRingBufDescr->tail = test_increment_counter(pRingBufDescr,
						 pRingBufDescr->tail);

    return OK;

}

/*------------------------------------------------------------------*/

extern MSTATUS
RING_BUF_write_byte(ringBufDescr *pRingBufDescr, ubyte * pWriteByte)
{
    ubyte*  pBuffer;
    ubyte4  head   = 0;
    ubyte4  tail   = 0;

    if (NULL == pRingBufDescr)
    {
        return ERR_NULL_POINTER;
    }

    pBuffer = pRingBufDescr->pBuffer;
    head    = pRingBufDescr->head;
    tail    = pRingBufDescr->tail;

    if(pRingBufDescr->full)
    {
        if ( head == tail ) /* overwrite oldest data */
        {
            *(pBuffer+head) = *pWriteByte;
            RING_BUF_increment_tail(pRingBufDescr);
            return OK;
        }
        else
        {
            RING_BUF_increment_head(pRingBufDescr);
            *(pBuffer + pRingBufDescr->head) = *pWriteByte;
            if ( pRingBufDescr->head == tail )
            {
                RING_BUF_increment_tail(pRingBufDescr);
                RING_BUF_increment_head(pRingBufDescr);
            }
            return OK;

        }

    }
    else
    {
        if ( (head == tail) && !pRingBufDescr->empty ) /* not empty, not full */
        {
            RING_BUF_increment_head(pRingBufDescr);
            *(pBuffer + pRingBufDescr->head) = *pWriteByte;
            return OK;
        }
        else
        {
            *(pBuffer + head) = *pWriteByte;
            RING_BUF_increment_head(pRingBufDescr);
            if( pRingBufDescr->empty ) pRingBufDescr->empty = 0;
            if (pRingBufDescr->head == tail) pRingBufDescr->full=1;
            return OK;
        }

    }

}

/*------------------------------------------------------------------*/

extern MSTATUS
RING_BUF_read_byte(ringBufDescr *pRingBufDescr, ubyte * pReadByte)
{
    ubyte*  pBuffer;
    ubyte4  head   = 0;
    ubyte4  tail   = 0;

    if (NULL == pRingBufDescr)
    {
        return ERR_NULL_POINTER;
    }

    if ( pRingBufDescr->empty == 1)
    {
        pRingBufDescr->head=0;
        pRingBufDescr->tail=0;
        return ERR_CIRCQ_EMPTY;
    }

    pBuffer = pRingBufDescr->pBuffer;
    head    = pRingBufDescr->head;
    tail    = pRingBufDescr->tail;

    if ( pRingBufDescr->full == 1)
    {
        if(head == tail)
        {
            *pReadByte = *(pBuffer+tail);
            *(pBuffer+tail) = 0;
            RING_BUF_increment_tail(pRingBufDescr);
            pRingBufDescr->full = 0;
            return OK;

        }
        else
        {
            *pReadByte = *pBuffer+tail;
            *(pBuffer+tail) = 0;
            RING_BUF_increment_tail(pRingBufDescr);
            RING_BUF_increment_head(pRingBufDescr);
            pRingBufDescr->full = 0;
            return OK;
        }
    }
    else /* not full, not empty */
    {
        *pReadByte = *(pBuffer+tail);
        *(pBuffer+tail)=0;
        RING_BUF_increment_tail(pRingBufDescr);
        if (pRingBufDescr->tail == head)
            pRingBufDescr->empty=1;
        return OK;
    }

    return OK;
}

/*------------------------------------------------------------------*/

extern MSTATUS
RING_BUF_write(ringBufDescr *pRingBufDescr,
               ubyte *pBuffer, ubyte4 numBytesToWrite, ubyte4 *pRetNumBytesWritten)
{

    MSTATUS status  = OK;
    ubyte4 index;

    if (pRetNumBytesWritten)
        *pRetNumBytesWritten = 0;

    if ((NULL == pRingBufDescr) || (NULL == pBuffer))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* we wait until we arrive here before we allocate a ring buffer */
    if ((NULL ==  pRingBufDescr->pBuffer) &&
        (NULL == (pRingBufDescr->pBuffer = (ubyte*) MALLOC(pRingBufDescr->buflen))) )
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    for( index = 0; index < numBytesToWrite; index ++)
    {
        if ( OK == (status = RING_BUF_write_byte(pRingBufDescr, pBuffer+index)) )
        {
	    if (pRetNumBytesWritten)
                (*pRetNumBytesWritten)++;
        }
        else
            goto exit;
    }

exit:

    return status;
}

extern MSTATUS
RING_BUF_read(ringBufDescr *pRingBufDescr,
              ubyte *pReadBuffer, ubyte4 numBytesToRead, ubyte4 *pRetNumBytesRead)
{
    MSTATUS status = OK;
    ubyte4 index;

    if (NULL != pRetNumBytesRead)
        *pRetNumBytesRead = 0;

    if ((NULL == pRingBufDescr) || (NULL == pReadBuffer))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for ( index = 0; index < numBytesToRead; index ++ )
    {
        if ( OK == (status = RING_BUF_read_byte(pRingBufDescr, pReadBuffer+index)) )
        {
	    if (NULL != pRetNumBytesRead)
                (*pRetNumBytesRead)++;
        }
        else
            goto exit;
    }

exit:
    return status;

}

extern MSTATUS
RING_BUF_peek(ringBufDescr *pRingBufDescr,
              ubyte *pReadBuffer, ubyte4 numBytesToRead, ubyte4 *pRetNumBytesRead)
{
    ubyte4    index;
    ubyte    *pBuffer;
    ubyte4    head   = 0;
    ubyte4    tail   = 0;
    ubyte     full   = 0;
    ubyte     empty  = 0;

    if (NULL != pRetNumBytesRead)
        *pRetNumBytesRead = 0;

    if ((NULL == pRingBufDescr) || (NULL == pReadBuffer))
    {
        return ERR_NULL_POINTER;
    }

    if ( pRingBufDescr->empty == 1)
    {
        pRingBufDescr->head=0;
        pRingBufDescr->tail=0;
        return ERR_CIRCQ_EMPTY;
    }

    if ( numBytesToRead > pRingBufDescr->buflen)
    {
        return ERR_CIRCQ_EMPTY;
    }

    pBuffer = pRingBufDescr->pBuffer;
    head    = pRingBufDescr->head;
    tail    = pRingBufDescr->tail;
    full    = pRingBufDescr->full;
    empty   = pRingBufDescr->empty;

    for ( index = 0; index < numBytesToRead; index ++ )
    {
        ubyte* pReadByte = pReadBuffer+index;

        if (empty == 1)
	    return ERR_CIRCQ_EMPTY;

        if (full == 1)
	{
	    if(head == tail)
	    {
	        *pReadByte = *(pBuffer+tail);
		tail = test_increment_counter(pRingBufDescr, tail);
		full = 0;
	    }
	    else
	    {
	        /* XXX: Can this state ever exist? */
	        *pReadByte = *pBuffer+tail;
		tail = test_increment_counter(pRingBufDescr, tail);
		head = test_increment_counter(pRingBufDescr, head);
		full = 0;
	    }
	}
	else /* not full, not empty */
	{
	    *pReadByte = *(pBuffer+tail);
	    tail = test_increment_counter(pRingBufDescr, tail);
	    if (tail == head)
	        empty = 1;
	}

	if (NULL != pRetNumBytesRead)
        (*pRetNumBytesRead)++;
    }

    return OK;
}

extern intBoolean
RING_BUF_isEmpty(ringBufDescr *pRingBufDescr)
{
    if (NULL == pRingBufDescr)
        return TRUE;
    return (1 == pRingBufDescr->empty);
}
