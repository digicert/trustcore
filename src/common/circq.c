/*
 * circq.c
 *
 * Circular Queue Factory
 * Lockless Safe for 1 Writer / 1 reader
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
#include "../common/circq.h"


/*------------------------------------------------------------------*/


extern MSTATUS
CIRCQ_init (c_queue_t **ppCq, ubyte4 capacity)
{
    MSTATUS status = OK;
    c_queue_t *pCq = (c_queue_t *) MALLOC(sizeof(c_queue_t));

    if (NULL == pCq)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    pCq->ppQueue = (ubyte**) MALLOC(sizeof(ubyte *) * (capacity + 1));

    if (NULL == pCq->ppQueue)
    {
        status = ERR_MEM_ALLOC_FAIL;
        FREE(pCq);
        goto exit;
    }

    pCq->head = 0;
    pCq->tail = 0;
    pCq->capacity = capacity;
    *ppCq = pCq;

exit:
    return status;
}


/*------------------------------------------------------------------*/


extern MSTATUS
CIRCQ_deInit (c_queue_t *pCq)
{
    MSTATUS status = OK;

    if (NULL == pCq)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    FREE (pCq->ppQueue);
    FREE (pCq);

exit:
    return status;

}


/*------------------------------------------------------------------*/

extern MSTATUS
CIRCQ_enq(c_queue_t *pCq, ubyte *pData)
{
    MSTATUS status = OK;

    if (NULL == pCq)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if  ((pCq->tail + 1) % (pCq->capacity + 1) == pCq->head)
    {
        status = ERR_CIRCQ_FULL;
        goto exit;
    }

    pCq->ppQueue[pCq->tail] = pData;
    pCq->tail = (pCq->tail + 1) % (pCq->capacity + 1);

exit:
    return status;
}

/*------------------------------------------------------------------*/


extern MSTATUS
CIRCQ_deq(c_queue_t *pCq, ubyte **ppData)
{

    MSTATUS status = OK;

    if (NULL == pCq)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (pCq->head == pCq->tail)
    {
        status = ERR_CIRCQ_EMPTY;
        goto exit;
    }


    *ppData = pCq->ppQueue[pCq->head];
    pCq->head = (pCq->head + 1) % (pCq->capacity + 1);

exit:

    return status;
}

/*------------------------------------------------------------------*/
