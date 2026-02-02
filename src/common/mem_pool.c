/*
 * mem_pool.c
 *
 * Memory Pool Factory
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
#include "../common/mem_pool.h"

#if (!defined(__DISABLE_DIGICERT_COMMON_MEM_POOL__))

/*------------------------------------------------------------------*/

static MSTATUS
MEM_POOL_threadPool(poolHeaderDescr *pPool)
{
    poolLink*   pLinkPools;
    sbyte4      count  = pPool->numPoolElements;
    MSTATUS     status = OK;

    if (0 == count)
    {
        status = ERR_MEM_POOL_COUNT_ZERO;
        goto exit;
    }

    /* reset head of pool to start of memory pool */
    pLinkPools = pPool->pHeadOfPool = (poolLink*) pPool->pStartOfPool;

    while (0 < (count - 1))
    {
        pLinkPools->pNextPool = (poolLink *)(((ubyte *)pLinkPools) + pPool->poolObjectSize);

        pLinkPools = pLinkPools->pNextPool;
        count--;
    }

    pLinkPools->pNextPool = NULL;

exit:
    return status;

} /* MEM_POOL_threadPool */


/*------------------------------------------------------------------*/

extern MSTATUS
MEM_POOL_createPool(poolHeaderDescr **ppRetPool, void *pMemPoolBase,
                    ubyte4 memAllocForPool, ubyte4 poolObjectSize)
{
    poolHeaderDescr*    pNewPool = NULL;
    MSTATUS             status = OK;

    if ((NULL == ppRetPool) || (NULL == pMemPoolBase))
    {
        status = ERR_MEM_POOL_NULL_PTR;
        goto exit;
    }

    *ppRetPool = NULL;

    if ((sizeof(poolLink) > poolObjectSize) || (poolObjectSize & (sizeof(void *)-1)))
    {
        /* pool object too small or size is not multiple of 8 */
        status = ERR_MEM_POOL_CREATE;
        goto exit;
    }

    if (NULL == (pNewPool = (poolHeaderDescr*) MALLOC(sizeof(poolHeaderDescr))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    /* clear out memory pool head */
    DIGI_MEMSET((ubyte *)pNewPool, 0x00, sizeof(poolHeaderDescr));

    pNewPool->pStartOfPool    = pMemPoolBase;
    pNewPool->poolObjectSize  = poolObjectSize;
    pNewPool->memAllocForPool = memAllocForPool;
    pNewPool->numPoolElements = memAllocForPool / poolObjectSize;

    if (OK <= (status = MEM_POOL_threadPool(pNewPool)))
    {
        *ppRetPool = pNewPool;
        pNewPool = NULL;
    }

exit:
    if (pNewPool)
        FREE(pNewPool);

    return status;

} /* MEM_POOL_createPool */


/*------------------------------------------------------------------*/

extern MSTATUS
MEM_POOL_initPool(poolHeaderDescr *pInitPool, void *pMemPoolBase,
                  ubyte4 memAllocForPool, ubyte4 poolObjectSize)
{
    MSTATUS             status = OK;

    if ((NULL == pInitPool) || (NULL == pMemPoolBase))
    {
        status = ERR_MEM_POOL_NULL_PTR;
        goto exit;
    }

    if ((sizeof(poolLink) > poolObjectSize) || (poolObjectSize & (sizeof(void *)-1)))
    {
        /* pool object too small */
        status = ERR_MEM_POOL_CREATE;
        goto exit;
    }

    /* clear out memory pool head */
    DIGI_MEMSET((ubyte *)pInitPool, 0x00, sizeof(poolHeaderDescr));

    pInitPool->pStartOfPool    = pMemPoolBase;
    pInitPool->poolObjectSize  = poolObjectSize;
    pInitPool->memAllocForPool = memAllocForPool;
    pInitPool->numPoolElements = memAllocForPool / poolObjectSize;

    status = MEM_POOL_threadPool(pInitPool);

exit:
    return status;

} /* MEM_POOL_initPool */


/*------------------------------------------------------------------*/

extern MSTATUS
MEM_POOL_recyclePoolMemory(poolHeaderDescr *pRecyclePool, ubyte4 poolObjectSize)
{
    MSTATUS status;

    if (NULL == pRecyclePool)
    {
        status = ERR_MEM_POOL_NULL_PTR;
        goto exit;
    }

    if (sizeof(poolLink) > poolObjectSize)
    {
        /* pool object too small */
        status = ERR_MEM_POOL_CREATE;
        goto exit;
    }

    pRecyclePool->poolObjectSize = poolObjectSize;
    pRecyclePool->numPoolElements = pRecyclePool->memAllocForPool / poolObjectSize;

    status = MEM_POOL_threadPool(pRecyclePool);

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MEM_POOL_uninitPool(poolHeaderDescr *pUninitPool, void **ppRetOrigMemPoolBase)
{
    MSTATUS status;

    if ((NULL == pUninitPool) || (NULL == ppRetOrigMemPoolBase))
    {
        status = ERR_MEM_POOL_NULL_PTR;
        goto exit;
    }

    *ppRetOrigMemPoolBase = pUninitPool->pStartOfPool;

    status = DIGI_MEMSET((ubyte *)pUninitPool, 0x00, sizeof(poolHeaderDescr));

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MEM_POOL_freePool(poolHeaderDescr **ppFreePool, void **ppRetOrigMemPoolBase)
{
    MSTATUS status;

    if ((NULL == ppFreePool) || (NULL == *ppFreePool))
    {
        status = ERR_MEM_POOL_NULL_PTR;
        goto exit;
    }

    if (NULL != ppRetOrigMemPoolBase)
        *ppRetOrigMemPoolBase = (*ppFreePool)->pStartOfPool;

    FREE(*ppFreePool);

    *ppFreePool = NULL;
    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
MEM_POOL_getPoolObject(poolHeaderDescr *pPool, void **ppGetPoolObject)
{
    MSTATUS status = ERR_MEM_POOL_GET_POOL_EMPTY;

    if ((NULL == pPool) || (NULL == ppGetPoolObject))
    {
        status = ERR_MEM_POOL_NULL_PTR;
        goto exit;
    }

    if (NULL != (*ppGetPoolObject = (void *)(pPool->pHeadOfPool)))
    {
        pPool->pHeadOfPool = ((poolLink *)(*ppGetPoolObject))->pNextPool;
        status = OK;
    }

exit:
    return status;

} /* MEM_POOL_getPoolObject */


/*------------------------------------------------------------------*/

extern MSTATUS
MEM_POOL_putPoolObject(poolHeaderDescr *pPool, void **ppPutPoolObject)
{
    void*       startRange;
    void*       endRange;
    poolLink*   pLinkPools;
    MSTATUS     status = ERR_MEM_POOL_BAD_PUT_POOL_OBJ;

    if ((NULL == pPool) || (NULL == ppPutPoolObject) || (NULL == *ppPutPoolObject))
    {
        status = ERR_MEM_POOL_NULL_PTR;
        goto exit;
    }

    startRange = pPool->pStartOfPool;
    endRange   = (void*)((ubyte*)startRange + pPool->memAllocForPool);

    /* minimal sanity check */
    if ((startRange <= (*ppPutPoolObject)) &&
        (endRange   >  (*ppPutPoolObject)) )
    {
        pLinkPools = (poolLink *)(*ppPutPoolObject);

        /* link next pool to old first pool */
        pLinkPools->pNextPool = pPool->pHeadOfPool;

        /* now make new pool first in pool list */
        pPool->pHeadOfPool = pLinkPools;

        *ppPutPoolObject = NULL;
        status = OK;
    }

exit:
    return status;

} /* MEM_POOL_putPoolObject */


/*------------------------------------------------------------------*/

extern MSTATUS
MEM_POOL_getIndexForObject(poolHeaderDescr *pPool, void *pPoolObject, sbyte4 *pRetIndex)
{
    void*       startRange;
    void*       endRange;
    MSTATUS      status = ERR_MEM_POOL;

    if ((NULL == pPool) || (NULL == pPoolObject) || (NULL == pRetIndex))
    {
        status = ERR_MEM_POOL_NULL_PTR;
        goto exit;
    }

    startRange = pPool->pStartOfPool;
    endRange   = (void*)((ubyte*)startRange + pPool->memAllocForPool);

    if ((startRange <= pPoolObject) &&
        (endRange > pPoolObject))
    {
        if (((ubyte4)((ubyte*)pPoolObject - (ubyte*)startRange)) % pPool->poolObjectSize)
        {
            goto exit;
        }

        *pRetIndex = (sbyte4)
                (((ubyte4)((ubyte*)pPoolObject - (ubyte*)startRange)) / pPool->poolObjectSize);
        status = OK;
    }

exit:
    return status;
} /* MEM_POOL_getIndexForObject */

#endif /* __DISABLE_DIGICERT_COMMON_MEM_POOL__ */
