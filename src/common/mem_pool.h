/*
 * mem_pool.h
 *
 * Memory Pool Factory Header
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

#ifndef __MEMORY_POOL_HEADER__
#define __MEMORY_POOL_HEADER__


/*------------------------------------------------------------------*/

typedef struct poolLink_s
{
    struct poolLink_s*  pNextPool;

} poolLink;

typedef struct
{
    poolLink*           pHeadOfPool;
    void*               pStartOfPool;
    sbyte4              numPoolElements;
    ubyte4              poolObjectSize;
    ubyte4              memAllocForPool;

} poolHeaderDescr;


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MEM_POOL_createPool(poolHeaderDescr **ppRetPool, void *pMemPoolBase, ubyte4 memAllocForPool, ubyte4 poolObjectSize);
MOC_EXTERN MSTATUS MEM_POOL_initPool(poolHeaderDescr *pInitPool, void *pMemPoolBase, ubyte4 memAllocForPool, ubyte4 poolObjectSize);
MOC_EXTERN MSTATUS MEM_POOL_uninitPool(poolHeaderDescr *pInitPool, void **ppRetOrigMemPoolBase);

MOC_EXTERN MSTATUS MEM_POOL_recyclePoolMemory(poolHeaderDescr *pRecyclePool, ubyte4 poolObjectSize);
MOC_EXTERN MSTATUS MEM_POOL_freePool(poolHeaderDescr **ppFreePool, void **ppRetOrigMemPoolBase);

MOC_EXTERN MSTATUS MEM_POOL_getPoolObject(poolHeaderDescr *pPool, void **ppGetPoolObject);
MOC_EXTERN MSTATUS MEM_POOL_putPoolObject(poolHeaderDescr *pPool, void **ppPutPoolObject);

MOC_EXTERN MSTATUS MEM_POOL_getIndexForObject(poolHeaderDescr *pPool, void *pPoolObject, sbyte4 *pRetIndex);

#endif /* __MEMORY_POOL_HEADER__ */
