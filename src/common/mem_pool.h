/*
 * mem_pool.h
 *
 * Memory Pool Factory Header
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
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
