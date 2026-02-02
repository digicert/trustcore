/*
 * instance.h
 *
 * Instance Factory Header
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

#ifndef __INSTANCE_HEADER__
#define __INSTANCE_HEADER__

/*---------------------------------------------------------------------------*/

/* low 16 bits */
#define INSTANCE_NUM_BITS_INDEX             (16)
#define INSTANCE_MASK_INDEX                 ((1L << INSTANCE_NUM_BITS_INDEX) - 1)

/* bits 16..24 */
#define INSTANCE_NUM_BITS_AGE               (8)
#define INSTANCE_MASK_AGE_INDEX             ((1L << (INSTANCE_NUM_BITS_AGE + INSTANCE_NUM_BITS_INDEX)) - 1)
#define INSTANCE_INCREMENT_AGE_MACRO(X)     (((X) + (1L << (INSTANCE_NUM_BITS_INDEX))) & (INSTANCE_MASK_AGE_INDEX))

#define INSTANCE_OPEN                       (1L << (INSTANCE_NUM_BITS_INDEX + INSTANCE_NUM_BITS_AGE))
#define INSTANCE_MASK_STATUS_MACRO(X)       ((X) & INSTANCE_OPEN)

#define INSTANCE_BAD_VALUE                  (0xffffffff)


/*---------------------------------------------------------------------------*/

typedef struct instanceDescr
{
    union
    {
        void*                   pContext;
        ubyte4                  index;

        struct instanceDescr*   pNext;  /* used, if on the free list */

    } u;

    ubyte4  instanceId;

} instanceDescr;

typedef struct instanceTableDescr
{
    instanceDescr*  pArrayInstances;
    ubyte4          sizeofArray;

    instanceDescr*  pFreeList;

    void*           pTableCookie;

} instanceTableDescr;


/*---------------------------------------------------------------------------*/

/* WARNING: none of these APIs are mutex protected */

/* allocation */
MOC_EXTERN MSTATUS INSTANCE_createTable(instanceTableDescr **ppRetTable, void *pTableCookie, ubyte4 tableSize);
MOC_EXTERN MSTATUS INSTANCE_releaseTable(instanceTableDescr **ppReleaseTable, void **ppRetTableCookie);

/* get/put instances (two types of instances: pointer & index) */
MOC_EXTERN MSTATUS INSTANCE_getInstanceSetContext(instanceTableDescr *pInstanceTable, ubyte4 *pRetNewInstance, void *pContext);
MOC_EXTERN MSTATUS INSTANCE_putInstanceGetContext(instanceTableDescr *pInstanceTable, ubyte4 putInstance, void **ppRetContext);

MOC_EXTERN MSTATUS INSTANCE_getInstanceSetIndex(instanceTableDescr *pInstanceTable, ubyte4 *pRetNewInstance, ubyte4 index);
MOC_EXTERN MSTATUS INSTANCE_putInstanceGetIndex(instanceTableDescr *pInstanceTable, ubyte4 putInstance, ubyte4 *pRetIndex);

/* finding associated index/context for a given instance */
MOC_EXTERN MSTATUS INSTANCE_getIndexFromInstance(instanceTableDescr *pInstanceTable, ubyte4 instance, ubyte4 *pRetIndex);
MOC_EXTERN MSTATUS INSTANCE_getContextFromInstance(instanceTableDescr *pInstanceTable, ubyte4 instance, void **ppRetContext);

/* for traversing active sessions --- should be used with caution */
MOC_EXTERN MSTATUS INSTANCE_traverseListInit(instanceTableDescr *pInstanceTable, ubyte4 *pRetTracker);
MOC_EXTERN MSTATUS INSTANCE_traverseContextListGetNext(instanceTableDescr *pInstanceTable, ubyte4 *pRetTracker, ubyte4 *pRetInstance, void **ppRetNextContext);
MOC_EXTERN MSTATUS INSTANCE_traverseIndexListGetNext(instanceTableDescr *pInstanceTable, ubyte4 *pRetTracker, ubyte4 *pRetInstance, ubyte4 *pRetNextIndex);

#endif /* __INSTANCE_HEADER__ */
