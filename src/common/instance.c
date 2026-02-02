/*
 * instance.c
 *
 * (Session/Context) Instance Factory
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
#include "../common/instance.h"


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
INSTANCE_createTable(instanceTableDescr **ppRetNewInstanceTable, void *pTableCookie, ubyte4 tableSize)
{
    instanceTableDescr* pTable = NULL;
    instanceDescr*      pArray;
    ubyte4              bufSize;
    ubyte4              i;
    MSTATUS             status;

    /* the world needs minimal limits */
    if (3 > tableSize)
        tableSize = 3;

    *ppRetNewInstanceTable = NULL;

    if (INSTANCE_MASK_INDEX < tableSize)
    {
        status = ERR_INSTANCE_TABLE_TOO_BIG;
        goto exit;
    }

    bufSize = sizeof(instanceTableDescr) + (tableSize * sizeof(instanceDescr));

    if (NULL == (pTable = (instanceTableDescr*) MALLOC(bufSize)))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    if (OK > (status = DIGI_MEMSET((ubyte *)pTable, 0x00, bufSize)))
        goto exit;

    pArray = pTable->pFreeList = pTable->pArrayInstances = (instanceDescr *)(1 + pTable);
    pTable->sizeofArray = tableSize;
    pTable->pTableCookie = pTableCookie;

    /* thread the free list */
    for (i = 0; i < tableSize - 1; i++)
    {
        pArray[i].u.pNext = &pArray[1 + i];
        pArray[i].instanceId = i;
    }

    pArray[tableSize - 1].u.pNext = NULL;
    pArray[tableSize - 1].instanceId = tableSize - 1;

    *ppRetNewInstanceTable = pTable;
    pTable = NULL;

exit:
    if (pTable)
    {
        FREE(pTable);
    }

    return status;

} /* INSTANCE_createTable */


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
INSTANCE_releaseTable(instanceTableDescr **ppReleaseInstanceTable, void **ppRetTableCookie)
{
    if ((NULL != ppReleaseInstanceTable) && (NULL != *ppReleaseInstanceTable))
    {
        if (NULL != ppRetTableCookie)
            *ppRetTableCookie = (*ppReleaseInstanceTable)->pTableCookie;

        FREE(*ppReleaseInstanceTable);
        *ppReleaseInstanceTable = NULL;
    }

    return OK;
}


/*---------------------------------------------------------------------------*/

static MSTATUS
INSTANCE_findInstance(instanceTableDescr *pInstanceTable, ubyte4 instance, instanceDescr **ppRetInstanceDescr)
{
    ubyte4  index  = instance & INSTANCE_MASK_INDEX;
    ubyte4  instanceId;
    MSTATUS status = OK;

    if ((index >= pInstanceTable->sizeofArray) || (INSTANCE_BAD_VALUE == instance))
    {
        /* index wrong, a severe bug */
        status = ERR_INSTANCE_BAD_ID;
        goto exit;
    }

    instanceId = pInstanceTable->pArrayInstances[index].instanceId;

    if (INSTANCE_OPEN != INSTANCE_MASK_STATUS_MACRO(instanceId))
    {
        /* good index in table, but the connection is closed. */
        status = ERR_INSTANCE_CLOSED;
        goto exit;
    }

    if (instanceId != instance)
    {
        /* good index in table, but the age is wrong. */
        status = ERR_INSTANCE_STALE_ID;
        goto exit;
    }

    /* return instance decriptor */
    *ppRetInstanceDescr = &pInstanceTable->pArrayInstances[index];

exit:
    return status;

} /* INSTANCE_getInstance */


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
INSTANCE_getIndexFromInstance(instanceTableDescr *pInstanceTable, ubyte4 instance, ubyte4 *pRetIndex)
{
    instanceDescr*  pInstanceDescr = NULL;
    MSTATUS         status;

    if (OK > (status = INSTANCE_findInstance(pInstanceTable, instance, &pInstanceDescr)))
        goto exit;

    /* return associated index */
    *pRetIndex = pInstanceDescr->u.index;

exit:
    return status;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
INSTANCE_getContextFromInstance(instanceTableDescr *pInstanceTable, ubyte4 instance, void **ppRetContext)
{
    instanceDescr*  pInstanceDescr = NULL;
    MSTATUS         status;

    if (OK > (status = INSTANCE_findInstance(pInstanceTable, instance, &pInstanceDescr)))
        goto exit;

    /* return associated index */
    *ppRetContext = pInstanceDescr->u.pContext;

exit:
    return status;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
INSTANCE_getInstanceSetContext(instanceTableDescr *pInstanceTable, ubyte4 *pRetNewInstance, void *pContext)
{
    instanceDescr*  pInstanceDescr = NULL;
    MSTATUS         status = ERR_INSTANCE_FREE_LIST_EMPTY;

    /* set to bad instance */
    *pRetNewInstance = INSTANCE_BAD_VALUE;

    if (NULL != pInstanceTable->pFreeList)
    {
        /* pull the first instance off the freelist */
        pInstanceDescr = pInstanceTable->pFreeList;

        /* set freelist to next instance */
        pInstanceTable->pFreeList = pInstanceTable->pFreeList->u.pNext;

        /* bind context to instance */
        pInstanceDescr->u.pContext = pContext;

        /* set instance to open */
        *pRetNewInstance = pInstanceDescr->instanceId |= INSTANCE_OPEN;

        status = OK;
    }

    return status;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
INSTANCE_putInstanceGetContext(instanceTableDescr *pInstanceTable, ubyte4 putInstance, void **ppRetContext)
{
    instanceDescr*  pInstanceDescr = NULL;
    MSTATUS         status;

    if (OK > (status = INSTANCE_findInstance(pInstanceTable, putInstance, &pInstanceDescr)))
        goto exit;

    /* return back associated context for instance */
    *ppRetContext = pInstanceDescr->u.pContext;

    /* clear instance open bit and increment age */
    pInstanceDescr->instanceId = INSTANCE_INCREMENT_AGE_MACRO(pInstanceDescr->instanceId);

    /* add instance to head of free list */
    pInstanceDescr->u.pNext = pInstanceTable->pFreeList;
    pInstanceTable->pFreeList = pInstanceDescr;

exit:
    return status;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
INSTANCE_getInstanceSetIndex(instanceTableDescr *pInstanceTable, ubyte4 *pRetNewInstance, ubyte4 index)
{
    instanceDescr*  pInstanceDescr = NULL;
    MSTATUS         status = ERR_INSTANCE_FREE_LIST_EMPTY;

    /* set to bad instance */
    *pRetNewInstance = INSTANCE_BAD_VALUE;

    if (NULL != pInstanceTable->pFreeList)
    {
        /* pull the first instance off the freelist */
        pInstanceDescr = pInstanceTable->pFreeList;

        /* set freelist to next instance */
        pInstanceTable->pFreeList = pInstanceTable->pFreeList->u.pNext;

        /* bind index to instance */
        pInstanceDescr->u.index = index;

        /* set instance to open */
        *pRetNewInstance = pInstanceDescr->instanceId |= INSTANCE_OPEN;

        status = OK;
    }

    return status;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
INSTANCE_putInstanceGetIndex(instanceTableDescr *pInstanceTable, ubyte4 putInstance, ubyte4 *pRetIndex)
{
    instanceDescr*  pInstanceDescr = NULL;
    MSTATUS         status;

    if (OK > (status = INSTANCE_findInstance(pInstanceTable, putInstance, &pInstanceDescr)))
        goto exit;

    /* return back associated index for instance */
    *pRetIndex = pInstanceDescr->u.index;

    /* clear instance open bit and increment age */
    pInstanceDescr->instanceId = INSTANCE_INCREMENT_AGE_MACRO(pInstanceDescr->instanceId);

    /* add instance to head of free list */
    pInstanceDescr->u.pNext = pInstanceTable->pFreeList;
    pInstanceTable->pFreeList = pInstanceDescr;

exit:
    return status;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
INSTANCE_traverseListInit(instanceTableDescr *pInstanceTable, ubyte4 *pRetTracker)
{
    ubyte4  i;
    MSTATUS status = OK;

    if ((NULL == pInstanceTable) || (NULL == pRetTracker))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    for (i = 0; i < pInstanceTable->sizeofArray; i++)
        if (pInstanceTable->pArrayInstances[i].instanceId & INSTANCE_OPEN)
            break;

    *pRetTracker = i;

exit:
    return status;
}


/*---------------------------------------------------------------------------*/

static MSTATUS
INSTANCE_traverseListGetNext(instanceTableDescr *pInstanceTable, ubyte4 *pRetTracker, ubyte4 *pRetInstance, void **ppRetNextContext, ubyte4 *pRetNextIndex)
{
    ubyte4  i;
    MSTATUS status = OK;

    /* end of list reached? */
    if (*pRetTracker >= pInstanceTable->sizeofArray)
    {
        /* we get cranky if we already said we passed the end of the list */
        if (*pRetTracker >= (1 + pInstanceTable->sizeofArray))
            status = ERR_INSTANCE_PASSED_END_LIST_REACHED;
        else
            *pRetTracker += 1;

        goto exit;
    }

    for (i = *pRetTracker; i < pInstanceTable->sizeofArray; i++)
    {
        if (pInstanceTable->pArrayInstances[i].instanceId & INSTANCE_OPEN)
        {
            if (NULL != ppRetNextContext)
                *ppRetNextContext = pInstanceTable->pArrayInstances[i].u.pContext;

            if (NULL != pRetNextIndex)
                *pRetNextIndex = pInstanceTable->pArrayInstances[i].u.index;

            *pRetInstance = pInstanceTable->pArrayInstances[i].instanceId;
            i++;

            break;
        }
    }

    *pRetTracker = i;

exit:
    return status;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
INSTANCE_traverseContextListGetNext(instanceTableDescr *pInstanceTable, ubyte4 *pRetTracker, ubyte4 *pRetInstance, void **ppRetNextContext)
{
    MSTATUS status = OK;

    if ((NULL == pInstanceTable) || (NULL == pRetTracker) || (NULL == ppRetNextContext))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *ppRetNextContext = NULL;

    status = INSTANCE_traverseListGetNext(pInstanceTable, pRetTracker, pRetInstance, ppRetNextContext, NULL);

exit:
    return status;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
INSTANCE_traverseIndexListGetNext(instanceTableDescr *pInstanceTable, ubyte4 *pRetTracker, ubyte4 *pRetInstance, ubyte4 *pRetNextIndex)
{
    MSTATUS status = OK;

    if ((NULL == pInstanceTable) || (NULL == pRetTracker) || (NULL == pRetNextIndex))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pRetNextIndex = INSTANCE_BAD_VALUE;

    status = INSTANCE_traverseListGetNext(pInstanceTable, pRetTracker, pRetInstance, NULL, pRetNextIndex);

exit:
    return status;
}
