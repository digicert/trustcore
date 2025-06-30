/*
 * hash_table.c
 *
 * Hash Table Factory
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
#include "../common/hash_value.h"
#include "../common/hash_table.h"

#if (!defined(__DISABLE_MOCANA_COMMON_HASH_TABLE_FACTORY__))

/*------------------------------------------------------------------*/

extern MSTATUS
HASH_TABLE_createIndiceTable(hashTableIndices **ppRetHashTable, ubyte4 hashTableSizeMask, void *pHashCookie,
                             funcPtrAllocElement pFuncAllocElement, funcPtrFreeElement pFuncFreeElement)
{
    hashTableIndices*   pHashTable = NULL;
    MSTATUS             status = OK;

    if ((NULL == ppRetHashTable) || (NULL == pFuncAllocElement) || (NULL == pFuncFreeElement))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* hashTableSizeMask should be ((2^n)-1) in size */
    if ((0 == (1 & hashTableSizeMask)) ||
        (0 != (((hashTableSizeMask | (hashTableSizeMask - 1)) + 1) & hashTableSizeMask)) )
    {
        status = ERR_HASH_TABLE_BAD_SIZE;
        goto exit;
    }

    if (NULL == (pHashTable = (hashTableIndices*) MALLOC(sizeof(hashTableIndices) + ((1 + hashTableSizeMask) * sizeof(hashTableIndexElement *)))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    MOC_MEMSET((ubyte *)pHashTable, 0x00, sizeof(hashTableIndices) + ((1 + hashTableSizeMask) * sizeof(hashTableIndexElement *)));
    pHashTable->hashTableSizeMask = hashTableSizeMask;
    pHashTable->pHashCookie       = pHashCookie;

    pHashTable->pFuncAllocElement = pFuncAllocElement;
    pHashTable->pFuncFreeElement  = pFuncFreeElement;

    *ppRetHashTable = pHashTable;
    pHashTable = NULL;

exit:
    if (NULL != pHashTable)
        FREE(pHashTable);

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HASH_TABLE_clearIndiceTable(hashTableIndices *pClearHashTable, void *pClearCtx, MSTATUS(*funcPtrClearIndex)(void * /* pClearCtx */, ubyte4 /* appDataIndex */))
{
    hashTableIndexElement*  pBucket;
    hashTableIndexElement*  pNextBucket;
    MSTATUS                 status = OK;

    /* clears out only the indices of a hash table --- leaves the basic table intact */
    if (NULL != pClearHashTable)
    {
        ubyte4  index;

        for (index = 0; index <= pClearHashTable->hashTableSizeMask; index++)
        {
            if (NULL != (pBucket = pClearHashTable->pHashTableArray[index]))
            {
                pClearHashTable->pHashTableArray[index] = NULL; /* prevent double dispose */
                while (pBucket)
                {
                    pNextBucket = pBucket->pNextElement;

                    if (funcPtrClearIndex)
                    {
                        if (OK > (status = funcPtrClearIndex(pClearCtx, pBucket->appDataIndex)))
                            goto exit;
                    }

                    pClearHashTable->pFuncFreeElement(pClearHashTable->pHashCookie, &pBucket);

                    /* move to the next bucket */
                    pBucket = pNextBucket;
                }
            }
        }
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HASH_TABLE_removeIndiceTable(hashTableIndices *pFreeHashTable, void **ppRetHashCookie)
{
    hashTableIndexElement*  pBucket;
    hashTableIndexElement*  pNextBucket;

    if (NULL != pFreeHashTable)
    {
        ubyte4  index;

        for (index = 0; index <= pFreeHashTable->hashTableSizeMask; index++)
        {
            if (NULL != (pBucket = pFreeHashTable->pHashTableArray[index]))
            {
                while (pBucket)
                {
                    pNextBucket = pBucket->pNextElement;

                    pFreeHashTable->pFuncFreeElement(pFreeHashTable->pHashCookie, &pBucket);

                    /* move to the next bucket */
                    pBucket = pNextBucket;
                }
            }
        }

        /* caller responsible for releasing pHashCookie */
        if (NULL != ppRetHashCookie)
            *ppRetHashCookie = pFreeHashTable->pHashCookie;

        FREE(pFreeHashTable);
    }

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HASH_TABLE_addIndex(hashTableIndices *pHashTable, ubyte4 hashValue, ubyte4 appDataIndex)
{
    hashTableIndexElement*  pBucket = NULL;
    hashTableIndexElement*  pInsertBucketLoc = NULL;
    MSTATUS                 status = OK;

    if ((NULL == pHashTable->pHashTableArray[hashValue & pHashTable->hashTableSizeMask]) ||
        (hashValue < pHashTable->pHashTableArray[hashValue & pHashTable->hashTableSizeMask]->hashValue))
    {
        /* get a new bucket */
        if (OK > (status = pHashTable->pFuncAllocElement(pHashTable->pHashCookie, &pBucket)))
            goto exit;

        /* initialize new bucket */
        pBucket->appDataIndex  = appDataIndex;
        pBucket->hashValue = hashValue;

        /* insert new bucket at head of list */
        SET_NEXT_ELEM(pBucket, pHashTable->pHashTableArray[hashValue & pHashTable->hashTableSizeMask]);
        pHashTable->pHashTableArray[hashValue & pHashTable->hashTableSizeMask] = pBucket;
    }
    else
    {
        pInsertBucketLoc = pHashTable->pHashTableArray[hashValue & pHashTable->hashTableSizeMask];

        /* add by hashValue to list */
        while ((NULL != pInsertBucketLoc->pNextElement) && (hashValue >= pInsertBucketLoc->pNextElement->hashValue))
        {
            pInsertBucketLoc = pInsertBucketLoc->pNextElement;

            /* don't add duplicates to the hash table */
            if ((hashValue == pInsertBucketLoc->hashValue) && (pInsertBucketLoc->appDataIndex == appDataIndex))
                goto exit;
        }

        /* get a new bucket */
        if (OK > (status = pHashTable->pFuncAllocElement(pHashTable->pHashCookie, &pBucket)))
            goto exit;

        /* initialize new bucket */
        pBucket->appDataIndex  = appDataIndex;
        pBucket->hashValue = hashValue;

        /* insert new bucket by hashValue order */
        SET_NEXT_ELEM(pBucket, pInsertBucketLoc->pNextElement);
        SET_NEXT_ELEM(pInsertBucketLoc, pBucket);
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HASH_TABLE_deleteIndex(hashTableIndices *pHashTable, ubyte4 hashValue, ubyte4 testDataIndex,
                       intBoolean *pRetFoundHashValue)
{
    hashTableIndexElement*  pBucket;
    hashTableIndexElement*  pLastBucket;
    MSTATUS                 status = OK;

    /* by default */
    *pRetFoundHashValue = FALSE;

    pBucket = pHashTable->pHashTableArray[hashValue & pHashTable->hashTableSizeMask];

    if (NULL == pBucket)
    {
        /* doesn't exist */
        goto exit;
    }

    /* check list head */
    if ((pBucket->hashValue == hashValue) && (pBucket->appDataIndex == testDataIndex))
    {
        hashTableIndexElement*  pBucketNext = pBucket->pNextElement;

        /* we have a match */
        *pRetFoundHashValue = TRUE;

        if (OK > (status = pHashTable->pFuncFreeElement(pHashTable->pHashCookie, &pBucket)))
            goto exit;  /* if free fails, leave in list */

        /* easy case: remove from head of list */
        pHashTable->pHashTableArray[hashValue & pHashTable->hashTableSizeMask] = pBucketNext;

        goto exit;
    }

    pLastBucket = pBucket;
    pBucket     = pBucket->pNextElement;

    while (pBucket)
    {
        if (pBucket->hashValue > hashValue)
        {
            /* not able to find hashValue; link list is sorted by hashValue*/
            break;
        }

        if ((pBucket->hashValue == hashValue) && (pBucket->appDataIndex == testDataIndex))
        {
            hashTableIndexElement*  pBucketNext = pBucket->pNextElement;

            /* we have a match */
            *pRetFoundHashValue = TRUE;

            if (OK > (status = pHashTable->pFuncFreeElement(pHashTable->pHashCookie, &pBucket)))
                goto exit;  /* if free fails, leave in list */

            /* remove from middle or end of list */
            SET_NEXT_ELEM(pLastBucket, pBucketNext);

            break;
        }

        /* move to the next bucket */
        pLastBucket = pBucket;
        pBucket     = pBucket->pNextElement;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HASH_TABLE_findIndex(hashTableIndices *pHashTable, ubyte4 hashValue, ubyte4 testDataIndex,
                     intBoolean *pRetFoundHashValue)
{
    hashTableIndexElement*  pBucket;
    MSTATUS                 status = OK;

    /* by default */
    *pRetFoundHashValue = FALSE;

    pBucket = pHashTable->pHashTableArray[hashValue & pHashTable->hashTableSizeMask];

    while (pBucket)
    {
        if (pBucket->hashValue > hashValue)
        {
            /* not able to find hashValue; link list is sorted by hashValue*/
            break;
        }
        else if ((pBucket->hashValue == hashValue) && (pBucket->appDataIndex == testDataIndex))
        {
            *pRetFoundHashValue = TRUE;
            break;
        }

        /* move to the next bucket */
        pBucket = pBucket->pNextElement;
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HASH_TABLE_createPtrsTable(hashTableOfPtrs **ppRetHashTable, ubyte4 hashTableSizeMask, void *pHashCookie,
                           funcPtrAllocHashPtrElement pFuncAllocElement, funcPtrFreeHashPtrElement pFuncFreeElement)
{
    hashTableOfPtrs*    pHashTable = NULL;
    MSTATUS             status = OK;

    if ((NULL == ppRetHashTable) || (NULL == pFuncAllocElement) || (NULL == pFuncFreeElement))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* hashTableSizeMask should be ((2^n)-1) in size */
    if ((0 == (1 & hashTableSizeMask)) ||
        (0 != (((hashTableSizeMask | (hashTableSizeMask - 1)) + 1) & hashTableSizeMask)) )
    {
        status = ERR_HASH_TABLE_BAD_SIZE;
        goto exit;
    }

    if (NULL == (pHashTable = (hashTableOfPtrs*) MALLOC(sizeof(hashTableOfPtrs) + ((1 + hashTableSizeMask) * sizeof(hashTablePtrElement *)))))
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    MOC_MEMSET((ubyte *)pHashTable, 0x00, sizeof(hashTableOfPtrs) + ((1 + hashTableSizeMask) * sizeof(hashTablePtrElement *)));
    pHashTable->hashTableSizeMask   = hashTableSizeMask;
    pHashTable->pHashCookie         = pHashCookie;

    pHashTable->pFuncAllocElement = pFuncAllocElement;
    pHashTable->pFuncFreeElement  = pFuncFreeElement;

    *ppRetHashTable = pHashTable;
    pHashTable = NULL;

exit:
    if (NULL != pHashTable)
        FREE(pHashTable);

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HASH_TABLE_removePtrsTable(hashTableOfPtrs *pFreeHashTable, void **ppRetHashCookie)
{
    hashTablePtrElement*    pBucket;
    hashTablePtrElement*    pNextBucket;

    if (NULL != pFreeHashTable)
    {
        ubyte4  index;

        for (index = 0; index <= pFreeHashTable->hashTableSizeMask; index++)
        {
            if (NULL != (pBucket = pFreeHashTable->pHashTableArray[index]))
            {
                while (pBucket)
                {
                    pNextBucket = pBucket->pNextElement;

                    pFreeHashTable->pFuncFreeElement(pFreeHashTable->pHashCookie, pBucket);

                    /* move to the next bucket */
                    pBucket = pNextBucket;
                }
            }
        }

        /* caller responsible for releasing pHashCookie */
        if (NULL != ppRetHashCookie)
            *ppRetHashCookie = pFreeHashTable->pHashCookie;

        FREE(pFreeHashTable);
    }

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HASH_TABLE_addPtr(hashTableOfPtrs *pHashTable, ubyte4 hashValue, void *pAppData)
{
    hashTablePtrElement*    pBucket;
    MSTATUS                 status;

    /* get a new bucket */
    if (OK > (status = pHashTable->pFuncAllocElement(pHashTable->pHashCookie, &pBucket)))
        goto exit;

    /* initialize new bucket */
    pBucket->pAppData  = pAppData;
    pBucket->hashValue = hashValue;

    if ((NULL == pHashTable->pHashTableArray[hashValue & pHashTable->hashTableSizeMask]) ||
        (hashValue < pHashTable->pHashTableArray[hashValue & pHashTable->hashTableSizeMask]->hashValue))
    {
        /* insert new bucket at head of list */
        SET_NEXT_ELEM(pBucket, pHashTable->pHashTableArray[hashValue & pHashTable->hashTableSizeMask]);
        pHashTable->pHashTableArray[hashValue & pHashTable->hashTableSizeMask] = pBucket;
    }
    else
    {
        hashTablePtrElement*    pInsertBucketLoc;

        pInsertBucketLoc = pHashTable->pHashTableArray[hashValue & pHashTable->hashTableSizeMask];

        while ((NULL != pInsertBucketLoc->pNextElement) && (hashValue > pInsertBucketLoc->pNextElement->hashValue))
            pInsertBucketLoc = pInsertBucketLoc->pNextElement;

        /* insert new bucket by hashValue order */
        SET_NEXT_ELEM(pBucket, pInsertBucketLoc->pNextElement);
        SET_NEXT_ELEM(pInsertBucketLoc, pBucket);
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS HASH_TABLE_deletePtr(hashTableOfPtrs *pHashTable, ubyte4 hashValue, void *pTestData, funcPtrExtraMatchTest, void **ppRetAppDataToDelete, intBoolean *pRetFoundHashValue);

extern MSTATUS
HASH_TABLE_deletePtr(hashTableOfPtrs *pHashTable, ubyte4 hashValue, void *pTestData,
                     funcPtrExtraMatchTest pFuncPtrExtraMatchTest,
                     void **ppRetAppDataToDelete, intBoolean *pRetFoundHashValue)
{
    hashTablePtrElement*    pBucket;
    hashTablePtrElement*    pLastBucket;
    intBoolean              isMatch = TRUE;
    MSTATUS                 status = OK;

    /* by default */
    *pRetFoundHashValue = FALSE;

    pBucket = pHashTable->pHashTableArray[hashValue & pHashTable->hashTableSizeMask];

    if (NULL == pBucket)
    {
        /* doesn't exist */
        goto exit;
    }

    /* check list head */
    if (pBucket->hashValue == hashValue)
    {
        if (NULL != pFuncPtrExtraMatchTest)
            if (OK > (status = pFuncPtrExtraMatchTest(pBucket->pAppData, pTestData, &isMatch)))
                goto exit;

        if (isMatch)
        {
            hashTablePtrElement*    pBucketNext = pBucket->pNextElement;

            /* caller is responsible for releasing pAppData */
            *ppRetAppDataToDelete = pBucket->pAppData;
            *pRetFoundHashValue = TRUE;

            if (OK > (status = pHashTable->pFuncFreeElement(pHashTable->pHashCookie, pBucket)))
                goto exit;  /* if free fails, leave in list */

            /* easy case: remove from head of list */
            pHashTable->pHashTableArray[hashValue & pHashTable->hashTableSizeMask] = pBucketNext;

            goto exit;
        }
    }

    pLastBucket = pBucket;
    pBucket     = pBucket->pNextElement;

    while (pBucket)
    {
        if (pBucket->hashValue > hashValue)
        {
            /* not able to find hashValue; link list is sorted by hashValue*/
            break;
        }

        if (pBucket->hashValue == hashValue)
        {
            if (NULL != pFuncPtrExtraMatchTest)
                if (OK > (status = pFuncPtrExtraMatchTest(pBucket->pAppData, pTestData, &isMatch)))
                    goto exit;

            if (isMatch)
            {
                hashTablePtrElement*    pBucketNext = pBucket->pNextElement;

                /* caller is responsible for releasing pAppData */
                *ppRetAppDataToDelete = pBucket->pAppData;
                *pRetFoundHashValue = TRUE;

                if (OK > (status = pHashTable->pFuncFreeElement(pHashTable->pHashCookie, pBucket)))
                    goto exit;  /* if free fails, leave in list */

                /* remove from middle or end of list */
                SET_NEXT_ELEM(pLastBucket, pBucketNext);

                goto exit;
            }
        }

        /* move to the next bucket */
        pLastBucket = pBucket;
        pBucket     = pBucket->pNextElement;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HASH_TABLE_findPtr(hashTableOfPtrs *pHashTable, ubyte4 hashValue, void *pTestData,
                   funcPtrExtraMatchTest pFuncPtrExtraMatchTest,
                   void **ppRetAppData, intBoolean *pRetFoundHashValue)
{
    hashTablePtrElement*    pBucket;
    hashTablePtrElement*    pNextBucket;
    intBoolean              isMatch = TRUE;
    MSTATUS                 status = OK;

    /* by default */
    *pRetFoundHashValue = FALSE;

    pBucket = pHashTable->pHashTableArray[hashValue & pHashTable->hashTableSizeMask];

    while (pBucket)
    {
        pNextBucket = pBucket->pNextElement;
        if (pBucket->hashValue > hashValue)
        {
            /* not able to find hashValue; link list is sorted by hashValue*/
            break;
        }
        else if (pBucket->hashValue == hashValue)
        {
            if (NULL != pFuncPtrExtraMatchTest)
                if (OK > (status = pFuncPtrExtraMatchTest(pBucket->pAppData, pTestData, &isMatch)))
                    goto exit;

            if (isMatch)
            {
                *ppRetAppData = pBucket->pAppData;
                *pRetFoundHashValue = TRUE;
                break;
            }
        }

        /* move to the next bucket */
        pBucket = pNextBucket;
    }

exit:
    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HASH_TABLE_traversePtrTable(hashTableOfPtrs *pHashTable,
                   MSTATUS(*funcPtrTraverseTable)(void * /* pAppData */))
{
    hashTablePtrElement*    pBucket;
    hashTablePtrElement*    pNextBucket;
    MSTATUS status = OK;

    if (NULL != pHashTable)
    {
        ubyte4  index;

        for (index = 0; index <= pHashTable->hashTableSizeMask; index++)
        {
            if (NULL != (pBucket = pHashTable->pHashTableArray[index]))
            {
                while (pBucket)
                {
                    pNextBucket = pBucket->pNextElement;

                    if (NULL != funcPtrTraverseTable)
                        if (OK > (status = funcPtrTraverseTable(pBucket->pAppData)))
                            goto exit;

                    /* move to the next bucket */
                    pBucket = pNextBucket;
                }
            }
        }
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

MOC_EXTERN void *
HASH_TABLE_iteratePtrTable(hashTableOfPtrs *pHashTable, void ** ppBucketCookie, ubyte4 *pIndex)
{
    hashTablePtrElement*    pBucket;
    hashTablePtrElement*    pNextBucket;
    intBoolean              lastElm = FALSE;

    if ((!pIndex) || (!ppBucketCookie))
        goto exit;

    if (NULL != pHashTable)
    {
        for (; *pIndex <= pHashTable->hashTableSizeMask; (*pIndex)++)
        {
            if (NULL != (pBucket = pHashTable->pHashTableArray[*pIndex]))
            {
                while (pBucket)
                {
                    if ((NULL == *ppBucketCookie) || (lastElm))
                    {
                        *ppBucketCookie = pBucket;
                        return pBucket->pAppData;
                    }

                    pNextBucket = pBucket->pNextElement;
                    if (*ppBucketCookie == pBucket)
                    {
                        if (pNextBucket)
                        {
                            *ppBucketCookie = pNextBucket;
                            return pNextBucket->pAppData;
                        }
                        else
                        {
                            lastElm = TRUE;
                        }
                    }
                    /* move to the next bucket */
                    pBucket = pNextBucket;
                }
            }
        }
    }

exit:
    return NULL;
}

extern MSTATUS
HASH_TABLE_traversePtrTableExt(hashTableOfPtrs *pHashTable, void *pCookie,
                   MSTATUS(*funcPtrTraverseTableExt)(void *pAppData, void *pCookie))
{
    hashTablePtrElement*    pBucket;
    hashTablePtrElement*    pNextBucket;
    MSTATUS status = OK;

    if (NULL != pHashTable)
    {
        ubyte4  index;

        for (index = 0; index <= pHashTable->hashTableSizeMask; index++)
        {
            if (NULL != (pBucket = pHashTable->pHashTableArray[index]))
            {
                while (pBucket)
                {
                    pNextBucket = pBucket->pNextElement;

                    if (NULL != funcPtrTraverseTableExt)
                        if (OK > (status = funcPtrTraverseTableExt(pBucket->pAppData, pCookie)))
                            goto exit;

                    /* move to the next bucket */
                    pBucket = pNextBucket;
                }
            }
        }
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/
/*------------------------------------------------------------------*/

#endif /* __DISABLE_MOCANA_COMMON_HASH_TABLE_FACTORY__ */
