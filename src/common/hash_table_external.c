/*
 * hash_table_external.c
 *
 * Hash Table connector to external implementations
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
#include "../common/hash_table_external.h"

#ifdef __ENABLE_DIGICERT_DPDK_CONNECTOR__

#include "../common/mstdlib.h"

#include <errno.h>
#include <rte_hash.h>

/*------------------------------------------------------------------*/

extern MSTATUS 
HASH_TABLE_EXT_createPtrsTable(hashTableOfPtrs **ppRetHashTable, ubyte4 hashTableSizeMask, void *pHashCookie,
                               ubyte4 keyLen, ubyte4 initValue)
{
    hashTableOfPtrs *pHashTable = NULL;
    MSTATUS status = ERR_NULL_POINTER;
    struct rte_hash_parameters params = {0};
    struct rte_hash *pRteHash = NULL;

    if (NULL == ppRetHashTable)
        goto exit;

    /* hashTableSizeMask should be ((2^n)-1) in size */
    if ((0 == (1 & hashTableSizeMask)) ||
        (0 != (((hashTableSizeMask | (hashTableSizeMask - 1)) + 1) & hashTableSizeMask)) )
    {
        status = ERR_HASH_TABLE_BAD_SIZE;
        goto exit;
    }

    status = ERR_INVALID_ARG;
    if (0 == keyLen)
        goto exit;

    params.entries = (uint32_t) hashTableSizeMask + 1;
    params.key_len = (uint32_t) keyLen;
    params.hash_func_init_val = (uint32_t) initValue;
    /* params.hash_func = rte_jhash; will be set as the default, no need to set here */

    pRteHash = rte_hash_create(&params);
    if (NULL == pRteHash)
    {
        status = ERR_HASH_TABLE_RTE_CREATE;
        goto exit;
    }
 
    status = DIGI_CALLOC((void **) &pHashTable, 1, sizeof(hashTableOfPtrs));
    if (OK != status)
        goto exit;

    pHashTable->pHashCookie = pHashCookie;
    pHashTable->pExternalHash = (void *) pRteHash; pRteHash = NULL;
    *ppRetHashTable = pHashTable; pHashTable = NULL;

exit:

    if (NULL != pHashTable)
    {
        (void) DIGI_FREE((void **) &pHashTable);
    }

    if (NULL != pRteHash)
    {
        rte_hash_free(pRteHash);
    }

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HASH_TABLE_EXT_removePtrsTable(hashTableOfPtrs *pFreeHashTable, void **ppRetHashCookie)
{
    hashTablePtrElement*    pBucket;
    hashTablePtrElement*    pNextBucket;

    if (NULL != pFreeHashTable)
    {
        if (NULL != pFreeHashTable->pExternalHash)
        {
            rte_hash_free((struct rte_hash *) pFreeHashTable->pExternalHash);
        }
        
        /* caller responsible for releasing pHashCookie  */
        if (NULL != ppRetHashCookie)
            *ppRetHashCookie = pFreeHashTable->pHashCookie;

        (void) DIGI_FREE((void **) &pFreeHashTable);
    }

    return OK;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HASH_TABLE_EXT_addPtr(hashTableOfPtrs *pHashTable, void *pKey, void *pAppData)
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 rteStatus = 0;

    if (NULL == pHashTable || NULL == pHashTable->pExternalHash)
        goto exit;

    /* add the element */
    status = ERR_HASH_TABLE_RTE_ADD_KEY;
    rteStatus = rte_hash_add_key_data((struct rte_hash *) pHashTable->pExternalHash, (const void *) pKey, pAppData);
    if (rteStatus)
        goto exit;

    status = OK;

exit:

    return status;
}


/*------------------------------------------------------------------*/

extern MSTATUS
HASH_TABLE_EXT_deletePtr(hashTableOfPtrs *pHashTable, void *pKey, void *pTestData,
                     funcPtrExtraMatchTest pFuncPtrExtraMatchTest,
                     void **ppRetAppDataToDelete, intBoolean *pRetFoundHashValue)
{
    intBoolean isMatch = TRUE;
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 rteStatus = 0;
    void *pLookupData = NULL;

    if (NULL == pHashTable || NULL == pRetFoundHashValue || 
        NULL == ppRetAppDataToDelete || NULL == pHashTable->pExternalHash)
        goto exit;

    /* by default */
    *pRetFoundHashValue = FALSE;

    status = OK;
    rteStatus = rte_hash_lookup_data((struct rte_hash *) pHashTable->pExternalHash, (const void *) pKey, &pLookupData);
    if (-ENOENT == rteStatus)
        goto exit;  /* key not there, status still OK */

    if (0 > rteStatus)  /* some other error */
    {
        status = ERR_HASH_TABLE_RTE_LOOKUP;
        goto exit;
    }

    if (NULL != pFuncPtrExtraMatchTest)
        if (OK > (status = pFuncPtrExtraMatchTest(pLookupData, pTestData, &isMatch)))
            goto exit;

    if (isMatch)
    {
        *pRetFoundHashValue = TRUE;
        *ppRetAppDataToDelete = pLookupData;

        /* only delete if we did indeed find a match */
        rteStatus = rte_hash_del_key((struct rte_hash *) pHashTable->pExternalHash, (const void *) pKey);
        if (0 > rteStatus)
        {
            status = ERR_HASH_TABLE_RTE_DELETE;
        }
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
HASH_TABLE_EXT_findPtr(hashTableOfPtrs *pHashTable, void *pKey, void *pTestData,
                   funcPtrExtraMatchTest pFuncPtrExtraMatchTest,
                   void **ppRetAppData, intBoolean *pRetFoundHashValue)
{
    intBoolean isMatch = TRUE;
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 rteStatus = 0;
    void *pLookupData = NULL;

    if (NULL == pHashTable || NULL == pRetFoundHashValue || 
        NULL == ppRetAppData || NULL == pHashTable->pExternalHash)
        goto exit;

    /* by default */
    *pRetFoundHashValue = FALSE;

    status = OK;
    rteStatus = rte_hash_lookup_data((struct rte_hash *) pHashTable->pExternalHash, (const void *) pKey, &pLookupData);
    if (-ENOENT == rteStatus)
        goto exit;  /* key not there, status still OK */

    if (0 > rteStatus)  /* some other error */
    {
        status = ERR_HASH_TABLE_RTE_LOOKUP;
        goto exit;
    }

    if (NULL != pFuncPtrExtraMatchTest)
        if (OK > (status = pFuncPtrExtraMatchTest(pLookupData, pTestData, &isMatch)))
            goto exit;

    if (isMatch)
    {
        *pRetFoundHashValue = TRUE;
        *ppRetAppData = pLookupData;
    }
    
exit:

    return status; 
}


/*------------------------------------------------------------------*/

extern MSTATUS HASH_TABLE_EXT_traversePtrTable(hashTableOfPtrs *pHashTable,
                                           MSTATUS(*funcPtrTraverseTable)(void * /* pAppData */))
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 rteStatus = 0;
    const void *pKey = NULL;
    void *pData = NULL;
    ubyte4 next = 0;
    
    if (NULL == pHashTable || NULL == funcPtrTraverseTable)
        goto exit;

    /* If no entries were added there is no table, nothing to do, OK no-op */
    status = OK;  
    if (NULL == pHashTable->pExternalHash)
        goto exit;

    while(TRUE) 
    {
        rteStatus = rte_hash_iterate((struct rte_hash *) pHashTable->pExternalHash, &pKey, &pData, (uint32_t *) &next);
        if (0 > rteStatus)
            break;

        if (NULL != funcPtrTraverseTable)
            if (OK > (status = funcPtrTraverseTable(pData)))
                goto exit;
    }

    if (-ENOENT != rteStatus)
    {
        status = ERR_HASH_TABLE_RTE_ITERATE;
        goto exit;
    }
        
exit:

    return status;
}

/*------------------------------------------------------------------*/

extern void * HASH_TABLE_EXT_iteratePtrTable(hashTableOfPtrs *pHashTable, void **ppKeyCookie, ubyte4 *pIndex)
{
    void *pData = NULL;

    /* If no entries were added there is no table, nothing to do, OK no-op */
    if (NULL == pHashTable || NULL == pHashTable->pExternalHash || NULL == pIndex || NULL == ppKeyCookie)
        goto exit;

    /* We just update index and ignore pBucketCookie, ok to ignore return value */
    (void) rte_hash_iterate((struct rte_hash *) pHashTable->pExternalHash, (const void **) ppKeyCookie, &pData, (uint32_t *) pIndex);

exit:

    return pData;
}

/*------------------------------------------------------------------*/

extern MSTATUS HASH_TABLE_EXT_traversePtrTableExt(hashTableOfPtrs *pHashTable, void *pCookie,
                                                  MSTATUS(*funcPtrTraverseTableExt)(void *pAppData, void *pCookie))
{
    MSTATUS status = ERR_NULL_POINTER;
    sbyte4 rteStatus = 0;
    const void *pKey = NULL;
    void *pData = NULL;
    ubyte4 next = 0;
    
    if (NULL == pHashTable || NULL == funcPtrTraverseTableExt)
        goto exit;

    /* If no entries were added there is no table, nothing to do, OK no-op */
    status = OK;
    if (NULL == pHashTable->pExternalHash)
        goto exit;

    while(TRUE) 
    {
        rteStatus = rte_hash_iterate((struct rte_hash *) pHashTable->pExternalHash, &pKey, &pData, (uint32_t *) &next);
        if (0 > rteStatus)
            break;

        if (NULL != funcPtrTraverseTableExt)
            if (OK > (status = funcPtrTraverseTableExt(pData, pCookie)))
                goto exit;
    }

    if (-ENOENT != rteStatus)
    {
        status = ERR_HASH_TABLE_RTE_ITERATE;
        goto exit;
    }
        
exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_DPDK_CONNECTOR__ */
