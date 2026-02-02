/*
 * ht_utils.c
 *
 * Hash Table Utilities
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
#include "../common/ht_utils.h"

MOC_EXTERN MSTATUS
HASH_TABLE_ptrAlloc(void *pHashCookie, hashTablePtrElement **ppRetNewHashElement)
{
    /* we could use a memory pool here to reduce probability of fragmentation */
    MSTATUS status = OK;

    MOC_UNUSED(pHashCookie);

    if (NULL == (*ppRetNewHashElement = (hashTablePtrElement*) MALLOC(sizeof(hashTablePtrElement))))
        status = ERR_MEM_ALLOC_FAIL;

    return status;
}

MOC_EXTERN MSTATUS
HASH_TABLE_ptrFree(void *pHashCookie, hashTablePtrElement *pFreeHashElement)
{
    MOC_UNUSED(pHashCookie);

    FREE(pFreeHashElement);

    return OK;
}

MOC_EXTERN MSTATUS
HASH_TABLE_ptrCheck(void *pAppData, void *pTestData, intBoolean *pRetIsMatch)
{
    *pRetIsMatch = ((pAppData == pTestData) ? TRUE : FALSE);
    return OK;
}
