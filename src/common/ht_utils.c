/*
 * ht_utils.c
 *
 * Hash Table Utilities
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
