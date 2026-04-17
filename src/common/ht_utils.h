/*
 * ht_utils.h
 *
 * Hash Table Utilities Header
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

#ifndef __HASH_TABLE_UTILS_HEADER__
#define __HASH_TABLE_UTILS_HEADER__

MOC_EXTERN MSTATUS HASH_TABLE_ptrAlloc(void *pHashCookie, hashTablePtrElement **ppRetNewHashElement);
MOC_EXTERN MSTATUS HASH_TABLE_ptrFree(void *pHashCookie, hashTablePtrElement *pFreeHashElement);
MOC_EXTERN MSTATUS HASH_TABLE_ptrCheck(void *pAppData, void *pTestData, intBoolean *pRetIsMatch);

#endif /* __HASH_TABLE_UTILS_HEADER__ */

