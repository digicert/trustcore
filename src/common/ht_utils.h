/*
 * ht_utils.h
 *
 * Hash Table Utilities Header
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

#ifndef __HASH_TABLE_UTILS_HEADER__
#define __HASH_TABLE_UTILS_HEADER__

MOC_EXTERN MSTATUS HASH_TABLE_ptrAlloc(void *pHashCookie, hashTablePtrElement **ppRetNewHashElement);
MOC_EXTERN MSTATUS HASH_TABLE_ptrFree(void *pHashCookie, hashTablePtrElement *pFreeHashElement);
MOC_EXTERN MSTATUS HASH_TABLE_ptrCheck(void *pAppData, void *pTestData, intBoolean *pRetIsMatch);

#endif /* __HASH_TABLE_UTILS_HEADER__ */

