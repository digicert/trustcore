/*
 * sort.h
 *
 * Byte Sorting Factory Header
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


/*------------------------------------------------------------------*/

#ifndef __SORT_HEADER__
#define __SORT_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS SORT_shellSort(void *pItmArray, ubyte4 itemSize, sbyte4 leftIndex, sbyte4 rightIndex, MSTATUS(*funcComparisonCallback)(void *pFirstItem, void *pSecondItem, intBoolean *pRetIsLess));

#ifdef __cplusplus
}
#endif

#endif /* __SORT_HEADER__ */

