/*
 * sort.h
 *
 * Byte Sorting Factory Header
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

