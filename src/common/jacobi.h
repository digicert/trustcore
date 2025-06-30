/*
 * jacobi.h
 *
 * Jacobi Symbol Header
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

#ifndef __JACOBI_HEADER__
#define __JACOBI_HEADER__


/*------------------------------------------------------------------*/

MOC_EXTERN MSTATUS JACOBI_jacobiSymbol(MOC_MOD(hwAccelDescr hwAccelCtx) const vlong *a, const vlong *p, sbyte4 *pRetJacobiResult, vlong **ppVlongQueue);

#endif /* __JACOBI_HEADER__ */
