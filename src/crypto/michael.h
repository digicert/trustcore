/*
 * michael.h
 *
 * 802.11i: Michael Message Integrity Check Algorithm Header
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */


/*------------------------------------------------------------------*/

#ifndef __MICHAEL_HEADER__
#define __MICHAEL_HEADER__

MOC_EXTERN MSTATUS MICHAEL_generateMic(ubyte *K, ubyte *M, ubyte4 mdsuLen, ubyte *pMIC);

#endif /* __MICHAEL_HEADER__ */

