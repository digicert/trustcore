/*
 * tkip.h
 *
 * 802.11i: TKIP Key Mixing Function Header
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

#ifndef __TKIP_HEADER__
#define __TKIP_HEADER__

MOC_EXTERN MSTATUS TKIP_makeKey(ubyte* tk, ubyte* ta, ubyte* tsc, ubyte2* ttak, ubyte* wepSeed);

MOC_EXTERN MSTATUS DoWEP(ubyte* keyMaterial, ubyte4 keyLength, const ubyte* payloadData, ubyte4 payloadDataLen);

#endif /* __TKIP_HEADER__ */

