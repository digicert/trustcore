/*
 * michael.h
 *
 * 802.11i: Michael Message Integrity Check Algorithm Header
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
 *
 */


/*------------------------------------------------------------------*/

#ifndef __MICHAEL_HEADER__
#define __MICHAEL_HEADER__

MOC_EXTERN MSTATUS MICHAEL_generateMic(ubyte *K, ubyte *M, ubyte4 mdsuLen, ubyte *pMIC);

#endif /* __MICHAEL_HEADER__ */

