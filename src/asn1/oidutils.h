/*
 * oidutils.h
 *
 * OIDutils.h
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

#ifndef __OIDUTILS_HEADER__
#define __OIDUTILS_HEADER__

/*------------------------------------------------------------------*/

/* exported routines */

/* convert a OID string in the format "2.16.840.1.113719.1.2.8.132"
    to an complete DER encoding (includes tag and length).
    The oid buffer was allocated with MALLOC and must be freed using FREE */
MOC_EXTERN MSTATUS BEREncodeOID( const sbyte* oidStr, byteBoolean* wildCard, ubyte** oid);

#endif /* #ifndef __OIDUTILS_HEADER__ */
