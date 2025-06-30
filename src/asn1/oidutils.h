/*
 * oidutils.h
 *
 * OIDutils.h
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

#ifndef __OIDUTILS_HEADER__
#define __OIDUTILS_HEADER__

/*------------------------------------------------------------------*/

/* exported routines */

/* convert a OID string in the format "2.16.840.1.113719.1.2.8.132"
    to an complete DER encoding (includes tag and length).
    The oid buffer was allocated with MALLOC and must be freed using FREE */
MOC_EXTERN MSTATUS BEREncodeOID( const sbyte* oidStr, byteBoolean* wildCard, ubyte** oid);

#endif /* #ifndef __OIDUTILS_HEADER__ */
