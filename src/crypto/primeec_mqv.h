/*
 * primeec_mqv.h
 *
 * Finite Field Elliptic Curve MQV Key Agreement routines
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
/*! \file primeec_mqv.h Finite Field Elliptic Curve MQV developer API header.
This header file contains definitions, enumerations, structures, and function
declarations used for EC MQV operations.

\since 3.06
\version 5.3 and later

To enable any of this file's functions, the following flags must be defined in
moptions.h:
- $__ENABLE_DIGICERT_ECC__$

! External Functions
This file contains the following public ($extern$) function declarations:

*/



/*------------------------------------------------------------------*/

#ifndef __PRIMEEC_MQV_HEADER__
#define __PRIMEEC_MQV_HEADER__

#if (defined(__ENABLE_DIGICERT_ECC__))
/* Support for Finite Field Elliptic Curve MQV Operations */

struct ECCKey;

MOC_EXTERN MSTATUS ECMQV_generateSharedSecret(const ECCKey* pPrivate1,
                                              const ECCKey* pPrivate2,
                                              const ECCKey* pPublic1,
                                              const ECCKey* pPbulic2,
                                              PFEPtr* pSharedSecret);


#endif /* __ENABLE_DIGICERT_ECC__  */

#endif /* __PRIMEFLD_HEADER__ */

