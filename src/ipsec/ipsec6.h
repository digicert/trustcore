/**
 * @file  ipsec6.h
 * @brief NanoSec IPsec IPv6 support header.
 *
 * @details    This file contains IPv6 support definitions for NanoSec IPsec.
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IPSEC_SERVICE__
 *     Additionally, the following flag must be defined in moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IPV6__
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

#ifndef __IPSEC6_HEADER__
#define __IPSEC6_HEADER__

#if (defined(__ENABLE_DIGICERT_IPSEC_SERVICE__) && defined(__ENABLE_DIGICERT_IPV6__))

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

struct ip6Hdr;

MOC_EXTERN MSTATUS
GetPktInfo6(struct ip6Hdr *pxHdr6, ubyte2 wBufSize,
            ubyte2 *pwLength, ubyte2 *pwHdrLen,
            ubyte **ppoNextHeader, ubyte **ppoDestAddr,
            intBoolean *pbFragOff, intBoolean *pbMoreFrags,
            intBoolean bIn);


#ifdef __cplusplus
}
#endif

#endif /* (defined(__ENABLE_DIGICERT_IPSEC_SERVICE__) && defined(__ENABLE_DIGICERT_IPV6__)) */

#endif /* __IPSEC6_HEADER__ */

