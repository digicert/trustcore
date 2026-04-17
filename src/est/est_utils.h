/**
 * @file  est_utils.h
 * @brief EST_UTILS -- Enrollment over Secure Transport utilities
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

#ifndef __EST_UTILS_HEADER__
#define __EST_UTILS_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#if (defined(__ENABLE_DIGICERT_EST_CLIENT__))

/*------------------------------------------------------------------*/
MOC_EXTERN ubyte4 EST_UTILS_filterPkcs7Message(ubyte *pOrigMesg, ubyte4 origLen);
#endif /* #ifdef __ENABLE_DIGICERT_EST_CLIENT__ */

#ifdef __cplusplus
}
#endif

#endif  /*#ifndef __EST_UTILS_HEADER__ */
