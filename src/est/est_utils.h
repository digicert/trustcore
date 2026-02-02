/**
 * @file  est_utils.h
 * @brief EST_UTILS -- Enrollment over Secure Transport utilities
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert's Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
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
