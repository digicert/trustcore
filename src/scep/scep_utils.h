/**
 * @file  scep_utils.h
 * @brief SCEP definitions and utility routines
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert's Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.
 *
 */

#ifndef __SCEP_UTILS_HEADER__
#define __SCEP_UTILS_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ENABLE_DIGICERT_SCEP_CLIENT__

/*------------------------------------------------------------------*/

/* exported routines */

MOC_EXTERN MSTATUS
SCEP_UTILS_integerToString(ubyte *number, ubyte4 numberLen, sbyte* pBuf, ubyte4 bufLen);

#endif /* __ENABLE_DIGICERT_SCEP_CLIENT__ */

#ifdef __cplusplus
}
#endif

#endif  /*#ifndef __SCEP_UTILS_HEADER__ */
