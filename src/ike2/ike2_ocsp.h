/**
 * @file  ike2_ocsp.h
 * @brief IKEv2 IKEv2 OCSP Support Header
 *
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_IKE_SERVER__
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
/* internal use only */

#ifndef __IKE_OCSP_HEADER__
#define __IKE_OCSP_HEADER__

#if defined(__ENABLE_DIGICERT_IKE_SERVER__)
#if defined(__ENABLE_IKE_OCSP_EXT__) && defined(__ENABLE_DIGICERT_OCSP_CLIENT__)

#ifdef __cplusplus
extern "C" {
#endif


/*------------------------------------------------------------------*/

struct ike_context;

extern MSTATUS IKE_ocspGetResponse(struct ike_context *ctx);
extern MSTATUS IKE_ocspValidateResponse(struct ike_context *ctx);

    
#ifdef __cplusplus
}
#endif

#endif /* defined(__ENABLE_IKE_OCSP_EXT__) && defined(__ENABLE_DIGICERT_OCSP_CLIENT__) */
#endif /* __ENABLE_DIGICERT_IKE_SERVER__ */

#endif /* __IKE_OCSP_HEADER__ */

