/**
 * @file  gdoi_client.h
 * @brief GDOI client API
 *
 * @details    Header file for GDOI client functionality
 *
 * @flags      Compilation flags required:
 *     + \c \__ENABLE_DIGICERT_GDOI_CLIENT__
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

#ifndef __GDOI_CLIENT_HEADER__
#define __GDOI_CLIENT_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


#ifdef __ENABLE_DIGICERT_GDOI_CLIENT__

struct ike_context;
extern MSTATUS GDOI_addTek(struct ike_context *ctx);

#endif /* defined(__ENABLE_DIGICERT_GDOI_CLIENT__) */


#ifdef __cplusplus
}
#endif

#endif /* __GDOI_CLIENT_HEADER__ */
