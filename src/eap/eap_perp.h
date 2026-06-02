/**
 * @file  eap_perp.h
 * @brief EAP-PERP method API
 *
 * @details    Protected EAP Roaming Protocol interface
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, the following flag must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_EAP_PEER__ or \c \__ENABLE_DIGICERT_EAP_AUTH__
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

#ifndef __EAP_PERP_H__
#define __EAP_PERP_H__
#ifdef __cplusplus
extern "C" {
#endif

#if (defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__))

MOC_EXTERN MSTATUS EAP_Perp_process_peer(ubyte *appSessionHdl, ubyte *reqData, ubyte **resp, ubyte4 *resplen);
MOC_EXTERN MSTATUS EAP_Perp_request_auth(ubyte *appSessionHdl, ubyte **reqData, ubyte4 *reqLen);
MOC_EXTERN MSTATUS EAP_Perp_process_auth(ubyte *appSessionHdl, ubyte *resp);

#endif /* ((defined(__ENABLE_DIGICERT_EAP_PEER__) || defined(__ENABLE_DIGICERT_EAP_AUTH__)) */
#ifdef __cplusplus
}
#endif
#endif /* __EAP_PERP_H__  */
