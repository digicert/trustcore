/**
 * @file  gdoi.h
 * @brief GDOI (Group Domain of Interpretation) protocol API
 *
 * @details    Header file for GDOI group key management
 * @flags      Compilation flags required:
 *     To enable any of this file's functions, one of the following flags must be defined in
 *     moptions.h:
 *     +   \c \__ENABLE_DIGICERT_GDOI_CLIENT__
 *     +   \c \__ENABLE_DIGICERT_GDOI_SERVER__
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

#ifndef __GDOI_HEADER__
#define __GDOI_HEADER__

#ifdef __cplusplus
extern "C" {
#endif


#if defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__)

struct ikesa;
struct ikePeerConfig;

extern struct ikesa *GDOI_newKek(struct ikePeerConfig *config,
                                 MOC_IP_ADDRESS peerAddr, ubyte2 wPeerPort,
                                 ubyte *poCky
                                 MOC_NATT(bUseNattPort)
                                 MOC_MTHM(serverInstance));

#endif /* defined(__ENABLE_DIGICERT_GDOI_CLIENT__) || defined(__ENABLE_DIGICERT_GDOI_SERVER__) */


#ifdef __cplusplus
}
#endif

#endif /* __GDOI_HEADER__ */
