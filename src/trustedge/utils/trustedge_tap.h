/**
 * trustedge_tap.h
 *
 * @brief TAP init/clean methods
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
 */
#ifndef __TRUSTEDGE_TAP_HEADER__
#define __TRUSTEDGE_TAP_HEADER__

#include "../../trustedge/utils/trustedge_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __ENABLE_DIGICERT_TAP__
#ifdef __ENABLE_DIGICERT_TAP_REMOTE__
MOC_EXTERN MSTATUS TRUSTEDGE_TAP_init(TAP_PROVIDER provider, sbyte *pServer, ubyte4 port, ubyte4 modNum);
#else
MOC_EXTERN MSTATUS TRUSTEDGE_TAP_init(ubyte4 modNum, TrustEdgeConfig *pConfig);
#endif
MOC_EXTERN void TRUSTEDGE_TAP_unloadKey(AsymmetricKey *pKey);
MOC_EXTERN void TRUSTEDGE_TAP_clean(void);

MOC_EXTERN MSTATUS TRUSTEDGE_TAP_getCtx(
    TAP_Context **ppTapCtx, TAP_EntityCredentialList **ppTapEntityCred,
    TAP_CredentialList **ppTapKeyCred, void *pKey, TapOperation op,
    ubyte getContext);

MOC_EXTERN MSTATUS TRUSTEDGE_TAP_isProviderModuleLoaded(
    TAP_PROVIDER provider,
    TAP_ModuleId moduleId,
    byteBoolean *pLoaded);

#endif /* __ENABLE_DIGICERT_TAP__ */
#ifdef __cplusplus
}
#endif

#endif /* __TRUSTEDGE_TAP_HEADER__ */
