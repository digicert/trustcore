/*
 * trustedge_state.h
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

#ifndef __TRUSTEDGE_STATE_HEADER__
#define __TRUSTEDGE_STATE_HEADER__
#if defined(__ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__)

#include "../../trustedge/trustedge_main.h"

#ifdef __cplusplus
extern "C" {
#endif

void TRUSTEDGE_setState(enum TrustedgeState state);

#ifdef __cplusplus
}
#endif

#endif /* __ENABLE_DIGICERT_TRUSTEDGE_LIBRARY_MODE__ */
#endif /* __TRUSTEDGE_STATE_HEADER__ */
