/*
 * crypto_interface_rc5_priv.h
 *
 * Cryptographic Interface header file for redefining RC5 methods.
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
#ifndef __CRYPTO_INTERFACE_RC5_PRIV_HEADER__
#define __CRYPTO_INTERFACE_RC5_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RC5_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RC5_INTERNAL__))

#define MocCreateRC5Ctx CRYPTO_INTERFACE_MocCreateRC5Ctx
#define MocDeleteRC5Ctx CRYPTO_INTERFACE_MocDeleteRC5Ctx
#define MocRC5Update    CRYPTO_INTERFACE_MocRC5Update
#define MocRC5Final     CRYPTO_INTERFACE_MocRC5Final
#define MocReinitRC5Ctx CRYPTO_INTERFACE_MocReinitRC5Ctx
#define MocRC5GetIv     CRYPTO_INTERFACE_MocRC5GetIv
#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_RC5_PRIV_HEADER__ */
