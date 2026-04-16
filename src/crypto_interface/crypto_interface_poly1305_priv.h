/*
 * crypto_interface_poly1305_priv.h
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

#ifndef __CRYPTO_INTERFACE_POLY1305_PRIV_HEADER__
#define __CRYPTO_INTERFACE_POLY1305_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_POLY1305_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_POLY1305_INTERNAL__))

#define Poly1305Init            CRYPTO_INTERFACE_Poly1305Init
#define Poly1305Update          CRYPTO_INTERFACE_Poly1305Update
#define Poly1305Final           CRYPTO_INTERFACE_Poly1305Final
#define Poly1305_completeDigest CRYPTO_INTERFACE_Poly1305_completeDigest

#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_POLY1305_PRIV_HEADER__ */
