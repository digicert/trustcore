/*
 * crypto_interface_arc4_priv.h
 *
 * Cryptographic Interface header file for redefining RC4 methods.
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
#ifndef __CRYPTO_INTERFACE_ARC4_PRIV_HEADER__
#define __CRYPTO_INTERFACE_ARC4_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_ARC4_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_ARC4_INTERNAL__))

#define CreateRC4Ctx  CRYPTO_INTERFACE_CreateRC4Ctx
#define DeleteRC4Ctx  CRYPTO_INTERFACE_DeleteRC4Ctx
#define DoRC4         CRYPTO_INTERFACE_DoRC4
#define CloneRC4Ctx   CRYPTO_INTERFACE_CloneRC4Ctx

#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_ARC4_PRIV_HEADER__ */
