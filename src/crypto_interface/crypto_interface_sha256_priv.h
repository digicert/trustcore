 /*
 * crypto_interface_sha256_priv.h
 *
 * Cryptographic Interface header file for redeclaring SHA256 functions.
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

/**
@file       crypto_interface_sha256_priv.h
@brief      Cryptographic Interface header file for redeclaring SHA256 functions.
@details    Add details here.

@filedoc    crypto_interface_sha256_priv.h
*/
#ifndef __CRYPTO_INTERFACE_SHA256_PRIV_HEADER__
#define __CRYPTO_INTERFACE_SHA256_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA256_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA256_INTERNAL__))

#define SHA256_allocDigest    CRYPTO_INTERFACE_SHA256_allocDigest
#define SHA256_freeDigest     CRYPTO_INTERFACE_SHA256_freeDigest
#define SHA256_initDigest     CRYPTO_INTERFACE_SHA256_initDigest
#define SHA256_updateDigest   CRYPTO_INTERFACE_SHA256_updateDigest
#define SHA256_finalDigest    CRYPTO_INTERFACE_SHA256_finalDigest
#define SHA256_completeDigest CRYPTO_INTERFACE_SHA256_completeDigest
#define SHA256_cloneCtx       CRYPTO_INTERFACE_SHA256_cloneCtx

#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_SHA256_PRIV_HEADER__ */
