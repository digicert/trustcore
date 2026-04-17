 /*
 * crypto_interface_sha1_priv.h
 *
 * Cryptographic Interface header file for redeclaring SHA1 functions.
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
@file       crypto_interface_sha1_priv.h
@brief      Cryptographic Interface header file for redeclaring SHA1 functions.
@details    Add details here.

@filedoc    crypto_interface_sha1_priv.h
*/
#ifndef __CRYPTO_INTERFACE_SHA1_PRIV_HEADER__
#define __CRYPTO_INTERFACE_SHA1_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA1_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA1_INTERNAL__))

#define SHA1_allocDigest    CRYPTO_INTERFACE_SHA1_allocDigest
#define SHA1_freeDigest     CRYPTO_INTERFACE_SHA1_freeDigest
#define SHA1_initDigest     CRYPTO_INTERFACE_SHA1_initDigest
#define SHA1_updateDigest   CRYPTO_INTERFACE_SHA1_updateDigest
#define SHA1_finalDigest    CRYPTO_INTERFACE_SHA1_finalDigest
#define SHA1_completeDigest CRYPTO_INTERFACE_SHA1_completeDigest
#define SHA1_cloneCtx       CRYPTO_INTERFACE_SHA1_cloneCtx
#define SHA1_G              CRYPTO_INTERFACE_SHA1_G
#define SHA1_GK             CRYPTO_INTERFACE_SHA1_GK

#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_SHA1_PRIV_HEADER__ */
