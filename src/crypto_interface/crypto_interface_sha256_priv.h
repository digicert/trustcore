 /*
 * crypto_interface_sha256_priv.h
 *
 * Cryptographic Interface header file for redeclaring SHA256 functions.
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
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
