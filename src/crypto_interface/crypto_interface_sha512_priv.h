 /*
 * crypto_interface_sha512_priv.h
 *
 * Cryptographic Interface header file for redeclaring SHA512 functions.
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
@file       crypto_interface_sha512_priv.h
@brief      Cryptographic Interface header file for redeclaring SHA512 functions.
@details    Add details here.

@filedoc    crypto_interface_sha512_priv.h
*/
#ifndef __CRYPTO_INTERFACE_SHA512_PRIV_HEADER__
#define __CRYPTO_INTERFACE_SHA512_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_SHA512_MAPPING__)) && \
    (!defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_SHA512_INTERNAL__))

#define SHA512_allocDigest    CRYPTO_INTERFACE_SHA512_allocDigest
#define SHA512_freeDigest     CRYPTO_INTERFACE_SHA512_freeDigest
#define SHA512_initDigest     CRYPTO_INTERFACE_SHA512_initDigest
#define SHA512_updateDigest   CRYPTO_INTERFACE_SHA512_updateDigest
#define SHA512_finalDigest    CRYPTO_INTERFACE_SHA512_finalDigest
#define SHA512_completeDigest CRYPTO_INTERFACE_SHA512_completeDigest
#define SHA512_cloneCtx       CRYPTO_INTERFACE_SHA512_cloneCtx

#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_SHA512_PRIV_HEADER__ */
