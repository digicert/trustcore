 /*
 * crypto_interface_sha1_priv.h
 *
 * Cryptographic Interface header file for redeclaring SHA1 functions.
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

#if ( defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_SHA1_MAPPING__)) && \
    (!defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_SHA1_INTERNAL__))

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
