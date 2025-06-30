/*
 * crypto_interface_poly1305_priv.h
 *
 *
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

#ifndef __CRYPTO_INTERFACE_POLY1305_PRIV_HEADER__
#define __CRYPTO_INTERFACE_POLY1305_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_POLY1305_MAPPING__)) && \
    (!defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_POLY1305_INTERNAL__))

#define Poly1305Init            CRYPTO_INTERFACE_Poly1305Init
#define Poly1305Update          CRYPTO_INTERFACE_Poly1305Update
#define Poly1305Final           CRYPTO_INTERFACE_Poly1305Final
#define Poly1305_completeDigest CRYPTO_INTERFACE_Poly1305_completeDigest

#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_POLY1305_PRIV_HEADER__ */
