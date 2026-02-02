 /*
 * crypto_interface_md4_priv.h
 *
 * Cryptographic Interface header file for redeclaring MD4 functions.
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
@file       crypto_interface_md4_priv.h
@brief      Cryptographic Interface header file for redeclaring MD4 functions.
@details    Add details here.

@filedoc    crypto_interface_md4_priv.h
*/
#ifndef __CRYPTO_INTERFACE_MD4_PRIV_HEADER__
#define __CRYPTO_INTERFACE_MD4_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_MD4_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_MD4_INTERNAL__))

#define MD4Alloc           CRYPTO_INTERFACE_MD4Alloc
#define MD4Free            CRYPTO_INTERFACE_MD4Free
#define MD4Init            CRYPTO_INTERFACE_MD4Init
#define MD4Update          CRYPTO_INTERFACE_MD4Update
#define MD4Final           CRYPTO_INTERFACE_MD4Final
#define MD4_completeDigest CRYPTO_INTERFACE_MD4_completeDigest
#define MD4_cloneCtx       CRYPTO_INTERFACE_MD4_cloneCtx

#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_MD4_PRIV_HEADER__ */
