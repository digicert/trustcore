 /*
 * crypto_interface_sha384_priv.h
 *
 * Cryptographic Interface header file for redeclaring SHA384 functions.
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
@file       crypto_interface_sha384_priv.h
@brief      Cryptographic Interface header file for redeclaring SHA384 functions.
@details    Add details here.

@filedoc    crypto_interface_sha384_priv.h
*/
#ifndef __CRYPTO_INTERFACE_SHA384_PRIV_HEADER__
#define __CRYPTO_INTERFACE_SHA384_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_SHA384_MAPPING__)) && \
    (!defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_SHA384_INTERNAL__))

#define SHA384_initDigest     CRYPTO_INTERFACE_SHA384_initDigest
#define SHA384_finalDigest    CRYPTO_INTERFACE_SHA384_finalDigest
#define SHA384_completeDigest CRYPTO_INTERFACE_SHA384_completeDigest
#define SHA384_cloneCtx       CRYPTO_INTERFACE_SHA384_cloneCtx

#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_SHA384_PRIV_HEADER__ */
