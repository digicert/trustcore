/*
 * crypto_interface_random_priv.h
 *
 * Cryptographic Interface header file for redefining random functions.
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
@file       crypto_interface_random_priv.h
@brief      Cryptographic Interface header file for redefining random functions.
@details    Add details here.

@filedoc    crypto_interface_random_priv.h
*/
#ifndef __CRYPTO_INTERFACE_RANDOM_PRIV_HEADER__
#define __CRYPTO_INTERFACE_RANDOM_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_RANDOM_MAPPING__)) && \
    (!defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_RANDOM_INTERNAL__))

#define RANDOM_acquireContextEx      CRYPTO_INTERFACE_RANDOM_acquireContextEx
#define RANDOM_releaseContextEx      CRYPTO_INTERFACE_RANDOM_releaseContextEx
#define RANDOM_addEntropyBitEx       CRYPTO_INTERFACE_RANDOM_addEntropyBitEx

#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_RANDOM_PRIV_HEADER__ */