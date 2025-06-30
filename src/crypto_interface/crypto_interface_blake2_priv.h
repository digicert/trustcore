/*
 * crypto_interface_blake2_priv.h
 *
 * Cryptographic Interface header file for redefining Blake2 methods.
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
 @file       crypto_interface_blake2_priv.h
 @brief      Cryptographic Interface header file for redefining Blake2 methods.
 @details    Add details here.
 
 @filedoc    crypto_interface_blake2_priv.h
 */
#ifndef __CRYPTO_INTERFACE_BLAKE2_PRIV_HEADER__
#define __CRYPTO_INTERFACE_BLAKE2_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_BLAKE_2B_MAPPING__)) && \
    (!defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_BLAKE_2B_INTERNAL__))

#define BLAKE2B_alloc         CRYPTO_INTERFACE_BLAKE_2B_alloc
#define BLAKE2B_init          CRYPTO_INTERFACE_BLAKE_2B_init
#define BLAKE2B_update        CRYPTO_INTERFACE_BLAKE_2B_update
#define BLAKE2B_final         CRYPTO_INTERFACE_BLAKE_2B_final
#define BLAKE2B_complete      CRYPTO_INTERFACE_BLAKE_2B_complete
#define BLAKE2B_delete        CRYPTO_INTERFACE_BLAKE_2B_delete
#define BLAKE2B_cloneCtx      CRYPTO_INTERFACE_BLAKE_2B_cloneCtx

#endif

#if ( defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_BLAKE_2S_MAPPING__)) && \
    (!defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_BLAKE_2S_INTERNAL__))

#define BLAKE2S_alloc         CRYPTO_INTERFACE_BLAKE_2S_alloc
#define BLAKE2S_init          CRYPTO_INTERFACE_BLAKE_2S_init
#define BLAKE2S_update        CRYPTO_INTERFACE_BLAKE_2S_update
#define BLAKE2S_final         CRYPTO_INTERFACE_BLAKE_2S_final
#define BLAKE2S_complete      CRYPTO_INTERFACE_BLAKE_2S_complete
#define BLAKE2S_delete        CRYPTO_INTERFACE_BLAKE_2S_delete
#define BLAKE2S_cloneCtx      CRYPTO_INTERFACE_BLAKE_2S_cloneCtx

#endif
   
#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_BLAKE2_PRIV_HEADER__ */
