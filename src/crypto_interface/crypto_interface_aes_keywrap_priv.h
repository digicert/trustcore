/*
 * crypto_interface_aes_keywrap_priv.h
 *
 * Cryptographic Interface header file for redefining
 * AES-KEYWRAP functions.
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
 @file       crypto_interface_aes_keywrap_priv.h
 @brief      Cryptographic Interface header file for redefining AES-KEYWRAP functions.
 @details    Add details here.
 
 @filedoc    crypto_interface_aes_keywrap_priv.h
 */
#ifndef __CRYPTO_INTERFACE_AES_KEYWRAP_PRIV_HEADER__
#define __CRYPTO_INTERFACE_AES_KEYWRAP_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif
    
#if ( defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_AES_KEYWRAP_MAPPING__)) && \
    (!defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_AES_KEYWRAP_INTERNAL__))
    
#define AESKWRAP_encrypt3394Ex CRYPTO_INTERFACE_AESKWRAP_encrypt3394Ex
#define AESKWRAP_decrypt3394Ex CRYPTO_INTERFACE_AESKWRAP_decrypt3394Ex

#define AESKWRAP_encrypt5649Ex CRYPTO_INTERFACE_AESKWRAP_encrypt5649Ex
#define AESKWRAP_decrypt5649Ex CRYPTO_INTERFACE_AESKWRAP_decrypt5649Ex

#endif
    
#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_AES_KEYWRAP_PRIV_HEADER__ */
