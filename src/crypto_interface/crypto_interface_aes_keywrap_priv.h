/*
 * crypto_interface_aes_keywrap_priv.h
 *
 * Cryptographic Interface header file for redefining
 * AES-KEYWRAP functions.
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
    
#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_KEYWRAP_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_KEYWRAP_INTERNAL__))
    
#define AESKWRAP_encrypt3394Ex CRYPTO_INTERFACE_AESKWRAP_encrypt3394Ex
#define AESKWRAP_decrypt3394Ex CRYPTO_INTERFACE_AESKWRAP_decrypt3394Ex

#define AESKWRAP_encrypt5649Ex CRYPTO_INTERFACE_AESKWRAP_encrypt5649Ex
#define AESKWRAP_decrypt5649Ex CRYPTO_INTERFACE_AESKWRAP_decrypt5649Ex

#endif
    
#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_AES_KEYWRAP_PRIV_HEADER__ */
