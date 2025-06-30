/*
 * crypto_interface_aes_ccm_priv.h
 *
 * Cryptographic Interface header file for redefining AES-CCM methods.
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
 @file       crypto_interface_aes_ccm_priv.h
 @brief      Cryptographic Interface header file for redefining AES-CCM methods.
 @details    Add details here.
 
 @filedoc    crypto_interface_aes_ccm_priv.h
 */
#ifndef __CRYPTO_INTERFACE_AES_CCM_PRIV_HEADER__
#define __CRYPTO_INTERFACE_AES_CCM_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif
    
#if ( defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_AES_CCM_MAPPING__)) && \
    (!defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_AES_CCM_INTERNAL__))
    
#define AESCCM_encrypt          CRYPTO_INTERFACE_AES_CCM_encrypt
#define AESCCM_decrypt          CRYPTO_INTERFACE_AES_CCM_decrypt
#define AESCCM_createCtx        CRYPTO_INTERFACE_AES_CCM_createCtx
#define AESCCM_deleteCtx        CRYPTO_INTERFACE_AES_CCM_deleteCtx
#define AESCCM_cipher           CRYPTO_INTERFACE_AES_CCM_cipher
#define AESCCM_clone            CRYPTO_INTERFACE_AES_CCM_clone

#endif
    
#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_AES_CCM_PRIV_HEADER__ */
