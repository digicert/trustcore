/*
 * crypto_interface_aes_gcm_priv.h
 *
 * Cryptographic Interface header file for redefining
 * AES-GCM functions.
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
@file       crypto_interface_aes_gcm_priv.h
@brief      Cryptographic Interface header file for redefining AES-GCM functions.
@details    Add details here.

@filedoc    crypto_interface_aes_gcm_priv.h
*/
#ifndef __CRYPTO_INTERFACE_AES_GCM_PRIV_HEADER__
#define __CRYPTO_INTERFACE_AES_GCM_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_AES_GCM_MAPPING__)) && \
    (!defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_AES_GCM_INTERNAL__))

#define GCM_createCtx_256b       CRYPTO_INTERFACE_GCM_createCtx_256b
#define GCM_update_nonce_256b    CRYPTO_INTERFACE_GCM_update_nonce_256b
#define GCM_update_aad_256b      CRYPTO_INTERFACE_GCM_update_aad_256b
#define GCM_update_data_256b     CRYPTO_INTERFACE_GCM_update_data_256b
#define GCM_final_ex_256b        CRYPTO_INTERFACE_GCM_final_ex_256b
#define GCM_deleteCtx_256b       CRYPTO_INTERFACE_GCM_deleteCtx_256b
#define GCM_clone_256b           CRYPTO_INTERFACE_GCM_clone_256b
#define GCM_init_256b            CRYPTO_INTERFACE_GCM_init_256b
#define GCM_update_encrypt_256b  CRYPTO_INTERFACE_GCM_update_encrypt_256b
#define GCM_update_decrypt_256b  CRYPTO_INTERFACE_GCM_update_decrypt_256b
#define GCM_final_256b           CRYPTO_INTERFACE_GCM_final_256b
#define GCM_cipher_256b          CRYPTO_INTERFACE_GCM_cipher_256b
#define GCM_createCtx_4k         CRYPTO_INTERFACE_GCM_createCtx_4k
#define GCM_update_nonce_4k      CRYPTO_INTERFACE_GCM_update_nonce_4k
#define GCM_update_aad_4k        CRYPTO_INTERFACE_GCM_update_aad_4k
#define GCM_update_data_4k       CRYPTO_INTERFACE_GCM_update_data_4k
#define GCM_final_ex_4k          CRYPTO_INTERFACE_GCM_final_ex_4k
#define GCM_deleteCtx_4k         CRYPTO_INTERFACE_GCM_deleteCtx_4k
#define GCM_clone_4k             CRYPTO_INTERFACE_GCM_clone_4k
#define GCM_init_4k              CRYPTO_INTERFACE_GCM_init_4k
#define GCM_update_encrypt_4k    CRYPTO_INTERFACE_GCM_update_encrypt_4k
#define GCM_update_decrypt_4k    CRYPTO_INTERFACE_GCM_update_decrypt_4k
#define GCM_final_4k             CRYPTO_INTERFACE_GCM_final_4k
#define GCM_cipher_4k            CRYPTO_INTERFACE_GCM_cipher_4k
#define GCM_createCtx_64k        CRYPTO_INTERFACE_GCM_createCtx_64k
#define GCM_update_nonce_64k     CRYPTO_INTERFACE_GCM_update_nonce_64k
#define GCM_update_aad_64k       CRYPTO_INTERFACE_GCM_update_aad_64k
#define GCM_update_data_64k      CRYPTO_INTERFACE_GCM_update_data_64k
#define GCM_final_ex_64k         CRYPTO_INTERFACE_GCM_final_ex_64k
#define GCM_deleteCtx_64k        CRYPTO_INTERFACE_GCM_deleteCtx_64k
#define GCM_clone_64k            CRYPTO_INTERFACE_GCM_clone_64k
#define GCM_init_64k             CRYPTO_INTERFACE_GCM_init_64k
#define GCM_update_encrypt_64k   CRYPTO_INTERFACE_GCM_update_encrypt_64k
#define GCM_update_decrypt_64k   CRYPTO_INTERFACE_GCM_update_decrypt_64k
#define GCM_final_64k            CRYPTO_INTERFACE_GCM_final_64k
#define GCM_cipher_64k           CRYPTO_INTERFACE_GCM_cipher_64k

#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_AES_GCM_PRIV_HEADER__ */
