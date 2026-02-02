/*
 * crypto_interface_chacha20_priv.h
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


#ifndef __CRYPTO_INTERFACE_CHACHA20_PRIV_HEADER__
#define __CRYPTO_INTERFACE_CHACHA20_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_CHACHA20_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_CHACHA20_INTERNAL__))

#define CreateChaCha20Ctx               CRYPTO_INTERFACE_CreateChaCha20Ctx
#define DoChaCha20                      CRYPTO_INTERFACE_DoChaCha20
#define DeleteChaCha20Ctx               CRYPTO_INTERFACE_DeleteChaCha20Ctx
#define CHACHA20_setNonceAndCounterSSH  CRYPTO_INTERFACE_CHACHA20_setNonceAndCounterSSH

#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_POLY1305_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_POLY1305_INTERNAL__))

#define ChaCha20Poly1305_createCtx    CRYPTO_INTERFACE_ChaCha20Poly1305_createCtx
#define ChaCha20Poly1305_deleteCtx    CRYPTO_INTERFACE_ChaCha20Poly1305_deleteCtx
#define ChaCha20Poly1305_cipherSSH    CRYPTO_INTERFACE_ChaCha20Poly1305_cipherSSH
#define ChaCha20Poly1305_cipher       CRYPTO_INTERFACE_ChaCha20Poly1305_cipher
#define ChaCha20Poly1305_update_nonce CRYPTO_INTERFACE_ChaCha20Poly1305_update_nonce
#define ChaCha20Poly1305_update_aad   CRYPTO_INTERFACE_ChaCha20Poly1305_update_aad
#define ChaCha20Poly1305_update_data  CRYPTO_INTERFACE_ChaCha20Poly1305_update_data
#define ChaCha20Poly1305_final        CRYPTO_INTERFACE_ChaCha20Poly1305_final
#define ChaCha20Poly1305_cloneCtx     CRYPTO_INTERFACE_ChaCha20Poly1305_cloneCtx

#endif
#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_CHACHA20_PRIV_HEADER__ */
