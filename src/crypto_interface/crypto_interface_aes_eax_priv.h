/*
 * crypto_interface_aes_eax_priv.h
 *
 * Cryptographic Interface header file for redefining AES-EAX methods.
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
 @file       crypto_interface_aes_eax_priv.h
 @brief      Cryptographic Interface header file for redefining AES-EAX methods.
 @details    Add details here.
 
 @filedoc    crypto_interface_aes_eax_priv.h
 */
#ifndef __CRYPTO_INTERFACE_AES_EAX_PRIV_HEADER__
#define __CRYPTO_INTERFACE_AES_EAX_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif
    
#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_EAX_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_EAX_INTERNAL__))
    
#define AES_EAX_init               CRYPTO_INTERFACE_AES_EAX_init
#define AES_EAX_updateHeader       CRYPTO_INTERFACE_AES_EAX_updateHeader
#define AES_EAX_encryptMessage     CRYPTO_INTERFACE_AES_EAX_encryptMessage
#define AES_EAX_decryptMessage     CRYPTO_INTERFACE_AES_EAX_decryptMessage
#define AES_EAX_final              CRYPTO_INTERFACE_AES_EAX_final
#define AES_EAX_generateTag        CRYPTO_INTERFACE_AES_EAX_generateTag
#define AES_EAX_getPlainText       CRYPTO_INTERFACE_AES_EAX_getPlainText
#define AES_EAX_clear              CRYPTO_INTERFACE_AES_EAX_clear

#endif
    
#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_AES_EAX_PRIV_HEADER__ */
