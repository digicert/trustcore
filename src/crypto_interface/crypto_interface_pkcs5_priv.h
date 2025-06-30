/*
 * crypto_interface_pkcs5_priv.h
 *
 * Cryptographic Interface header file for redefining PKCS5 methods.
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
#ifndef __CRYPTO_INTERFACE_PKCS5_PRIV_HEADER__
#define __CRYPTO_INTERFACE_PKCS5_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif
    
#if ( defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_PKCS5_MAPPING__)) && \
    (!defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_PKCS5_INTERNAL__))
    
#define PKCS5_CreateKey_PBKDF1  CRYPTO_INTERFACE_PKCS5_CreateKey_PBKDF1
#define PKCS5_CreateKey_PBKDF2  CRYPTO_INTERFACE_PKCS5_CreateKey_PBKDF2
#define PKCS5_decrypt           CRYPTO_INTERFACE_PKCS5_decrypt
#define PKCS5_decryptV2         CRYPTO_INTERFACE_PKCS5_decryptV2
#define PKCS5_encryptV1         CRYPTO_INTERFACE_PKCS5_encryptV1
#define PKCS5_encryptV2_Alt     CRYPTO_INTERFACE_PKCS5_encryptV2_Alt

#endif
    
#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_PKCS5_PRIV_HEADER__ */
