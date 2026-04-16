/*
 * crypto_interface_pkcs5_priv.h
 *
 * Cryptographic Interface header file for redefining PKCS5 methods.
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
#ifndef __CRYPTO_INTERFACE_PKCS5_PRIV_HEADER__
#define __CRYPTO_INTERFACE_PKCS5_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif
    
#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_PKCS5_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_PKCS5_INTERNAL__))
    
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
