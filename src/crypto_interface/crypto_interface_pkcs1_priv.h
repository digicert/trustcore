/*
 * crypto_interface_pkcs1_priv.h
 *
 * Cryptographic Interface header file for redefining PKCS1 functions.
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
@file       crypto_interface_pkcs1_priv.h
@brief      Cryptographic Interface header file for redefining PKCS1 functions.
@details    Add details here.

@filedoc    crypto_interface_pkcs1_priv.h
*/
#ifndef __CRYPTO_INTERFACE_PKCS1_PRIV_HEADER__
#define __CRYPTO_INTERFACE_PKCS1_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_PKCS1_MAPPING__)) && \
    (!defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_PKCS1_INTERNAL__))

#define PKCS1_rsaOaepEncrypt   CRYPTO_INTERFACE_PKCS1_rsaOaepEncrypt
#define PKCS1_rsaOaepDecrypt   CRYPTO_INTERFACE_PKCS1_rsaOaepDecrypt
#define PKCS1_rsaPssSignExt    CRYPTO_INTERFACE_PKCS1_rsaPssSignExt
#define PKCS1_rsaPssVerifyExt  CRYPTO_INTERFACE_PKCS1_rsaPssVerifyExt
#define PKCS1_rsaPssSign       CRYPTO_INTERFACE_PKCS1_rsaPssSign
#define PKCS1_rsaPssVerify     CRYPTO_INTERFACE_PKCS1_rsaPssVerify
#define PKCS1_MGF1_FUNC        CRYPTO_INTERFACE_PKCS1_MGF1
#define PKCS1_rsassaPssVerify  CRYPTO_INTERFACE_PKCS1_rsassaPssVerify

#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_PKCS1_PRIV_HEADER__ */
