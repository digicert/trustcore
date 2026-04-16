/*
 * crypto_interface_des_priv.h
 *
 * Cryptographic Interface header file for redefining
 * DES functions.
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
@file       crypto_interface_des_priv.h
@brief      Cryptographic Interface header file for redefining DES functions.
@details    Add details here.

@filedoc    crypto_interface_des_priv.h
*/
#ifndef __CRYPTO_INTERFACE_DES_PRIV_HEADER__
#define __CRYPTO_INTERFACE_DES_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_DES_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_DES_INTERNAL__))

#define DES_initKey  CRYPTO_INTERFACE_DES_initKey
#define DES_encipher CRYPTO_INTERFACE_DES_encipher
#define DES_decipher CRYPTO_INTERFACE_DES_decipher
#define DES_clearKey CRYPTO_INTERFACE_DES_clearKey

#define CreateDESCtx CRYPTO_INTERFACE_CreateDESCtx
#define DeleteDESCtx CRYPTO_INTERFACE_DeleteDESCtx
#define DoDES        CRYPTO_INTERFACE_DoDES
#define CloneDESCtx  CRYPTO_INTERFACE_CloneDESCtx

#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_DES_PRIV_HEADER__ */
