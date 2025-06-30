/*
 * crypto_interface_tdes_priv.h
 *
 * Cryptographic Interface header file for redefining
 * Triple DES (TDES) functions.
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
@file       crypto_interface_tdes_priv.h
@brief      Cryptographic Interface header file for redefining Triple DES (TDES) functions.
@details    Add details here.

@filedoc    crypto_interface_tdes_priv.h
*/
#ifndef __CRYPTO_INTERFACE_TDES_PRIV_HEADER__
#define __CRYPTO_INTERFACE_TDES_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_TDES_MAPPING__)) && \
    (!defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_TDES_INTERNAL__))

#define Create3DESCtx      CRYPTO_INTERFACE_Create3DESCtx
#define Create2Key3DESCtx  CRYPTO_INTERFACE_Create2Key3DESCtx
#define Delete3DESCtx      CRYPTO_INTERFACE_Delete3DESCtx
#define Reset3DESCtx       CRYPTO_INTERFACE_Reset3DESCtx
#define Do3DES             CRYPTO_INTERFACE_Do3DES
#define Clone3DESCtx       CRYPTO_INTERFACE_Clone3DESCtx
#define THREE_DES_initKey  CRYPTO_INTERFACE_THREE_DES_initKey
#define THREE_DES_encipher CRYPTO_INTERFACE_THREE_DES_encipher
#define THREE_DES_decipher CRYPTO_INTERFACE_THREE_DES_decipher
#define THREE_DES_clearKey CRYPTO_INTERFACE_THREE_DES_clearKey

#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_TDES_PRIV_HEADER__ */
