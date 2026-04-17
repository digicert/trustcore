/*
 * crypto_interface_tdes_priv.h
 *
 * Cryptographic Interface header file for redefining
 * Triple DES (TDES) functions.
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

#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_TDES_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_TDES_INTERNAL__))

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
