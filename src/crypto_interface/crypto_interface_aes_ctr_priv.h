/*
 * crypto_interface_aes_ctr_priv.h
 *
 * Cryptographic Interface header file for redefining AES counter mode functions.
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
@file       crypto_interface_aes_priv.h
@brief      Cryptographic Interface header file for redefining AES functions.
@details    Add details here.

@filedoc    crypto_interface_aes_priv.h
*/
#ifndef __CRYPTO_INTERFACE_AES_CTR_PRIV_HEADER__
#define __CRYPTO_INTERFACE_AES_CTR_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CTR_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CTR_INTERNAL__))

#define CreateAESCTRCtx          CRYPTO_INTERFACE_CreateAESCTRCtx
#define DeleteAESCTRCtx          CRYPTO_INTERFACE_DeleteAESCTRCtx
#define AESCTRInit               CRYPTO_INTERFACE_AESCTRInit
#define DoAESCTR                 CRYPTO_INTERFACE_DoAESCTR
#define DoAESCTREx               CRYPTO_INTERFACE_DoAESCTREx
#define GetCounterBlockAESCTR    CRYPTO_INTERFACE_GetCounterBlockAESCTR
#define CreateAesCtrCtx          CRYPTO_INTERFACE_CreateAesCtrCtx
#define DoAesCtrEx               CRYPTO_INTERFACE_DoAesCtrEx
#define CloneAESCTRCtx           CRYPTO_INTERFACE_CloneAESCTRCtx

#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_AES_PRIV_HEADER__ */
