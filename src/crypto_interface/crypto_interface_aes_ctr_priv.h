/*
 * crypto_interface_aes_ctr_priv.h
 *
 * Cryptographic Interface header file for redefining AES counter mode functions.
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

#if ( defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_AES_CTR_MAPPING__)) && \
    (!defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_AES_CTR_INTERNAL__))

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
