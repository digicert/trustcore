/*
 * crypto_interface_aes_priv.h
 *
 * Cryptographic Interface header file for redefining AES functions.
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
#ifndef __CRYPTO_INTERFACE_AES_PRIV_HEADER__
#define __CRYPTO_INTERFACE_AES_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_INTERNAL__))

#define AESALGO_makeAesKey       CRYPTO_INTERFACE_AESALGO_makeAesKey
#define AESALGO_makeAesKeyEx     CRYPTO_INTERFACE_AESALGO_makeAesKeyEx
#define AESALGO_blockEncrypt     CRYPTO_INTERFACE_AESALGO_blockEncrypt
#define AESALGO_blockEncryptEx   CRYPTO_INTERFACE_AESALGO_blockEncryptEx
#define AESALGO_blockDecrypt     CRYPTO_INTERFACE_AESALGO_blockDecrypt
#define AESALGO_blockDecryptEx   CRYPTO_INTERFACE_AESALGO_blockDecryptEx
#define AESALGO_clearKey         CRYPTO_INTERFACE_AESALGO_clearKey
#define CreateAESCtx             CRYPTO_INTERFACE_CreateAESCtx
#define CreateAESECBCtx          CRYPTO_INTERFACE_CreateAESECBCtx
#define CreateAESCFBCtx          CRYPTO_INTERFACE_CreateAESCFBCtx
#define CreateAESCFB1Ctx         CRYPTO_INTERFACE_CreateAESCFB1Ctx
#define CreateAESOFBCtx          CRYPTO_INTERFACE_CreateAESOFBCtx
#define ResetAESCtx              CRYPTO_INTERFACE_ResetAESCtx
#define CloneAESCtx              CRYPTO_INTERFACE_CloneAESCtx
#define DeleteAESCtx             CRYPTO_INTERFACE_DeleteAESCtx
#define DeleteAESECBCtx          CRYPTO_INTERFACE_DeleteAESCtx
#define DoAES                    CRYPTO_INTERFACE_DoAES
#define DoAESECB                 CRYPTO_INTERFACE_DoAESECB

#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_AES_PRIV_HEADER__ */
