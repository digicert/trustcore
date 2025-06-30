/*
 * crypto_interface_aes_cmac_priv.h
 *
 * Cryptographic Interface header file for redefining AES CMAC methods.
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
 @file       crypto_interface_aes_cmac_priv.h
 @brief      Cryptographic Interface header file for redefining AES CMAC methods.
 @details    Add details here.
 
 @filedoc    crypto_interface_aes_cmac_priv.h
 */
#ifndef __CRYPTO_INTERFACE_AES_CMAC_PRIV_HEADER__
#define __CRYPTO_INTERFACE_AES_CMAC_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif
    
#if ( defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_AES_CMAC_MAPPING__)) && \
    (!defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_AES_CMAC_INTERNAL__))
    
#define AESCMAC_init          CRYPTO_INTERFACE_AESCMAC_init
#define AESCMAC_update        CRYPTO_INTERFACE_AESCMAC_update
#define AESCMAC_final         CRYPTO_INTERFACE_AESCMAC_final
    
#define AESCMAC_initExt       CRYPTO_INTERFACE_AESCMAC_initExt
#define AESCMAC_updateExt     CRYPTO_INTERFACE_AESCMAC_updateExt
#define AESCMAC_finalExt      CRYPTO_INTERFACE_AESCMAC_finalExt
#define AESCMAC_clear         CRYPTO_INTERFACE_AESCMAC_clear
    
#endif
    
#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_AES_CMAC_PRIV_HEADER__ */
