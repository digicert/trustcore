/*
 * crypto_interface_aes_cmac_priv.h
 *
 * Cryptographic Interface header file for redefining AES CMAC methods.
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
    
#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CMAC_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CMAC_INTERNAL__))
    
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
