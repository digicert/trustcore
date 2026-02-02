/*
 * crypto_interface_aes_xcbc_mac_96_priv.h
 *
 * Cryptographic Interface header file for redefining AES-XCBC functions.
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
@file       crypto_interface_aes_xcbc_mac_96_priv.h
@brief      Cryptographic Interface header file for redefining AES-XCBC functions.
@details    Add details here.

@filedoc    crypto_interface_aes_xcbc_mac_96_priv.h
*/
#ifndef __CRYPTO_INTERFACE_AES_XCBC_MAC_96_PRIV_HEADER__
#define __CRYPTO_INTERFACE_AES_XCBC_MAC_96_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_XCBC_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_XCBC_INTERNAL__))
    
#define AES_XCBC_MAC_96_init     CRYPTO_INTERFACE_AES_XCBC_MAC_96_init
#define AES_XCBC_MAC_96_update   CRYPTO_INTERFACE_AES_XCBC_MAC_96_update
#define AES_XCBC_MAC_96_final    CRYPTO_INTERFACE_AES_XCBC_MAC_96_final
#define AES_XCBC_MAC_96_reset    CRYPTO_INTERFACE_AES_XCBC_MAC_96_reset

#define AES_XCBC_PRF_128_init    CRYPTO_INTERFACE_AES_XCBC_PRF_128_init
#define AES_XCBC_PRF_128_final   CRYPTO_INTERFACE_AES_XCBC_PRF_128_final

#define AES_XCBC_clear           CRYPTO_INTERFACE_AES_XCBC_clear

#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_AES_XCBC_MAC_96_PRIV_HEADER__ */
