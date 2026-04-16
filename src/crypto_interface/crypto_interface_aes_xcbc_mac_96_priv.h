/*
 * crypto_interface_aes_xcbc_mac_96_priv.h
 *
 * Cryptographic Interface header file for redefining AES-XCBC functions.
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
