 /*
 * crypto_interface_ecc_eg_priv.h
 *
 * Cryptographic Interface header file for redeclaring ECEG functions.
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
@file       crypto_interface_ecc_eg_priv.h
@brief      Cryptographic Interface header file for redeclaring ECEG functions.
@details    Add details here.

@filedoc    crypto_interface_ecc_eg_priv.h
*/
#ifndef __CRYPTO_INTERFACE_ECC_EG_PRIV_HEADER__
#define __CRYPTO_INTERFACE_ECC_EG_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC_ELGAMAL_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC_ELGAMAL_INTERNAL__))

#define ECEG_init               CRYPTO_INTERFACE_ECEG_init
#define ECEG_update             CRYPTO_INTERFACE_ECEG_update
#define ECEG_final              CRYPTO_INTERFACE_ECEG_final
#define ECEG_encrypt            CRYPTO_INTERFACE_ECEG_encrypt
#define ECEG_decrypt            CRYPTO_INTERFACE_ECEG_decrypt
#define ECEG_encryptPKCSv1p5    CRYPTO_INTERFACE_ECEG_encryptPKCSv1p5
#define ECEG_decryptPKCSv1p5    CRYPTO_INTERFACE_ECEG_decryptPKCSv1p5

#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_ECC_EG_PRIV_HEADER__ */
