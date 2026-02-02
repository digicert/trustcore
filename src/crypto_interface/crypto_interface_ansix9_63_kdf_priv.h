/*
 * crypto_interface_ansix9_63_kdf_priv.h
 *
 * Cryptographic Interface specification for ANSIX9_63-KDF.
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
 @file       crypto_interface_ansix9_63_kdf_priv.h
 @brief      Cryptographic Interface header file for declaring ANSIX9_63-KDF functions.
 
 @filedoc    crypto_interface_ansix9_63_kdf_priv.h
 */
#ifndef __CRYPTO_INTERFACE_ANSIX9_63_KDF_PRIV_HEADER__
#define __CRYPTO_INTERFACE_ANSIX9_63_KDF_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif


#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_ANSIX9_63_KDF_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_ANSIX9_63_KDF_INTERNAL__))

#define ANSIX963KDF_generate CRYPTO_INTERFACE_ANSIX963KDF_generate

#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_ANSIX9_63_KDF_PRIV_HEADER__ */
