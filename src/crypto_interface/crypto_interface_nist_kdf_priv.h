/*
 * crypto_interface_nist_kdf_priv.h
 *
 * Cryptographic Interface header file for redefining
 * NIST-KDF functions.
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
 @file       crypto_interface_nist_kdf_priv.h
 @brief      Cryptographic Interface header file for redefining NIST-KDF functions.
 @details    Add details here.
 
 @filedoc    crypto_interface_nist_kdf_priv.h
 */
#ifndef __CRYPTO_INTERFACE_NIST_KDF_PRIV_HEADER__
#define __CRYPTO_INTERFACE_NIST_KDF_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif
    
#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_NIST_KDF_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_NIST_KDF_INTERNAL__))
    
#define KDF_NIST_CounterMode        CRYPTO_INTERFACE_KDF_NIST_CounterMode
#define KDF_NIST_FeedbackMode       CRYPTO_INTERFACE_KDF_NIST_FeedbackMode
#define KDF_NIST_DoublePipelineMode CRYPTO_INTERFACE_KDF_NIST_DoublePipelineMode

#endif
    
#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_NIST_KDF_PRIV_HEADER__ */
