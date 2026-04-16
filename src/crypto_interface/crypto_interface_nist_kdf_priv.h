/*
 * crypto_interface_nist_kdf_priv.h
 *
 * Cryptographic Interface header file for redefining
 * NIST-KDF functions.
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
