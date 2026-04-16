/*
 * crypto_interface_ansix9_63_kdf_priv.h
 *
 * Cryptographic Interface specification for ANSIX9_63-KDF.
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
