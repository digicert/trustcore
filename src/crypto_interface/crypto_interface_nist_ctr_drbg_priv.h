/*
 * crypto_interface_nist_ctr_drbg_priv.h
 *
 * Cryptographic Interface header file for redefining NIST CTR DRBG.
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
@file       crypto_interface_nist_ctr_drbg_priv.h
@brief      Cryptographic Interface header file for redefining random functions.
@details    Add details here.

@filedoc    crypto_interface_nist_ctr_drbg_priv.h
*/
#ifndef __CRYPTO_INTERFACE_NIST_CTR_DRBG_PRIV_HEADER__
#define __CRYPTO_INTERFACE_NIST_CTR_DRBG_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_NIST_CTR_DRBG_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_NIST_CTR_DRBG_INTERNAL__))

#define NIST_CTRDRBG_newContext         CRYPTO_INTERFACE_NIST_CTRDRBG_newContext
#define NIST_CTRDRBG_newDFContext       CRYPTO_INTERFACE_NIST_CTRDRBG_newDFContext
#define NIST_CTRDRBG_deleteContext      CRYPTO_INTERFACE_NIST_CTRDRBG_deleteContext
#define NIST_CTRDRBG_reseed             CRYPTO_INTERFACE_NIST_CTRDRBG_reseed
#define NIST_CTRDRBG_generate           CRYPTO_INTERFACE_NIST_CTRDRBG_generate
#define NIST_CTRDRBG_numberGenerator    CRYPTO_INTERFACE_NIST_CTRDRBG_numberGenerator
#define NIST_CTRDRBG_generateSecret     CRYPTO_INTERFACE_NIST_CTRDRBG_generateSecret
#define NIST_CTRDRBG_setStateFromSecret CRYPTO_INTERFACE_NIST_CTRDRBG_setStateFromSecret

#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_NIST_CTR_DRBG_PRIV_HEADER__ */
