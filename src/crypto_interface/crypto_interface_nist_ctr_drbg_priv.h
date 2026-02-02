/*
 * crypto_interface_nist_ctr_drbg_priv.h
 *
 * Cryptographic Interface header file for redefining NIST CTR DRBG.
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
