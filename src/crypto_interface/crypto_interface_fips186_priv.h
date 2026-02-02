/*
 * crypto_interface_fips186_priv.h
 *
 * Cryptographic Interface header file for redefining FIPS-186 RNG methods.
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
#ifndef __CRYPTO_INTERFACE_FIPS186_PRIV_HEADER__
#define __CRYPTO_INTERFACE_FIPS186_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif
    
#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_FIPS186_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_FIPS186_INTERNAL__))
    
#define RANDOM_KSrcGenerator           CRYPTO_INTERFACE_RANDOM_KSrcGenerator
#define RANDOM_newFIPS186Context       CRYPTO_INTERFACE_RANDOM_newFIPS186Context
#define RANDOM_deleteFIPS186Context    CRYPTO_INTERFACE_RANDOM_deleteFIPS186Context
#define RANDOM_numberGeneratorFIPS186  CRYPTO_INTERFACE_RANDOM_numberGeneratorFIPS186
#define RANDOM_seedFIPS186Context      CRYPTO_INTERFACE_RANDOM_seedFIPS186Context

#endif
    
#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_FIPS186_PRIV_HEADER__ */
