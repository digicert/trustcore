/*
 * crypto_interface_rc5_priv.h
 *
 * Cryptographic Interface header file for redefining RC5 methods.
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
#ifndef __CRYPTO_INTERFACE_RC5_PRIV_HEADER__
#define __CRYPTO_INTERFACE_RC5_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_RC5_MAPPING__)) && \
    (!defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_RC5_INTERNAL__))

#define MocCreateRC5Ctx CRYPTO_INTERFACE_MocCreateRC5Ctx
#define MocDeleteRC5Ctx CRYPTO_INTERFACE_MocDeleteRC5Ctx
#define MocRC5Update    CRYPTO_INTERFACE_MocRC5Update
#define MocRC5Final     CRYPTO_INTERFACE_MocRC5Final
#define MocReinitRC5Ctx CRYPTO_INTERFACE_MocReinitRC5Ctx
#define MocRC5GetIv     CRYPTO_INTERFACE_MocRC5GetIv
#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_RC5_PRIV_HEADER__ */
