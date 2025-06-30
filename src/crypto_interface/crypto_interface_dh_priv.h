/*
 * crypto_interface_dh_priv.h
 *
 * Cryptographic Interface header file for redefining DH functions.
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
@file       crypto_interface_dh_priv.h
@brief      Cryptographic Interface header file for redefining DH functions.

@filedoc    crypto_interface_dh_priv.h
*/
#ifndef __CRYPTO_INTERFACE_DH_PRIV_HEADER__
#define __CRYPTO_INTERFACE_DH_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_DH_MAPPING__)) && \
    (!defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_DH_INTERNAL__))
    
#define DH_allocate                 CRYPTO_INTERFACE_DH_allocate
#define DH_allocateServer           CRYPTO_INTERFACE_DH_allocateServer
#define DH_allocateClientAux        CRYPTO_INTERFACE_DH_allocateClientAux
#define DH_freeDhContext            CRYPTO_INTERFACE_DH_freeDhContext
#define DH_setKeyParameters         CRYPTO_INTERFACE_DH_setKeyParameters
#define DH_getKeyParametersAlloc    CRYPTO_INTERFACE_DH_getKeyParametersAlloc
#define DH_freeKeyTemplate          CRYPTO_INTERFACE_DH_freeKeyTemplate
#define DH_generateKeyPair          CRYPTO_INTERFACE_DH_generateKeyPair
#define DH_getPublicKey             CRYPTO_INTERFACE_DH_getPublicKey
#define DH_computeKeyExchangeEx     CRYPTO_INTERFACE_DH_computeKeyExchangeEx
#define DH_validateDomainParams     CRYPTO_INTERFACE_DH_validateDomainParams
#define DH_verifySafePG             CRYPTO_INTERFACE_DH_verifySafePG
#define DH_verifyPQ_FIPS1864        CRYPTO_INTERFACE_DH_verifyPQ_FIPS1864
#define DH_verifyG                  CRYPTO_INTERFACE_DH_verifyG
#define DH_getPByteString           CRYPTO_INTERFACE_DH_getPByteString
    
#define DH_allocateExt              CRYPTO_INTERFACE_DH_allocateExt
#define DH_allocateServerExt        CRYPTO_INTERFACE_DH_allocateServerExt
#define DH_allocateClientAuxExt     CRYPTO_INTERFACE_DH_allocateClientAuxExt
#define DH_freeDhContextExt         CRYPTO_INTERFACE_DH_freeDhContextExt
#define DH_setKeyParametersExt      CRYPTO_INTERFACE_DH_setKeyParametersExt
#define DH_getKeyParametersAllocExt CRYPTO_INTERFACE_DH_getKeyParametersAllocExt
#define DH_freeKeyTemplateExt       CRYPTO_INTERFACE_DH_freeKeyTemplateExt
#define DH_generateKeyPairExt       CRYPTO_INTERFACE_DH_generateKeyPairExt
#define DH_getPublicKeyExt          CRYPTO_INTERFACE_DH_getPublicKeyExt
#define DH_computeKeyExchangeExExt  CRYPTO_INTERFACE_DH_computeKeyExchangeExExt

#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_DH_PRIV_HEADER__ */
