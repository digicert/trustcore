/*
 * crypto_interface_dsa_priv.h
 *
 * Cryptographic Interface header file for redefining DSA functions.
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
@file       crypto_interface_dsa_priv.h
@brief      Cryptographic Interface header file for redefining DSA functions.

@filedoc    crypto_interface_dsa_priv.h
*/
#ifndef __CRYPTO_INTERFACE_DSA_PRIV_HEADER__
#define __CRYPTO_INTERFACE_DSA_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_DSA_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_DSA_INTERNAL__))

#define DSA_createKey             CRYPTO_INTERFACE_DSA_createKey
#define DSA_cloneKey              CRYPTO_INTERFACE_DSA_cloneKey
#define DSA_freeKey               CRYPTO_INTERFACE_DSA_freeKey
#define DSA_computeKeyPair        CRYPTO_INTERFACE_DSA_computeKeyPair
#define DSA_makeKeyBlob           CRYPTO_INTERFACE_DSA_makeKeyBlob
#define DSA_extractKeyBlob        CRYPTO_INTERFACE_DSA_extractKeyBlob
#define DSA_equalKey              CRYPTO_INTERFACE_DSA_equalKey
#define DSA_getCipherTextLength   CRYPTO_INTERFACE_DSA_getCipherTextLength
#define DSA_getSignatureLength    CRYPTO_INTERFACE_DSA_getSignatureLength
#define DSA_generateKeyAux        CRYPTO_INTERFACE_DSA_generateKeyAux
#define DSA_generateKeyAux2       CRYPTO_INTERFACE_DSA_generateKeyAux2
#define DSA_computeSignatureAux   CRYPTO_INTERFACE_DSA_computeSignatureAux
#define DSA_verifySignatureAux    CRYPTO_INTERFACE_DSA_verifySignatureAux
#define DSA_setKeyParametersAux   CRYPTO_INTERFACE_DSA_setKeyParametersAux
#define DSA_getKeyParametersAlloc CRYPTO_INTERFACE_DSA_getKeyParametersAlloc
#define DSA_freeKeyTemplate       CRYPTO_INTERFACE_DSA_freeKeyTemplate
#define generatePQ                CRYPTO_INTERFACE_DSA_generatePQ
#define DSA_generateRandomGAux    CRYPTO_INTERFACE_DSA_generateRandomGAux
    
#define DSA_computeSignature2Aux  CRYPTO_INTERFACE_DSA_computeSignature2Aux
#define DSA_verifySignature2Aux   CRYPTO_INTERFACE_DSA_verifySignature2Aux
    
#endif

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_DSA_PRIV_HEADER__ */
