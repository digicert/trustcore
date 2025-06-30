/*
 * crypto_interface_ecc_priv.h
 *
 * Cryptographic Interface header file for redefining ECC functions.
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
@file       crypto_interface_ecc_priv.h
@brief      Cryptographic Interface header file for redefining ECC functions.
@details    Add details here.

@filedoc    crypto_interface_ecc_priv.h
*/
#ifndef __CRYPTO_INTERFACE_ECC_PRIV_HEADER__
#define __CRYPTO_INTERFACE_ECC_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_ECC_MAPPING__)) && \
    (!defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_ECC_INTERNAL__))

#define EC_newKeyEx                                                            \
    CRYPTO_INTERFACE_EC_newKeyAux
#define EC_isKeyPrivate                                                        \
    CRYPTO_INTERFACE_EC_isKeyPrivate
#define EC_deleteKeyEx                                                         \
    CRYPTO_INTERFACE_EC_deleteKeyAux
#define EC_getCurveIdFromKey                                                   \
    CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux
#define EC_getElementByteStringLen                                             \
    CRYPTO_INTERFACE_EC_getElementByteStringLenAux
#define EC_getPointByteStringLenByCurveId                                      \
    CRYPTO_INTERFACE_EC_getPointByteStringLenByCurveId
#define EC_getPointByteStringLenEx                                             \
    CRYPTO_INTERFACE_EC_getPointByteStringLenAux
#define EC_generateKeyPairEx                                                   \
    CRYPTO_INTERFACE_EC_generateKeyPairAux
#define EC_generateKeyPairAlloc                                                \
    CRYPTO_INTERFACE_EC_generateKeyPairAllocAux
#define ECDSA_signDigest                                                       \
    CRYPTO_INTERFACE_ECDSA_signDigestAux
#define ECDSA_verifySignatureDigest                                            \
    CRYPTO_INTERFACE_ECDSA_verifySignatureDigestAux
#define ECDH_generateSharedSecretFromKeys                                      \
    CRYPTO_INTERFACE_ECDH_generateSharedSecretFromKeysAux
#define ECDH_generateSharedSecretFromPublicByteString                          \
    CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux
#define EC_getKeyParametersAlloc                                               \
    CRYPTO_INTERFACE_EC_getKeyParametersAllocAux
#define EC_freeKeyTemplate                                                     \
    CRYPTO_INTERFACE_EC_freeKeyTemplateAux
#define EC_setKeyParametersEx                                                  \
    CRYPTO_INTERFACE_EC_setKeyParametersAux
#define EC_setPrivateKeyEx                                                     \
    CRYPTO_INTERFACE_EC_setPrivateKey
#define EC_writePublicKeyToBuffer                                              \
    CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux
#define EC_writePublicKeyToBufferAlloc                                         \
    CRYPTO_INTERFACE_EC_writePublicKeyToBufferAllocAux
#define EC_newPublicKeyFromByteString                                          \
    CRYPTO_INTERFACE_EC_newPublicKeyFromByteStringAux
#define EC_cloneKeyEx                                                          \
    CRYPTO_INTERFACE_EC_cloneKeyAux
#define EC_equalKeyEx                                                          \
    CRYPTO_INTERFACE_EC_equalKeyAux
#define EC_verifyKeyPairEx                                                     \
    CRYPTO_INTERFACE_EC_verifyKeyPairAux
#define EC_verifyPublicKeyEx                                                   \
    CRYPTO_INTERFACE_EC_verifyPublicKeyAux
#define ECDSA_signMessage                                                      \
  CRYPTO_INTERFACE_ECDSA_signMessageExt
#define ECDSA_verifyMessage                                                    \
  CRYPTO_INTERFACE_ECDSA_verifyMessageExt
#define ECDSA_initVerify                                                       \
  CRYPTO_INTERFACE_ECDSA_initVerifyExt
#define ECDSA_updateVerify                                                     \
  CRYPTO_INTERFACE_ECDSA_updateVerifyExt
#define ECDSA_finalVerify                                                      \
  CRYPTO_INTERFACE_ECDSA_finalVerifyExt
#define EdDSA_signInput                                                        \
  CRYPTO_INTERFACE_EdDSA_signInput
#define EdDSA_verifyInput                                                      \
  CRYPTO_INTERFACE_EdDSA_verifyInput
#define EC_createCombMutexes                                                   \
  CRYPTO_INTERFACE_EC_createCombMutexes
#define EC_deleteAllCombsAndMutexes                                            \
  CRYPTO_INTERFACE_EC_deleteAllCombsAndMutexes

#endif /* ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE_ECC_MAPPING__ */

#if ( defined(__ENABLE_MOCANA_CRYPTO_INTERFACE_ECC__))

struct ECCKey;

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_loadKeys (
  struct ECCKey **ppNewKey,
  MocAsymKey *ppPriKey,
  MocAsymKey *ppPubKey
  );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_loadKey (
  struct ECCKey **ppNewKey,
  MocAsymKey *ppKey
  );

#endif /* ifdef __ENABLE_MOCANA_CRYPTO_INTERFACE_ECC__ */

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_ECC_PRIV_HEADER__ */
