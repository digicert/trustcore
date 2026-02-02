/*
 * crypto_interface_rsa_priv.h
 *
 * Cryptographic Interface header file for redefining RSA functions.
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
@file       crypto_interface_rsa_priv.h
@brief      Cryptographic Interface header file for redefining RSA functions.
@details    Add details here.

@filedoc    crypto_interface_rsa_priv.h
*/
#ifndef __CRYPTO_INTERFACE_RSA_PRIV_HEADER__
#define __CRYPTO_INTERFACE_RSA_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA_MAPPING__)) && \
    (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA_INTERNAL__))

#define RSA_createKey               CRYPTO_INTERFACE_RSA_createKeyAux
#define RSA_freeKey                 CRYPTO_INTERFACE_RSA_freeKeyAux
#define RSA_signMessage             CRYPTO_INTERFACE_RSA_signMessageAux
#define RSA_verifySignature         CRYPTO_INTERFACE_RSA_verifySignatureAux
#define RSA_signData                CRYPTO_INTERFACE_RSA_signData
#define RSA_verifyData              CRYPTO_INTERFACE_RSA_verifyData
#define RSA_getCipherTextLength     CRYPTO_INTERFACE_RSA_getCipherTextLengthAux
#define RSA_setPublicKeyParameters  CRYPTO_INTERFACE_RSA_setPublicKeyParametersAux
#define RSA_setPublicKeyData        CRYPTO_INTERFACE_RSA_setPublicKeyData
#define RSA_setAllKeyParameters     CRYPTO_INTERFACE_RSA_setAllKeyParameters
#define RSA_setAllKeyData           CRYPTO_INTERFACE_RSA_setAllKeyDataAux
#define RSA_encrypt                 CRYPTO_INTERFACE_RSA_encryptAux
#define RSA_decrypt                 CRYPTO_INTERFACE_RSA_decryptAux
#define RSA_keyFromByteString       CRYPTO_INTERFACE_RSA_keyFromByteString
#define RSA_generateKey             CRYPTO_INTERFACE_RSA_generateKey
#define RSA_byteStringFromKey       CRYPTO_INTERFACE_RSA_byteStringFromKey
#define RSA_cloneKey                CRYPTO_INTERFACE_RSA_cloneKey
#define RSA_equalKey                CRYPTO_INTERFACE_RSA_equalKey
#define RSA_getKeyParametersAlloc   CRYPTO_INTERFACE_RSA_getKeyParametersAllocAux
#define RSA_freeKeyTemplate         CRYPTO_INTERFACE_RSA_freeKeyTemplateAux
#define RSA_applyPublicKey          CRYPTO_INTERFACE_RSA_applyPublicKeyAux
#define RSA_applyPrivateKey         CRYPTO_INTERFACE_RSA_applyPrivateKeyAux
#define RSA_verifyDigest            CRYPTO_INTERFACE_RSA_verifyDigest

#endif /* ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA_MAPPING__ */

#if ( defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__))

struct RSAKey;

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_loadKeys (
  struct RSAKey **ppNewKey,
  MocAsymKey *ppPriKey,
  MocAsymKey *ppPubKey
  );

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_loadKey (
  struct RSAKey **ppNewKey,
  MocAsymKey *ppKey
  );

#endif /* ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_RSA__ */

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_RSA_PRIV_HEADER__ */
