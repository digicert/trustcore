/*
 * crypto_interface_pubcrypto_priv.h
 *
 * Cryptographic Interface header file for redeclaring key handling
 * functions for the Crypto Interface.
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

#ifndef __CRYPTO_INTERFACE_PUBCRYPTO_PRIV_HEADER__
#define __CRYPTO_INTERFACE_PUBCRYPTO_PRIV_HEADER__

#include "../cap/capdecl.h"

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_loadAsymmetricKey (
  AsymmetricKey *pAsymKey,
  ubyte4 keyType,
  void **ppAlgKey
  );

#ifdef __cplusplus
}
#endif

#endif /* __CRYPTO_INTERFACE_PUBCRYPTO_PRIV_HEADER__ */