/*
 * crypto_interface_pubcrypto.c
 *
 * Cryptographic Interface specification for public key utility functions.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_PUBCRYPTO_INTERNAL__

#include "../crypto/mocasym.h"
#include "../common/initmocana.h"
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/crypto_interface_pubcrypto_priv.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_PUBCRYPTO__))

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_loadAsymmetricKey (
  AsymmetricKey *pAsymKey,
  ubyte4 keyType,
  void **ppAlgKey
  )
{
  MSTATUS status;
  void *pNewKey = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pAsymKey) || (NULL == ppAlgKey) )
    goto exit;

  if (NULL == *ppAlgKey)
    goto exit;

  /* Make sure the key object is clear */
  status = CRYPTO_initAsymmetricKey (pAsymKey);
  if (OK != status)
    goto exit;

  switch (keyType)
  {
    default:
      status = ERR_BAD_KEY_TYPE;
      goto exit;

#ifndef __DISABLE_DIGICERT_RSA__
    case akt_rsa:
      pAsymKey->key.pRSA = (RSAKey *)(*ppAlgKey);
      pAsymKey->type = akt_rsa;
      break;

    case akt_tap_rsa:
      status = CRYPTO_INTERFACE_RSA_loadKey (
        (RSAKey **)&pNewKey, (MocAsymKey *)ppAlgKey);
      if (OK != status)
        goto exit;

      /* Set the pointer within the AsymmetricKey */
      pAsymKey->key.pRSA = (RSAKey *)(pNewKey);
      pAsymKey->type = akt_tap_rsa;
      pNewKey = NULL;
      break;
#endif

#if !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && defined(__ENABLE_DIGICERT_DSA__)
    case akt_dsa:
      pAsymKey->key.pDSA = (DSAKey *)(*ppAlgKey);
      pAsymKey->type = akt_dsa;
      break;
#endif

#if (defined(__ENABLE_DIGICERT_ECC__))
    case akt_ecc:
    case akt_ecc_ed:
      pAsymKey->key.pECC = (ECCKey *)(*ppAlgKey);
      pAsymKey->type = keyType;
      break;

    case akt_tap_ecc:
      status = CRYPTO_INTERFACE_EC_loadKey (
        (ECCKey **)&pNewKey, (MocAsymKey *)ppAlgKey);
      if (OK != status)
        goto exit;

      /* Set the pointer within the AsymmetricKey */
      pAsymKey->key.pECC = (ECCKey *)(pNewKey);
      pAsymKey->type = akt_tap_ecc;
      pNewKey = NULL;
      break;
#endif

    case akt_moc:
    case akt_custom:
      pAsymKey->key.pMocAsymKey = (MocAsymKey )(*ppAlgKey);
      pAsymKey->type = keyType;
      break;
  }

  *ppAlgKey = NULL;

exit:
  return status;
}


#endif
