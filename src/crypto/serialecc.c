/*
 * serialecc.c
 *
 * Serialize ECC keys using ECCKey.
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

#include "../crypto/mocasymkeys/mocsw/commonecc.h"
#if (defined(__ENABLE_DIGICERT_ECC__))
#include "../crypto/primefld.h"
#include "../crypto/ecc.h"
#endif
#include "../crypto/malgo_id.h"
#include "../crypto/sec_key.h"

#if (defined(__ENABLE_DIGICERT_ECC__))

#define MOC_SUPPORTED_CURVE_COUNT 5

extern MSTATUS KeySerializeEcc (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  AsymmetricKey *pAsymKey,
  serializedKeyFormat keyFormat,
  ubyte **ppSerializedKey,
  ubyte4 *pSerializedKeyLen
  )
{
  MSTATUS status = OK;
  ECCKey *pNewKey = NULL;
  ubyte4 keyType = akt_ecc, version = 0;
  MAlgoId *pAlgoId = NULL;
  
  status = ERR_NULL_POINTER;
  if ( (NULL == pAsymKey) || (NULL == ppSerializedKey) ||
       (NULL == pSerializedKeyLen) )
    goto exit;

  if (deserialize == keyFormat)
  {
    ubyte4 curveId = 0;
    ubyte *pPriv = NULL;
    ubyte4 privLen = 0;
    ubyte *pPub = NULL;
    ubyte4 pubLen = 0;

    if ( (NULL == *ppSerializedKey) || (0 == *pSerializedKeyLen) )
      goto exit;

    if (0x00 == (*ppSerializedKey)[0])
    {
      status = KEYBLOB_parseHeader(*ppSerializedKey, *pSerializedKeyLen, &keyType, &version);
      if (OK != status)
        goto exit;

      status = ERR_BAD_KEY_BLOB;
      if (akt_ecc != keyType && akt_ecc_ed != keyType)
      {
        goto exit;
      }

      status = KEYBLOB_extractKeyBlobEx(*ppSerializedKey, *pSerializedKeyLen, pAsymKey);
      goto exit;
    }
    else
    {
      /* Deserialization PKCS8 keys only works for NIST curves, edDSA 25519 and edDSA 448 keys not supported */
      status = DeserializeEccKeyPKCS8X509(NULL, *ppSerializedKey, *pSerializedKeyLen, &curveId, &pPriv, &privLen, &pPub, &pubLen, &pAlgoId);
      
#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
      /* See if it's an Edward's curve key */
      if (OK != status)
      {
        status = DeserializeEccEdKeyPKCS8(*ppSerializedKey, *pSerializedKeyLen, &curveId, &pPriv, &privLen, &pPub, &pubLen);
        if (OK != status)
        {
          status = ERR_EC_DIFFERENT_SERIALIZATION;
        }
      }
#else
      if (OK != status && ERR_EC_DIFFERENT_SERIALIZATION != status)
        goto exit;
#endif
      if (ERR_EC_DIFFERENT_SERIALIZATION == status)
      {
        status = DeserializeEccKeyAlt(NULL, *ppSerializedKey, *pSerializedKeyLen, &curveId, &pPub, &pubLen);
        if (OK != status)
          goto exit;
      }
        
      if (cid_EC_Ed25519 == curveId || cid_EC_Ed448 == curveId)
      {
        keyType = akt_ecc_ed;
      }
    }
      
    status = EC_newKeyEx(curveId, &pNewKey);
    if (OK != status)
      goto exit;

    status = EC_setKeyParametersEx (MOC_ECC(hwAccelCtx) pNewKey, pPub, pubLen, pPriv, privLen);
    if (OK != status)
      goto exit;

    /* Prepare the asymmetric key */
    status = CRYPTO_uninitAsymmetricKey (pAsymKey, NULL);
    if (OK != status)
      goto exit;

    /* Load the newly created ECC key into the asymmetric key, this will NULL pNewKey on success */
    status = CRYPTO_loadAsymmetricKey(pAsymKey, keyType, (void **)&pNewKey);
    if (OK != status)
      goto exit;

    if (NULL != pAlgoId)
    {
      /* if pAlgoId isn't NULL, give pAsymKey the reference */
      pAsymKey->pAlgoId = pAlgoId;
      pAlgoId = NULL;
    }

    goto exit;
  }

  /* Before serializing, make sure the type is ECC.
   */
  status = ERR_BAD_KEY;
  if (akt_ecc != pAsymKey->type && akt_ecc_ed != pAsymKey->type)
    goto exit;
    
  status = SerializeEccKeyAlloc ( MOC_ASYM(hwAccelCtx)
    pAsymKey, keyFormat, NULL, ppSerializedKey, pSerializedKeyLen);

exit:
  
  if (NULL != pNewKey)
  {
    EC_deleteKeyEx (&pNewKey);
  }

  if (NULL != pAlgoId)
  {
    ALG_ID_free(&pAlgoId);
  }

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_ECC__)) */
