/*
 * serialrsa.c
 *
 * Serialize RSA keys using RSAKey.
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

#include "../crypto/mocasymkeys/mocsw/commonrsa.h"

#ifndef __DISABLE_DIGICERT_RSA__

extern MSTATUS KeySerializeRsa (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  AsymmetricKey *pAsymKey,
  serializedKeyFormat keyFormat,
  ubyte **ppSerializedKey,
  ubyte4 *pSerializedKeyLen
  )
{
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if ( (NULL == pAsymKey) || (NULL == ppSerializedKey) ||
       (NULL == pSerializedKeyLen) )
    goto exit;

  if (deserialize == keyFormat)
  {
    if ( (NULL == *ppSerializedKey) || (0 == *pSerializedKeyLen) )
      goto exit;

    status = CRYPTO_uninitAsymmetricKey (pAsymKey, NULL);
    if (OK != status)
      goto exit;

    status = DeserializeRsaKey ( MOC_ASYM(hwAccelCtx)
      *ppSerializedKey, *pSerializedKeyLen, pAsymKey, NULL);
    goto exit;
  }

  /* Before serializing, make sure the type is RSA.
   */
  status = ERR_BAD_KEY;
  if (akt_rsa != pAsymKey->type && akt_rsa_pss != pAsymKey->type)
    goto exit;

  status = SerializeRsaKeyAlloc ( MOC_ASYM(hwAccelCtx)
    pAsymKey, keyFormat, ppSerializedKey, pSerializedKeyLen);

exit:
  return (status);
}

#endif /* __DISABLE_DIGICERT_RSA__ */
