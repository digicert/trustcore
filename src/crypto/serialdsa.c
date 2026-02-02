/*
 * serialdsa.c
 *
 * Serialize DSA keys using DSAKey.
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

#include "../crypto/mocasymkeys/mocsw/commondsa.h"

#if (defined(__ENABLE_DIGICERT_DSA__))

extern MSTATUS KeySerializeDsa (
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

    status = DeserializeDsaKey ( MOC_ASYM(hwAccelCtx)
      *ppSerializedKey, *pSerializedKeyLen, pAsymKey, NULL);
    goto exit;
  }

  /* Before serializing, make sure the type is DSA.
   */
  status = ERR_BAD_KEY;
  if (akt_dsa != pAsymKey->type)
    goto exit;

  status = SerializeDsaKeyAlloc ( MOC_ASYM(hwAccelCtx)
    pAsymKey, keyFormat, ppSerializedKey, pSerializedKeyLen);

exit:

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_DSA__)) */
