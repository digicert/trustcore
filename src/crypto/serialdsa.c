/*
 * serialdsa.c
 *
 * Serialize DSA keys using DSAKey.
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
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
