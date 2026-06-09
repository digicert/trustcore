/*
 * qstapserial.c
 *
 * Serialize TAP QS keys.
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

#include "../../../crypto/mocasymkeys/tap/qstap.h"
#include "../../../asn1/mocasn1.h"

#if defined(__ENABLE_DIGICERT_PQC__) && defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_ASYM_KEY__)

#ifdef __ENABLE_DIGICERT_SERIALIZE__
static MSTATUS BuildQsTapKeyBlobAlloc (
  TAP_Key *pTapKey,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  )
{
  MSTATUS status;
  ubyte *pBuf = NULL;
  TAP_Buffer serializedKey = { 0 };
  ubyte *pSerializedTapKey = NULL;
  ubyte4 serializedKeyLen;
  ubyte pBlobStart[MOC_QS_TAP_BLOB_START_LEN] = {
    MOC_QS_TAP_BLOB_START
  };

  /* Serialize the TAP key */
  status = TAP_serializeKey (
    pTapKey, TAP_BLOB_FORMAT_MOCANA, TAP_BLOB_ENCODING_BINARY,  &serializedKey, NULL);
  if (OK != status)
    goto exit;

  serializedKeyLen = serializedKey.bufferLen;
  pSerializedTapKey = serializedKey.pBuffer;

  status = DIGI_MALLOC (
    (void **)&pBuf, serializedKeyLen + MOC_QS_TAP_BLOB_START_LEN);
  if (OK != status)
    goto exit;

  /* Write out the prefix */
  status = DIGI_MEMCPY (
    (void *)pBuf, (void *)pBlobStart, MOC_QS_TAP_BLOB_START_LEN);
  if (OK != status)
    goto exit;

  /* Copy in the serialized TAP key data */
  status = DIGI_MEMCPY (
    pBuf + MOC_QS_TAP_BLOB_START_LEN, 
    pSerializedTapKey, serializedKeyLen);
  if (OK != status)
    goto exit;

  *ppEncoding = pBuf;
  *pEncodingLen = serializedKeyLen + MOC_QS_TAP_BLOB_START_LEN;
  pBuf = NULL;

exit:

  DIGI_FREE((void **)&pSerializedTapKey);

  if (NULL != pBuf)
  {
    DIGI_FREE ((void **)&pBuf);
  }

  return status;

} /* BuildQsTapKeyBlobAlloc */
#endif /* __ENABLE_DIGICERT_SERIALIZE__ */

/*----------------------------------------------------------------------------*/

MSTATUS SerializeQsTapKeyAlloc (
  TAP_Key *pKey,
  serializedKeyFormat keyFormat,
  ubyte **ppSerializedKey,
  ubyte4 *pSerializedKeyLen
  )
{
  MSTATUS status = ERR_INVALID_INPUT;

  switch(keyFormat)
  {
    case mocanaBlobVersion2:
#ifdef __ENABLE_DIGICERT_SERIALIZE__
      status = BuildQsTapKeyBlobAlloc (
        pKey, ppSerializedKey, pSerializedKeyLen);
#else
      status = ERR_NOT_IMPLEMENTED;
#endif
      break;
    case privateKeyInfoDer:
    case privateKeyPem:
      status = ERR_NOT_IMPLEMENTED;
      break;
    default:
      break;
  }
  
  return status;

} /* SerializeQsTapKeyAlloc */

/*----------------------------------------------------------------------------*/
     
MSTATUS QsTapSerializeKey (
  MocAsymKey pMocAsymKey,
  serializedKeyFormat keyFormat,
  MKeyOperatorDataReturn *pOutputInfo
  )
{
  MSTATUS status;
  MQsTapKeyData *pInfo = (MQsTapKeyData *)(pMocAsymKey->pKeyData);

  status = ERR_INVALID_INPUT;
  if (NULL != pInfo)
  {
    if (NULL != pInfo->pKey)
    {
      status = SerializeQsTapKeyAlloc (
        pInfo->pKey, keyFormat, pOutputInfo->ppData, pOutputInfo->pLength);
    }
  }

  return status;

} /* QsTapSerializeKey */

#endif /* defined(__ENABLE_DIGICERT_PQC__) && defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_ASYM_KEY__) */
