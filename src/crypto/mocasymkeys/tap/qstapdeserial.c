/*
 * qstapdeserial.c
 *
 * Deserialize TAP QS keys.
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
#include "../../../crypto/mocasymkeys/tap/idtap.h"
#include "../../../asn1/mocasn1.h"

#if defined(__ENABLE_DIGICERT_PQC__) && defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_ASYM_KEY__)

#ifdef __ENABLE_DIGICERT_SERIALIZE__
static MSTATUS ReadQsTapKeyBlob (
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  TAP_Key **ppTapKey
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  ubyte4 tapBlobLen;
  TAP_Key *pNewKey = NULL;
  ubyte *pTapBlob = NULL;
  TAP_Buffer keyBuffer = {0};
  ubyte pBlobStart[MOC_QS_TAP_BLOB_START_LEN] = {
    MOC_QS_TAP_BLOB_START
  };

  /* Ensure there is some data to process */
  status = ERR_INVALID_INPUT;
  if (MOC_QS_TAP_BLOB_START_LEN > serializedKeyLen)
    goto exit;

  /* Make sure the prefix is what we expect */
  status = DIGI_MEMCMP (
    (void *)pSerializedKey, (void *)pBlobStart, MOC_QS_TAP_BLOB_START_LEN,
    &cmpResult);
  if (OK != status)
    goto exit;

  status = ERR_INVALID_INPUT;
  if (0 != cmpResult)
    goto exit;

  /* Prefix matches, this is a mocana blob. Increment our placeholder pointer
   * beyond the prefix to point at the actual data blob */
  pTapBlob = pSerializedKey + MOC_QS_TAP_BLOB_START_LEN;
  tapBlobLen = serializedKeyLen - MOC_QS_TAP_BLOB_START_LEN;

  keyBuffer.pBuffer = pTapBlob;
  keyBuffer.bufferLen = tapBlobLen;
  status = TAP_deserializeKey(&keyBuffer, &pNewKey, NULL);
  if (OK != status)
    goto exit;

  *ppTapKey = pNewKey;
  pNewKey = NULL;

exit:

  if (NULL != pNewKey)
  {
    TAP_freeKey(&pNewKey);
  }

  return status;

} /* ReadQsTapKeyBlob */

/*----------------------------------------------------------------------------*/

static MSTATUS DeserializeQsTapKey (
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  intBoolean *pIsPrivate,
  TAP_Key **ppTapKey
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  if (NULL == pIsPrivate)
    goto exit;

  if (NULL == pSerializedKey || 0 == serializedKeyLen)
    goto exit;

  if (0x30 == pSerializedKey[0])
  {
    /* der encoding, not supported yet */
    status = ERR_NOT_IMPLEMENTED;
    goto exit;
  }

  status = ReadQsTapKeyBlob (
    pSerializedKey, serializedKeyLen, ppTapKey);
  *pIsPrivate = TRUE;

exit:
  return status;

} /* DeserializeQsTapKey */
#endif /* __ENABLE_DIGICERT_SERIALIZE__ */

/*----------------------------------------------------------------------------*/

MSTATUS QsTapDeserializeKey (
  MocAsymKey pMocAsymKey,
  MKeyOperatorData *pInputInfo
  )
{
#ifdef __ENABLE_DIGICERT_SERIALIZE__
  MSTATUS status;
  intBoolean isPrivate = FALSE;
  TAP_Key *pNewKey = NULL;
  TAP_Key *pLoadedNewKey = NULL;
  MQsTapKeyData *pData = NULL;
  MQsTapKeyData *pNewData = NULL;

  status = DeserializeQsTapKey (
    pInputInfo->pData, pInputInfo->length, &isPrivate, &pNewKey);
  if (OK != status)
    goto exit;

  if (TAP_PROVIDER_NANOROOT == pNewKey->providerObjectData.objectInfo.providerType)
  {
    /* We only use the id from the deserialized key, then we properly import a loaded TAP_Key from the id */
    TAP_Buffer keyId;

    /* pNewKey->providerObjectData.objectBlob.blob.pBuffer has the 4 byte idlen followed by 4 byte id, so for NanoRoot should be 8 bytes */ 
    status = ERR_INVALID_INPUT;
    if (8 != pNewKey->providerObjectData.objectBlob.blob.bufferLen)
        goto exit;
    
    keyId.pBuffer = pNewKey->providerObjectData.objectBlob.blob.pBuffer + 4;
    keyId.bufferLen = pNewKey->providerObjectData.objectBlob.blob.bufferLen - 4;

     /* if other PQC algs are added then we'll need to check the id or serialize the qs alg but assume mldsa for now */
    status = IdTapLoadKeyData(&keyId, TAP_KEY_ALGORITHM_MLDSA, pMocAsymKey, &pLoadedNewKey);
    if (OK != status)
      goto exit;

    /* Now put the loaded key in the keyData */
    pData = (MQsTapKeyData *)(pMocAsymKey->pKeyData);
    if (NULL == pData)
    {
      status = DIGI_CALLOC ((void **)&pNewData, 1, sizeof(MQsTapKeyData));
      if (OK != status)
        goto exit;

      pData = pNewData;
      pMocAsymKey->pKeyData = (void *)pNewData; pNewData = NULL;
    }
    pData->pKey = pLoadedNewKey; pLoadedNewKey = NULL;
    pData->isKeyLoaded = TRUE;
  }
  else
  {
    status = QsTapLoadKeyData(&pNewKey, NULL, 0, NULL, NULL, pMocAsymKey);

    if (TRUE != isPrivate)
    {
      pMocAsymKey->localType = MOC_LOCAL_KEY_PQC_MLDSA;
    }
  }

exit:

  if (NULL != pNewKey)
  {
    TAP_freeKey(&pNewKey);
  }
  
  if (NULL != pLoadedNewKey)
  {
    TAP_freeKey(&pLoadedNewKey);
  }

  if (NULL != pNewData)
  {
    DIGI_FREE ((void **)&pNewData);
  }

  return status;
#else
  return ERR_NOT_IMPLEMENTED;
#endif
} /* QsTapDeserializeKey */
#endif /* defined(__ENABLE_DIGICERT_QS__) && defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_ASYM_KEY__) */
