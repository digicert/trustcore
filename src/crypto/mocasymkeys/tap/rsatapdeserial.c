/*
 * rsatapdeserial.c
 *
 * Deserialize TAP RSA keys.
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

#include "../../../crypto/mocasymkeys/mocsw/commonrsa.h"
#include "../../../crypto/mocasymkeys/tap/rsatap.h"
#include "../../../crypto/pkcs_key.h"
#include "../../../asn1/mocasn1.h"

#if defined(__ENABLE_DIGICERT_TAP__)
#if defined(__ENABLE_DIGICERT_ASYM_KEY__)

MSTATUS RsaTapDeserializeKey (
  MocAsymKey pMocAsymKey,
  MKeyOperatorData *pInputInfo
  )
{
  MSTATUS status;
  intBoolean isPrivate = FALSE;
  TAP_Key *pNewKey = NULL;

  status = DeserializeRsaTapKey (
    pInputInfo->pData, pInputInfo->length, &isPrivate, &pNewKey);
  if (OK != status)
    goto exit;

  /* Load the TAP key into a MocAsymKey */
  status = RsaTapLoadKeyData(&pNewKey, NULL, 0, NULL, pMocAsymKey);
  if (OK != status)
    goto exit;

  if (TRUE != isPrivate)
  {
    pMocAsymKey->localType = MOC_LOCAL_KEY_RSA_PUB_TAP;
  }

exit:

  if (NULL != pNewKey)
  {
    TAP_freeKey(&pNewKey);
  }

  return status;

} /* RsaTapDeserializeKey */

#endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__)) */

/*----------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SERIALIZE__))

MSTATUS DeserializeRsaTapKey (
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  intBoolean *pIsPrivate,
  TAP_Key **ppTapKey
  )
{
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if (NULL == pIsPrivate)
    goto exit;

  if (0x30 == pSerializedKey[0])
  {
    /* Try to read a DER encoding of the serialized TAP key. There is a chance
     * that the input is a raw serialized tap key blob that happens to have
     * 0x30 for its first byte. In this case the read will fail with invalid
     * input, at which time we try again to read it as a mocana blob or a raw
     * tap blob. If this is successful we are done, simply goto and return */
    status = ReadRsaTapKeyDer (
      pSerializedKey, serializedKeyLen, pIsPrivate, ppTapKey);
    if (ERR_INVALID_INPUT != status)
      goto exit;

  }

  status = ReadRsaTapKeyBlob (
    pSerializedKey, serializedKeyLen, ppTapKey);
  *pIsPrivate = TRUE;

exit:
  return status;

} /* DeserializeRsaTapKey */

/*----------------------------------------------------------------------------*/

MSTATUS ReadRsaTapKeyDer (
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  intBoolean *pIsPrivate,
  TAP_Key **ppTapKey
  )
{
  MSTATUS status;
  sbyte4 cmpResult, isPrivate;
  ubyte4 getAlgIdLen, getKeyDataLen, tapBlobLen, bytesRead;
  ubyte *pGetAlgId = NULL;
  ubyte *pGetKeyData = NULL;
  ubyte *pTapBlob = NULL;
  TAP_Key *pNewKey = NULL;
  TAP_Buffer keyBuffer = {0};
  MAsn1Element *pArray = NULL;
  ubyte pAlgId[MOP_RSA_TAP_ALG_ID_LEN] = 
  {
    MOP_RSA_TAP_ALG_ID
  };
  ubyte4 hasCreds = 0;

  /* For an RSA TAP key, the privateKeyData is defined as follows:
   * SEQ {
   *   Version version,
   *   ModuleId moduleId,
   *   INTEGER modulus,
   *   INTEGER publicExponent
   *   TapPrivateKey tapPrivateKey
   * }
   *
   * where:
   * Version ::= INTEGER { v1(0) } (v1,...)
   * ModuleId ::= INTEGER { tpm2-1-2(1), tpm2-0(2) } (tpm-1-2, tpm-2-0, ...)
   * TapPrivateKey ::= OCTET STRING
   */
  MAsn1TypeAndCount pTemplate[6] = 
  {
    { MASN1_TYPE_SEQUENCE, 5 },
      { MASN1_TYPE_INTEGER, 0 },
      { MASN1_TYPE_INTEGER, 0 },
      { MASN1_TYPE_INTEGER, 0 },
      { MASN1_TYPE_INTEGER, 0 },
      { MASN1_TYPE_OCTET_STRING, 0 }
  };

  status = ERR_NULL_POINTER;
  if (NULL == pIsPrivate)
    goto exit;

  /* Extract the serialized tap key blob from the key info */
  status = CRYPTO_findKeyInfoComponents (
    pSerializedKey, serializedKeyLen, &pGetAlgId, &getAlgIdLen,
    &pGetKeyData, &getKeyDataLen, &isPrivate);
  if (OK != status)
    goto exit;

  /* Ensure alg id matches */
  status = ASN1_compareOID (
    pAlgId, MOP_RSA_TAP_ALG_ID_LEN, pGetAlgId, getAlgIdLen,
    NULL, &cmpResult);
  if (OK != status)
    goto exit;

  if (0 != cmpResult) /* might be a pw protected key */
  {
    pAlgId[MOP_TAP_PW_OID_INDEX] |= MOP_TAP_PW_MASK;
    status = ASN1_compareOID (pAlgId, MOP_RSA_TAP_ALG_ID_LEN, pGetAlgId, getAlgIdLen, NULL, &cmpResult);
    if (OK != status)
      goto exit;

    if (0 != cmpResult)
    {
      status = ERR_INVALID_INPUT;
      goto exit;
    }
    hasCreds = 1;
  }

  status = MAsn1CreateElementArray (
    pTemplate, 6, MASN1_FNCT_DECODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  status = MAsn1Decode (pGetKeyData, getKeyDataLen, pArray, &bytesRead);
  if (OK != status)
    goto exit;

  pTapBlob = pArray[5].value.pValue;
  tapBlobLen = pArray[5].valueLen;

  /* Deserialize the TAP key blob */
  keyBuffer.pBuffer = pTapBlob;
  keyBuffer.bufferLen = tapBlobLen;
  status = TAP_deserializeKey(&keyBuffer, &pNewKey, NULL);
  if (OK != status)
    goto exit;

  pNewKey->hasCreds = hasCreds;

  *pIsPrivate = isPrivate;
  *ppTapKey = pNewKey;
  pNewKey = NULL;

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }
  if (NULL != pNewKey)
  {
    TAP_freeKey(&pNewKey);
  }

  return status;

} /* ReadRsaTapKeyDer */

/*----------------------------------------------------------------------------*/

MSTATUS ReadRsaTapKeyBlob (
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  TAP_Key **ppTapKey
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  TAP_Key *pNewKey = NULL;
  TAP_Buffer keyBuffer = {0};
  ubyte *pBlob = NULL;
  ubyte4 blobLen = 0;
  ubyte pPrefix[MOC_RSA_TAP_BLOB_START_LEN] = {
    MOC_RSA_TAP_BLOB_START
  };

  status = ERR_INVALID_INPUT;
  if (MOC_RSA_TAP_BLOB_START_LEN > serializedKeyLen)
    goto exit;

  status = DIGI_MEMCMP (
    (void *)pSerializedKey, (void *)pPrefix,
    MOC_RSA_TAP_BLOB_START_LEN, &cmpResult);
  if (OK != status)
    goto exit;

  status = ERR_INVALID_INPUT;
  if (0 != cmpResult)
    goto exit;

  /* Prefix matches, this is a mocana blob. Increment our placeholder pointer
    * beyond the prefix to point at the actual data blob */
  pBlob = pSerializedKey + MOC_RSA_TAP_BLOB_START_LEN;
  blobLen = serializedKeyLen - MOC_RSA_TAP_BLOB_START_LEN;

  keyBuffer.pBuffer = pBlob;
  keyBuffer.bufferLen = blobLen;
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

} /* ReadRsaTapKeyBlob */

#endif /* (defined(__ENABLE_DIGICERT_SERIALIZE__)) */
#endif /* __ENABLE_DIGICERT_TAP__ */
