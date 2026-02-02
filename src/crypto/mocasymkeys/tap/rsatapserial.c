/*
 * rsatapserial.c
 *
 * Serialize TAP RSA keys.
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

MSTATUS RsaTapSerializeKey (
  MocAsymKey pMocAsymKey,
  serializedKeyFormat keyFormat,
  MKeyOperatorDataReturn *pOutputInfo
  )
{
  MSTATUS status;
  MRsaTapKeyData *pInfo = (MRsaTapKeyData *)(pMocAsymKey->pKeyData);

  status = ERR_INVALID_INPUT;
  if (NULL != pInfo)
  {
    if (NULL != pInfo->pKey)
    {
      status = SerializeRsaTapKeyAlloc (
        pInfo->pKey, keyFormat, pOutputInfo->ppData, pOutputInfo->pLength);
    }
  }

  return status;

} /* RsaTapSerializeKey */

#endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__)) */

/*----------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SERIALIZE__))

MSTATUS SerializeRsaTapKeyAlloc (
  TAP_Key *pKey,
  serializedKeyFormat keyFormat,
  ubyte **ppSerializedKey,
  ubyte4 *pSerializedKeyLen
  )
{
  MSTATUS status;

  status = ERR_INVALID_INPUT;
  switch(keyFormat)
  {
    case mocanaBlobVersion2:
      status = BuildRsaTapKeyBlobAlloc (
        pKey, ppSerializedKey, pSerializedKeyLen);
      break;

    case privateKeyInfoDer:
    case privateKeyPem:
      status = DerEncodeRsaTapKeyAlloc (
        pKey, ppSerializedKey, pSerializedKeyLen);
      break;

    default:
      break;
  }
  
  return status;

} /* SerializeRsaTapKeyAlloc */

/*----------------------------------------------------------------------------*/

MSTATUS BuildRsaTapKeyBlobAlloc (
  TAP_Key *pTapKey,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  )
{
  MSTATUS status;
  ubyte4 serializedKeyLen = 0;
  ubyte *pSerializedTapKey = NULL;
  TAP_Buffer serializedKey = { 0, };
  ubyte *pNewKeyBlob = NULL;
  ubyte pStart[MOC_RSA_TAP_BLOB_START_LEN] = {
    MOC_RSA_TAP_BLOB_START
  };

  /* Serialize the TAP key */
  status = TAP_serializeKey (
    pTapKey, TAP_BLOB_FORMAT_MOCANA, TAP_BLOB_ENCODING_BINARY,  &serializedKey, NULL);
  if (OK != status)
    goto exit;
  serializedKeyLen = serializedKey.bufferLen;
  pSerializedTapKey = serializedKey.pBuffer;

  /* Allocate buffer large enough for the prefix and data */
  status = DIGI_MALLOC (
    (void **)&pNewKeyBlob, serializedKeyLen + MOC_RSA_TAP_BLOB_START_LEN);
  if (OK != status)
    goto exit;

  /* Copy in the prefix */
  status = DIGI_MEMCPY((void *)pNewKeyBlob, pStart, MOC_RSA_TAP_BLOB_START_LEN);
  if (OK != status)
    goto exit;

  /* Copy in the serialized TAP key data */
  status = DIGI_MEMCPY (
    pNewKeyBlob + MOC_RSA_TAP_BLOB_START_LEN, 
    pSerializedTapKey, serializedKeyLen);
  if (OK != status)
    goto exit;

  *ppEncoding = pNewKeyBlob;
  *pEncodingLen = serializedKeyLen + MOC_RSA_TAP_BLOB_START_LEN;
  pNewKeyBlob = NULL;

exit:
  
  /* TAP allocated space for the serialized key, that data was copied into
   * the new key blob so free it now that we are done */
  if (NULL != pSerializedTapKey)
  {
    DIGI_FREE((void **)&pSerializedTapKey);
  }

  if (NULL != pNewKeyBlob)
  {
    DIGI_FREE((void **)&pNewKeyBlob);
  }

  return status;

} /* BuildRsaTapKeyBlobAlloc */

/*----------------------------------------------------------------------------*/

MSTATUS DerEncodeRsaTapKeyAlloc (
  TAP_Key *pTapKey,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  )
{
  MSTATUS status;
  ubyte4 serializedKeyLen, encodingLen;
  TAP_Buffer serializedKey = { 0 };
  ubyte *pNewBuf = NULL;
  ubyte *pSerializedTapKey = NULL;
  MAsn1Element *pArray = NULL;
  ubyte pAlgId[MOP_RSA_TAP_ALG_ID_LEN] =
  {
    MOP_RSA_TAP_ALG_ID
  };

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

  status = MAsn1CreateElementArray (
    pTemplate, 6, MASN1_FNCT_ENCODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  /* Get the serialized key blob from TAP */
  status = TAP_serializeKey (
    pTapKey, TAP_BLOB_FORMAT_MOCANA, TAP_BLOB_ENCODING_BINARY,  &serializedKey, NULL);
  if (OK != status)
    goto exit;

  serializedKeyLen = serializedKey.bufferLen;
  pSerializedTapKey = serializedKey.pBuffer;

  /* Set the Version */
  status = MAsn1SetInteger (
    pArray + 1, NULL, 0, TRUE, 0);
  if (OK != status)
    goto exit;

  /* Set the Module Id */
  status = MAsn1SetInteger (
    pArray + 2, NULL, 0, TRUE, (sbyte4)pTapKey->providerObjectData.objectInfo.moduleId);
  if (OK != status)
    goto exit;

  /* Set the modulus value */
  status = MAsn1SetInteger (
    pArray + 3, 
    pTapKey->keyData.publicKey.publicKey.rsaKey.pModulus,
    pTapKey->keyData.publicKey.publicKey.rsaKey.modulusLen, TRUE, 0);
  if (OK != status)
    goto exit;

  /* Set the public exponent */
  status = MAsn1SetInteger (
    pArray + 4, 
    pTapKey->keyData.publicKey.publicKey.rsaKey.pExponent,
    pTapKey->keyData.publicKey.publicKey.rsaKey.exponentLen, TRUE, 0);
  if (OK != status)
    goto exit;

  /* Put the serialized TAP key blob into the octet string for encoding */
  status = MAsn1SetValue(pArray + 5, pSerializedTapKey, serializedKeyLen);
  if (OK != status)
    goto exit;

  /* Get the encoding length */
  status = MAsn1Encode (pArray, NULL, 0, &encodingLen);
  if (OK == status)
    status = ERR_INVALID_INPUT;
  if (ERR_BUFFER_TOO_SMALL != status)
    goto exit;

  /* Allocate space for the encoding */
  status = DIGI_MALLOC ((void **)&pNewBuf, encodingLen);
  if (OK != status)
    goto exit;

  /* Get the ASN1 encoding */
  status = MAsn1Encode (pArray, pNewBuf, encodingLen, &encodingLen);
  if (OK != status)
    goto exit;

  /* Last byte of OID is masked if it's a pw protected key */
  if (pTapKey->hasCreds)
  {
    pAlgId[MOP_TAP_PW_OID_INDEX] |= MOP_TAP_PW_MASK;
  }

  /* Use this new encoding to build a new key info */
  status = CRYPTO_makeKeyInfo (
    TRUE, (ubyte *)pAlgId, MOP_RSA_TAP_ALG_ID_LEN,
    pNewBuf, encodingLen, ppEncoding, pEncodingLen);

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }
  if (NULL != pNewBuf)
  {
    DIGI_FREE ((void **)&pNewBuf);
  }
  if (NULL != serializedKey.pBuffer)
  {
    TAP_UTILS_freeBuffer(&serializedKey);
  }

  return status;

} /* DerEncodeRsaTapKeyAlloc */

#endif /* (defined(__ENABLE_DIGICERT_SERIALIZE__)) */
#endif /* __ENABLE_DIGICERT_TAP__ */
