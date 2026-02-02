/*
 * ecctapserial.c
 *
 * Serialize TAP ECC keys.
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

#include "../../../crypto/mocasymkeys/tap/ecctap.h"
#include "../../../asn1/mocasn1.h"

#if defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_TAP__)
#if defined(__ENABLE_DIGICERT_ASYM_KEY__)

/*----------------------------------------------------------------------------*/

MSTATUS BuildEccTapKeyBlobAlloc (
  TAP_Key *pTapKey,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  );

MSTATUS DerEncodeEccTapKeyAlloc (
  TAP_Key *pTapKey,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  );

/*----------------------------------------------------------------------------*/
     
MSTATUS EccTapSerializeKey (
  MocAsymKey pMocAsymKey,
  serializedKeyFormat keyFormat,
  MKeyOperatorDataReturn *pOutputInfo
  )
{
  MSTATUS status;
  MEccTapKeyData *pInfo = (MEccTapKeyData *)(pMocAsymKey->pKeyData);

  status = ERR_INVALID_INPUT;
  if (NULL != pInfo)
  {
    if (NULL != pInfo->pKey)
    {
      status = SerializeEccTapKeyAlloc (
        pInfo->pKey, keyFormat, pOutputInfo->ppData, pOutputInfo->pLength);
    }
  }

  return status;

} /* EccTapSerializeKey */

#endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__)) */

/*----------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_SERIALIZE__))

MSTATUS SerializeEccTapKeyAlloc (
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
      status = BuildEccTapKeyBlobAlloc (
        pKey, ppSerializedKey, pSerializedKeyLen);
      break;
    case privateKeyInfoDer:
    case privateKeyPem:
      status = DerEncodeEccTapKeyAlloc (
        pKey, ppSerializedKey, pSerializedKeyLen);
      break;
    default:
      break;
  }
  
  return status;

} /* SerializeEccTapKeyAlloc */

/*----------------------------------------------------------------------------*/

MSTATUS BuildEccTapKeyBlobAlloc (
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
  ubyte pBlobStart[MOC_ECC_TAP_BLOB_START_LEN] = {
    MOC_ECC_TAP_BLOB_START
  };

  /* Serialize the TAP key */
  status = TAP_serializeKey (
    pTapKey, TAP_BLOB_FORMAT_MOCANA, TAP_BLOB_ENCODING_BINARY,  &serializedKey, NULL);
  if (OK != status)
    goto exit;

  serializedKeyLen = serializedKey.bufferLen;
  pSerializedTapKey = serializedKey.pBuffer;

  status = DIGI_MALLOC (
    (void **)&pBuf, serializedKeyLen + MOC_ECC_TAP_BLOB_START_LEN);
  if (OK != status)
    goto exit;

  /* Write out the prefix */
  status = DIGI_MEMCPY (
    (void *)pBuf, (void *)pBlobStart, MOC_ECC_TAP_BLOB_START_LEN);
  if (OK != status)
    goto exit;

  /* Copy in the serialized TAP key data */
  status = DIGI_MEMCPY (
    pBuf + MOC_ECC_TAP_BLOB_START_LEN, 
    pSerializedTapKey, serializedKeyLen);
  if (OK != status)
    goto exit;

  *ppEncoding = pBuf;
  *pEncodingLen = serializedKeyLen + MOC_ECC_TAP_BLOB_START_LEN;
  pBuf = NULL;

exit:

  DIGI_FREE((void **)&pSerializedTapKey);

  if (NULL != pBuf)
  {
    DIGI_FREE ((void **)&pBuf);
  }

  return status;

} /* BuildEccTapKeyBlobAlloc */

/*----------------------------------------------------------------------------*/

MSTATUS DerEncodeEccTapKeyAlloc (
  TAP_Key *pTapKey,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  )
{
  MSTATUS status;
  ubyte4 serializedKeyLen, encodingLen, pubPointLen, oidLen;
  TAP_Buffer serializedKey = { 0 };
  ubyte *pOid = NULL;
  ubyte *pNewBuf = NULL;
  ubyte *pPubPoint = NULL;
  ubyte *pSerializedTapKey = NULL;
  MAsn1Element *pArray = NULL;
  ubyte pAlgId[MOP_ECC_TAP_KEY_ALG_ID_LEN] =
  {
    MOP_ECC_TAP_KEY_ALG_ID
  };
  ubyte pEccOid192[MOP_ECC_CURVE_P192_OID_LEN] =
  {
    MOP_ECC_CURVE_P192_OID
  };
  ubyte pEccOid224[MOP_ECC_CURVE_P224_OID_LEN] =
  {
    MOP_ECC_CURVE_P224_OID
  };

 /* For the ECC TAP Key, build
  * SEQ {
  *   Version version,
  *   ModuleId moduleId,
  *   ECParameters parameters,
  *   ECPoint publicKey,
  *   TapPrivateKey tapPrivateKey
  * }
  * 
  * where
  * Version ::= INTEGER { v1(0) } (v1,...)
  * ModuleId ::= INTEGER { tpm2-1-2(1), tpm2-0(2) } (tpm-1-2, tpm-2-0, ...)
  * ECPoint ::= OCTET STRING
  * TapPrivateKey ::= OCTET STRING
  * ECParameters ::= CHOICE {
  *   OID namedCurve
  *   NULL implicitCurve
  *   SpecifiedECDomain
  * }
  * 
  * Since we only support named curves, encode the choice with the curve OID.
  */
  MAsn1TypeAndCount pTemplate[6] =
  {
    { MASN1_TYPE_SEQUENCE, 5 },
      { MASN1_TYPE_INTEGER, 0 },
      { MASN1_TYPE_INTEGER, 0 },
      { MASN1_TYPE_OID, 0 },
      { MASN1_TYPE_OCTET_STRING, 0 },
      { MASN1_TYPE_OCTET_STRING, 0 }
  };

  status = MAsn1CreateElementArray (
    pTemplate, 6, MASN1_FNCT_ENCODE, NULL, &pArray);
  if (OK != status)
    goto exit;

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

  /* Set the ECParameters */
  status = ERR_INVALID_INPUT;
  switch(pTapKey->keyData.algKeyInfo.eccInfo.curveId)
  {
    case TAP_ECC_CURVE_NIST_P192:
      pOid = pEccOid192;
      oidLen = MOP_ECC_CURVE_P192_OID_LEN;
      break;

    case TAP_ECC_CURVE_NIST_P256:
      pEccOid192[MOP_ECC_CURVE_P192_OID_LEN - 1] = MOP_ECC_CURVE_P256_BYTE;
      pOid = pEccOid192;
      oidLen = MOP_ECC_CURVE_P192_OID_LEN;
      break;

    case TAP_ECC_CURVE_NIST_P224:
      pOid = pEccOid224;
      oidLen = MOP_ECC_CURVE_P224_OID_LEN;
      break;

    case TAP_ECC_CURVE_NIST_P384:
      pEccOid224[MOP_ECC_CURVE_P224_OID_LEN - 1] = MOP_ECC_CURVE_P384_BYTE;
      pOid = pEccOid224;
      oidLen = MOP_ECC_CURVE_P224_OID_LEN;
      break;

    case TAP_ECC_CURVE_NIST_P521:
      pEccOid224[MOP_ECC_CURVE_P224_OID_LEN - 1] = MOP_ECC_CURVE_P521_BYTE;
      pOid = pEccOid224;
      oidLen = MOP_ECC_CURVE_P224_OID_LEN;
      break;

    default:
      goto exit;
  }

  pArray[3].value.pValue = pOid + 2;
  pArray[3].valueLen = oidLen - 2;
  pArray[3].state = MASN1_STATE_SET_COMPLETE;

  /* Set the public point, the length has one byte extra to indicate uncompressed */
  pubPointLen = pTapKey->keyData.publicKey.publicKey.eccKey.pubXLen + 
                pTapKey->keyData.publicKey.publicKey.eccKey.pubYLen + 1;

  /* Allocate space for the public point buffer */
  status = DIGI_MALLOC((void **)&pPubPoint, pubPointLen);
  if (OK != status)
    goto exit;

  /* Set byte to indicate uncompressed point */
  pPubPoint[0] = 0x04;

  /* Copy the public info to the new buffer */
  status = DIGI_MEMCPY (
    (void *)(pPubPoint + 1),
    (void *)pTapKey->keyData.publicKey.publicKey.eccKey.pPubX,
    pTapKey->keyData.publicKey.publicKey.eccKey.pubXLen);
  if (OK != status)
    goto exit;

  status = DIGI_MEMCPY (
    (void *)(pPubPoint + 1 + pTapKey->keyData.publicKey.publicKey.eccKey.pubXLen),
    (void *)pTapKey->keyData.publicKey.publicKey.eccKey.pPubY,
    pTapKey->keyData.publicKey.publicKey.eccKey.pubYLen);
  if (OK != status)
    goto exit;

  status = MAsn1SetValue (pArray + 4, pPubPoint, pubPointLen);
  if (OK != status)
    goto exit;

  /* Get the serialized key blob from TAP */
  status = TAP_serializeKey (
    pTapKey, TAP_BLOB_FORMAT_MOCANA, TAP_BLOB_ENCODING_BINARY,  &serializedKey, NULL);
  if (OK != status)
    goto exit;

  serializedKeyLen = serializedKey.bufferLen;
  pSerializedTapKey = serializedKey.pBuffer;

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
    TRUE, (ubyte *)pAlgId, MOP_ECC_TAP_KEY_ALG_ID_LEN,
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
  if (NULL != pPubPoint)
  {
    DIGI_FREE((void **)&pPubPoint);
  }
  if (NULL != pSerializedTapKey)
  {
    DIGI_FREE ((void **)&pSerializedTapKey);
  }

  return status;

} /* DerEncodeEccTapKeyAlloc */

#endif /* defined(__ENABLE_DIGICERT_SERIALIZE__) */
#endif /* defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_TAP__) */
