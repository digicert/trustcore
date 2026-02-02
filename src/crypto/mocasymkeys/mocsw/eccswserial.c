/*
 * eccswserial.c
 *
 * Functions to Serialize ECC keys in software.
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

#include "../../../crypto/mocasym.h"
#include "../../../crypto/mocasymkeys/mocsw/commonasym.h"
#include "../../../crypto/mocasymkeys/mocsw/commonecc.h"

#include "../../../asn1/parseasn1.h"
#include "../../../asn1/mocasn1.h"
#include "../../../crypto/primefld.h"
#include "../../../crypto/ecc.h"
#include "../../../crypto/hw_accel.h"

#if  (defined(__ENABLE_DIGICERT_ECC__))
#if  (defined(__ENABLE_DIGICERT_ASYM_KEY__))

MSTATUS EccSwSerializeKey (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  MocAsymKey pMocAsymKey,
  serializedKeyFormat keyFormat,
  MKeyOperatorDataReturn *pOutputInfo
  )
{
  MSTATUS status;
  MEccSwKeyData *pData = (MEccSwKeyData *)(pMocAsymKey->pKeyData);

  status = ERR_INVALID_INPUT;
  if (NULL != pData)
  {
    if (NULL != pData->pKey)
    {
      status = SerializeEccKeyAlloc ( MOC_ASYM(hwAccelCtx)
        NULL, keyFormat, pData->ParamsCall,
        pOutputInfo->ppData, pOutputInfo->pLength);
    }
  }

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__)) */

MSTATUS SerializeEccKeyAlloc (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  AsymmetricKey *pAsymKey,
  serializedKeyFormat keyFormat,
  StandardParams Params,
  ubyte **ppSerializedKey,
  ubyte4 *pSerializedKeyLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ECCKey *pKey = NULL;
  intBoolean isPriv = FALSE;

  if (NULL == pAsymKey)
    goto exit;

  pKey = pAsymKey->key.pECC;

  if (NULL == pKey)
      goto exit;

  /* If requesting a blob, get a blob.
   */
  if (mocanaBlobVersion2 == keyFormat)
  {
    status = KEYBLOB_makeKeyBlobEx (pAsymKey, ppSerializedKey, pSerializedKeyLen);
    goto exit;
  }

  /* At this point, the format should be either pub key or pri key DER. We don't
   * build PEM directly, the contents of PEM is the DER and the caller should
   * take care of the PEM with any DER.
   * Build the DER of the key data.
   * But first, make sure the format matches.
   */
  status = EC_isKeyPrivate(pKey, &isPriv);
  if (OK != status)
    goto exit;
  
  if (FALSE == isPriv)
  {
    if ( (privateKeyInfoDer == keyFormat) || (privateKeyPem == keyFormat) )
    {
      status = ERR_INVALID_INPUT;
      goto exit;
    }
  }
  else
  {
    if ( (publicKeyInfoDer == keyFormat) || (publicKeyPem == keyFormat) )
    {
      status = ERR_INVALID_INPUT;
      goto exit;
    }
  }

  if (akt_ecc == pAsymKey->type)
  {
    status = DerEncodeEccKeyAlloc( MOC_ECC(hwAccelCtx) pKey, ppSerializedKey, pSerializedKeyLen);
  }
#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
  else if (akt_ecc_ed == pAsymKey->type)
  {
    status = DerEncodeEccEdKeyAlloc( MOC_ECC(hwAccelCtx) pKey, ppSerializedKey, pSerializedKeyLen);
  }
#endif
  /* caller already checked type to be one of akt_ecc or ekt_ecc_ed */

exit:

  return (status);
}

MSTATUS BuildEccKeyBlobAlloc (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pEccKey,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  )
{
  MSTATUS status;
  ubyte4 primeSize, priLen, totalSize, offset, temp, keyDataType;
  ubyte *pBuf = NULL;
  ubyte pBlobStart[MOC_ECC_BLOB_START_LEN] = {
    MOC_ECC_BLOB_START
  };

  MEccKeyTemplate keyTemplate = { 0 };

  /* The key blob is
   *   prefix || curve ID || pubLen || pub point [ || priLen || priVal ]
   * If this is a public key, there is no priLen or priVal.
   * The curveId, pubLen, and priLen are each 4 bytes.
   * The length of the blob is dependent on the prime size.
   * Determine the length. The pub point will be (2 * primeSize) + 1. The priVal
   * will be primeSize.
   */
  status = EC_getElementByteStringLen(pEccKey, &primeSize);
  if (OK != status)
    goto exit;

  priLen = 0;
  keyDataType = MOC_GET_PUBLIC_KEY_DATA;
  if (FALSE != pEccKey->privateKey)
  {
    priLen = primeSize + 4;
    keyDataType = MOC_GET_PRIVATE_KEY_DATA;
  }
  status = EC_getKeyParametersAlloc(MOC_ECC(hwAccelCtx) pEccKey, &keyTemplate, keyDataType);
  if (OK != status)
    goto exit;

  status = ERR_BAD_LENGTH;
  if (((2 * primeSize) + 1) != keyTemplate.publicKeyLen)
    goto exit;

  if (FALSE != pEccKey->privateKey)
    if (primeSize != keyTemplate.privateKeyLen)
      goto exit;

  totalSize = MOC_ECC_BLOB_START_LEN + 9 + (2 * primeSize) + priLen;

  status = DIGI_MALLOC ((void **)&pBuf, totalSize);
  if (OK != status)
    goto exit;

  /* Write out the prefix.
   */
  status = DIGI_MEMCPY (
    (void *)pBuf, (void *)pBlobStart, MOC_ECC_BLOB_START_LEN);
  if (OK != status)
    goto exit;

  offset = MOC_ECC_BLOB_START_LEN;
  /* The curveId.
   */
  status = EC_getCurveIdFromKey (pEccKey, &temp);
  if (OK != status)
    goto exit;

  BIGEND32 (pBuf + offset, temp);
  offset += 4;
  /* The length of the point.
   */
  temp = keyTemplate.publicKeyLen;
  BIGEND32 (pBuf + offset, temp);
  offset += 4;
  /* The point.
   */
  status = DIGI_MEMCPY (
    pBuf + offset, keyTemplate.pPublicKey, keyTemplate.publicKeyLen);
  if (OK != status)
    goto exit;

  offset += keyTemplate.publicKeyLen;
  if (0 != priLen)
  {
    /* If there is a private value, write its length.
     */
    BIGEND32 (pBuf + offset, keyTemplate.privateKeyLen);
    offset += 4;
    /* Finally the private value.
     */
    status = DIGI_MEMCPY (
      pBuf + offset, keyTemplate.pPrivateKey, keyTemplate.privateKeyLen);
    if (OK != status)
      goto exit;
  }

  *ppEncoding = pBuf;
  *pEncodingLen = totalSize;
  pBuf = NULL;

exit:

  EC_freeKeyTemplate(NULL, &keyTemplate);

  if (NULL != pBuf)
  {
    DIGI_FREE ((void **)&pBuf);
  }

  return (status);
}

MSTATUS DerEncodeEccKeyAlloc (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pEccKey,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  )
{
  MSTATUS status;
  ubyte version;
  ubyte4 primeSize, curveOidLen, algIdLen, keyDataLen, pubValLen, derLen, eccId;
  ubyte4 keyDataType;
  ubyte *pPubVal = NULL;
  ubyte *pPriVal = NULL;
  ubyte *pDer = NULL;
  ubyte *pKeyData;
  ubyte pKeyOid[MOP_ECC_KEY_OID_LEN] = {
    MOP_ECC_KEY_OID
  };
  ubyte pGetCurveOid[MOP_MAX_ECC_CURVE_OID_LEN];
  ubyte pAlgId[MOP_ECC_KEY_OID_LEN + MOP_MAX_ECC_CURVE_OID_LEN + 2];

  MAsn1Element *pArray = NULL;
  MAsn1TypeAndCount pTemplate[5] = {
    { MASN1_TYPE_SEQUENCE, 4 },
      { MASN1_TYPE_INTEGER, 0 },
      { MASN1_TYPE_OCTET_STRING, 0 },
      { MASN1_TYPE_OID | MASN1_EXPLICIT, 0 },
      { MASN1_TYPE_BIT_STRING | MASN1_EXPLICIT | 1, 0 },
  };
  MEccKeyTemplate keyTemplate = { 0 };

  status = MAsn1CreateElementArray (
    pTemplate, 5, MASN1_FNCT_ENCODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  /* Determine the curve OID.
   */
  status = EC_getCurveIdFromKey(pEccKey, &eccId);
  if (OK != status)
    goto exit;

  status = GetCurveOid (
    eccId, pGetCurveOid, MOP_MAX_ECC_CURVE_OID_LEN, &curveOidLen);
  if (OK != status)
    goto exit;

  /* Build the AlgId.
   * The alg ID is the key OID with params curve OID.
   *   SEQ
   *     OID
   *     OID
   */
  pAlgId[0] = 0x30;

  status = DIGI_MEMCPY (
    (void *)(pAlgId + 2), (void *)pKeyOid, MOP_ECC_KEY_OID_LEN);
  if (OK != status)
    goto exit;

  pAlgId[1] = MOP_ECC_KEY_OID_LEN + curveOidLen;

  status = DIGI_MEMCPY (
    (void *)(pAlgId + MOP_ECC_KEY_OID_LEN + 2), (void *)pGetCurveOid, curveOidLen);
  if (OK != status)
    goto exit;

  algIdLen = MOP_ECC_KEY_OID_LEN + curveOidLen + 2;

  /* If this is a public key, build the public point.
   * If this is a private key, build
   *   SEQ {
   *     INT version (1)
   *     OCTET priVal
   *     OID EXPLICIT [0] curve OID
   *     BIT STRING EXPLICIT [1] pubKey
   *
   * Both need the pub point, so build it first.
   * It will be 04 <prime size> <prime size>
   * Also, add a leading 00 byte in case we want to use this for a BIT STRING.
   */
  status = EC_getElementByteStringLen(pEccKey, &primeSize);
  if (OK != status)
    goto exit;

  pubValLen = (2 * primeSize) + 1;

  keyDataType = MOC_GET_PUBLIC_KEY_DATA;
  if (FALSE != pEccKey->privateKey)
    keyDataType = MOC_GET_PRIVATE_KEY_DATA;

  status = EC_getKeyParametersAlloc(MOC_ECC(hwAccelCtx) pEccKey, &keyTemplate, keyDataType);
  if (OK != status)
    goto exit;

  status = ERR_BAD_LENGTH;
  if (pubValLen != keyTemplate.publicKeyLen)
    goto exit;

  if (FALSE != pEccKey->privateKey)
    if (primeSize != keyTemplate.privateKeyLen)
      goto exit;

  status = DIGI_MALLOC ((void **)&pPubVal, pubValLen + 1);
  if (OK != status)
    goto exit;

  /* This is there in case we put the pubVal into a BIT STRING, it's the unused
   * bits.
   */
  pPubVal[0] = 0;

  status = DIGI_MEMCPY (
    pPubVal + 1, keyTemplate.pPublicKey, keyTemplate.publicKeyLen);
  if (OK != status)
    goto exit;

  pKeyData = pPubVal + 1;
  keyDataLen = pubValLen;

  if (FALSE != pEccKey->privateKey)
  {
    /* Get the private value, it is the same size as the prime.
     */
    status = DIGI_MALLOC ((void *)&pPriVal, primeSize);
    if (OK != status)
      goto exit;

    status = DIGI_MEMCPY (
      pPriVal, keyTemplate.pPrivateKey, keyTemplate.privateKeyLen);
    if (OK != status)
      goto exit;

    version = 1;
    pArray[1].value.pValue = &version;
    pArray[1].valueLen = 1;
    pArray[1].state = MASN1_STATE_SET_COMPLETE;
    pArray[2].value.pValue = pPriVal;
    pArray[2].valueLen = primeSize;
    pArray[2].state = MASN1_STATE_SET_COMPLETE;
    pArray[3].value.pValue = pGetCurveOid + 2;
    pArray[3].valueLen = curveOidLen - 2;
    pArray[3].state = MASN1_STATE_SET_COMPLETE;
    pArray[4].value.pValue = pPubVal;
    pArray[4].valueLen = pubValLen + 1;
    pArray[4].state = MASN1_STATE_SET_COMPLETE;

    status = MAsn1Encode (pArray, NULL, 0, &derLen);
    if (OK == status)
      status = ERR_INVALID_INPUT;
    if (ERR_BUFFER_TOO_SMALL != status)
      goto exit;

    status = DIGI_MALLOC ((void **)&pDer, derLen);
    if (OK != status)
      goto exit;

    status = MAsn1Encode (pArray, pDer, derLen, &derLen);
    if (OK != status)
      goto exit;

    pKeyData = pDer;
    keyDataLen = derLen;
  }

  /* Now call the routine that will put the data into P8 or X.509.
   */
  status = CRYPTO_makeKeyInfo (
    pEccKey->privateKey, (ubyte *)pAlgId, algIdLen,
    pKeyData, keyDataLen, ppEncoding, pEncodingLen);

exit:

  EC_freeKeyTemplate(NULL, &keyTemplate);

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }
  if (NULL != pPriVal)
  {
    DIGI_FREE ((void **)&pPriVal);
  }
  if (NULL != pDer)
  {
    DIGI_FREE ((void **)&pDer);
  }
  if (NULL != pPubVal)
  {
    DIGI_FREE ((void **)&pPubVal);
  }

  return (status);
}

#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
MSTATUS DerEncodeEccEdKeyAlloc (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  ECCKey *pEccKey,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte version = 0;
  ubyte4 derLen = 0, eccId = 0;
  ubyte4 keyDataType = MOC_GET_PRIVATE_KEY_DATA;
  ubyte *pPubVal = NULL;
  ubyte *pPriVal = NULL;
  ubyte *pDer = NULL;
  
  ubyte pOid[MOP_ECC_CURVE_EDDH_25519_OID_LEN] = {0}; /* same length for all curves */
  ubyte4 oidLen = 0;
  
  intBoolean isPriv = FALSE;
  MAsn1Element *pArray = NULL;
  
#ifdef __ENABLE_DIGICERT_EDDSA_PRIV_W_PUB_SER__
  MAsn1TypeAndCount pTemplate[6] =
  {
    { MASN1_TYPE_SEQUENCE, 4 },
    { MASN1_TYPE_INTEGER, 0 },
    { MASN1_TYPE_SEQUENCE, 1 },
    { MASN1_TYPE_OID, 0 },
    { MASN1_TYPE_OCTET_STRING, 0 }, /* Octet string containing an octet string */
    { MASN1_TYPE_BIT_STRING | MASN1_IMPLICIT | 1, 0 }
  };
#else
  MAsn1TypeAndCount pTemplate[5] =
  {
    { MASN1_TYPE_SEQUENCE, 3 },
    { MASN1_TYPE_INTEGER, 0 },
    { MASN1_TYPE_SEQUENCE, 1 },
    { MASN1_TYPE_OID, 0 },
    { MASN1_TYPE_OCTET_STRING, 0 } /* Octet string containing an octet string */
  };
#endif
  
  MAsn1TypeAndCount pTemplatePub[4] =
  {
    { MASN1_TYPE_SEQUENCE, 2 },
    { MASN1_TYPE_SEQUENCE, 1 },
    { MASN1_TYPE_OID, 0 },
    { MASN1_TYPE_BIT_STRING, 0 }
  };
  
  MEccKeyTemplate keyTemplate = {0};
  
  if (NULL == ppEncoding || NULL == pEncodingLen)
    goto exit;
  
  /* Determine the curve OID.
   */
  status = EC_getCurveIdFromKey(pEccKey, &eccId);
  if (OK != status)
    goto exit;
  
  status = GetCurveOid (eccId, pOid, MOP_ECC_CURVE_EDDH_25519_OID_LEN, &oidLen);
  if (OK != status)
    goto exit;
  
  status = EC_isKeyPrivate(pEccKey, &isPriv);
  if (OK != status)
    goto exit;
  
  if (!isPriv)
  {
    keyDataType = MOC_GET_PUBLIC_KEY_DATA;
  }
  
  status = EC_getKeyParametersAlloc(MOC_ECC(hwAccelCtx) pEccKey, &keyTemplate, keyDataType);
  if (OK != status)
    goto exit;
  
  /*
   Our Edwards keys are always the correct length. No need for extra zero padding.
   
   However, our public key will be an ans1 BITSTRING type, hence the first
   byte should be 0x00 to represent 0 bits are to be removed from the end.
   
   And our private key will be encoded as a OCTET STRING in an OCTET STRING,
   so both keys will need to be copied over.
   */
  status = DIGI_MALLOC ((void **) &pPubVal, keyTemplate.publicKeyLen + 1);
  if (OK != status)
    goto exit;

  pPubVal[0] = 0x00;
  status = DIGI_MEMCPY(pPubVal + 1, keyTemplate.pPublicKey, keyTemplate.publicKeyLen);
  if (OK != status)
    goto exit;
  
  if (isPriv)
  {
    status = DIGI_MALLOC ((void **) &pPriVal, keyTemplate.privateKeyLen + 2);
    if (OK != status)
      goto exit;
    
    pPriVal[0] = OCTETSTRING;
    pPriVal[1] = (ubyte) keyTemplate.privateKeyLen; /* Must change if new larger keys are used! */
    status = DIGI_MEMCPY(pPriVal + 2, keyTemplate.pPrivateKey, keyTemplate.privateKeyLen);
    if (OK != status)
      goto exit;

#ifdef __ENABLE_DIGICERT_EDDSA_PRIV_W_PUB_SER__
    version = 1;

    /* finally ready to create the asn1 array */
    status = MAsn1CreateElementArray (pTemplate, 6, MASN1_FNCT_ENCODE, NULL, &pArray);
#else
     /* version is still 0 */
    status = MAsn1CreateElementArray (pTemplate, 5, MASN1_FNCT_ENCODE, NULL, &pArray);
#endif
    if (OK != status)
      goto exit;
    
    pArray[1].value.pValue = &version;
    pArray[1].valueLen = 1;
    pArray[1].state = MASN1_STATE_SET_COMPLETE;
    
    pArray[3].value.pValue = pOid + 2; /* GetCurveOid had the tag and length, skip and start with the value */
    pArray[3].valueLen = oidLen - 2;
    pArray[3].state = MASN1_STATE_SET_COMPLETE;
    
    pArray[4].value.pValue = pPriVal;
    pArray[4].valueLen = keyTemplate.privateKeyLen + 2;
    pArray[4].state = MASN1_STATE_SET_COMPLETE;

#ifdef __ENABLE_DIGICERT_EDDSA_PRIV_W_PUB_SER__
    pArray[5].value.pValue = pPubVal;
    pArray[5].valueLen = keyTemplate.publicKeyLen + 1;
    pArray[5].state = MASN1_STATE_SET_COMPLETE;
#endif
  }
  else
  {
    status = MAsn1CreateElementArray (pTemplatePub, 4, MASN1_FNCT_ENCODE, NULL, &pArray);
    if (OK != status)
      goto exit;
    
    pArray[2].value.pValue = pOid + 2; /* GetCurveOid had the tag and length, skip and start with the value */
    pArray[2].valueLen = oidLen - 2;
    pArray[2].state = MASN1_STATE_SET_COMPLETE;
    
    pArray[3].value.pValue = pPubVal;
    pArray[3].valueLen = keyTemplate.publicKeyLen + 1;
    pArray[3].state = MASN1_STATE_SET_COMPLETE;
  }
  
  status = MAsn1Encode (pArray, NULL, 0, &derLen);
  if (OK == status)
    status = ERR_INVALID_INPUT;
  if (ERR_BUFFER_TOO_SMALL != status)
    goto exit;
  
  status = DIGI_MALLOC ((void **)&pDer, derLen);
  if (OK != status)
    goto exit;
  
  status = MAsn1Encode (pArray, pDer, derLen, &derLen);
  if (OK != status)
    goto exit;
  
  *ppEncoding = pDer; pDer = NULL;
  *pEncodingLen = derLen;
  
exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }
  
  if (NULL != pDer)
  {
    DIGI_MEMSET_FREE (&pDer, derLen);
  }
  
  if (NULL != pPriVal)
  {
    DIGI_MEMSET_FREE (&pPriVal, keyTemplate.privateKeyLen);
  }

  if (NULL != pPubVal)
  {
    DIGI_MEMSET_FREE (&pPubVal, keyTemplate.publicKeyLen);
  }
  
  EC_freeKeyTemplate(pEccKey, &keyTemplate);
  
  return status;
}
#endif /* __ENABLE_DIGICERT_ECC_EDDSA__ */
#endif /* (defined(__ENABLE_DIGICERT_ECC__)) */
