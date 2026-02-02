/*
 * dsaswserial.c
 *
 * Serialize DSA keys using an object with MDsaSwKeyData as pKey.
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

/* This is how DSA DER is supposed to work.
 * Private:
 *  PKCS 8
 *  alg Id is
 *    SEQ {
 *      OID,
 *      SEQ {
 *        p, q, g } }
 *  key data
 *    INT x
 *
 * Public:
 *  Subject Public Key Info
 *  alg Id is
 *    SEQ {
 *      OID,
 *      SEQ {
 *        p, q, g } }
 *  key data
 *    INT y
 *
 * Unfortunately, we might see
 *   PKCS 8
 *   alg ID is
 *     SEQ {
 *       OID }
 *   key data is
 *     SEQ {
 *       INT version,
 *       INTs p, q, g, y, x }
 * Subject Public Key Info
 *   alg ID is
 *     SEQ {
 *       OID }
 *   key data is
 *     SEQ {
 *       INTs p, q, g, y }
 */

#include "../../../crypto/mocasymkeys/mocsw/commondsa.h"
#include "../../../asn1/mocasn1.h"

#if (defined(__ENABLE_DIGICERT_DSA__))
#if (defined(__ENABLE_DIGICERT_ASYM_KEY__))

MSTATUS DsaSwSerializeKey (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  MocAsymKey pMocAsymKey,
  serializedKeyFormat keyFormat,
  MKeyOperatorDataReturn *pOutputInfo
  )
{
  MSTATUS status;
  MDsaSwKeyData *pData = (MDsaSwKeyData *)(pMocAsymKey->pKeyData);

  status = ERR_INVALID_INPUT;
  if (NULL != pData)
  {
    if (NULL != pData->pKey)
    {
      status = SerializeDsaKeyAlloc ( MOC_ASYM(hwAccelCtx)
        NULL, keyFormat, pOutputInfo->ppData, pOutputInfo->pLength);
    }
  }

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__)) */

#if (defined(__ENABLE_DIGICERT_SERIALIZE__))

MSTATUS SerializeDsaKeyAlloc (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  AsymmetricKey *pAsymKey,
  serializedKeyFormat keyFormat,
  ubyte **ppSerializedKey,
  ubyte4 *pSerializedKeyLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  DSAKey *pKey = NULL;
  
  if (NULL == pAsymKey)
      goto exit;

  pKey = pAsymKey->key.pDSA;

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
  status = ERR_INVALID_INPUT;
  if (NULL == DSA_X (pKey))
  {
    if ( (privateKeyInfoDer == keyFormat) ||
         (privateKeyPem == keyFormat) )
      goto exit;
  }
  else
  {
    if ( (publicKeyInfoDer == keyFormat) ||
         (publicKeyPem == keyFormat) )
      goto exit;
  }

  status = DerEncodeDsaKeyAlloc ( MOC_DSA(hwAccelCtx)
    pKey, ppSerializedKey, pSerializedKeyLen);

exit:

  return (status);
}

MSTATUS DerEncodeDsaKeyAlloc (
  MOC_DSA(hwAccelDescr hwAccelCtx)
  DSAKey *pDsaKey,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  )
{
  MSTATUS status;
  intBoolean isPrivate;
  ubyte4 index, extra, encodingLen, keyDataLen;
  ubyte *pBuf = NULL;
  ubyte pDsaOid[MOP_DSA_OID_LEN] = {
    MOP_DSA_OID
  };
  MAsn1Element *pArray = NULL;
  MAsn1TypeAndCount pTemplate[7] = {
    { MASN1_TYPE_SEQUENCE, 2 },
      { MASN1_TYPE_ENCODED, 0 },
      { MASN1_TYPE_SEQUENCE, 3 },
        { MASN1_TYPE_INTEGER, 0 },
        { MASN1_TYPE_INTEGER, 0 },
        { MASN1_TYPE_INTEGER, 0 },
    { MASN1_TYPE_INTEGER, 0 }
  };

  encodingLen = 0;
  keyDataLen = 0;

  /* Build the AlgId
   *   SEQ {
   *     OID
   *     SEQ {
   *       INT p
   *       INT q
   *       INT g }
   *
   * Then the key data is INTEGER, either x (private) or y (public).
   */
  status = MAsn1CreateElementArray (
    pTemplate, 7, MASN1_FNCT_ENCODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  pArray[1].value.pValue = pDsaOid;
  pArray[1].valueLen = MOP_DSA_OID_LEN;
  pArray[1].state = MASN1_STATE_SET_COMPLETE;

  isPrivate = FALSE;
  extra = 0;
  for (index = 0; index < 4; ++index)
  {
    /* For the pub or private key.
     * If the pri key is not NULL, use it. If it is, use the pub value.
     */
    if (3 == index)
    {
      if (NULL != pDsaKey->dsaVlong[4])
      {
        isPrivate = TRUE;
        extra = 1;
      }
    }

    status = MAsn1SetIntegerFromVlong (
      pArray + index + 3, pDsaKey->dsaVlong[index + extra], TRUE);
    if (OK != status)
      goto exit;
  }

  /* How big is the AlgId?
   */
  status = MAsn1Encode (pArray, NULL, 0, &encodingLen);
  if (OK == status)
    status = ERR_INVALID_INPUT;
  if (ERR_BUFFER_TOO_SMALL != status)
    goto exit;

  /* How big is the Key Data?
   */
  status = MAsn1Encode (pArray + 6, NULL, 0, &keyDataLen);
  if (OK == status)
    status = ERR_INVALID_INPUT;
  if (ERR_BUFFER_TOO_SMALL != status)
    goto exit;

  /* Allocate space for both.
   */
  status = DIGI_MALLOC ((void **)&pBuf, encodingLen + keyDataLen);
  if (OK != status)
    goto exit;

  status = MAsn1Encode (pArray, pBuf, encodingLen, &encodingLen);
  if (OK != status)
    goto exit;

  status = MAsn1Encode (
    pArray + 6, pBuf + encodingLen, keyDataLen, &keyDataLen);
  if (OK != status)
    goto exit;

  /* Now call the routine that will put the data into P8 or X.509.
   */
  status = CRYPTO_makeKeyInfo (
    isPrivate, pBuf, encodingLen, pBuf + encodingLen, keyDataLen,
    ppEncoding, pEncodingLen);

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }
  if (NULL != pBuf)
  {
    DIGI_MEMSET ((void *)pBuf, 0, encodingLen + keyDataLen);
    DIGI_FREE ((void **)&pBuf);
  }

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_SERIALIZE__)) */
#endif /* (defined(__ENABLE_DIGICERT_DSA__)) */
