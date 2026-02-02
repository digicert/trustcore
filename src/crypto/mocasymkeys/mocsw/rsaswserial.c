/*
 * rsaswserial.c
 *
 * Serialize RSA keys using an object with MRsaSwKeyData as pKey.
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
#include "../../../crypto/pkcs_key.h"
#include "../../../crypto/malgo_id.h"
#include "../../../asn1/mocasn1.h"

#ifndef __DISABLE_DIGICERT_RSA__

#if  (defined(__ENABLE_DIGICERT_ASYM_KEY__))

MSTATUS RsaSwSerializeKey (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  MocAsymKey pMocAsymKey,
  serializedKeyFormat keyFormat,
  MKeyOperatorDataReturn *pOutputInfo
  )
{
  MSTATUS status;
  MRsaSwKeyData *pData = (MRsaSwKeyData *)(pMocAsymKey->pKeyData);

  status = ERR_INVALID_INPUT;
  if (NULL != pData)
  {
    if (NULL != pData->pKey)
    {
      status = SerializeRsaKeyAlloc ( MOC_ASYM(hwAccelCtx)
        NULL, keyFormat, pOutputInfo->ppData, pOutputInfo->pLength);
    }
  }

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__)) */

MSTATUS SerializeRsaKeyAlloc (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  AsymmetricKey *pAsymKey,
  serializedKeyFormat keyFormat,
  ubyte **ppSerializedKey,
  ubyte4 *pSerializedKeyLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  RSAKey *pKey = NULL;
  byteBoolean isPriSer = FALSE;

  if (NULL == pAsymKey)
    goto exit;

  pKey = pAsymKey->key.pRSA;

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
  if (privateKeyInfoDer == keyFormat || privateKeyPem == keyFormat)
  {
      if (FALSE == pKey->privateKey)
      {
          status = ERR_INVALID_INPUT;
          goto exit;
      }
      isPriSer = TRUE;
  }

  status = DerEncodeRsaKeyAlloc ( MOC_RSA(hwAccelCtx)
    pAsymKey, isPriSer, ppSerializedKey, pSerializedKeyLen);

exit:
  return (status);
}

MSTATUS BuildRsaKeyBlobAlloc (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  RSAKey *pRsaKey,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  )
{
  MSTATUS status;
  ubyte4 dataLen;
  ubyte *pNewBuf = NULL;
  ubyte pStart[MOC_RSA_BLOB_START_LEN] = {
    MOC_RSA_BLOB_START
  };

  /* An RSA key blob begins with
   *  pubKey: 00 00 00 00  00 00 00 01  00 00 00 01  02 00
   *  priKey: 00 00 00 00  00 00 00 01  00 00 00 01  02 01
   *
   * Then there are either 2 integers (pub key) or 7 integers (pri key)
   * Each integer is 4 bytes for length, then length bytes for the integer.
   *
   * We only need to write out the first 12 bytes of the blob, the
   * byteStringFromKey function will write out the 02 00 or 02 01.
   */

  /* Get the total length.
   * This function will return OK, even if the buffer is too small.
   */
  dataLen = 0;
  status = RSA_byteStringFromKey ( MOC_RSA(hwAccelCtx) pRsaKey, NULL, &dataLen);
  if (OK != status)
    goto exit;

  /* Allocate a buffer big enough to hold the prefix and the key data.
   */
  status = DIGI_MALLOC ((void **)&pNewBuf, dataLen + MOC_RSA_BLOB_START_LEN);
  if (OK != status)
    goto exit;

  status = DIGI_MEMCPY ((void *)pNewBuf, pStart, MOC_RSA_BLOB_START_LEN);
  if (OK != status)
    goto exit;

  status = RSA_byteStringFromKey ( MOC_RSA(hwAccelCtx)
    pRsaKey, pNewBuf + MOC_RSA_BLOB_START_LEN, &dataLen);
  if (OK != status)
    goto exit;

  *ppEncoding = pNewBuf;
  *pEncodingLen = dataLen + MOC_RSA_BLOB_START_LEN;
  pNewBuf = NULL;

exit:

  if (NULL != pNewBuf)
  {
    DIGI_FREE ((void **)&pNewBuf);
  }

  return (status);
}

MSTATUS DerEncodeRsaKeyAlloc (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  AsymmetricKey *pAsymKey,
  byteBoolean isPriSer,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  )
{
  MSTATUS status;
  ubyte version;
  ubyte4 encodingLen, keyDataType;
  ubyte *pNewBuf = NULL;
  MRsaKeyTemplate keyTemplate = {0};
  byteBoolean freeAlgId = FALSE;

  RSAKey *pKey = NULL;

  ubyte pRsaEncAlgId[MOP_RSA_P1_ENC_ALG_ID_LEN] = 
  {
    MOP_RSA_P1_ENC_ALG_ID
  };

  ubyte pRsaPssAlgId[MOP_RSA_PSS_ALG_ID_LEN] =
  {
    MOP_RSA_PSS_ALG_ID
  };

  /* default */
  ubyte *pAlgId = pRsaEncAlgId; 
  ubyte4 algIdLen = MOP_RSA_P1_ENC_ALG_ID_LEN;

  /* Use the same template for both pub and pri, using OPTIONAL to "cheat".
   */
  MAsn1Element *pArray = NULL;
  MAsn1TypeAndCount pTemplate[10] = {
    { MASN1_TYPE_SEQUENCE, 9 },
      { MASN1_TYPE_INTEGER | MASN1_OPTIONAL, 0 },
      { MASN1_TYPE_INTEGER, 0 },
      { MASN1_TYPE_INTEGER, 0 },
      { MASN1_TYPE_INTEGER | MASN1_OPTIONAL, 0 },
      { MASN1_TYPE_INTEGER | MASN1_OPTIONAL, 0 },
      { MASN1_TYPE_INTEGER | MASN1_OPTIONAL, 0 },
      { MASN1_TYPE_INTEGER | MASN1_OPTIONAL, 0 },
      { MASN1_TYPE_INTEGER | MASN1_OPTIONAL, 0 },
      { MASN1_TYPE_INTEGER | MASN1_OPTIONAL, 0 }
  };

  status = ERR_NULL_POINTER;
  if (NULL == pAsymKey)
    goto exit;

  pKey = pAsymKey->key.pRSA;
  
  /* If the key is public, build
   *   SEQ {
   *     INT modulus,
   *     INT pubExpo }
   *
   * If the key is private, build
   *   SEQ {
   *     INT version, -- 0, 1 is for multi prime
   *     INT modulus,
   *     INT pubExpo,
   *     INT priExpo,
   *     INT prime1,
   *     INT prime2,
   *     INT expo1,
   *     INT expo2,
   *     INT coeff }
   */
  /* Init this to a pub key array. If the key is private, we'll change it.
   */

  status = MAsn1CreateElementArray (
    pTemplate, 10, MASN1_FNCT_ENCODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  keyDataType = MOC_GET_PUBLIC_KEY_DATA;
  if (isPriSer)
    keyDataType = MOC_GET_PRIVATE_KEY_DATA;

  status = RSA_getKeyParametersAlloc (MOC_RSA(hwAccelCtx)
    pKey, &keyTemplate, keyDataType);
  if (OK != status)
    goto exit;

  status = MAsn1SetInteger (
    pArray + 2, keyTemplate.pN, keyTemplate.nLen, TRUE, 0);
  if (OK != status)
    goto exit;

  status = MAsn1SetInteger (
    pArray + 3, keyTemplate.pE, keyTemplate.eLen, TRUE, 0);
  if (OK != status)
    goto exit;

  if (FALSE != pKey->privateKey && isPriSer)
  {
    version = 0;
    pArray[1].value.pValue = &version;
    pArray[1].valueLen = 1;
    pArray[1].state = MASN1_STATE_SET_COMPLETE;

    status = MAsn1SetInteger (
      pArray + 4, keyTemplate.pD, keyTemplate.dLen, TRUE, 0);
    if (OK != status)
      goto exit;

    status = MAsn1SetInteger (
      pArray + 5, keyTemplate.pP, keyTemplate.pLen, TRUE, 0);
    if (OK != status)
      goto exit;

    status = MAsn1SetInteger (
      pArray + 6, keyTemplate.pQ, keyTemplate.qLen, TRUE, 0);
    if (OK != status)
      goto exit;

    status = MAsn1SetInteger (
      pArray + 7, keyTemplate.pDp, keyTemplate.dpLen, TRUE, 0);
    if (OK != status)
      goto exit;

    status = MAsn1SetInteger (
      pArray + 8, keyTemplate.pDq, keyTemplate.dqLen, TRUE, 0);
    if (OK != status)
      goto exit;

    status = MAsn1SetInteger (
      pArray + 9, keyTemplate.pQinv, keyTemplate.qInvLen, TRUE, 0);
    if (OK != status)
      goto exit;
  }

  status = MAsn1Encode (pArray, NULL, 0, &encodingLen);
  if (OK == status)
    status = ERR_INVALID_INPUT;
  if (ERR_BUFFER_TOO_SMALL != status)
    goto exit;

  status = DIGI_MALLOC ((void **)&pNewBuf, encodingLen);
  if (OK != status)
    goto exit;

  status = MAsn1Encode (pArray, pNewBuf, encodingLen, &encodingLen);
  if (OK != status)
    goto exit;

  /* Now call the routine that will put the data into P8 or X.509.
   */

  /* if pAlgoId is defined get the alg oid from there, otherwise check for pss */
  if ((NULL != pAsymKey) && (NULL != pAsymKey->pAlgoId))
  {
    status = ALG_ID_serializeAlloc(pAsymKey->pAlgoId, &pAlgId, &algIdLen);
    if (OK != status)
      goto exit;

    freeAlgId = TRUE;
  }
  else if (NULL != pAsymKey && akt_rsa_pss == pAsymKey->type)
  {
    pAlgId = pRsaPssAlgId;
    algIdLen = MOP_RSA_PSS_ALG_ID_LEN;
  }
  
  status = CRYPTO_makeKeyInfo (
    isPriSer, (ubyte *)pAlgId, algIdLen,
    pNewBuf, encodingLen, ppEncoding, pEncodingLen);

exit:

  RSA_freeKeyTemplate(NULL, &keyTemplate);

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }
  if (NULL != pNewBuf)
  {
    DIGI_FREE ((void **)&pNewBuf);
  }

  if (freeAlgId)
  {
    DIGI_FREE((void**)&pAlgId);
  }

  return (status);
}

#endif /* __DISABLE_DIGICERT_RSA__ */
