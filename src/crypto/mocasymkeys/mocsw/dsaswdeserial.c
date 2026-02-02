/*
 * dsaswdeserial.c
 *
 * Deserialize DSA keys using an object with MDsaSwKeyData as pKey.
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

#include "../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_DSA__))

#include "../../../crypto/mocasymkeys/mocsw/commondsa.h"
#include "../../../asn1/mocasn1.h"
#include "../../../crypto/malgo_id.h"
#include "../../../crypto/pubcrypto.h"


MSTATUS DeserializeDsaKey (
  MOC_ASYM(hwAccelDescr hwAccelCtx)
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  AsymmetricKey *pAsymKey,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  intBoolean isPrivate;
  sbyte4 cmpResult;
  ubyte4 pubPriFlag, bytesRead, algIdLen, keyDataLen, keyType, version;
  ubyte *pGetAlgId, *pGetKeyData;
  DSAKey *pNewKey = NULL;
  MAlgoId *pAlgoId = NULL;

  ubyte pDsaOid[MOP_DSA_OID_LEN] = {
    MOP_DSA_OID
  };
  MAsn1Element *pArray = NULL;
  MAsn1TypeAndCount pTemplate[7] = {
    { MASN1_TYPE_SEQUENCE, 2 },
      { MASN1_TYPE_OID, 0 },
      { MASN1_TYPE_SEQUENCE, 3 },
        { MASN1_TYPE_INTEGER, 0 },
        { MASN1_TYPE_INTEGER, 0 },
        { MASN1_TYPE_INTEGER, 0 },
    { MASN1_TYPE_INTEGER, 0 },
  };

  /* If the first byte is 0, this should be a blob.
   */
  if (0 == pSerializedKey[0])
  {
    status = KEYBLOB_parseHeader(pSerializedKey, serializedKeyLen, &keyType, &version);
    if (OK != status)
        goto exit;

    status = ERR_BAD_KEY_BLOB;
    if (akt_dsa != keyType)
    {
        goto exit;
    }

    status = KEYBLOB_extractKeyBlobEx(pSerializedKey, serializedKeyLen, pAsymKey);
    goto exit;
  }

  /* DER decode the key.
   * Init pubPriFlag to 0, meaning we don't know yet if the key is public or
   * private.
   */
  pubPriFlag = 0;

  /* Parse, isolating the algID and key data.
   * Init isPrivate to false, meaning we'll try the public key first if the data
   * is not P8 or X.509.
   * If it is P8 or X.509, we'll either reset isPrivate or not, but we'll know
   * what it should be.
   */
  isPrivate = FALSE;
  status = CRYPTO_findKeyInfoComponents (
    pSerializedKey, serializedKeyLen, &pGetAlgId, &algIdLen,
    &pGetKeyData, &keyDataLen, &isPrivate);
  if (OK == status)
  {
    /* If this worked, make sure the algId is for DSA.
     */
    status = ASN1_compareOID (
      pDsaOid, MOP_DSA_OID_LEN, pGetAlgId, algIdLen, NULL,
      &cmpResult);
    if (OK != status)
      goto exit;

    status = ERR_INVALID_INPUT;
    if (0 != cmpResult)
      goto exit;

    status = ALG_ID_deserializeBuffer(
        ALG_ID_DSA_OID, pGetAlgId, algIdLen, &pAlgoId);
    if (OK != status)
        goto exit;

    status = CRYPTO_loadAlgoId(pAsymKey, (void **) &pAlgoId);
    if (OK != status)
      goto exit;

    pubPriFlag = 2;
    if (FALSE == isPrivate)
      pubPriFlag = 1;
  }
  else
  {
    /* If this didn't work, it is possible the data is another form.
     */
    status = DecodeDsaAlternate ( MOC_DSA(hwAccelCtx)
      pSerializedKey, serializedKeyLen, pubPriFlag, &(pAsymKey->key.pDSA), ppVlongQueue);
    goto exit;
  }

  /* We need to decode the alg ID for p, q, and g.
   *   SEQ {
   *     OID
   *     SEQ {
   *       INT p
   *       INT q
   *       INT g }
   */
  status = MAsn1CreateElementArray (
    pTemplate, 7, MASN1_FNCT_DECODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  /* If this fails, it's still possible the data was encoded incrrectly.
   */
  status = MAsn1Decode (pGetAlgId, algIdLen, pArray, &bytesRead);
  if (OK != status)
  {
    status = DecodeDsaAlternate ( MOC_DSA(hwAccelCtx)
      pGetKeyData, keyDataLen, pubPriFlag, &(pAsymKey->key.pDSA), ppVlongQueue);
    goto exit;
  }

  status = DSA_createKey (&pNewKey);
  if (OK != status)
    goto exit;

  /* Decode the key data.
   */
  status = MAsn1Decode (pGetKeyData, keyDataLen, pArray + 6, &bytesRead);
  if (OK != status)
    goto exit;

  /* Now load the data.
   */
  if (1 == pubPriFlag)
  {
    status = DSA_setPublicKeyParameters ( MOC_DSA(hwAccelCtx)
      pNewKey, pArray[3].value.pValue, pArray[3].valueLen,
      pArray[4].value.pValue, pArray[4].valueLen,
      pArray[5].value.pValue, pArray[5].valueLen,
      pArray[6].value.pValue, pArray[6].valueLen, ppVlongQueue);
  }
  else
  {
    status = DSA_setAllKeyParameters ( MOC_DSA(hwAccelCtx)
      pNewKey, pArray[3].value.pValue, pArray[3].valueLen,
      pArray[4].value.pValue, pArray[4].valueLen,
      pArray[5].value.pValue, pArray[5].valueLen,
      pArray[6].value.pValue, pArray[6].valueLen, ppVlongQueue);
  }
  if (OK != status)
    goto exit;

  pAsymKey->key.pDSA = pNewKey;
  pNewKey = NULL;

exit:

  if (OK == status)
  {
    pAsymKey->type = akt_dsa;
  }

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }
  if (NULL != pNewKey)
  {
    DSA_freeKey (&pNewKey, ppVlongQueue);
  }

  return (status);
}

MSTATUS ReadDsaKeyBlob (
  MOC_DSA(hwAccelDescr hwAccelCtx)
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  DSAKey **ppKey,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  DSAKey *pNewKey = NULL;
  ubyte pStart[MOC_DSA_BLOB_START_LEN] = {
    MOC_DSA_BLOB_START
  };

  /* A DSA key blob begins with
   *  pubKey: 00 00 00 00  00 00 00 01  00 00 00 03
   *  priKey: 00 00 00 00  00 00 00 01  00 00 00 03
   */
  status = ERR_INVALID_INPUT;
  if (MOC_DSA_BLOB_START_LEN > serializedKeyLen)
    goto exit;

  status = DIGI_MEMCMP (
    (void *)pSerializedKey, (void *)pStart, MOC_DSA_BLOB_START_LEN, &cmpResult);
  if (OK != status)
    goto exit;

  status = ERR_INVALID_INPUT;
  if (0 != cmpResult)
    goto exit;

  status = DSA_extractKeyBlob ( MOC_DSA(hwAccelCtx)
    &pNewKey, pSerializedKey + MOC_DSA_BLOB_START_LEN,
    serializedKeyLen - MOC_DSA_BLOB_START_LEN);
  if (OK != status)
    goto exit;

  *ppKey = pNewKey;
  pNewKey = NULL;

exit:

  if (NULL != pNewKey)
  {
    DSA_freeKey (&pNewKey, ppVlongQueue);
  }

  return (status);
}

MSTATUS DecodeDsaAlternate (
  MOC_DSA(hwAccelDescr hwAccelCtx)
  ubyte *pKeyData,
  ubyte4 keyDataLen,
  ubyte4 pubPriFlag,
  DSAKey **ppKey,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  ubyte4 bytesRead, pLen, qLen;
  DSAKey *pNewKey = NULL;
  MAsn1Element *pArray = NULL;
  MAsn1TypeAndCount pTemplate[7] = {
    { MASN1_TYPE_SEQUENCE, 6 },
      { MASN1_TYPE_INTEGER, 0 },
      { MASN1_TYPE_INTEGER, 0 },
      { MASN1_TYPE_INTEGER, 0 },
      { MASN1_TYPE_INTEGER, 0 },
      { MASN1_TYPE_INTEGER, 0 },
      { MASN1_TYPE_INTEGER, 0 },
  };

  status = DSA_createKey (&pNewKey);
  if (OK != status)
    goto exit;

  /* If pubPriFlag is 1, do public. If it is 0, try public first.
   */
  if (2 > pubPriFlag)
  {
    pTemplate[0].count = 4;
    status = MAsn1CreateElementArray (
      pTemplate, 5, MASN1_FNCT_DECODE, NULL, &pArray);
    if (OK != status)
      goto exit;

    status = MAsn1Decode (pKeyData, keyDataLen, pArray, &bytesRead);
    if (OK == status)
    {
      pLen = pArray[1].valueLen;
      qLen = pArray[2].valueLen;

      /* These integer values may have a full leading zero on the encoding,
       * we dont want to count that byte when validating the input */
      if ( (0 == pArray[1].value.pValue[0]) && (pLen > 0) )
      {
        pLen--;
      }

      if ( (0 == pArray[2].value.pValue[0]) && (qLen > 0) )
      {
        qLen--;
      }

      /* It's possible the key is RSA, so make sure the lengths make sense.
       * Acceptable lengths for p and q are
       *   128, 20
       *   256, 28
       *   256, 32
       *   384, 32
       */
      if ( ((pLen == 128) && (qLen == 20)) || ((pLen == 256) && (qLen == 28)) ||
        ((pLen == 256) && (qLen == 32)) || ((pLen == 384) && (qLen == 32)) )
      {
        status = DSA_setPublicKeyParameters ( MOC_DSA(hwAccelCtx)
          pNewKey, pArray[1].value.pValue, pArray[1].valueLen,
          pArray[2].value.pValue, pArray[2].valueLen,
          pArray[3].value.pValue, pArray[3].valueLen,
          pArray[4].value.pValue, pArray[4].valueLen, ppVlongQueue);
        if (OK == status)
        {
          *ppKey = pNewKey;
          pNewKey = NULL;
          goto exit;
        }
      }
    }

    /* The decode didn't work. If pubPriFlag is 1, we don't try private, so give
     * up. If it is 0, we'll try the private key.
     */
    if (1 == pubPriFlag)
      goto exit;

    status = MAsn1FreeElementArray (&pArray);
    if (OK != status)
      goto exit;

    pTemplate[0].count = 6;
  }

  status = MAsn1CreateElementArray (
    pTemplate, 7, MASN1_FNCT_DECODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  status = MAsn1Decode (pKeyData, keyDataLen, pArray, &bytesRead);
  if (OK != status)
    goto exit;

  status = ERR_INVALID_INPUT;

  /* These integer values may have a full leading zero on the encoding,
   * we dont want to count that byte when validating the input */
  pLen = pArray[2].valueLen;
  if ( (0 == pArray[2].value.pValue[0]) && (pLen > 0) )
  {
    pLen--;
  }

  qLen = pArray[3].valueLen;
  if ( (0 == pArray[3].value.pValue[0]) && (qLen > 0) )
  {
    qLen--;
  }

  if ( ((pLen == 128) && (qLen == 20)) || ((pLen == 256) && (qLen == 28)) ||
    ((pLen == 256) && (qLen == 32)) || ((pLen == 384) && (qLen == 32)) )
  {
    status = DSA_setAllKeyParameters ( MOC_DSA(hwAccelCtx)
      pNewKey, pArray[2].value.pValue, pArray[2].valueLen,
      pArray[3].value.pValue, pArray[3].valueLen,
      pArray[4].value.pValue, pArray[4].valueLen,
      pArray[6].value.pValue, pArray[6].valueLen, ppVlongQueue);
    if (OK != status)
      goto exit;

    *ppKey = pNewKey;
    pNewKey = NULL;
  }

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }
  if (NULL != pNewKey)
  {
    DSA_freeKey (&pNewKey, ppVlongQueue);
  }

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_DSA__)) */
