/*
 * rsaswdeserial.c
 *
 * Deserialize RSA keys using an object with MRsaSwKeyData as pKey.
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
#include "../../../asn1/mocasn1.h"
#include "../../../crypto/malgo_id.h"
#include "../../../crypto/pubcrypto.h"
#include "../../../crypto/keyblob.h"

#ifndef __DISABLE_DIGICERT_RSA__


MSTATUS DeserializeRsaKey (
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
  ubyte4 flag, bytesRead, algIdLen, keyDataLen, keyType, version;
  ubyte *pGetAlgId, *pGetKeyData;
  RSAKey *pNewKey = NULL;
  MAlgoId *pAlgoId = NULL;

  ubyte pRsaOid[MOP_RSA_P1_ENC_OID_LEN] = {
    MOP_RSA_P1_ENC_OID
  };

  ubyte pRsaPssOid[MOP_RSA_PSS_OID_LEN] = {
    MOP_RSA_PSS_OID
  };

  /* Use the same template for both pub and pri, using OPTIONAL to "cheat".
   */
  MAsn1Element *pArray = NULL;
  MAsn1TypeAndCount pTemplate[10] = {
    { MASN1_TYPE_SEQUENCE, 9 },
      { MASN1_TYPE_INTEGER, 0 },
      { MASN1_TYPE_INTEGER, 0 },
      { MASN1_TYPE_INTEGER | MASN1_OPTIONAL, 0 },
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

  /* If the first byte is 0, this should be a blob.
   */
  if (0 == pSerializedKey[0])

  {
    status = KEYBLOB_parseHeader(pSerializedKey, serializedKeyLen, &keyType, &version);
    if (OK != status)
        goto exit;

    status = ERR_BAD_KEY_BLOB;
    if ( (akt_rsa != keyType) && (akt_rsa_pss != keyType) )
    {
        goto exit;
    }

    status = KEYBLOB_extractKeyBlobEx(pSerializedKey, serializedKeyLen, pAsymKey);
    goto exit;
  }

  status = RSA_createKey (&pNewKey);
  if (OK != status)
    goto exit;

  /* DER decode the key.
   * Init flag to 0, meaning the data is not P8 or X.509
   */
  flag = 0;

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
    /* If this worked, check if it is an RSA ENC key algo.
     */
    status = ASN1_compareOID (
      pRsaOid, MOP_RSA_P1_ENC_OID_LEN, pGetAlgId, algIdLen, NULL,
      &cmpResult);
    if (OK != status)
      goto exit;

    if (0 == cmpResult)
    {
        /* If compare succeeds, deserialize as an RSA ENC key */
        status = ALG_ID_deserializeBuffer(
            ALG_ID_RSA_ENC_OID, pGetAlgId, algIdLen, &pAlgoId);
        if (OK != status)
            goto exit;
    }
    else
    {
        /* If compare fails, check if it is a RSA PSS key algo.
         */
        status = ASN1_compareOID (
          pRsaPssOid, MOP_RSA_PSS_OID_LEN, pGetAlgId, algIdLen, NULL,
          &cmpResult);
        if (OK != status)
          goto exit;

        status = ERR_INVALID_INPUT;
        if (0 != cmpResult)
            goto exit;

        status = ALG_ID_deserializeBuffer(
            ALG_ID_RSA_SSA_PSS_OID, pGetAlgId, algIdLen, &pAlgoId);
        if (OK != status)
            goto exit;

    }
    status = CRYPTO_loadAlgoId(pAsymKey, (void **) &pAlgoId);
    if (OK != status)
        goto exit;

    flag = 1;
  }
  else
  {
    /* If this didn't work, it is possible the data is PKCS 1 data.
     */
    pGetKeyData = pSerializedKey;
    keyDataLen = serializedKeyLen;
  }

  /* Decode the actual key data.
   * If public
   *   SEQ {
   *     INT modulus,
   *     INT pubExpo }
   *
   * If private
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
  status = MAsn1CreateElementArray (
    pTemplate, 10, MASN1_FNCT_DECODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  status = MAsn1Decode (pGetKeyData, keyDataLen, pArray, &bytesRead);
  if (OK != status)
    goto exit;

  /* If we have a private key, make sure that is OK.
   */
  status = ERR_INVALID_INPUT;
  if (NULL != pArray[9].value.pValue)
  {
    /* If isPrivate is FALSE, that could be because the key was X.509 (public) or
     * it wasn't X.509 or P8.
     * If X.509, this is an error. WE know it's X.509 if flag is not 0.
     */
    if ( (FALSE == isPrivate) && (0 != flag) )
      goto exit;

    isPrivate = TRUE;
  }
  else
  {
    /* The data is not complete RSA private. Make sure we are expecting public.
     */
    if (FALSE != isPrivate)
      goto exit;
  }

  /* If isPrivate is TRUE, we know the data was P8, try only that.
   * If isPrivate is FALSE, either the data is X.509 or neither. Either way, try
   * public first.
   */
  if (FALSE == isPrivate)
  {
    status = RSA_setPublicKeyData ( MOC_RSA(hwAccelCtx)
      pNewKey, pArray[2].value.pValue, pArray[2].valueLen,
      pArray[1].value.pValue, pArray[1].valueLen, ppVlongQueue);
    if (OK != status)
      goto exit;

    pAsymKey->key.pRSA = pNewKey;
    pNewKey = NULL;
    goto exit;
  }

  /* If we reach this point, the key is private.
   */
  /* Make sure the first INTEGER is 0.
   */
  status = ERR_INVALID_INPUT;
  if ( (1 != pArray[1].valueLen) || (0 != pArray[1].value.pValue[0]) )
    goto exit;

  /* Load the key data.
   */
  status = RSA_setAllKeyData ( MOC_RSA(hwAccelCtx)
    pNewKey, pArray[3].value.pValue, pArray[3].valueLen,
    pArray[2].value.pValue, pArray[2].valueLen,
    pArray[5].value.pValue, pArray[5].valueLen,
    pArray[6].value.pValue, pArray[6].valueLen, ppVlongQueue);
  if (OK != status)
    goto exit;

  pAsymKey->key.pRSA = pNewKey;
  pNewKey = NULL;

exit:

  if (OK == status)
  {
    /* TO DO eventually we should set type to akt_rsa_pss for pss keys, for legacy we leave type akt_rsa 
       and the caller can use the pAsymKey->pAlgoId to determine if its PSS */
    pAsymKey->type = akt_rsa;
  }

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }
  if (NULL != pNewKey)
  {
    RSA_freeKey (&pNewKey, ppVlongQueue);
  }

  return (status);
}

MSTATUS ReadRsaKeyBlob (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  RSAKey **ppKey,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  RSAKey *pNewKey = NULL;
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
   * First, make sure the leading bytes are there.
   */
  status = ERR_INVALID_INPUT;
  if (MOC_RSA_BLOB_START_LEN > serializedKeyLen)
    goto exit;

  status = DIGI_MEMCMP (
    (void *)pSerializedKey, (void *)pStart, MOC_RSA_BLOB_START_LEN, &cmpResult);
  if (OK != status)
    goto exit;

  status = ERR_INVALID_INPUT;
  if (0 != cmpResult)
    goto exit;

  status = RSA_keyFromByteString ( MOC_RSA(hwAccelCtx)
    &pNewKey, pSerializedKey + MOC_RSA_BLOB_START_LEN,
    serializedKeyLen - MOC_RSA_BLOB_START_LEN, ppVlongQueue);
  if (OK != status)
    goto exit;

  *ppKey = pNewKey;
  pNewKey = NULL;

exit:

  if (NULL != pNewKey)
  {
    RSA_freeKey (&pNewKey, ppVlongQueue);
  }

  return (status);
}

#endif /* __DISABLE_DIGICERT_RSA__ */
