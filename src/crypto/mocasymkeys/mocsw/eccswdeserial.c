/*
 * eccswdeserial.c
 *
 * Functions to Deserialize ECC keys in software.
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
#include "../../../crypto/mocasym.h"
#include "../../../crypto/mocasymkeys/mocsw/commonasym.h"
#include "../../../crypto/mocasymkeys/mocsw/commonecc.h"

#include "../../../asn1/parseasn1.h"
#include "../../../asn1/mocasn1.h"
#include "../../../crypto/primefld.h"
#include "../../../crypto/ecc.h"
#include "../../../crypto/malgo_id.h"
#include "../../../crypto/pubcrypto.h"
#include "../../../crypto/sec_key.h"

#if  (defined(__ENABLE_DIGICERT_ECC__))


#if  (defined(__ENABLE_DIGICERT_ASYM_KEY__))
MSTATUS EccSwDeserializeKey (
  MOC_ECC(hwAccelDescr hwAccelCtx)
  MocAsymKey pMocAsymKey,
  MKeyOperatorData *pInputInfo,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  MEccSwKeyData *pData = (MEccSwKeyData *)(pMocAsymKey->pKeyData);

  ubyte4 curveId = 0;
  ubyte4 curveIdCheck = 0;
  ubyte *pPriv = NULL;
  ubyte4 privLen = 0;
  ubyte *pPub = NULL;
  ubyte4 pubLen = 0;
  
  /* This function works only if we have a key already and it has Params.
   */
  status = ERR_INVALID_INPUT;
  if (NULL == pData)
    goto exit;

  if ( (NULL == pData->pKey) || (NULL == pData->ParamsCall) )
    goto exit;

  if (0x00 == pInputInfo->pData[0])
  {
    status = ReadEccKeyBlob(pData->ParamsCall, pInputInfo->pData, pInputInfo->length, &curveId, &pPriv, &privLen, &pPub, &pubLen);
    if (OK != status)
      goto exit;  /* 0x00 start is always a Digicert key blob, so go to exit on any error */
  }
  else
  {
    status = DeserializeEccKeyPKCS8X509(pData->ParamsCall, pInputInfo->pData, pInputInfo->length, &curveId, &pPriv, &privLen, &pPub, &pubLen, NULL);

#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
    /* See if it's an Edward's curve key */
    if (OK != status)
    {
      status = DeserializeEccEdKeyPKCS8(pInputInfo->pData, pInputInfo->length, &curveId, &pPriv, &privLen, &pPub, &pubLen);
      if (OK != status)
      {
        status = ERR_EC_DIFFERENT_SERIALIZATION;
      }
    }
#else
    if (OK != status && ERR_EC_DIFFERENT_SERIALIZATION != status)
      goto exit;
#endif
    
    if (ERR_EC_DIFFERENT_SERIALIZATION == status)
    {
      status = DeserializeEccKeyAlt(pData->ParamsCall, pInputInfo->pData, pInputInfo->length, &curveId, &pPub, &pubLen);
      if (OK != status)
        goto exit;
    }
  }

  /* make sure the curveId matches that of the key passed in */
  status = EC_getCurveIdFromKey(pData->pKey, &curveIdCheck);
  if (OK != status)
    goto exit;

  if (curveId != curveIdCheck)
  {
    status = ERR_EC_DIFFERENT_CURVE;
    goto exit;
  }

  status = EC_setKeyParametersEx (MOC_ECC(hwAccelCtx) pData->pKey, pPub, pubLen, pPriv, privLen);

exit:
  
  return status;
}

#endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__)) */

MSTATUS DeserializeEccKeyPKCS8X509 (
  StandardParams Params,
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  ubyte4 *pCurveId,
  ubyte **ppPriv,
  ubyte4 *pPrivLen,
  ubyte **ppPub,
  ubyte4 *pPubLen,
  MAlgoId **ppAlgoId
)
{
  MSTATUS status = ERR_EC_DIFFERENT_SERIALIZATION;
  intBoolean isPrivate = FALSE;
  ubyte4 algIdLen = 0, keyDataLen = 0, oidLen = 0, curveOidLen = 0, bytesRead = 0;
  ubyte *pAlgId = NULL, *pKeyData = NULL, *pOid = NULL, *pCurveOid = NULL;
  sbyte4 cmpResult;

  MAsn1Element *pArray = NULL;

  ubyte pEccOid[MOP_ECC_KEY_OID_LEN] = {
    MOP_ECC_KEY_OID
  };

  MAsn1TypeAndCount pTemplate[5] =
  {
    { MASN1_TYPE_SEQUENCE, 4 },
    { MASN1_TYPE_INTEGER, 0 },
    { MASN1_TYPE_OCTET_STRING, 0 },
    { MASN1_TYPE_OID | MASN1_EXPLICIT | MASN1_OPTIONAL, 0 },
    { MASN1_TYPE_BIT_STRING | MASN1_EXPLICIT | MASN1_OPTIONAL | 1, 0 }
  };

  /* internally used method, NULL checks not necc */

  MOC_UNUSED(Params);

  if ( 0x30 != pSerializedKey[0])
    goto exit;

  /* See if it is PKCS8 or X.509 */
  status = CRYPTO_findKeyInfoComponents (pSerializedKey, serializedKeyLen, &pAlgId, &algIdLen,
                                         &pKeyData, &keyDataLen, &isPrivate);
  if (OK != status)
  {
    /*
     If not P8 or X.509, it might be an alternate encoding.
     It may be just an asn1 encoded private key or a compressed form public key
     We will test for such a private key later in this method and if that's
     not found we'll test for such a public key in DeserializeEccKeyAlt()
     */
    pKeyData = pSerializedKey;
    keyDataLen = serializedKeyLen;
    pAlgId = NULL;
    algIdLen = 0;
    isPrivate = TRUE; /* test for an alternate private key later */
  }

  if (NULL != pAlgId)
  {
    /* This could be a public or private key, which may or may not contain the
     * curve oid in the alg id. If it is not here we will look for it later in
     * the ECPrivateKeyInfo. */
    status = ASN1_parseAlgId (pAlgId, algIdLen, &pOid, &oidLen, &pCurveOid, &curveOidLen);
    if (OK != status)
      goto exit;  /* leave status alone */
  }

  if (NULL != pCurveOid)
  {
    /* Validate now that the the Oid is the correct form 0x06 and its length */
    if ( 0x06 != *pCurveOid || ((ubyte)(curveOidLen - 2) != *(pCurveOid + 1)) )
    {
      status = ERR_INVALID_INPUT;
      goto exit;
    }

    status = ASN1_compareOID (
      pEccOid, MOP_ECC_KEY_OID_LEN, pAlgId, algIdLen, NULL,
      &cmpResult);
    if (OK != status)
      goto exit;

    status = ERR_INVALID_INPUT;
    if (0 != cmpResult)
        goto exit;

    *ppAlgoId = NULL;
    status = ALG_ID_deserializeBuffer(
      ALG_ID_EC_PUBLIC_KEY_OID, pAlgId, algIdLen, ppAlgoId);
    if (OK != status)
      goto exit;

    /* And then the rest of the Oid is what we'll use to determine the curve */
    pCurveOid += 2;
    curveOidLen -= 2;
  }

  /* Do we need to try to decode the private key? */
  if (TRUE == isPrivate)
  {
    status = MAsn1CreateElementArray (pTemplate, 5, MASN1_FNCT_DECODE, NULL, &pArray);
    if (OK != status)
      goto exit;

    status = MAsn1Decode (pKeyData, keyDataLen, pArray, &bytesRead);
    if (OK != status)
      goto exit;
    
    /* Get the curve OID without the 06 len. */
    if (NULL != pArray[3].value.pValue)
    {
      pCurveOid = pArray[3].value.pValue;
      curveOidLen = pArray[3].valueLen;
    }
  }

  /* If we still don't have a curve Oid then we must have a different serialization */
  if (!curveOidLen)
  {
    status = ERR_EC_DIFFERENT_SERIALIZATION;
    goto exit;
  }

  /* Get the curve Id from the Oid */
  status = GetCurveId(pCurveOid, curveOidLen, pCurveId);
  if (OK != status)
    goto exit;  /* leave status alone */

  if (FALSE == isPrivate)
  {
    *ppPub = pKeyData;
    *pPubLen = keyDataLen;
  }
  else
  {
    /* The pub point is part of a BIT STRING, so don't look at the unused bits
     * octet.
     */
    if (NULL != pArray[4].value.pValue)
    {
      *ppPub = pArray[4].value.pValue + 1;
      *pPubLen = pArray[4].valueLen - 1;  /* don't count the bits octet */
    }

    *ppPriv = pArray[2].value.pValue;
    *pPrivLen = pArray[2].valueLen;
  }

exit:

  if ( (OK != status) && (NULL != *ppAlgoId) )
  {
    ALG_ID_free(ppAlgoId);
  }

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }

  return status;
}


MSTATUS DeserializeEccKeyAlt (
  StandardParams Params,
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  ubyte4 *pCurveId,
  ubyte **ppPub,
  ubyte4 *pPubLen
  )
{
  /*
   We determine which curve the (public) key is based on the length.

   NOTE: If future curves are added with the repeated lengths, we will not
   be able to deserialize keys in this manner.
   */

#define PUBKEY_LEN_P192 49
#define PUBKEY_LEN_P224 57
#define PUBKEY_LEN_P256 65
#define PUBKEY_LEN_P384 97
#define PUBKEY_LEN_P521 133

  MSTATUS status = ERR_INVALID_INPUT;

   /* internally used method, NULL checks not necc */

  if ( 0x04 != pSerializedKey[0] )
    goto exit;

  if (PUBKEY_LEN_P192 == serializedKeyLen)
    *pCurveId = cid_EC_P192;
  else if (PUBKEY_LEN_P224 == serializedKeyLen)
    *pCurveId = cid_EC_P224;
  else if (PUBKEY_LEN_P256 == serializedKeyLen)
    *pCurveId = cid_EC_P256;
  else if (PUBKEY_LEN_P384 == serializedKeyLen)
    *pCurveId = cid_EC_P384;
  else if (PUBKEY_LEN_P521 == serializedKeyLen)
    *pCurveId = cid_EC_P521;
  else goto exit;

  status = OK;

  *ppPub = pSerializedKey;
  *pPubLen = serializedKeyLen;

exit:

  return status;
}

static const ubyte pBlobStart[MOC_ECC_BLOB_START_LEN] =
{
  MOC_ECC_BLOB_START
};

MSTATUS ReadEccKeyBlob (
  StandardParams Params,
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  ubyte4 *pCurveId,
  ubyte **ppPriv,
  ubyte4 *pPrivLen,
  ubyte **ppPub,
  ubyte4 *pPubLen
  )
{
  MSTATUS status = ERR_INVALID_INPUT;
  sbyte4 cmpResult;
  ubyte4 bytesLeft;
  ubyte *pCurrent;

  MOC_UNUSED(Params);

  /* internally used method, NULL checks not necc.
   *
   * The key blob is
   *   prefix || curve ID || pubLen || pub point [ || priLen || priVal ]
   * First, make sure there are prefixLen + 8 bytes, so we can read the prefix,
   * curveId, and pubLen.
   */
  status = ERR_INVALID_INPUT;
  if ((MOC_ECC_BLOB_START_LEN + 8) > serializedKeyLen)
    goto exit;

  /* Make sure the prefix is what we expect.
   */
  status = DIGI_MEMCMP (
    (void *)pSerializedKey, (void *)pBlobStart, MOC_ECC_BLOB_START_LEN,
    &cmpResult);
  if (OK != status)
    goto exit;

  status = ERR_INVALID_INPUT;
  if (0 != cmpResult)
    goto exit;

  pCurrent = pSerializedKey + MOC_ECC_BLOB_START_LEN;
  bytesLeft = serializedKeyLen - MOC_ECC_BLOB_START_LEN;

  /* Read the curveId and pubLen.
   */
  *pCurveId = (((ubyte4)pCurrent[0]) << 24) +
              (((ubyte4)pCurrent[1]) << 16) +
              (((ubyte4)pCurrent[2]) <<  8) +
              ((ubyte4)pCurrent[3]);

  *pPubLen = (((ubyte4)pCurrent[4]) << 24) +
             (((ubyte4)pCurrent[5]) << 16) +
             (((ubyte4)pCurrent[6]) <<  8) +
             ((ubyte4)pCurrent[7]);

  /* There should be at least pubLen bytes available.
   * If there are more, there should be at least 4 bytes more.
   */
  pCurrent += 8;
  bytesLeft -= 8;

  if (*pPubLen > bytesLeft)
    goto exit;  /* status still ERR_INVALID_INPUT */

  *ppPriv = NULL;
  *pPrivLen = 0;

  *ppPub = pCurrent;

  if (*pPubLen < bytesLeft)
  {
    /* The next bytes should be the private value. */
    pCurrent += *pPubLen;
    bytesLeft -= *pPubLen;

    if (4 > bytesLeft)
      goto exit;

    *pPrivLen = (((ubyte4)pCurrent[0]) << 24) +
                (((ubyte4)pCurrent[1]) << 16) +
                (((ubyte4)pCurrent[2]) <<  8) +
                ((ubyte4)pCurrent[3]);

    if (bytesLeft < (*pPrivLen + 4))
      goto exit;  /* status still ERR_INVALID_INPUT */

    *ppPriv = pCurrent + 4;
  }

  status = OK;

exit:

  return status;
}

#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
MSTATUS DeserializeEccEdKeyPKCS8 (
  ubyte *pSerializedKey,
  ubyte4 serializedKeyLen,
  ubyte4 *pCurveId,
  ubyte **ppPriv,
  ubyte4 *pPrivLen,
  ubyte **ppPub,
  ubyte4 *pPubLen
  )
{
  MSTATUS status = ERR_EC_DIFFERENT_SERIALIZATION;
  MAsn1Element *pArray = NULL;
  MAsn1Element *pOctetArray = NULL;
  ubyte4 bytesRead = 0;
  ubyte *pOid = NULL;
  ubyte4 oidLen = 0;
  ubyte4 oidIndex = 3;
  ubyte4 pubIndex = 6;
  byteBoolean isExtraParams = TRUE;
  byteBoolean isPriv = TRUE;
  ubyte4 version = 0;
  ubyte *pVerPtr = NULL;
  ubyte4 verLen = 0;

  MAsn1TypeAndCount pTemplate[6] =
  {
    { MASN1_TYPE_SEQUENCE, 4 },
    { MASN1_TYPE_INTEGER, 0 },
    { MASN1_TYPE_SEQUENCE, 1 },
    { MASN1_TYPE_OID, 0 },
    { MASN1_TYPE_OCTET_STRING, 0 }, /* Octet string containing an octet string */
    { MASN1_TYPE_BIT_STRING | MASN1_OPTIONAL | MASN1_IMPLICIT | 1, 0 }
  };
  
  MAsn1TypeAndCount pTemplateWExtra[7] =
  {
    { MASN1_TYPE_SEQUENCE, 5 },
    { MASN1_TYPE_INTEGER, 0 },
    { MASN1_TYPE_SEQUENCE, 1 },
    { MASN1_TYPE_OID, 0 },
    { MASN1_TYPE_OCTET_STRING, 0 }, /* Octet string containing an octet string */
    { MASN1_TYPE_ENCODED | MASN1_EXPLICIT | 0, 0 }, /* extra params */
    { MASN1_TYPE_BIT_STRING | MASN1_OPTIONAL | MASN1_IMPLICIT | 1, 0}
  };
    
  MAsn1TypeAndCount pTemplatePub[4] =
  {
    { MASN1_TYPE_SEQUENCE, 2 },
    { MASN1_TYPE_SEQUENCE, 1 },
    { MASN1_TYPE_OID, 0 },
    { MASN1_TYPE_BIT_STRING, 0 }
  };
  
  MAsn1TypeAndCount pOctetTemplate[1] =
  {
    { MASN1_TYPE_OCTET_STRING, 0 },
  };
  
  /* internally used method, NULL checks not necc */
  
  /* zero output ptrs in case of error */
  *ppPriv = NULL;
  *pPrivLen = 0;
  *ppPub = NULL;
  *pPubLen = 0;
  *pCurveId = 0;
  
  if ( 0x30 != pSerializedKey[0])
    goto exit;

  /* First assume there is extra params */
  status = MAsn1CreateElementArray (pTemplateWExtra, 7, MASN1_FNCT_DECODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  /* Try to decode */
  status = MAsn1Decode (pSerializedKey, serializedKeyLen, pArray, &bytesRead);
  if (OK != status)
  {
    /* Free the array and try with the regular template */
    status = MAsn1FreeElementArray (&pArray);
    if (OK != status)
      goto exit;
    
    status = MAsn1CreateElementArray (pTemplate, 6, MASN1_FNCT_DECODE, NULL, &pArray);
    if (OK != status)
      goto exit;
    
    status = MAsn1Decode (pSerializedKey, serializedKeyLen, pArray, &bytesRead);
    if (OK != status)
    {
      /* And finally try for a public key */
      status = MAsn1FreeElementArray (&pArray);
      if (OK != status)
        goto exit;
      
      status = MAsn1CreateElementArray (pTemplatePub, 4, MASN1_FNCT_DECODE, NULL, &pArray);
      if (OK != status)
        goto exit;
      
      status = MAsn1Decode (pSerializedKey, serializedKeyLen, pArray, &bytesRead);
      if (OK != status)
        goto exit; /* no other choices! go to exit */
      
      isPriv = FALSE;
      oidIndex = 2;
      pubIndex = 3;
    }
    else
    {
      isExtraParams = FALSE;
      pubIndex = 5;
    }
  }
  
  /* Get the Oid in its full encoding */
  
  pOid = pArray[oidIndex].encoding.pEncoding;
  oidLen = pArray[oidIndex].encodingLen;
  
  /* check the encoding, all ED curves have the same oidLen, ok to use EDDH macro */
  if ( 0x06 != *pOid && MOP_ECC_CURVE_EDDH_25519_OID_LEN != oidLen)
  {
    status = ERR_INVALID_INPUT;
    goto exit;
  }
  
  /* now get the value */
  pOid = pArray[oidIndex].value.pValue;
  oidLen = pArray[oidIndex].valueLen;

  /* Get the curve Id from the Oid */
  status = GetCurveId(pOid, oidLen, pCurveId);
  if (OK != status)
    goto exit;

  if (isPriv)
  {
    pVerPtr = pArray[1].value.pValue;
    verLen = pArray[1].valueLen;
    
    /* remove zero padding */
    while ( verLen > 0 && !(*pVerPtr) )
    {
      pVerPtr++;
      verLen--;
    }
    
    /* get the version */
    if (!verLen)
    {
      version = 0;
    }
    else if (1 == verLen && *pVerPtr < 2)
    {
      version = *pVerPtr;
    }
    else
    {
      status = ERR_EC_UNKNOWN_KEY_FILE_VERSION;
      goto exit;
    }
    
    /* get the octet string within the octet string */
    status = MAsn1CreateElementArray (pOctetTemplate, 1, MASN1_FNCT_DECODE, NULL, &pOctetArray);
    if (OK != status)
      goto exit;
    
    status = MAsn1Decode (pArray[4].value.pValue, pArray[4].valueLen, pOctetArray, &bytesRead);
    if (OK != status)
      goto exit;
    
    *ppPriv = pOctetArray[0].value.pValue;
    *pPrivLen = pOctetArray[0].valueLen;
  }
  
  if (NULL != pArray[pubIndex].value.pValue)
  {
    /* version must be 1 for private keys with a public key */
    if (isPriv && 1 != version)
    {
      status = ERR_EC_UNKNOWN_KEY_FILE_VERSION;
      goto exit;
    }
    
    *ppPub = pArray[pubIndex].value.pValue + 1; /* skip the unused bits byte */
    *pPubLen = pArray[pubIndex].valueLen - 1;
  }
  else if (isPriv && version) /* version must be 0 for private keys without a public key */
  {
    status = ERR_EC_UNKNOWN_KEY_FILE_VERSION;
  }
  else if (!isPriv || isExtraParams) /* public key required in these cases */
  {
    status = ERR_INVALID_INPUT;
  }
  
exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }
  
  if (NULL != pOctetArray)
  {
    MAsn1FreeElementArray (&pOctetArray);
  }

  return status;
}
#endif /* __ENABLE_DIGICERT_ECC_EDDSA__ */
#endif /* (defined(__ENABLE_DIGICERT_ECC__)) */
