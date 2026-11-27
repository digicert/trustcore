/*
 * id.c
 *
 * ASN.1 helpers for keys identified by ID.
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

#include "../../../crypto/mocasymkeys/mocsw/id.h"
#include "../../../asn1/mocasn1.h"

#if defined(__ENABLE_DIGICERT_ASYM_KEY__) && defined(__ENABLE_DIGICERT_SERIALIZE__)

static MSTATUS IdParseUbyte4(MAsn1Element *pElement, ubyte4 *pValue)
{
  ubyte4 i = 0;
  ubyte4 value = 0;

  if (0 == pElement->valueLen || pElement->valueLen > 5 ||
      0 != (pElement->value.pValue[0] & 0x80))
    return ERR_INVALID_INPUT;

  if (5 == pElement->valueLen)
  {
    if (0 != pElement->value.pValue[0] ||
        0 == (pElement->value.pValue[1] & 0x80))
      return ERR_INVALID_INPUT;
    i = 1;
  }
  else if (pElement->valueLen > 1 &&
           0 == pElement->value.pValue[0] &&
           0 == (pElement->value.pValue[1] & 0x80))
  {
    return ERR_INVALID_INPUT;
  }

  for (; i < pElement->valueLen; ++i)
    value = (value << 8) | pElement->value.pValue[i];

  *pValue = value;
  return OK;
}

MSTATUS IdParseAsn1(ubyte *pInput, ubyte4 inputLen, ubyte *pOid, ubyte4 oidLen,
                    ubyte **ppId, ubyte4 *pIdLen, ubyte4 *pTokenId,
                    ubyte4 *pProvider, ubyte4 *pModule)
{
  MSTATUS status = OK;
  sbyte4 cmpResult, isPrivate;
  ubyte4 getAlgIdLen, getKeyDataLen, bytesRead;
  ubyte *pGetAlgId = NULL;
  ubyte *pGetKeyData = NULL;
  MAsn1Element *pArray = NULL;
  ubyte4 provider = 0;
  ubyte4 moduleId = 0;
  ubyte4 tokenId = 0;
  
  /* The privateKeyData is defined as follows:
  * SEQ {
  *   Version version,
  *   Provider provider,
  *   Module moduleId,
  *   Token tokenId,
  *   ObjectId objectId 
  * }
  *
  * where:
  * Version ::= INTEGER { v1(0) } (v1,...)
  * Provider ::= INTEGER
  * Module ::= INTEGER
  * Token ::= INTEGER
  * ObjectId ::= OCTET STRING
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

  if ((NULL == ppId) != (NULL == pIdLen))
    return ERR_NULL_POINTER;

  status = CRYPTO_findKeyInfoComponents (
    pInput, inputLen, &pGetAlgId, &getAlgIdLen,
    &pGetKeyData, &getKeyDataLen, &isPrivate);
  if (OK != status)
    goto exit;

  /* Ensure alg id matches */
  status = ASN1_compareOID (
    pOid, oidLen, pGetAlgId, getAlgIdLen,
    NULL, &cmpResult);
  if (OK != status)
    goto exit;

  if (0 != cmpResult)
  {
    status = ERR_INVALID_INPUT;
    goto exit;
  }

  status = MAsn1CreateElementArray (
    pTemplate, 6, MASN1_FNCT_DECODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  status = MAsn1Decode (pGetKeyData, getKeyDataLen, pArray, &bytesRead);
  if (OK != status)
    goto exit;

  if (NULL != pProvider)
  {
    ubyte4 i = 0;
    if (0 == pArray[2].valueLen || pArray[2].valueLen > 5 ||
        0 != (pArray[2].value.pValue[0] & 0x80))
    {
      status = ERR_INVALID_INPUT;
      goto exit;
    }
    if (5 == pArray[2].valueLen)
    {
      if (0 != pArray[2].value.pValue[0] ||
          0 == (pArray[2].value.pValue[1] & 0x80))
      {
        status = ERR_INVALID_INPUT;
        goto exit;
      }
      i = 1;
    }
    for (; i < pArray[2].valueLen; ++i)
      provider = (provider << 8) | pArray[2].value.pValue[i];

    *pProvider = provider;
  }

  if (NULL != pModule)
  {
    /* Get module ID, at most 4 bytes in length */
    status = IdParseUbyte4(pArray + 3, &moduleId);
    if (OK != status)
      goto exit;
    *pModule = moduleId;
  }

  if (NULL != pTokenId)
  {
    /* Get TokenId, at most 4 bytes in length */
    status = IdParseUbyte4(pArray + 4, &tokenId);
    if (OK != status)
      goto exit;
    *pTokenId = tokenId;
  }

  if(NULL != ppId)
  {
    /* Get the object Id which is already an octet string, need to copy it */
    status = DIGI_MALLOC_MEMCPY((void **) ppId, pArray[5].valueLen, pArray[5].value.pValue, pArray[5].valueLen);
    *pIdLen = pArray[5].valueLen;
  }

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }

  return status;
}

MSTATUS IdCreateAsn1(ubyte4 provider, ubyte4 moduleId, ubyte4 tokenId, ubyte *pOid, ubyte4 oidLen,
                     ubyte *pId, ubyte4 idLen, ubyte **ppOut, ubyte4 *pOutLen)
{
  MSTATUS status = OK;
  ubyte4 encodingLen;
  ubyte *pNewBuf = NULL;
  MAsn1Element *pArray = NULL;

  /* For the Key Id, the privateKeyData is defined as follows:
  * SEQ {
  *   Version version,
  *   Provider provider,
  *   Module moduleId,
  *   Token tokenId,
  *   ObjectId objectId 
  * }
  *
  * where:
  * Version ::= INTEGER { v1(0) } (v1,...)
  * Provider ::= INTEGER
  * Module ::= INTEGER
  * Token ::= INTEGER
  * ObjectId ::= OCTET STRING
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

  /* internal method, null checks not necc */

  status = MAsn1CreateElementArray (
    pTemplate, 6, MASN1_FNCT_ENCODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  /* Set the Version */
  status = MAsn1SetInteger (
    pArray + 1, NULL, 0, TRUE, 0);
  if (OK != status)
    goto exit;

  /* Set the provider */
  status = MAsn1SetInteger (
    pArray + 2, NULL, 0, TRUE, provider);
  if (OK != status)
    goto exit;

  /* Set the module Id */
  status = MAsn1SetInteger (
    pArray + 3, NULL, 0, TRUE, moduleId);
  if (OK != status)
    goto exit;

  /* Set the token Id */
  status = MAsn1SetInteger (
    pArray + 4, NULL, 0, TRUE, tokenId);
  if (OK != status)
    goto exit;

  /* Set the object id */
  status = MAsn1SetValue (
    pArray + 5, pId, idLen);
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

  /* Use this new encoding to build a new key info */
  status = CRYPTO_makeKeyInfo (
    TRUE, pOid, oidLen,
    pNewBuf, encodingLen, ppOut, pOutLen);

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }
  if (NULL != pNewBuf)
  {
    DIGI_FREE ((void **)&pNewBuf);
  }

  return status;
}

MSTATUS IdSerializeKey (
  MKeyOperatorData *pInput, MKeyOperatorDataReturn *pOutput)
{
  MKeyObjectInfo *pInfo;
  ubyte pOid[MOP_TAP_KEY_ID_ALG_ID_LEN] = {MOP_TAP_KEY_ID_ALG_ID};

  if (NULL == pInput || NULL == pInput->pData ||
      NULL == pInput->pAdditionalOpInfo || NULL == pOutput ||
      NULL == pOutput->ppData || NULL == pOutput->pLength)
    return ERR_NULL_POINTER;
  if (0 == pInput->length)
    return ERR_INVALID_INPUT;

  pInfo = (MKeyObjectInfo *) pInput->pAdditionalOpInfo;
  return IdCreateAsn1(pInfo->provider, pInfo->moduleId, pInfo->tokenId,
                      pOid, sizeof(pOid), pInput->pData, pInput->length,
                      pOutput->ppData, pOutput->pLength);
}

MSTATUS IdDeserializeKey (
  MKeyOperatorData *pInput, MKeyObjectInfo *pOutput)
{
  MSTATUS status;
  ubyte *pId = NULL;
  ubyte4 idLen = 0;
  ubyte4 provider = 0;
  ubyte pOid[MOP_TAP_KEY_ID_ALG_ID_LEN] = {MOP_TAP_KEY_ID_ALG_ID};

  if (NULL == pInput || NULL == pInput->pData || NULL == pOutput)
    return ERR_NULL_POINTER;

  status = IdParseAsn1(pInput->pData, pInput->length, pOid, sizeof(pOid),
                       &pId, &idLen, NULL, &provider, NULL);
  if (OK == status && 0 == idLen)
    status = ERR_INVALID_INPUT;
  if (OK == status)
  {
    pOutput->pId = pId;
    pOutput->idLen = idLen;
    pOutput->provider = provider;
  }
  else if (NULL != pId)
  {
    (void) DIGI_MEMSET_FREE(&pId, idLen);
  }
  return status;
}

#endif
