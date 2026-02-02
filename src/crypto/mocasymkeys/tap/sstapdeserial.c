/*
 * sstapdeserial.c
 *
 * Deserialize Secure Storage keys.
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

#include "../../../crypto/mocasymkeys/tap/sstap.h"
#include "../../../asn1/mocasn1.h"

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_ASYM_KEY__) && defined(__ENABLE_DIGICERT_SERIALIZE__)

#include "../../../crypto_interface/cryptointerface.h"

static MSTATUS SSTapParseAsn1(ubyte *pInput, ubyte4 inputLen, TAP_Buffer *pId, ubyte4 *pTokenId, ubyte4 *pProvider, ubyte4 *pModule)
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

  ubyte pAlgId[MOP_SECURE_STORAGE_KEY_ALG_ID_LEN] =
  {
    MOP_SECURE_STORAGE_KEY_ALG_ID
  };
  
  /* For the Secure Storage Key, the privateKeyData is defined as follows:
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

  status = CRYPTO_findKeyInfoComponents (
    pInput, inputLen, &pGetAlgId, &getAlgIdLen,
    &pGetKeyData, &getKeyDataLen, &isPrivate);
  if (OK != status)
    goto exit;

  /* Ensure alg id matches */
  status = ASN1_compareOID (
    pAlgId, MOP_SECURE_STORAGE_KEY_ALG_ID_LEN, pGetAlgId, getAlgIdLen,
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
    /* Get provider, at most 4 bytes in length */
    if (pArray[2].valueLen > 0)
    {
      provider = pArray[2].value.pValue[0];
    }
    if (pArray[2].valueLen > 1)
    {
      provider <<= 8;
      provider |= (pArray[2].value.pValue[1]);
    }
    if (pArray[2].valueLen > 2)
    {
      provider <<= 8;
      provider |= (pArray[2].value.pValue[2]);
    }
    if (pArray[2].valueLen > 3)
    {
      provider <<= 8;
      provider |= (pArray[2].value.pValue[3]);
    }

    *pProvider = provider;
  }

  if (NULL != pModule)
  {
    /* Get provider, at most 4 bytes in length */
    if (pArray[3].valueLen > 0)
    {
      moduleId = pArray[3].value.pValue[0];
    }
    if (pArray[3].valueLen > 1)
    {
      moduleId <<= 8;
      moduleId |= (pArray[3].value.pValue[1]);
    }
    if (pArray[3].valueLen > 2)
    {
      moduleId <<= 8;
      moduleId |= (pArray[3].value.pValue[2]);
    }
    if (pArray[3].valueLen > 3)
    {
      moduleId <<= 8;
      moduleId |= (pArray[3].value.pValue[3]);
    }

    *pModule = moduleId;
  }

  if (NULL != pTokenId)
  {
    /* Get TokenId, at most 4 bytes in length */
    if (pArray[4].valueLen > 0)
    {
      tokenId = pArray[4].value.pValue[0];
    }
    if (pArray[4].valueLen > 1)
    {
      tokenId <<= 8;
      tokenId |= (pArray[4].value.pValue[1]);
    }
    if (pArray[4].valueLen > 2)
    {
      tokenId <<= 8;
      tokenId |= (pArray[4].value.pValue[2]);
    }
    if (pArray[4].valueLen > 3)
    {
      tokenId <<= 8;
      tokenId |= (pArray[4].value.pValue[3]);
    }

    *pTokenId = tokenId;
  }

  if(NULL != pId)
  {
    /* Get the object Id which is already an octet string, need to copy it */
    status = DIGI_MALLOC_MEMCPY((void **) &pId->pBuffer, pArray[5].valueLen, pArray[5].value.pValue, pArray[5].valueLen);
    pId->bufferLen = pArray[5].valueLen;
  }

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }

  return status;
}

/*----------------------------------------------------------------------------*/

MSTATUS SSTapGetTapInfo(
  MKeyOperatorData *pInput,
  MKeyObjectInfo *pTapInfo
)
{
  if (NULL == pInput || NULL == pTapInfo || NULL == pInput->pData)
    return ERR_NULL_POINTER;

  return SSTapParseAsn1(pInput->pData, pInput->length, NULL, NULL, &pTapInfo->provider, &pTapInfo->moduleId);
}

/*----------------------------------------------------------------------------*/

MSTATUS SSTapDeserializeKey (
  MKeyOperatorData *pInput,
  MKeyOperatorDataReturn *pOutput
  )
{
  MSTATUS status = ERR_NULL_POINTER, status2 = OK;

  TAP_Context *pTapContext = NULL;
  TAP_EntityCredentialList *pEntityCredentials = NULL;
  TAP_CredentialList *pKeyCredentials = NULL;
  
  TAP_ErrorContext errContext = {0};
  TAP_ObjectInfo objInfo = {0};

  TAP_Buffer id = {0};  
  ubyte4 tokenId = 0;

  TAP_Buffer recData = {0};

  ubyte4 providerCtx = 0;
  ubyte4 moduleIdCtx = 0;
  ubyte4 provider = 0;
  ubyte4 moduleId = 0;

  if (NULL == pInput || NULL == pOutput || NULL == pInput->pData)
    goto exit;

  status = SSTapParseAsn1(pInput->pData, pInput->length, &id, &tokenId, &provider, &moduleId);
  if (OK != status)
    goto exit;

  if (g_pFuncPtrGetTapContext != NULL)
  {
    if (OK > (status = g_pFuncPtrGetTapContext(&pTapContext,
                                                &pEntityCredentials,
                                                &pKeyCredentials,
                                                NULL, tap_key_store, 1/*get context*/)))
    {
      goto exit;
    }
  }
  else
  {
    status = ERR_NOT_IMPLEMENTED;
    goto exit;
  }

  status = TAP_getTapInfo(pTapContext, &providerCtx, &moduleIdCtx);
  if (OK != status)
    goto release_tap;

  /* validate the key belongs to the correct provider and module */
  status = ERR_TAP_INVALID_TAP_PROVIDER;
  if (provider != providerCtx)
    goto release_tap;
  
  status = ERR_TAP_BAD_MODULE_ID;
  if (moduleId != moduleIdCtx)
    goto release_tap;

  /* We set the object Id as an attribute */
  status = DIGI_MALLOC((void **) &objInfo.objectAttributes.pAttributeList, 1 * sizeof(TAP_Attribute));
  if (OK != status)
    goto release_tap;

  objInfo.objectAttributes.pAttributeList[0].type = TAP_ATTR_OBJECT_ID_BYTESTRING;
  objInfo.objectAttributes.pAttributeList[0].length = sizeof(id);
  objInfo.objectAttributes.pAttributeList[0].pStructOfType = (void *)&id;

  objInfo.objectAttributes.listLen = 1;
  objInfo.tokenId = tokenId;

  status = TAP_getPolicyStorage(pTapContext, pEntityCredentials, &objInfo, NULL, &recData, &errContext);
  if (OK != status)
    goto release_tap;

  *(pOutput->ppData) = recData.pBuffer; recData.pBuffer = NULL;
  *(pOutput->pLength) = recData.bufferLen; recData.bufferLen = 0;

release_tap:

  if (g_pFuncPtrGetTapContext != NULL)
  {
    if (OK > (status2 = g_pFuncPtrGetTapContext(&pTapContext,
                                                &pEntityCredentials,
                                                &pKeyCredentials,
                                                NULL, tap_key_store, 0/* release context*/)))
    {
      if (OK == status)
        status = status2;
    }
  }

exit:

  if (NULL != objInfo.objectAttributes.pAttributeList)
  {
    (void) DIGI_FREE((void **) &objInfo.objectAttributes.pAttributeList);
  }

  if (NULL != recData.pBuffer)
  {
    (void) DIGI_MEMSET_FREE(&recData.pBuffer, recData.bufferLen);
  }

  if (NULL != id.pBuffer)
  {
    (void) DIGI_MEMSET_FREE(&id.pBuffer, id.bufferLen);
  }

  return status;

} /* SSTapDeserializeKey */

#endif
