/*
 * idtapserial.c
 *
 * Serialize the ID of TAP keys.
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../../../crypto/mocasymkeys/tap/idtap.h"
#include "../../../asn1/mocasn1.h"

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_ASYM_KEY__) && defined(__ENABLE_DIGICERT_SERIALIZE__)

#include "../../../crypto_interface/cryptointerface.h"

MSTATUS IdTapCreateAsn1(ubyte4 provider, ubyte4 moduleId, ubyte4 tokenId, ubyte *pOid, ubyte4 oidLen,
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
  * Moduke ::= INTEGER
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

/*----------------------------------------------------------------------------*/

MSTATUS IdTapSerializeKey (
  MKeyOperatorData *pInput,
  MKeyOperatorDataReturn *pOutput
  )
{
  MSTATUS status = ERR_NULL_POINTER, status2 = OK;

  TAP_Context *pTapContext = NULL;
  TAP_EntityCredentialList *pEntityCredentials = NULL;
  TAP_CredentialList *pKeyCredentials = NULL;
  
  TAP_Buffer id = {0};
  ubyte4 provider = 0;
  ubyte4 moduleId = 0;
  MKeyObjectInfo *pObjInfo = NULL;

  ubyte pOid[MOP_TAP_KEY_ID_ALG_ID_LEN] = {MOP_TAP_KEY_ID_ALG_ID};

  if (NULL == pInput || NULL == pOutput || NULL == pInput->pAdditionalOpInfo)
    goto exit;

  pObjInfo = (MKeyObjectInfo *) pInput->pAdditionalOpInfo;
  id.pBuffer = pObjInfo->pId;
  id.bufferLen = pObjInfo->idLen;

  if (NULL == id.pBuffer)
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

  status = TAP_getTapInfo(pTapContext, &provider, &moduleId);
  if (OK != status)
    goto release_tap;

  /* If pObjInfo->provider or pObjInfo->module are set, validate it */
  status = ERR_TAP_INVALID_TAP_PROVIDER;
  if (pObjInfo->provider && pObjInfo->provider != provider)
    goto release_tap;

  status = ERR_TAP_BAD_MODULE_ID;
  if (pObjInfo->moduleId && pObjInfo->moduleId != moduleId)
    goto release_tap;

  status = IdTapCreateAsn1(provider, moduleId, pObjInfo->tokenId, pOid, sizeof(pOid),
                           id.pBuffer, id.bufferLen, pOutput->ppData, pOutput->pLength);

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

  return status;

} /* IdTapSerializeKey */

#endif
