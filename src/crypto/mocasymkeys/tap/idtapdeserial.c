/*
 * idtapdeserial.c
 *
 * Deserialize keys by TAP ID.
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

#include "../../../crypto/mocasymkeys/tap/idtap.h"
#include "../../../crypto/mocasymkeys/mocsw/id.h"
#include "../../../asn1/mocasn1.h"

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_ASYM_KEY__) && defined(__ENABLE_DIGICERT_SERIALIZE__)

#include "../../../crypto_interface/cryptointerface.h"

MSTATUS IdTapGetTapInfo(
  MKeyOperatorData *pInput,
  MKeyObjectInfo *pTapInfo,
  byteBoolean isSS
)
{
  ubyte pOidKeyId[MOP_TAP_KEY_ID_ALG_ID_LEN] = {MOP_TAP_KEY_ID_ALG_ID};
  ubyte pOidKeySS[MOP_SECURE_STORAGE_KEY_ALG_ID_LEN] = {MOP_SECURE_STORAGE_KEY_ALG_ID};
  ubyte *pOid = (ubyte *) (isSS ? pOidKeySS : pOidKeyId);
  ubyte4 oidLen = isSS ? MOP_SECURE_STORAGE_KEY_ALG_ID_LEN : MOP_TAP_KEY_ID_ALG_ID_LEN;

  if (NULL == pInput || NULL == pTapInfo || NULL == pInput->pData)
    return ERR_NULL_POINTER;

  return IdParseAsn1(pInput->pData, pInput->length, pOid, oidLen,
                     NULL, NULL, NULL, &pTapInfo->provider, &pTapInfo->moduleId);
}

/*----------------------------------------------------------------------------*/

MSTATUS IdTapDeserializeKey (
  MKeyOperatorData *pInput,
  MKeyOperatorDataReturn *pOutput
  )
{
  MSTATUS status = ERR_NULL_POINTER, status2 = OK;

  TAP_Context *pTapContext = NULL;
  TAP_EntityCredentialList *pEntityCredentials = NULL;
  TAP_CredentialList *pKeyCredentials = NULL;
  
  TAP_Buffer id = {0};  
  ubyte4 tokenId = 0;

  ubyte4 providerCtx = 0;
  ubyte4 moduleIdCtx = 0;
  ubyte4 provider = 0;
  ubyte4 moduleId = 0;

  ubyte pOid[MOP_TAP_KEY_ID_ALG_ID_LEN] = {MOP_TAP_KEY_ID_ALG_ID};

  if (NULL == pInput || NULL == pOutput || NULL == pInput->pData)
    goto exit;

  status = IdParseAsn1(pInput->pData, pInput->length, pOid, sizeof(pOid),
                       &id.pBuffer, &id.bufferLen, &tokenId, &provider, &moduleId);
  if (OK != status)
    goto exit;

  /* Validate the provider and moduleId match */
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

  *(pOutput->ppData) = id.pBuffer; id.pBuffer = NULL;
  *(pOutput->pLength) = id.bufferLen; id.bufferLen = 0;

  status = OK;

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

  if (NULL != id.pBuffer)
  {
    (void) DIGI_MEMSET_FREE(&id.pBuffer, id.bufferLen);
  }

  return status;

} /* IdTapDeserializeKey */

#endif
