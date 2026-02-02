/*
 * rsatapload.c
 *
 * Load and free RSA info in a TAP object.
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

#include "../../../crypto/mocasymkeys/tap/rsatap.h"

#ifdef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
#include "../../../crypto_interface/cryptointerface.h"
#endif

#if defined(__ENABLE_DIGICERT_ASYM_KEY__) && defined(__ENABLE_DIGICERT_TAP__)

MSTATUS RsaTapLoadKeyData (
  TAP_Key **ppNewKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  MocSymCtx *ppDigestCtx,
  MocAsymKey pMocAsymKey
  )
{
  MSTATUS status = OK;
  MRsaTapKeyData *pNewData = NULL;
  MRsaTapKeyData *pData = (MRsaTapKeyData *)(pMocAsymKey->pKeyData);

  if (NULL == pData)
  {
    status = DIGI_CALLOC (
      (void **)&pNewData, 1, sizeof(MRsaTapKeyData));
    if (OK != status)
      goto exit;

    /* pNewData->isDeferUnload is already FALSE from the CALLOC above */
    pData = pNewData;
    pMocAsymKey->pKeyData = (void *)pNewData;
    pNewData = NULL;
  }

  if (NULL != ppNewKey)
  {
    if (NULL != *ppNewKey)
    {
      if (NULL != pData->pKey)
      {
         TAP_freeKey(&(pData->pKey));
      }

      pData->pKey = *ppNewKey;
      *ppNewKey = NULL;
    }
  }

  status = LoadCommonKeyData (
    pMocAsymKey, pAlgId, algIdLen, ppDigestCtx);

exit:

  if (NULL != pNewData)
  {
    DIGI_FREE ((void **)&pNewData);
  }

  return status;
}

/*----------------------------------------------------------------------------*/

MSTATUS RsaTapFreeKey (
  MocAsymKey pMocAsymKey
  )
{
  MSTATUS status, fStatus;
  MRsaTapKeyData *pKeyData;
#ifdef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
  TAP_CredentialList *pKeyCredentials = NULL;
  TAP_EntityCredentialList *pEntityCredentials = NULL;
  TAP_Context *pTapContext = NULL;
  TAP_Key *pTapKey = NULL;
  TAP_ErrorContext errContext = {0};
  TAP_ErrorContext *pErrContext = &errContext;
#endif

  /* Anything to free? */
  status = OK;
  if (NULL == pMocAsymKey)
    goto exit;
  if (NULL == pMocAsymKey->pKeyData)
    goto exit;

  status = FreeCommonKeyData (pMocAsymKey);

  pKeyData = (MRsaTapKeyData *)(pMocAsymKey->pKeyData);

  /* The caller may have overwritten or modified internal data
   * during prior callback execution so let them have the first shot
   * at freeing this data up through the callback */
  if (NULL != pKeyData->Callback)
  {
    fStatus = pKeyData->Callback (
      pMocAsymKey->pMocCtx, MOC_ASYM_OP_FREE, (void *)pKeyData);
    if (OK == status)
      status = fStatus;
  }

  if (NULL != pKeyData->pKey)
  {
#ifdef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
    pTapKey = (TAP_Key *)pKeyData->pKey;
    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status = g_pFuncPtrGetTapContext(&pTapContext,
                        &pEntityCredentials,
                        &pKeyCredentials,
                        (void *)pMocAsymKey, tap_rsa_sign, 1/*get context*/)))
        {
            goto exit;
        }
    }
    else
    {
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
    }

    if (!pKeyData->isKeyLoaded)
    {
        status = TAP_loadKey(pTapContext, pEntityCredentials, pTapKey, pKeyCredentials, NULL, pErrContext);
        if (OK != status)
            goto exit;

        pKeyData->isKeyLoaded = TRUE;
    }
#endif

    fStatus = TAP_freeKey (&(pKeyData->pKey));
    if (OK == status)
      status = fStatus;
  }

  fStatus = DIGI_FREE (&(pMocAsymKey->pKeyData));
  if (OK == status)
    status = fStatus;

exit:
#ifdef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
  if (g_pFuncPtrGetTapContext != NULL)
  {
      g_pFuncPtrGetTapContext(&pTapContext,
                      &pEntityCredentials,
                      &pKeyCredentials,
                      (void *)pMocAsymKey, tap_rsa_sign, 0/*release context*/);
  }
#endif
  return status;
}

/*----------------------------------------------------------------------------*/

MSTATUS RsaTapGetPubFromPri (
  MocAsymKey pMocAsymKey,
  MocAsymKey *ppPubKey,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  MocAsymKey pNewPub = NULL;
  MRsaTapKeyData *pData = (MRsaTapKeyData *)(pMocAsymKey->pKeyData);

  status = ERR_NULL_POINTER;
  if ( (NULL == pData) || (NULL == ppPubKey) )
    goto exit;

  /* Create an empty MocAsymKey shell */
  status = DIGI_CALLOC((void **)&pNewPub, 1, sizeof(MocAsymmetricKey));
  if (OK != status)
    goto exit;

  if (NULL != pMocAsymKey->pMocCtx)
  {
    /* Acquire a reference to the MocCtx. This is necessary because when freeing
     * the new public key the reference count for the MocCtx it has a pointer to
     * will be decremented. If we dont acquire a reference here then the count
     * will be off which would likely lead to the MocCtx being freed to early. */
    status = AcquireMocCtxRef(pMocAsymKey->pMocCtx);
    if (OK != status)
      goto exit;
  }

  /* This public key only has references to the local data of the private key */
  pNewPub->KeyOperator = KeyOperatorRsaTap;
  pNewPub->pMocCtx = pMocAsymKey->pMocCtx;
  pNewPub->pKeyData = pMocAsymKey->pKeyData;
  pNewPub->localType = MOC_LOCAL_KEY_RSA_PUB_TAP;

  *ppPubKey = pNewPub;
  pNewPub = NULL;

exit:

  if (NULL != pNewPub)
  {
    DIGI_FREE((void **)&pNewPub);
  }

  return status;
}

#endif
