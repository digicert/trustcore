/*
 * ecctapload.c
 *
 * Load and free ECC info in an object with MEccTapKeyData as pKey.
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

#include "../../../crypto/mocasymkeys/tap/ecctap.h"

#ifdef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
#include "../../../crypto_interface/cryptointerface.h"
#endif

#if defined(__ENABLE_DIGICERT_ASYM_KEY__) && \
    defined(__ENABLE_DIGICERT_ECC__) && \
    defined(__ENABLE_DIGICERT_TAP__)

MSTATUS EccTapLoadKeyData (
  TAP_Key **ppNewKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  MocSymCtx *ppDigestCtx,
  StandardParams paramsCall,
  MocAsymKey pMocAsymKey
  )
{
  MSTATUS status;
  MEccTapKeyData *pNewData = NULL;
  MEccTapKeyData *pData = (MEccTapKeyData *)(pMocAsymKey->pKeyData);

#ifdef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
  TAP_CredentialList *pKeyCredentials = NULL;
  TAP_EntityCredentialList *pEntityCredentials = NULL;
  TAP_Context *pTapContext = NULL;
  TAP_Key *pTapKey = NULL;
  TAP_ErrorContext errContext = {0};
  TAP_ErrorContext *pErrContext = &errContext;
#endif

  if (NULL == pData)
  {
    status = DIGI_CALLOC (
      (void **)&pNewData, 1, sizeof(MEccTapKeyData));
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
#ifdef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
        pTapKey = (TAP_Key *)pData->pKey;
        if (g_pFuncPtrGetTapContext != NULL)
        {
          if (OK > (status = g_pFuncPtrGetTapContext(&pTapContext,
                          &pEntityCredentials,
                          &pKeyCredentials,
                          (void *)pMocAsymKey, tap_ecc_sign, 1/*get context*/)))
          {
            goto exit;
          }
        }
        else
        {
          status = ERR_NOT_IMPLEMENTED;
          goto exit;
        }

        if (!pData->isKeyLoaded)
        {
          status = TAP_loadKey(pTapContext, pEntityCredentials, pTapKey, pKeyCredentials, NULL, pErrContext);
          if (OK != status)
              goto exit;

          pData->isKeyLoaded = TRUE;
        }
#endif

        TAP_freeKey(&(pData->pKey));
      }

      pData->pKey = *ppNewKey;
      *ppNewKey = NULL;
    }
  }

  status = LoadCommonKeyData (
    pMocAsymKey, pAlgId, algIdLen, ppDigestCtx);

exit:

#ifdef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
  if (g_pFuncPtrGetTapContext != NULL)
  {
      g_pFuncPtrGetTapContext(&pTapContext,
                      &pEntityCredentials,
                      &pKeyCredentials,
                      (void *)pMocAsymKey, tap_ecc_sign, 0/*release context*/);
  }
#endif

  if (NULL != pNewData)
  {
    DIGI_FREE ((void **)&pNewData);
  }

  return status;
}

/*----------------------------------------------------------------------------*/

MSTATUS EccTapFreeKey (
  MocAsymKey pMocAsymKey
  )
{
  MSTATUS status, fStatus;
  MEccTapKeyData *pKeyData;

#ifdef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
  TAP_CredentialList *pKeyCredentials = NULL;
  TAP_EntityCredentialList *pEntityCredentials = NULL;
  TAP_Context *pTapContext = NULL;
  TAP_Key *pTapKey = NULL;
  TAP_ErrorContext errContext = {0};
  TAP_ErrorContext *pErrContext = &errContext;
#endif

  /* Anything to free?
   */
  status = OK;
  if (NULL == pMocAsymKey)
    goto exit;
  if (NULL == pMocAsymKey->pKeyData)
    goto exit;

  status = FreeCommonKeyData (pMocAsymKey);

  pKeyData = (MEccTapKeyData *)(pMocAsymKey->pKeyData);

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
                      (void *)pMocAsymKey, tap_ecc_sign, 1/*get context*/)))
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
                      (void *)pMocAsymKey, tap_ecc_sign, 0/*release context*/);
  }
#endif

  return (status);

} /* EccTapFreeKey */

/*----------------------------------------------------------------------------*/

MSTATUS EccTapGetPubFromPri (
  MocAsymKey pMocAsymKey,
  MocAsymKey *ppPubKey
  )
{
  MSTATUS status;
  MocAsymKey pNewPub = NULL;

  status = ERR_NULL_POINTER;
  if ((NULL == pMocAsymKey) || (NULL == ppPubKey) ||
      (NULL == pMocAsymKey->pKeyData))
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
  pNewPub->KeyOperator = KeyOperatorEccTap;
  pNewPub->pMocCtx = pMocAsymKey->pMocCtx;
  pNewPub->pKeyData = pMocAsymKey->pKeyData;
  pNewPub->localType = MOC_LOCAL_KEY_ECC_PUB_TAP | MOC_LOCAL_KEY_P256;

  *(ppPubKey) = pNewPub;
  pNewPub = NULL;

exit:

  if (NULL != pNewPub)
  {
    DIGI_FREE((void **)&pNewPub);
  }

  return status;

} /* EccTapGetPubFromPri */

#endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__)) etc */
