/*
 * mbedchacha20.c
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

#include "../../../crypto/mocsym.h"


#ifdef __ENABLE_DIGICERT_CHACHA20_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbedchacha20.h"

MOC_EXTERN MSTATUS MChaCha20MbedCreate (
  MocSymCtx pCtx,
  MChaChaUpdateData *pInput
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MbedChaChaInfo *pNewCtx = NULL;

  if (NULL == pCtx)
    goto exit;

  /* Allocate the outer, wrapper context */
  status = DIGI_CALLOC((void **) &pNewCtx, 1, sizeof(MbedChaChaInfo));
  if (OK != status)
    goto exit;

  pCtx->pLocalData = pNewCtx;

  if (NULL != pInput)
  {
    status = MChaCha20MbedUpdateInfo(pCtx, pInput);
    if (OK != status)
      goto exit;
  }

  pCtx->localType = MOC_LOCAL_TYPE_CHACHA20_OPERATOR;
  pCtx->SymOperator = SymOperatorChaCha20;

  pNewCtx = NULL;

exit:

  if (NULL != pNewCtx)
  {
     DIGI_FREE((void **) &pNewCtx); /* ok to ignore return, only here on error */
  }
    
  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MChaCha20MbedUpdateInfo (
  MocSymCtx pCtx,
  MChaChaUpdateData *pInput
  )
{
  MSTATUS status;
  MbedChaChaInfo *pInfo = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pCtx) || (NULL == pCtx->pLocalData) || (NULL == pInput) )
    goto exit;

  pInfo = (MbedChaChaInfo *) pCtx->pLocalData;

  if ( (NULL != pInput->nonce.pData) && (0 != pInput->nonce.length) )
  {
    status = ERR_CHACHA20_BAD_NONCE_LENGTH;
    if (CHACHA20_NONCE_LEN != pInput->nonce.length)
      goto exit;

    status = DIGI_MEMCPY(pInfo->pNonce, pInput->nonce.pData, CHACHA20_NONCE_LEN);
    if (OK != status)
      goto exit;

    pInfo->nonceLen = CHACHA20_NONCE_LEN;
  }

  pInfo->counter = pInput->counter;

  status = OK;

exit:

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MChaCha20MbedLoadKey (
  MocSymCtx pCtx,
  MSymOperatorData *pKeyData
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MbedChaChaInfo *pInfo = NULL;

  if ( (NULL == pCtx) || (NULL == pCtx->pLocalData) || (NULL == pKeyData) )
    goto exit;

  pInfo = (MbedChaChaInfo *) pCtx->pLocalData;

  status = ERR_CHACHA20_BAD_KEY_LENGTH;
  if (CHACHA20_KEY_LEN != pKeyData->length)
    goto exit;

  pInfo->keyLen = 0;

  status = DIGI_MEMCPY(
    pInfo->pKey, pKeyData->pData, pKeyData->length);
  if (OK != status)
    goto exit;

  pInfo->keyLen = pKeyData->length;

exit:

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MChaCha20MbedInit (
  MocSymCtx pCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MbedChaChaInfo *pInfo = NULL;
  mbedtls_chacha20_context *pNewCtx = NULL;
  int mbedStatus;
  byteBoolean isAllocated = FALSE;

  if ( (NULL == pCtx) || (NULL == pCtx->pLocalData) )
    goto exit;

  pInfo = (MbedChaChaInfo *) pCtx->pLocalData;
  pNewCtx = pInfo->pMbedChaChaCtx;

  status = ERR_CHACHA20_BAD_KEY_LENGTH;
  if (CHACHA20_KEY_LEN != pInfo->keyLen)
    goto exit;

  status = ERR_CHACHA20_BAD_NONCE_LENGTH;
  if (CHACHA20_NONCE_LEN != pInfo->nonceLen)
    goto exit;

  /* If this is the first call to init(), allocate an inner
   * mbedtls_chacha20_context.  If not, just zeroize it */
  if (NULL == pNewCtx)
  {
    status = DIGI_MALLOC((void **) &pNewCtx, sizeof(mbedtls_chacha20_context));
    if (OK != status)
      goto exit;
      
    isAllocated = TRUE;
  }

  mbedtls_chacha20_init(pNewCtx);

  status = ERR_MBED_CHACHA20_SETKEY_FAIL;
  mbedStatus = mbedtls_chacha20_setkey(pNewCtx, pInfo->pKey);
  if (OK != mbedStatus)
    goto exit;

  status = ERR_MBED_CHACHA20_START_FAIL;
  mbedStatus = mbedtls_chacha20_starts(
    pNewCtx, pInfo->pNonce, (uint32_t) pInfo->counter);
  if (OK != mbedStatus)
    goto exit;

  pInfo->pMbedChaChaCtx = pNewCtx;
  pNewCtx = NULL;
  status = OK;

exit:

  if (isAllocated && NULL != pNewCtx)
  {
    mbedtls_chacha20_free(pNewCtx);
    DIGI_FREE((void **) &pNewCtx); /* ok to ignore return, here only on error */
  }

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MChaCha20MbedUpdate (
  MocSymCtx pCtx,
  MSymOperatorData *pInput,
  MSymOperatorBuffer *pOutput
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  int mbedStatus;
  MbedChaChaInfo *pInfo = NULL;
  mbedtls_chacha20_context *pChaChaCtx = NULL;

  if (NULL == pCtx || NULL == pCtx->pLocalData || NULL == pInput || NULL == pOutput || NULL == pOutput->pOutputLen)
    goto exit;

  pInfo = (MbedChaChaInfo *) pCtx->pLocalData;
    
  pChaChaCtx = pInfo->pMbedChaChaCtx;
  if (NULL == pChaChaCtx)
    goto exit;

  /* Check to see if the output buffer is large enough.  pOutput->pOutputLen
   * will be set to the proper length in any case. */
  status = ERR_BUFFER_TOO_SMALL;
  *(pOutput->pOutputLen) = pInput->length;
  if (pOutput->bufferSize < pInput->length)
    goto exit;

  *(pOutput->pOutputLen) = 0;

  status = ERR_MBED_CHACHA20_UPDATE_FAIL;
  mbedStatus = mbedtls_chacha20_update(
    pChaChaCtx, (size_t) pInput->length, (const unsigned char *) pInput->pData,
    pOutput->pBuffer);
  if (OK != mbedStatus)
    goto exit;

  *(pOutput->pOutputLen) = pInput->length;

  status = OK;

exit:

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MChaCha20MbedFree (
  MocSymCtx pCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MbedChaChaInfo *pInfo = NULL;

  if (NULL == pCtx)
    goto exit;
    
  pInfo = (MbedChaChaInfo *) pCtx->pLocalData;
    
  status = OK;
  if (NULL != pInfo)
  {
    MSTATUS fstatus;
      
    if (NULL != pInfo->pMbedChaChaCtx)
    {
      mbedtls_chacha20_free (pInfo->pMbedChaChaCtx);
      status = DIGI_FREE ((void **) &(pInfo->pMbedChaChaCtx));
    }
        
    fstatus = DIGI_MEMSET ((ubyte *) pInfo, 0x00, sizeof (MbedChaChaInfo));
    if (OK == status)
      status = fstatus;
    
    fstatus = DIGI_FREE ((void **) &pInfo);
    if (OK == status)
      status = fstatus;
      
    /* don't forget to NULL the context's copy of the ptr */
    pCtx->pLocalData = NULL;
  }

exit:
  
  return status;
}

#endif /* ifdef __ENABLE_DIGICERT_CHACHA20_MBED__ */
