/*
 * mbedpoly1305.c
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


#ifdef __ENABLE_DIGICERT_POLY1305_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbedpoly1305.h"


/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MPoly1305MbedFreeData (
  MbedPolyInfo **ppCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == ppCtx)
    goto exit;

  status = OK;
  if (NULL != *ppCtx)
  {
    MSTATUS fstatus;
    
    /* Free the Poly1305 context using the mbedtls API */
    if (NULL != (*ppCtx)->pPolyCtx)
    {
      mbedtls_poly1305_free((*ppCtx)->pPolyCtx);
      status = DIGI_FREE((void **)(&((*ppCtx)->pPolyCtx)));
    }

    /* Clear out and free the key data */
    fstatus = DIGI_MEMSET((*ppCtx)->pKey, 0x00, MOC_POLY1305_KEY_LEN);
    if (OK == status)
      status = fstatus;

    /* Free the shell */
    fstatus = DIGI_FREE((void **) ppCtx);
    if (OK == status)
      status = fstatus;
  }

exit:

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MPoly1305MbedCreate (
  MocSymCtx pSymCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MbedPolyInfo *pNewCtx = NULL;

  if (NULL == pSymCtx)
    goto exit;
  
  /* Create the Poly1305 context and attempt to set it up. */
  status = DIGI_CALLOC((void **) &pNewCtx, 1, sizeof(MbedPolyInfo));
  if (OK != status)
    goto exit;

  /* Allocate the inner mbedtls context */
  status = DIGI_MALLOC(
    (void **) &(pNewCtx->pPolyCtx), sizeof(mbedtls_poly1305_context));
  if (OK != status)
    goto exit;

  pSymCtx->localType = MOC_LOCAL_TYPE_POLY1305_OPERATOR;
  pSymCtx->SymOperator = SymOperatorPoly1305;
  pSymCtx->pLocalData = (void *) pNewCtx;

  pNewCtx = NULL;

  status = OK;

exit:

  if (NULL != pNewCtx)
    MPoly1305MbedFreeData(&pNewCtx); /* ok to ignore return, only here on error */

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MPoly1305MbedLoadKey(
  MocSymCtx pSymCtx,
  MSymOperatorData *pKeyData
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MbedPolyInfo *pCtx = NULL;

  if ( (NULL == pKeyData ) || (NULL == pKeyData->pData) || (NULL == pSymCtx) ||
       (NULL == pSymCtx->pLocalData) )
    goto exit;

  pCtx = (MbedPolyInfo *) pSymCtx->pLocalData;

  status = ERR_BAD_LENGTH;
  if (MOC_POLY1305_KEY_LEN != pKeyData->length)
    goto exit;

  /* If there is already a key in the context, memset it to 0 */
  status = DIGI_MEMSET(pCtx->pKey, 0x00, pKeyData->length);
  if (OK != status)
    goto exit;

  /* Store the provided key within the context */
  status = DIGI_MEMCPY(pCtx->pKey, pKeyData->pData, pKeyData->length);
  if (OK != status)
    goto exit;

  pCtx->keyLen = pKeyData->length;

exit:

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MPoly1305MbedInit(
  MocSymCtx pSymCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  int mbedStatus;
  MbedPolyInfo *pCtx = NULL;

  if ( (NULL == pSymCtx) || (NULL == pSymCtx->pLocalData) )
    goto exit;

  pCtx = (MbedPolyInfo *) pSymCtx->pLocalData;

  status = ERR_BAD_LENGTH;
  if (MOC_POLY1305_KEY_LEN != pCtx->keyLen)
    goto exit;

  mbedtls_poly1305_init(pCtx->pPolyCtx);

  /* Attempt to load the key data into the context */
  status = ERR_MBED_POLY1305_START_FAIL;
  mbedStatus = mbedtls_poly1305_starts (pCtx->pPolyCtx, pCtx->pKey);
  if (OK != mbedStatus)
    goto exit;

  status = OK;

exit:

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MPoly1305MbedUpdate (
  MocSymCtx pSymCtx,
  MSymOperatorData *pInput
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  int mbedStatus;
  MbedPolyInfo *pCtx = NULL;

  if ( (NULL == pSymCtx) || (NULL == pSymCtx->pLocalData) || (NULL == pInput) )
    goto exit;

  pCtx = (MbedPolyInfo *) pSymCtx->pLocalData;

  status = ERR_MBED_POLY1305_UPDATE_FAIL;
  mbedStatus = mbedtls_poly1305_update(
    pCtx->pPolyCtx, pInput->pData, pInput->length);
  if (OK != mbedStatus)
    goto exit;

  status = OK;

exit:

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MPoly1305MbedFinal (
  MocSymCtx pSymCtx,
  MSymOperatorData *pInput,
  MSymOperatorBuffer *pOutput
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  int mbedStatus;
  MbedPolyInfo *pCtx = NULL;

  if ( (NULL == pSymCtx) || (NULL == pSymCtx->pLocalData) ||
       (NULL == pOutput) || (NULL == pOutput->pOutputLen) || (NULL == pInput) )
    goto exit;

  pCtx = (MbedPolyInfo *) pSymCtx->pLocalData;

  status = ERR_BUFFER_TOO_SMALL;
  *(pOutput->pOutputLen) = MOC_POLY1305_MAC_LEN;
  if (MOC_POLY1305_MAC_LEN > pOutput->bufferSize)
    goto exit;

  *(pOutput->pOutputLen) = 0;

  status = MPoly1305MbedUpdate(pSymCtx, pInput);
  if (OK != status)
    goto exit;

  status = ERR_MBED_POLY1305_FINISH_FAIL;
  mbedStatus = mbedtls_poly1305_finish(pCtx->pPolyCtx, pOutput->pBuffer);
  if (OK != mbedStatus)
    goto exit;

  *(pOutput->pOutputLen) = MOC_POLY1305_MAC_LEN;

  status = OK;

exit:

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MPoly1305MbedFree (
  MocSymCtx pSymCtx
  )
{
  if (NULL == pSymCtx)
    return ERR_NULL_POINTER;

  return MPoly1305MbedFreeData((MbedPolyInfo **) &(pSymCtx->pLocalData));
}

/*----------------------------------------------------------------------------*/


MOC_EXTERN MSTATUS MPoly1305MbedClone(
    MocSymCtx pCtx,
    MocSymCtx pCopyCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MbedPolyInfo *pInfo = NULL;
    MbedPolyInfo *pNewInfo = NULL;
    mbedtls_poly1305_context *pNewCtx = NULL;

    if ( (NULL == pCtx) || (NULL == pCtx->pLocalData) || (NULL == pCopyCtx) )
        goto exit;

    pInfo = (MbedPolyInfo *)pCtx->pLocalData;

    /* Allocate the info shell */
    status = DIGI_CALLOC((void **) &pNewInfo, 1, sizeof(MbedPolyInfo));
    if (OK != status)
        goto exit;

    /* Copy the info shell */
    status = DIGI_MEMCPY((void *)pNewInfo, (void *)pInfo, sizeof(MbedPolyInfo));
    if (OK != status)
        goto exit;

    if (NULL != pInfo->pPolyCtx)
    {
        /* Allocate the underlying MBED context */
        status = DIGI_MALLOC((void **)&pNewCtx, sizeof(mbedtls_poly1305_context));
        if (OK != status)
            goto exit;

        /* Copy the underlying MBED context data */
        status = DIGI_MEMCPY (
            pNewCtx, (void *)pInfo->pPolyCtx, sizeof(mbedtls_poly1305_context));
        if (OK != status)
            goto exit;

        pNewInfo->pPolyCtx = pNewCtx;
        pNewCtx = NULL;
    }

    pCopyCtx->pLocalData = (void *)pNewInfo;
    pNewInfo = NULL;

exit:
    if (NULL != pNewInfo)
    {
        DIGI_FREE((void **)&pNewInfo);
    }
    if (NULL != pNewCtx)
    {
        DIGI_FREE((void **)&pNewCtx);
    }

    return status;
}


#endif
