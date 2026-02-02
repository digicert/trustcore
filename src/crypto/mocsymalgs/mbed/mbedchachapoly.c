/*
 * mbedchachapoly.c
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


#if defined(__ENABLE_DIGICERT_CHACHA20_MBED__) && defined(__ENABLE_DIGICERT_POLY1305_MBED__)

#include "../../../crypto/mocsymalgs/mbed/mbedchachapoly.h"

MOC_EXTERN MSTATUS MChaChaPolyMbedCreate (
  MocSymCtx pCtx,
  sbyte4 *pEncrypt
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MbedChaChaPolyInfo *pNewInfo = NULL;

  if (NULL == pCtx)
    goto exit;

  /* Allocate the outer, wrapper context */
  status = DIGI_CALLOC((void **) &pNewInfo, 1, sizeof(MbedChaChaPolyInfo));
  if (OK != status)
    goto exit;

  if (NULL != pEncrypt)
    pNewInfo->encrypt = *pEncrypt;

  pCtx->pLocalData = pNewInfo;
  pCtx->localType = MOC_LOCAL_TYPE_CHACHAPOLY_OPERATOR;
  pCtx->SymOperator = SymOperatorChaChaPoly;

  pNewInfo = NULL;

exit:

  if (NULL != pNewInfo)
  {
     DIGI_FREE((void **) &pNewInfo); /* ok to ignore return, only here on error */
  }

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MChaChaPolyMbedUpdateInfo (
  MocSymCtx pCtx,
  MChaChaUpdateData *pInput
  )
{
  MSTATUS status;
  MbedChaChaPolyInfo *pInfo = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pCtx) || (NULL == pCtx->pLocalData) || (NULL == pInput))
    goto exit;

  pInfo = (MbedChaChaPolyInfo *) pCtx->pLocalData;

  if (pInput->nonce.length && NULL == pInput->nonce.pData)
    goto exit;

  if (NULL != pInput->nonce.pData)
  {
    /* check the nonceLen before continuing */
    status = ERR_CHACHA20_BAD_NONCE_LENGTH;
    if (CHACHA20_NONCE_LEN != pInput->nonce.length)
      goto exit;

    /* copy the nonce to the pInfo. we don't call mbedtls_chachapoly_starts until an INIT op code is called */
    status = DIGI_MEMCPY(pInfo->pNonce, pInput->nonce.pData, CHACHA20_NONCE_LEN);
    goto exit;  /* Done, we can't be updating nonce and aad simultaneously */
  }

  if (pInput->aad.length && NULL == pInput->aad.pData)
    goto exit; /* status still ERR_NULL_POINTER */

  if (pInput->aad.length)
  {
    int mbedStatus;

    if (NULL == pInfo->pAeadCtx)
      goto exit; /* status still ERR_NULL_POINTER */

    /* we call mbedtls_chachapoly_update_aad right away, no temp storing of the aad needed */
    status = ERR_MBED_CHACHAPOLY_UPDATE_AAD_FAIL;
    mbedStatus = mbedtls_chachapoly_update_aad(pInfo->pAeadCtx, pInput->aad.pData, pInput->aad.length);
    if (OK != mbedStatus)
      goto exit;
  } /* else ok no-op */

  status = OK;

exit:

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MChaChaPolyMbedLoadKey (
  MocSymCtx pCtx,
  MSymOperatorData *pKeyData
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MbedChaChaPolyInfo *pInfo = NULL;
  mbedtls_chachapoly_context *pNewCtx = NULL;
  byteBoolean isAllocated = FALSE;
  int mbedStatus;

  if ( (NULL == pCtx) || (NULL == pCtx->pLocalData) || (NULL == pKeyData) )
    goto exit;

  pInfo = (MbedChaChaPolyInfo *) pCtx->pLocalData;

  status = ERR_CHACHA20_BAD_KEY_LENGTH;
  if (CHACHA20_KEY_LEN != pKeyData->length)
    goto exit;

  pNewCtx = pInfo->pAeadCtx;

  /* If this is the first call to loadKey, allocate an inner
   * mbedtls_chacha20_context.  If not, just zeroize it */
  if (NULL == pNewCtx)
  {
    status = DIGI_MALLOC((void **) &pNewCtx, sizeof(mbedtls_chachapoly_context));
    if (OK != status)
      goto exit;

    isAllocated = TRUE;
  }

  mbedtls_chachapoly_init(pNewCtx);

  status = ERR_MBED_CHACHAPOLY_SETKEY_FAIL;
  mbedStatus = mbedtls_chachapoly_setkey(pNewCtx, pKeyData->pData);
  if (OK != mbedStatus)
    goto exit;

  pInfo->pAeadCtx = pNewCtx;
  pNewCtx = NULL;

  status = OK;

exit:

  if (isAllocated && NULL != pNewCtx)
  {
    mbedtls_chachapoly_free(pNewCtx);
    DIGI_FREE((void **) &pNewCtx); /* ok to ignore return, here only on error */
  }

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MChaChaPolyMbedInit (
  MocSymCtx pCtx
  )
{
  MSTATUS status;
  MbedChaChaPolyInfo *pInfo = NULL;
  int mbedStatus;

  status = ERR_NULL_POINTER;
  if ( (NULL == pCtx) || (NULL == pCtx->pLocalData) )
    goto exit;

  pInfo = (MbedChaChaPolyInfo *) pCtx->pLocalData;

  if (NULL == pInfo->pAeadCtx)
    goto exit;

  status = ERR_MBED_CHACHAPOLY_START_FAIL;
  mbedStatus = mbedtls_chachapoly_starts(pInfo->pAeadCtx, pInfo->pNonce,
                                         pInfo->encrypt ? MBEDTLS_CHACHAPOLY_ENCRYPT : MBEDTLS_CHACHAPOLY_DECRYPT);
  if (OK != mbedStatus)
    goto exit;

  status = OK;

exit:

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MChaChaPolyMbedUpdate (
  MocSymCtx pCtx,
  MSymOperatorData *pInput,
  MSymOperatorBuffer *pOutput
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  int mbedStatus;
  MbedChaChaPolyInfo *pInfo = NULL;
  mbedtls_chachapoly_context *pAeadCtx = NULL;

  if (NULL == pCtx || NULL == pCtx->pLocalData || NULL == pInput || NULL == pOutput || NULL == pOutput->pOutputLen)
    goto exit;

  pInfo = (MbedChaChaPolyInfo *) pCtx->pLocalData;

  pAeadCtx = pInfo->pAeadCtx;
  if (NULL == pAeadCtx)
    goto exit;

  /* Check to see if the output buffer is large enough.  pOutput->pOutputLen
   * will be set to the proper length in any case. */
  status = ERR_BUFFER_TOO_SMALL;
  *(pOutput->pOutputLen) = pInput->length;
  if (pOutput->bufferSize < pInput->length)
    goto exit;

  *(pOutput->pOutputLen) = 0;

  status = ERR_MBED_CHACHAPOLY_UPDATE_FAIL;
  mbedStatus = mbedtls_chachapoly_update(
    pAeadCtx, (size_t) pInput->length, (const unsigned char *) pInput->pData,
    pOutput->pBuffer);
  if (OK != mbedStatus)
    goto exit;

  *(pOutput->pOutputLen) = pInput->length;

  status = OK;

exit:

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MChaChaPolyMbedFinal (
  MocSymCtx pCtx,
  MSymOperatorData *pInput,
  MSymOperatorBuffer *pOutput
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  int mbedStatus;
  MbedChaChaPolyInfo *pInfo = NULL;
  mbedtls_chachapoly_context *pAeadCtx = NULL;

  if (NULL == pCtx || NULL == pCtx->pLocalData)
    goto exit;

  pInfo = (MbedChaChaPolyInfo *) pCtx->pLocalData;

  pAeadCtx = pInfo->pAeadCtx;
  if (NULL == pAeadCtx)
    goto exit;

  if (pInfo->encrypt)
  {
    if (NULL == pOutput || NULL == pOutput->pOutputLen)
      goto exit;  /* status still ERR_NULL_POINTER */

    status = ERR_CHACHA20_BAD_TAG_LENGTH;
    if (CHACHAPOLY_TAG_LEN != pOutput->bufferSize)
      goto exit;

    status = ERR_MBED_CHACHAPOLY_FINISH_FAIL;
    mbedStatus = mbedtls_chachapoly_finish(pAeadCtx, pOutput->pBuffer);
    if (OK != mbedStatus)
      goto exit;

    *(pOutput->pOutputLen) = CHACHAPOLY_TAG_LEN;
  }
  else
  {
    ubyte pTag[CHACHAPOLY_TAG_LEN];
    sbyte4 res;

    if (NULL == pInput || NULL == pInput->pData)
      goto exit; /* status still ERR_NULL_POINTER */

    status = ERR_CHACHA20_BAD_TAG_LENGTH;
    if (CHACHAPOLY_TAG_LEN != pInput->length)
      goto exit;

    /* get the tag */
    status = ERR_MBED_CHACHAPOLY_FINISH_FAIL;
    mbedStatus = mbedtls_chachapoly_finish(pAeadCtx, pTag);
    if (OK != mbedStatus)
      goto exit;

    /* verify the tag */
    status = DIGI_CTIME_MATCH(pTag, pInput->pData, CHACHAPOLY_TAG_LEN, &res);
    if (OK != status)
      goto exit;

    /* zero out the copy of the tag, no need to check return code */
    DIGI_MEMSET(pTag, 0x00, CHACHAPOLY_TAG_LEN);

    if (0 != res)
    {
      status = ERR_CRYPTO_AEAD_FAIL;
      goto exit;
    }
  }

  status = OK;

exit:

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MChaChaPolyMbedFree (
  MocSymCtx pCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MbedChaChaPolyInfo *pInfo = NULL;

  if (NULL == pCtx)
    goto exit;

  pInfo = (MbedChaChaPolyInfo *) pCtx->pLocalData;

  status = OK;
  if (NULL != pInfo)
  {
    MSTATUS fstatus;

    if (NULL != pInfo->pAeadCtx)
    {
      mbedtls_chachapoly_free (pInfo->pAeadCtx);
      status = DIGI_FREE ((void **) &(pInfo->pAeadCtx));
    }

    fstatus = DIGI_MEMSET ((ubyte *) pInfo, 0x00, sizeof (MbedChaChaPolyInfo));
    if (OK == status)
      status = fstatus;

    fstatus = DIGI_FREE ((void **) &pInfo);
    if (OK == status)
      status = fstatus;

    /* NULL the context's pointer too */
    pCtx->pLocalData = NULL;
  }

exit:

  return status;
}

/*----------------------------------------------------------------------------*/

MSTATUS MChaChaPolyMbedClone(
    MocSymCtx pCtx,
    MocSymCtx pCopyCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MbedChaChaPolyInfo *pInfo = NULL;
    MbedChaChaPolyInfo *pNewInfo = NULL;
    void *pNewCtx = NULL;

    if ( (NULL == pCtx) || (NULL == pCtx->pLocalData) || (NULL == pCopyCtx) )
        goto exit;

    pInfo = (MbedChaChaPolyInfo *)pCtx->pLocalData;

    /* Allocate the info shell */
    status = DIGI_CALLOC((void **) &pNewInfo, 1, sizeof(MbedChaChaPolyInfo));
    if (OK != status)
        goto exit;

    /* Copy the info shell */
    status = DIGI_MEMCPY((void *)pNewInfo, (void *)pInfo, sizeof(MbedChaChaPolyInfo));
    if (OK != status)
        goto exit;

    /* Allocate the underlying MBED context */
    status = DIGI_MALLOC((void **)&pNewCtx, sizeof(mbedtls_chachapoly_context));
    if (OK != status)
        goto exit;

    /* Copy the underlying MBED context data */
    status = DIGI_MEMCPY (
        pNewCtx, (void *)pInfo->pAeadCtx, sizeof(mbedtls_chachapoly_context));
    if (OK != status)
        goto exit;

    pNewInfo->pAeadCtx = pNewCtx;
    pCopyCtx->pLocalData = (void *)pNewInfo;
    pNewCtx = NULL;
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

#endif /* defined(__ENABLE_DIGICERT_CHACHA20_MBED__) && defined(__ENABLE_DIGICERT_POLY1305_MBED__) */
