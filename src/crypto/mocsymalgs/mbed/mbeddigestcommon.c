/*
 * mbeddigestcommon.c
 *
 * Common digest functions shared between the Mbed digest operators
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


#if defined(__ENABLE_DIGICERT_MD4_MBED__) || \
    defined(__ENABLE_DIGICERT_MD5_MBED__) || \
    defined(__ENABLE_DIGICERT_SHA1_MBED__) || \
    defined(__ENABLE_DIGICERT_SHA224_MBED__) || \
    defined(__ENABLE_DIGICERT_SHA256_MBED__) || \
    defined(__ENABLE_DIGICERT_SHA384_MBED__) || \
    defined(__ENABLE_DIGICERT_SHA512_MBED__)

#include "../../../crypto/mocsymalgs/mbed/mbeddigestcommon.h"

MSTATUS MbedDigestCreate(
  MocSymCtx pMocSymCtx,
  MSymOperator symOp,
  void *pAssociatedInfo,
  ubyte4 ctxSize,
  ubyte4 localType
  )
{
  MSTATUS status;
  
  void *pCtx = NULL;
  
  /* Ensure the associated info is NULL. None of the digests require any
   * associated info.
   */
  status = ERR_INVALID_ARG;
  if (NULL != pAssociatedInfo)
    goto exit;
  
  /* Allocate memory for the MbedTLS digest context. The size of the context is
   * passed in by the operator.
   */
  status = DIGI_CALLOC(&pCtx, 0x01, ctxSize);
  if (OK != status)
    goto exit;
  
  /* If everything went fine then set the local type, operator, and local data
   */
  pMocSymCtx->localType = localType;
  pMocSymCtx->SymOperator = symOp;
  pMocSymCtx->pLocalData = pCtx;
  
  pCtx = NULL;
  
exit:

  if (NULL != pCtx)
    DIGI_FREE((void **) pCtx);

  return status;
}

MSTATUS MbedDigestInit(
  MocSymCtx pMocSymCtx,
  MbedDigestInitFunc pDigestInit,
  MbedDigestStartFunc pDigestStart
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  int mbedRet;
  
  /* pMocSymCtx already checked for non NULL in operator op method */
  if (NULL == pMocSymCtx->pLocalData)
      goto exit;
  
  /* Call the provided function pointers. These function pointers don't have
   * a return value so assume they succeeded.
   */
  pDigestInit(pMocSymCtx->pLocalData);
  
  status = ERR_MBED_FAILURE;
  mbedRet = pDigestStart(pMocSymCtx->pLocalData);
  if (0 != mbedRet)
    goto exit;
  
  status = OK;
  
exit:

  return status;
}

MSTATUS MbedDigestUpdate(
  MocSymCtx pMocSymCtx,
  MSymOperatorData *pDataToDigest,
  MbedDigestUpdateFunc pDigestUpdate
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  int mbedRet;
  
  /* If the data to digest is NULL but there was a valid length passed in then
   * return ERR_NULL_POINTER, pMocSymCtx already checked for non NULL in operator op method
   */
  if ( NULL == pDataToDigest || (NULL == pDataToDigest->pData && 0 != pDataToDigest->length) ||
       NULL == pMocSymCtx->pLocalData )
    goto exit;
  
  status = ERR_MBED_FAILURE;
  
  /* Call the update function pointer.
   */
  mbedRet = pDigestUpdate(
    pMocSymCtx->pLocalData, pDataToDigest->pData, pDataToDigest->length);
  if (0 != mbedRet)
    goto exit;
  
  status = OK;
  
exit:

  return status;
}

MSTATUS MbedDigestFinal(
  MocSymCtx pMocSymCtx,
  MSymOperatorData *pDataToDigest,
  MSymOperatorBuffer *pDigest,
  MbedDigestUpdateFunc pDigestUpdate,
  MbedDigestFinalFunc pDigestFinal,
  ubyte4 digestLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  int mbedRet;
  ubyte4 bufSize = 0;
  
  /* pMocSymCtx already checked for non NULL in operator op method */
  if (NULL == pMocSymCtx || NULL == pMocSymCtx->pLocalData || NULL == pDigest || NULL == pDigest->pOutputLen)
    goto exit;
    
  if (NULL != pDigest->pBuffer)
    bufSize = pDigest->bufferSize;
  
  /* Check if the buffer that was provided is big enough
   */
  status = ERR_BUFFER_TOO_SMALL;
  *(pDigest->pOutputLen) = digestLen;
  if (digestLen > bufSize)
    goto exit;
    
  *(pDigest->pOutputLen) = 0;
  
  /* Call update to digest (optional) input data, and then final to get the result out.
   */
  if (NULL != pDataToDigest && 0 != pDataToDigest->length)
  {
    status = ERR_NULL_POINTER;
    if (NULL == pDataToDigest->pData)
      goto exit;
    
    status = ERR_MBED_FAILURE;
    mbedRet = pDigestUpdate(
      pMocSymCtx->pLocalData, pDataToDigest->pData, pDataToDigest->length);
    if (0 != mbedRet)
      goto exit;
  }
    
  status = ERR_MBED_FAILURE;
  mbedRet = pDigestFinal(
    pMocSymCtx->pLocalData, pDigest->pBuffer);
  if (0 != mbedRet)
    goto exit;
  
  *(pDigest->pOutputLen) = digestLen;
  status = OK;
  
exit:

  return status;
}

MSTATUS MbedDigestClone(
  MocSymCtx pMocSymCtx,
  MocSymCtx pNewCtx,
  MbedDigestCloneFunc pDigestClone
  )
{
  MSTATUS status;
  
  /* If the local data is NULL then there is nothing to clone. The pNewCtx
   * that is passed in should be NULL from the higher level
   * CRYPTO_cloneMocSymCtx call. pMocSymCtx is already checked to be non NULL.
   */
  status = OK;
  if ( NULL == pMocSymCtx->pLocalData )
    goto exit;
  
  /* If the local data is not NULL, then create the context.
   */
  status = pMocSymCtx->SymOperator(
    pNewCtx, NULL, MOC_SYM_OP_CREATE, NULL, NULL);
  if (OK != status)
    goto exit;
  
  /* Call the clone digest function pointer provided by the caller. Function
   * does not return a status.
   */
  pDigestClone(pNewCtx->pLocalData, pMocSymCtx->pLocalData);
  
exit:

  return status;
}

MSTATUS MbedDigestFree(
  MocSymCtx pMocSymCtx,
  MbedDigestFreeFunc pDigestFree
  )
{
  MSTATUS status;
  
  /* pMocSymCtx already checked for non NULL in the calling op method */
  status = OK;
  if (NULL != pMocSymCtx->pLocalData)
  {
    /* Call the digest function pointer provided by the caller. Again no return
     * status. Note that this will not actually free the context, it will simply
     * memset is to 0.
     */
    pDigestFree(pMocSymCtx->pLocalData);
    
    /* Actually free the data.
     */
    status = DIGI_FREE(&(pMocSymCtx->pLocalData));
  }

  return status;
}
#endif /* IF ENABLE SOME HASH ALGO */
