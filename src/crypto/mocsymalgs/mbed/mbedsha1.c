/*
 * mbedsha1.c
 *
 * Custom Sha1 constants and single transform operations
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


#ifdef __ENABLE_DIGICERT_SHA1_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbedsha1.h"
#include "mbedtls/sha1.h"

#ifndef SHA1_RESULT_SIZE
#define SHA1_RESULT_SIZE 20
#endif

#ifndef SHA1_BLOCK_SIZE
#define SHA1_BLOCK_SIZE 64
#endif

MOC_EXTERN MSTATUS MbedSha1InitCustom(
  MocSymCtx pMocSymCtx,
  MSha1InitData *pInitConsts
  )
{
  mbedtls_sha1_context *pCtx;
  
  /* pMocSymCtx already checked for non NULL in operator op method */
  if (NULL == pMocSymCtx->pLocalData)
    return ERR_NULL_POINTER;
  
  pCtx = (mbedtls_sha1_context *) pMocSymCtx->pLocalData;
  
  mbedtls_sha1_init(pCtx);
  
  /* No choice but to reach inside the mbed context and set the constants directly */
  pCtx->state[0] = pInitConsts->pSha1Consts[0];
  pCtx->state[1] = pInitConsts->pSha1Consts[1];
  pCtx->state[2] = pInitConsts->pSha1Consts[2];
  pCtx->state[3] = pInitConsts->pSha1Consts[3];
  pCtx->state[4] = pInitConsts->pSha1Consts[4];
  
  return OK;
}


MOC_EXTERN MSTATUS MbedSha1RawTransform(
  MocSymCtx pMocSymCtx,
  MSymOperatorData *pInputInfo,
  MSymOperatorBuffer *pOutputInfo
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  int mbedRet;
  ubyte4 bufSize = 0;
  mbedtls_sha1_context *pCtx;
  
  /* If the data to digest is NULL but there was a valid length passed in then
   * return ERR_NULL_POINTER, pMocSymCtx already checked for non NULL in operator op method
   */
  if ( NULL == pInputInfo || NULL == pInputInfo->pData || NULL == pMocSymCtx->pLocalData ||
       NULL == pOutputInfo || NULL == pOutputInfo->pOutputLen  )
    goto exit;
  
  status = ERR_INVALID_INPUT;
  if( SHA1_BLOCK_SIZE != pInputInfo->length)
    goto exit;
  
  if (NULL != pOutputInfo->pBuffer)
    bufSize = pOutputInfo->bufferSize;
  
  /* Check if the buffer that was provided is big enough */
  status = ERR_BUFFER_TOO_SMALL;
  *(pOutputInfo->pOutputLen) = SHA1_RESULT_SIZE;
  if (SHA1_RESULT_SIZE > bufSize)
    goto exit;
  
  *(pOutputInfo->pOutputLen) = 0;

  pCtx = (mbedtls_sha1_context *) pMocSymCtx->pLocalData;
  
  status = ERR_MBED_FAILURE;
  mbedRet = mbedtls_internal_sha1_process(pCtx, pInputInfo->pData);
  if (0 != mbedRet)
    goto exit;
  
  /* No choice but to reach inside the mbed context and get the result directly */
  BIGEND32( pOutputInfo->pBuffer, pCtx->state[0]);
  BIGEND32( pOutputInfo->pBuffer + 4, pCtx->state[1]);
  BIGEND32( pOutputInfo->pBuffer + 8, pCtx->state[2]);
  BIGEND32( pOutputInfo->pBuffer + 12, pCtx->state[3]);
  BIGEND32( pOutputInfo->pBuffer + 16, pCtx->state[4]);
  
  *(pOutputInfo->pOutputLen) = SHA1_RESULT_SIZE;
  status = OK;
  
exit:
  
  return status;
}
#endif /* __ENABLE_DIGICERT_SHA1_MBED__ */
