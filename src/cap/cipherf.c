/*
 * cipherf.c
 *
 * Cipher Functions
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

/**
@file       cipherf.c
@brief      Cipher Functions
@details    Add details here.

@filedoc    cipherf.c
*/
#include "../cap/capsym.h"

#if (defined(__ENABLE_DIGICERT_SYM__))

extern MSTATUS CRYPTO_cipherInit (
  MocSymCtx pSymCtx,
  ubyte4 cipherFlag
  )
{
  MSTATUS status;
  symOperation op = MOC_SYM_OP_DECRYPT_INIT;

  status = ERR_NULL_POINTER;
  if (NULL == pSymCtx)
    goto exit;

  if (NULL == pSymCtx->SymOperator)
    goto exit;

  if (MOC_CIPHER_FLAG_DECRYPT != cipherFlag)
    op = MOC_SYM_OP_ENCRYPT_INIT;

  status = pSymCtx->SymOperator (pSymCtx, NULL, op, NULL, NULL);
  if (OK != status)
    goto exit;

  pSymCtx->state = CTX_STATE_INIT;

exit:

  return (status);
}

extern MSTATUS CRYPTO_cipherUpdate (
  MocSymCtx pSymCtx,
  ubyte4 cipherFlag,
  ubyte *pDataToProcess,
  ubyte4 dataToProcessLen,
  ubyte *pProcessedData,
  ubyte4 bufferSize,
  ubyte4 *pProcessedDataLen
  )
{
  MSTATUS status;
  symOperation op = MOC_SYM_OP_DECRYPT_UPDATE;
  MSymOperatorData inputInfo;
  MSymOperatorBuffer outputInfo;

  status = ERR_NULL_POINTER;
  if ( (NULL == pSymCtx) || (NULL == pProcessedDataLen) )
    goto exit;

  if (NULL == pSymCtx->SymOperator)
    goto exit;

  status = ERR_CRYPTO_CTX_STATE;
  if ((CTX_STATE_INIT != pSymCtx->state) &&
      (CTX_STATE_UPDATE != pSymCtx->state))
    goto exit;

  if (MOC_CIPHER_FLAG_DECRYPT != cipherFlag)
    op = MOC_SYM_OP_ENCRYPT_UPDATE;

  inputInfo.pData = pDataToProcess;
  inputInfo.length = 0;
  if (NULL != pDataToProcess)
    inputInfo.length = dataToProcessLen;
  outputInfo.pBuffer = pProcessedData;
  outputInfo.bufferSize = 0;
  if (NULL != pProcessedData)
    outputInfo.bufferSize = bufferSize;
  outputInfo.pOutputLen = pProcessedDataLen;
  status = pSymCtx->SymOperator (
    pSymCtx, NULL, op, (void *)&inputInfo, (void *)&outputInfo);
  if (OK != status)
    goto exit;

  pSymCtx->state = CTX_STATE_UPDATE;

exit:

  return (status);
}

extern MSTATUS CRYPTO_cipherFinal (
  MocSymCtx pSymCtx,
  ubyte4 cipherFlag,
  ubyte *pDataToProcess,
  ubyte4 dataToProcessLen,
  ubyte *pProcessedData,
  ubyte4 bufferSize,
  ubyte4 *pProcessedDataLen
  )
{
  MSTATUS status;
  symOperation op = MOC_SYM_OP_DECRYPT_FINAL;
  MSymOperatorData inputInfo;
  MSymOperatorBuffer outputInfo;

  status = ERR_NULL_POINTER;
  if ( (NULL == pSymCtx) || (NULL == pProcessedDataLen) )
    goto exit;

  if (NULL == pSymCtx->SymOperator)
    goto exit;

  status = ERR_CRYPTO_CTX_STATE;
  if ((CTX_STATE_INIT != pSymCtx->state) &&
      (CTX_STATE_UPDATE != pSymCtx->state))
    goto exit;

  if (MOC_CIPHER_FLAG_DECRYPT != cipherFlag)
    op = MOC_SYM_OP_ENCRYPT_FINAL;

  inputInfo.pData = pDataToProcess;
  inputInfo.length = 0;
  if (NULL != pDataToProcess)
    inputInfo.length = dataToProcessLen;
  outputInfo.pBuffer = pProcessedData;
  outputInfo.bufferSize = 0;
  if (NULL != pProcessedData)
    outputInfo.bufferSize = bufferSize;
  outputInfo.pOutputLen = pProcessedDataLen;
  status = pSymCtx->SymOperator (
    pSymCtx, NULL, op, (void *)&inputInfo, (void *)&outputInfo);
  if (OK != status)
    goto exit;

  pSymCtx->state = CTX_STATE_FINAL;

exit:

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_SYM__)) */
