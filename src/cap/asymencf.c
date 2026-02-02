/*
 * asymencf.c
 *
 * Asymmetric Key Encryption functions.
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
@file       asymencf.c
@brief      Mocana Asymmetric Key Encryption functions.
@details    Add details here.

@filedoc    asymencf.c
*/
#include "../cap/capasym.h"
#include "../common/initmocana.h"

#if (defined(__ENABLE_DIGICERT_ASYM_KEY__))

/* Common code. Encrypt and decrypt are the same, except for the keyOp.
 */
MSTATUS AsymProcess (
  keyOperation keyOp,
  MocAsymKey pKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte4 algorithmDetails,
  void *pAdditionalInfo,
  RNGFun RngFun,
  void *pRngFunArg,
  ubyte *pDataToProcess,
  ubyte4 dataToProcessLen,
  ubyte *pProcessedData,
  ubyte4 bufferSize,
  ubyte4 *pProcessedDataLen,
  struct vlong **ppVlongQueue
  );

extern MSTATUS CRYPTO_asymEncrypt (
  MocAsymKey pKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte4 algorithmDetails,
  void *pAdditionalEncryptInfo,
  RNGFun RngFun,
  void *pRngFunArg,
  ubyte *pDataToEncrypt,
  ubyte4 dataToEncryptLen,
  ubyte *pEncryptedData,
  ubyte4 bufferSize,
  ubyte4 *pEncryptedDataLen,
  struct vlong **ppVlongQueue
  )
{
  return (AsymProcess (
    MOC_ASYM_OP_ENCRYPT, pKey, pAlgId, algIdLen, algorithmDetails,
    pAdditionalEncryptInfo, RngFun, pRngFunArg, pDataToEncrypt, dataToEncryptLen,
    pEncryptedData, bufferSize, pEncryptedDataLen, ppVlongQueue));
}

MOC_EXTERN MSTATUS CRYPTO_asymDecrypt (
  MocAsymKey pKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte4 algorithmDetails,
  void *pAdditionalDecryptInfo,
  RNGFun RngFun,
  void *pRngFunArg,
  ubyte *pDataToDecrypt,
  ubyte4 dataToDecryptLen,
  ubyte *pDecryptedData,
  ubyte4 bufferSize,
  ubyte4 *pDecryptedDataLen,
  struct vlong **ppVlongQueue
  )
{
  return (AsymProcess (
    MOC_ASYM_OP_DECRYPT, pKey, pAlgId, algIdLen, algorithmDetails,
    pAdditionalDecryptInfo, RngFun, pRngFunArg, pDataToDecrypt, dataToDecryptLen,
    pDecryptedData, bufferSize, pDecryptedDataLen, ppVlongQueue));
}

MSTATUS AsymProcess (
  keyOperation keyOp,
  MocAsymKey pKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte4 algorithmDetails,
  void *pAdditionalInfo,
  RNGFun RngFun,
  void *pRngFunArg,
  ubyte *pDataToProcess,
  ubyte4 dataToProcessLen,
  ubyte *pProcessedData,
  ubyte4 bufferSize,
  ubyte4 *pProcessedDataLen,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  MocSubCtx *pSubCtx = NULL;
  MSubCtxOpList *pOpList;
  MKeyAsymEncryptInfo inputData;
  MKeyOperatorBuffer outputData;
  MRandomGenInfo randInfo;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKey) || (NULL == pDataToProcess) ||
       (NULL == pProcessedDataLen) )
    goto exit;

  status = ERR_INVALID_ARG;
  if (NULL == pKey->KeyOperator)
    goto exit;

  status = MocAcquireSubCtxRef (
    pKey->pMocCtx, MOC_SUB_CTX_TYPE_OP_LIST, &pSubCtx);
  if (OK != status)
    goto exit;

  pOpList = (MSubCtxOpList *)(pSubCtx->pLocalCtx);

  randInfo.RngFun = RngFun;
  randInfo.pRngFunArg = pRngFunArg;
  inputData.pAlgId = pAlgId;
  inputData.algIdLen = algIdLen;
  inputData.algorithmDetails = algorithmDetails;
  inputData.pSymOperators = pOpList->pSymOperators;
  inputData.listCount = pOpList->symOperatorCount;
  inputData.pAdditionalInfo = pAdditionalInfo; 
  inputData.pRandInfo = &randInfo;
  inputData.pData = pDataToProcess;
  inputData.length = dataToProcessLen;
  outputData.pBuffer = pProcessedData;
  outputData.bufferSize = 0;
  if (NULL != pProcessedData)
    outputData.bufferSize = bufferSize;
  outputData.pLength = pProcessedDataLen;

  status = pKey->KeyOperator (
    pKey, pKey->pMocCtx, keyOp, (void *)&inputData,
    (void *)&outputData, ppVlongQueue);

exit:

  if (NULL != pSubCtx)
  {
    MocReleaseSubCtxRef (&pSubCtx);
  }

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__)) */
