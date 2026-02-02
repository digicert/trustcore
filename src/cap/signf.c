/*
 * signf.c
 *
 * Mocana Asymmetric Sign and Verify functions.
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
@file       signf.c
@brief      Mocana Asymmetric Sign and Verify functions.
@details    Add details here.

@filedoc    signf.c
*/
#include "../cap/capasym.h"
#include "../common/initmocana.h"

#if (defined(__ENABLE_DIGICERT_ASYM_KEY__))

MOC_EXTERN MSTATUS CRYPTO_asymSignDigest (
  MocAsymKey pKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte4 algorithmDetails,
  void *pAdditionalSignInfo,
  RNGFun RngFun,
  void *pRngFunArg,
  ubyte *pDigest,
  ubyte4 digestLen,
  ubyte *pSignature,
  ubyte4 bufferSize,
  ubyte4 *pSignatureLen,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  MocSubCtx *pSubCtx = NULL;
  MSubCtxOpList *pOpList;
  MKeyAsymSignInfo inputInfo;
  MKeyOperatorBuffer outputInfo;
  MRandomGenInfo randInfo;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKey) || (NULL == pDigest) || (NULL == pSignatureLen) )
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
  inputInfo.pAlgId = pAlgId;
  inputInfo.algIdLen = algIdLen;
  inputInfo.algorithmDetails = algorithmDetails;
  inputInfo.pSymOperators = pOpList->pSymOperators;
  inputInfo.listCount = pOpList->symOperatorCount;
  inputInfo.pAdditionalInfo = pAdditionalSignInfo;
  inputInfo.pRandInfo = &randInfo;
  inputInfo.pData = pDigest;
  inputInfo.length = digestLen;
  outputInfo.pBuffer = pSignature;
  if( NULL != pSignature)
    outputInfo.bufferSize = bufferSize;
  else
    outputInfo.bufferSize = 0;
  outputInfo.pLength = pSignatureLen;

  status = pKey->KeyOperator (
    pKey, pKey->pMocCtx, MOC_ASYM_OP_SIGN_DIGEST, (void *)&inputInfo,
    (void *)&outputInfo, ppVlongQueue);

exit:

  if (NULL != pSubCtx)
  {
    MocReleaseSubCtxRef (&pSubCtx);
  }

  return status;
}

MOC_EXTERN MSTATUS CRYPTO_asymSignDigestInfo (
  MocAsymKey pKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte4 algorithmDetails,
  void *pAdditionalSignInfo,
  RNGFun RngFun,
  void *pRngFunArg,
  ubyte *pDigestInfo,
  ubyte4 digestInfoLen,
  ubyte *pSignature,
  ubyte4 bufferSize,
  ubyte4 *pSignatureLen,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  MocSubCtx *pSubCtx = NULL;
  MSubCtxOpList *pOpList;
  MKeyAsymSignInfo inputInfo;
  MKeyOperatorBuffer outputInfo;
  MRandomGenInfo randInfo;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKey) || (NULL == pDigestInfo) ||
       (NULL == pSignatureLen) )
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
  inputInfo.pAlgId = pAlgId;
  inputInfo.algIdLen = algIdLen;
  inputInfo.algorithmDetails = algorithmDetails;
  inputInfo.pSymOperators = pOpList->pSymOperators;
  inputInfo.listCount = pOpList->symOperatorCount;
  inputInfo.pAdditionalInfo = pAdditionalSignInfo;
  inputInfo.pRandInfo = &randInfo;
  inputInfo.pData = pDigestInfo;
  inputInfo.length = digestInfoLen;
  outputInfo.pBuffer = pSignature;
  if( NULL != pSignature)
    outputInfo.bufferSize = bufferSize;
  else
    outputInfo.bufferSize = 0;
  outputInfo.pLength = pSignatureLen;

  status = pKey->KeyOperator (
    pKey, pKey->pMocCtx, MOC_ASYM_OP_SIGN_DIGEST_INFO, (void *)&inputInfo,
    (void *)&outputInfo, ppVlongQueue);

exit:

  if (NULL != pSubCtx)
  {
    MocReleaseSubCtxRef (&pSubCtx);
  }

  return (status);
}

MOC_EXTERN MSTATUS CRYPTO_asymSignMessage (
  MocAsymKey pKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte4 algorithmDetails,
  void *pAdditionalSignInfo,
  RNGFun RngFun,
  void *pRngFunArg,
  ubyte *pMessage,
  ubyte4 messageLen,
  ubyte *pSignature,
  ubyte4 bufferSize,
  ubyte4 *pSignatureLen,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  MocSubCtx *pSubCtx = NULL;
  MSubCtxOpList *pOpList;
  MKeyAsymSignInfo inputInfo;
  MKeyOperatorBuffer outputInfo;
  MRandomGenInfo randInfo;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKey) || (NULL == pMessage) ||
       (NULL == pSignatureLen) )
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
  inputInfo.pAlgId = pAlgId;
  inputInfo.algIdLen = algIdLen;
  inputInfo.algorithmDetails = algorithmDetails;
  inputInfo.pSymOperators = pOpList->pSymOperators;
  inputInfo.listCount = pOpList->symOperatorCount;
  inputInfo.pAdditionalInfo = pAdditionalSignInfo;
  inputInfo.pRandInfo = &randInfo;
  inputInfo.pData = pMessage;
  inputInfo.length = messageLen;
  outputInfo.pBuffer = pSignature;
  outputInfo.bufferSize = bufferSize;
  outputInfo.pLength = pSignatureLen;

  status = pKey->KeyOperator (
    pKey, pKey->pMocCtx, MOC_ASYM_OP_SIGN_MESSAGE, (void *)&inputInfo,
    (void *)&outputInfo, ppVlongQueue);

exit:

  if (NULL != pSubCtx)
  {
    MocReleaseSubCtxRef (&pSubCtx);
  }

  return (status);
}

MOC_EXTERN MSTATUS CRYPTO_asymVerifyDigest (
  MocAsymKey pKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte4 algorithmDetails,
  void *pAdditionalVfyInfo,
  RNGFun RngFun,
  void *pRngFunArg,
  ubyte *pDigest,
  ubyte4 digestLen,
  ubyte *pSignature,
  ubyte4 signatureLen,
  ubyte4 *pVerifyFailures,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  MocSubCtx *pSubCtx = NULL;
  MSubCtxOpList *pOpList;
  MKeyAsymVerifyInfo inputInfo;
  MRandomGenInfo randInfo;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKey) || (NULL == pDigest) ||
       (NULL == pSignature) || (NULL == pVerifyFailures) )
    goto exit;

  /* Init to this value. If something goes wrong, we know this return will be
   * correct, and if nothing goes wrong, the Operator can change it.
   */
  *pVerifyFailures = MOC_ASYM_VFY_FAIL_INCOMPLETE;

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
  inputInfo.pAlgId = pAlgId;
  inputInfo.algIdLen = algIdLen;
  inputInfo.algorithmDetails = algorithmDetails;
  inputInfo.pSymOperators = pOpList->pSymOperators;
  inputInfo.listCount = pOpList->symOperatorCount;
  inputInfo.pAdditionalVfyInfo = pAdditionalVfyInfo;
  inputInfo.pRandInfo = &randInfo;
  inputInfo.pData = pDigest;
  inputInfo.length = digestLen;
  inputInfo.pSignature = pSignature;
  inputInfo.signatureLen = signatureLen;

  status = pKey->KeyOperator (
    pKey, pKey->pMocCtx, MOC_ASYM_OP_VERIFY_DIGEST, (void *)&inputInfo,
    (void *)pVerifyFailures, ppVlongQueue);

exit:

  if (NULL != pSubCtx)
  {
    MocReleaseSubCtxRef (&pSubCtx);
  }

  return (status);
}


MOC_EXTERN MSTATUS CRYPTO_asymVerifyDigestInfo (
  MocAsymKey pKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte4 algorithmDetails,
  void *pAdditionalVfyInfo,
  RNGFun RngFun,
  void *pRngFunArg,
  ubyte *pDigestInfo,
  ubyte4 digestInfoLen,
  ubyte *pSignature,
  ubyte4 signatureLen,
  ubyte4 *pVerifyFailures,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  MocSubCtx *pSubCtx = NULL;
  MSubCtxOpList *pOpList;
  MKeyAsymVerifyInfo inputInfo;
  MRandomGenInfo randInfo;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKey) || (NULL == pDigestInfo) ||
       (NULL == pSignature) || (NULL == pVerifyFailures) )
    goto exit;

  /* Init to this value. If something goes wrong, we know this return will be
   * correct, and if nothing goes wrong, the Operator can change it.
   */
  *pVerifyFailures = MOC_ASYM_VFY_FAIL_INCOMPLETE;

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
  inputInfo.pAlgId = pAlgId;
  inputInfo.algIdLen = algIdLen;
  inputInfo.algorithmDetails = algorithmDetails;
  inputInfo.pSymOperators = pOpList->pSymOperators;
  inputInfo.listCount = pOpList->symOperatorCount;
  inputInfo.pAdditionalVfyInfo = pAdditionalVfyInfo;
  inputInfo.pRandInfo = &randInfo;
  inputInfo.pData = pDigestInfo;
  inputInfo.length = digestInfoLen;
  inputInfo.pSignature = pSignature;
  inputInfo.signatureLen = signatureLen;

  status = pKey->KeyOperator (
    pKey, pKey->pMocCtx, MOC_ASYM_OP_VERIFY_DIGEST_INFO, (void *)&inputInfo,
    (void *)pVerifyFailures, ppVlongQueue);

exit:

  if (NULL != pSubCtx)
  {
    MocReleaseSubCtxRef (&pSubCtx);
  }

  return (status);
}

MOC_EXTERN MSTATUS CRYPTO_asymVerifyMessage (
  MocAsymKey pKey,
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte4 algorithmDetails,
  void *pAdditionalVfyInfo,
  RNGFun RngFun,
  void *pRngFunArg,
  ubyte *pMessage,
  ubyte4 messageLen,
  ubyte *pSignature,
  ubyte4 signatureLen,
  ubyte4 *pVerifyFailures,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  MocSubCtx *pSubCtx = NULL;
  MSubCtxOpList *pOpList;
  MKeyAsymVerifyInfo inputInfo;
  MRandomGenInfo randInfo;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKey) || (NULL == pMessage) ||
       (NULL == pSignature) || (NULL == pVerifyFailures) )
    goto exit;

  /* Init to this value. If something goes wrong, we know this return will be
   * correct, and if nothing goes wrong, the Operator can change it.
   */
  *pVerifyFailures = MOC_ASYM_VFY_FAIL_INCOMPLETE;

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
  inputInfo.pAlgId = pAlgId;
  inputInfo.algIdLen = algIdLen;
  inputInfo.algorithmDetails = algorithmDetails;
  inputInfo.pSymOperators = pOpList->pSymOperators;
  inputInfo.listCount = pOpList->symOperatorCount;
  inputInfo.pAdditionalVfyInfo = pAdditionalVfyInfo;
  inputInfo.pRandInfo = &randInfo;
  inputInfo.pData = pMessage;
  inputInfo.length = messageLen;
  inputInfo.pSignature = pSignature;
  inputInfo.signatureLen = signatureLen;

  status = pKey->KeyOperator (
    pKey, pKey->pMocCtx, MOC_ASYM_OP_VERIFY_MESSAGE, (void *)&inputInfo,
    (void *)pVerifyFailures, ppVlongQueue);

exit:

  if (NULL != pSubCtx)
  {
    MocReleaseSubCtxRef (&pSubCtx);
  }

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__)) */
