/*
 * mocsym.c
 *
 * MocSym Context Functions.
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
@file       mocsym.c
@brief      MocSym Context Functions.
@details    Add details here.

@filedoc    mocsym.c
*/
#include "../cap/capsym.h"
#include "../common/initmocana.h"

#if (defined(__ENABLE_DIGICERT_SYM__))

/* See cryptoInterfaceSymAlgo for ordering */
MOC_EXTERN_DATA_DEF const ubyte4 pSupportedSymAlgos[MOC_NUM_SUPPORTED_SYM_ALGOS] =
{
  MOC_DIGEST_ALG_MD2,
  MOC_DIGEST_ALG_MD4,
  MOC_DIGEST_ALG_MD5,
  MOC_DIGEST_ALG_SHA1,
  MOC_DIGEST_ALG_SHA224,
  MOC_DIGEST_ALG_SHA256,
  MOC_DIGEST_ALG_SHA384,
  MOC_DIGEST_ALG_SHA512,
  MOC_SYM_ALG_AES,
  MOC_SYM_ALG_AES_ECB,
  MOC_SYM_ALG_AES_CBC,
  MOC_SYM_ALG_AES_CFB,
  MOC_SYM_ALG_AES_CFB1,
  MOC_SYM_ALG_AES_OFB,
  MOC_SYM_ALG_AES_CTR,
  MOC_SYM_ALG_AES_GCM,
  MOC_SYM_ALG_AES_CCM,
  MOC_SYM_ALG_AES_XTS,
  MOC_SYM_ALG_AES_EAX,
  MOC_SYM_ALG_DES,
  MOC_SYM_ALG_DES_ECB,
  MOC_SYM_ALG_DES_CBC,
  MOC_SYM_ALG_TDES,
  MOC_SYM_ALG_TDES_ECB,
  MOC_SYM_ALG_TDES_CBC,
  MOC_SYM_ALG_ARC2_CBC,
  MOC_SYM_ALG_HMAC,
  MOC_RAND_ALG_CTR_DRBG_AES,
  MOC_RAND_ALG_FIPS186,
  MOC_SYM_ALG_ARC4,
  MOC_SYM_ALG_RC5,
  MOC_SYM_ALG_AES_CMAC,
  MOC_SYM_ALG_NIST_KDF,
  MOC_SYM_ALG_POLY1305,
  MOC_SYM_ALG_CHACHA20,
  MOC_SYM_ALG_CHACHAPOLY,
  MOC_SYM_ALG_HMAC_KDF,
  MOC_SYM_ALG_AES_XCBC,
  MOC_SYM_ALG_BLOWFISH_CBC,
  MOC_LOCAL_TYPE_BLAKE_2B,
  MOC_LOCAL_TYPE_BLAKE_2S,
  MOC_SYM_ALG_PKCS5_PBE,
  MOC_DIGEST_ALG_SHA3,
  MOC_SYM_ALG_ANSI_X9_63_KDF,
  MOC_SYM_ALG_AES_KW,
  MOC_RAND_ALG_NIST_DRBG_HASH
};

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_createMocSymCtx (
  MSymOperator SymOperator,
  void *pOperatorInfo,
  MocCtx pMocCtx,
  MocSymCtx *ppNewCtx
  )
{
  MSTATUS status;
  ubyte4 i;
  ubyte4 localType = 0;
  ubyte4 algoFlag = 0;
  MocSymContext *pCtx = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == SymOperator) || (NULL == ppNewCtx) )
    goto exit;

  *ppNewCtx = NULL;

  /* Allocate the Context shell.
   */
  status = DIGI_CALLOC ((void **)&pCtx, sizeof (MocSymContext), 1);
  if (OK != status)
    goto exit;

  /* Get the local type from the provided operator */
  status = SymOperator (
    (MocSymCtx)pCtx, pMocCtx, MOC_SYM_OP_GET_LOCAL_TYPE, NULL, (void *)&localType);
  if (OK != status)
    goto exit;

  /* If this is a software implementation, ensure we support the algorithm */
  if (0 != (MOC_LOCAL_TYPE_SW & localType))
  {
    /* Mask off bits to get the algorithm this operator claims to be implementing */
    algoFlag = (localType & MOC_LOCAL_TYPE_COM_MASK) |
              (localType & MOC_LOCAL_TYPE_ALG_MASK);

    /* Check with the list of approved algorithms */
    status = ERR_CRYPTO_ALGORITHM_UNSUPPORTED;
    for (i = 0; i < MOC_NUM_SUPPORTED_SYM_ALGOS; i++)
    {
      if (algoFlag == pSupportedSymAlgos[i])
      {
        status = OK;
        break;
      }
    }

    /* If status is not OK, we dont support that algorithm */
    if (OK != status)
      goto exit;
  }

  /* Now call the Operator passed in to complete the process.
   */
  status = SymOperator (
    (MocSymCtx)pCtx, pMocCtx, MOC_SYM_OP_CREATE, pOperatorInfo, NULL);
  if (OK != status)
    goto exit;

  pCtx->state = CTX_STATE_CREATE;
  *ppNewCtx = (MocSymCtx)pCtx;
  pCtx = NULL;

exit:

  if (NULL != pCtx)
  {
    CRYPTO_freeMocSymCtx ((MocSymCtx *)&pCtx);
  }

  return (status);
}

/*----------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_CREATE_MOCSYM_FROM_ALG_ID__
extern MSTATUS CRYPTO_createMocSymCtxFromAlgId (
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte *pKeyData,
  ubyte4 keyDataLen,
  intBoolean isEncoded,
  MocCtx pMocCtx,
  MocSymCtx *ppNewCtx
  )
{
  MSTATUS status;
  ubyte4 index;
  MocSymContext *pCtx = NULL;
  MocSubCtx *pOpListCtx = NULL;
  MSubCtxOpList *pOpList;
  MSymOperatorAlgIdAndOpList inputData;

  status = ERR_NULL_POINTER;
  if ( (NULL == ppNewCtx) || (NULL == pAlgId) ||
       (0 == algIdLen) )
    goto exit;

  *ppNewCtx = NULL;

  /* We need the list of Operators.
   */
  status = MocAcquireSubCtxRef (
    pMocCtx, MOC_SUB_CTX_TYPE_OP_LIST, &pOpListCtx);
  if (OK != status)
    goto exit;

  pOpList = (MSubCtxOpList *)(pOpListCtx->pLocalCtx);

  /* Now call each of the Operators passed in.
   * The Operator might be in the Digest list, it might be in the Sym list.
   */
  inputData.pAlgId = pAlgId;
  inputData.algIdLen = algIdLen;
  inputData.pOperatorList = pOpList->pSymOperators;
  inputData.listCount = pOpList->symOperatorCount;
  for (index = 0; index < inputData.listCount; ++index)
  {
    if (NULL == pCtx)
    {
      /* Allocate the Context shell.
       */
      status = DIGI_CALLOC ((void **)&pCtx, sizeof (MocSymContext), 1);
      if (OK != status)
        goto exit;
    }

    inputData.currentIndex = index;
    if (NULL == (inputData.pOperatorList)[index].SymOperator)
      continue;

    /* If this does not succeed, move on to the next Operator.
     */
    status = (inputData.pOperatorList)[index].SymOperator (
      pCtx, pMocCtx, MOC_SYM_OP_CREATE_FROM_ALG_ID, (void *)&inputData, NULL);
    if (OK != status)
      continue;

    /* If we reach this code, the Operator worked. If we have no key, then we're
     * done, sto looking.
     */
    if ( (NULL == pKeyData) || (0 == keyDataLen) )
      break;

    /* If we have a key, see if the Operator can work with it.
     */
    if (FALSE == isEncoded)
    {
      status = CRYPTO_loadSymKey (pCtx, pKeyData, keyDataLen);
    }
    else
    {
      status = CRYPTO_loadEncodedSymKey (pCtx, pKeyData, keyDataLen);
    }
    if (OK == status)
      break;

    /* If we reach this point, we have an object built but the key did not match.
     * Hence, we need to destroy that object.
     */
    status = CRYPTO_freeMocSymCtx ((MocSymCtx *)&pCtx);
    if (OK != status)
      goto exit;
  }

  /* If we went through the entire list and found no Operator, error.
   */
  status = ERR_NOT_FOUND;
  if (index >= inputData.listCount)
    goto exit;

  /* We did find one, so return it.
   */
  *ppNewCtx = (MocSymCtx)pCtx;
  pCtx = NULL;
  status = OK;

exit:

  if (NULL != pCtx)
  {
    CRYPTO_freeMocSymCtx ((MocSymCtx *)&pCtx);
  }
  if (NULL != pOpListCtx)
  {
    MocReleaseSubCtxRef (&pOpListCtx);
  }

  return (status);
}
#endif /* __DISABLE_DIGICERT_CREATE_MOCSYM_FROM_ALG_ID__ */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_getSymOperatorAndInfoFromIndex (
  ubyte4 index,
  MocCtx pMocCtx,
  MSymOperator *ppSymOperator,
  void **ppOperatorInfo
  )
{
  MSTATUS status;
  ubyte4 listCount;
  MocSubCtx *pSubCtx = NULL;
  MSubCtxOpList *pOpList;
  MSymOperatorAndInfo *pSymOperators;

  status = ERR_NULL_POINTER;
  if ( (NULL == pMocCtx) || (NULL == ppSymOperator) )
    goto exit;

  /* We need the list of Operators.
   */
  status = MocAcquireSubCtxRef (
    pMocCtx, MOC_SUB_CTX_TYPE_OP_LIST, &pSubCtx);
  if (OK != status)
    goto exit;

  pOpList = (MSubCtxOpList *)(pSubCtx->pLocalCtx);
  pSymOperators = pOpList->pSymOperators;
  listCount = pOpList->symOperatorCount;

  status = ERR_INVALID_ARG;
  if (listCount <= index)
    goto exit;

  /* We already know the index, just set the pointers */
  *ppSymOperator = pSymOperators[index].SymOperator;

  /* If the caller wanted the associated info give that back as well */
  if (NULL != ppOperatorInfo)
  {
    *ppOperatorInfo = pSymOperators[index].pOperatorInfo;
  }

  status = OK;

exit:

  if (NULL != pSubCtx)
  {
    MocReleaseSubCtxRef (&pSubCtx);
  }

  return status;
}


/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_getSymOperatorData (
  MocSymCtx pSymCtx,
  MocCtx pCtx,
  MSymOperatorData *pOperatorData
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  if ( (NULL == pOperatorData) || (NULL == pSymCtx) || (NULL == pSymCtx->SymOperator) )
    goto exit;

  status = pSymCtx->SymOperator (
    (MocSymCtx)pSymCtx, pCtx, MOC_SYM_OP_GET_OP_DATA, NULL, (void*)pOperatorData);
  if (OK != status)
    goto exit;

exit:
  return status;
}


/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_getMocSymObjectFromIndex (
  ubyte4 index,
  MocCtx pMocCtx,
  void *pOperatorInfo,
  MocSymCtx *ppObj
  )
{
  MSTATUS status;
  MSymOperator SymOperator;
  void *pOpInfo = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pMocCtx) || (NULL == ppObj) )
    goto exit;

  *ppObj = NULL;

  /* Get the operator and info from the MocCtx based on the index */
  status = CRYPTO_getSymOperatorAndInfoFromIndex (
    index, pMocCtx, &SymOperator, &pOpInfo);
  if (OK != status)
    goto exit;

  /* If the caller specified an operator info then use it, disregarding
   * the operator info from the list */
  if (NULL != pOperatorInfo)
  {
    pOpInfo = pOperatorInfo;
  }

  /* Create the object */
  status = CRYPTO_createMocSymCtx (
    SymOperator, pOpInfo, pMocCtx, ppObj);

exit:
  return status;
}


/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_getMocSymObjectFromFlag (
  ubyte4 flag,
  MocCtx pMocCtx,
  void *pOpInfo,
  MocSymCtx *ppObj
  )
{
  MSTATUS status;
  ubyte4 index, localType, listCount;
  void *pOperatorInfo = NULL;
  MocSubCtx *pSubCtx = NULL;
  MSubCtxOpList *pOpList;
  MSymOperatorAndInfo *pSymOperators;
  MocSymContext temp = { 0, NULL, NULL, 0 };

  status = ERR_NULL_POINTER;
  if ( (NULL == pMocCtx) || (NULL == ppObj) )
    goto exit;

  *ppObj = NULL;

  /* We need the list of Operators.
   */
  status = MocAcquireSubCtxRef (
    pMocCtx, MOC_SUB_CTX_TYPE_OP_LIST, &pSubCtx);
  if (OK != status)
    goto exit;

  pOpList = (MSubCtxOpList *)(pSubCtx->pLocalCtx);
  pSymOperators = pOpList->pSymOperators;
  listCount = pOpList->symOperatorCount;

  for (index = 0; index < listCount; ++index)
  {
    if (NULL != pSymOperators[index].SymOperator)
    {
      /* Ask the Operator to return the localType.
       * If it works, see if the algorithm is the same as the target.
       */
      status = pSymOperators[index].SymOperator (
        &temp, pMocCtx, MOC_SYM_OP_GET_LOCAL_TYPE, NULL, (void *)&localType);
      if (OK == status)
      {
        if ( (flag & MOC_LOCAL_TYPE_COM_MASK) == (localType & MOC_LOCAL_TYPE_COM_MASK) &&
             (flag & MOC_LOCAL_TYPE_ALG_MASK) == (localType & MOC_LOCAL_TYPE_ALG_MASK) )
        {
          if (NULL != pOpInfo)
          {
            pOperatorInfo = pOpInfo;
          }
          else
          {
            pOperatorInfo = pSymOperators[index].pOperatorInfo;
          }

          /* Build the object from this Operator.
           * It's possible the Operator doesn't work (e.g. HW with no HW impl
           * attached to the machine on which the program is running), and the
           * caller has a backup.
           * So try to build it. If it works, we're done. If not move on.
           * That's why we goto exit with a successful call.
           */
          status = CRYPTO_createMocSymCtx (
            pSymOperators[index].SymOperator, pOperatorInfo,
            pMocCtx, ppObj);
          if (OK == status)
            goto exit;
        }
      }
    }
  }

  /* If we went through the list and found no match, error.
   */
  status = ERR_NOT_FOUND;

exit:

  if (NULL != pSubCtx)
  {
    MocReleaseSubCtxRef (&pSubCtx);
  }

  return (status);
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_getMocSymObjectFromType (
  ubyte4 target,
  MocCtx pMocCtx,
  MocSymCtx *ppObj
  )
{
  return CRYPTO_getMocSymObjectFromFlag(target, pMocCtx, NULL, ppObj);
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_freeMocSymCtx (
  MocSymCtx *ppSymCtx
  )
{
  MSTATUS status, fStatus;
  MocSymContext *pCtx;

  /* Anything to free?
   */
  status = OK;
  if (NULL == ppSymCtx)
    goto exit;

  pCtx = (MocSymContext *)(*ppSymCtx);
  if (NULL == *ppSymCtx)
    goto exit;

  /* The Operator knows how to free any resources it acquired.
   * Note that the pLocalData field might be NULL, but we still want to call the
   * Operator. It might need to do some hardware exit function, even if there is
   * no local data.
   */
  if (NULL != pCtx->SymOperator)
  {
    status = pCtx->SymOperator (
      (MocSymCtx)pCtx, NULL, MOC_SYM_OP_FREE, NULL, NULL);
  }

  fStatus = DIGI_MEMSET ((void *)pCtx, 0, sizeof (MocSymContext));
  if (OK == status)
    status = fStatus;

  fStatus = DIGI_FREE ((void **)ppSymCtx);
  if (OK == status)
    status = fStatus;

exit:

  return (status);
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_cloneMocSymCtx (
  MocSymCtx pSymCtx,
  MocSymCtx *ppNewCtx
  )
{
  MSTATUS status;

  MocSymContext *pCtxCopy = NULL;

  /* NULL checks
   */
  status = ERR_NULL_POINTER;
  if ( (NULL == pSymCtx) ||
       (NULL == pSymCtx->SymOperator) ||
       (NULL == ppNewCtx) )
    goto exit;

  /* Allocate space for the new MocSymCtx
   */
  status = DIGI_MALLOC((void **) &pCtxCopy, sizeof(MocSymContext));
  if (OK != status)
    goto exit;

  /* Call on the operator to clone itself into the new MocSymCtx
   */
  status = pSymCtx->SymOperator(
    pSymCtx, NULL, MOC_SYM_OP_CLONE, NULL, pCtxCopy);
  if (OK != status)
    goto exit;

  /* If the user passed in a non NULL MocSymCtx then free it
   */
  if (NULL != *ppNewCtx)
  {
    status = CRYPTO_freeMocSymCtx(ppNewCtx);
    if (OK != status)
      goto exit;
  }

  pCtxCopy->localType = pSymCtx->localType;
  pCtxCopy->state = pSymCtx->state;
  pCtxCopy->SymOperator = pSymCtx->SymOperator;

  /* Set the return MocSymCtx and NULL out pCtxCopy so it doesn't get freed
   */
  *ppNewCtx = pCtxCopy;
  pCtxCopy = NULL;

exit:

  if (NULL != pCtxCopy)
    DIGI_FREE((void **) &pCtxCopy);

  return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_getAlgorithmIdAlloc (
  MocSymCtx pSymCtx,
  ubyte **ppAlgId,
  ubyte4 *pAlgIdLen
  )
{
  MSTATUS status;
  ubyte4 idLen;
  ubyte *pNewBuf = NULL;
  MSymOperatorBuffer outputInfo;

  status = ERR_NULL_POINTER;
  if ( (NULL == pSymCtx) || (NULL == ppAlgId) || (NULL == pAlgIdLen) )
    goto exit;

  if (NULL == pSymCtx->SymOperator)
    goto exit;

  *ppAlgId = NULL;
  *pAlgIdLen = 0;

  /* Call the Operator with no output buffer to get the size required.
   * We expect to get ERR_BUFFER_TOO_SMALL.
   */
  outputInfo.pBuffer = NULL;
  outputInfo.bufferSize = 0;
  outputInfo.pOutputLen = &idLen;
  status = pSymCtx->SymOperator (
    pSymCtx, NULL, MOC_SYM_OP_GET_ALG_ID, NULL, (void *)&outputInfo);
  if (OK == status)
    status = ERR_UNSUPPORTED_OPERATION;
  if (ERR_BUFFER_TOO_SMALL != status)
    goto exit;

  /* Now allocate a buffer big enough.
   */
  status = DIGI_MALLOC ((void **)&pNewBuf, idLen);
  if (OK != status)
    goto exit;

  /* Now call the Operator again with the buffer.
   */
  outputInfo.pBuffer = pNewBuf;
  outputInfo.bufferSize = idLen;
  outputInfo.pOutputLen = &idLen;
  status = pSymCtx->SymOperator (
    pSymCtx, NULL, MOC_SYM_OP_GET_ALG_ID, NULL, (void *)&outputInfo);
  if (OK != status)
    goto exit;

  /* If everything worked, return the result.
   */
  *ppAlgId = pNewBuf;
  *pAlgIdLen = idLen;
  pNewBuf = NULL;

exit:

  if (NULL != pNewBuf)
  {
    DIGI_FREE ((void **)&pNewBuf);
  }

  return (status);
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_getAlgorithmId (
  MocSymCtx pSymCtx,
  ubyte *pAlgId,
  ubyte4 bufferSize,
  ubyte4 *pAlgIdLen
  )
{
  MSTATUS status;
  ubyte4 bufSize;
  MSymOperatorBuffer outputInfo;

  status = ERR_NULL_POINTER;
  if ( (NULL == pSymCtx) || (NULL == pAlgIdLen) )
    goto exit;

  if (NULL == pSymCtx->SymOperator)
    goto exit;

  *pAlgIdLen = 0;

  bufSize = 0;
  if (NULL != pAlgId)
    bufSize = bufferSize;

  /* Call the Operator with no output buffer to get the size required.
   * We expect to get ERR_BUFFER_TOO_SMALL.
   */
  outputInfo.pBuffer = pAlgId;
  outputInfo.bufferSize = bufSize;
  outputInfo.pOutputLen = pAlgIdLen;
  status = pSymCtx->SymOperator (
    pSymCtx, NULL, MOC_SYM_OP_GET_ALG_ID, NULL, (void *)&outputInfo);

exit:

  return (status);
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_updateSymOperatorData (
  MocSymCtx pSymCtx,
  MocCtx pMocCtx,
  void *pOperatorData
  )
{
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if ((NULL == pSymCtx) || (NULL == pOperatorData))
    goto exit;

  if (NULL == pSymCtx->SymOperator)
    goto exit;

  status = pSymCtx->SymOperator (
      pSymCtx, pMocCtx, MOC_SYM_OP_UPDATE_OP_DATA, pOperatorData, NULL);

exit:
  return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_deriveKey (
  MocSymCtx pSymCtx,
  void *pAssociatedInfo,
  ubyte *pDerivedKey,
  ubyte4 bufferSize,
  ubyte4 *pDerivedKeyLen
  )
{
  MSTATUS status;
  ubyte4 bufSize;
  MSymOperatorBuffer outputInfo;

  status = ERR_NULL_POINTER;
  if ( (NULL == pDerivedKey) || (NULL == pDerivedKeyLen) )
    goto exit;

  if ( (NULL == pSymCtx) || (NULL == pSymCtx->SymOperator) )
    goto exit;

  bufSize = 0;
  if (NULL != pDerivedKey)
    bufSize = bufferSize;

  outputInfo.bufferSize = bufSize;
  outputInfo.pBuffer = pDerivedKey;
  outputInfo.pOutputLen = pDerivedKeyLen;
  status = pSymCtx->SymOperator (
    pSymCtx, NULL, MOC_SYM_OP_DERIVE_KEY, pAssociatedInfo, (void *)&outputInfo);

exit:
  return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_deriveKeyAlloc (
  MocSymCtx pSymCtx,
  void *pAssociatedInfo,
  ubyte **ppDerivedKey,
  ubyte4 *pDerivedKeyLen
  )
{
  MSTATUS status;
  ubyte4 bufSize;
  MSymOperatorBuffer outputInfo;
  ubyte *pNewBuf = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == ppDerivedKey) || (NULL == pDerivedKeyLen) )
    goto exit;

  if ( (NULL == pSymCtx) || (NULL == pSymCtx->SymOperator) )
    goto exit;

  *ppDerivedKey = NULL;
  *pDerivedKeyLen = 0;

  /* First get the required buffer size */
  outputInfo.bufferSize = 0;
  outputInfo.pBuffer = NULL;
  outputInfo.pOutputLen = &bufSize;
  status = pSymCtx->SymOperator (
    pSymCtx, NULL, MOC_SYM_OP_DERIVE_KEY, pAssociatedInfo, (void *)&outputInfo);
  if (OK == status)
    status = ERR_UNSUPPORTED_OPERATION;
  if (ERR_BUFFER_TOO_SMALL != status)
    goto exit;

  /* Allocate the new buffer */
  status = DIGI_MALLOC((void **)&pNewBuf, bufSize);
  if (OK != status)
    goto exit;

  /* Now derive the key for real */
  outputInfo.bufferSize = bufSize;
  outputInfo.pBuffer = pNewBuf;
  outputInfo.pOutputLen = &bufSize;
  status = pSymCtx->SymOperator (
    pSymCtx, NULL, MOC_SYM_OP_DERIVE_KEY, pAssociatedInfo, (void *)&outputInfo);
  if (OK != status)
    goto exit;

  *ppDerivedKey = pNewBuf;
  *pDerivedKeyLen = bufSize;
  pNewBuf = NULL;

exit:

  if (NULL != pNewBuf)
  {
    DIGI_FREE((void **)&pNewBuf);
  }

  return status;
}

MSTATUS CRYPTO_doRawTransform (
  MocSymCtx pSymCtx,
  ubyte *pDataToProcess,
  ubyte4 dataToProcessLen,
  ubyte *pProcessedData,
  ubyte4 bufferSize,
  ubyte4 *pProcessedDataLen
  )
{
  MSTATUS status;
  symOperation op = MOC_SYM_OP_DO_RAW_TRANSFORM;
  MSymOperatorData inputInfo = {0};
  MSymOperatorBuffer outputInfo = {0};
  
  status = ERR_NULL_POINTER;
  if (NULL == pSymCtx || NULL == pProcessedDataLen || NULL == pSymCtx->SymOperator)
    goto exit;
  
  inputInfo.pData = pDataToProcess;
  if (NULL != pDataToProcess)
    inputInfo.length = dataToProcessLen;
  
  outputInfo.pBuffer = pProcessedData;
  if (NULL != pProcessedData)
    outputInfo.bufferSize = bufferSize;
  
  outputInfo.pOutputLen = pProcessedDataLen;
  
  status = pSymCtx->SymOperator (pSymCtx, NULL, op, (void *)&inputInfo, (void *)&outputInfo);

exit:
  
  return status;
}
#endif /* (defined(__ENABLE_DIGICERT_SYM__)) */
