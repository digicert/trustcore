/*
 * nonrandop.c
 *
 * deterministic rng data generation for test vectors.
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
#include "../../crypto/mocsym.h"
#include "../../crypto/sha1.h"
#include "../../crypto/des.h"
#include "../../crypto/three_des.h"
#include "../../crypto/aes.h"
#include "../../crypto/nist_rng_types.h"
#include "nonrandop.h"

/* This is the local info for the non-random operator.
 *
 * randomContext *pRandCtx - This variable will store the context specified by
 *   the caller during the call to CRYPTO_createMocSymRandom. This must be
 *   supplied otherwise an error will occur.
 * ubyte *pRandBuffer - This is the buffer that will contain static data. Once
 *   the caller requests for "random" data, it will be retrieved from this
 *   buffer which can be set by calling CRYPTO_seedRandomContext.
 * ubyte4 randBufferLen - This variable will store the amount of bytes that have
 *   been stored in the operator.
 * intBoolean used - This variable will determine whether the static data has
 *   been used up or not. Once all the data is used up, the operator will now
 *   generate random data by calling RANDOM_numberGenerator on the random
 *   context that was passed in during the create call.
 */
typedef struct NonRandomInfo {
  randomContext *pRandCtx;
  ubyte *pRandBuffer;
  ubyte4 randBufferLen;
  ubyte4 randPos;
  intBoolean used;
} NonRandomInfo;

MSTATUS NonRandomCreate(
  MocSymCtx pCtx,
  randomContext *pDefaultRand
  );

MSTATUS NonRandomFree(
  MocSymCtx pCtx
  );

MSTATUS NonRandomStaticSeed(
  MocSymCtx pCtx,
  MRandomSeedInfo *pInput
  );

MSTATUS NonRandomLoadStaticSeed(
  MocSymCtx pCtx,
  MSymOperatorBuffer *pOutput
  );

#if defined(__ENABLE_DIGICERT_SYM__)

extern MSTATUS NonRandomOperator(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  )
{
  MSTATUS status = OK;

  status = ERR_NULL_POINTER;
  if (NULL == pMocSymCtx)
    goto exit;

  switch (symOp)
  {
    default:
      status = ERR_NOT_IMPLEMENTED;
      goto exit;

    case MOC_SYM_OP_GET_LOCAL_TYPE:
    
      status = ERR_NULL_POINTER;
      if (NULL != pOutputInfo)
      {
        /* IMPORTANT: Since this operator is for testing only we do not register it as a software operator.
                      We instead use MOC_LOCAL_TYPE_HW and trick the code into using it appropriately. */
        *((ubyte4 *)pOutputInfo) = (MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_HW | MOC_LOCAL_TYPE_SYM | MOC_LOCAL_TYPE_RANDOM );
        status = OK;
      }
      break;
          
    case MOC_SYM_OP_CREATE:
      status = NonRandomCreate(pMocSymCtx, (randomContext *) pInputInfo);
      break;

    case MOC_SYM_OP_RAND_GET_SEED_TYPE:
      status = ERR_NULL_POINTER;
      if (NULL != pOutputInfo)
      {
        *((ubyte4 *)(pOutputInfo)) = MOC_SYM_RAND_SEED_TYPE_DIRECT;
        status = OK;
      }
      break;

    case MOC_SYM_OP_FREE:
      status = NonRandomFree(pMocSymCtx);
      break;

    case MOC_SYM_OP_SEED_RANDOM:
      status = NonRandomStaticSeed(
        pMocSymCtx, (MRandomSeedInfo *) pInputInfo);
      break;

    case MOC_SYM_OP_GENERATE_RANDOM:
      status = NonRandomLoadStaticSeed(
        pMocSymCtx, (MSymOperatorBuffer *) pOutputInfo);
      break;

  }

exit:

  return status;
}

/* Creates a NonRandom operator. This function requires that a randomContext is
 * passed, that way when all the static data is used up, it can get actual
 * random data from the operator.
 */
MSTATUS NonRandomCreate(
  MocSymCtx pCtx,
  randomContext *pDefaultRand
  )
{
  MSTATUS status = OK;
  NonRandomInfo *pNewInfo = NULL;

  status = ERR_NULL_POINTER;
  if (NULL == pDefaultRand)
    goto exit;

  status = DIGI_CALLOC((void **) &pNewInfo, 1, sizeof (NonRandomInfo));
  if (OK != status)
    goto exit;

  pNewInfo->pRandCtx = pDefaultRand;
  pNewInfo->used = FALSE;

  pCtx->localType =
    MOC_LOCAL_TYPE_MOCANA | MOC_LOCAL_TYPE_SW | MOC_LOCAL_TYPE_SYM |
    MOC_LOCAL_TYPE_RANDOM;
  pCtx->SymOperator = NonRandomOperator;
  pCtx->pLocalData = (void *) pNewInfo;

exit:
  return status;
}

/* Free's up the non-random operator.
 */
MSTATUS NonRandomFree(
  MocSymCtx pCtx
  )
{
  MSTATUS status = OK, fstatus;

  NonRandomInfo *pLocalData = (NonRandomInfo *) (pCtx->pLocalData);

  if (NULL != pLocalData)
  {
    if (NULL != pLocalData->pRandBuffer)
    {
      fstatus = DIGI_FREE((void **) &(pLocalData->pRandBuffer));
      if (OK == status)
        status = fstatus;
    }

    fstatus = DIGI_FREE((void **) &pLocalData);
    if (OK == status)
      status = fstatus;
  }

exit:
  return status;
}

/* This will load a buffer into the context. The buffer that is loaded in will
 * be the next "random" value that the global random context generates. Random
 * is in quotes because the value is not actually random, it's the value that
 * was loaded in. This allows the user to control seed/random values, which
 * is useful for testing purposes.
 */
MSTATUS NonRandomStaticSeed(
  MocSymCtx pSymCtx,
  MRandomSeedInfo *pSeedData
  )
{
  MSTATUS status = OK;

  NonRandomInfo *pLocalInfo = (NonRandomInfo *) pSymCtx->pLocalData;
  ubyte *pSeed = NULL;

  status = ERR_NULL_POINTER;
  if (NULL == pSeedData || NULL == pSeedData->pEntropyMaterial || NULL == pLocalInfo)
    goto exit;

  status = ERR_BAD_LENGTH;
  if (0 == pSeedData->entropyMaterialLen)
    goto exit;

  /* Clear any seed data */
  if (NULL != pLocalInfo->pRandBuffer)
  {
    status = DIGI_FREE((void **) &(pLocalInfo->pRandBuffer));
    if (OK != status)
      goto exit;

    pLocalInfo->randBufferLen = 0;
  }

  status = DIGI_MALLOC((void **) &pSeed, pSeedData->entropyMaterialLen);
  if (OK != status)
    goto exit;

  status = DIGI_MEMCPY(pSeed, pSeedData->pEntropyMaterial, pSeedData->entropyMaterialLen);
  if (OK != status)
    goto exit;

  pLocalInfo->randBufferLen = pSeedData->entropyMaterialLen;
  pLocalInfo->pRandBuffer = pSeed;
  pLocalInfo->used = FALSE;
  pLocalInfo->randPos = 0;
    
  pSeed = NULL;

exit:

  if (NULL != pSeed)
  {
    DIGI_FREE((void **) &pSeed);
  }
  return status;
}

/* This function will take the buffer that was loaded in by the user and
 * copy it into the buffer that the user needs it for. Additionally, if all the
 * static data that has been loaded up is used, then the operator will generate
 * data using the random operator the caller specified during the creation call.
 *
 * Why do we need to be able to switch the random operators? It's because some
 * functions in Mocana's NanoCrypto library will make multiple requests to
 * generate a random seed and for testing purposes only SOME of the requests
 * to generate a random seed will be static. This means that the other requests
 * must actually produce a random seed. This function allows that by loading
 * a user defined seed into a buffer then swapping into another random operator
 * that is supposed to be random.
 */
MSTATUS NonRandomLoadStaticSeed(
  MocSymCtx pSymCtx,
  MSymOperatorBuffer *pOutput
  )
{
  MSTATUS status = OK;

  NonRandomInfo *pLocalData = (NonRandomInfo *) pSymCtx->pLocalData;

  status = ERR_NULL_POINTER;
  if ( (NULL == pOutput) || (NULL == pOutput->pBuffer) || (NULL == pLocalData) )
    goto exit;

  if (FALSE == pLocalData->used)
  {
    if (NULL == pLocalData->pRandBuffer) /* rng was never seeded */
      goto exit;
      
    ubyte4 copyLen = (pOutput->bufferSize <= pLocalData->randBufferLen - pLocalData->randPos) ?
                      pOutput->bufferSize : (pLocalData->randBufferLen - pLocalData->randPos);

    status = OK;
    if (0 == copyLen)
      goto exit;
      
    /* zero pad if the number of bytes to copy is less than what we need */
    if (copyLen < pOutput->bufferSize)
    {
      status = DIGI_MEMSET(pOutput->pBuffer, 0x00, pOutput->bufferSize - copyLen);
      if (OK != status)
        goto exit;
    }
      
    status = DIGI_MEMCPY(pOutput->pBuffer + (pOutput->bufferSize - copyLen), pLocalData->pRandBuffer + pLocalData->randPos, copyLen);
    if (OK != status)
      goto exit;

    pLocalData->randPos += copyLen;
    
    /* Are we done using the non-random data? */
    if (pLocalData->randPos >= pLocalData->randBufferLen)
      pLocalData->used = TRUE;
  }
  else
  {
    status = RANDOM_numberGenerator(
      pLocalData->pRandCtx, pOutput->pBuffer, pOutput->bufferSize);
    if (OK != status)
      goto exit;
  }

  *(pOutput->pOutputLen) = pLocalData->randBufferLen;

exit:

  return status;
}

#endif /* defined(__ENABLE_DIGICERT_SYM__) */
