/*
 * randomf.c
 *
 * Random Number Generating Functions.
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
@file       randomf.c
@brief      Random Number Generating Functions.
@details    Add details here.

@filedoc    randomf.c
*/
#include "../cap/capasym.h"

#if (defined(__ENABLE_DIGICERT_SYM__))

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_createMocSymRandom (
  MSymOperator SymOperator,
  void *pOperatorInfo,
  MocCtx pMocCtx,
  randomContext **ppMocSymRandom
  )
{
  MSTATUS status;
  RandomCtxWrapper *pWrap = NULL;
  MocSymCtx pCtx = NULL;
  MocRandCtx *pRandCtx = NULL;

  /* Create the shell that will be the randomContext. */
  status = DIGI_MALLOC (
    (void **)&pWrap, sizeof (RandomCtxWrapper));
  if (OK != status)
    goto exit;

  status = DIGI_MEMSET (
    (void *)pWrap, 0, sizeof (RandomCtxWrapper));
  if (OK != status)
    goto exit;

  pWrap->WrappedCtxType = MOC_RAND;

  /* Now build a MocSymCtx. */
  status = CRYPTO_createMocSymCtx (
    SymOperator, pOperatorInfo, pMocCtx, &pCtx);
  if (OK != status)
    goto exit;

  /* Verify that it is a random object. */
  status = ERR_RAND_INVALID_CONTEXT;
  if (0 == (pCtx->localType & MOC_LOCAL_TYPE_RANDOM))
    goto exit;

  /* Initialize the reseed bit counter. */
  pWrap->reseedBitCounter = 0;

  /* Now load the MocSymCtx into the wrapper. */
  pRandCtx = (MocRandCtx *)(pWrap->WrappedCtx.storage);
  pRandCtx->pMocSymObj = (void *)pCtx;
  *ppMocSymRandom = (randomContext *)pWrap;

  pCtx = NULL;
  pWrap = NULL;

  status = OK;

exit:

  if (NULL != pCtx)
  {
    CRYPTO_freeMocSymCtx (&pCtx);
  }
  if (NULL != pWrap)
  {
    DIGI_FREE ((void **)&pWrap);
  }

  return (status);
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_freeMocSymRandom (
  randomContext **ppMocSymRandom
  )
{
  MSTATUS status, fStatus;
  RandomCtxWrapper *pWrap;
  MocRandCtx *pRandCtx = NULL;
  MocSymCtx pSymCtx;

  /* Anything to free?
   */
  status = OK;
  if (NULL == ppMocSymRandom)
    goto exit;

  pWrap = (RandomCtxWrapper *)(*ppMocSymRandom);
  if (NULL == *ppMocSymRandom)
    goto exit;

  /* If this is not a MocSym rand, error.
   */
  status = ERR_RAND_INVALID_CONTEXT;
  if (MOC_RAND != pWrap->WrappedCtxType)
    goto exit;

  /* Is there a local object?
   */
  status = OK;
  pRandCtx = (MocRandCtx *)&(pWrap->WrappedCtx.storage);
  if ( (NULL != pRandCtx) && (NULL != pRandCtx->pMocSymObj) )
  {
    pSymCtx = (MocSymCtx)(pRandCtx->pMocSymObj);
    status = CRYPTO_freeMocSymCtx (&pSymCtx);
  }

  /* The last thing we need to do is free the shell.
   */
  fStatus = DIGI_FREE ((void **)ppMocSymRandom);
  if (OK == status)
    status = fStatus;

exit:

  return (status);
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_seedRandomContext (
  randomContext *pRandom,
  void *pSeedInfo,
  ubyte *pEntropyBytes,
  ubyte4 entropyLen
  )
{
  MSTATUS status;
  RandomCtxWrapper *pWrap = (RandomCtxWrapper *)pRandom;
  MocRandCtx *pRandCtx = NULL;
  MocSymCtx pCtx = NULL;
  MRandomSeedInfo seedInfo;

  status = ERR_NULL_POINTER;
  if (NULL == pRandom)
    goto exit;

  /* We need either seed info or entropy bytes */
  if ( (NULL == pSeedInfo) && (NULL == pEntropyBytes) )
    goto exit;

  /* If this is not a MocSym random, seed a bit differently.
   */
  if (MOC_RAND != pWrap->WrappedCtxType)
  {
    status = RANDOM_seedOldRandom (
      pRandom, pEntropyBytes, entropyLen);
    goto exit;
  }

  pRandCtx = GET_MOC_RAND_CTX(pWrap);
  pCtx = (MocSymCtx)(pRandCtx->pMocSymObj);

  status = ERR_RAND_INVALID_CONTEXT;
  if ( (NULL == pCtx) || (NULL == pCtx->SymOperator) )
    goto exit;

  /* Prepare the seeding structure */
  seedInfo.pOperatorSeedInfo = pSeedInfo;
  seedInfo.pEntropyMaterial = pEntropyBytes;
  seedInfo.entropyMaterialLen = entropyLen;

  /* Have the operator seed itself */
  status = pCtx->SymOperator (
    pCtx, NULL, MOC_SYM_OP_SEED_RANDOM, (void *)&seedInfo, NULL);

exit:

  return (status);
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_reseedRandomContext (
  randomContext *pRandom,
  ubyte *pEntropyBytes,
  ubyte4 entropyLen,
  ubyte *pAdditionalData,
  ubyte4 additionalDataLen
  )
{
  MSTATUS status;
  RandomCtxWrapper *pWrap = (RandomCtxWrapper *)pRandom;
  MocRandCtx *pRandCtx = NULL;
  MocSymCtx pCtx = NULL;
  MRandomReseedInfo reseedInfo;

  status = ERR_NULL_POINTER;
  if (NULL == pRandom)
    goto exit;

  pRandCtx = GET_MOC_RAND_CTX(pWrap);
  if (NULL == pRandCtx)
    goto exit;
  pCtx = (MocSymCtx)(pRandCtx->pMocSymObj);

  status = ERR_RAND_INVALID_CONTEXT;
  if ( (NULL == pCtx) || (NULL == pCtx->SymOperator) )
    goto exit;

  /* Prepare the reseed structure */
  reseedInfo.pEntropyMaterial = pEntropyBytes;
  reseedInfo.entropyMaterialLen = entropyLen;
  reseedInfo.pAdditionalData = pAdditionalData;
  reseedInfo.additionalDataLen = additionalDataLen;

  /* Have the operator reseed itself */
  status = pCtx->SymOperator (
    pCtx, NULL, MOC_SYM_OP_RESEED_RANDOM, (void *)&reseedInfo, NULL);

exit:
  return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_getSeedType (
  randomContext *pRandom,
  ubyte4 *pSeedType
  )
{
  MSTATUS status;
  RandomCtxWrapper *pWrap = (RandomCtxWrapper *)pRandom;
  MocRandCtx *pRandCtx = NULL;
  MocSymCtx pCtx = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pRandom) || (NULL == pSeedType) )
    goto exit;

  pRandCtx = GET_MOC_RAND_CTX(pWrap);
  if (NULL == pRandCtx)
    goto exit;
  pCtx = (MocSymCtx)(pRandCtx->pMocSymObj);

  status = ERR_RAND_INVALID_CONTEXT;
  if ( (NULL == pCtx) || (NULL == pCtx->SymOperator) )
    goto exit;

  status = pCtx->SymOperator (
    pCtx, NULL, MOC_SYM_OP_RAND_GET_SEED_TYPE, NULL, (void *)pSeedType);

exit:
  return status;
}

#endif /* (defined(__ENABLE_DIGICERT_SYM__)) */
