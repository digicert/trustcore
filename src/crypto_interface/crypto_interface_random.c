/*
 * crypto_interface_random.c
 *
 * Cryptographic Interface for Random Number Generation.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_RANDOM_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../common/random.h"
#include "../common/rng_seed.h"
#include "../crypto_interface/crypto_interface_priv.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RANDOM__))

static ubyte4 entropyCollectLen = MOC_DEFAULT_NUM_ENTROPY_BYTES;
static MGetEntropyFunc RegisteredEntropyFunc = NULL;
static MGetPersoStrCallback RegisteredGetPersoStr = NULL;

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_RANDOM_ACQUIRE_CTX_EX(_status, _ppCtx, _algo)                      \
    _status = RANDOM_acquireContextEx(_ppCtx, _algo);
#else
#define MOC_RANDOM_ACQUIRE_CTX_EX(_status, _ppCtx, _algo)                      \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_RANDOM_RELEASE_CTX_EX(_status, _ppCtx)                             \
    _status = RANDOM_releaseContextEx(_ppCtx);
#else
#define MOC_RANDOM_RELEASE_CTX_EX(_status, _ppCtx)                             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_RANDOM_ADD_ENTROPY_BIT(_status, _pCtx, _bit)                       \
    _status = RANDOM_addEntropyBitEx(_pCtx, _bit);
#else
#define MOC_RANDOM_ADD_ENTROPY_BIT(_status, _pCtx, _bit)                       \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

static MSTATUS CRYPTO_INTERFACE_getEntropyFunc (
  MGetEntropyFunc *ppEntropyFunc
  );

static MSTATUS CRYPTO_INTERFACE_getEntropyFuncEx (
  MGetEntropyFunc *ppEntropyFunc
  );

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RANDOM_acquireContextEx (
  randomContext **ppRandomContext,
  ubyte algoId
  )
{
  MSTATUS status;
  ubyte4 algoStatus, index, seedType;
  MCtrDrbgAesSeedInfo seedInfo = {0};
  MocCtx pMocCtx = NULL;
  randomContext *pNewRandCtx = NULL;
  MSymOperator SymOperator = NULL;
  void *pOperatorInfo = NULL;
  MGetEntropyFunc EntropyFunc = NULL;
  ubyte *pEntropy = NULL;
  ubyte4 entropyLen = 0;
  ubyte pEntropyBuf[MOC_DEFAULT_NUM_ENTROPY_BYTES];
  algoStatus = 0;
  index = 0;

  status = ERR_NULL_POINTER;
  if (NULL == ppRandomContext)
    goto exit;

  /* Do we have an alternate implementation of an AES based CTR DRBG? */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_ctr_drbg_aes, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if ( (MODE_DRBG_CTR == algoId) && (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus) )
  {
    /* Get the mocctx from the crypto interface core */
    status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
    if (OK != status)
      goto exit;

    /* Get the associated operator from the index */
    status = CRYPTO_getSymOperatorAndInfoFromIndex (
      index, pMocCtx, &SymOperator, &pOperatorInfo);
    if (OK != status)
      goto exit;

    /* Create a new random context */
    status = CRYPTO_createMocSymRandom (
      SymOperator, pOperatorInfo, pMocCtx, &pNewRandCtx);
    if (OK != status)
      goto exit;

    /* Determine how this operator gets entropy */
    status = CRYPTO_getSeedType(pNewRandCtx, &seedType);
    if (OK != status)
      goto exit;

    /* Does this object support seeding? */
    status = ERR_RAND_SEED_METHOD_NOT_SUPPORTED;
    if (MOC_SYM_RAND_SEED_TYPE_NONE == seedType)
      goto exit;

    /* Retrieve the function pointer which will be used for entropy collection,
     * either get the one registered here earlier or the mocana default  */
    status = CRYPTO_INTERFACE_getEntropyFunc(&EntropyFunc);
    if (OK != status)
      goto exit;

    seedInfo.useDf = 1;
    seedInfo.keyLenBytes = NIST_CTRDRBG_DEFAULT_KEY_LEN_BYTES;
    seedInfo.entropyCollectLen = entropyCollectLen;

    /* If this operator supports direct entropy injection, collect the entropy
     * into a buffer now and provide that to the operator */
    if (MOC_SYM_RAND_SEED_TYPE_DIRECT == seedType)
    {
      status = ERR_RAND_SEED_LEN_INVALID;
      if ( (entropyCollectLen < seedInfo.keyLenBytes) ||
           (MOC_DEFAULT_NUM_ENTROPY_BYTES < entropyCollectLen) )
        goto exit;

      status = DIGI_MEMSET(pEntropyBuf, 0, MOC_DEFAULT_NUM_ENTROPY_BYTES);
      if (OK != status)
        goto exit;

      status = EntropyFunc(NULL, pEntropyBuf, entropyCollectLen);
      if (OK != status)
        goto exit;

      pEntropy = pEntropyBuf;
      entropyLen = entropyCollectLen;
    }
    else if (MOC_SYM_RAND_SEED_TYPE_CALLBACK == seedType)
    {
      status = ERR_RAND_SEED_LEN_INVALID;
      if (entropyCollectLen < seedInfo.keyLenBytes)
        goto exit;

      /* This operator expects a funciton pointer to perform its entropy
       * collection, specify the one we determined earlier */
      seedInfo.EntropyFunc = EntropyFunc;
      seedInfo.pEntropyCtx = NULL;
    }

    /* If a callback was registered to get the personalization string,
     * invoke it now, otherwise use the default */
    if (NULL != RegisteredGetPersoStr)
    {
      seedInfo.pCustom = RegisteredGetPersoStr(&(seedInfo.customLen));
    }
    else
    {
      seedInfo.pCustom = DIGICERT_RNG_GET_PERSONALIZATION_STRING(
        &(seedInfo.customLen));
    }

    status = CRYPTO_seedRandomContext (
      pNewRandCtx, (void *)&seedInfo, pEntropy, entropyLen);
    if (OK != status)
      goto exit;

    *ppRandomContext = pNewRandCtx;
    pNewRandCtx = NULL;
  }
  else
  {
    MOC_RANDOM_ACQUIRE_CTX_EX(status, ppRandomContext, algoId)
  }

exit:

  if (NULL != pNewRandCtx)
  {
    CRYPTO_freeMocSymRandom(&pNewRandCtx);
  }

  return status;

}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RANDOM_releaseContextEx (
  randomContext **pp_randomContext
  )
{
  MSTATUS status, fStatus;
  ubyte4 algoStatus, index;
  RandomCtxWrapper *pWrapper = NULL;
  MocRandCtx *pMocRandCtx = NULL;

  status = ERR_NULL_POINTER;
  if (NULL == pp_randomContext)
    goto exit;

  pWrapper = (RandomCtxWrapper *)(*pp_randomContext);
  if (NULL == pWrapper)
    goto exit;

  /* Do we have an alternate implementation of an AES based CTR DRBG? */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_ctr_drbg_aes, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if ( (IS_MOC_RAND(pWrapper)) && (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus) )
  {
    status = ERR_NULL_POINTER;
    pMocRandCtx = GET_MOC_RAND_CTX(pWrapper);
    if (NULL == pMocRandCtx)
      goto exit;

    status = CRYPTO_freeMocSymCtx((MocSymCtx *)&(pMocRandCtx->pMocSymObj));

    fStatus = DIGI_FREE((void **)pp_randomContext);
    if (OK == status)
      status = fStatus;
  }
  else
  {
    MOC_RANDOM_RELEASE_CTX_EX(status, pp_randomContext)
  }

exit:
  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RANDOM_addEntropyBitEx (
  randomContext *pRandomContext,
  ubyte entropyBit
  )
{
  MSTATUS status;
  ubyte4 algoStatus, index, bitsNeeded;
  RandomCtxWrapper *pWrapper = NULL;
  MGetEntropyFunc EntropyFunc = NULL;
  ubyte pEntropyBuf[MOC_DEFAULT_NUM_ENTROPY_BYTES];
  ubyte4 seedType;

  status = ERR_NULL_POINTER;
  if (NULL == pRandomContext)
    goto exit;

  pWrapper = (RandomCtxWrapper *)pRandomContext;

  /* Do we have an alternate implementation of an AES based CTR DRBG? */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_ctr_drbg_aes, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if ( (IS_MOC_RAND(pWrapper)) && (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus) )
  {
    /* First add the bit into the EntropyDepot */
    status = RNG_SEED_addEntropyBit(entropyBit);
    if (OK != status)
      goto exit;

    /* Increment our reseed counter */
    pWrapper->reseedBitCounter++;

    /* If we have "enough" new entropy bits, then reseed our context */
    bitsNeeded = MOC_DEFAULT_NUM_ENTROPY_BYTES * 8;
    if (pWrapper->reseedBitCounter < bitsNeeded)
    {
      /* We have not filled our depot, simply return OK */
      goto exit;
    }

    /* Determine how this operator gets entropy */
    status = CRYPTO_getSeedType(pRandomContext, &seedType);
    if (OK != status)
      goto exit;

    /* Does this object support seeding? */
    status = ERR_RAND_SEED_METHOD_NOT_SUPPORTED;
    if (MOC_SYM_RAND_SEED_TYPE_NONE == seedType)
      goto exit;

    /* If this operator supports direct entropy injection, collect the entropy
     * into a buffer now and provide that to the operator */
    if (MOC_SYM_RAND_SEED_TYPE_DIRECT == seedType)
    {
      status = ERR_RAND_SEED_LEN_INVALID;
      if ( (entropyCollectLen < NIST_CTRDRBG_DEFAULT_KEY_LEN_BYTES) ||
           (MOC_DEFAULT_NUM_ENTROPY_BYTES < entropyCollectLen) )
        goto exit;

      /* Get our source of entropy */
      status = CRYPTO_INTERFACE_getEntropyFuncEx(&EntropyFunc);
      if (OK != status)
        goto exit;

      status = DIGI_MEMSET(pEntropyBuf, 0, MOC_DEFAULT_NUM_ENTROPY_BYTES);
      if (OK != status)
        goto exit;

      /* Collect entropy */
      status = EntropyFunc(NULL, pEntropyBuf, entropyCollectLen);
      if (OK != status)
        goto exit;

      /* Reseed */
      status = RANDOM_reseedContext (
        pRandomContext, pEntropyBuf, entropyCollectLen, NULL, 0);
    }
    else
    {
      /* This operator already knows how to reseed itself */
      status = RANDOM_reseedContext(pRandomContext, NULL, 0, NULL, 0);
    }

    /* Reset the reseed bit counter */
    pWrapper->reseedBitCounter = 0;

  }
  else
  {
    MOC_RANDOM_ADD_ENTROPY_BIT(status, pRandomContext, entropyBit)
  }

exit:
  return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS CRYPTO_INTERFACE_getEntropyFunc (
  MGetEntropyFunc *ppEntropyFunc
  )
{
  MSTATUS status;
  MGetEntropyFunc EntropyFunc = NULL;

  status = ERR_NULL_POINTER;
  if (NULL == ppEntropyFunc)
    goto exit;

  /* Determine how entropy will be collected, either using an externally
   * registered function pointer or one of the default Mocana functions */
  if (NULL != RegisteredEntropyFunc)
  {
    EntropyFunc = RegisteredEntropyFunc;
  }
  else
  {
    status = CRYPTO_INTERFACE_getEntropyFuncEx(&EntropyFunc);
    if (OK != status)
      goto exit;
  }

  *ppEntropyFunc = EntropyFunc;
  status = OK;

exit:
  return status;

}

/*----------------------------------------------------------------------------*/

static MSTATUS CRYPTO_INTERFACE_getEntropyFuncEx (
  MGetEntropyFunc *ppEntropyFunc
  )
{
  MSTATUS status;
  MGetEntropyFunc EntropyFunc = NULL;
#ifndef __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__
  ubyte entropySrc = 0;
#endif

  status = ERR_NULL_POINTER;
  if (NULL == ppEntropyFunc)
    goto exit;

#ifndef __DISABLE_DIGICERT_RAND_ENTROPY_THREADS__

  /* Determine the Mocana default entropy collection function based on build
   * flags and initialization options. */
  entropySrc = RANDOM_getEntropySource();

  if (ENTROPY_SRC_INTERNAL == entropySrc)
  {
    EntropyFunc = RNG_SEED_extractDepotBitsEx;
  }
  else
  {
    EntropyFunc = RNG_SEED_extractInitialDepotBitsEx;
  }
#else
  EntropyFunc = RNG_SEED_extractDepotBitsEx;
#endif

  *ppEntropyFunc = EntropyFunc;
  status = OK;

exit:
  return status;

}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_registerEntropyFunc (
  MGetEntropyFunc EntropyFunc,
  ubyte4 entropyLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  if (NULL == EntropyFunc)
    goto exit;

  /* Do we already have a different entropy function registered? */
  status = ERR_INTERNAL_ERROR;
  if ( (NULL != RegisteredEntropyFunc) && (EntropyFunc != RegisteredEntropyFunc) )
    goto exit;

  /* Register the provided function pointer and collection length */
  RegisteredEntropyFunc = EntropyFunc;
  entropyCollectLen = entropyLen;
  status = OK;

exit:
  return status;
}

/*----------------------------------------------------------------------------*/

extern void CRYPTO_INTERFACE_unregisterFuncs (void)
{
  RegisteredEntropyFunc = NULL;
  RegisteredGetPersoStr = NULL;
  entropyCollectLen = MOC_DEFAULT_NUM_ENTROPY_BYTES;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_regsterGetPersoStrCallback (
  MGetPersoStrCallback GetPersoStr
  )
{
MSTATUS status = ERR_NULL_POINTER;
  if (NULL == GetPersoStr)
    goto exit;

  /* Do we already have a different function registered? */
  status = ERR_INTERNAL_ERROR;
  if ( (NULL != RegisteredGetPersoStr) && (GetPersoStr != RegisteredGetPersoStr) )
    goto exit;

  /* Register the provided function pointer */
  RegisteredGetPersoStr = GetPersoStr;
  status = OK;

exit:
  return status;
}

#endif
