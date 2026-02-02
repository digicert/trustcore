/*
 * crypto_interface_dh.c
 *
 * Cryptographic Interface specification for DH.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_DH_INTERNAL__

#include "../crypto/mocasym.h"
#include "../common/initmocana.h"
#include "../crypto/ffc.h"
#include "../crypto/dh.h"
#include "../cap/capasym_dh_params.h"
#include "../crypto_interface/crypto_interface_priv.h"
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_DSA__
#include "../crypto/dsa.h"
#include "../crypto_interface/crypto_interface_dsa.h"
#endif

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_DH__))

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_DIFFIE_HELLMAN__))
#define MOC_DH_ALLOC(_status, _ppNewCtx, _pExtCtx)                            \
    _status = DH_allocateExt(_ppNewCtx, _pExtCtx);
#else
#define MOC_DH_ALLOC(_status, _ppNewCtx, _pExtCtx)                            \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_DIFFIE_HELLMAN__))
#define MOC_DH_ALLOC_SERVER(_status, _pRandomContext, ppNewCtx, _groupNum, _pExtCtx)    \
    _status = DH_allocateServerExt(MOC_DH(hwAccelCtx) _pRandomContext, ppNewCtx, _groupNum, _pExtCtx);
#else
#define MOC_DH_ALLOC_SERVER(_status, _pRandomContext, ppNewCtx, _groupNum, _pExtCtx)    \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_DIFFIE_HELLMAN__))
#define MOC_DH_ALLOC_CLIENT_AUX(_status, _pRandomContext, ppNewCtx, _groupNum, _pExtCtx)\
    _status = DH_allocateClientAuxExt(MOC_DH(hwAccelCtx) _pRandomContext, ppNewCtx, _groupNum, _pExtCtx);
#else
#define MOC_DH_ALLOC_CLIENT_AUX(_status, _pRandomContext, ppNewCtx, _groupNum, _pExtCtx)\
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_DIFFIE_HELLMAN__))
#define MOC_DH_FREE(_status, _ppNewCtx, _ppVlongQueue, _pExtCtx)              \
    _status = DH_freeDhContextExt(_ppNewCtx, _ppVlongQueue, _pExtCtx);
#else
#define MOC_DH_FREE(_status, _ppNewCtx, _ppVlongQueue, _pExtCtx)              \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_DIFFIE_HELLMAN__))
#define MOC_DH_SET_KEY_PARAMETERS(_status, _pTargetCtx, _pSrcTemplate, _pExtCtx)        \
    _status = DH_setKeyParametersExt(MOC_DH(hwAccelCtx) _pTargetCtx, _pSrcTemplate, _pExtCtx);
#else
#define MOC_DH_SET_KEY_PARAMETERS(_status, _pTargetCtx, _pSrcTemplate, _pExtCtx)        \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_DIFFIE_HELLMAN__))
#define MOC_DH_GET_KEY_PARAMETERS_ALLOC(_status, _pTargetTemplate, _pSrcCtx, _keyType, _pExtCtx)  \
    _status = DH_getKeyParametersAllocExt(MOC_DH(hwAccelCtx) _pTargetTemplate, _pSrcCtx, _keyType, _pExtCtx);
#else
#define MOC_DH_GET_KEY_PARAMETERS_ALLOC(_status, _pTargetTemplate, _pSrcCtx, _keyType, _pExtCtx)  \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_DIFFIE_HELLMAN__))
#define MOC_DH_FREE_KEY_TEMPLATE(_status, _pCtx, _pTemplate, _pExtCtx)                  \
    _status = DH_freeKeyTemplateExt(_pCtx, _pTemplate, _pExtCtx);
#else
#define MOC_DH_FREE_KEY_TEMPLATE(_status, _pCtx, _pTemplate, _pExtCtx)                  \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_DIFFIE_HELLMAN__))
#define MOC_DH_GENERATE_KEY_PAIR(_status, _pCtx, _pRandomContext, _numBytes, _pExtCtx)  \
    _status = DH_generateKeyPairExt(MOC_DH(hwAccelCtx) _pCtx, _pRandomContext, _numBytes, _pExtCtx);
#else
#define MOC_DH_GENERATE_KEY_PAIR(_status, _pCtx, _pRandomContext, _numBytes, _pExtCtx)  \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_DIFFIE_HELLMAN__))
#define MOC_DH_GET_PUBLIC_KEY(_status, _pCtx, _ppPublicKey, _pPublicKeyLen, _pExtCtx)   \
    _status = DH_getPublicKeyExt(MOC_DH(hwAccelCtx) _pCtx, _ppPublicKey, _pPublicKeyLen, _pExtCtx);
#else
#define MOC_DH_GET_PUBLIC_KEY(_status, _pCtx, _ppPublicKey, _pPublicKeyLen, _pExtCtx)   \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_DIFFIE_HELLMAN__))
#define MOC_DH_COMPUTE_KEY_EX(_status, _pCtx, _pRndCtx, _pOtherPartysPublicKey, _publicKeyLen, _ppSharedSecret, _pSharedSecretLen, _pExtCtx)    \
    _status = DH_computeKeyExchangeExExt(MOC_DH(hwAccelCtx) _pCtx, _pRndCtx, _pOtherPartysPublicKey, _publicKeyLen, _ppSharedSecret, _pSharedSecretLen, _pExtCtx);
#else
#define MOC_DH_COMPUTE_KEY_EX(_status, _pCtx, _pRndCtx, _pOtherPartysPublicKey, _publicKeyLen, _ppSharedSecret, _pSharedSecretLen, _pExtCtx)    \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_DIFFIE_HELLMAN__))
#define MOC_DH_VALIDATE_DOMAIN(_status, _pFipsRngCtx, _pCtx, _hashType, _C, _pSeed, _seedSize, _pIsValid, _pPriKeyLen, _ppVlongQueue)   \
    _status = DH_validateDomainParams(MOC_DH(hwAccelCtx) _pFipsRngCtx, _pCtx, _hashType, _C, _pSeed, _seedSize, _pIsValid, _pPriKeyLen, _ppVlongQueue)
#else
#define MOC_DH_VALIDATE_DOMAIN(_status, _pFipsRngCtx, _pCtx, _hashType, _C, _pSeed, _seedSize, _pIsValid, _pPriKeyLen, _ppVlongQueue)   \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_DIFFIE_HELLMAN__))
#define MOC_DH_VALIDATE_FIPS1864(_status, _pFipsRngCtx, _pCtx, _hashType, _C, _pSeed, _seedSize, _pIsValid, _ppVlongQueue)   \
    _status = DH_verifyPQ_FIPS1864(MOC_DH(hwAccelCtx) _pFipsRngCtx, _pCtx, _hashType, _C, _pSeed, _seedSize, _pIsValid, _ppVlongQueue)
#else
#define MOC_DH_VALIDATE_FIPS1864(_status, _pFipsRngCtx, _pCtx, _hashType, _C, _pSeed, _seedSize, _pIsValid, _ppVlongQueue)   \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_DIFFIE_HELLMAN__))
#define MOC_DH_VALIDATE_SAFE_PG(_status, _pCtx, _pIsValid, _pPriKeyLen, _ppVlongQueue)   \
    _status = DH_verifySafePG(_pCtx, _pIsValid, _pPriKeyLen, _ppVlongQueue)
#else
#define MOC_DH_VALIDATE_SAFE_PG(_status, _pCtx, _pIsValid, _pPriKeyLen, _ppVlongQueue)   \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_DIFFIE_HELLMAN__))
#define MOC_DH_VALIDATE_G(_status, _pCtx, _pIsValid, _ppVlongQueue);   \
    _status = DH_verifyG(MOC_DH(hwAccelCtx) _pCtx, _pIsValid, _ppVlongQueue)
#else
#define MOC_DH_VALIDATE_G(_status, _pCtx, _pIsValid, _ppVlongQueue);   \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_DIFFIE_HELLMAN__))
#define MOC_DH_GET_PBYTE_STRING(_status, _groupNum, _ppBytes, _pLen);   \
    _status = DH_getPByteString(_groupNum, _ppBytes, _pLen)
#else
#define MOC_DH_GET_PBYTE_STRING(_status, _groupNum, _ppBytes, _pLen);   \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_DIFFIE_HELLMAN__)) && \
    (defined(__ENABLE_DIGICERT_DH_MODES__))
#define MOC_DH_KEY_AGREE(_status, _mode, _pRandom, _pStatic, _pEphem, _pOtherStatic, _otherStaticLen, _pOtherEphem, _otherEphemLen, _ppSS, _pSSlen); \
    _status = DH_keyAgreementScheme(MOC_DH(hwAccelCtx) _mode, _pRandom, _pStatic, _pEphem, _pOtherStatic, _otherStaticLen, _pOtherEphem, _otherEphemLen, _ppSS, _pSSlen)
#else
#define MOC_DH_KEY_AGREE(_status, _mode, _pRandom, _pStatic, _pEphem, _pOtherStatic, _otherStaticLen, _pOtherEphem, _otherEphemLen, _ppSS, _pSSlen); \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#include "../cap/capasym_dh_params.h"

/* 768 bit prime */
static const ubyte gpGroup1[] = MOCANA_DH_group1;

/* 1024 bit prime */
static const ubyte gpGroup2[] = MOCANA_DH_group2;

/* 1536 bit prime */
static const ubyte gpGroup5[] = MOCANA_DH_group5;

/* 2048 bit prime */
static const ubyte gpGroup14[] = MOCANA_DH_group14;

/* 3072 bit prime */
static const ubyte gpGroup15[] = MOCANA_DH_group15;

/* 4096 bit prime */
static const ubyte gpGroup16[] = MOCANA_DH_group16;

/* 6144 bit prime */
static const ubyte gpGroup17[] = MOCANA_DH_group17;

/* 8192 bit prime */
static const ubyte gpGroup18[] = MOCANA_DH_group18;

/* 2048 bit prime */
static const ubyte gpGroup24[] = MOCANA_DH_group24;

#ifndef __DISABLE_DIGICERT_DH_RFC7919_GROUPS__
/* ffdhe2048 */
static const ubyte gpGroupFFDHE2048[] = MOCANA_DH_FFDHE2048;

/* ffdhe3072 */
static const ubyte gpGroupFFDHE3072[] = MOCANA_DH_FFDHE3072;

/* ffdhe4096 */
static const ubyte gpGroupFFDHE4096[] = MOCANA_DH_FFDHE4096;

/* ffdhe6144 */
static const ubyte gpGroupFFDHE6144[] = MOCANA_DH_FFDHE6144;

/* ffdhe8192 */
static const ubyte gpGroupFFDHE8192[] = MOCANA_DH_FFDHE8192;
#endif

#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__ */

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_allocateExt (
  diffieHellmanContext **ppNewCtx,
  void *pExtCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 algoStatus, index;
  MocCtx pMocCtx = NULL;
  diffieHellmanContext *pNewCtx = NULL;
  MocAsymKey pNewPriKey = NULL;
  MocAsymKey pNewPubKey = NULL;

  if (NULL == ppNewCtx)
    goto exit;

  /* Determine if we have an DH implementation */
  status = CRYPTO_INTERFACE_checkAsymAlgoStatus(moc_alg_dh, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    /* Get a reference to the MocCtx registered with the crypto interface */
    status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
    if (OK != status)
      goto exit;

    /* Get an empty DH private key from the MocCtx */
    status = CRYPTO_getAsymObjectFromIndex (
      index, pMocCtx, NULL, MOC_ASYM_KEY_TYPE_PRIVATE, &pNewPriKey);
    if (OK != status)
      goto exit;

    /* Get an empty DH public key from the MocCtx */
    status = CRYPTO_getAsymObjectFromIndex (
      index, pMocCtx, NULL, MOC_ASYM_KEY_TYPE_PUBLIC, &pNewPubKey);
    if (OK != status)
      goto exit;

    /* Allocate the DH context */
    status = DIGI_CALLOC((void **)&pNewCtx, 1, sizeof(diffieHellmanContext));
    if (OK != status)
      goto exit;

    /* Set the newly created keys inside the DH ctx */
    pNewCtx->pPrivateKey = pNewPriKey;
    pNewPriKey = NULL;
    pNewCtx->pPublicKey = pNewPubKey;
    pNewPubKey = NULL;

    /* Mark this object to indicate that it is using an alternate
     * implementation through the crypto interface */
    pNewCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

    /* Set the callers pointer */
    *ppNewCtx = pNewCtx;
    pNewCtx = NULL;
  }
  else
  {
    MOC_DH_ALLOC(status, ppNewCtx, pExtCtx)
  }

exit:

  if (NULL != pNewPriKey)
  {
    CRYPTO_freeMocAsymKey(&pNewPriKey, NULL);
  }
  if (NULL != pNewPubKey)
  {
    CRYPTO_freeMocAsymKey(&pNewPubKey, NULL);
  }
  if (NULL != pNewCtx)
  {
    DIGI_FREE((void **)&pNewCtx);
  }

  return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_allocate (
  diffieHellmanContext **ppNewCtx
  )
{
  return CRYPTO_INTERFACE_DH_allocateExt(ppNewCtx, NULL);
}

/* ---------------------------------------------------------------------------------------- */

static MSTATUS CRYPTO_INTERFACE_DH_allocateAndSet (
  randomContext *pRandomContext,
  diffieHellmanContext **ppNewCtx,
  MDhKeyGenParams *pKeyGenParams,
  ubyte4 index
)
{
  MSTATUS status;
  MocCtx pMocCtx = NULL;
  diffieHellmanContext *pNewCtx = NULL;
  MKeyOperator keyOperator;

  /* Allocate the DH context */
  status = DIGI_CALLOC((void **)&pNewCtx, 1, sizeof(diffieHellmanContext));
  if (OK != status)
    goto exit;

  /* Get a reference to the MocCtx registered with the crypto interface */
  status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
  if (OK != status)
    goto exit;

  /* Get the DH operator */
  status = CRYPTO_getAsymOperatorAndInfoFromIndex(index, pMocCtx, &keyOperator, NULL);
  if (OK != status)
    goto exit;

  /* Generate the server or client key */
  status = CRYPTO_generateKeyPair(keyOperator, (void *) pKeyGenParams, pMocCtx, RANDOM_rngFun, (void *) pRandomContext,
                                  &(pNewCtx->pPublicKey), &(pNewCtx->pPrivateKey), NULL);
  if (OK != status)
    goto exit;

  /* Mark this object to indicate that it is using an alternate
   * implementation through the crypto interface */
  pNewCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

  *ppNewCtx = pNewCtx; pNewCtx = NULL;

exit:

  if (NULL != pNewCtx)
  {
    DIGI_FREE((void **)&pNewCtx);
  }

  return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_allocateServerExt (
  MOC_DH(hwAccelDescr hwAccelCtx)
  randomContext *pRandomContext,
  diffieHellmanContext **ppNewCtx,
  ubyte4 groupNum,
  void *pExtCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 algoStatus, index;

  if (NULL == ppNewCtx)
    goto exit;

  /* Determine if we have an DH implementation */
  status = CRYPTO_INTERFACE_checkAsymAlgoStatus(moc_alg_dh, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    MDhKeyGenParams keyGenParams = {0};
    MDhKeyTemplate keyTemplate = {0};

    keyGenParams.isServer = TRUE;
    keyTemplate.groupNum = groupNum;
    /* default yLen key size. operator can override this since they know the group num */
    keyTemplate.yLen = MOCANA_DH_NUM_Y_BYTES;
    keyGenParams.pKeyTemplate = &keyTemplate;

    status = CRYPTO_INTERFACE_DH_allocateAndSet(pRandomContext, ppNewCtx, &keyGenParams, index);
  }
  else
  {
    MOC_DH_ALLOC_SERVER(status, pRandomContext, ppNewCtx, groupNum, pExtCtx)
  }

exit:

  return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_allocateServer (
  MOC_DH(hwAccelDescr hwAccelCtx)
  randomContext *pRandomContext,
  diffieHellmanContext **ppNewCtx,
  ubyte4 groupNum
  )
{
  return CRYPTO_INTERFACE_DH_allocateServerExt(MOC_DH(hwAccelCtx) pRandomContext, ppNewCtx, groupNum, NULL);
}

/* ---------------------------------------------------------------------------------------- */

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_allocateClientAuxExt (
  MOC_DH(hwAccelDescr hwAccelCtx)
  randomContext *pRandomContext,
  diffieHellmanContext **ppNewCtx,
  ubyte4 groupNum,
  void *pExtCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 algoStatus, index;

  if (NULL == ppNewCtx)
    goto exit;

  /* Determine if we have an DH implementation */
  status = CRYPTO_INTERFACE_checkAsymAlgoStatus(moc_alg_dh, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    MDhKeyGenParams keyGenParams = {0};
    MDhKeyTemplate keyTemplate = {0};

    keyGenParams.isServer = FALSE;
    keyTemplate.groupNum = groupNum;
    /* default yLen key size. operator can override this since they know the group num */
    keyTemplate.yLen = MOCANA_DH_NUM_Y_BYTES;
    keyGenParams.pKeyTemplate = &keyTemplate;

    status = CRYPTO_INTERFACE_DH_allocateAndSet(pRandomContext, ppNewCtx, &keyGenParams, index);
  }
  else
  {
    MOC_DH_ALLOC_CLIENT_AUX(status, pRandomContext, ppNewCtx, groupNum, pExtCtx)
  }

exit:

  return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_allocateClientAux (
  MOC_DH(hwAccelDescr hwAccelCtx)
  randomContext *pRandomContext,
  diffieHellmanContext **ppNewCtx,
  ubyte4 groupNum
  )
{
  return CRYPTO_INTERFACE_DH_allocateClientAuxExt(MOC_DH(hwAccelCtx) pRandomContext, ppNewCtx, groupNum, NULL);
}

/* ---------------------------------------------------------------------------------------- */

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_freeDhContextExt (
  diffieHellmanContext **ppDhCtx,
  vlong **ppVlongQueue,
  void *pExtCtx
  )
{
  MSTATUS status, fStatus;

  status = ERR_NULL_POINTER;
  if (NULL == ppDhCtx || NULL == *ppDhCtx)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == (*ppDhCtx)->enabled)
  {

    status = CRYPTO_freeMocAsymKey(&((*ppDhCtx)->pPrivateKey), NULL);

    fStatus = CRYPTO_freeMocAsymKey(&((*ppDhCtx)->pPublicKey), NULL);
    if (OK == status)
      status = fStatus;

    fStatus = DIGI_FREE((void **)ppDhCtx);
    if (OK == status)
      status = fStatus;
  }
  else
  {
    MOC_DH_FREE(status, ppDhCtx, ppVlongQueue, pExtCtx)
  }

exit:

  return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_freeDhContext (
  diffieHellmanContext **ppDhCtx,
  vlong **ppVlongQueue
  )
{
  return CRYPTO_INTERFACE_DH_freeDhContextExt(ppDhCtx, ppVlongQueue, NULL);
}

/* ---------------------------------------------------------------------------------------- */

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_setKeyParametersExt (
  MOC_DH(hwAccelDescr hwAccelCtx)
  diffieHellmanContext *pTargetCtx,
  MDhKeyTemplate *pSrcTemplate,
  void *pExtCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pTargetCtx)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pTargetCtx->enabled)
  {

    if (NULL == pSrcTemplate)
      goto exit;

    if (pSrcTemplate->yLen && NULL != pSrcTemplate->pY)
    {
      /* Set the private key data */
      status = CRYPTO_setKeyData(pTargetCtx->pPrivateKey, (void *) pSrcTemplate);
      if (OK != status)
        goto exit;

      /* Delete any previously created public key */
      status = CRYPTO_freeMocAsymKey(&(pTargetCtx->pPublicKey), NULL);
      if (OK != status)
        goto exit;

      /* Create a new public from the private we just made */
      status = CRYPTO_getPubFromPri (pTargetCtx->pPrivateKey, &(pTargetCtx->pPublicKey), NULL);
    }
    else
    {
      /* Set the public key data */
      status = CRYPTO_setKeyData(pTargetCtx->pPublicKey, (void *) pSrcTemplate);
    }
  }
  else
  {
    MOC_DH_SET_KEY_PARAMETERS(status, pTargetCtx, pSrcTemplate, pExtCtx)
  }

exit:

  return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_setKeyParameters (
  MOC_DH(hwAccelDescr hwAccelCtx)
  diffieHellmanContext *pTargetCtx,
  MDhKeyTemplate *pSrcTemplate
  )
{
  return CRYPTO_INTERFACE_DH_setKeyParametersExt(MOC_DH(hwAccelCtx) pTargetCtx, pSrcTemplate, NULL);
}

/* ---------------------------------------------------------------------------------------- */

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_getKeyParametersAllocExt (
  MOC_DH(hwAccelDescr hwAccelCtx)
  MDhKeyTemplate *pTargetTemplate,
  diffieHellmanContext *pSrcCtx,
  ubyte keyType,
  void *pExtCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MocAsymKey pKeyToUse = NULL;

  if (NULL == pSrcCtx)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pSrcCtx->enabled)
  {
    if (NULL == pTargetTemplate)
      goto exit;

    /* Identify which MocAsymKey to retrieve from within pKey */
    if (MOC_GET_PRIVATE_KEY_DATA == keyType)
    {
      /* If the caller specified they want private key data, but there is no
       * private key, that's an error */
      if (NULL == pSrcCtx->pPrivateKey)
        goto exit;

      pKeyToUse = pSrcCtx->pPrivateKey;
    }
    else if (MOC_GET_PUBLIC_KEY_DATA == keyType)
    {
      /* If the caller requested public key data, and a public key exists, use
       * that. If not, try to use a private key instead */
      if (NULL != pSrcCtx->pPublicKey)
        pKeyToUse = pSrcCtx->pPublicKey;
      else if (NULL != pSrcCtx->pPrivateKey)
        pKeyToUse = pSrcCtx->pPrivateKey;
      else
        goto exit;

    }
    else
    {
      status = ERR_INVALID_ARG;
      goto exit;
    }

    status = CRYPTO_getKeyDataAlloc (pKeyToUse, (void *) pTargetTemplate, keyType);
  }
  else
  {
    MOC_DH_GET_KEY_PARAMETERS_ALLOC(status, pTargetTemplate, pSrcCtx, keyType, pExtCtx)
  }

exit:

  return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_getKeyParametersAlloc (
  MOC_DH(hwAccelDescr hwAccelCtx)
  MDhKeyTemplate *pTargetTemplate,
  diffieHellmanContext *pSrcCtx,
  ubyte keyType
  )
{
  return CRYPTO_INTERFACE_DH_getKeyParametersAllocExt(MOC_DH(hwAccelCtx) pTargetTemplate, pSrcCtx, keyType, NULL);
}

/* ---------------------------------------------------------------------------------------- */

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_freeKeyTemplateExt (
  diffieHellmanContext *pCtx,
  MDhKeyTemplate *pTemplate,
  void *pExtCtx
  )
{
  MSTATUS status = OK;

  /* allow pTemplate NULL and no-op in that case */
  if (NULL == pTemplate)
    goto exit;

  /*
   If the caller provided a CRYPTO_INTERFACE_ALGO_ENABLED key try to use
   an operator to free the template
   */
  if (NULL != pCtx && CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  {
    /* Request that the operator free the template */
    status = CRYPTO_freeKeyTemplate(pCtx->pPublicKey, (void *)pTemplate);
  }
  else
  {
    MOC_DH_FREE_KEY_TEMPLATE(status, pCtx, pTemplate, pExtCtx)
  }

  /* If the status is not OK, it is likely that the operator did not
   * implement that op code. Attempt to free it by hand now */
  if ( OK != status || NULL == pCtx )
  {
    if (NULL != pTemplate->pG)
    {
      status = DIGI_MEMSET(pTemplate->pG, 0x00, pTemplate->gLen);
      if (OK != status)
        goto exit;

      status = DIGI_FREE((void **)&pTemplate->pG);
      if (OK != status)
        goto exit;

      pTemplate->gLen = 0;
    }

    if (NULL != pTemplate->pP)
    {
      status = DIGI_MEMSET(pTemplate->pP, 0x00, pTemplate->pLen);
      if (OK != status)
        goto exit;

      status = DIGI_FREE((void **)&pTemplate->pP);
      if (OK != status)
        goto exit;

      pTemplate->pLen = 0;
    }

    if (NULL != pTemplate->pQ)
    {
      status = DIGI_MEMSET(pTemplate->pQ, 0x00, pTemplate->qLen);
      if (OK != status)
        goto exit;

      status = DIGI_FREE((void **)&pTemplate->pQ);
      if (OK != status)
        goto exit;

      pTemplate->qLen = 0;
    }

    if (NULL != pTemplate->pY)
    {
      status = DIGI_MEMSET(pTemplate->pY, 0x00, pTemplate->yLen);
      if (OK != status)
        goto exit;

      status = DIGI_FREE((void **)&pTemplate->pY);
      if (OK != status)
        goto exit;

      pTemplate->yLen = 0;
    }

    if (NULL != pTemplate->pF)
    {
      status = DIGI_MEMSET(pTemplate->pF, 0x00, pTemplate->fLen);
      if (OK != status)
        goto exit;

      status = DIGI_FREE ((void **) &pTemplate->pF);
      if (OK != status)
        goto exit;

      pTemplate->fLen = 0;
    }

    status = OK;
  }

exit:

  return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_freeKeyTemplate (
  diffieHellmanContext *pCtx,
  MDhKeyTemplate *pTemplate
  )
{
  return CRYPTO_INTERFACE_DH_freeKeyTemplateExt(pCtx, pTemplate, NULL);
}

/* ---------------------------------------------------------------------------------------- */

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_generateKeyPairExt (
  MOC_DH(hwAccelDescr hwAccelCtx)
  diffieHellmanContext *pCtx,
  randomContext *pRandomContext,
  ubyte4 numBytes,
  void *pExtCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MSTATUS fstatus;
  MDhKeyGenParams keyGenParams = {0};
  MDhKeyTemplate keyTemplate = {0};

  if (NULL == pCtx)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  {
    ubyte4 algoStatus, index;
    MocCtx pMocCtx = NULL;
    MKeyOperator keyOperator;

    status = ERR_INVALID_ARG;
    if (!numBytes)
      goto exit;

    /* Get a reference to the MocCtx registered with the crypto interface */
    status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
    if (OK != status)
      goto exit;

    /* get the index of the operator */
    status = CRYPTO_INTERFACE_checkAsymAlgoStatus(moc_alg_dh, &algoStatus, &index);
    if (OK != status)
      goto exit;

    /* get the operator */
    status = CRYPTO_getAsymOperatorAndInfoFromIndex(index, pMocCtx, &keyOperator, NULL);
    if (OK != status)
      goto exit;

    /* get the group params from the public key, whether a custom group or not
     Also set yLen to be the number of bytes we want for the requested private key */;
    keyGenParams.pKeyTemplate = &keyTemplate;

    status = CRYPTO_getKeyDataAlloc (pCtx->pPublicKey, (void *) &keyTemplate, MOC_GET_PUBLIC_KEY_DATA);
    if (OK != status)
      goto exit;

    keyTemplate.groupNum = DH_GROUP_TBD;
    keyTemplate.yLen = numBytes;

    /* Generate the new private and public keys (destroying any old ones) */
    status = CRYPTO_generateKeyPair(keyOperator, (void *) &keyGenParams, pMocCtx, RANDOM_rngFun, (void *) pRandomContext,
                                    &(pCtx->pPublicKey), &(pCtx->pPrivateKey), NULL);
  }
  else
  {
    MOC_DH_GENERATE_KEY_PAIR(status, pCtx, pRandomContext, numBytes, pExtCtx)
  }

exit:

  if(NULL != keyGenParams.pKeyTemplate)
  {
     fstatus = CRYPTO_INTERFACE_DH_freeKeyTemplate(pCtx, keyGenParams.pKeyTemplate);
     if (OK == status)
       status = fstatus;
  }

  return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_generateKeyPair (
  MOC_DH(hwAccelDescr hwAccelCtx)
  diffieHellmanContext *pCtx,
  randomContext *pRandomContext,
  ubyte4 numBytes
  )
{
  return CRYPTO_INTERFACE_DH_generateKeyPairExt(MOC_DH(hwAccelCtx) pCtx, pRandomContext, numBytes, NULL);
}

/* ---------------------------------------------------------------------------------------- */

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_getPublicKeyExt (
  MOC_DH(hwAccelDescr hwAccelCtx)
  diffieHellmanContext *pCtx,
  ubyte **ppPublicKey,
  ubyte4 *pPublicKeyLen,
  void *pExtCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte *pPublicKey = NULL;
  MDhKeyTemplate keyTemplate = {0};

  if (NULL == pCtx)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  {
    if (NULL == ppPublicKey || NULL == pPublicKeyLen)
      goto exit;

    /* We need a public key for this operation */
    if (NULL == pCtx->pPublicKey)
      goto exit;

    /* Get the public key data from the operator */
    status = CRYPTO_getKeyDataAlloc (pCtx->pPublicKey, (void *)&keyTemplate, MOC_GET_PUBLIC_KEY_DATA);
    if (OK != status)
      goto exit;

    status = DIGI_MALLOC((void **) &pPublicKey, keyTemplate.fLen);
    if (OK != status)
      goto exit;

    /* Copy the public key data to the provided buffer */
    status = DIGI_MEMCPY(pPublicKey, keyTemplate.pF, keyTemplate.fLen);
    if (OK != status)
      goto exit;

    *ppPublicKey = pPublicKey; pPublicKey = NULL;
    *pPublicKeyLen = keyTemplate.fLen;

  }
  else
  {
    MOC_DH_GET_PUBLIC_KEY(status, pCtx, ppPublicKey, pPublicKeyLen, pExtCtx)
  }

exit:

  if (NULL != pPublicKey)
  {
    DIGI_MEMSET(pPublicKey, 0x00, keyTemplate.fLen);
    DIGI_FREE((void **) &pPublicKey);
  }

  /* free the key template, ok to ignore return code */
  CRYPTO_INTERFACE_DH_freeKeyTemplate(pCtx, &keyTemplate);

  return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_getPublicKey (
  MOC_DH(hwAccelDescr hwAccelCtx)
  diffieHellmanContext *pCtx,
  ubyte **ppPublicKey,
  ubyte4 *pPublicKeyLen
  )
{
  return CRYPTO_INTERFACE_DH_getPublicKeyExt(MOC_DH(hwAccelCtx) pCtx, ppPublicKey, pPublicKeyLen, NULL);
}

/* ---------------------------------------------------------------------------------------- */

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_computeKeyExchangeExExt (
  MOC_DH(hwAccelDescr hwAccelCtx)
  diffieHellmanContext *pCtx,
  randomContext *pRandomContext,
  ubyte *pOtherPartysPublicKey,
  ubyte4 publicKeyLen,
  ubyte **ppSharedSecret,
  ubyte4 *pSharedSecretLen,
  void *pExtCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 ssLen = 0;
  ubyte *pSS = NULL;

  if (NULL == pCtx)
    goto exit;

  /* Is this a crypto interface key? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  {
    if (NULL == pOtherPartysPublicKey || NULL == ppSharedSecret || NULL == pSharedSecretLen || NULL == pCtx->pPrivateKey)
      goto exit;

    status = ERR_BAD_CLIENT_E;
    if (!publicKeyLen)
      goto exit;

    /* get the shared secret length */
    status = CRYPTO_computeSharedSecret (pCtx->pPrivateKey, NULL, pOtherPartysPublicKey, publicKeyLen, NULL,
                                         NULL, 0, &ssLen, NULL);
    if (OK == status)
      status = ERR_CRYPTO_FAILURE;
    if (ERR_BUFFER_TOO_SMALL != status)
      goto exit;

    status = DIGI_MALLOC((void **)&pSS, ssLen);
    if (OK != status)
      goto exit;

    if (NULL != pRandomContext)
    {
      MRandomGenInfo randInfo = {0};

      randInfo.RngFun = RANDOM_rngFun;
      randInfo.pRngFunArg = pRandomContext;

      status = CRYPTO_computeSharedSecret (pCtx->pPrivateKey, NULL, pOtherPartysPublicKey, publicKeyLen, (void *) &randInfo,
                                           pSS, ssLen, &ssLen, NULL);
    }
    else
    {
      status = CRYPTO_computeSharedSecret (pCtx->pPrivateKey, NULL, pOtherPartysPublicKey, publicKeyLen, NULL,
                                           pSS, ssLen, &ssLen, NULL);
    }
    if (OK != status)
      goto exit;

    *ppSharedSecret = pSS; pSS = NULL;
    *pSharedSecretLen = ssLen;

  }
  else
  {
    MOC_DH_COMPUTE_KEY_EX(status, pCtx, pRandomContext, pOtherPartysPublicKey, publicKeyLen, ppSharedSecret, pSharedSecretLen, pExtCtx)
  }

exit:

  if (NULL != pSS)
  {
    DIGI_MEMSET(pSS, 0x00, ssLen);
    DIGI_FREE((void **) &pSS);
  }

  return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_computeKeyExchangeEx (
  MOC_DH(hwAccelDescr hwAccelCtx)
  diffieHellmanContext *pCtx,
  randomContext *pRandomContext,
  ubyte *pOtherPartysPublicKey,
  ubyte4 publicKeyLen,
  ubyte **ppSharedSecret,
  ubyte4 *pSharedSecretLen
  )
{
  return CRYPTO_INTERFACE_DH_computeKeyExchangeExExt(MOC_DH(hwAccelCtx) pCtx, pRandomContext, pOtherPartysPublicKey, publicKeyLen, ppSharedSecret, pSharedSecretLen, NULL);
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_keyAgreementScheme(
  MOC_DH(hwAccelDescr hwAccelCtx)
  ubyte4 mode,
  randomContext *pRandomContext,
  diffieHellmanContext *pStatic, 
  diffieHellmanContext *pEphemeral, 
  ubyte *pOtherPartysStatic, 
  ubyte4 otherStaticLen,
  ubyte *pOtherPartysEphemeral,
  ubyte4 otherEphemeralLen,
  ubyte **ppSharedSecret,
  ubyte4 *pSharedSecretLen)
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte *pSS = NULL;
  ubyte4 ssLen = 0;
  ubyte *pSS1 = NULL;
  ubyte4 ss1Len = 0;
  ubyte *pSS2 = NULL;
  ubyte4 ss2Len = 0;

  if (NULL == pEphemeral && NULL == pStatic)
    goto exit;

  /* Is one of them a crypto interface key? */
  if ( (NULL != pStatic && CRYPTO_INTERFACE_ALGO_ENABLED == pStatic->enabled) || 
       (NULL != pEphemeral && CRYPTO_INTERFACE_ALGO_ENABLED == pEphemeral->enabled) )
  {

    if (NULL == ppSharedSecret || NULL == pSharedSecretLen)
        goto exit;

    switch (mode)
    {
        /* no operators yet built to support MQV */
        case MQV2:
        case MQV1_U:
        case MQV1_V:
            
            status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
            break;

        case DH_HYBRID1:
             
            /* calculate Z_s */
            status = CRYPTO_INTERFACE_DH_computeKeyExchangeExExt(MOC_DH(hwAccelCtx) pStatic, pRandomContext, pOtherPartysStatic, otherStaticLen, &pSS1, &ss1Len, NULL);
            if (OK != status)
                goto exit;

            /* calculate Z_e */
            status = CRYPTO_INTERFACE_DH_computeKeyExchangeExExt(MOC_DH(hwAccelCtx) pEphemeral, pRandomContext, pOtherPartysEphemeral, otherEphemeralLen, &pSS2, &ss2Len, NULL);
            if (OK != status)
                goto exit;
                 
            /* Z = Z_e Z_s */
            ssLen = ss1Len + ss2Len;
            status = DIGI_MALLOC((void **) &pSS, ssLen);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSS, pSS2, ss2Len);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSS + ss2Len, pSS1, ss1Len);
            if (OK != status)
                goto exit;

            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;
            break;

        case DH_EPHEMERAL:

            /* calculate Z = Z_e */
            status = CRYPTO_INTERFACE_DH_computeKeyExchangeExExt(MOC_DH(hwAccelCtx) pEphemeral, pRandomContext, pOtherPartysEphemeral, otherEphemeralLen, &pSS, &ssLen, NULL);
            if (OK != status)
                goto exit;

            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;
            break;
            
        case DH_HYBRID_ONE_FLOW_U:
            
            /* calculate Z_s */
            status = CRYPTO_INTERFACE_DH_computeKeyExchangeExExt(MOC_DH(hwAccelCtx) pStatic, pRandomContext, pOtherPartysStatic, otherStaticLen, &pSS1, &ss1Len, NULL);
            if (OK != status)
                goto exit;

            /* calculate Z_e */
            status = CRYPTO_INTERFACE_DH_computeKeyExchangeExExt(MOC_DH(hwAccelCtx) pEphemeral, pRandomContext, pOtherPartysStatic, otherStaticLen, &pSS2, &ss2Len, NULL);
            if (OK != status)
                goto exit;
                             
            /* Z = Z_e Z_s */
            ssLen = ss1Len + ss2Len;
            status = DIGI_MALLOC((void **) &pSS, ssLen);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSS, pSS2, ss2Len);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSS + ss2Len, pSS1, ss1Len);
            if (OK != status)
                goto exit;

            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;
            break;

        case DH_HYBRID_ONE_FLOW_V:

            /* calculate Z_s */
            status = CRYPTO_INTERFACE_DH_computeKeyExchangeExExt(MOC_DH(hwAccelCtx) pStatic, pRandomContext, pOtherPartysStatic, otherStaticLen, &pSS1, &ss1Len, NULL);
            if (OK != status)
                goto exit;

            /* calculate Z_e */
            status = CRYPTO_INTERFACE_DH_computeKeyExchangeExExt(MOC_DH(hwAccelCtx) pStatic, pRandomContext, pOtherPartysEphemeral, otherEphemeralLen, &pSS2, &ss2Len, NULL);
            if (OK != status)
                goto exit;
                 
            /* Z = Z_e Z_s */
            ssLen = ss1Len + ss2Len;
            status = DIGI_MALLOC((void **) &pSS, ssLen);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSS, pSS2, ss2Len);
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY(pSS + ss2Len, pSS1, ss1Len);
            if (OK != status)
                goto exit;

            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;
            break;

        case DH_ONE_FLOW_U:
            
            /* calculate Z */
            status = CRYPTO_INTERFACE_DH_computeKeyExchangeExExt(MOC_DH(hwAccelCtx) pEphemeral, pRandomContext, pOtherPartysStatic, otherStaticLen, &pSS, &ssLen, NULL);
            if (OK != status)
                goto exit;
                 
            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;

            break;

        case DH_ONE_FLOW_V:

            /* calculate Z */
            status = CRYPTO_INTERFACE_DH_computeKeyExchangeExExt(MOC_DH(hwAccelCtx) pStatic, pRandomContext, pOtherPartysEphemeral, otherEphemeralLen, &pSS, &ssLen, NULL);
            if (OK != status)
                goto exit;
                 
            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;

            break;

        case DH_STATIC:
            
            /* calculate Z = Z_s */
            status = CRYPTO_INTERFACE_DH_computeKeyExchangeExExt(MOC_DH(hwAccelCtx) pStatic, pRandomContext, pOtherPartysStatic, otherStaticLen, &pSS, &ssLen, NULL);
            if (OK != status)
                goto exit;
                 
            *ppSharedSecret = pSS; pSS = NULL;
            *pSharedSecretLen = ssLen;

            break;

        default:
            status = ERR_INVALID_ARG;
    }
  }
  else
  {
    MOC_DH_KEY_AGREE(status, mode, pRandomContext, pStatic, pEphemeral, pOtherPartysStatic, otherStaticLen, pOtherPartysEphemeral, otherEphemeralLen, ppSharedSecret, pSharedSecretLen);
  }

exit:

  if (NULL != pSS)
  {
      (void) DIGI_MEMSET_FREE(&pSS, ssLen);
  }

  if (NULL != pSS1)
  {
      (void) DIGI_MEMSET_FREE(&pSS1, ss1Len);
  }

  if (NULL != pSS2)
  {
      (void) DIGI_MEMSET_FREE(&pSS2, ss2Len);
  }

  return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_validateDomainParams(MOC_DH(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
                                                            diffieHellmanContext *pCtx, FFCHashType hashType, ubyte4 C,
                                                            ubyte *pSeed, ubyte4 seedSize, intBoolean *pIsValid, ubyte4 *pPriKeyLen, vlong **ppVlongQueue)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    /* Is this a crypto interface key? */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#else
        /* for now no validation needed */
        if (NULL != pIsValid)
            *pIsValid = TRUE;

        if (NULL != pPriKeyLen)
            *pPriKeyLen = MOCANA_DH_NUM_Y_BYTES;
        status = OK;
#endif
    }
    else
    {
        MOC_DH_VALIDATE_DOMAIN(status, pFipsRngCtx, pCtx, hashType, C, pSeed, seedSize, pIsValid, pPriKeyLen, ppVlongQueue);
    }

exit:

    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_verifySafePG(diffieHellmanContext *pCtx, intBoolean *pIsValid, ubyte4 *pPriKeyLen, vlong **ppVlongQueue)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    /* Is this a crypto interface key? */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#else
        /* for now no validation needed */
        if (NULL != pIsValid)
            *pIsValid = TRUE;

        if (NULL != pPriKeyLen)
            *pPriKeyLen = MOCANA_DH_NUM_Y_BYTES;

        status = OK;
#endif
    }
    else
    {
        MOC_DH_VALIDATE_SAFE_PG(status, pCtx, pIsValid, pPriKeyLen, ppVlongQueue);
    }

exit:

    return status;
}


MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_verifyPQ_FIPS1864(MOC_DH(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
                                                         diffieHellmanContext *pCtx, FFCHashType hashType, ubyte4 C,
                                                         ubyte *pSeed, ubyte4 seedSize, intBoolean *pIsValid, vlong **ppVlongQueue)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    /* Is this a crypto interface key? */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#else
        /* for now no validation needed */
        if (NULL != pIsValid)
            *pIsValid = TRUE;

        status = OK;
#endif
    }
    else
    {
        MOC_DH_VALIDATE_FIPS1864(status, pFipsRngCtx, pCtx, hashType, C, pSeed, seedSize, pIsValid, ppVlongQueue);
    }

exit:

    return status;
}


MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_verifyG(MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pCtx, intBoolean *pIsValid, vlong **ppVlongQueue)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    /* Is this a crypto interface key? */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
#ifdef __ENABLE_DIGICERT_FIPS_MODULE__
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#else
        /* for now no validation needed */
        if (NULL != pIsValid)
            *pIsValid = TRUE;

        status = OK;
#endif
    }
    else
    {
        MOC_DH_VALIDATE_G(status, pCtx, pIsValid, ppVlongQueue);
    }

exit:

    return status;
}


MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_getPByteString(ubyte4 groupNum, const ubyte **ppBytes, sbyte4 *pLen)
{
    MSTATUS status = ERR_NULL_POINTER;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__

    switch (groupNum)
    {
        case DH_GROUP_1:
            *ppBytes = gpGroup1;
            *pLen = sizeof(gpGroup1);
            break;

        case DH_GROUP_2:
            *ppBytes = gpGroup2;
            *pLen = sizeof(gpGroup2);
            break;

        case DH_GROUP_5:
            *ppBytes = gpGroup5;
            *pLen = sizeof(gpGroup5);
            break;
        case DH_GROUP_14:
            *ppBytes = gpGroup14;
            *pLen = sizeof(gpGroup14);
            break;

        case DH_GROUP_15:
            *ppBytes = gpGroup15;
            *pLen = sizeof(gpGroup15);
            break;

       case DH_GROUP_16:
            *ppBytes = gpGroup16;
            *pLen = sizeof(gpGroup16);
            break;

        case DH_GROUP_17:
            *ppBytes = gpGroup17;
            *pLen = sizeof(gpGroup17);
            break;

        case DH_GROUP_18:
            *ppBytes = gpGroup18;
            *pLen = sizeof(gpGroup18);
            break;
        case DH_GROUP_24:
            *ppBytes = gpGroup24;
            *pLen = sizeof(gpGroup24);
            break;
#ifndef __DISABLE_DIGICERT_DH_RFC7919_GROUPS__

        case DH_GROUP_FFDHE2048:
            *ppBytes = gpGroupFFDHE2048;
            *pLen = sizeof(gpGroupFFDHE2048);
            break;

        case DH_GROUP_FFDHE3072:
            *ppBytes = gpGroupFFDHE3072;
            *pLen = sizeof(gpGroupFFDHE3072);
            break;

        case DH_GROUP_FFDHE4096:
            *ppBytes = gpGroupFFDHE4096;
            *pLen = sizeof(gpGroupFFDHE4096);
            break;

        case DH_GROUP_FFDHE6144:
            *ppBytes = gpGroupFFDHE6144;
            *pLen = sizeof(gpGroupFFDHE6144);
            break;

        case DH_GROUP_FFDHE8192:
            *ppBytes = gpGroupFFDHE8192;
            *pLen = sizeof(gpGroupFFDHE8192);
            break;
#endif

        default:
            status = ERR_CRYPTO_DH_UNSUPPORTED_GROUP;
            goto exit;
    }

#else
    MOC_DH_GET_PBYTE_STRING(status, groupNum, ppBytes, pLen);
#endif

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
exit:
#endif

    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_verifyPublicKey(
    MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pCtx,
    intBoolean *pIsValid,
    vlong **ppVlongQueue)
{
    MSTATUS status = ERR_NULL_POINTER;
    byteBoolean isValid = FALSE;

    if (NULL == pCtx || NULL == pIsValid)
        goto exit;

    /* Other validation handled by the below methods */

    /* Is this a crypto interface key? */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        status = CRYPTO_validateKey(pCtx->pPublicKey, &isValid);
        *pIsValid = (intBoolean) isValid;
    }
    else
    {
#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_DIFFIE_HELLMAN__))
        /* We don't have a passthrough until we're able to edit the FIPS layer. Call FFC code directly.
           Validate G does the same ops as public key validation */
        status = FFC_verifyG(MOC_FFC(hwAccelCtx) COMPUTED_VLONG_P(pCtx), COMPUTED_VLONG_Q(pCtx), 
                             COMPUTED_VLONG_F(pCtx), pIsValid, ppVlongQueue);
#else
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif
    }

exit:

    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_verifyKeyPair(
    MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pCtx,
    intBoolean *pIsValid,
    vlong **ppVlongQueue)
{
    MSTATUS status = ERR_NULL_POINTER;
    byteBoolean vfy = FALSE;
    
    if (NULL == pCtx || NULL == pIsValid)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        status = CRYPTO_validatePubPriMatch (pCtx->pPrivateKey, pCtx->pPublicKey, &vfy);
        *pIsValid = (intBoolean) vfy;
    }
    else
    {
#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_DIFFIE_HELLMAN__))
        vlong *pPubCmp = NULL;
        sbyte4 compare = -1;

        *pIsValid = FALSE;

        /* we must have a private and public key */
        if (NULL == COMPUTED_VLONG_P(pCtx) || NULL == COMPUTED_VLONG_G(pCtx) ||
            NULL == COMPUTED_VLONG_Y(pCtx) || NULL == COMPUTED_VLONG_F(pCtx))
            return ERR_INVALID_INPUT;

        status = VLONG_modexp(MOC_MOD(hwAccelCtx) COMPUTED_VLONG_G(pCtx), COMPUTED_VLONG_Y(pCtx), COMPUTED_VLONG_P(pCtx), &pPubCmp, ppVlongQueue);
        if (OK != status)
            goto exit;

        compare = VLONG_compareSignedVlongs(COMPUTED_VLONG_F(pCtx), pPubCmp);
        
        /* free in any case */
        status = VLONG_freeVlong(&pPubCmp, ppVlongQueue);
        if (0 != compare || OK != status)
        {
          *pIsValid = FALSE;
        }
        else
        {
          *pIsValid = TRUE;
        }
#else
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif
    }

exit:

    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_verifyPrivateKey(
    MOC_DH(hwAccelDescr hwAccelCtx) diffieHellmanContext *pCtx,
    intBoolean *pIsValid,
    vlong **ppVlongQueue)
{
    MSTATUS status = ERR_NULL_POINTER;
    byteBoolean isValid = FALSE;

    if (NULL == pCtx || NULL == pIsValid)
        goto exit;

    /* Other validation handled by the below methods */

    /* Is this a crypto interface key? */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        status = CRYPTO_validateKey(pCtx->pPrivateKey, &isValid);
        *pIsValid = (intBoolean) isValid;
    }
    else
    {
#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_DIFFIE_HELLMAN__))
        vlong *pQminus1 = NULL;
        sbyte4 compare = -1;
        sbyte4 bitLen = 0;

        *pIsValid = FALSE;

        /* we must have a private key */
        if (NULL == COMPUTED_VLONG_Y(pCtx))
            return ERR_INVALID_INPUT;

        /* compare with q if it's there, otherwise check the bitlength against P */
        if (NULL != COMPUTED_VLONG_Q(pCtx))
        {
            /* make q-1 */
            status = VLONG_makeVlongFromVlong(COMPUTED_VLONG_Q(pCtx), &pQminus1, ppVlongQueue);
            if (OK != status)
                goto exit;

            status = VLONG_decrement(pQminus1, ppVlongQueue);
            if (OK != status)
            {
                (void) VLONG_freeVlong(&pQminus1, ppVlongQueue);
                goto exit;
            }
    
            compare = VLONG_compareSignedVlongs(pQminus1, COMPUTED_VLONG_Y(pCtx));
            status = VLONG_freeVlong(&pQminus1, ppVlongQueue);
        }
        else if (NULL != COMPUTED_VLONG_P(pCtx))
        {
            bitLen = (sbyte4) VLONG_bitLength(COMPUTED_VLONG_P(pCtx));
            
            if ((sbyte4) VLONG_bitLength(COMPUTED_VLONG_Y(pCtx)) <= bitLen - 1)
                compare = 1;

            status = OK;
        }
        else
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        
        bitLen = (sbyte4) VLONG_bitLength(COMPUTED_VLONG_Y(pCtx));

        if (OK != status || compare <= 0 || bitLen <= 1)
        {
          *pIsValid = FALSE;
        }
        else
        {
          *pIsValid = TRUE;
        }
#else
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif
    }

exit:

    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DH_generateDomainParams(
    MOC_FFC(hwAccelDescr hwAccelCtx) diffieHellmanContext *pCtx,
    randomContext* pFipsRngCtx,
    ubyte4 keySize,
    ubyte4 qSize,
    FFCHashType hashType,
    vlong **ppVlongQueue
    )
{
    MSTATUS status = ERR_NULL_POINTER, fstatus = OK;

    if (NULL == pCtx)
        goto exit;

    /* Other validation handled by the below methods */

    /* Is this a crypto interface key? */
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_DIFFIE_HELLMAN__)) && \
    (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_DSA__))

        /* Until we can modify the FIPS layer we'll use DSA's paramgen */
        DSAKey *pDsaKey = NULL;

        status = CRYPTO_INTERFACE_DSA_createKey (&pDsaKey);
        if (OK != status)
            goto exit;

        status = CRYPTO_INTERFACE_DSA_generateKeyAux2 (MOC_DSA(hwAccelCtx) pFipsRngCtx, pDsaKey, keySize,
                                                       qSize, (DSAHashType) hashType, ppVlongQueue);
        if (OK != status)
            goto exit_internal;

        /* free any existing params and then copy from the DSA key */
        if (NULL != COMPUTED_VLONG_P(pCtx))
        {
            status = VLONG_freeVlong(&COMPUTED_VLONG_P(pCtx), ppVlongQueue);
            if (OK != status)
                goto exit_internal;
        }
  
        if (NULL != COMPUTED_VLONG_Q(pCtx))
        {
            status = VLONG_freeVlong(&COMPUTED_VLONG_Q(pCtx), ppVlongQueue);
            if (OK != status)
                goto exit_internal;
        }

        if (NULL != COMPUTED_VLONG_G(pCtx))
        {
            status = VLONG_freeVlong(&COMPUTED_VLONG_G(pCtx), ppVlongQueue);
            if (OK != status)
                goto exit_internal;
        }

        status = VLONG_makeVlongFromVlong(DSA_P(pDsaKey), &COMPUTED_VLONG_P(pCtx), ppVlongQueue);
        if (OK != status)
            goto exit_internal;

        status = VLONG_makeVlongFromVlong(DSA_Q(pDsaKey), &COMPUTED_VLONG_Q(pCtx), ppVlongQueue);
        if (OK != status)
            goto exit_internal;

        status = VLONG_makeVlongFromVlong(DSA_G(pDsaKey), &COMPUTED_VLONG_G(pCtx), ppVlongQueue);

exit_internal:

        fstatus = CRYPTO_INTERFACE_DSA_freeKey(&pDsaKey, ppVlongQueue);
        if (OK == status)
            status = fstatus;

#else 
        MOC_UNUSED(fstatus);
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif
    }

exit:

    return status;
}
#endif /* if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_DH__) */
