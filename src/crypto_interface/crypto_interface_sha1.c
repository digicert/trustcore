 /*
 * crypto_interface_sha1.c
 *
 * Cryptographic Interface for SHA1.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA1_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../crypto/sha1.h"
#include "../crypto_interface/crypto_interface_priv.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA1__))


/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_SHA1_ALLOC(_status, _pContext)                                    \
    _status = SHA1_allocDigest(MOC_HASH(hwAccelCtx) _pContext);
#else
#define MOC_SHA1_ALLOC(_status, _pContext)                                    \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_SHA1_INIT(_status, _pContext)                                     \
    _status = SHA1_initDigest(MOC_HASH(hwAccelCtx) _pContext);
#else
#define MOC_SHA1_INIT(_status, _pContext)                                     \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_SHA1_UPDATE(_status, _pContext, _pData, _dataLen)               \
    _status = SHA1_updateDigest(MOC_HASH(hwAccelCtx) _pContext, _pData, _dataLen);
#else
#define MOC_SHA1_UPDATE(_status, _pContext, _pData, _dataLen)               \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_SHA1_FINAL(_status, _pContext, _pOutput)                       \
    _status = SHA1_finalDigest(MOC_HASH(hwAccelCtx) _pContext, _pOutput);
#else
#define MOC_SHA1_FINAL(_status, _pContext, _pOutput)                       \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_SHA1_FREE(_status, _pContext)                                  \
    _status = SHA1_freeDigest(MOC_HASH(hwAccelCtx) _pContext);
#else
#define MOC_SHA1_FREE(_status, _pContext)                                  \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_SHA1_COMPLETE(_status, _pData, _dataLen, _pOutput)             \
    _status = SHA1_completeDigest(MOC_HASH(hwAccelCtx) _pData, _dataLen, _pOutput);
#else
#define MOC_SHA1_COMPLETE(_status, _pData, _dataLen, _pOutput)             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_SHA1_CLONE(_status, _pDest, _pSrc)                             \
    _status = SHA1_cloneCtx(MOC_HASH(hwAccelCtx) _pDest, _pSrc);
#else
#define MOC_SHA1_CLONE(_status, _pDest, _pSrc)                             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

 /*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_SHA1_G(_status, _pData, _pOutput)                              \
    _status = SHA1_G(_pData, _pOutput)
#else
#define MOC_SHA1_G(_status, _pData, _pOutput)                              \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_SHA1_GK(_status, _pData, _pOutput)                             \
    _status = SHA1_GK(_pData, _pOutput)
#else
#define MOC_SHA1_GK(_status, _pData, _pOutput)                             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA1_allocDigest(
  MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 algoStatus = 0, index = 0;
  SHA1_CTX *pShaCtx = NULL;

  if (NULL == pp_context)
    goto exit;

  /* Determine if we have a SHA1 implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus(moc_alg_sha1, &algoStatus, &index);
  if (OK != status)
    goto exit;

  /* If this algorithm is not disabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    /* Simply allocate the shell */
    status = DIGI_CALLOC((void **)&pShaCtx, 1, sizeof(SHA1_CTX));
    if (OK != status)
      goto exit;

    /* Mark this object to indicate that it is using an alternate
     * implementation through the crypto interface */
    pShaCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

    *pp_context = (BulkCtx) pShaCtx; pShaCtx = NULL;
  }
  else
  {
    MOC_SHA1_ALLOC(status, pp_context)
  }

exit:

  if (NULL != pShaCtx)
  {
    (void) DIGI_FREE((void **)&pShaCtx);
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA1_initDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA1_CTX *pContext
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 algoStatus = 0, index = 0;
  MocSymCtx pNewSymCtx = NULL;

  if (NULL == pContext)
    goto exit;

  pContext->hashId = ht_sha1;

  /* In case allocDigest was not called, check status again through ci core */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus(moc_alg_sha1, &algoStatus, &index);
  if (OK != status)
    goto exit;

  /* If this algorithm is not disabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    if (NULL == pContext->pMocSymCtx)
    {
      status = CRYPTO_INTERFACE_createAndLoadSymKey(index, NULL, NULL, 0, &pNewSymCtx);
      if (OK != status)
        goto exit;
 
      pContext->pMocSymCtx = pNewSymCtx; pNewSymCtx = NULL;
    }
    
    /* Mark this object to indicate that it is using an alternate
     * implementation through the crypto interface */
    pContext->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

    status = CRYPTO_digestInit(pContext->pMocSymCtx);
  }
  else
  {
    /* SHA1 wasn't enabled afterall, mark as such */
    pContext->enabled = 0;
    pContext->pMocSymCtx = NULL;
    MOC_SHA1_INIT(status, pContext)
  }

exit:

  if (NULL != pNewSymCtx)
  { /* must be error condition, no need to check return code */
    (void) CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA1_updateDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA1_CTX *pContext,
  const ubyte *pData,
  ubyte4 dataLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pContext)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pContext->enabled)
  {
    status = CRYPTO_digestUpdate (
      pContext->pMocSymCtx, (ubyte *)pData, dataLen);
  }
  else
  {
    MOC_SHA1_UPDATE(status, pContext, pData, dataLen)
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA1_finalDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA1_CTX *pContext,
  ubyte *pOutput
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 outputLen = 0;

  if (NULL == pContext)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pContext->enabled)
  {
    status = CRYPTO_digestFinal (
      pContext->pMocSymCtx, NULL, 0, pOutput, SHA1_RESULT_SIZE, &outputLen);
  }
  else
  {
    MOC_SHA1_FINAL(status, pContext, pOutput)
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA1_completeDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData,
  ubyte4 dataLen,
  ubyte *pShaOutput
  )
{
  MSTATUS status = OK;
  ubyte4 outputLen = 0, algoStatus = 0, index = 0;
  MocSymCtx pNewSymCtx = NULL;

  /* Determine if we have a SHA1 implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_sha1, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    status = CRYPTO_INTERFACE_createAndLoadSymKey (
      index, NULL, NULL, 0, &pNewSymCtx);
    if (OK != status)
      goto exit;

    status = CRYPTO_digestInit(pNewSymCtx);
    if (OK != status)
      goto exit;

    status = CRYPTO_digestUpdate (
      pNewSymCtx, (ubyte *)pData, dataLen);
    if (OK != status)
      goto exit;

    status = CRYPTO_digestFinal (
      pNewSymCtx, NULL, 0, pShaOutput, SHA1_RESULT_SIZE, &outputLen);
  }
  else
  {
    MOC_SHA1_COMPLETE(status, pData, dataLen, pShaOutput)
  }

exit:

  if (NULL != pNewSymCtx)
  {
    MSTATUS fstatus = CRYPTO_freeMocSymCtx(&pNewSymCtx);
    if (OK == status)
      status = fstatus;
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA1_freeDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context
  )
{
  MSTATUS status = ERR_NULL_POINTER, fstatus = OK;
  SHA1_CTX *pShaCtx = NULL;

  if (NULL == pp_context)
    goto exit;

  status = OK;
  pShaCtx = (SHA1_CTX *)(*pp_context);
  if (NULL == pShaCtx)   /* OK no-op if nothing to free */
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pShaCtx->enabled)
  {
    /* Free the underlying context if present */
    if (NULL != pShaCtx->pMocSymCtx)
    {
      status = CRYPTO_freeMocSymCtx(&(pShaCtx->pMocSymCtx));
    }

    /* Now free the outer shell */
    fstatus = DIGI_FREE((void **)&pShaCtx);
    if (OK == status)
      status = fstatus;

    /* NULL out the callers reference */
    *pp_context = NULL;
  }
  else
  {
    MOC_SHA1_FREE(status, pp_context)
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA1_cloneCtx(
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA1_CTX *pDest, 
  SHA1_CTX *pSrc
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MocSymCtx pNewSymCtx = NULL;

  if (NULL == pSrc || NULL == pDest)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pSrc->enabled)
  {
    status = CRYPTO_cloneMocSymCtx (pSrc->pMocSymCtx, &pNewSymCtx);
    if (OK != status)
      goto exit;

    pDest->pMocSymCtx = pNewSymCtx; pNewSymCtx = NULL;
    pDest->enabled = pSrc->enabled;
    pDest->hashId = pSrc->hashId;
  }
  else
  {
    MOC_SHA1_CLONE(status, pDest, pSrc)
  }

exit:

  if (NULL != pNewSymCtx)
  {
    /* here on error only, ignore status */
    (void) CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }

  return status;
}

/*---------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RNG__
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA1_G (
  ubyte *pData,
  ubyte *pOutput
  )
{
  MSTATUS status = OK;
  ubyte4 algoStatus = 0, index = 0;
  MocSymCtx pSymCtx = NULL;

  /* Determine if we have a SHA1 implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_sha1, &algoStatus, &index);
  if (OK != status)
    goto exit;

  /* If this algorithm is not disabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    ubyte4 outLen;

    status = CRYPTO_INTERFACE_createAndLoadSymKey (index, NULL, NULL, 0, &pSymCtx);
    if (OK != status)
      goto exit;

    status = CRYPTO_digestInit(pSymCtx);
    if (OK != status)
      goto exit;

    status = CRYPTO_doRawTransform(pSymCtx, pData, SHA1_BLOCK_SIZE, pOutput, SHA1_RESULT_SIZE, &outLen);
  }
  else
  {
    MOC_SHA1_G(status, pData, pOutput);
  }

exit:

  if (NULL != pSymCtx)
  {
    MSTATUS fstatus = CRYPTO_freeMocSymCtx(&pSymCtx);
    if (OK == status)
      status = fstatus;
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA1_GK (
  ubyte *pData,
  ubyte *pOutput
  )
{
  MSTATUS status = OK;
  ubyte4 algoStatus = 0, index = 0;
  MocSymCtx pSymCtx = NULL;

  /* Determine if we have a SHA1 implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_sha1, &algoStatus, &index);
  if (OK != status)
    goto exit;

  /* If this algorithm is not disabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    ubyte4 outLen = 0;
    MSha1InitData sha1InitData = {0};

    /* cyclic shift of the hash blocks */
    sha1InitData.pSha1Consts[4] = 0x67452301UL;
    sha1InitData.pSha1Consts[0] = 0xefcdab89UL;
    sha1InitData.pSha1Consts[1] = 0x98badcfeUL;
    sha1InitData.pSha1Consts[2] = 0x10325476UL;
    sha1InitData.pSha1Consts[3] = 0xc3d2e1f0UL;

    status = CRYPTO_INTERFACE_createAndLoadSymKey (index, NULL, NULL, 0, &pSymCtx);
    if (OK != status)
      goto exit;

    status = CRYPTO_digestInitCustom(pSymCtx, &sha1InitData);
    if (OK != status)
      goto exit;

    status = CRYPTO_doRawTransform(pSymCtx, pData, SHA1_BLOCK_SIZE, pOutput, SHA1_RESULT_SIZE, &outLen);
  }
  else
  {
    MOC_SHA1_GK(status, pData, pOutput);
  }

exit:

  if (NULL != pSymCtx)
  {
    MSTATUS fstatus = CRYPTO_freeMocSymCtx(&pSymCtx);
    if (OK == status)
      status = fstatus;
  }

  return status;
}
#endif /* __DISABLE_DIGICERT_RNG__ */
#endif /* if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA1__)) */
