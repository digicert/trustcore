 /*
 * crypto_interface_sha512.c
 *
 * Cryptographic Interface for SHA512.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA512_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../crypto/sha512.h"
#include "../crypto_interface/crypto_interface_priv.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA512__))

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_SHA512_ALLOC(_status, _pContext)                                  \
    _status = SHA512_allocDigest(MOC_HASH(hwAccelCtx) _pContext);
#else
#define MOC_SHA512_ALLOC(_status, _pContext)                                  \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_SHA512__))
#define MOC_SHA512_INIT(_status, _pContext)                                   \
    _status = SHA512_initDigest(MOC_HASH(hwAccelCtx) _pContext);
#else
#define MOC_SHA512_INIT(_status, _pContext)                                   \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_SHA512__))
#define MOC_SHA512_UPDATE(_status, _pContext, _pData, _dataLen)               \
    _status = SHA512_updateDigest(MOC_HASH(hwAccelCtx) _pContext, _pData, _dataLen);
#else
#define MOC_SHA512_UPDATE(_status, _pContext, _pData, _dataLen)               \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_SHA512__))
#define MOC_SHA512_FINAL(_status, _pContext, _pOutput)                       \
    _status = SHA512_finalDigest(MOC_HASH(hwAccelCtx) _pContext, _pOutput);
#else
#define MOC_SHA512_FINAL(_status, _pContext, _pOutput)                       \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_SHA512_FREE(_status, _pContext)                                  \
    _status = SHA512_freeDigest(MOC_HASH(hwAccelCtx) _pContext);
#else
#define MOC_SHA512_FREE(_status, _pContext)                                  \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_SHA512__))
#define MOC_SHA512_COMPLETE(_status, _pData, _dataLen, _pOutput)             \
    _status = SHA512_completeDigest(MOC_HASH(hwAccelCtx) _pData, _dataLen, _pOutput);
#else
#define MOC_SHA512_COMPLETE(_status, _pData, _dataLen, _pOutput)             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

 /*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_SHA512__))
#define MOC_SHA512_CLONE(_status, _pDest, _pSrc)                             \
    _status = SHA512_cloneCtx(MOC_HASH(hwAccelCtx) _pDest, _pSrc);
#else
#define MOC_SHA512_CLONE(_status, _pDest, _pSrc)                             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA512_allocDigest(
  MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  SHA512_CTX *pShaCtx = NULL;
  ubyte4 algoStatus = 0, index = 0;

  if (NULL == pp_context)
    goto exit;

  /* This API is used for allocating a context for either SHA384 or SHA512
     We don't know yet which one it is since some SHA384 cipher suites will refer
     to this API. If either is operator enabled then we'll allocated the context
     directly rather than passthrough */

  /* First determine if we have a SHA512 implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus(moc_alg_sha512, &algoStatus, &index);
  if (OK != status)
    goto exit;

  /* If not then check for sha384 */
  if (CRYPTO_INTERFACE_ALGO_ENABLED != algoStatus)
  {
    status = CRYPTO_INTERFACE_checkSymAlgoStatus(moc_alg_sha384, &algoStatus, &index);
    if (OK != status)
      goto exit;  
  }

  /* If this algorithm is not disabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    /* Simply allocate the shell. We have to wait on the MocSymCtx until we know if it's SHA384 or SHA512 */
    status = DIGI_CALLOC((void **)&pShaCtx, 1, sizeof(SHA512_CTX));
    if (OK != status)
      goto exit;

    /* set the enabled flag now, but init will do its own verification */
    pShaCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

    *pp_context = (BulkCtx) pShaCtx; pShaCtx = NULL;
  }
  else
  {
    MOC_SHA512_ALLOC(status, pp_context)
  }

exit:

  if (NULL != pShaCtx)
  {
    (void) DIGI_FREE((void **)&pShaCtx);
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA512_initDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA512_CTX *pContext
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 algoStatus = 0, index = 0;
  MocSymCtx pNewSymCtx = NULL;

  if (NULL == pContext)
    goto exit;

  pContext->hashId = ht_sha512;

  /* Now that we know it's SHA512, determine if we have a SHA512 implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_sha512, &algoStatus, &index);
  if (OK != status)
    goto exit;

  /* If this algorithm is not disabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    if (NULL == pContext->pMocSymCtx)
    {
      status = CRYPTO_INTERFACE_createAndLoadSymKey (
        index, NULL, NULL, 0, &pNewSymCtx);
      if (OK != status)
        goto exit;

      pContext->pMocSymCtx = pNewSymCtx; pNewSymCtx = NULL;
    }
    
    /* mark enabled just in case allocDigest was not called */
    pContext->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

    status = CRYPTO_digestInit(pContext->pMocSymCtx);
  }
  else
  { 
    /* SHA512 wasn't enabled afterall, mark as such */
    pContext->enabled = 0;
    pContext->pMocSymCtx = NULL;
    MOC_SHA512_INIT(status, pContext)
  }

exit:

  if (NULL != pNewSymCtx)
  {
    /* Here on error only, no need to check status */
    (void) CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA512_updateDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA512_CTX *pContext,
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
    MOC_SHA512_UPDATE(status, pContext, pData, dataLen)
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA512_finalDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA512_CTX *pContext,
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
      pContext->pMocSymCtx, NULL, 0, pOutput, SHA512_RESULT_SIZE, &outputLen);
  }
  else
  {
    MOC_SHA512_FINAL(status, pContext, pOutput)
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA512_completeDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData,
  ubyte4 dataLen,
  ubyte *pShaOutput
  )
{
  MSTATUS status = OK;
  ubyte4 outputLen = 0, algoStatus = 0, index = 0;
  MocSymCtx pNewSymCtx = NULL;

  /* Determine if we have a SHA512 implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_sha512, &algoStatus, &index);
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
      pNewSymCtx, NULL, 0, pShaOutput, SHA512_RESULT_SIZE, &outputLen);
  }
  else
  {
    MOC_SHA512_COMPLETE(status, pData, dataLen, pShaOutput)
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

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA512_freeDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context
  )
{
  MSTATUS status = ERR_NULL_POINTER, fstatus = OK;
  SHA512_CTX *pShaCtx = NULL;

  if (NULL == pp_context)
    goto exit;

  status = OK;
  pShaCtx = (SHA512_CTX *)(*pp_context);
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
    MOC_SHA512_FREE(status, pp_context)
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA512_cloneCtx(
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA512_CTX *pDest, 
  SHA512_CTX *pSrc
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
    MOC_SHA512_CLONE(status, pDest, pSrc)
  }

exit:

  if (NULL != pNewSymCtx)
  {
    /* here on error only, ignore status */
    (void) CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }

  return status;
}
#endif /* if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA512__)) */
