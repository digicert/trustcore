 /*
 * crypto_interface_md4.c
 *
 * Cryptographic Interface for MD4.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_MD4_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../crypto/md4.h"
#include "../crypto_interface/crypto_interface_priv.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_MD4__))


/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_MD4_ALLOC(_status, _pContext)                                  \
    _status = MD4Alloc(MOC_HASH(hwAccelCtx) _pContext);                    \
    if (OK == _status)                                                     \
    {                                                                      \
      ((MD4_CTX *)(*_pContext))->enabled = 0;                              \
      ((MD4_CTX *)(*_pContext))->pMocSymCtx = NULL;                        \
    }
#else
#define MOC_MD4_ALLOC(_status, _pContext)                                  \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_MD4_INIT(_status, _pContext)                                   \
    _status = MD4Init(MOC_HASH(hwAccelCtx) _pContext);
#else
#define MOC_MD4_INIT(_status, _pContext)                                   \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_MD4_UPDATE(_status, _pContext, _pData, _dataLen)               \
    _status = MD4Update(MOC_HASH(hwAccelCtx) _pContext, _pData, _dataLen);
#else
#define MOC_MD4_UPDATE(_status, _pContext, _pData, _dataLen)               \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_MD4_FINAL(_status, _pContext, _pOutput)                       \
    _status = MD4Final(MOC_HASH(hwAccelCtx) _pContext, _pOutput);
#else
#define MOC_MD4_FINAL(_status, _pContext, _pOutput)                       \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_MD4_FREE(_status, _pContext)                                  \
    _status = MD4Free(MOC_HASH(hwAccelCtx) _pContext);
#else
#define MOC_MD4_FREE(_status, _pContext)                                  \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_MD4_COMPLETE(_status, _pData, _dataLen, _pOutput)             \
    _status = MD4_completeDigest(MOC_HASH(hwAccelCtx) _pData, _dataLen, _pOutput);
#else
#define MOC_MD4_COMPLETE(_status, _pData, _dataLen, _pOutput)             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_MD4_CLONE(_status, _pDest, _pSrc)                             \
    _status = MD4_cloneCtx(MOC_HASH(hwAccelCtx) _pDest, _pSrc);
#else
#define MOC_MD4_CLONE(_status, _pDest, _pSrc)                             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MD4Alloc(
  MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MD4_CTX *pMDCtx = NULL;
  ubyte4 algoStatus = 0, index = 0;

  if (NULL == pp_context)
    goto exit;

  /* Determine if we have an MD4 implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus(moc_alg_md4, &algoStatus, &index);
  if (OK != status)
    goto exit;

  /* If this algorithm is not disabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    /* Simply allocate the shell */
    status = DIGI_CALLOC((void **)&pMDCtx, 1, sizeof(MD4_CTX));
    if (OK != status)
      goto exit;

    /* Mark this object to indicate that it is using an alternate
     * implementation through the crypto interface */
    pMDCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

    *pp_context = (BulkCtx) pMDCtx; pMDCtx = NULL;
  }
  else
  {
    MOC_MD4_ALLOC(status, pp_context)
  }

exit:

  if (NULL != pMDCtx)
  {
    (void) DIGI_FREE((void **)&pMDCtx);
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MD4Init (
  MOC_HASH(hwAccelDescr hwAccelCtx) MD4_CTX *pContext
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 algoStatus = 0, index = 0;
  MocSymCtx pNewSymCtx = NULL;

  if (NULL == pContext)
    goto exit;

  pContext->hashId = ht_md4;

  /* In case allocDigest was not called, check status again through ci core */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus(moc_alg_md4, &algoStatus, &index);
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
    /* MD4 wasn't enabled afterall, mark as such */
    pContext->enabled = 0;
    pContext->pMocSymCtx = NULL;
    MOC_MD4_INIT(status, pContext)
  }

exit:

  if (NULL != pNewSymCtx)
  {
    (void) CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MD4Update (
  MOC_HASH(hwAccelDescr hwAccelCtx) MD4_CTX *pContext,
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
    MOC_MD4_UPDATE(status, pContext, pData, dataLen)
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MD4Final (
  MOC_HASH(hwAccelDescr hwAccelCtx) MD4_CTX *pContext,
  ubyte pOutput[MD4_DIGESTSIZE]
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 outputLen = 0;

  if (NULL == pContext)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pContext->enabled)
  {
    status = CRYPTO_digestFinal (
      pContext->pMocSymCtx, NULL, 0, pOutput, MD4_DIGESTSIZE, &outputLen);
  }
  else
  {
    MOC_MD4_FINAL(status, pContext, pOutput)
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MD4_completeDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData,
  ubyte4 dataLen,
  ubyte *pOutput
  )
{
  MSTATUS status = OK;
  ubyte4 outputLen = 0, algoStatus = 0, index = 0;
  MocSymCtx pNewSymCtx = NULL;

  /* Determine if we have a MD4 implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_md4, &algoStatus, &index);
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
      pNewSymCtx, NULL, 0, pOutput, MD4_DIGESTSIZE, &outputLen);
  }
  else
  {
    MOC_MD4_COMPLETE(status, pData, dataLen, pOutput)
  }

exit:

  if (NULL != pNewSymCtx)
  {
    (void) CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MD4Free (
  MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context
  )
{
  MSTATUS status = ERR_NULL_POINTER, fstatus = OK;
  MD4_CTX *pCtx = NULL;

  status = ERR_NULL_POINTER;
  if (NULL == pp_context)
    goto exit;

  status = OK;
  pCtx = (MD4_CTX *)(*pp_context);
  if (NULL == pCtx)   /* OK no-op if nothing to free */
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  {
    /* Free the underlying context if present */
    if (NULL != pCtx->pMocSymCtx)
    {
      status = CRYPTO_freeMocSymCtx(&(pCtx->pMocSymCtx));
    }

    /* Now free the outer shell */
    fstatus = DIGI_FREE((void **)&pCtx);
    if (OK == status)
      status = fstatus;

    /* NULL out the callers reference */
    *pp_context = NULL;
  }
  else
  {
    MOC_MD4_FREE(status, pp_context)
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MD4_cloneCtx(
  MOC_HASH(hwAccelDescr hwAccelCtx) MD4_CTX *pDest, 
  MD4_CTX *pSrc
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
    MOC_MD4_CLONE(status, pDest, pSrc)
  }

exit:

  if (NULL != pNewSymCtx)
  {
    /* here on error only, ignore status */
    (void) CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }

  return status;
}
#endif /* if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_MD4__)) */
