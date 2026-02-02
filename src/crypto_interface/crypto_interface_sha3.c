 /*
 * crypto_interface_sha3.c
 *
 * Cryptographic Interface for SHA3.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA3_INTERNAL__

#include "../crypto/mocsym.h"
#include "../crypto/sha3.h"
#include "../crypto_interface/crypto_interface_priv.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA3__))


/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && defined(__ENABLE_DIGICERT_SHA3__))
#define MOC_SHA3_ALLOC(_status, _pContext)                                    \
    _status = SHA3_allocDigest(MOC_HASH(hwAccelCtx) _pContext);
#else
#define MOC_SHA3_ALLOC(_status, _pContext)                                    \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && defined(__ENABLE_DIGICERT_SHA3__))
#define MOC_SHA3_INIT(_status, _pContext, _mode)                              \
    _status = SHA3_initDigest(MOC_HASH(hwAccelCtx) _pContext, _mode);
#else
#define MOC_SHA3_INIT(_status, _pContext, _mode)                              \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && defined(__ENABLE_DIGICERT_SHA3__))
#define MOC_SHA3_UPDATE(_status, _pContext, _pData, _dataLen)               \
    _status = SHA3_updateDigest(MOC_HASH(hwAccelCtx) _pContext, _pData, _dataLen);
#else
#define MOC_SHA3_UPDATE(_status, _pContext, _pData, _dataLen)               \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && defined(__ENABLE_DIGICERT_SHA3__))
#define MOC_SHA3_FINAL(_status, _pContext, _pOutput, _desiredResultLen)     \
    _status = SHA3_finalDigest(MOC_HASH(hwAccelCtx) _pContext, _pOutput, _desiredResultLen);
#else
#define MOC_SHA3_FINAL(_status, _pContext, _pOutput, _desiredResultLen)     \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && defined(__ENABLE_DIGICERT_SHA3__))
#define MOC_SHA3_FREE(_status, _pContext)                                   \
    _status = SHA3_freeDigest(MOC_HASH(hwAccelCtx) _pContext);
#else
#define MOC_SHA3_FREE(_status, _pContext)                                   \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && defined(__ENABLE_DIGICERT_SHA3__))
#define MOC_SHA3_COMPLETE(_status, _mode, _pData, _dataLen, _pOutput, _desiredResultLen) \
    _status = SHA3_completeDigest(MOC_HASH(hwAccelCtx) _mode, _pData, _dataLen, _pOutput, _desiredResultLen);
#else
#define MOC_SHA3_COMPLETE(_status, _mode, _pData, _dataLen, _pOutput, _desiredResultLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

 /*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__) && defined(__ENABLE_DIGICERT_SHA3__))
#define MOC_SHA3_CLONE(_status, _pDest, _pSrc)                             \
    _status = SHA3_cloneCtx(MOC_HASH(hwAccelCtx) _pDest, _pSrc);
#else
#define MOC_SHA3_CLONE(_status, _pDest, _pSrc)                             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA3_allocDigest(
  MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  SHA3_CTX *pShaCtx = NULL;
  ubyte4 algoStatus = 0, index = 0;
  MocSymCtx pNewSymCtx = NULL;

  if (NULL == pp_context)
    goto exit;

  /* Determine if we have a SHA3 implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus(moc_alg_sha3, &algoStatus, &index);
  if (OK != status)
    goto exit;

  /* If this algorithm is not disabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    status = CRYPTO_INTERFACE_createAndLoadSymKey(index, NULL, NULL, 0, &pNewSymCtx);
    if (OK != status)
      goto exit;

    /* Simply allocate the shell */
    status = DIGI_CALLOC((void **)&pShaCtx, 1, sizeof(SHA3_CTX));
    if (OK != status)
      goto exit;

    /* Mark this object to indicate that it is using an alternate
     * implementation through the crypto interface */
    pShaCtx->pMocSymCtx = pNewSymCtx; pNewSymCtx = NULL;
    pShaCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

    *pp_context = (BulkCtx) pShaCtx; pShaCtx = NULL;
  }
  else
  {
    MOC_SHA3_ALLOC(status, pp_context)
  }

exit:

  if (NULL != pNewSymCtx)
  { /* must be error condition, no need to check return code */
    (void) CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }

  if (NULL != pShaCtx)
  {
    (void) DIGI_FREE((void **)&pShaCtx);
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA3_initDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA3_CTX *pContext,
  ubyte4 mode
  )
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pContext)
    goto exit;
  
  switch (mode)
  { 
    case MOCANA_SHA3_MODE_SHA3_224:
      pContext->hashId = ht_sha3_224;
      break;

    case MOCANA_SHA3_MODE_SHA3_256:
      pContext->hashId = ht_sha3_256;
      break;

    case MOCANA_SHA3_MODE_SHA3_384:
      pContext->hashId = ht_sha3_384;
      break;

    case MOCANA_SHA3_MODE_SHA3_512:
      pContext->hashId = ht_sha3_512;
      break;

    case MOCANA_SHA3_MODE_SHAKE128:
      pContext->hashId = ht_shake128;
      break;

    case MOCANA_SHA3_MODE_SHAKE256:
      pContext->hashId = ht_shake256;
      break;

    default:
      /* we won't set the hashId but will continue in case the operator
         can still handle it */
      pContext->hashId = 0;
      break;
  }

  /* If this algorithm is not disabled */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pContext->enabled)
  {
    status = CRYPTO_updateSymOperatorData (pContext->pMocSymCtx, NULL, (void *) &mode);
    if (OK != status)
      goto exit;

    status = CRYPTO_digestInit(pContext->pMocSymCtx);
  }
  else
  {
    MOC_SHA3_INIT(status, pContext, mode)
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA3_updateDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA3_CTX *pContext,
  ubyte *pData,
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
    MOC_SHA3_UPDATE(status, pContext, pData, dataLen)
  }


exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA3_finalDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA3_CTX *pContext,
  ubyte *pOutput,
  ubyte4 desiredResultLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 outputLen = 0;

  if (NULL == pContext)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pContext->enabled)
  {
    status = CRYPTO_digestFinal (
      pContext->pMocSymCtx, NULL, 0, pOutput, desiredResultLen, &outputLen);
  }
  else
  {
    MOC_SHA3_FINAL(status, pContext, pOutput, desiredResultLen)
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA3_completeDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) ubyte4 mode, 
  ubyte *pData,
  ubyte4 dataLen,
  ubyte *pShaOutput,
  ubyte4 desiredResultLen
  )
{
  MSTATUS status = OK;
  ubyte4 outputLen = 0, algoStatus = 0, index = 0;
  MocSymCtx pNewSymCtx = NULL;

  /* Determine if we have a SHA3 implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_sha3, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    status = CRYPTO_INTERFACE_createAndLoadSymKey (
      index, NULL, NULL, 0, &pNewSymCtx);
    if (OK != status)
      goto exit;

    status = CRYPTO_updateSymOperatorData (
      pNewSymCtx, NULL, (void *) &mode);
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
      pNewSymCtx, NULL, 0, pShaOutput, desiredResultLen, &outputLen);
  }
  else
  {
    MOC_SHA3_COMPLETE(status, mode, pData, dataLen, pShaOutput, desiredResultLen)
  }

exit:

  if (NULL != pNewSymCtx)
  {
    CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA3_freeDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *pp_context
  )
{
  MSTATUS status = ERR_NULL_POINTER, fstatus = OK;
  SHA3_CTX *pShaCtx = NULL;

  if (NULL == pp_context)
    goto exit;

  status = OK;
  pShaCtx = (SHA3_CTX *)(*pp_context);
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
    MOC_SHA3_FREE(status, pp_context)
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA3_cloneCtx(
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA3_CTX *pDest, 
  SHA3_CTX *pSrc
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
    MOC_SHA3_CLONE(status, pDest, pSrc)
  }

exit:

  if (NULL != pNewSymCtx)
  {
    /* here on error only, ignore status */
    (void) CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }

  return status;
}
#endif /* if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA3__)) */
