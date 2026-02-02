 /*
 * crypto_interface_sha384.c
 *
 * Cryptographic Interface for SHA384.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA384_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../crypto/sha512.h"
#include "../crypto_interface/crypto_interface_priv.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA384__))

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_SHA384__))
#define MOC_SHA384_INIT(_status, _pContext)                                   \
    _status = SHA384_initDigest(MOC_HASH(hwAccelCtx) _pContext);
#else
#define MOC_SHA384_INIT(_status, _pContext)                                   \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_SHA384__))
#define MOC_SHA384_FINAL(_status, _pContext, _pOutput)                       \
    _status = SHA384_finalDigest(MOC_HASH(hwAccelCtx) _pContext, _pOutput);
#else
#define MOC_SHA384_FINAL(_status, _pContext, _pOutput)                       \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_SHA384__))
#define MOC_SHA384_COMPLETE(_status, _pData, _dataLen, _pOutput)             \
    _status = SHA384_completeDigest(MOC_HASH(hwAccelCtx) _pData, _dataLen, _pOutput);
#else
#define MOC_SHA384_COMPLETE(_status, _pData, _dataLen, _pOutput)             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_SHA384__))
#define MOC_SHA384_CLONE(_status, _pDest, _pSrc)                             \
    _status = SHA384_cloneCtx(MOC_HASH(hwAccelCtx) _pDest, _pSrc);
#else
#define MOC_SHA384_CLONE(_status, _pDest, _pSrc)                             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA384_initDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA384_CTX *pContext
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 algoStatus = 0, index = 0;
  MocSymCtx pNewSymCtx = NULL;

  if (NULL == pContext)
    goto exit;

  pContext->hashId = ht_sha384;

  /* Now that we know it's SHA384, determine if we have a SHA384 implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_sha384, &algoStatus, &index);
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
    /* SHA384 wasn't enabled afterall, mark as such */
    pContext->enabled = 0;
    pContext->pMocSymCtx = NULL;
    MOC_SHA384_INIT(status, pContext)
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

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA384_finalDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA384_CTX *pContext,
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
      pContext->pMocSymCtx, NULL, 0, pOutput, SHA384_RESULT_SIZE, &outputLen);
  }
  else
  {
    MOC_SHA384_FINAL(status, pContext, pOutput)
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA384_completeDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData,
  ubyte4 dataLen,
  ubyte *pShaOutput
  )
{
  MSTATUS status = OK;
  ubyte4 outputLen = 0, algoStatus = 0, index = 0;
  MocSymCtx pNewSymCtx = NULL;

  /* Determine if we have a SHA384 implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_sha384, &algoStatus, &index);
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
      pNewSymCtx, NULL, 0, pShaOutput, SHA384_RESULT_SIZE, &outputLen);
  }
  else
  {
    MOC_SHA384_COMPLETE(status, pData, dataLen, pShaOutput)
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

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_SHA384_cloneCtx(
  MOC_HASH(hwAccelDescr hwAccelCtx) SHA384_CTX *pDest, 
  SHA384_CTX *pSrc
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
    MOC_SHA384_CLONE(status, pDest, pSrc)
  }

exit:

  if (NULL != pNewSymCtx)
  {
    /* here on error only, ignore status */
    (void) CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }

  return status;
}
#endif /* if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA384__)) */
