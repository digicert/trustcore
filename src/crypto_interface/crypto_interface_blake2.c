/*
 * crypto_interface_blowfish.c
 *
 * Cryptographic Interface specification for Blowfish.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_BLAKE_2B_INTERNAL__
#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_BLAKE_2S_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../crypto/blake2.h"
#include "../crypto_interface/crypto_interface_priv.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_BLAKE_2B__

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_BLAKE2B_ALLOC(_status, _ppCtx)                                    \
    _status = BLAKE2B_alloc(MOC_HASH(hwAccelCtx) _ppCtx);                     \
    if (OK == _status)                                                        \
    {                                                                         \
        ((BLAKE2B_CTX *)(*_ppCtx))->pMocSymCtx = NULL;                        \
        ((BLAKE2B_CTX *)(*_ppCtx))->enabled = CRYPTO_INTERFACE_ALGO_DISABLED; \
    }
#else
#define MOC_BLAKE2B_ALLOC(_status, _ppCtx)                                    \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_BLAKE2B_INIT(_status, _pCtx, _outLen, _pKey, _keyLen)             \
    _status = BLAKE2B_init(MOC_HASH(hwAccelCtx) _pCtx, _outLen, _pKey, _keyLen)
#else
#define MOC_BLAKE2B_INIT(_status, _pCtx, _outLen, _pKey, _keyLen)             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_BLAKE2B_UPDATE(_status, _pCtx, _pData, _dataLen)                  \
    _status = BLAKE2B_update(MOC_HASH(hwAccelCtx) _pCtx, _pData, _dataLen)
#else
#define MOC_BLAKE2B_UPDATE(_status, _pCtx, _pData, _dataLen)                  \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_BLAKE2B_FINAL(_status, _pCtx, _pOutput)                           \
    _status = BLAKE2B_final(MOC_HASH(hwAccelCtx) _pCtx, _pOutput)
#else
#define MOC_BLAKE2B_FINAL(_status, _pCtx, _pOutput)                           \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_BLAKE2B_COMPLETE(_status, _pKey, _keyLen, _pData, _dataLen,       \
        _pOutput, _outLen)                                                    \
    _status = BLAKE2B_complete(MOC_HASH(hwAccelCtx) _pKey, _keyLen, _pData, _dataLen, _pOutput,    \
        _outLen)
#else
#define MOC_BLAKE2B_COMPLETE(_status, _pKey, _keyLen, _pData, _dataLen,       \
        _pOutput, _outLen)                                                    \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_BLAKE2B_DELETE(_status, _ppCtx)                                   \
    _status = BLAKE2B_delete(MOC_HASH(hwAccelCtx) _ppCtx)
#else
#define MOC_BLAKE2B_DELETE(_status, _ppCtx)                                   \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

 /*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_BLAKE2B_CLONE(_status, _pDest, _pSrc)                             \
    _status = BLAKE2B_cloneCtx(MOC_HASH(hwAccelCtx) _pDest, _pSrc);
#else
#define MOC_BLAKE2B_CLONE(_status, _pDest, _pSrc)                             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2B_alloc(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx)
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 algoStatus, index;

  if (NULL == ppCtx)
    goto exit;

  /* Determine if we have an BLAKE 2B implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_blake2b, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_BLAKE2B_ALLOC(status, ppCtx);
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2B_init(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte4 outLen,
    ubyte *pKey, ubyte4 keyLen)
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 algoStatus = 0, index = 0;

  if (NULL == pCtx)
    goto exit;

  ((BLAKE2B_CTX *) pCtx)->hashId = ht_blake2b;

  /* Determine if we have an BLAKE 2B implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_blake2b, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_BLAKE2B_INIT(status, pCtx, outLen, pKey, keyLen);
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2B_update(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData,
    ubyte4 dataLen)
{
  MSTATUS status = ERR_NULL_POINTER;
  BLAKE2B_CTX *pContext = (BLAKE2B_CTX *)pCtx;

  if (NULL == pContext)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pContext->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_BLAKE2B_UPDATE(status, pCtx, pData, dataLen);
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2B_final(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pOutput)
{
  MSTATUS status = ERR_NULL_POINTER;
  BLAKE2B_CTX *pContext = (BLAKE2B_CTX *)pCtx;

  if (NULL == pContext)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pContext->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_BLAKE2B_FINAL(status, pCtx, pOutput);
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2B_complete(
    MOC_HASH(hwAccelDescr hwAccelCtx) ubyte *pKey,
    ubyte4 keyLen, ubyte *pData, ubyte4 dataLen, ubyte *pOutput, ubyte4 outLen)
{
  MSTATUS status;
  ubyte4 algoStatus, index;

  /* Determine if we have an BLAKE 2B implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_blake2b, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_BLAKE2B_COMPLETE(status, pKey, keyLen, pData, dataLen, pOutput, outLen);
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2B_delete(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx)
{
  MSTATUS status = ERR_NULL_POINTER;
  BLAKE2B_CTX *pContext;
  
  if (NULL == ppCtx)
    goto exit;

  pContext = (BLAKE2B_CTX *)*ppCtx;

  status = OK; /* ok no-op if nothing to free */
  if (NULL == pContext)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pContext->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_BLAKE2B_DELETE(status, ppCtx);
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2B_cloneCtx(
  MOC_HASH(hwAccelDescr hwAccelCtx) BLAKE2B_CTX *pDest, 
  BLAKE2B_CTX *pSrc
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  
  if (NULL == pSrc)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pSrc->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_BLAKE2B_CLONE(status, pDest, pSrc)
  }

exit:

  return status;
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_BLAKE_2B__ */

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_BLAKE_2S__

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_BLAKE2S_ALLOC(_status, _ppCtx)                                    \
    _status = BLAKE2S_alloc(MOC_HASH(hwAccelCtx) _ppCtx);                     \
    if (OK == _status)                                                        \
    {                                                                         \
        ((BLAKE2S_CTX *)(*_ppCtx))->pMocSymCtx = NULL;                        \
        ((BLAKE2S_CTX *)(*_ppCtx))->enabled = CRYPTO_INTERFACE_ALGO_DISABLED; \
    }
#else
#define MOC_BLAKE2S_ALLOC(_status, _ppCtx)                                    \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_BLAKE2S_INIT(_status, _pCtx, _outLen, _pKey, _keyLen)             \
    _status = BLAKE2S_init(MOC_HASH(hwAccelCtx) _pCtx, _outLen, _pKey, _keyLen)
#else
#define MOC_BLAKE2S_INIT(_status, _pCtx, _outLen, _pKey, _keyLen)             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_BLAKE2S_UPDATE(_status, _pCtx, _pData, _dataLen)                  \
    _status = BLAKE2S_update(MOC_HASH(hwAccelCtx) _pCtx, _pData, _dataLen)
#else
#define MOC_BLAKE2S_UPDATE(_status, _pCtx, _pData, _dataLen)                  \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_BLAKE2S_FINAL(_status, _pCtx, _pOutput)                           \
    _status = BLAKE2S_final(MOC_HASH(hwAccelCtx) _pCtx, _pOutput)
#else
#define MOC_BLAKE2S_FINAL(_status, _pCtx, _pOutput)                           \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_BLAKE2S_COMPLETE(_status, _pKey, _keyLen, _pData, _dataLen,       \
        _pOutput, _outLen)                                                    \
    _status = BLAKE2S_complete(MOC_HASH(hwAccelCtx) _pKey, _keyLen, _pData, _dataLen, _pOutput,    \
        _outLen)
#else
#define MOC_BLAKE2S_COMPLETE(_status, _pKey, _keyLen, _pData, _dataLen,       \
        _pOutput, _outLen)                                                    \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_BLAKE2S_DELETE(_status, _ppCtx)                                   \
    _status = BLAKE2S_delete(MOC_HASH(hwAccelCtx) _ppCtx)
#else
#define MOC_BLAKE2S_DELETE(_status, _ppCtx)                                   \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_BLAKE2S_CLONE(_status, _pDest, _pSrc)                             \
    _status = BLAKE2S_cloneCtx(MOC_HASH(hwAccelCtx) _pDest, _pSrc);
#else
#define MOC_BLAKE2S_CLONE(_status, _pDest, _pSrc)                             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2S_alloc(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx)
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 algoStatus, index;

  if (NULL == ppCtx)
    goto exit;

  /* Determine if we have an BLAKE 2S implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_blake2b, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_BLAKE2S_ALLOC(status, ppCtx);
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2S_init(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte4 outLen,
    ubyte *pKey, ubyte4 keyLen)
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 algoStatus = 0, index = 0;

  if (NULL == pCtx)
    goto exit;

  ((BLAKE2S_CTX *) pCtx)->hashId = ht_blake2s;

  /* Determine if we have an BLAKE 2S implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_blake2b, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_BLAKE2S_INIT(status, pCtx, outLen, pKey, keyLen);
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2S_update(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pData,
    ubyte4 dataLen)
{
  MSTATUS status = ERR_NULL_POINTER;
  BLAKE2S_CTX *pContext = (BLAKE2S_CTX *)pCtx;

  if (NULL == pContext)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pContext->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_BLAKE2S_UPDATE(status, pCtx, pData, dataLen);
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2S_final(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx pCtx, ubyte *pOutput)
{
  MSTATUS status = ERR_NULL_POINTER;
  BLAKE2S_CTX *pContext = (BLAKE2S_CTX *)pCtx;

  if (NULL == pContext)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pContext->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_BLAKE2S_FINAL(status, pCtx, pOutput);
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2S_complete(
    MOC_HASH(hwAccelDescr hwAccelCtx) ubyte *pKey,
    ubyte4 keyLen, ubyte *pData, ubyte4 dataLen, ubyte *pOutput, ubyte4 outLen)
{
  MSTATUS status;
  ubyte4 algoStatus, index;

  /* Determine if we have an BLAKE 2S implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_blake2b, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_BLAKE2S_COMPLETE(status, pKey, keyLen, pData, dataLen, pOutput, outLen);
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2S_delete(MOC_HASH(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx)
{
  MSTATUS status = ERR_NULL_POINTER;
  BLAKE2S_CTX *pContext;
  
  if (NULL == ppCtx)
    goto exit;

  pContext = (BLAKE2S_CTX *)*ppCtx;

  status = OK; /* ok no-op if nothing to free */
  if (NULL == pContext)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pContext->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_BLAKE2S_DELETE(status, ppCtx);
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_BLAKE_2S_cloneCtx(
  MOC_HASH(hwAccelDescr hwAccelCtx) BLAKE2S_CTX *pDest, 
  BLAKE2S_CTX *pSrc
  )
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pSrc)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pSrc->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_BLAKE2S_CLONE(status, pDest, pSrc)
  }

exit:

  return status;
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_BLAKE_2S__ */
