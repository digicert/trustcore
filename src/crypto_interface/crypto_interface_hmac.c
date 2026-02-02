/*
 * crypto_interface_hmac.c
 *
 * Cryptographic Interface specification for HMAC.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_HMAC_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../crypto/md4.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/sha3.h"
#include "../crypto/hmac.h"
#include "../crypto_interface/crypto_interface_hmac_common.h"
#include "../crypto_interface/crypto_interface_hmac_tap.h"
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/crypto_interface_md4.h"
#include "../crypto_interface/crypto_interface_md5.h"
#include "../crypto_interface/crypto_interface_sha1.h"
#include "../crypto_interface/crypto_interface_sha256.h"
#include "../crypto_interface/crypto_interface_sha512.h"
#include "../crypto_interface/crypto_interface_sha3.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_HMAC__))

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_HMAC__))
#define MOC_HMAC_CREATE(_status, _ppCtx, _pBHAlgo)                            \
  _status = HmacCreate(MOC_HASH(hwAccelCtx) _ppCtx, _pBHAlgo);                \
  if (OK == _status)                                                          \
  {                                                                           \
    (*_ppCtx)->pMocSymCtx = NULL;                                             \
    (*_ppCtx)->enabled = 0;                                                   \
  }
#else
#define MOC_HMAC_CREATE(_status, _ppCtx, _pBHAlgo)                            \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_HMAC__))
#define MOC_HMAC_KEY(_status, _pCtx, _pKey, _keyLen)                          \
  _status = HmacKey(MOC_HASH(hwAccelCtx) _pCtx, _pKey, _keyLen);
#else
#define MOC_HMAC_KEY(_status, _pCtx, _pKey, _keyLen)                          \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_HMAC__))
#define MOC_HMAC_RESET(_status, _pCtx)                                        \
  _status = HmacReset(MOC_HASH(hwAccelCtx) _pCtx);
#else
#define MOC_HMAC_RESET(_status, _pCtx)                                        \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_HMAC__))
#define MOC_HMAC_UPDATE(_status, _pCtx, _pData, _dataLen)                     \
  _status = HmacUpdate(MOC_HASH(hwAccelCtx) _pCtx, _pData, _dataLen);
#else
#define MOC_HMAC_UPDATE(_status, _pCtx, _pData, _dataLen)                     \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_HMAC__))
#define MOC_HMAC_FINAL(_status, _pCtx, _pResult)                              \
  _status = HmacFinal(MOC_HASH(hwAccelCtx) _pCtx, _pResult);
#else
#define MOC_HMAC_FINAL(_status, _pCtx, _pResult)                              \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_HMAC__))
#define MOC_HMAC_DELETE(_status, _ppCtx)                                      \
  _status = HmacDelete(MOC_HASH(hwAccelCtx) _ppCtx);
#else
#define MOC_HMAC_DELETE(_status, _ppCtx)                                      \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_HMAC__))
#define MOC_HMAC_MD5(_status, _pK, _kLen, _pT, _tLen, _pOpt, _optLen, _pRes)  \
  _status = HMAC_MD5(MOC_HASH(hwAccelCtx) _pK, _kLen, _pT, _tLen, _pOpt, _optLen, _pRes);
#else
#define MOC_HMAC_MD5(_status, _pK, _kLen, _pT, _tLen, _pOpt, _optLen, _pRes)  \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_HMAC__))
#define MOC_HMAC_SHA1(_status, _pK, _kLen, _pT, _tLen, _pOpt, _optLen, _pRes) \
  _status = HMAC_SHA1(MOC_HASH(hwAccelCtx) _pK, _kLen, _pT, _tLen, _pOpt, _optLen, _pRes);
#else
#define MOC_HMAC_SHA1(_status, _pK, _kLen, _pT, _tLen, _pOpt, _optLen, _pRes) \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_HMAC__))
#define MOC_HMAC_SHA1_EX(_status, _pK, _kLen, _ppTexts, _pLens, _numT, _pRes)  \
  _status = HMAC_SHA1Ex(MOC_HASH(hwAccelCtx) _pK, _kLen, _ppTexts, _pLens, _numT, _pRes);
#else
#define MOC_HMAC_SHA1_EX(_status, _pK, _kLen, _ppTexts, _pLens, _numT, _pRes)  \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_HMAC__)) && \
    (!defined(__DISABLE_DIGICERT_SHA256__))
#define MOC_HMAC_SHA256(_status, _pK, _kLen, _pT, _tLen, _pOpt,               \
                        _optLen, _pRes)                                       \
  _status = HMAC_SHA256(MOC_HASH(hwAccelCtx) _pK, _kLen, _pT, _tLen, _pOpt, _optLen, _pRes);
#else
#define MOC_HMAC_SHA256(_status, _pK, _kLen, _pT, _tLen, _pOpt,               \
                        _optLen, _pRes)                                       \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_HMAC__)) && \
    (!defined(__DISABLE_DIGICERT_SHA512__))
#define MOC_HMAC_SHA512(_status, _pK, _kLen, _pT, _tLen, _pOpt,               \
                        _optLen, _pRes)                                       \
  _status = HMAC_SHA512(MOC_HASH(hwAccelCtx) _pK, _kLen, _pT, _tLen, _pOpt, _optLen, _pRes);
#else
#define MOC_HMAC_SHA512(_status, _pK, _kLen, _pT, _tLen, _pOpt,               \
                        _optLen, _pRes)                                       \
  _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacCreate (
  MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX **ppCtx,
  const BulkHashAlgo *pBHAlgo
  )
{
  MSTATUS status;
  ubyte hashAlgo;
  ubyte4 algoStatus, index;
  HMAC_CTX *pHmacCtx = NULL;
  MocSymCtx pNewSymCtx = NULL;

  /* Determine if we have an HMAC implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_hmac, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    status = ERR_NULL_POINTER;
    if ( (NULL == ppCtx) || (NULL == pBHAlgo) )
      goto exit;

    status = CRYPTO_INTERFACE_HmacGetHashAlgoFlag (
      pBHAlgo, &hashAlgo);
    if (OK != status)
      goto exit;

    /* Create an empty MocSymCtx */
    status = CRYPTO_INTERFACE_createAndLoadSymKey (
      index, (void *)&hashAlgo, NULL, 0, &pNewSymCtx);
    if (OK != status)
      goto exit;

    /* Allocate the HMAC_CTX shell */
    status = DIGI_CALLOC((void **)&pHmacCtx, 1, sizeof(HMAC_CTX));
    if (OK != status)
      goto exit;

    pHmacCtx->pBHAlgo = pBHAlgo;
    pHmacCtx->pMocSymCtx = pNewSymCtx;
    pNewSymCtx = NULL;

    /* Mark this object to indicate that it is using an alternate
     * implementation through the crypto interface */
    pHmacCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;
    *ppCtx = pHmacCtx;
    pHmacCtx = NULL;
  }
  else
  {
    MOC_HMAC_CREATE(status, ppCtx, pBHAlgo)
  }

exit:

  if (NULL != pNewSymCtx)
  {
    CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }
  if (NULL != pHmacCtx)
  {
    DIGI_FREE((void **)&pHmacCtx);
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacReset (
  MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX *pCtx
  )
{
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if (NULL == pCtx)
    goto exit;

  /* Is this object using an alternate implementation? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  {
    if (NULL != pCtx->pMocSymCtx && (0 != (MOC_LOCAL_TYPE_TAP & pCtx->pMocSymCtx->localType)) )
    {
      status = CRYPTO_INTERFACE_TAP_HmacReset(pCtx->pMocSymCtx);
    }
    else
    {
      /* Reinitialize the underlying MocSymCtx */
      status = CRYPTO_macInit(pCtx->pMocSymCtx);
    }
  }
  else
  {
    MOC_HMAC_RESET(status, pCtx)
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacKey (
  MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX *pCtx,
  const ubyte *pKey,
  ubyte4 keyLen
  )
{
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if (NULL == pCtx)
    goto exit;

  /* Is this object using an alternate implementation? */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  {
    /* Load the key data into the underlying MocSymCtx if it is not NULL. */
    if ( (NULL == pKey) && (0 < keyLen) )
      goto exit;

    if ( (NULL != pKey) && (0 < keyLen) )
    {
      status = CRYPTO_loadSymKey (pCtx->pMocSymCtx, (ubyte *)pKey, keyLen);
      if (OK != status)
        goto exit;
    }

    /* Initialize the MAC operation */
    status = CRYPTO_macInit(pCtx->pMocSymCtx);
  }
  else
  {
    MOC_HMAC_KEY(status, pCtx, pKey, keyLen)
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacUpdate (
  MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX *pCtx,
  const ubyte *pData,
  ubyte4 dataLen
  )
{
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if (NULL == pCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  { 
    if ( (NULL == pData) && (0 < dataLen) )
      goto exit;

    if (NULL != pCtx->pMocSymCtx && (0 != (MOC_LOCAL_TYPE_TAP & pCtx->pMocSymCtx->localType)) )
    {
      status = CRYPTO_INTERFACE_TAP_HmacUpdate(pCtx->pMocSymCtx, pData, dataLen);
    }
    else
    {
      if (dataLen)
      {
        status = CRYPTO_macUpdate(pCtx->pMocSymCtx, (ubyte *)pData, dataLen);
        goto exit;
      }

      status = OK;
    }
  }
  else
  {
    MOC_HMAC_UPDATE(status, pCtx, pData, dataLen)
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacFinal (
  MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX *pCtx,
  ubyte *pResult
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte4 outLen;

  if (NULL == pCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  {
    if (NULL == pResult)
      goto exit;

    if (NULL != pCtx->pMocSymCtx && (0 != (MOC_LOCAL_TYPE_TAP & pCtx->pMocSymCtx->localType)) )
    {
      status = CRYPTO_INTERFACE_TAP_HmacFinal(pCtx->pMocSymCtx, pResult);
    }
    else
    {
      if (NULL == pCtx->pBHAlgo)
        goto exit;

      /* We assume the output buffer is as large as the hash output length */
      status = CRYPTO_macFinal (
        pCtx->pMocSymCtx, NULL, 0, pResult, pCtx->pBHAlgo->digestSize, &outLen);
    }
  }
  else
  {
    MOC_HMAC_FINAL(status, pCtx, pResult)
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacDelete (
  MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX **ppCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER, fStatus;
  HMAC_CTX *pHmacCtx = NULL;

  if (NULL == ppCtx)
    goto exit;

  pHmacCtx = *ppCtx;

  /* Is there anything to free? */
  status = OK;
  if (NULL == pHmacCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pHmacCtx->enabled)
  {
    /* If there is a MocSymCtx, free it now */
    if (NULL != pHmacCtx->pMocSymCtx)
    {
      status = CRYPTO_freeMocSymCtx(&(pHmacCtx->pMocSymCtx));
    }

    /* Free the outer shell */
    fStatus = DIGI_FREE((void **)&pHmacCtx);
    if (OK == status)
      status = fStatus;

    /* NULL out the callers reference */
    *ppCtx = NULL;
  }
  else
  {
    MOC_HMAC_DELETE(status, ppCtx);
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacCloneCtx (
  MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX **ppDest,
  HMAC_CTX *pSrc
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MocSymCtx pNewSymCtx = NULL;
  HMAC_CTX *pNew = NULL;

  if (NULL == ppDest || NULL == pSrc)
    goto exit;

  /* instead of calling CRYPTO_INTERFACE_HmacCreate we will allocate directly */
  status = DIGI_CALLOC((void **)&pNew, 1, sizeof(HMAC_CTX));
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pSrc->enabled)
  {
    status = CRYPTO_cloneMocSymCtx (pSrc->pMocSymCtx, &pNewSymCtx);
    if (OK != status)
      goto exit;

    pNew->pMocSymCtx = pNewSymCtx; pNewSymCtx = NULL;
    pNew->enabled = pSrc->enabled;
    pNew->pBHAlgo = pSrc->pBHAlgo;
  }
  else
  {
#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && (!defined(__DISABLE_DIGICERT_HMAC__))
    /* No Clone API to passthrough to until we can modify FIPS boundary */
    
    /* We need a deep copy but start with a shallow one */
    status = DIGI_MEMCPY((void *)pNew, (void *)pSrc, sizeof(HMAC_CTX));
    if (OK != status)
      goto exit;

    /* now put our own hash ctx if possible */
    if (NULL != pSrc->pBHAlgo && NULL != pSrc->hashCtxt)
    {
      ubyte hashId;
      BulkCtx pNewHash = NULL;
   
      status = pSrc->pBHAlgo->allocFunc(MOC_HASH(hwAccelCtx) &pNewHash);
      if (OK != status)
        goto exit;

      /* There is no clone in the pBHAlgo, so we need to switch on the hash_id */
      status = CRYPTO_INTERFACE_HmacGetHashAlgoFlag (pSrc->pBHAlgo, &hashId);
      if (OK != status)
        goto exit_free_hash;
 
      switch (hashId)
      {
#ifdef __ENABLE_DIGICERT_MD4__
        case ht_md4:
          status = CRYPTO_INTERFACE_MD4_cloneCtx(MOC_HASH(hwAccelCtx) (MD4_CTX *) pNewHash, (MD4_CTX *) pSrc->hashCtxt);
          break;
#endif
        case ht_md5:
          status = CRYPTO_INTERFACE_MD5_cloneCtx(MOC_HASH(hwAccelCtx) (MD5_CTX *) pNewHash, (MD5_CTX *) pSrc->hashCtxt);
          break;

        case ht_sha1:
          status = CRYPTO_INTERFACE_SHA1_cloneCtx(MOC_HASH(hwAccelCtx) (SHA1_CTX *) pNewHash, (SHA1_CTX *) pSrc->hashCtxt);
          break;

#ifndef __DISABLE_DIGICERT_SHA224__
        case ht_sha224:
          status = CRYPTO_INTERFACE_SHA224_cloneCtx(MOC_HASH(hwAccelCtx) (SHA224_CTX *) pNewHash, (SHA224_CTX *) pSrc->hashCtxt);
          break;
#endif
#ifndef __DISABLE_DIGICERT_SHA256__
        case ht_sha256:
          status = CRYPTO_INTERFACE_SHA256_cloneCtx(MOC_HASH(hwAccelCtx) (SHA256_CTX *) pNewHash, (SHA256_CTX *) pSrc->hashCtxt);
          break;
#endif
#ifndef __DISABLE_DIGICERT_SHA384__
        case ht_sha384:
          status = CRYPTO_INTERFACE_SHA384_cloneCtx(MOC_HASH(hwAccelCtx) (SHA384_CTX *) pNewHash, (SHA384_CTX *) pSrc->hashCtxt);
          break;
#endif
#ifndef __DISABLE_DIGICERT_SHA512__
        case ht_sha512:
          status = CRYPTO_INTERFACE_SHA512_cloneCtx(MOC_HASH(hwAccelCtx) (SHA512_CTX *) pNewHash, (SHA512_CTX *) pSrc->hashCtxt);
          break;
#endif
#ifdef __ENABLE_DIGICERT_SHA3__
        case ht_sha3_224:
        case ht_sha3_256:
        case ht_sha3_384:
        case ht_sha3_512:
        case ht_shake128:
        case ht_shake256:
           status = CRYPTO_INTERFACE_SHA3_cloneCtx(MOC_HASH(hwAccelCtx) (SHA3_CTX *) pNewHash, (SHA3_CTX *) pSrc->hashCtxt);
           break;
#endif
        default:
           status = ERR_INVALID_INPUT;
           break;
      }
      if (OK != status)
         goto exit_free_hash;
      
      pNew->hashCtxt = pNewHash; pNewHash = NULL;
    
exit_free_hash:

      if (NULL != pNewHash)
      {
        (void) pSrc->pBHAlgo->freeFunc(MOC_HASH(hwAccelCtx) &pNewHash);
      }
    }
    else
    {
      /* make sure hashCtxt is NULL on new context */
      pNew->hashCtxt = NULL;
    }
#else
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    goto exit;
#endif /*(!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && (!defined(__DISABLE_DIGICERT_HMAC__)) */
  }

  *ppDest = pNew; pNew = NULL;

exit:
  
  if (NULL != pNew)
  {
    (void) DIGI_FREE((void **) &pNew); /* no need to zero out */
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacQuickerEx (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  const ubyte *pOptText,
  ubyte4 optTextLen,
  ubyte *pResult,
  const BulkHashAlgo *pBHAlgo,
  HMAC_CTX *pCtx
  )
{
  MSTATUS status;

  status = CRYPTO_INTERFACE_HmacKey (
    MOC_HASH(hwAccelCtx) pCtx, pKey, keyLen);
  if (OK != status)
    goto exit;

  status = CRYPTO_INTERFACE_HmacUpdate (
    MOC_HASH(hwAccelCtx) pCtx, pText, textLen);
  if (OK != status)
    goto exit;

  if ( (NULL != pOptText) && (0 != optTextLen) )
  {
    status = CRYPTO_INTERFACE_HmacUpdate (
      MOC_HASH(hwAccelCtx) pCtx, pOptText, optTextLen);
    if (OK != status)
      goto exit;
  }

  status = CRYPTO_INTERFACE_HmacFinal (
    MOC_HASH(hwAccelCtx) pCtx, pResult);
  if (OK != status)
    goto exit;

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacQuicker (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  ubyte *pResult,
  const BulkHashAlgo *pBHAlgo,
  HMAC_CTX *pCtx
  )
{
  return CRYPTO_INTERFACE_HmacQuickerEx (
    MOC_HASH(hwAccelCtx) pKey, keyLen, pText, textLen, NULL, 0, pResult,
    pBHAlgo, pCtx);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacQuickEx (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  const ubyte *pOptText,
  ubyte4 optTextLen,
  ubyte *pResult,
  const BulkHashAlgo *pBHAlgo
  )
{
  MSTATUS status;
  HMAC_CTX *pCtx = NULL;

  status = CRYPTO_INTERFACE_HmacCreate (
    MOC_HASH(hwAccelCtx) &pCtx, pBHAlgo);
  if (OK != status)
    goto exit;

  status = CRYPTO_INTERFACE_HmacQuickerEx (
    MOC_HASH(hwAccelCtx) pKey, keyLen, pText, textLen, pOptText, optTextLen,
    pResult, pBHAlgo, pCtx);
  if (OK != status)
    goto exit;

exit:

  if (NULL != pCtx)
  {
    CRYPTO_INTERFACE_HmacDelete(MOC_HASH(hwAccelCtx) &pCtx);
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacQuick (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  ubyte *pResult,
  const BulkHashAlgo *pBHAlgo
  )
{
  return CRYPTO_INTERFACE_HmacQuickEx (
    MOC_HASH(hwAccelCtx) pKey, keyLen, pText, textLen, NULL, 0, pResult, pBHAlgo);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacSingle (
  MOC_HASH(hwAccelDescr hwAccelCtx) HMAC_CTX *pCtx,
  const ubyte *pText,
  sbyte4 textLen,
  ubyte *pResult
  )
{
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if (NULL == pCtx)
    goto exit;

  /* Call TAP APIs if needed, otherwise use existing calls */
  if ( (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled) &&
       (NULL != pCtx->pMocSymCtx && (0 != (MOC_LOCAL_TYPE_TAP & pCtx->pMocSymCtx->localType))) )
  {
    status = CRYPTO_INTERFACE_TAP_HmacSingle(pCtx->pMocSymCtx, pText, textLen, pResult);
  }
  else
  {
    status = CRYPTO_INTERFACE_HmacUpdate (
      MOC_HASH(hwAccelCtx) pCtx, pText, textLen);
    if (OK != status)
      goto exit;

    status = CRYPTO_INTERFACE_HmacFinal (
      MOC_HASH(hwAccelCtx) pCtx, pResult);
    if (OK != status)
      goto exit;
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacQuickerInlineEx (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  const ubyte *pOptText,
  sbyte4 optTextLen,
  ubyte *pResult,
  const BulkHashAlgo *pBHAlgo,
  BulkCtx pContext
  )
{
  /* pContext is dereferenced in no CI version, this is added to match
   * negative test results between implementations. */
  if(NULL == pContext)
    return ERR_NULL_POINTER;

  return CRYPTO_INTERFACE_HmacQuickEx (
    MOC_HASH(hwAccelCtx) pKey, keyLen, pText, textLen, pOptText, optTextLen,
    pResult, pBHAlgo);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HmacQuickerInline (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  ubyte *pResult,
  const BulkHashAlgo *pBHAlgo,
  BulkCtx pContext
  )
{
  return CRYPTO_INTERFACE_HmacQuick (
    MOC_HASH(hwAccelCtx) pKey, keyLen, pText, textLen, pResult, pBHAlgo);
}

/*---------------------------------------------------------------------------*/

static MSTATUS CRYPTO_INTERFACE_HmacProcess (
  const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  const ubyte *pTextOpt,
  sbyte4 textOptLen,
  ubyte4 index,
  ubyte hashAlgo,
  ubyte *pResult,
  ubyte4 resultLen
  )
{
  MSTATUS status;
  ubyte4 outLen = 0;
  MocSymCtx pCtx = NULL;

  status = ERR_NULL_POINTER;
  if (NULL == pResult)
    goto exit;

  if ( (NULL == pKey) && (0 < keyLen) )
    goto exit;

  if ( (NULL == pText) && (0 < textLen) )
    goto exit;

  status = CRYPTO_INTERFACE_createAndLoadSymKey (
    index, (void *)&hashAlgo, (ubyte *)pKey, (ubyte4)keyLen, &pCtx);
  if (OK != status)
    goto exit;

  status = CRYPTO_macInit(pCtx);
  if (OK != status)
    goto exit;

  status = CRYPTO_macUpdate(pCtx, (ubyte *)pText, (ubyte4)textLen);
  if (OK != status)
    goto exit;

  if ( (NULL != pTextOpt) && (0 < textOptLen) )
  {
    status = CRYPTO_macUpdate(pCtx, (ubyte *)pTextOpt, (ubyte4)textOptLen);
    if (OK != status)
      goto exit;
  }

  status = CRYPTO_macFinal (
    pCtx, NULL, 0, pResult, resultLen, &outLen);

exit:

  if (NULL != pCtx)
  {
    CRYPTO_freeMocSymCtx(&pCtx);
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HMAC_MD5 (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  const ubyte *pTextOpt,
  sbyte4 textOptLen,
  ubyte pResult[MD5_DIGESTSIZE]
  )
{
  MSTATUS status;
  ubyte4 algoStatus, index;

  /* Determine if we have an HMAC implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_hmac, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    /* Create the object and process the data */
    status = CRYPTO_INTERFACE_HmacProcess (
      pKey, keyLen, pText, textLen, pTextOpt, textOptLen,
      index, ht_md5, (ubyte *)pResult, MD5_DIGESTSIZE);
  }
  else
  {
    MOC_HMAC_MD5 (
      status, pKey, keyLen, pText, textLen, pTextOpt, textOptLen, pResult)
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HMAC_MD5_quick (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  ubyte *pResult
  )
{
  return CRYPTO_INTERFACE_HMAC_MD5 (
    MOC_HASH(hwAccelCtx) pKey, keyLen, pText, textLen, NULL, 0, pResult);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HMAC_SHA1 (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  const ubyte *pTextOpt,
  sbyte4 textOptLen,
  ubyte pResult[SHA_HASH_RESULT_SIZE]
  )
{
  MSTATUS status;
  ubyte4 algoStatus, index;

  /* Determine if we have an HMAC implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_hmac, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    /* Create the object and process the data */
    status = CRYPTO_INTERFACE_HmacProcess (
      pKey, keyLen, pText, textLen, pTextOpt, textOptLen,
      index, ht_sha1, (ubyte *)pResult, SHA_HASH_RESULT_SIZE);
  }
  else
  {
    MOC_HMAC_SHA1 (
      status, pKey, keyLen, pText, textLen, pTextOpt, textOptLen, pResult)
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HMAC_SHA1_96 (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  const ubyte *pTextOpt,
  sbyte4 textOptLen,
  ubyte *pResult
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ubyte pTemp[SHA_HASH_RESULT_SIZE];

  if (NULL == pResult)
    goto exit;

  status = CRYPTO_INTERFACE_HMAC_SHA1(MOC_HASH(hwAccelCtx) pKey, keyLen, pText, textLen, pTextOpt, textOptLen, pTemp);
  if (OK != status)
    goto exit;

  status = DIGI_MEMCPY(pResult, pTemp, 12); /* 96 bits is 12 bytes */

exit:

  (void) DIGI_MEMSET(pTemp, 0x00, SHA_HASH_RESULT_SIZE);

  return status;
}
 
/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HMAC_SHA1_quick (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  ubyte *pResult
  )
{
  return CRYPTO_INTERFACE_HMAC_SHA1 (
    MOC_HASH(hwAccelCtx) pKey, keyLen, pText, textLen, NULL, 0, pResult);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HMAC_SHA256 (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  const ubyte *pTextOpt,
  sbyte4 textOptLen,
  ubyte pResult[SHA256_RESULT_SIZE]
  )
{
  MSTATUS status;
  ubyte4 algoStatus, index;

  /* Determine if we have an HMAC implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_hmac, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    /* Create the object and process the data */
    status = CRYPTO_INTERFACE_HmacProcess (
      pKey, keyLen, pText, textLen, pTextOpt, textOptLen,
      index, ht_sha256, (ubyte *)pResult, SHA256_RESULT_SIZE);
  }
  else
  {
    MOC_HMAC_SHA256 (
      status, pKey, keyLen, pText, textLen, pTextOpt, textOptLen, pResult)
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HMAC_SHA512 (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *pText,
  sbyte4 textLen,
  const ubyte *pTextOpt,
  sbyte4 textOptLen,
  ubyte pResult[SHA512_RESULT_SIZE]
  )
{
  MSTATUS status;
  ubyte4 algoStatus, index;

  /* Determine if we have an HMAC implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_hmac, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    /* Create the object and process the data */
    status = CRYPTO_INTERFACE_HmacProcess (
      pKey, keyLen, pText, textLen, pTextOpt, textOptLen,
      index, ht_sha512, (ubyte *)pResult, SHA512_RESULT_SIZE);
  }
  else
  {
    MOC_HMAC_SHA512 (
      status, pKey, keyLen, pText, textLen, pTextOpt, textOptLen, pResult)
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_HMAC_SHA1Ex (
  MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pKey,
  sbyte4 keyLen,
  const ubyte *ppTexts[],
  sbyte4 pTextLens[],
  sbyte4 numTexts,
  ubyte pResult[SHA_HASH_RESULT_SIZE]
  )
{
  MSTATUS status;
  ubyte4 algoStatus, index;
  ubyte hashAlgo = ht_sha1;
  ubyte4 outLen = 0;
  MocSymCtx pCtx = NULL;

  /* Determine if we have an HMAC implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_hmac, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    status = ERR_NULL_POINTER;
    if ( (NULL == ppTexts) || (NULL == pTextLens) || (NULL == pResult) )
      goto exit;

    if ( (NULL == pKey) && (0 < keyLen) )
      goto exit;

    status = CRYPTO_INTERFACE_createAndLoadSymKey (
      index, (void *)&hashAlgo, (ubyte *)pKey, (ubyte4)keyLen, &pCtx);
    if (OK != status)
      goto exit;

    status = CRYPTO_macInit(pCtx);
    if (OK != status)
      goto exit;

    for (index = 0; (sbyte4)index < numTexts; index++)
    {
      status = CRYPTO_macUpdate(pCtx, (ubyte *)ppTexts[index], (ubyte4)pTextLens[index]);
      if (OK != status)
        goto exit;
    }

    status = CRYPTO_macFinal (
      pCtx, NULL, 0, (ubyte *)pResult, SHA_HASH_RESULT_SIZE, &outLen);
  }
  else
  {
    MOC_HMAC_SHA1_EX (
      status, pKey, keyLen, ppTexts, pTextLens, numTexts, pResult)
  }

exit:

  if (NULL != pCtx)
  {
    CRYPTO_freeMocSymCtx(&pCtx);
  }

  return status;
}

#endif
