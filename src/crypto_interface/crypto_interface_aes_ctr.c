/*
 * crypto_interface_aes_ctr.c
 *
 * Cryptographic Interface specification for AES COUNTER modes.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CTR_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../crypto/aes.h"
#include "../crypto/aesalgo.h"
#include "../crypto/aes_ecb.h"
#include "../crypto/aes_ctr.h"
#include "../crypto_interface/crypto_interface_aes_ctr.h"
#include "../crypto_interface/crypto_interface_aes_ctr_tap.h"
#include "../crypto_interface/crypto_interface_priv.h"
#ifdef __ENABLE_DIGICERT_TAP__
#include "../crypto/mocsymalgs/tap/symtap.h"
#endif

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CTR__))

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_CTR_CIPHER__))
#define MOC_AES_CREATE_CTR(_pCtx, _pKey, _keyLen, _encrypt)           \
    _pCtx = CreateAESCTRCtx(MOC_SYM(hwAccelCtx) _pKey, _keyLen, _encrypt); \
    if (NULL != _pCtx)                                                \
    {                                                                 \
        _pCtx->pMocSymCtx = NULL;                                     \
        _pCtx->enabled = CRYPTO_INTERFACE_ALGO_DISABLED;              \
    }
#else
#define MOC_AES_CREATE_CTR(_pCtx, _pKey, _keyLen, _encrypt)           \
    _pCtx = NULL;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_CTR_CIPHER__))
#define MOC_AES_AESCTRINIT(_status, _pCtx, _pData, _dataLength, _init)  \
    _status = AESCTRInit(MOC_SYM(hwAccelCtx) _pCtx, _pData, _dataLength, _init)
#else
#define MOC_AES_AESCTRINIT(_status, _pCtx, _pData, _dataLength, _init)  \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_CTR_CIPHER__))
#define MOC_AES_DOAESCTR(_status, _pCtx, _pData, _dataLength, _encrypt, _iv)  \
    _status = DoAESCTR(MOC_SYM(hwAccelCtx) _pCtx, _pData, _dataLength, _encrypt, _iv)
#else
#define MOC_AES_DOAESCTR(_status, _pCtx, _pData, _dataLength, _encrypt, _iv)  \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_CTR_CIPHER__))
#define MOC_AES_DOAESCTREX(_status, _pCtx, _pData, _dataLength, _encrypt, _iv, _limit)  \
    _status = DoAESCTREx(MOC_SYM(hwAccelCtx) _pCtx, _pData, _dataLength, _encrypt, _iv, _limit)
#else
#define MOC_AES_DOAESCTREX(_status, _pCtx, _pData, _dataLength, _encrypt, _iv, _limit)  \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) &&                  \
    (!defined(__DISABLE_AES_CIPHERS__)) &&                                    \
    (!defined(__DISABLE_AES_CTR_CIPHER__))
#define MOC_AES_DELETE_CTR_CTX(_status, _ppCtx)                               \
    _status = DeleteAESCTRCtx(MOC_SYM(hwAccelCtx) _ppCtx);
#else
#define MOC_AES_DELETE_CTR_CTX(_status, _ppCtx)                               \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) &&                  \
    (!defined(__DISABLE_AES_CIPHERS__)) &&                                    \
    (!defined(__DISABLE_AES_CTR_CIPHER__))
#define MOC_AES_CLONE_CTR_CTX(_status, _pCtx, _ppCtx)                         \
    _status = CloneAESCTRCtx(MOC_SYM(hwAccelCtx) _pCtx, _ppCtx);
#else
#define MOC_AES_CLONE_CTR_CTX(_status, _pCtx, _ppCtx)                         \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) &&                  \
    (!defined(__DISABLE_AES_CIPHERS__)) &&                                    \
    (!defined(__DISABLE_AES_CTR_CIPHER__))
#define MOC_AES_GET_COUNTER_BLOCK(_status, _ctx, _pCounterBlock)              \
    _status = GetCounterBlockAESCTR(MOC_SYM(hwAccelCtx) _ctx, _pCounterBlock);
#else
#define MOC_AES_GET_COUNTER_BLOCK(_status, _ctx, _pCounterBlock)              \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_CTR_CIPHER__))
#define MOC_AES_CREATE_CTR_IPSEC(_pCtx, _pKey, _keyLen, _encrypt)             \
    _pCtx = CreateAesCtrCtx(MOC_SYM(hwAccelCtx) _pKey, _keyLen, _encrypt);    \
    if (NULL != _pCtx)                                                        \
    {                                                                         \
        _pCtx->pMocSymCtx = NULL;                                             \
        _pCtx->enabled = CRYPTO_INTERFACE_ALGO_DISABLED;                      \
    }
#else
#define MOC_AES_CREATE_CTR_IPSEC(_pCtx, _pKey, _keyLen, _encrypt)             \
    _pCtx = NULL
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_CTR_CIPHER__))
#define MOC_AES_DOAESCTR_IPSEC(_status, _pCtx, _pData, _dataLength, _encrypt, _iv)  \
    _status = DoAesCtrEx(MOC_SYM(hwAccelCtx) _pCtx, _pData, _dataLength, _encrypt, _iv)
#else
#define MOC_AES_DOAESCTR_IPSEC(_status, _pCtx, _pData, _dataLength, _encrypt, _iv)  \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_AESCTRInit (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  AES_CTR_Ctx* pCtx,
  const ubyte* pKeyMaterial,
  sbyte4 keyMaterialLength,
  const ubyte pInitCounter[AES_BLOCK_SIZE]
  )
{
  MSTATUS status;
  ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
  MocSymCtx pNewSymCtx = NULL;
  MocCtx pMocCoreCtx = NULL;
  MAesCtrUpdateData aesParams = {0};
  ubyte4 index = 0;

  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_aes_ctr, &algoStatus, &index);
  if (OK != status)
    goto exit;

  /*
   We do allow for the user to call CRYPTO_INTERFACE_AESCTRInit without a call to
   CRYPTO_INTERFACE_CreateAESCTRCtx, so don't get CRYPTO_INTERFACE_ALGO_ENABLED from
   the pCtx, get it from algoStatus.
   */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    status = ERR_NULL_POINTER;
    if (NULL == pCtx)
      goto exit;

    status = DIGI_MEMSET((ubyte*)pCtx, 0x00, sizeof(aesCTRCipherContext));
    if (OK != status)
      goto exit;

    /* set enabled immediately, so in case of error, delete will handle correctly */
    pCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

    status = CRYPTO_INTERFACE_getMocCtx (&pMocCoreCtx);
    if (OK != status)
      goto exit;

    /* MocSymCtx has to be created before we updateSymOperatorData. */
    status = CRYPTO_INTERFACE_createAndLoadSymKey (
      index, NULL, (ubyte *) pKeyMaterial, (ubyte4)keyMaterialLength, &pNewSymCtx);
    if (OK != status)
      goto exit;

    /* pInitCounter is the full 16 bytes, so we set just the iv field */
    aesParams.iv.pData = (ubyte *) pInitCounter;
    aesParams.iv.length = AES_BLOCK_SIZE;
    /* aesParams.updateStreamOffset is 0, FALSE, by default */

    status = CRYPTO_updateSymOperatorData (
      pNewSymCtx, pMocCoreCtx, (void *)&aesParams);
    if (OK != status)
      goto exit;

    /* initialize cipher operation since we have all necessary data */
    status = CRYPTO_cipherInit(pNewSymCtx, MOC_CIPHER_FLAG_ENCRYPT);
    if (OK != status)
      goto exit;

    pCtx->pMocSymCtx = pNewSymCtx;
    pNewSymCtx = NULL;
  }
  else
  {
    MOC_AES_AESCTRINIT(status, pCtx, pKeyMaterial, keyMaterialLength, pInitCounter);
  }

exit:

  if (NULL != pNewSymCtx)
      CRYPTO_freeMocSymCtx(&pNewSymCtx);  /* don't change status so no need to check return code */

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateAESCTRCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte* pKeyMaterial,
  sbyte4 keyLength,
  sbyte4 encrypt
  )
{
  MSTATUS status;
  ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
  aesCTRCipherContext *pCtx = NULL;
  MOC_UNUSED(encrypt);

  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_aes_ctr, &algoStatus, NULL);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    status = DIGI_CALLOC((void **)&pCtx, 1, sizeof(aesCTRCipherContext));
    if (OK != status)
      goto exit;

    /* the last 16 bytes are the counter, adjust keyLength accordingly. */
    keyLength -= AES_BLOCK_SIZE;
    status = CRYPTO_INTERFACE_AESCTRInit(MOC_SYM(hwAccelCtx) pCtx, pKeyMaterial, (ubyte4)keyLength,
      pKeyMaterial + keyLength);
  }
  else
  {
    MOC_AES_CREATE_CTR(pCtx, pKeyMaterial, keyLength, encrypt)
  }

exit:

  if ( (OK != status) && (NULL != pCtx) )
    CRYPTO_INTERFACE_DeleteAESCTRCtx(MOC_SYM(hwAccelCtx) (BulkCtx *) &pCtx); /* don't change status so no need to check return code */

  return pCtx;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DeleteAESCTRCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx
  )
{
  MSTATUS status, fstatus;
  aesCTRCipherContext *pCtx = NULL;

  status = ERR_NULL_POINTER;
  if (NULL == ppCtx)
    goto exit;

  /* It is not an error to attempt to free a NULL context */
  status = OK;
  pCtx = (aesCTRCipherContext *)(*ppCtx);
  if (NULL == pCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  {
    if (NULL != pCtx->pMocSymCtx && (0 != (MOC_LOCAL_TYPE_TAP & pCtx->pMocSymCtx->localType)) )
    {
      status = CRYPTO_INTERFACE_TAP_DeleteAESCTRCtx(pCtx->pMocSymCtx);
    }

     /* Free the underlying context.  */
    fstatus = CRYPTO_freeMocSymCtx(&(pCtx->pMocSymCtx));
    if (OK == status)
      status = fstatus;

    /* Free the shell */
    fstatus = DIGI_FREE((void **)&pCtx);
    if (OK == status)
      status = fstatus;

    /* NULL out the callers pointer */
    *ppCtx = NULL;
  }
  else
  {
    MOC_AES_DELETE_CTR_CTX(status, ppCtx)
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_CloneAESCTRCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  BulkCtx *ppNewCtx
  )
{
  MSTATUS status;
  aesCTRCipherContext *pAesCtx = NULL;
  aesCTRCipherContext *pNewAesCtx = NULL;
  MocSymCtx pNewSymCtx = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pCtx) || (NULL == ppNewCtx) )
    goto exit;

  pAesCtx = (aesCTRCipherContext *)pCtx;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pAesCtx->enabled)
  {
    /* Clone the underlying MocSymCtx */
    status = CRYPTO_cloneMocSymCtx(pAesCtx->pMocSymCtx, &pNewSymCtx);
    if (OK != status)
      goto exit;

    status = DIGI_CALLOC((void **)&pNewAesCtx, 1, sizeof(aesCTRCipherContext));
    if (OK != status)
      goto exit;

    status = DIGI_MEMCPY((void *)pNewAesCtx, (void *)pAesCtx, sizeof(aesCTRCipherContext));
    if (OK != status)
      goto exit;

    pNewAesCtx->pMocSymCtx = pNewSymCtx;
    pNewSymCtx = NULL;
    *ppNewCtx = (BulkCtx)pNewAesCtx;
    pNewAesCtx = NULL;

  }
  else
  {
    MOC_AES_CLONE_CTR_CTX(status, pCtx, ppNewCtx)
  }

exit:
  if (NULL != pNewSymCtx)
  {
    CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }
  if (NULL != pNewAesCtx)
  {
    DIGI_FREE((void **)&pNewAesCtx);
  }
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoAESCTREx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte* pData,
  sbyte4 dataLength,
  sbyte4 encrypt,
  ubyte* pIv,
  sbyte4 limit
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  sbyte4 retLength = -1;
  MocCtx pMocCoreCtx = NULL;
  MAesCtrUpdateData aesParams = {0};

  aesCTRCipherContext *pAesCtx = (aesCTRCipherContext *)pCtx;
  if (NULL == pAesCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pAesCtx->enabled)
  {
    if (NULL == pAesCtx->pMocSymCtx)
      goto exit;

    if (0 != (MOC_LOCAL_TYPE_TAP & pAesCtx->pMocSymCtx->localType))
    {
      status = CRYPTO_INTERFACE_TAP_DoAESCTR(pAesCtx->pMocSymCtx, pData, dataLength, pIv);
    }
    else
    {
      status = ERR_INVALID_ARG;
      if ( (AES_BLOCK_SIZE < limit) || (limit < 0) )
        goto exit;

      status = ERR_NULL_POINTER;
      if (NULL == pData)
        goto exit;

      if(NULL != pIv)
      {
        status = CRYPTO_INTERFACE_getMocCtx (&pMocCoreCtx);
        if (OK != status)
          goto exit;

        /* pIv is the full 16 bytes, so we set just the iv field */
        aesParams.iv.pData = pIv;
        aesParams.iv.length = AES_BLOCK_SIZE;
        /* aesParams.updateStreamOffset is 0, FALSE, by default */

        status = CRYPTO_updateSymOperatorData (
        pAesCtx->pMocSymCtx, pMocCoreCtx, (void *)&aesParams);
        if (OK != status)
          goto exit;
      }

      status = CRYPTO_cipherUpdate (
        pAesCtx->pMocSymCtx, MOC_CIPHER_FLAG_ENCRYPT, pData, (ubyte4)dataLength,
        pData, (ubyte4)dataLength, (ubyte4 *) &retLength);
    }
  }
  else
  {
    MOC_AES_DOAESCTREX(status, pCtx, pData, dataLength, encrypt, pIv, limit);
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_GetCounterBlockAESCTR (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte pCounterBuffer[AES_BLOCK_SIZE]
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MSymOperatorData operatorData = {0};

  aesCTRCipherContext *pAesCtx = (aesCTRCipherContext *)pCtx;
  if (NULL == pAesCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pAesCtx->enabled)
  {

    operatorData.pData = pCounterBuffer;
    status = CRYPTO_getSymOperatorData(pAesCtx->pMocSymCtx, NULL, &operatorData);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pCounterBuffer, operatorData.pData, AES_BLOCK_SIZE);
    if (OK != status)
        goto exit;
  }
  else
  {
    MOC_AES_GET_COUNTER_BLOCK(status, pCtx, pCounterBuffer);
  }

exit:
  return status;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoAESCTR (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte* pData,
  sbyte4 dataLength,
  sbyte4 encrypt,
  ubyte* pIv
  )
{
  return CRYPTO_INTERFACE_DoAESCTREx(MOC_SYM(hwAccelCtx) pCtx, pData, dataLength, encrypt, pIv, AES_BLOCK_SIZE);
}

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_IPSEC_SERVICE__

MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateAesCtrCtx(
  MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *pKeyMaterial,
  sbyte4 keyLength,
  sbyte4 encrypt
  )
{
  MSTATUS status;
  ubyte4 algoStatus, index;
  aesCTRCipherContext *pCtx = NULL;
  MOC_UNUSED(encrypt);

  status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_aes_ctr, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    MocSymCtx pNewSymCtx = NULL;
    MocCtx pMocCoreCtx = NULL;
    MAesCtrUpdateData aesParams = {0};

    /* sanity check on the keyLength before proceeding */
    status = ERR_AES_BAD_KEY_LENGTH;
    if (20 != keyLength && 28 != keyLength && 36 != keyLength)
      goto exit;

    status = DIGI_CALLOC((void **)&pCtx, 1, sizeof(aesCTRCipherContext));
    if (OK != status)
      goto exit;

    /* set enabled immediately, so in case of error, delete will handle correctly */
    pCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

    status = CRYPTO_INTERFACE_getMocCtx (&pMocCoreCtx);
    if (OK != status)
      goto exit;

    /* MocSymCtx has to be created before we updateSymOperatorData. */
    status = CRYPTO_INTERFACE_createAndLoadSymKey (index, NULL, pKeyMaterial, (ubyte4) (keyLength - 4), &pNewSymCtx);
    if (OK != status)
      goto exit;

    /* the nonce is the 4 bytes after the key */
    aesParams.nonce.pData = pKeyMaterial + keyLength - 4;
    aesParams.nonce.length = 4;
    aesParams.updateStreamOffset = TRUE;
    /* aesParams.streamOffset is 0 already */

    status = CRYPTO_updateSymOperatorData (pNewSymCtx, pMocCoreCtx, (void *)&aesParams);
    if (OK != status)
      goto exit;

    /* initialize cipher operation since we have all necessary data */
    status = CRYPTO_cipherInit(pNewSymCtx, MOC_CIPHER_FLAG_ENCRYPT);
    if (OK != status)
      goto exit;

    pCtx->pMocSymCtx = pNewSymCtx;
  }
  else
  {
    MOC_AES_CREATE_CTR_IPSEC(pCtx, pKeyMaterial, keyLength, encrypt);
  }

exit:

  if ( (OK != status) && (NULL != pCtx) )
    CRYPTO_INTERFACE_DeleteAESCTRCtx(MOC_SYM(hwAccelCtx) (BulkCtx *) &pCtx); /* don't change status so no need to check return code */

  return pCtx;
}


MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoAesCtrEx(
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pData,
  sbyte4 dataLength,
  sbyte4 encrypt,
  ubyte *pIv
  )
{
  MSTATUS status = ERR_NULL_POINTER;

  aesCTRCipherContext *pAesCtx = (aesCTRCipherContext *)pCtx;
  if (NULL == pAesCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pAesCtx->enabled)
  {
    sbyte4 retLength = -1;
    MocCtx pMocCoreCtx = NULL;
    MAesCtrUpdateData aesParams = {0};
    /* update the ctr to a hardcoded big endian 1 */
    ubyte pCtr[4] = {0x00, 0x00, 0x00, 0x01};

    status = ERR_NULL_POINTER;
    if (NULL == pData || NULL == pIv)
      goto exit;

    status = CRYPTO_INTERFACE_getMocCtx (&pMocCoreCtx);
    if (OK != status)
      goto exit;

    /* iv is just the 8 byte portion  */
    aesParams.iv.pData = pIv;
    aesParams.iv.length = 8;
    aesParams.ctr.pData = pCtr;
    aesParams.ctr.length = 4;
    aesParams.updateStreamOffset = TRUE;
    /* aesParams.streamOffset is 0, FALSE, by default */

    status = CRYPTO_updateSymOperatorData (pAesCtx->pMocSymCtx, pMocCoreCtx, (void *)&aesParams);
    if (OK != status)
      goto exit;

    status = CRYPTO_cipherUpdate (pAesCtx->pMocSymCtx, MOC_CIPHER_FLAG_ENCRYPT, pData, (ubyte4) dataLength,
                                  pData, (ubyte4) dataLength, (ubyte4 *) &retLength);
  }
  else
  {
    MOC_AES_DOAESCTR_IPSEC(status, pCtx, pData, dataLength, encrypt, pIv);
  }

exit:

  return status;
}
#endif /* __ENABLE_DIGICERT_IPSEC_SERVICE__ */

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_UpdateAesCtrEx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte* pInput,
  sbyte4 inputLen,
  ubyte *pOutput,
  sbyte4 *pBytesWritten
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  aesCTRCipherContext *pAesCtx = (aesCTRCipherContext *)pCtx;

  if (NULL == pAesCtx || NULL == pBytesWritten)
    goto exit;

  *pBytesWritten = 0;

  /* For TAP we will process in 16 bytes blocks only */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pAesCtx->enabled && NULL != pAesCtx->pMocSymCtx && 0 != (MOC_LOCAL_TYPE_TAP & pAesCtx->pMocSymCtx->localType))
  {
#ifdef __ENABLE_DIGICERT_TAP__
    ubyte4 bytesToProcess = 0;
    MTapKeyData *pTapData = (MTapKeyData *) pAesCtx->pMocSymCtx->pLocalData;

    if (NULL == pTapData)
      goto exit;

    /* process leftover bytes first */
    if (pTapData->leftOverLen)
    {
      /* do we have enough for a full block? */
      if ( (ubyte4) inputLen + pTapData->leftOverLen >= AES_BLOCK_SIZE )
      {
        bytesToProcess = AES_BLOCK_SIZE - pTapData->leftOverLen;

        status = DIGI_MEMCPY(pTapData->pLeftOvers + pTapData->leftOverLen, pInput, bytesToProcess);
        if (OK != status)
          goto exit;

        /* process the full block in the leftovers buffer */
        status = CRYPTO_INTERFACE_TAP_DoAESCTR(pAesCtx->pMocSymCtx, pTapData->pLeftOvers, AES_BLOCK_SIZE, NULL);
        if (OK != status)
          goto exit;

        status = DIGI_MEMCPY(pOutput, pTapData->pLeftOvers, AES_BLOCK_SIZE);
        if (OK != status)
          goto exit;

        pInput += bytesToProcess; /* OK to move passed by value ptr */
        inputLen -= (sbyte4) bytesToProcess;

        pOutput += AES_BLOCK_SIZE; /* OK to move passed by value ptr */
        (*pBytesWritten) += AES_BLOCK_SIZE;

        pTapData->leftOverLen = 0;
      }
      else
      {
        status = DIGI_MEMCPY(pTapData->pLeftOvers + pTapData->leftOverLen, pInput, inputLen);
        if (OK != status)
          goto exit;

        inputLen = 0;
      }
    }

    /* process any remaining full blocks */
    bytesToProcess = (ubyte4) (inputLen / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    if (bytesToProcess && pInput != pOutput)
    {
      status = DIGI_MEMCPY(pOutput, pInput, bytesToProcess);
      if (OK != status)
        goto exit;
    }

    if (bytesToProcess > 0)
    {
      status = CRYPTO_INTERFACE_TAP_DoAESCTR(pAesCtx->pMocSymCtx, pOutput, bytesToProcess, NULL);
      if (OK != status)
        goto exit;
    }

    pInput += bytesToProcess; /* OK to move passed by value ptr */
    inputLen -= (sbyte4) bytesToProcess;

    /* done with output so no need to move ptr */
    (*pBytesWritten) += (sbyte4) bytesToProcess;

    /* if still leftovers, copy to the buffer */
    if (inputLen)
    {
      status = DIGI_MEMCPY(pTapData->pLeftOvers, pInput, inputLen);
      if (OK != status)
        goto exit;

      pTapData->leftOverLen = (ubyte4) inputLen;
    }
#else
    status = ERR_TAP_UNSUPPORTED;
#endif
  }
  else
  {
    /* if different input and output buffers then we need to copy the input data for an in-place cipher op */
    if (inputLen && pInput != pOutput)
    {
      status = DIGI_MEMCPY(pOutput, pInput, inputLen);
      if (OK != status)
        goto exit;
    }

    status = CRYPTO_INTERFACE_DoAESCTREx (MOC_SYM(hwAccelCtx) pCtx, pOutput, inputLen, 0, NULL, AES_BLOCK_SIZE);
    if (OK != status)
      goto exit;

    *pBytesWritten = inputLen;
  }

exit:

  return status;
}


MOC_EXTERN MSTATUS CRYPTO_INTERFACE_FinalAesCtrEx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pOutput,
  sbyte4 *pBytesWritten
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  aesCTRCipherContext *pAesCtx = (aesCTRCipherContext *)pCtx;

  if (NULL == pAesCtx || NULL == pBytesWritten)
    goto exit;

  *pBytesWritten = 0;

  /* For TAP we will process in 16 bytes blocks only */
  if (CRYPTO_INTERFACE_ALGO_ENABLED == pAesCtx->enabled && NULL != pAesCtx->pMocSymCtx && 0 != (MOC_LOCAL_TYPE_TAP & pAesCtx->pMocSymCtx->localType))
  {
#ifdef __ENABLE_DIGICERT_TAP__
    MTapKeyData *pTapData = (MTapKeyData *) pAesCtx->pMocSymCtx->pLocalData;

    if (NULL == pTapData)
      goto exit;

    /* process any leftovers */
    if (pTapData->leftOverLen)
    {
      /* process the leftovers buffer, ok to include the garbage bytes after leftOverLen bytes */
      status = CRYPTO_INTERFACE_TAP_DoAESCTR(pAesCtx->pMocSymCtx, pTapData->pLeftOvers, AES_BLOCK_SIZE, NULL);
      if (OK != status)
        goto exit;

      /* only copy the proper leftOverLen bytes */
      status = DIGI_MEMCPY(pOutput, pTapData->pLeftOvers, pTapData->leftOverLen);
      if (OK != status)
        goto exit;

      (*pBytesWritten) += (sbyte4) pTapData->leftOverLen;
    }
#else
    return ERR_TAP_UNSUPPORTED;
#endif
  }

  /* no-op if not TAP */

  status = OK;

exit:

  return status;
}

#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CTR__ */
