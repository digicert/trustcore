/*
 * crypto_interface_chacha20.c
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_CHACHA20_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../crypto/chacha20.h"
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/crypto_interface_chacha20.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_CHACHA20__))

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_CHACHA20_CREATE(_pCtx, _pKey, _keyLen, _mode)                     \
    _pCtx = CreateChaCha20Ctx(MOC_SYM(hwAccelCtx) _pKey, _keyLen, _mode);    \
    if (NULL != _pCtx)                                                        \
    {                                                                         \
      _pCtx->pMocSymCtx = NULL;                                               \
      _pCtx->enabled = 0;                                                     \
    }
#else
#define MOC_CHACHA20_CREATE(_pCtx, _pKey, _keyLen, _mode)                     \
    _pCtx = NULL
#endif

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_CHACHA20_DO(_status, _pCtx, _pData, _dataLen, _mode, _pIv)        \
    _status = DoChaCha20(MOC_SYM(hwAccelCtx) _pCtx, _pData, _dataLen, _mode, _pIv)
#else
#define MOC_CHACHA20_DO(_status, _pCtx, _pData, _dataLen, _mode, _pIv)        \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_CHACHA20_DELETE(_status, _ppCtx)                                  \
    _status = DeleteChaCha20Ctx(MOC_SYM(hwAccelCtx) _ppCtx)
#else
#define MOC_CHACHA20_DELETE(_status, _ppCtx)                                  \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_CHACHA20_SET_NONCE_COUNTER_SSH(_status, _pCtx, _pNonce, _nonceLength, _pCounter, _counterLength) \
    _status = CHACHA20_setNonceAndCounterSSH (                                                               \
      MOC_SYM(hwAccelCtx) _pCtx, _pNonce, _nonceLength, _pCounter, _counterLength)
#else
#define MOC_CHACHA20_SET_NONCE_COUNTER_SSH(_status, _pCtx, _pNonce, _nonceLength, _pCounter, _counterLength) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_CHACHA20POLY1305_CREATE(_pCtx, _pKey, _keyLen, _encrypt)          \
    _pCtx = ChaCha20Poly1305_createCtx (                                      \
      MOC_SYM(hwAccelCtx) _pKey, _keyLen, _encrypt);                         \
    if (NULL != _pCtx)                                                        \
    {                                                                         \
      _pCtx->pMocSymCtx = NULL;                                               \
      _pCtx->enabled = 0;                                                     \
    }
#else
#define MOC_CHACHA20POLY1305_CREATE(_pCtx, _pKey, _keyLen, _encrypt)          \
    _pCtx = NULL
#endif

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_CHACHA20POLY1305_CIPHER_SSH(_status, _pCtx, _pNonce, _nLen, _pAdata,    \
                                        _alen, _pData, _dlen, _verifyLen, _encrypt) \
    _status = ChaCha20Poly1305_cipherSSH (                                          \
      MOC_SYM(hwAccelCtx) _pCtx, _pNonce, _nLen, _pAdata, _alen, _pData, _dlen, _verifyLen, _encrypt)
#else
#define MOC_CHACHA20POLY1305_CIPHER_SSH(_status, _pCtx, _pNonce, _nLen, _pAdata,    \
                                        _alen, _pData, _dlen, _verifyLen, _encrypt) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_CHACHA20POLY1305_UPDATE_NONCE(_status, _ppCtx, _pNonce, _nonceLen) \
    _status = ChaCha20Poly1305_update_nonce(MOC_SYM(hwAccelCtx) _ppCtx, _pNonce, _nonceLen)
#else
#define MOC_CHACHA20POLY1305_UPDATE_NONCE(_status, _ppCtx, _pNonce, _nonceLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_CHACHA20POLY1305_UPDATE_AAD(_status, _ppCtx, _pAadData, _pAadDataLen) \
    _status = ChaCha20Poly1305_update_aad(MOC_SYM(hwAccelCtx) _ppCtx, _pAadData, _pAadDataLen)
#else
#define MOC_CHACHA20POLY1305_UPDATE_AAD(_status, _ppCtx, _pAadData, _pAadDataLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_CHACHA20POLY1305_UPDATE_DATA(_status, _ppCtx, _pData, _dataLen)    \
    _status = ChaCha20Poly1305_update_data(MOC_SYM(hwAccelCtx) _ppCtx, _pData, _dataLen)
#else
#define MOC_CHACHA20POLY1305_UPDATE_DATA(_status, _ppCtx, _pData, _dataLen)    \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_CHACHA20POLY1305_FINAL(_status, _ppCtx, _pTag, _tagLen)            \
    _status = ChaCha20Poly1305_final(MOC_SYM(hwAccelCtx) _ppCtx, _pTag, _tagLen)
#else
#define MOC_CHACHA20POLY1305_FINAL(_status, _ppCtx, _pTag, _tagLen)            \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_CHACHA20POLY1305_CLONE(_status, _pCtx, _ppCtx)                     \
    _status = ChaCha20Poly1305_cloneCtx(MOC_SYM(hwAccelCtx) _pCtx, _ppCtx);
#else
#define MOC_CHACHA20POLY1305_CLONE(_status, _pCtx, _ppCtx)                     \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/


MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateChaCha20Ctx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  const ubyte pKey[48],
  sbyte4 keyLen,
  sbyte4 mode
  )
{
  MSTATUS status;
  ubyte4 algoStatus, index;
  MocSymCtx pNewSymCtx = NULL;
  ChaCha20Ctx *pCtx = NULL;

  MOC_UNUSED(mode);

  if (NULL == pKey)
    goto exit;

  /* Verify key length */
  /* 32 byte key, 4byte counter, 12 byte nonce */
  if (48 != keyLen)
    goto exit;

  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_chacha20, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    MChaChaUpdateData chachaParams = {0};
    MocCtx pMocCtx = NULL;

    /* Create a copy of the Operator MocSymCtx and store the key within it */
    status = CRYPTO_INTERFACE_createAndLoadSymKey (
      index, NULL, (ubyte *) pKey, 32, &pNewSymCtx);
    if (OK != status)
      goto exit;

    /* Get a reference to the MocCtx within the Crypto Interface Core */
    status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
    if (OK != status)
      goto exit;

    /* Update the Operator with the nonce and counter */
    chachaParams.nonce.pData = ( (ubyte *) (pKey + 36) );
    chachaParams.nonce.length = 12;
    chachaParams.counter = ( (ubyte4) *(pKey + 32) );
    status = CRYPTO_updateSymOperatorData (
      pNewSymCtx, pMocCtx, (void *) &chachaParams);
    if (OK != status)
      goto exit;

    status = CRYPTO_cipherInit(pNewSymCtx, 0);
    if (OK != status)
      goto exit;

    /* Allocate the ChaCha20 context */
    status = DIGI_CALLOC ((void **) &pCtx, 1, sizeof (ChaCha20Ctx));
    if (OK != status)
      goto exit;

    pCtx->pMocSymCtx = pNewSymCtx;
    pNewSymCtx = NULL;

    /* Mark this object to indicate that it is using an alternate
     * implementation through the crypto interface */
    pCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;
  }
  else
  {
    MOC_CHACHA20_CREATE(pCtx, pKey, keyLen, mode);
  }

exit:

  if (NULL != pNewSymCtx)
      CRYPTO_freeMocSymCtx (&pNewSymCtx); /* ok to ignore return, here only on error */

  return (BulkCtx) pCtx;
}


/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoChaCha20 (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pBulkCtx,
  ubyte* pData,
  sbyte4 dataLen,
  sbyte4 mode,
  ubyte* pIv
  )
{
  MSTATUS status;
  ubyte4 dataOut;
  ChaCha20Ctx *pCtx = (ChaCha20Ctx *) pBulkCtx;

  MOC_UNUSED(mode);

  status = ERR_NULL_POINTER;
  if (NULL == pCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  {
    /* Invalid data, valid length */
    if ( (NULL == pData) && (0 < dataLen) )
      goto exit;  /* status still ERR_NULL_POINTER */

    if ( dataLen )
    {
      status = CRYPTO_cipherUpdate (
        pCtx->pMocSymCtx, 0, pData, (ubyte4) dataLen, pData, (ubyte4) dataLen,
        &dataOut);
      if (OK != status)
        goto exit;
    }
    status = OK;
  }
  else
  {
    MOC_CHACHA20_DO(status, pCtx, pData, dataLen, mode, pIv);
  }

exit:

  return status;
}


/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DeleteChaCha20Ctx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx *ppBulkCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ChaCha20Ctx *pCtx = NULL;

  if (NULL == ppBulkCtx)
    goto exit;

  status = OK; /* ok no-op if the context was already deleted */
  pCtx = ( (ChaCha20Ctx *) (*ppBulkCtx) );
  if (NULL == pCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  {
    MSTATUS fstatus;

    /* Free the underlying context */
    status = CRYPTO_freeMocSymCtx (&(pCtx->pMocSymCtx));

    /* Free the shell */
    fstatus = DIGI_FREE((void **) &pCtx);
    if (OK == status)
        status = fstatus;

    /* NULL-out the caller's pointer */
    *ppBulkCtx = NULL;
  }
  else
  {
    MOC_CHACHA20_DELETE(status, ppBulkCtx);
  }

exit:

  return status;
}


/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_CHACHA20_setNonceAndCounterSSH(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx ctx,
    ubyte *pNonce,
    ubyte4 nonceLength,
    ubyte *pCounter,
    ubyte counterLength
    )
{
  MSTATUS status = ERR_NULL_POINTER;
  ChaCha20Ctx *pCtx = NULL;

  if (NULL == ctx)
      goto exit;

  pCtx = (ChaCha20Ctx*) ctx;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_CHACHA20_SET_NONCE_COUNTER_SSH(status, ctx, pNonce, nonceLength, pCounter, counterLength);
  }

exit:
  return status;
}

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_POLY1305__))

/*----------------------------------------------------------------------------*/

MOC_EXTERN BulkCtx CRYPTO_INTERFACE_ChaCha20Poly1305_createCtx(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  ubyte *pKey,
  sbyte4 keyLen,
  sbyte4 encrypt
  )
{
  MSTATUS status;
  ubyte4 algoStatus, index;
  MocSymCtx pNewSymCtx = NULL;
  ChaCha20Ctx *pCtx = NULL;

  if (NULL == pKey)
    goto exit;

  /* Verify key length */
  /* 32 byte key */
  if (32 != keyLen)
    goto exit;

  status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_chachapoly, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    /* Create a copy of the Operator MocSymCtx and store the key within it */
    status = CRYPTO_INTERFACE_createAndLoadSymKey (index, &encrypt, (ubyte *) pKey, 32, &pNewSymCtx);
    if (OK != status)
      goto exit;

    /* we don't have the nonce or counter yet so we can't update the operator any further */

    /* Allocate the ChaCha20 context */
    status = DIGI_CALLOC ((void **) &pCtx, 1, sizeof (ChaCha20Ctx));
    if (OK != status)
      goto exit;

    pCtx->pMocSymCtx = pNewSymCtx;
    pNewSymCtx = NULL;

    /* Mark this object to indicate that it is using an alternate
     * implementation through the crypto interface */
    pCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;
  }
  else
  {
    MOC_CHACHA20POLY1305_CREATE(pCtx, pKey, keyLen, encrypt);
  }

exit:

  if (NULL != pNewSymCtx)
    CRYPTO_freeMocSymCtx (&pNewSymCtx); /* ok to ignore return, here only on error */

  return (BulkCtx) pCtx;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ChaCha20Poly1305_deleteCtx(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx *ppCtx
  )
{
  return CRYPTO_INTERFACE_DeleteChaCha20Ctx(MOC_SYM(hwAccelCtx) ppCtx);
}
/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ChaCha20Poly1305_cipherSSH(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pCtx,
  ubyte *pNonce,
  ubyte4 nonceLen,
  ubyte *pAad,
  ubyte4 aadLen,
  ubyte *pData,
  ubyte4 dataLen,
  ubyte4 verifyLen,
  sbyte4 encrypt
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ChaCha20Ctx *pChaChaCtx = (ChaCha20Ctx *) pCtx;

  if (NULL == pChaChaCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pChaChaCtx->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
    MOC_CHACHA20POLY1305_CIPHER_SSH(status, pCtx, pNonce, nonceLen, pAad, aadLen, pData, dataLen, verifyLen, encrypt);
  }

exit:
  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ChaCha20Poly1305_cipher(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pCtx,
  ubyte *pNonce,
  ubyte4 nonceLen,
  ubyte *pAad,
  ubyte4 aadLen,
  ubyte *pData,
  ubyte4 dataLen,
  ubyte4 verifyLen,
  sbyte4 encrypt
  )
{
  MSTATUS status;

  MOC_UNUSED(encrypt);

  status = CRYPTO_INTERFACE_ChaCha20Poly1305_update_nonce(MOC_SYM(hwAccelCtx) pCtx, pNonce, nonceLen);
  if (OK != status)
    goto exit;

  status = CRYPTO_INTERFACE_ChaCha20Poly1305_update_aad(MOC_SYM(hwAccelCtx) pCtx, pAad, aadLen);
  if (OK != status)
    goto exit;

  status = CRYPTO_INTERFACE_ChaCha20Poly1305_update_data(MOC_SYM(hwAccelCtx) pCtx, pData, dataLen);
  if (OK != status)
    goto exit;

  status = CRYPTO_INTERFACE_ChaCha20Poly1305_final(MOC_SYM(hwAccelCtx) pCtx, pData+dataLen, verifyLen);

exit:

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ChaCha20Poly1305_update_nonce(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pCtx,
  ubyte *pNonce,
  ubyte4 nonceLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ChaCha20Ctx *pChaChaCtx = (ChaCha20Ctx *) pCtx;

  if (NULL == pChaChaCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pChaChaCtx->enabled)
  {
    MChaChaUpdateData chachaParams = {0};
    MocCtx pMocCtx = NULL;

    /* Get a reference to the MocCtx within the Crypto Interface Core */
    status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
    if (OK != status)
      goto exit;

    /* Update the Operator with the nonce. Counter is zero automatically. */
    chachaParams.nonce.pData = pNonce;
    chachaParams.nonce.length = nonceLen;

    status = CRYPTO_updateSymOperatorData (pChaChaCtx->pMocSymCtx, pMocCtx, (void *) &chachaParams);
    if (OK != status)
      goto exit;

    status = CRYPTO_cipherInit(pChaChaCtx->pMocSymCtx, 0);
  }
  else
  {
    MOC_CHACHA20POLY1305_UPDATE_NONCE(status, pCtx, pNonce, nonceLen);
  }

exit:

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ChaCha20Poly1305_update_aad(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pCtx,
  ubyte *pAadData,
  ubyte4 aadDataLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ChaCha20Ctx *pChaChaCtx = (ChaCha20Ctx *) pCtx;

  if (NULL == pChaChaCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pChaChaCtx->enabled)
  {
    MChaChaUpdateData chachaParams = {0};
    MocCtx pMocCtx = NULL;

    /* Get a reference to the MocCtx within the Crypto Interface Core */
    status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
    if (OK != status)
      goto exit;

    /* Update the Operator with the aad. */
    chachaParams.aad.pData = pAadData;
    chachaParams.aad.length = aadDataLen;

    status = CRYPTO_updateSymOperatorData (pChaChaCtx->pMocSymCtx, pMocCtx, (void *) &chachaParams);
  }
  else
  {
    MOC_CHACHA20POLY1305_UPDATE_AAD(status, pCtx, pAadData, aadDataLen);
  }

exit:

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ChaCha20Poly1305_update_data(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pCtx,
  ubyte *pData,
  ubyte4 dataLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ChaCha20Ctx *pChaChaCtx = (ChaCha20Ctx *) pCtx;

  if (NULL == pChaChaCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pChaChaCtx->enabled)
  {
    ubyte4 dataOut;

    if (dataLen && NULL == pData)
      goto exit;

    status = OK;
    if (dataLen)
      status = CRYPTO_cipherUpdate(pChaChaCtx->pMocSymCtx, 0, pData, dataLen,
                                   pData, dataLen, &dataOut);
  }
  else
  {
    MOC_CHACHA20POLY1305_UPDATE_DATA(status, pCtx, pData, dataLen);
  }

exit:

  return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ChaCha20Poly1305_final(
  MOC_SYM(hwAccelDescr hwAccelCtx)
  BulkCtx pCtx,
  ubyte *pTag,
  ubyte4 tagLen
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ChaCha20Ctx *pChaChaCtx = (ChaCha20Ctx *) pCtx;

  if (NULL == pChaChaCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pChaChaCtx->enabled)
  {
    ubyte4 dataOut;

    if (tagLen && NULL == pTag)
      goto exit;

    status = CRYPTO_cipherFinal(pChaChaCtx->pMocSymCtx, 0, pTag, tagLen, pTag, tagLen, &dataOut);
  }
  else
  {
    MOC_CHACHA20POLY1305_FINAL(status, pCtx, pTag, tagLen);
  }

exit:

  return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ChaCha20Poly1305_cloneCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  BulkCtx *ppNewCtx
  )
{
  MSTATUS status;
  ChaCha20Ctx *pChaChaCtx = NULL;
  ChaCha20Ctx *pNewChaChaCtx = NULL;
  MocSymCtx pNewSymCtx = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pCtx) || (NULL == ppNewCtx) )
    goto exit;

  pChaChaCtx = (ChaCha20Ctx *)pCtx;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pChaChaCtx->enabled)
  {
    /* Clone the underlying MocSymCtx */
    status = CRYPTO_cloneMocSymCtx(pChaChaCtx->pMocSymCtx, &pNewSymCtx);
    if (OK != status)
      goto exit;

    status = DIGI_CALLOC((void **)&pNewChaChaCtx, 1, sizeof(ChaCha20Ctx));
    if (OK != status)
      goto exit;

    status = DIGI_MEMCPY((void *)pNewChaChaCtx, (void *)pChaChaCtx, sizeof(ChaCha20Ctx));
    if (OK != status)
      goto exit;

    pNewChaChaCtx->pMocSymCtx = pNewSymCtx;
    pNewSymCtx = NULL;
    *ppNewCtx = (BulkCtx)pNewChaChaCtx;
    pNewChaChaCtx = NULL;
  }
  else
  {
    MOC_CHACHA20POLY1305_CLONE(status, pCtx, ppNewCtx);
  }

exit:
  if (NULL != pNewSymCtx)
  {
    CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }
  if (NULL != pNewChaChaCtx)
  {
    DIGI_FREE((void **)&pNewChaChaCtx);
  }
  return status;
}

#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_POLY1305__ */
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_CHACHA20__ */
