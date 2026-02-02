/*
 * crypto_interface_aes.c
 *
 * Cryptographic Interface specification for AES core modes.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../crypto/aes.h"
#include "../crypto/aesalgo.h"
#include "../crypto/aes_ecb.h"
#include "../crypto/aes_ctr.h"
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/crypto_interface_aes.h"
#include "../crypto_interface/crypto_interface_aes_tap.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_AES__))

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__))
#define MOC_AES_ALGO_MAKE_KEY(_status, _pCtx, _keyLen, _pKey, _encrypt, _mode) \
    _status = AESALGO_makeAesKey(_pCtx, _keyLen, _pKey, _encrypt, _mode);      \
    if (OK == _status)                                                         \
    {                                                                          \
      _pCtx->enabled = 0;                                                      \
      _pCtx->pMocSymCtx = NULL;                                                \
    }
#else
#define MOC_AES_ALGO_MAKE_KEY(_status, _pCtx, _keyLen, _pKey, _encrypt, _mode) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__))
#define MOC_AES_ALGO_BLOCK_ENCRYPT(_status, _pCtx, _pIv, _pIn, _inLen, _pOut, _pLen) \
    _status = AESALGO_blockEncrypt(_pCtx, _pIv, _pIn, _inLen, _pOut, _pLen);
#else
#define MOC_AES_ALGO_BLOCK_ENCRYPT(_status, _pCtx, _pIv, _pIn, _inLen, _pOut, _pLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__))
#define MOC_AES_ALGO_BLOCK_DECRYPT(_status, _pCtx, _pIv, _pIn, _inLen, _pOut, _pLen) \
    _status = AESALGO_blockDecrypt(_pCtx, _pIv, _pIn, _inLen, _pOut, _pLen);
#else
#define MOC_AES_ALGO_BLOCK_DECRYPT(_status, _pCtx, _pIv, _pIn, _inLen, _pOut, _pLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__))
#define MOC_AES_CREATE_CBC(_pCtx, _pKey, _keyLen, _encrypt)           \
    _pCtx = CreateAESCtx(MOC_SYM(hwAccelCtx) _pKey, _keyLen, _encrypt);
#else
#define MOC_AES_CREATE_CBC(_pCtx, _pKey, _keyLen, _encrypt)           \
    _pCtx = NULL;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__))
#define MOC_AES_CREATE_ECB(_pCtx, _pKey, _keyLen, _encrypt)           \
    _pCtx = CreateAESECBCtx(MOC_SYM(hwAccelCtx) _pKey, _keyLen, _encrypt);
#else
#define MOC_AES_CREATE_ECB(_pCtx, _pKey, _keyLen, _encrypt)           \
    _pCtx = NULL;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__))
#define MOC_AES_CREATE_CFB(_pCtx, _pKey, _keyLen, _encrypt)           \
    _pCtx = CreateAESCFBCtx(MOC_SYM(hwAccelCtx) _pKey, _keyLen, _encrypt);
#else
#define MOC_AES_CREATE_CFB(_pCtx, _pKey, _keyLen, _encrypt)           \
    _pCtx = NULL;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__))
#define MOC_AES_CREATE_CFB1(_pCtx, _pKey, _keyLen, _encrypt)          \
    _pCtx = CreateAESCFB1Ctx(MOC_SYM(hwAccelCtx) _pKey, _keyLen, _encrypt);
#else
#define MOC_AES_CREATE_CFB1(_pCtx, _pKey, _keyLen, _encrypt)          \
    _pCtx = NULL;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__))
#define MOC_AES_CREATE_OFB(_pCtx, _pKey, _keyLen, _encrypt)           \
    _pCtx = CreateAESOFBCtx(MOC_SYM(hwAccelCtx) _pKey, _keyLen, _encrypt);
#else
#define MOC_AES_CREATE_OFB(_pCtx, _pKey, _keyLen, _encrypt)           \
    _pCtx = NULL;
#endif

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__))
#define MOC_AES_RESET_CTX(_status, _pCtx)                                    \
    _status = ResetAESCtx(MOC_SYM(hwAccelCtx) _pCtx);
#else
#define MOC_AES_RESET_CTX(_status, _pCtx)                                    \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__))
#define MOC_AES_CLONE(_status, _pCtx, _ppNewCtx)                             \
    _status = CloneAESCtx(MOC_SYM(hwAccelCtx) _pCtx, _ppNewCtx);
#else
#define MOC_AES_CLONE(_status, _pCtx, _ppNewCtx)                             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__))
#define MOC_AES_DELETE_CTX(_status, _ppCtx)                                    \
    _status = DeleteAESCtx(MOC_SYM(hwAccelCtx) _ppCtx);
#else
#define MOC_AES_DELETE_CTX(_status, _ppCtx)                                    \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESALGO_makeAesKey (
  aesCipherContext *pCtx,
  sbyte4 keyLen,
  const ubyte *pKeyMaterial,
  sbyte4 encrypt,
  sbyte4 mode
  )
{
  MSTATUS status;
  ubyte4 algoStatus, index;
  cryptoInterfaceSymAlgo aesMode = 0;
  MocSymCtx pNewSymCtx = NULL;
  algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;

  if ( (128 != keyLen) && (192 != keyLen) && (256 != keyLen) )
  {
    status = ERR_AES_BAD_KEY_LENGTH;
    goto exit;
  }

  /* What mode are we trying to create? If we dont recognize the mode that is
   * not necessarily an error */
  switch(mode)
  {
    case MODE_ECB:
      aesMode = moc_alg_aes_ecb;
      break;

    case MODE_CBC:
      aesMode = moc_alg_aes_cbc;
      break;

    case MODE_CFB128:
      aesMode = moc_alg_aes_cfb;
      break;

    case MODE_CFB1:
      aesMode = moc_alg_aes_cfb1; 
      break;

    case MODE_OFB:
      aesMode = moc_alg_aes_ofb;
      break;
      
    case MODE_CTR:
      aesMode = moc_alg_aes_ctr;
      break;
  }

  /* We recognize the mode, check with the core to see if we have an alternate
   * implementation available for this mode */
  if (0 != aesMode)
  {
    status = CRYPTO_INTERFACE_checkSymAlgoStatus (
      aesMode, &algoStatus, &index);
    if (OK != status)
      goto exit;
  }

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    /* We do have an alternate implementation of this mode. Create a new
     * MocSymCtx and load the key data in, remember we recieve the key length
     * in bits but this function expects the length in bytes */
    status = CRYPTO_INTERFACE_createAndLoadSymKey (
      index, NULL, (ubyte *)pKeyMaterial, (ubyte4)(keyLen / 8), &pNewSymCtx);
    if (OK != status)
      goto exit;

    /* We do not want to call init here, we still need the IV. Instead we will
     * load the newly created MocSymCtx into the provided AES shell. When we
     * recieve the IV in AESALGO_blockEncrypt, we will perform the init. */
    pCtx->keyLen = keyLen;
    pCtx->mode = mode;
    pCtx->encrypt = encrypt;
    pCtx->pMocSymCtx = pNewSymCtx;
    pNewSymCtx = NULL;

    /* Mark this object as crypto interface enabled */
    pCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;
  }
  else
  {
    MOC_AES_ALGO_MAKE_KEY (
      status, pCtx, keyLen, pKeyMaterial, encrypt, mode);
  }

exit:

  if (NULL != pNewSymCtx)
  { /* ok to ignore return code, only here on error case already */
    CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESALGO_makeAesKeyEx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  aesCipherContext *pCtx,
  sbyte4 keyLen,
  const ubyte *pKeyMaterial,
  sbyte4 encrypt,
  sbyte4 mode
  )
{
  return CRYPTO_INTERFACE_AESALGO_makeAesKey (
    pCtx, keyLen, pKeyMaterial, encrypt, mode);
}

/*---------------------------------------------------------------------------*/

static MSTATUS CRYPTO_INTERFACE_AESALGO_processBlock (
  aesCipherContext *pCtx,
  ubyte *pIv,
  ubyte *pInput,
  sbyte4 inputLen,
  ubyte *pOutBuffer,
  sbyte4 *pRetLength,
  ubyte4 cipherFlag
  )
{
  MSTATUS status;
  ubyte4 outLen;
  MAesUpdateData aesParams;
  MocCtx pMocCtx = NULL;

  /* We must have an underlying MocSymCtx */
  status = ERR_NULL_POINTER;
  if (NULL == pCtx->pMocSymCtx)
    goto exit;

  /* If this is the first call for this context, update the underlying
   * MocSymCtx with the initialization vector and then initialize the
   * operation. If this is a continuation of a previous operation,
   * simply continue the update process */
  if (0 == pCtx->initialized)
  {
    /* Get a reference to the MocCtx within the Crypto Interface Core */
    status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
    if (OK != status)
      goto exit;

    /* Update the operator with the initialization vector for all modes
     * except ECB */
    if (MODE_ECB != pCtx->mode)
    {
      aesParams.pInitVector = pIv;
      aesParams.initVectorLen = AES_BLOCK_SIZE;
      status = CRYPTO_updateSymOperatorData (
        pCtx->pMocSymCtx, pMocCtx, (void *)&aesParams);
      if (OK != status)
        goto exit;
    }

    /* Initialize the cipher operation  */
    status = CRYPTO_cipherInit(pCtx->pMocSymCtx, cipherFlag);
    if (OK != status)
      goto exit;

    /* Mark this object as initialized so we dont overwrite the
     * initialization vector within the object on the next call */
    pCtx->initialized = 1;
  }

  /* Update the cipher operation, again remember that this function recieves
    * bit lengths while CRYPTO_cipherUpdate expects byte lengths */
  status = CRYPTO_cipherUpdate (
    pCtx->pMocSymCtx, cipherFlag, pInput, (ubyte4)(inputLen/8),
    pOutBuffer, (ubyte4)(inputLen/8), &outLen);
  if (OK != status)
    goto exit;

  *pRetLength = outLen*8;

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESALGO_blockEncrypt (
  aesCipherContext *pCtx,
  ubyte *pIv,
  ubyte *pInput,
  sbyte4 inputLen,
  ubyte *pOutBuffer,
  sbyte4 *pRetLength
  )
{
  MSTATUS status = ERR_NULL_POINTER;

  if ( (NULL == pCtx) || (NULL == pRetLength) || (NULL == pInput))
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  {
    if (NULL == pCtx->pMocSymCtx)
      goto exit;

    if (0 != (MOC_LOCAL_TYPE_TAP & pCtx->pMocSymCtx->localType))
    {
      status = CRYPTO_INTERFACE_TAP_AESALGO_blockEncrypt(pCtx->pMocSymCtx, pIv, pInput, inputLen, pOutBuffer, pRetLength);
    }
    else
    {
      status = CRYPTO_INTERFACE_AESALGO_processBlock (
        pCtx, pIv, pInput, inputLen, pOutBuffer, pRetLength, MOC_CIPHER_FLAG_ENCRYPT);
    }
  }
  else
  {
    MOC_AES_ALGO_BLOCK_ENCRYPT (
      status, pCtx, pIv, pInput, inputLen, pOutBuffer, pRetLength)
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESALGO_blockEncryptEx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  aesCipherContext *pCtx,
  ubyte *pIv,
  ubyte *pInput,
  sbyte4 inputLen,
  ubyte *pOutBuffer,
  sbyte4 *pRetLength
  )
{
  return CRYPTO_INTERFACE_AESALGO_blockEncrypt (
    pCtx, pIv, pInput, inputLen, pOutBuffer, pRetLength);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESALGO_blockDecrypt (
  aesCipherContext *pCtx,
  ubyte *pIv,
  ubyte *pInput,
  sbyte4 inputLen,
  ubyte *pOutBuffer,
  sbyte4 *pRetLength
  )
{
  MSTATUS status = ERR_NULL_POINTER;

  if ( (NULL == pCtx) || (NULL == pRetLength) || (NULL == pInput))
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  {
    if (NULL == pCtx->pMocSymCtx)
      goto exit;

    if (0 != (MOC_LOCAL_TYPE_TAP & pCtx->pMocSymCtx->localType))
    {
      status = CRYPTO_INTERFACE_TAP_AESALGO_blockDecrypt(pCtx->pMocSymCtx, pIv, pInput, inputLen, pOutBuffer, pRetLength);
    }
    else
    {
      status = CRYPTO_INTERFACE_AESALGO_processBlock (
        pCtx, pIv, pInput, inputLen, pOutBuffer, pRetLength, MOC_CIPHER_FLAG_DECRYPT);
    }
  }
  else
  {
    MOC_AES_ALGO_BLOCK_DECRYPT (
      status, pCtx, pIv, pInput, inputLen, pOutBuffer, pRetLength)
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESALGO_blockDecryptEx (
  MOC_SYM(hwAccelDescr hwAccelCtx)
  aesCipherContext *pCtx,
  ubyte *pIv,
  ubyte *pInput,
  sbyte4 inputLen,
  ubyte *pOutBuffer,
  sbyte4 *pRetLength
  )
{
  return CRYPTO_INTERFACE_AESALGO_blockDecrypt (
    pCtx, pIv, pInput, inputLen, pOutBuffer, pRetLength);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESALGO_clearKey (
  aesCipherContext *pCtx
  )
{
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if (NULL == pCtx)
    goto exit;

  if (NULL != pCtx->pMocSymCtx)
  {
    status = CRYPTO_freeMocSymCtx(&(pCtx->pMocSymCtx));
    if (OK != status)
        goto exit;
  }

  status = DIGI_MEMSET((ubyte *)pCtx, 0, sizeof(aesCipherContext));

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateAESCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* pKeyMaterial,
  sbyte4 keyLength,
  sbyte4 encrypt
  )
{
  MSTATUS status;
  ubyte4 algoStatus;
  aesCipherContext *pCtx = NULL;

  /* Determine if we have an AES-CBC implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_aes_cbc, &algoStatus, NULL);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    status = DIGI_CALLOC((void **)&pCtx, 1, sizeof(aesCipherContext));
    if (OK != status)
      goto exit;

    status = CRYPTO_INTERFACE_AESALGO_makeAesKey (
      pCtx, 8 * keyLength, pKeyMaterial, encrypt, MODE_CBC);
    if (OK != status)
    {
      DIGI_FREE((void **)&pCtx);
      pCtx = NULL;
      goto exit;
    }

    /* Set the initialized flag to 0 until we've done our first processBlock */
    pCtx->initialized = 0;
  }
  else
  {
    MOC_AES_CREATE_CBC(pCtx, pKeyMaterial, keyLength, encrypt)
  }

exit:

  return pCtx;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateAESECBCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* pKeyMaterial,
  sbyte4 keyLength,
  sbyte4 encrypt
  )
{
  MSTATUS status;
  ubyte4 algoStatus;
  aesCipherContext *pCtx = NULL;

  /* Determine if we have an AES-ECB implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_aes_ecb, &algoStatus, NULL);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    status = DIGI_CALLOC((void **)&pCtx, 1, sizeof(aesCipherContext));
    if (OK != status)
      goto exit;

    status = CRYPTO_INTERFACE_AESALGO_makeAesKey (
      pCtx, 8 * keyLength, pKeyMaterial, encrypt, MODE_ECB);
    if (OK != status)
    {
      DIGI_MEMSET((ubyte*)pCtx, 0x00, sizeof(aesCipherContext));
      DIGI_FREE((void**)&pCtx);
      pCtx = NULL;
    }
  }
  else
  {
    MOC_AES_CREATE_ECB(pCtx, pKeyMaterial, keyLength, encrypt)
  }

exit:

  return pCtx;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateAESCFBCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* pKeyMaterial,
  sbyte4 keyLength,
  sbyte4 encrypt
  )
{
  MSTATUS status;
  ubyte4 algoStatus;
  aesCipherContext *pCtx = NULL;

  /* Determine if we have an AES-CFB implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_aes_cfb, &algoStatus, NULL);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    status = DIGI_CALLOC((void **)&pCtx, 1, sizeof(aesCipherContext));
    if (OK != status)
      goto exit;

    status = CRYPTO_INTERFACE_AESALGO_makeAesKey (
      pCtx, 8 * keyLength, pKeyMaterial, encrypt, MODE_CFB128);
    if (OK != status)
    {
      DIGI_FREE((void **)&pCtx);
      pCtx = NULL;
      goto exit;
    }

  }
  else
  {
    MOC_AES_CREATE_CFB(pCtx, pKeyMaterial, keyLength, encrypt)
  }

exit:

  return pCtx;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateAESCFB1Ctx (
  MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* pKeyMaterial,
  sbyte4 keyLength,
  sbyte4 encrypt
  )
{
  MSTATUS status;
  ubyte4 algoStatus;
  aesCipherContext *pCtx = NULL;

  /* Determine if we have an AES-CFB implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_aes_cfb1, &algoStatus, NULL); 
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    status = DIGI_CALLOC((void **)&pCtx, 1, sizeof(aesCipherContext));
    if (OK != status)
      goto exit;

    status = CRYPTO_INTERFACE_AESALGO_makeAesKey (
      pCtx, 8 * keyLength, pKeyMaterial, encrypt, MODE_CFB1);
    if (OK != status)
    {
      DIGI_FREE((void **)&pCtx);
      pCtx = NULL;
      goto exit;
    }

  }
  else
  {
    MOC_AES_CREATE_CFB1(pCtx, pKeyMaterial, keyLength, encrypt)
  }

exit:

  return pCtx;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateAESOFBCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) ubyte* pKeyMaterial,
  sbyte4 keyLength,
  sbyte4 encrypt
  )
{
  MSTATUS status;
  ubyte4 algoStatus;
  aesCipherContext *pCtx = NULL;

  /* Determine if we have an AES-OFB implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_aes_ofb, &algoStatus, NULL);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    status = DIGI_CALLOC((void **)&pCtx, 1, sizeof(aesCipherContext));
    if (OK != status)
      goto exit;

    status = CRYPTO_INTERFACE_AESALGO_makeAesKey (
      pCtx, 8 * keyLength, pKeyMaterial, encrypt, MODE_OFB);
    if (OK != status)
    {
      DIGI_FREE((void **)&pCtx);
      pCtx = NULL;
      goto exit;
    }

  }
  else
  {
    MOC_AES_CREATE_OFB(pCtx, pKeyMaterial, keyLength, encrypt)
  }

exit:

  return pCtx;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_ResetAESCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx
  )
{
  MSTATUS status;
  aesCipherContext *pCtx = NULL;

  status = ERR_NULL_POINTER;
  if (NULL == ppCtx)
    goto exit;

  pCtx = (aesCipherContext *)(*ppCtx);
  if (NULL == pCtx)
    goto exit;

  status = OK;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  {
    if (NULL != pCtx->pMocSymCtx && (0 != (MOC_LOCAL_TYPE_TAP & pCtx->pMocSymCtx->localType)) )
    {
      status = CRYPTO_INTERFACE_TAP_ResetAESCtx(pCtx->pMocSymCtx);
    }
    pCtx->initialized = 0;
  }
  else
  {
    MOC_AES_RESET_CTX(status, ppCtx)
  }

exit:

  return status;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DeleteAESCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx
  )
{
  MSTATUS status, fstatus;
  aesCipherContext *pCtx = NULL;

  status = ERR_NULL_POINTER;
  if (NULL == ppCtx)
    goto exit;

  /* It is not an error to attempt to free a NULL context */
  status = OK;
  pCtx = (aesCipherContext *)(*ppCtx);
  if (NULL == pCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  {
    if (NULL != pCtx->pMocSymCtx && (0 != (MOC_LOCAL_TYPE_TAP & pCtx->pMocSymCtx->localType)) )
    {
      status = CRYPTO_INTERFACE_TAP_DeleteAESCtx(pCtx->pMocSymCtx);
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
    MOC_AES_DELETE_CTX(status, ppCtx)
  }

exit:
  return status;

}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_CloneAESCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  BulkCtx *ppNewCtx
  )
{
  MSTATUS status;
  aesCipherContext *pAesCtx = NULL;
  aesCipherContext *pNewAesCtx = NULL;
  MocSymCtx pNewSymCtx = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pCtx) || (NULL == ppNewCtx) )
    goto exit;

  pAesCtx = (aesCipherContext *)pCtx;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pAesCtx->enabled)
  {
    /* Clone the underlying MocSymCtx */
    status = CRYPTO_cloneMocSymCtx(pAesCtx->pMocSymCtx, &pNewSymCtx);
    if (OK != status)
      goto exit;

    status = DIGI_CALLOC((void **)&pNewAesCtx, 1, sizeof(aesCipherContext));
    if (OK != status)
      goto exit;

    status = DIGI_MEMCPY((void *)pNewAesCtx, (void *)pAesCtx, sizeof(aesCipherContext));
    if (OK != status)
      goto exit;

    pNewAesCtx->pMocSymCtx = pNewSymCtx;
    pNewSymCtx = NULL;
    *ppNewCtx = (BulkCtx)pNewAesCtx;
    pNewAesCtx = NULL;

  }
  else
  {
    MOC_AES_CLONE(status, pCtx, ppNewCtx)
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

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoAES (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pData,
  sbyte4 dataLength,
  sbyte4 encrypt,
  ubyte *pIv
  )
{
  MSTATUS status;
  sbyte4 retLength;
  aesCipherContext *pAesCtx = (aesCipherContext *)pCtx;

  status = ERR_NULL_POINTER;
  if ( (NULL == pAesCtx) || ((MODE_ECB != pAesCtx->mode) && (NULL == pIv)) )
  {
    goto exit;
  }

  status = ERR_AES_BAD_OPERATION;
  if(encrypt != pAesCtx->encrypt)
  {
    goto exit;
  }

  status = ERR_AES_BAD_LENGTH;
  if ( (MODE_ECB == pAesCtx->mode || MODE_CBC == pAesCtx->mode) && 0 != (dataLength % AES_BLOCK_SIZE) )
  {
    goto exit;
  }

  if (encrypt)
  {
    status = CRYPTO_INTERFACE_AESALGO_blockEncrypt (
      pAesCtx, pIv, pData, 8 * dataLength, pData, &retLength);
  }
  else
  {
    status = CRYPTO_INTERFACE_AESALGO_blockDecrypt (
      pAesCtx, pIv, pData, 8 * dataLength, pData, &retLength);
  }

exit:
  return status;

}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoAESEx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pData,
  sbyte4 dataLength,
  sbyte4 encrypt,
  ubyte *pIv
  )
{
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
  MSTATUS status = ERR_NULL_POINTER;
  aesCipherContext *pAesCtx = (aesCipherContext*)pCtx;

  if (NULL == pAesCtx)
    goto exit;

  /* We want to update the IV the operator is using with the one that is passed
   * to this function call. if initialized is set to zero, then
   * CRYPTO_INTERFACE_DoAES call will make updateSymOperatorData call,
   * otherwise we have to make it ourselves.
   */
  if (1 == pAesCtx->initialized && MODE_ECB != pAesCtx->mode)
  {
    MAesUpdateData aesParams;
    MocCtx pMocCtx = NULL;
    /* Get a reference to the MocCtx within the Crypto Interface Core */
    status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
    if (OK != status)
      goto exit;

    aesParams.pInitVector = pIv;
    aesParams.initVectorLen = AES_BLOCK_SIZE;
    status = CRYPTO_updateSymOperatorData (pAesCtx->pMocSymCtx, pMocCtx, (void *)&aesParams);
    if (OK != status)
    goto exit;
  }

  status = CRYPTO_INTERFACE_DoAES(MOC_SYM(hwAccelCtx) pCtx, pData, dataLength, encrypt, pIv);
  if (OK != status)
    goto exit;

  status = CRYPTO_INTERFACE_getIv(pAesCtx->pMocSymCtx, pIv);

exit:

  return status;

#else

  return CRYPTO_INTERFACE_DoAES(MOC_SYM(hwAccelCtx) pCtx, pData, dataLength, encrypt, pIv);

#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__ */
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoAESECB (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pData,
  sbyte4 dataLength,
  sbyte4 encrypt
  )
{
  return CRYPTO_INTERFACE_DoAES(MOC_SYM(hwAccelCtx) pCtx, pData, dataLength, encrypt, NULL);
}
#endif
