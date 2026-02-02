/*
 * crypto_interface_tdes.c
 *
 * Cryptographic Interface specification for TDES.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_TDES_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../crypto/des.h"
#include "../crypto/three_des.h"
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/crypto_interface_tdes.h"
#include "../crypto_interface/crypto_interface_des_tap.h"
#include "../crypto_interface/crypto_interface_tdes_tap.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_TDES__))

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_3DES_CIPHERS__))
#define MOC_TDES_CREATE(_pCtx, _pKeyData, _keyLen, _encrypt)                  \
    _pCtx = Create3DESCtx(MOC_SYM(hwAccelCtx) _pKeyData, _keyLen, _encrypt);  \
    if (NULL != _pCtx)                                                        \
    {                                                                         \
       _pCtx->enabled = 0;                                                    \
       _pCtx->pMocSymCtx = NULL;                                              \
    }
#else
#define MOC_TDES_CREATE(_pCtx, _pKeyData, _keyLen, _encrypt)
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_3DES_CIPHERS__))
#define MOC_DO_TDES(_status, _pCtx, _pData, _dataLen, _encrypt, _pIv)         \
    _status = Do3DES(MOC_SYM(hwAccelCtx) _pCtx, _pData, _dataLen, _encrypt, _pIv);
#else
#define MOC_DO_TDES(_status, _pCtx, _pData, _dataLen, _encrypt, _pIv)         \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_3DES_CIPHERS__))
#define MOC_TDES_DELETE(_status, _pCtx)                                       \
    _status = Delete3DESCtx(MOC_SYM(hwAccelCtx) _pCtx);
#else
#define MOC_TDES_DELETE(_status, _pCtx)                                       \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_3DES_CIPHERS__))
#define MOC_TDES_CLONE(_status, _pCtx, _ppNewCtx)                             \
    _status = Clone3DESCtx(MOC_SYM(hwAccelCtx) _pCtx, _ppNewCtx);
#else
#define MOC_TDES_CLONE(_status, _pCtx, _ppNewCtx)                             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_3DES_CIPHERS__))
#define MOC_TDES_RESET(_status, _pCtx)                                       \
    _status = Reset3DESCtx(MOC_SYM(hwAccelCtx) _pCtx);
#else
#define MOC_TDES_RESET(_status, _pCtx)                                       \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_3DES_CIPHERS__))
#define MOC_THREE_DES_INIT(_status, _pCtx, _pKey, _keyLen)                     \
    _status = THREE_DES_initKey(_pCtx, _pKey, _keyLen);                        \
    if (OK == _status)                                                         \
    {                                                                          \
      _pCtx->enabled = 0;                                                      \
      _pCtx->pMocSymCtx = NULL;                                                \
    }
#else
#define MOC_THREE_DES_INIT(_status, _pCtx, _pKey, _keyLen)                     \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_3DES_CIPHERS__))
#define MOC_THREE_DES_ENCRYPT(_status, _pCtx, _pSrc, _pDest, _numBytes)       \
    _status = THREE_DES_encipher(_pCtx, _pSrc, _pDest, _numBytes);
#else
#define MOC_THREE_DES_ENCRYPT(_status, _pCtx, _pSrc, _pDest, _numBytes)       \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_3DES_CIPHERS__))
#define MOC_THREE_DES_DECRYPT(_status, _pCtx, _pSrc, _pDest, _numBytes)       \
    _status = THREE_DES_decipher(_pCtx, _pSrc, _pDest, _numBytes);
#else
#define MOC_THREE_DES_DECRYPT(_status, _pCtx, _pSrc, _pDest, _numBytes)       \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

MOC_EXTERN BulkCtx CRYPTO_INTERFACE_Create3DESCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *pKeyMaterial,
  sbyte4 keyLen,
  sbyte4 encrypt
  )
{
  MSTATUS status;
  ubyte4 algoStatus, index;
  void *pPtr = NULL;
  MocSymCtx pNewSymCtx = NULL;
  DES3Ctx *pTDesCtx = NULL;

  /* Determine if we have a TDES-CBC implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_tdes_cbc, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    /* Create a new MocSymCtx and load the key data in */
    status = CRYPTO_INTERFACE_createAndLoadSymKey (
      index, NULL, pKeyMaterial, (ubyte4)keyLen, &pNewSymCtx);
    if (OK != status)
      goto exit;

    /* We do not want to call init here, we still need the IV from the Do3DES
     * call. Instead we will create an empty object and allocate the DES3Ctx
     * shell. When we recieve the IV in CRYPTO_INTERFACE_Do3DES, we will
     * perform the init. */
    status = DIGI_CALLOC(&pPtr, 1, sizeof(DES3Ctx));
    if (OK != status)
      goto exit;

    pTDesCtx = (DES3Ctx *)pPtr;
    pPtr = NULL;
    pTDesCtx->pMocSymCtx = pNewSymCtx;
    pNewSymCtx = NULL;

    /* Mark this object to indicate that it is using an alternate
     * implementation through the crypto interface */
    pTDesCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;
  }
  else
  {
    MOC_TDES_CREATE(pTDesCtx, pKeyMaterial, keyLen, encrypt)
  }

exit:

  if (NULL != pPtr)
  {
    DIGI_FREE(&pPtr);
  }
  if (NULL != pNewSymCtx)
  {
    CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }

  return pTDesCtx;

}

/*---------------------------------------------------------------------------*/

#ifndef __DISABLE_3DES_TWO_KEY_CIPHER__

MOC_EXTERN BulkCtx CRYPTO_INTERFACE_Create2Key3DESCtx(
  MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *pKeyMaterial,
  sbyte4 keyLength,
  sbyte4 encrypt
  )
{
  ubyte pTempKey[THREE_DES_KEY_LENGTH];
  BulkCtx ctx = NULL;
  MSTATUS status;

  if (THREE_DES_TWO_KEY_LENGTH != keyLength)
      goto exit;

  /* DIGI_MEMCPY will check for NULL pKeyMaterial */
  status = DIGI_MEMCPY(pTempKey, pKeyMaterial, keyLength);
  if (OK != status)
    goto exit;

  status = DIGI_MEMCPY(pTempKey + THREE_DES_TWO_KEY_LENGTH, pKeyMaterial, DES_KEY_LENGTH);
  if (OK != status)
    goto exit;

  ctx = CRYPTO_INTERFACE_Create3DESCtx (
    MOC_SYM(hwAccelCtx) pTempKey, THREE_DES_KEY_LENGTH, encrypt);

exit:

  /* clear sensitive key material from the stack, no need to check return code */
  DIGI_MEMSET(pTempKey, 0x00, THREE_DES_KEY_LENGTH);

  return ctx;
}

#endif /* __DISABLE_3DES_TWO_KEY_CIPHER__ */

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_Do3DES (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pData,
  sbyte4 dataLen,
  sbyte4 encrypt,
  ubyte *pIv
  )
{
  MSTATUS status;
  MTDesUpdateData tDesParams;
  MocCtx pMocCtx = NULL;
  DES3Ctx *pTDesCtx = NULL;
  ubyte4 outLen = 0;
  ubyte4 cipherFlag = MOC_CIPHER_FLAG_ENCRYPT;

  status = ERR_NULL_POINTER;
  if (NULL == pCtx)
    goto exit;

  pTDesCtx = (DES3Ctx *)pCtx;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pTDesCtx->enabled)
  {    
    if (NULL != pTDesCtx->pMocSymCtx && 0 != (MOC_LOCAL_TYPE_TAP & pTDesCtx->pMocSymCtx->localType))
    {
      status = CRYPTO_INTERFACE_TAP_Do3DES(pTDesCtx->pMocSymCtx, pData, dataLen, encrypt, pIv);
    }
    else
    {
      /* Get a reference to the MocCtx registered with the Crypto Interface */
      status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
      if (OK != status)
        goto exit;

      /* We assumed encryption to start, check for decryption */
      if (0 == encrypt)
        cipherFlag = MOC_CIPHER_FLAG_DECRYPT;

      /* If this is the first call to Do3DES for this DES3Ctx, update the
      * underlying MocSymCtx with the initialization vector and then
      * initialize the operation. If this is a continuation of a previous
      * operation, simply continue the update process */
      if (0 == pTDesCtx->initialized)
      {
        /* Update the operator with the initialization vector, also inform the
        * operator that they should not be performing PKCS5 padding */
        tDesParams.pInitVector = pIv;
        tDesParams.initVectorLen = THREE_DES_BLOCK_SIZE;
        tDesParams.padding = FALSE;
        status = CRYPTO_updateSymOperatorData (
          pTDesCtx->pMocSymCtx, pMocCtx, (void *)&tDesParams);
        if (OK != status)
          goto exit;

        /* Initialize the cipher operation  */
        status = CRYPTO_cipherInit(pTDesCtx->pMocSymCtx, cipherFlag);
        if (OK != status)
          goto exit;

        /* Mark this object as initialized so we dont overwrite the
        * initialization vector within the object on the next call */
        pTDesCtx->initialized = 1;
      }

      /* Update the cipher operation */
      status = CRYPTO_cipherUpdate (
        pTDesCtx->pMocSymCtx, cipherFlag, pData, (ubyte4)dataLen, pData,
        (ubyte4)dataLen, &outLen);
    }
  }
  else
  {
    MOC_DO_TDES(status, pCtx, pData, dataLen, encrypt, pIv)
  }

exit:
  return status;

}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_Do3DESEx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pData,
  sbyte4 dataLen,
  sbyte4 encrypt,
  ubyte *pIv
  )
{
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
  MSTATUS status = ERR_NULL_POINTER;
  DES3Ctx *pTDesCtx = (DES3Ctx*)pCtx;

  if (NULL == pTDesCtx)
    goto exit;

  /* We want to update the IV the operator is using with the one that is passed
   * to this function call. if initialized is set to zero, then
   * CRYPTO_INTERFACE_Do3DES call will make updateSymOperatorData call,
   * otherwise we have to make it ourselves.
   */
  if (1 == pTDesCtx->initialized)
  {
    MocCtx pMocCtx = NULL;
    MTDesUpdateData tDesParams = {0};

    status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
    if (OK != status)
      goto exit;

    tDesParams.pInitVector = pIv;
    tDesParams.initVectorLen = THREE_DES_BLOCK_SIZE;
    tDesParams.padding = FALSE;
    status = CRYPTO_updateSymOperatorData (
      pTDesCtx->pMocSymCtx, pMocCtx, (void *)&tDesParams);
    if (OK != status)
      goto exit;
  }

  status = CRYPTO_INTERFACE_Do3DES(MOC_SYM(hwAccelCtx) pCtx, pData, dataLen, encrypt, pIv);
  if (OK != status)
    goto exit;

  /* update the passed in pIv to the latest copy */
  status = CRYPTO_INTERFACE_getIv(MOC_SYM(hwAccelCtx) pTDesCtx->pMocSymCtx, pIv);

exit:

  return status;

#else

  return CRYPTO_INTERFACE_Do3DES(MOC_SYM(hwAccelCtx) pCtx, pData, dataLen, encrypt, pIv);

#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__ */
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_Delete3DESCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *pCtx
  )
{
  MSTATUS status, fStatus;
  DES3Ctx *pTDesCtx = NULL;
  MocSymCtx pSymCtx = NULL;

  status = ERR_NULL_POINTER;
  if (NULL == pCtx)
    goto exit;

  pTDesCtx = (DES3Ctx *)(*pCtx);

  /* It is not an error to attempt to free a NULL context */
  status = OK;
  if (NULL == pTDesCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pTDesCtx->enabled)
  {
    /* Make our own copy of the MocSymCtx pointer */
    pSymCtx = pTDesCtx->pMocSymCtx;

    /* Free the outer shell first */
    status = DIGI_FREE((void **)&pTDesCtx);

    /* Set the passed in location to NULL too */
    *pCtx = NULL;

    /* It is not an error to attempt to free a NULL context */
    if (NULL == pSymCtx)
      goto exit;

    /* If a TAP context we need to finalize the cipher operation */
    if (0 != (MOC_LOCAL_TYPE_TAP & pSymCtx->localType))
    {
      fStatus = CRYPTO_INTERFACE_TAP_DES_Final(pSymCtx);
      if (OK == status)
        status = fStatus;
    }

    /* Free the inner context */
    fStatus = CRYPTO_freeMocSymCtx(&pSymCtx);
    if (OK == status)
      status = fStatus;
  }
  else
  {
    MOC_TDES_DELETE(status, pCtx)
  }


exit:
  return status;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_Clone3DESCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  BulkCtx *ppNewCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  DES3Ctx *pTDesCtx = NULL;
  DES3Ctx *pNewTDesCtx = NULL;
  MocSymCtx pNewSymCtx = NULL;

  if ( (NULL == pCtx) || (NULL == ppNewCtx) )
    goto exit;

  pTDesCtx = (DES3Ctx *)pCtx;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pTDesCtx->enabled)
  {
    /* Clone the underlying MocSymCtx */
    status = CRYPTO_cloneMocSymCtx(pTDesCtx->pMocSymCtx, &pNewSymCtx);
    if (OK != status)
      goto exit;

    status = DIGI_CALLOC((void **) &pNewTDesCtx, 1, sizeof(DES3Ctx));
    if (OK != status)
      goto exit;

    pNewTDesCtx->pMocSymCtx = pNewSymCtx;
    pNewSymCtx = NULL;

    pNewTDesCtx->initialized = pTDesCtx->initialized;
    pNewTDesCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;
    *ppNewCtx = (BulkCtx) pNewTDesCtx;
    pNewTDesCtx = NULL;
  }
  else
  {
    MOC_TDES_CLONE(status, pCtx, ppNewCtx)
  }

exit:

  if (NULL != pNewSymCtx)
  {
    (void) CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }
  if (NULL != pNewTDesCtx)
  {
    (void) DIGI_FREE((void **)&pNewTDesCtx);
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_Reset3DESCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *pCtx
  )
{
  MSTATUS status;
  DES3Ctx *pTDesCtx = NULL;

  status = ERR_NULL_POINTER;
  if (NULL == pCtx)
    goto exit;

  pTDesCtx = (DES3Ctx *)(*pCtx);

  if (NULL == pTDesCtx)
    goto exit;

  status = OK;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pTDesCtx->enabled)
  {
    pTDesCtx->initialized = 0;
  }
  else
  {
    MOC_TDES_RESET(status, pCtx)
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN BulkCtx CRYPTO_INTERFACE_THREE_DES_createCtx (
    ubyte *pKeyMaterial,
    sbyte4 keyLen,
    sbyte4 encrypt
    )
{
  MSTATUS status = OK;
  ctx3des *pCtx = NULL;

  MOC_UNUSED(encrypt);

  status = DIGI_CALLOC((void **) &pCtx, 1, sizeof(ctx3des));
  if (OK != status)
    return NULL;

  status = CRYPTO_INTERFACE_THREE_DES_initKey(pCtx, pKeyMaterial, keyLen);
  if (OK != status)
  {
    (void) DIGI_FREE((void **)&pCtx);
    pCtx = NULL;
  }

  return (BulkCtx) pCtx;
}

/*---------------------------------------------------------------------------*/

#ifndef __DISABLE_3DES_TWO_KEY_CIPHER__
MOC_EXTERN BulkCtx CRYPTO_INTERFACE_THREE_DES_create2KeyCtx( 
  ubyte *pKeyMaterial,
  sbyte4 keyLen,
  sbyte4 encrypt
  )
{
  MSTATUS status = OK;
  ubyte pFullKey[THREE_DES_KEY_LENGTH] = {0};
  BulkCtx pCtx = NULL;

  if (THREE_DES_TWO_KEY_LENGTH != keyLen)
    return NULL;
  
  status = DIGI_MEMCPY(pFullKey, pKeyMaterial, keyLen);
  if (OK != status)
    goto exit;

  status = DIGI_MEMCPY(pFullKey + THREE_DES_TWO_KEY_LENGTH, pKeyMaterial, DES_KEY_LENGTH);
  if (OK != status)
    goto exit;

  pCtx = CRYPTO_INTERFACE_THREE_DES_createCtx(pFullKey, THREE_DES_KEY_LENGTH, encrypt);

exit:

  (void) DIGI_MEMSET(pFullKey, 0x00, THREE_DES_KEY_LENGTH);
  
  return pCtx;
}
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_THREE_DES_initKey (
  ctx3des *pCtx,
  const ubyte *pKey,
  sbyte4 keyLen
  )
{
  MSTATUS status;
  ubyte4 algoStatus, index;
  MocSymCtx pNewSymCtx = NULL;

  /* Determine if we have a TDES-ECB implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_tdes_ecb, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    /* Create a new MocSymCtx and load the key data in */
    status = CRYPTO_INTERFACE_createAndLoadSymKey (
      index, NULL, (ubyte *)pKey, (ubyte4)keyLen, &pNewSymCtx);
    if (OK != status)
      goto exit;

    /* Place the newly created MocSymCtx into the object */
    pCtx->pMocSymCtx = pNewSymCtx;
    pNewSymCtx = NULL;

    /* Mark this object to indicate that it is using an alternate
     * implementation through the crypto interface */
    pCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;
  }
  else
  {
    MOC_THREE_DES_INIT(status, pCtx, pKey, keyLen)
  }

exit:

  if (NULL != pNewSymCtx)
  {
    CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_THREE_DES_encipher (
  ctx3des *pCtx,
  ubyte *pSrc,
  ubyte *pDest,
  ubyte4 numBytes
  )
{
  MSTATUS status;
  ubyte4 outLen;

  status = ERR_NULL_POINTER;
  if (NULL == pCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  {
    /* We must have an underlying MocSymCtx */
    if (NULL == pCtx->pMocSymCtx)
      goto exit;

    if (0 != (MOC_LOCAL_TYPE_TAP & pCtx->pMocSymCtx->localType))
    {
      status = CRYPTO_INTERFACE_TAP_THREE_DES_encipher(pCtx->pMocSymCtx, pSrc, pDest, numBytes);
    }
    else
    {
      status = CRYPTO_cipherInit(pCtx->pMocSymCtx, MOC_CIPHER_FLAG_ENCRYPT);
      if (OK != status)
        goto exit;

      /* Update the cipher operation */
      status = CRYPTO_cipherUpdate (
        pCtx->pMocSymCtx, MOC_CIPHER_FLAG_ENCRYPT, pSrc, numBytes, pDest,
        numBytes, &outLen);
    }
  }
  else
  {
    MOC_THREE_DES_ENCRYPT(status, pCtx, pSrc, pDest, numBytes)
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_THREE_DES_decipher (
  ctx3des *pCtx,
  ubyte *pSrc,
  ubyte *pDest,
  ubyte4 numBytes
  )
{
  MSTATUS status;
  ubyte4 outLen;

  status = ERR_NULL_POINTER;
  if (NULL == pCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  {
    /* We must have an underlying MocSymCtx */
    if (NULL == pCtx->pMocSymCtx)
      goto exit;

    if (0 != (MOC_LOCAL_TYPE_TAP & pCtx->pMocSymCtx->localType))
    {
      status = CRYPTO_INTERFACE_TAP_THREE_DES_decipher(pCtx->pMocSymCtx, pSrc, pDest, numBytes);
    }
    else
    {
      status = CRYPTO_cipherInit(pCtx->pMocSymCtx, MOC_CIPHER_FLAG_DECRYPT);
      if (OK != status)
        goto exit;

      /* Update the cipher operation */
      status = CRYPTO_cipherUpdate (
        pCtx->pMocSymCtx, MOC_CIPHER_FLAG_DECRYPT, pSrc, numBytes, pDest,
        numBytes, &outLen);
    }
  }
  else
  {
    MOC_THREE_DES_DECRYPT(status, pCtx, pSrc, pDest, numBytes)
  }

exit:
  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_THREE_DES_clearKey (
  ctx3des *pCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  {
    if (NULL != pCtx->pMocSymCtx)
    {
      status = CRYPTO_freeMocSymCtx(&(pCtx->pMocSymCtx));
      if (OK != status)
        goto exit;
    }
  }

  status = DIGI_MEMSET((ubyte *)pCtx, 0, sizeof(ctx3des));

exit:

  return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_THREE_DES_deleteCtx(BulkCtx *pCtx)
{
  MSTATUS status = OK, fstatus = OK;

  if (NULL == pCtx)
    return ERR_NULL_POINTER;
  
  if (NULL != *pCtx)
  {
    status = CRYPTO_INTERFACE_THREE_DES_clearKey((ctx3des *) *pCtx);

    /* context already zeroed by the above call too */
    fstatus = DIGI_FREE(pCtx);
    if (OK == status)
      status = fstatus;
  }

  return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_THREE_DES_cloneCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  BulkCtx *ppNewCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  ctx3des *pTDesCtx = NULL;
  ctx3des *pNewTDesCtx = NULL;
  MocSymCtx pNewSymCtx = NULL;

  if ( (NULL == pCtx) || (NULL == ppNewCtx) )
    goto exit;

  /* No passthrough in FIPS layer, allocate here in CI in all cases */
  status = DIGI_CALLOC((void **) &pNewTDesCtx, 1, sizeof(ctx3des));
  if (OK != status)
    goto exit;

  pTDesCtx = (ctx3des *)pCtx;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pTDesCtx->enabled)
  {
    /* Clone the underlying MocSymCtx */
    status = CRYPTO_cloneMocSymCtx(pTDesCtx->pMocSymCtx, &pNewSymCtx);
    if (OK != status)
      goto exit;

    pNewTDesCtx->pMocSymCtx = pNewSymCtx; pNewSymCtx = NULL;
    pNewTDesCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;
  }
  else
  {
    status = DIGI_MEMCPY((ubyte *) pNewTDesCtx, (ubyte *) pTDesCtx, sizeof(ctx3des));
    if (OK != status)
       goto exit;
  }

  *ppNewCtx = (BulkCtx) pNewTDesCtx;
  pNewTDesCtx = NULL;

exit:

  if (NULL != pNewSymCtx)
  {
    (void) CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }
  if (NULL != pNewTDesCtx)
  {
    (void) DIGI_FREE((void **)&pNewTDesCtx);
  }
  return status;
}
#endif
