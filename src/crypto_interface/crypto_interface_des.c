/*
 * crypto_interface_des.c
 *
 * Cryptographic Interface specification for DES.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_DES_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../crypto/des.h"
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/crypto_interface_des.h"
#include "../crypto_interface/crypto_interface_des_tap.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_DES__)) || \
    (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_TDES__))

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DES_INIT(_status, _pCtx, _pKey, _keyLen)                          \
    _status = DES_initKey(_pCtx, _pKey, _keyLen);                             \
    if (OK == _status)                                                        \
    {                                                                         \
       _pCtx->enabled = 0;                                                    \
       _pCtx->initialized = 0;                                                \
       _pCtx->pMocSymCtx = NULL;                                              \
    }
#else
#define MOC_DES_INIT(_status, _pCtx, _pKey, _keyLen)                          \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DES_ENCRYPT(_status, _pCtx, _pSrc, _pDest, _numBytes)             \
    _status = DES_encipher(_pCtx, _pSrc, _pDest, _numBytes)
#else
#define MOC_DES_ENCRYPT(_status, _pCtx, _pSrc, _pDest, _numBytes)             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DES_DECRYPT(_status, _pCtx, _pSrc, _pDest, _numBytes)             \
    _status = DES_decipher(_pCtx, _pSrc, _pDest, _numBytes)
#else
#define MOC_DES_DECRYPT(_status, _pCtx, _pSrc, _pDest, _numBytes)             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DES_CLEAR(_status, _pCtx)                                         \
    _status = DES_clearKey(_pCtx)
#else
#define MOC_DES_CLEAR(_status, _pCtx)                                         \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DES_CREATE(_pCtx, _pKeyData, _keyLen, _encrypt)                   \
    _pCtx = CreateDESCtx(MOC_SYM(hwAccelCtx) _pKeyData, _keyLen, _encrypt);   \
    if (NULL != _pCtx)                                                        \
    {                                                                         \
       _pCtx->enabled = 0;                                                    \
       _pCtx->initialized = 0;                                                \
       _pCtx->pMocSymCtx = NULL;                                              \
    }
#else
#define MOC_DES_CREATE(_pCtx, _pKeyData, _keyLen, _encrypt)
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DO_DES(_status, _pCtx, _pData, _dataLen, _encrypt, _pIv)          \
    _status = DoDES(MOC_SYM(hwAccelCtx) _pCtx, _pData, _dataLen, _encrypt, _pIv)
#else
#define MOC_DO_DES(_status, _pCtx, _pData, _dataLen, _encrypt, _pIv)          \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DES_DELETE(_status, _pCtx)                                        \
    _status = DeleteDESCtx(MOC_SYM(hwAccelCtx) _pCtx)
#else
#define MOC_DES_DELETE(_status, _pCtx)                                        \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DES_CLONE(_status, _pCtx, _ppCtx)                                 \
    _status = CloneDESCtx(MOC_SYM(hwAccelCtx) _pCtx, _ppCtx)
#else
#define MOC_DES_CLONE(_status, _pCtx, _ppCtx)                                 \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DES_initKey (
  DES_CTX *pCtx,
  const ubyte *pKey,
  sbyte4 keyLen
  )
{
  MSTATUS status;
  ubyte4 algoStatus, index;
  MocSymCtx pNewSymCtx = NULL;

  /* Determine if we have a TDES-ECB implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_des_ecb, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    /* Create a new MocSymCtx and load the key data in */
    status = CRYPTO_INTERFACE_createAndLoadSymKey (index, NULL, (ubyte *)pKey, (ubyte4)keyLen, &pNewSymCtx);
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
    MOC_DES_INIT(status, pCtx, pKey, keyLen);
  }

exit:

  if (NULL != pNewSymCtx)
  {
    CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }

  return status;
}
/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DES_encipher (
  DES_CTX *pCtx,
  ubyte *pSrc,
  ubyte *pDest,
  ubyte4 numBytes
  )
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  {
    /* We must have an underlying MocSymCtx */
    if (NULL == pCtx->pMocSymCtx)
      goto exit;

    if (0 != (MOC_LOCAL_TYPE_TAP & pCtx->pMocSymCtx->localType))
    {
      status = CRYPTO_INTERFACE_TAP_DES_encipher(pCtx->pMocSymCtx, pSrc, pDest, numBytes);
    }
    else
    {
      ubyte4 outLen;

      status = CRYPTO_cipherInit(pCtx->pMocSymCtx, MOC_CIPHER_FLAG_ENCRYPT);
      if (OK != status)
        goto exit;

      /* Update the cipher operation */
      status = CRYPTO_cipherUpdate (pCtx->pMocSymCtx, MOC_CIPHER_FLAG_ENCRYPT, pSrc, numBytes, pDest, numBytes, &outLen);
    }
  }
  else
  {
    MOC_DES_ENCRYPT(status, pCtx, pSrc, pDest, numBytes);
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DES_decipher (
  DES_CTX *pCtx,
  ubyte *pSrc,
  ubyte *pDest,
  ubyte4 numBytes
  )
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  {
    /* We must have an underlying MocSymCtx */
    if (NULL == pCtx->pMocSymCtx)
      goto exit;

    if (0 != (MOC_LOCAL_TYPE_TAP & pCtx->pMocSymCtx->localType))
    {
      status = CRYPTO_INTERFACE_TAP_DES_decipher(pCtx->pMocSymCtx, pSrc, pDest, numBytes);
    }
    else
    {
      ubyte4 outLen;

      status = CRYPTO_cipherInit(pCtx->pMocSymCtx, MOC_CIPHER_FLAG_DECRYPT);
      if (OK != status)
        goto exit;

      /* Update the cipher operation */
      status = CRYPTO_cipherUpdate (pCtx->pMocSymCtx, MOC_CIPHER_FLAG_DECRYPT, pSrc, numBytes, pDest, numBytes, &outLen);
    }
  }
  else
  {
    MOC_DES_DECRYPT(status, pCtx, pSrc, pDest, numBytes);
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DES_clearKey (
  DES_CTX *pCtx
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

    status = DIGI_MEMSET((ubyte *)pCtx, 0, sizeof(DES_CTX));
  }
  else
  {
    MOC_DES_CLEAR(status, pCtx);
  }

exit:

  return status;
}

/*----------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_DES__

MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateDESCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *pKeyMaterial,
  sbyte4 keyLen,
  sbyte4 encrypt
  )
{
  MSTATUS status;
  ubyte4 algoStatus, index;
  void *pPtr = NULL;
  MocSymCtx pNewSymCtx = NULL;
  DES_CTX *pDesCtx = NULL;

  /* Determine if we have a DES-CBC implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_des_cbc, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    /* Create a new MocSymCtx and load the key data in */
    status = CRYPTO_INTERFACE_createAndLoadSymKey (
      index, NULL, pKeyMaterial, (ubyte4)keyLen, &pNewSymCtx);
    if (OK != status)
      goto exit;

    /* We do not want to call init here, we still need the IV from the DoDES
     * call. Instead we will create an empty object and allocate the DESCtx
     * shell. When we recieve the IV in CRYPTO_INTERFACE_DoDES, we will
     * perform the init. */
    status = DIGI_CALLOC(&pPtr, 1, sizeof(DES_CTX));
    if (OK != status)
      goto exit;

    pDesCtx = (DES_CTX *) pPtr;
    pPtr = NULL;
    pDesCtx->pMocSymCtx = pNewSymCtx;
    pNewSymCtx = NULL;

    /* Mark this object to indicate that it is using an alternate
     * implementation through the crypto interface, and uninitialized with an iv */
    pDesCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;
    pDesCtx->initialized = 0;
  }
  else
  {
    MOC_DES_CREATE(pDesCtx, pKeyMaterial, keyLen, encrypt);
  }

exit:

  if (NULL != pPtr)
  {
    DIGI_FREE(&pPtr);  /* here on error only, ignore return code */
  }
  if (NULL != pNewSymCtx)
  {
    CRYPTO_freeMocSymCtx(&pNewSymCtx);  /* here on error only, ignore return code */
  }

  return pDesCtx;

}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoDES (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pData,
  sbyte4 dataLen,
  sbyte4 encrypt,
  ubyte *pIv
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  DES_CTX *pDesCtx = (DES_CTX *) pCtx;

  if (NULL == pDesCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pDesCtx->enabled)
  {
    if (0 != (MOC_LOCAL_TYPE_TAP & pDesCtx->pMocSymCtx->localType))
    {
      status = CRYPTO_INTERFACE_TAP_DoDES(pDesCtx->pMocSymCtx, pData, dataLen, encrypt, pIv);
    }
    else
    {
      ubyte4 outLen = 0;
      ubyte4 cipherFlag = MOC_CIPHER_FLAG_ENCRYPT;

      /* We assumed encryption to start, check for decryption */
      if (0 == encrypt)
        cipherFlag = MOC_CIPHER_FLAG_DECRYPT;

      /* If this is the first call to DoDES for this DES_CTX, update the
      * underlying MocSymCtx with the initialization vector and then
      * initialize the operation. If this is a continuation of a previous
      * operation, simply continue the update process */
      if (0 == pDesCtx->initialized)
      {
        MDesUpdateData desParams = {0};
        MocCtx pMocCtx = NULL;

        /* Get a reference to the MocCtx registered with the Crypto Interface */
        status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
        if (OK != status)
          goto exit;

        /* Update the operator with the initialization vector, also inform the
        * operator that they should not be performing PKCS5 padding */
        desParams.pInitVector = pIv;
        desParams.initVectorLen = DES_BLOCK_SIZE;
        desParams.padding = FALSE;

        status = CRYPTO_updateSymOperatorData (
          pDesCtx->pMocSymCtx, pMocCtx, (void *)&desParams);
        if (OK != status)
          goto exit;

        /* Initialize the cipher operation  */
        status = CRYPTO_cipherInit(pDesCtx->pMocSymCtx, cipherFlag);
        if (OK != status)
          goto exit;

        /* Mark this object as initialized so we dont overwrite the
        * initialization vector within the object on the next call */
        pDesCtx->initialized = 1;
      }

      /* Update the cipher operation */
      status = CRYPTO_cipherUpdate (
        pDesCtx->pMocSymCtx, cipherFlag, pData, (ubyte4)dataLen, pData,
        (ubyte4)dataLen, &outLen);
    }
  }
  else
  {
    MOC_DO_DES(status, pCtx, pData, dataLen, encrypt, pIv);
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoDESEx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  ubyte *pData,
  sbyte4 dataLen,
  sbyte4 encrypt,
  ubyte *pIv
  )
{
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    MSTATUS status = ERR_NULL_POINTER;
    DES_CTX *pDesCtx = (DES_CTX *) pCtx;

    if (NULL == pDesCtx)
        goto exit;

    /* We want to update the IV the operator is using with the one that is passed
     * to this function call. if initialized is set to zero, then
     * CRYPTO_INTERFACE_DoDES call will make updateSymOperatorData call,
     * otherwise we have to make it ourselves.
     */
    if (1 == pDesCtx->initialized)
    {
        MocCtx pMocCtx = NULL;
        MDesUpdateData desParams = {0};

        /* Get a reference to the MocCtx registered with the Crypto Interface */
        status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
        if (OK != status)
            goto exit;

        /* Update the operator with the initialization vector */
        desParams.pInitVector = pIv;
        desParams.initVectorLen = DES_BLOCK_SIZE;
        desParams.padding = FALSE;

        status = CRYPTO_updateSymOperatorData (pDesCtx->pMocSymCtx, pMocCtx, (void *)&desParams);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_INTERFACE_DoDES(pCtx, pData, dataLen, encrypt, pIv);
    if (OK != status)
        goto exit;

    /* update the passed in pIv to the latest copy */
    status = CRYPTO_INTERFACE_getIv(pDesCtx->pMocSymCtx, pIv);

exit:

    return status;

#else

    return CRYPTO_INTERFACE_DoDES(MOC_SYM(hwAccelCtx) pCtx, pData, dataLen, encrypt, pIv);

#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DeleteDESCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *pCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  DES_CTX *pDesCtx = NULL;

  if (NULL == pCtx)
    goto exit;

  pDesCtx = (DES_CTX *)(*pCtx);
  
  /* It is not an error to attempt to free a NULL context */
  status = OK;
  if (NULL == pDesCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pDesCtx->enabled)
  {
    MocSymCtx pSymCtx = NULL;
    MSTATUS fstatus;

    /* Make our own copy of the MocSymCtx pointer */
    pSymCtx = pDesCtx->pMocSymCtx;

    /* Free the outer shell first */
    status = DIGI_FREE((void **)&pDesCtx);

    /* and set the caller's pointer to NULL too */
    *pCtx = NULL;

    /* It is not an error to attempt to free a NULL context */
    if (NULL == pSymCtx)
      goto exit;

    /* If a TAP context we need to finalize the cipher operation */
    if (0 != (MOC_LOCAL_TYPE_TAP & pSymCtx->localType))
    {
      fstatus = CRYPTO_INTERFACE_TAP_DES_Final(pSymCtx);
      if (OK == status)
        status = fstatus;
    }

    /* Free the inner context */
    fstatus = CRYPTO_freeMocSymCtx(&pSymCtx);
    if (OK == status)
      status = fstatus;
  }
  else
  {
    MOC_DES_DELETE(status, pCtx);
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_CloneDESCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  BulkCtx *ppNewCtx
  )
{
  MSTATUS status;
  DES_CTX *pDesCtx = NULL;
  DES_CTX *pNewDesCtx = NULL;
  MocSymCtx pNewSymCtx = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pCtx) || (NULL == ppNewCtx) )
    goto exit;

  pDesCtx = (DES_CTX *)pCtx;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pDesCtx->enabled)
  {
    /* Clone the underlying MocSymCtx */
    status = CRYPTO_cloneMocSymCtx(pDesCtx->pMocSymCtx, &pNewSymCtx);
    if (OK != status)
      goto exit;

    status = DIGI_CALLOC((void **)&pNewDesCtx, 1, sizeof(DES_CTX));
    if (OK != status)
      goto exit;

    status = DIGI_MEMCPY((void *)pNewDesCtx, (void *)pDesCtx, sizeof(DES_CTX));
    if (OK != status)
      goto exit;

    pNewDesCtx->pMocSymCtx = pNewSymCtx;
    pNewSymCtx = NULL;
    *ppNewCtx = (BulkCtx)pNewDesCtx;
    pNewDesCtx = NULL;

  }
  else
  {
    MOC_DES_CLONE(status, pCtx, ppNewCtx);
  }

exit:
  if (NULL != pNewSymCtx)
  {
    CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }
  if (NULL != pNewDesCtx)
  {
    DIGI_FREE((void **)&pNewDesCtx);
  }
  return status;
}

#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_DES__ */

#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_DES__ || __ENABLE_DIGICERT_CRYPTO_INTERFACE_TDES__ */
