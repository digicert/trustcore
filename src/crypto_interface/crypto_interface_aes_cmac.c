/*
 * crypto_interface_aes_cmac.c
 *
 * Cryptographic Interface specification for AES CMAC methods.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CMAC_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../crypto/aes.h"
#include "../crypto/aes_ecb.h"
#include "../crypto/aes_cmac.h"
#include "../crypto_interface/crypto_interface_aes_cmac.h"
#include "../crypto_interface/crypto_interface_priv.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CMAC__

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_CMAC__))
#define MOC_AES_CMAC_INIT(_status, _pKey, _keyLen, _pCtx, _pExtCtx)           \
    _status = AESCMAC_initExt(MOC_SYM(hwAccelCtx) _pKey, _keyLen, _pCtx, _pExtCtx);               \
    if (OK == _status)                                                        \
    {                                                                         \
       _pCtx->enabled = 0;                                                    \
       _pCtx->pMocSymCtx = NULL;                                              \
    }
#else
#define MOC_AES_CMAC_INIT(_status, _pKey, _keyLen, _pCtx, _pExtCtx)           \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_CMAC__))
#define MOC_AES_CMAC_UPDATE(_status, _pData, _dataLen, _pCtx, _pExtCtx)       \
    _status = AESCMAC_updateExt(MOC_SYM(hwAccelCtx) _pData, _dataLen, _pCtx, _pExtCtx)
#else
#define MOC_AES_CMAC_UPDATE(_status, _pData, _dataLen, _pCtx, _pExtCtx)       \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_CMAC__))
#define MOC_AES_CMAC_FINAL(_status, _cmac, _pCtx, _pExtCtx)                   \
    _status = AESCMAC_finalExt(MOC_SYM(hwAccelCtx) _cmac, _pCtx, _pExtCtx)
#else
#define MOC_AES_CMAC_FINAL(_status, _cmac, _pCtx, _pExtCtx)                   \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_CMAC__))
#define MOC_AES_CMAC_CLEAR(_status, _pCtx)                                    \
    _status = AESCMAC_clear(MOC_SYM(hwAccelCtx) _pCtx)
#else
#define MOC_AES_CMAC_CLEAR(_status, _pCtx)                                    \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESCMAC_init(
    MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte *pKeyMaterial,
    sbyte4 keyLength,
    AESCMAC_Ctx *pCtx
)
{
    return CRYPTO_INTERFACE_AESCMAC_initExt(MOC_SYM(hwAccelCtx) pKeyMaterial, keyLength, pCtx, NULL);
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESCMAC_initExt(
    MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte *pKeyMaterial,
    sbyte4 keyLength,
    AESCMAC_Ctx *pCtx,
    void *pExtCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
    ubyte4 index = 0;
    MocSymCtx pNewSymCtx = NULL;
    
    if (NULL == pCtx || NULL == pKeyMaterial)
        goto exit;
    
    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_aes_cmac, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        /* MocSymCtx has to be created before we updateSymOperatorData. */
        status = CRYPTO_INTERFACE_createAndLoadSymKey (index, NULL, (ubyte *) pKeyMaterial, (ubyte4) keyLength, &pNewSymCtx);
        if (OK != status)
            goto exit;
        
        /* initialize cipher operation since we have all necessary data */
        status = CRYPTO_macInit(pNewSymCtx);
        if (OK != status)
            goto exit;
        
        pCtx->pMocSymCtx = pNewSymCtx;
        pNewSymCtx = NULL;
        
        pCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;
    }
    else
    {
        MOC_AES_CMAC_INIT(status, pKeyMaterial, keyLength, pCtx, pExtCtx);
    }
    
exit:
    
    if (NULL != pNewSymCtx)
        (void) CRYPTO_freeMocSymCtx(&pNewSymCtx);  /* no reason to check status, if here then error occurred */
    
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESCMAC_update(
    MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte *pData,
    sbyte4 dataLength,
    AESCMAC_Ctx *pCtx
    )
{
    return CRYPTO_INTERFACE_AESCMAC_updateExt(MOC_SYM(hwAccelCtx) pData, dataLength, pCtx, NULL);
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESCMAC_updateExt(
    MOC_SYM(hwAccelDescr hwAccelCtx) const ubyte *pData,
    sbyte4 dataLength,
    AESCMAC_Ctx *pCtx,
    void *pExtCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    
    if (NULL == pCtx)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        if (NULL == pData && dataLength)
            goto exit;
    
        if (dataLength)
            status = CRYPTO_macUpdate(pCtx->pMocSymCtx, (ubyte *) pData, (ubyte4) dataLength);
        else
            status = OK;
    }
    else
    {
        MOC_AES_CMAC_UPDATE(status, pData, dataLength, pCtx, pExtCtx);
    }
    
exit:
    
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESCMAC_final(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte cmac[16],
    AESCMAC_Ctx* pCtx
    )
{
    return CRYPTO_INTERFACE_AESCMAC_finalExt(MOC_SYM(hwAccelCtx) cmac, pCtx, NULL);
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESCMAC_finalExt(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte cmac[16],
    AESCMAC_Ctx* pCtx,
    void *pExtCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    
    if (NULL == pCtx)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        ubyte4 outLen;
        MSTATUS fstatus;
        
        if (NULL == cmac)
            goto exit;
        
        status = CRYPTO_macFinal(pCtx->pMocSymCtx, NULL, 0, cmac, 16, &outLen);
        
        /* regardless of status, cleanup the context */
        fstatus = CRYPTO_freeMocSymCtx(&(pCtx->pMocSymCtx));
        if (OK == status)
            status = fstatus;
        
        DIGI_MEMSET((ubyte *) pCtx, 0x00, sizeof(AESCMAC_Ctx)); /* ok to ignore return code */
    }
    else
    {
        MOC_AES_CMAC_FINAL(status, cmac, pCtx, pExtCtx);
    }
    
exit:
    
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESCMAC_clear(
    MOC_SYM(hwAccelDescr hwAccelCtx) AESCMAC_Ctx* pCtx
    )
{
  MSTATUS status = ERR_NULL_POINTER;

  if (NULL == pCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  {
    status = OK;
    if (NULL != pCtx->pMocSymCtx)
    {
       status = CRYPTO_freeMocSymCtx(&(pCtx->pMocSymCtx));
    }

    (void) DIGI_MEMSET((ubyte *) pCtx, 0x00, sizeof(AESCMAC_Ctx)); 
  }
  else
  {
    MOC_AES_CMAC_CLEAR(status, pCtx);
  }

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESCMAC_cloneCtx (
  MOC_SYM(hwAccelDescr hwAccelCtx) AESCMAC_Ctx *pDest,
  AESCMAC_Ctx *pSrc
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MocSymCtx pNewSymCtx = NULL;
  aesCipherContext *pNewAesCtx = NULL;

  if (NULL == pSrc || NULL == pDest)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pSrc->enabled)
  {
    status = CRYPTO_cloneMocSymCtx (pSrc->pMocSymCtx, &pNewSymCtx);
    if (OK != status)
      goto exit;

    pDest->pMocSymCtx = pNewSymCtx; pNewSymCtx = NULL;
    pDest->enabled = pSrc->enabled;
  }
  else
  {
#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_CMAC__))
    /* No Clone API to passthrough to until we can modify FIPS boundary */

    /* we must reach in and clone the aesCipherCtx, rest can be copied */
    status = DIGI_MALLOC((void **) &pNewAesCtx, sizeof(aesCipherContext));
    if (OK != status)
      goto exit;

    /* this also copies the omac context in full */
    status = DIGI_MEMCPY((void *) pDest, (void *) pSrc, sizeof(AESCMAC_Ctx));
    if (OK != status)
      goto exit;

    /* but copy to and put our new AES context there */
    status = DIGI_MEMCPY((void *) pNewAesCtx, (void *) pSrc->pAesCtx, sizeof(aesCipherContext));
    if (OK != status)
      goto exit;

    pDest->pAesCtx = pNewAesCtx; pNewAesCtx = NULL;
#else
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif
  }

exit:

  if (NULL != pNewSymCtx)
  {
    /* here on error only, ignore status */
    (void) CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }

  if (NULL != pNewAesCtx)
  {
    (void) DIGI_FREE((void **) &pNewAesCtx); /* copy of the data was last op, so no need to zero memory on error */
  }

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESCMAC_finalAndReset(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte cmac[16],
    AESCMAC_Ctx* pCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  aesCipherContext *pAesClone = NULL;

  if (NULL == pCtx)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  {
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
  }
  else
  {
#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_CMAC__))
    
    /* we must reach in and clone the aesCipherCtx for later use */
    status = DIGI_MALLOC((void **) &pAesClone, sizeof(aesCipherContext));
    if (OK != status)
      goto exit;

    status = DIGI_MEMCPY((void *) pAesClone, (void *) pCtx->pAesCtx, sizeof(aesCipherContext));
    if (OK != status)
      goto exit;

    /* Now finalize */
    status = CRYPTO_INTERFACE_AESCMAC_finalExt(MOC_SYM(hwAccelCtx) cmac, pCtx, NULL);
    if (OK != status)
      goto exit;
    
    status = CRYPTO_INTERFACE_AESCMAC_clear(MOC_SYM(hwAccelCtx) pCtx);
    if (OK != status)
      goto exit;

    pCtx->pAesCtx = pAesClone; pAesClone = NULL;
    (void) AES_OMAC_init( &pCtx->omacCtx); /* will always return OK */
#else
    status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif
  }

exit:

  if (NULL != pAesClone)
  {
    (void) DIGI_MEMSET_FREE((ubyte **) &pAesClone, sizeof(aesCipherContext));
  }

  return status;
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_CMAC__ */
