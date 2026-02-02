/*
 * crypto_interface_poly1305.c
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_POLY1305_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../crypto/poly1305.h"
#include "../crypto_interface/crypto_interface_priv.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_POLY1305__))

#define MOC_POLY1305_KEY_LEN 32
#define MOC_POLY1305_MAC_LEN 16

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_POLY1305_INIT(_status, _pCtx, _pKey)                              \
    _status = Poly1305Init(MOC_HASH(hwAccelCtx) _pCtx, _pKey);                 \
    if (OK == _status)                                                        \
    {                                                                         \
      _pCtx->pMocSymCtx = NULL;                                               \
      _pCtx->enabled = 0;                                                     \
    }
#else
#define MOC_POLY1305_INIT(_status, _pCtx, _pKey)                              \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_POLY1305_UPDATE(_status, _pCtx, _pM, _bytes)                      \
    _status = Poly1305Update(MOC_HASH(hwAccelCtx) _pCtx, _pM, _bytes);
#else
#define MOC_POLY1305_UPDATE(_status, _pCtx, _pM, _bytes)                      \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_POLY1305_FINAL(_status, _pCtx, _pMac)                             \
    _status = Poly1305Final(MOC_HASH(hwAccelCtx) _pCtx, _pMac);
#else
#define MOC_POLY1305_FINAL(_status, _pCtx, _pMac)                             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_POLY1305_COMPLETE(_status, _pMac, _pM, _bytes, _pKey)             \
    _status = Poly1305_completeDigest(MOC_HASH(hwAccelCtx) _pMac, _pM, _bytes, _pKey);
#else
#define MOC_POLY1305_COMPLETE(_status, _pMac, _pM, _bytes, _pKey)             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_Poly1305Init (
  MOC_HASH(hwAccelDescr hwAccelCtx) Poly1305Ctx *pCtx,
  const ubyte pKey[32]
  )
{
  MSTATUS status;
  ubyte4 algoStatus, index;
  MocSymCtx pNewSymCtx = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pCtx) || (NULL == pKey) )
    goto exit;

  /* Determine uf we have a Poly1305 implementation */
  status = CRYPTO_INTERFACE_checkSymAlgoStatus (
    moc_alg_poly1305, &algoStatus, &index);
  if (OK != status)
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
  {
    /* Create an empty MocSymCtx and store the key within it */
    status = CRYPTO_INTERFACE_createAndLoadSymKey(
      index, NULL, (ubyte *) pKey, MOC_POLY1305_KEY_LEN, &pNewSymCtx);
    if (OK != status)
      goto exit;

    /* Initialize the MAC operation */
    status = CRYPTO_macInit(pNewSymCtx);
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
    MOC_POLY1305_INIT(status, pCtx, pKey)
  }

exit:

  if (NULL != pNewSymCtx)
    CRYPTO_freeMocSymCtx (&pNewSymCtx);

  return status;
}


/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_Poly1305Update (
  MOC_HASH(hwAccelDescr hwAccelCtx) Poly1305Ctx *pCtx,
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
    status = CRYPTO_macUpdate(pCtx->pMocSymCtx, (ubyte *) pData, dataLen);
  }
  else
  {
    MOC_POLY1305_UPDATE(status, pCtx, pData, dataLen);
  }

exit:

  return status;
}


/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_Poly1305Final (
  MOC_HASH(hwAccelDescr hwAccelCtx) Poly1305Ctx *pCtx,
  ubyte *pResult
  )
{
  MSTATUS status;
  ubyte4 outLen;

  status = ERR_NULL_POINTER;
  if ( (NULL == pCtx) || (NULL == pResult) )
    goto exit;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
  {
    MSTATUS fstatus;
    
    status = CRYPTO_macFinal (pCtx->pMocSymCtx, NULL, 0, pResult, MOC_POLY1305_MAC_LEN, &outLen);
      
    /* cleanup irregardless of status */
    fstatus = CRYPTO_freeMocSymCtx(&(pCtx->pMocSymCtx));
    if (OK == status)
        status = fstatus;
      
    DIGI_MEMSET((ubyte *) pCtx, 0x00, sizeof(Poly1305Ctx)); /* ok to ignore return code */
  }
  else
  {
    MOC_POLY1305_FINAL(status, pCtx, pResult)
  }

exit:

  return status;
}


/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_Poly1305_completeDigest (
  MOC_HASH(hwAccelDescr hwAccelCtx) ubyte pMac[16],
  const ubyte *pM,
  ubyte4 bytes,
  const ubyte pKey[32]
  )
{
  MSTATUS status;
  Poly1305Ctx ctx;

  status = ERR_NULL_POINTER;
  if ( (NULL == pMac) || (NULL == pKey) )
    goto exit;

  status = CRYPTO_INTERFACE_Poly1305Init (MOC_HASH(hwAccelCtx) &ctx, pKey);
  if (OK != status)
    goto exit;

  status = CRYPTO_INTERFACE_Poly1305Update (MOC_HASH(hwAccelCtx) &ctx, pM, bytes);
  if (OK != status)
    goto exit;

  status = CRYPTO_INTERFACE_Poly1305Final (MOC_HASH(hwAccelCtx) &ctx, pMac);

exit:

  return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_Poly1305_cloneCtx (
  MOC_HASH(hwAccelDescr hwAccelCtx) Poly1305Ctx *pDest,
  Poly1305Ctx *pSrc
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
  }
  else
  {
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    /* No Clone API to passthrough to until we can modify FIPS boundary */
    /* Poly1305Ctx has no pointers in this case so we can just do a memcpy */
    status = DIGI_MEMCPY((void *) pDest, (void *) pSrc, sizeof(Poly1305Ctx));
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

  return status;
}
#endif
