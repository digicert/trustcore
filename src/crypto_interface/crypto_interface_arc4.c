/*
 * crypto_interface_arc4.c
 *
 * Cryptographic Interface specification for RC4 methods.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_ARC4_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../crypto/arc4.h"
#include "../crypto/rc4algo.h"
#include "../crypto_interface/crypto_interface_priv.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_ARC4__))

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) &&                   \
    (!defined(__DISABLE_ARC4_CIPHERS__))
#define MOC_RC4_CREATE(_pCtx, _pKey, _keyLen, _encrypt)                        \
    _pCtx = CreateRC4Ctx(MOC_SYM(hwAccelCtx) _pKey, _keyLen, _encrypt);        \
    if (NULL != _pCtx)                                                         \
    {                                                                          \
      _pCtx->enabled = 0;                                                      \
      _pCtx->pMocSymCtx = NULL;                                                \
    }
#else
#define MOC_RC4_CREATE(_pCtx, _pKey, _keyLen, _encrypt)                        \
    _pCtx = NULL
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_ARC4_CIPHERS__))
#define MOC_RC4_DELETE(_status, _ppCtx) \
    _status = DeleteRC4Ctx(MOC_SYM(hwAccelCtx) _ppCtx);
#else
#define MOC_RC4_DELETE(_status, _ppCtx) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_ARC4_CIPHERS__))
#define MOC_RC4_CLONE(_status, _pCtx, _ppNewCtx)             \
    _status = CloneRC4Ctx(MOC_SYM(hwAccelCtx) _pCtx, _ppNewCtx);
#else
#define MOC_RC4_CLONE(_status, _pCtx, _ppNewCtx)             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif



/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_ARC4_CIPHERS__))
#define MOC_RC4_DO(_status, _pCtx, _pData, _dataLen, _encrypt, _pIv) \
    _status = DoRC4(MOC_SYM(hwAccelCtx) _pCtx, _pData, _dataLen, _encrypt, _pIv)
#else
#define MOC_RC4_DO(_status, _pCtx, _pData, _dataLen, _encrypt, _pIv) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateRC4Ctx(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *pKeyMaterial,
    sbyte4 keyLen,
    sbyte4 encrypt
    )
{
    MSTATUS status;
    ubyte4 algoStatus;
    ubyte4 index;
    rc4_key *pNewCtx = NULL;
    MocSymCtx pNewSymCtx = NULL;

    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_arc4, &algoStatus, &index);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        /* Create a copy of the Operator MocSymCtx and store the key within it */
        status = CRYPTO_INTERFACE_createAndLoadSymKey (index, NULL, (ubyte *) pKeyMaterial, keyLen, &pNewSymCtx);
        if (OK != status)
            goto exit;

        status = CRYPTO_cipherInit(pNewSymCtx, 0);
        if (OK != status)
            goto exit;

        /* Allocate the rc4 context */
        status = DIGI_CALLOC ((void **) &pNewCtx, 1, sizeof (rc4_key));
        if (OK != status)
            goto exit;

        pNewCtx->pMocSymCtx = pNewSymCtx;
        pNewSymCtx = NULL;

        /* Mark this object to indicate that it is using an alternate
         * implementation through the crypto interface */
        pNewCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;
    }
    else
    {
        MOC_RC4_CREATE(pNewCtx, pKeyMaterial, keyLen, encrypt);
    }

exit:

    if (NULL != pNewSymCtx)
        CRYPTO_freeMocSymCtx (&pNewSymCtx); /* ok to ignore return, here only on error */

    return (BulkCtx) pNewCtx;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DeleteRC4Ctx(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    rc4_key *pCtx = NULL;

    if (NULL == ppCtx)
        goto exit;

    status = OK; /* ok no-op if the context was already deleted */
    pCtx = (rc4_key *) (*ppCtx);
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
        *ppCtx = NULL;
    }
    else
    {
        MOC_RC4_DELETE(status, ppCtx);
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_CloneRC4Ctx (
  MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
  BulkCtx *ppNewCtx
  )
{
  MSTATUS status;
  rc4_key *pRc4Ctx = NULL;
  rc4_key *pNewRc4Ctx = NULL;
  MocSymCtx pNewSymCtx = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pCtx) || (NULL == ppNewCtx) )
    goto exit;

  pRc4Ctx = (rc4_key *)pCtx;

  if (CRYPTO_INTERFACE_ALGO_ENABLED == pRc4Ctx->enabled)
  {
    /* Clone the underlying MocSymCtx */
    status = CRYPTO_cloneMocSymCtx(pRc4Ctx->pMocSymCtx, &pNewSymCtx);
    if (OK != status)
      goto exit;

    status = DIGI_CALLOC((void **)&pNewRc4Ctx, 1, sizeof(rc4_key));
    if (OK != status)
      goto exit;

    status = DIGI_MEMCPY((void *)pNewRc4Ctx, (void *)pRc4Ctx, sizeof(rc4_key));
    if (OK != status)
      goto exit;

    pNewRc4Ctx->pMocSymCtx = pNewSymCtx;
    pNewSymCtx = NULL;
    *ppNewCtx = (BulkCtx)pNewRc4Ctx;
    pNewRc4Ctx = NULL;
  }
  else
  {
    MOC_RC4_CLONE(status, pCtx, ppNewCtx);
  }

exit:
  if (NULL != pNewSymCtx)
  {
    CRYPTO_freeMocSymCtx(&pNewSymCtx);
  }
  if (NULL != pNewRc4Ctx)
  {
    DIGI_FREE((void **)&pNewRc4Ctx);
  }
  return status;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoRC4(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte *pData,
    sbyte4 dataLen,
    sbyte4 encrypt,
    ubyte *pIv
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    rc4_key *pRC4Ctx = NULL;

    if (NULL == pCtx)
        goto exit;

    pRC4Ctx = (rc4_key *) pCtx;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pRC4Ctx->enabled)
    {
        ubyte4 dataOut;

        /* quick validation */
        if (NULL == pData && dataLen)
            goto exit;  /* status still ERR_NULL_POINTER */

        status = ERR_INVALID_ARG;
        if ( dataLen < 0)
            goto exit;

        status = OK;
        if (dataLen)
            status = CRYPTO_cipherUpdate (pRC4Ctx->pMocSymCtx, 0, pData, (ubyte4) dataLen, pData, (ubyte4) dataLen, &dataOut);
    }
    else
    {
        MOC_RC4_DO(status, pCtx, pData, dataLen, encrypt, pIv);
    }

exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_ARC4__ */
