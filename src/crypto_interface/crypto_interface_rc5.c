/*
 * crypto_interface_rc5.c
 *
 * Cryptographic Interface specification for RC5 methods.
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 *
 */

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_RC5_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../crypto/rc5algo.h"
#include "../crypto_interface/crypto_interface_priv.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_RC5__))

/* First two fields of MocRc5LocalCtx in rc5algo.c */
typedef struct _RC5CTX_SHADOW
{
    MocSymCtx pMocSymCtx;
    ubyte enabled;

} RC5CTX_SHADOW;

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) &&                  \
    (defined(__ENABLE_DIGICERT_RC5__))
#define MOC_RC5_CREATE(_status, _pKey, _keyLen, _iv, _ivLen, _bsb, _rounds, _pad, _encrypt, _ppCtx) \
    _status = MocCreateRC5Ctx(MOC_SYM(hwAccelCtx) _pKey, _keyLen, _iv, _ivLen, _bsb, _rounds, _pad, _encrypt, _ppCtx); \
    if (OK == _status)                                                        \
    {                                                                         \
      (*((RC5CTX_SHADOW **)_ppCtx))->enabled = 0;                             \
      (*((RC5CTX_SHADOW **)_ppCtx))->pMocSymCtx = NULL;                       \
    }
#else
#define MOC_RC5_CREATE(_status, _pKey, _keyLen, _iv, _ivLen, _bsb, _rounds, _pad, _encrypt, _ppCtx) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) &&                  \
    (defined(__ENABLE_DIGICERT_RC5__))
#define MOC_RC5_DELETE(_status, _ppCtx) \
    _status = MocDeleteRC5Ctx(MOC_SYM(hwAccelCtx) _ppCtx)
#else
#define MOC_RC5_DELETE(_status, _ppCtx) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) &&                  \
    (defined(__ENABLE_DIGICERT_RC5__))
#define MOC_RC5_UPDATE(_status, _pCtx, _enc, _pData, dataLen, _out, _outLen, _bytesWritten) \
    _status = MocRC5Update(MOC_SYM(hwAccelCtx) _pCtx, _enc, _pData, dataLen, _out, _outLen, _bytesWritten);
#else
#define MOC_RC5_UPDATE(_status, _pCtx, _enc, _pData, dataLen, _out, _outLen, _bytesWritten) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) &&                  \
    (defined(__ENABLE_DIGICERT_RC5__))
#define MOC_RC5_FINAL(_status, _pCtx, _enc, _pData, dataLen, _out, _outLen, _bytesWritten) \
    _status = MocRC5Final(MOC_SYM(hwAccelCtx) _pCtx, _enc, _pData, dataLen, _out, _outLen, _bytesWritten);
#else
#define MOC_RC5_FINAL(_status, _pCtx, _enc, _pData, dataLen, _out, _outLen, _bytesWritten) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) &&                  \
    (defined(__ENABLE_DIGICERT_RC5__))
#define MOC_RC5_REINIT(_status, _pCtx) \
    _status = MocReinitRC5Ctx(MOC_SYM(hwAccelCtx) _pCtx)
#else
#define MOC_RC5_REINIT(_status, _pCtx) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) &&                  \
    (defined(__ENABLE_DIGICERT_RC5__))
#define MOC_RC5_GETIV(_status, _pCtx, _pIv, _ivLen) \
    _status = MocRC5GetIv(MOC_SYM(hwAccelCtx) _pCtx, _pIv, _ivLen)
#else
#define MOC_RC5_GETIV(_status, _pCtx, _pIv, _ivLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_RC5__))
#define MOC_RC5_CLONE(_status, _pCtx, _ppNewCtx)             \
    _status = MocRC5CloneCtx(MOC_SYM(hwAccelCtx) _pCtx, _ppNewCtx);
#else
#define MOC_RC5_CLONE(_status, _pCtx, _ppNewCtx)             \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MocCreateRC5Ctx (
    MOC_SYM(hwAccelDescr hwAccelCtx)
    ubyte *keyMaterial,
    sbyte4 keyLength,
    ubyte *iv,
    sbyte4 ivLen,
    sbyte4 blockSizeBits,
    sbyte4 roundCount,
    sbyte4 padding,
    sbyte4 encrypt,
    BulkCtx *ppBulkCtx
    )
{
    MSTATUS status = OK;
    ubyte4 algoStatus = 0;
    ubyte4 index = 0;

    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_rc5, &algoStatus, &index);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        /* NO operation implementation. RC5 has more params than a standard block cipher */
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_RC5_CREATE(status, keyMaterial, keyLength, iv, ivLen, blockSizeBits, roundCount, padding, encrypt, ppBulkCtx);
    }

exit:
    
    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MocDeleteRC5Ctx (
    MOC_SYM(hwAccelDescr hwAccelCtx)
    BulkCtx *ctx
    )
{
    MSTATUS status = OK;
    RC5CTX_SHADOW *pCtx = NULL;

    /* return OK if no context is present */
    if (NULL == ctx || NULL == *ctx)
        goto exit;

    pCtx = (RC5CTX_SHADOW *) *ctx;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_RC5_DELETE(status, ctx);
    }

exit:
    
    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MocRC5Update (
    MOC_SYM(hwAccelDescr hwAccelCtx)
    BulkCtx pBulkCtx,
    sbyte4 encrypt,
    ubyte *pDataToProcess,
    ubyte4 dataToProcessLen,
    ubyte *pProcessedData,
    ubyte4 bufferSize,
    ubyte4 *pProcessedDataLen
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    RC5CTX_SHADOW *pCtx = NULL;

    if (NULL == pBulkCtx)
        goto exit;

    pCtx = (RC5CTX_SHADOW *) pBulkCtx;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_RC5_UPDATE(status, pBulkCtx, encrypt, pDataToProcess, dataToProcessLen, pProcessedData, bufferSize, pProcessedDataLen);
    }

exit:
    
    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MocRC5Final (
    MOC_SYM(hwAccelDescr hwAccelCtx)
    BulkCtx pBulkCtx,
    sbyte4 encrypt,
    ubyte *pDataToProcess,
    ubyte4 dataToProcessLen,
    ubyte *pProcessedData,
    ubyte4 bufferSize,
    ubyte4 *pProcessedDataLen
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    RC5CTX_SHADOW *pCtx = NULL;

    if (NULL == pBulkCtx)
        goto exit;

    pCtx = (RC5CTX_SHADOW *) pBulkCtx;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_RC5_FINAL(status, pBulkCtx, encrypt, pDataToProcess, dataToProcessLen, pProcessedData, bufferSize, pProcessedDataLen);
    }

exit:
    
    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MocReinitRC5Ctx (
    MOC_SYM(hwAccelDescr hwAccelCtx)
    BulkCtx pBulkCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    RC5CTX_SHADOW *pCtx = NULL;

    if (NULL == pBulkCtx)
        goto exit;

    pCtx = (RC5CTX_SHADOW *) pBulkCtx;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_RC5_REINIT(status, pBulkCtx);
    }

exit:
    
    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MocRC5GetIv (
    MOC_SYM(hwAccelDescr hwAccelCtx)
    BulkCtx pBulkCtx,
    ubyte *pIv,
    ubyte4 ivLen
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    RC5CTX_SHADOW *pCtx = NULL;

    if (NULL == pBulkCtx)
        goto exit;

    pCtx = (RC5CTX_SHADOW *) pBulkCtx;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_RC5_GETIV(status, pBulkCtx, pIv, ivLen);
    }

exit:
    
    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_MocRC5CloneCtx (
    MOC_SYM(hwAccelDescr hwAccelCtx)
    BulkCtx pCtx,
    BulkCtx *ppNewCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    RC5CTX_SHADOW *pRc5Ctx = NULL;
    RC5CTX_SHADOW *pNewRc5Ctx = NULL;
    MocSymCtx pNewSymCtx = NULL;

    if ((NULL == pCtx) || (NULL == ppNewCtx))
        goto exit;

    pRc5Ctx = (RC5CTX_SHADOW *)pCtx;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pRc5Ctx->enabled)
    {
        /* Clone the underlying MocSymCtx */
        status = CRYPTO_cloneMocSymCtx(pRc5Ctx->pMocSymCtx, &pNewSymCtx);
        if (OK != status)
            goto exit;

        status = DIGI_CALLOC((void **)&pNewRc5Ctx, 1, sizeof(RC5CTX_SHADOW));
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY((void *)pNewRc5Ctx, (void *)pRc5Ctx, sizeof(RC5CTX_SHADOW));
        if (OK != status)
            goto exit;

        pNewRc5Ctx->pMocSymCtx = pNewSymCtx;
        pNewSymCtx = NULL;
        *ppNewCtx = (BulkCtx)pNewRc5Ctx;
        pNewRc5Ctx = NULL;
    }
    else
    {
        MOC_RC5_CLONE(status, pCtx, ppNewCtx);
    }

exit:
    if (NULL != pNewSymCtx)
    {
        CRYPTO_freeMocSymCtx(&pNewSymCtx);
    }
    if (NULL != pNewRc5Ctx)
    {
        DIGI_FREE((void **)&pNewRc5Ctx);
    }
    return status;
}

#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_RC5__ */
