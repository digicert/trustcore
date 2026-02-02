/*
 * crypto_interface_rc5.c
 *
 * Cryptographic Interface specification for RC5 methods.
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*.
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
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_RC5__ */
