/*
 * crypto_interface_fips186.c
 *
 * Cryptographic Interface specification for FIPS186 RNG.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_FIPS186_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../common/random.h"
#include "../crypto_interface/crypto_interface_priv.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_FIPS186__

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_DIGICERT_KSRC_GENERATOR__))
#define MOC_RANDOM_KSRC(_status, _pCtx, _buffer) \
    _status = RANDOM_KSrcGenerator(_pCtx, _buffer)
#else
#define MOC_RANDOM_KSRC(_status, _pCtx, _buffer) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_FIPS186_NEW_CTX(_status, _ppCtx, _b, _pXKey, _seedLen, _pXSeed) \
    _status = RANDOM_newFIPS186Context(_ppCtx, _b, _pXKey, _seedLen, _pXSeed)
#else
#define MOC_FIPS186_NEW_CTX(_status, _ppCtx, _b, _pXKey, _seedLen, _pXSeed) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_FIPS186_DELETE_CTX(_status, _ppCtx) \
    _status = RANDOM_deleteFIPS186Context(_ppCtx)
#else
#define MOC_FIPS186_DELETE_CTX(_status, _ppCtx) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_FIPS186_NUM_GEN(_status, _pCtx, _pRetBytes, _numBytes) \
    _status = RANDOM_numberGeneratorFIPS186(_pCtx, _pRetBytes, _numBytes)
#else
#define MOC_FIPS186_NUM_GEN(_status, _pCtx, _pRetBytes, _numBytes) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_FIPS186_SEED_CTX(_status, _pCtx, _pSeed, _seedLen) \
    _status = RANDOM_seedFIPS186Context(_pCtx, _pSeed, _seedLen)
#else
#define MOC_FIPS186_SEED_CTX(_status, _pCtx, _pSeed, _seedLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

MSTATUS CRYPTO_INTERFACE_RANDOM_KSrcGenerator(
    randomContext *pRandomContext,
    ubyte buffer[40]
    )
{
    MSTATUS status;
    ubyte4 algoStatus;
    ubyte4 index;
    
    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_fips186, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_RANDOM_KSRC(status, pRandomContext, buffer);
    }
    
exit:
    
    return status;
}

MSTATUS CRYPTO_INTERFACE_RANDOM_newFIPS186Context(
    randomContext **ppRandomContext,
    ubyte b,
    const ubyte pXKey[/*b*/],
    sbyte4 seedLen,
    const ubyte pXSeed[/*seedLen*/]
    )
{
    MSTATUS status;
    ubyte4 algoStatus;
    ubyte4 index;
    
    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_fips186, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_FIPS186_NEW_CTX(status, ppRandomContext, b, pXKey, seedLen, pXSeed);
    }
    
exit:
    
    return status;
}

MSTATUS CRYPTO_INTERFACE_RANDOM_deleteFIPS186Context(
    randomContext **ppRandomContext
    )
{
    MSTATUS status;
    ubyte4 algoStatus;
    ubyte4 index;
    
    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_fips186, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_FIPS186_DELETE_CTX(status, ppRandomContext);
    }
    
exit:
    
    return status;
}

MSTATUS CRYPTO_INTERFACE_RANDOM_numberGeneratorFIPS186(
    randomContext *pRandomContext,
    ubyte *pRetRandomBytes,
    sbyte4 numRandomBytes
    )
{
    MSTATUS status;
    ubyte4 algoStatus;
    ubyte4 index;
    
    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_fips186, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_FIPS186_NUM_GEN(status, pRandomContext, pRetRandomBytes, numRandomBytes);
    }
    
exit:
    
    return status;
}

MSTATUS CRYPTO_INTERFACE_RANDOM_seedFIPS186Context (
    randomContext *pRandomCtx,
    ubyte *pSeed,
    ubyte4 seedLen
    )
{
    MSTATUS status;
    ubyte4 algoStatus;
    ubyte4 index;
    
    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_fips186, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_FIPS186_SEED_CTX(status, pRandomCtx, pSeed, seedLen);
    }
    
exit:
    
    return status;
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_FIPS186__ */
