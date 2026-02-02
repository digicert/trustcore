/*
 * crypto_interface_nist_drbg_hash.c
 *
 * Cryptographic Interface for Random Number Generation
 * via the NIST DRBG HASH.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_NIST_DRBG_HASH_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../common/random.h"
#include "../crypto/nist_drbg_hash.h"
#include "../crypto_interface/crypto_interface_priv.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_NIST_DRBG_HASH__

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_NIST_DRBG_HASH__))
#define MOC_NIST_HASH_DRBG_NEW_CTX(_status, _ppCtx, _pEntropy, _entLen, _pNonce, _nonceLen, _pPerso, _persoLen, _hashMethod, _outLen) \
    _status = NIST_HASHDRBG_newSeededContext(MOC_SYM(hwAccelCtx) _ppCtx, _pEntropy, _entLen, _pNonce, _nonceLen, _pPerso, _persoLen, _hashMethod, _outLen)
#else
#define MOC_NIST_HASH_DRBG_NEW_CTX(_status, _ppCtx, _pEntropy, _entLen, _pNonce, _nonceLen, _pPerso, _persoLen, _hashMethod, _outLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_NIST_DRBG_HASH__))
#define MOC_NIST_HASH_DRBG_DELETE(_status, _ppCtx) \
    _status = NIST_HASHDRBG_deleteContext(MOC_SYM(hwAccelCtx) _ppCtx)
#else
#define MOC_NIST_HASH_DRBG_DELETE(_status, _ppCtx) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_NIST_DRBG_HASH__))
#define MOC_NIST_HASH_DRBG_RESEED(_status, _pCtx, _pEntropy, _entLen, _pAdd, _addLen) \
    _status = NIST_HASHDRBG_reSeed(MOC_SYM(hwAccelCtx) _pCtx, _pEntropy, _entLen, _pAdd, _addLen)
#else
#define MOC_NIST_HASH_DRBG_RESEED(_status, _pCtx, _pEntropy, _entLen, _pAdd, _addLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (defined(__ENABLE_DIGICERT_NIST_DRBG_HASH__))
#define MOC_NIST_HASH_DRBG_GEN(_status, _pCtx, _pAdd, _addLen, _pOut, _outLen) \
    _status = NIST_HASHDRBG_generate(MOC_SYM(hwAccelCtx) _pCtx, _pAdd, _addLen, _pOut, _outLen)
#else
#define MOC_NIST_HASH_DRBG_GEN(_status, _pCtx, _pAdd, _addLen, _pOut, _outLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_NIST_HASHDRBG_newSeededContext(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    NIST_HASH_DRBG_Ctx **ppNewContext,
    ubyte *pEntropyInput,
    ubyte4 entropyInputLen,
    ubyte *pNonce,
    ubyte4 nonceLen,
    ubyte *pPersonalization,
    ubyte4 personalizationLen,
    DrbgHashMethod hashMethod,
    ubyte4 hashOutLenBytes)
{
    MSTATUS status;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
    ubyte4 index;
    
    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_drbg_hash, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_NIST_HASH_DRBG_NEW_CTX(status, ppNewContext, pEntropyInput, entropyInputLen, pNonce, nonceLen, pPersonalization, personalizationLen, hashMethod, hashOutLenBytes);
    }

exit:

    return status;      
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_NIST_HASHDRBG_deleteContext( 
    MOC_SYM(hwAccelDescr hwAccelCtx)
    NIST_HASH_DRBG_Ctx **ppContext)
{
    MSTATUS status = OK;

    /* OK if nothing to free */
    if (NULL == ppContext || NULL == *ppContext)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == (*ppContext)->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_NIST_HASH_DRBG_DELETE(status, ppContext);
    }

exit:

    return status;      
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_NIST_HASHDRBG_reSeed(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    NIST_HASH_DRBG_Ctx *pContext,
    ubyte *pEntropyInput,
    ubyte4 entropyInputLen,
    ubyte *pAdditionalInput,
    ubyte4 additionalInputLen)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pContext)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pContext->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_NIST_HASH_DRBG_RESEED(status, pContext, pEntropyInput, entropyInputLen, pAdditionalInput, additionalInputLen);
    }

exit:

    return status;      
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_NIST_HASHDRBG_generate(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    NIST_HASH_DRBG_Ctx *pContext,
    ubyte *pAdditionalInput,
    ubyte4 additionalInputLen,
    ubyte *pOutput,
    ubyte4 outputLenBytes)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pContext)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pContext->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_NIST_HASH_DRBG_GEN(status, pContext, pAdditionalInput, additionalInputLen, pOutput, outputLenBytes);
    }

exit:

    return status;      
}    

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_NIST_HASHDRBG_numberGenerator(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    NIST_HASH_DRBG_Ctx *pRandomContext,
    ubyte *pBuffer,
    sbyte4 bufferLen)
{
    return CRYPTO_INTERFACE_NIST_HASHDRBG_generate(MOC_SYM(hwAccelCtx) pRandomContext, NULL, 0, pBuffer, (ubyte4) bufferLen); 
}    

MOC_EXTERN sbyte4 CRYPTO_INTERFACE_NIST_HASHDRBG_rngFun(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    void *pRngFunArg,
    ubyte4 length, ubyte *pBuffer)
{
    return CRYPTO_INTERFACE_NIST_HASHDRBG_generate(MOC_SYM(hwAccelCtx) pRngFunArg, NULL, 0, pBuffer, length);
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_NIST_CTR_DRBG__ */
