/*
 * crypto_interface_nist_ctr_drbg.c
 *
 * Cryptographic Interface for Random Number Generation
 * via the NIST CTR DRBG.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_NIST_CTR_DRBG_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../common/random.h"
#include "../crypto/sha1.h"
#include "../crypto/aes.h"
#include "../crypto/des.h"
#include "../crypto/three_des.h"
#include "../crypto/nist_rng_types.h"
#include "../crypto/nist_rng.h"
#include "../crypto/nist_rng_ex.h"
#include "../crypto_interface/crypto_interface_priv.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_NIST_CTR_DRBG__))

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_NIST_CTR_DRBG_NEW_CTX(_status, _ppCtx, _pEntropy, _keyLen, _outLen, _pPerso, _persoLen) \
    _status = NIST_CTRDRBG_newContext(MOC_SYM(hwAccelCtx) _ppCtx, _pEntropy, _keyLen, _outLen, _pPerso, _persoLen)
#else
#define MOC_NIST_CTR_DRBG_NEW_CTX(_status, _ppCtx, _pEntropy, _keyLen, _outLen, _pPerso, _persoLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_NIST_CTR_DRBG_NEW_CTX_DF(_status, _ppCtx, _keyLen, _outLen, _pEntropy, _entropyLen, _pNonce, _nonceLen, _pPerso, _persoLen) \
    _status = NIST_CTRDRBG_newDFContext(MOC_SYM(hwAccelCtx) _ppCtx, _keyLen, _outLen, _pEntropy, _entropyLen, _pNonce, _nonceLen, _pPerso, _persoLen)
#else
#define MOC_NIST_CTR_DRBG_NEW_CTX_DF(_status, _ppCtx, _keyLen, _outLen, _pEntropy, _entropyLen, _pNonce, _nonceLen, _pPerso, _persoLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_NIST_CTR_DRBG_DELETE(_status, _ppCtx)                              \
    _status = NIST_CTRDRBG_deleteContext(MOC_SYM(hwAccelCtx) _ppCtx)
#else
#define MOC_NIST_CTR_DRBG_DELETE(_status, _ppCtx)                              \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_NIST_CTR_DRBG_RESEED(_status, _pCtx, _pEntropy, _entropyLen, _pAddInput, _addInLen) \
    _status = NIST_CTRDRBG_reseed(MOC_SYM(hwAccelCtx) _pCtx, _pEntropy, _entropyLen, _pAddInput, _addInLen)
#else
#define MOC_NIST_CTR_DRBG_RESEED(_status, _ppCtx, _pEntropy, _entropyLen, _pAddInput, _addInLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_NIST_CTR_DRBG_GENERATE(_status, _pCtx, _pAddInput, _addInLen, _pOut, outLenBits) \
    _status = NIST_CTRDRBG_generate(MOC_SYM(hwAccelCtx) _pCtx, _pAddInput, _addInLen, _pOut, outLenBits)
#else
#define MOC_NIST_CTR_DRBG_GENERATE(_status, _pCtx, _pAddInput, _addInLen, _pOut, outLenBits) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_NIST_CTR_DRBG_GEN_SECRET(_status, _pCtx, _pAddInput, _addInputLen, _pSecret, _secretLen) \
    _status = NIST_CTRDRBG_generateSecret(MOC_SYM(hwAccelCtx) _pCtx, _pAddInput, _addInputLen, _pSecret, _secretLen)
#else
#define MOC_NIST_CTR_DRBG_GEN_SECRET(_status, _pCtx, _pAddInput, _addInputLen, _pSecret, _secretLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
#define MOC_NIST_CTR_DRBG_SET_SECRET(_status, _pCtx, _pAddInput, _addInputLen, _pSecret, _secretLen) \
    _status = NIST_CTRDRBG_setStateFromSecret(MOC_SYM(hwAccelCtx) _pCtx, _pAddInput, _addInputLen, _pSecret, _secretLen)
#else
#define MOC_NIST_CTR_DRBG_SET_SECRET(_status, _pCtx, _pAddInput, _addInputLen, _pSecret, _secretLen) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*----------------------------------------------------------------------------*/

/* callback function used just to copy the entropy provided via pCtx */
static MSTATUS getEntropyFunc(void *pCtx, ubyte *pBuffer, ubyte4 bufferLen)
{
    return DIGI_MEMCPY(pBuffer, (ubyte *) pCtx, bufferLen);
}


static MSTATUS CRYPTO_INTERFACE_NIST_CTRDRBG_generalNewCtx(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    randomContext **ppNewContext,
    ubyte4 keyLenBytes,
    ubyte *pEntropyInput,
    ubyte4 entropyInputLen,
    ubyte *pNonce,
    ubyte4 nonceLen,
    ubyte *pPersonalization,
    ubyte4 personalizationLen,
    ubyte4 index,
    ubyte4 useDf
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 seedType;
    MCtrDrbgAesSeedInfo seedInfo = {0};
    MocCtx pMocCtx = NULL;
    MSymOperator SymOperator = NULL;
    void *pOperatorInfo = NULL;
    randomContext *pNewRandCtx = NULL;
    ubyte *pCustom = NULL;  /* for the nonce || personalization string */
    ubyte4 customLen = 0;
    byteBoolean customAllocated = FALSE;

    if (NULL == ppNewContext)
        goto exit;
    
    /* Get the mocctx from the crypto interface core */
    status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
    if (OK != status)
        goto exit;
    
    /* Get the associated operator from the index */
    status = CRYPTO_getSymOperatorAndInfoFromIndex (index, pMocCtx, &SymOperator, &pOperatorInfo);
    if (OK != status)
        goto exit;
    
    /* Create a new random context */
    status = CRYPTO_createMocSymRandom (SymOperator, pOperatorInfo, pMocCtx, &pNewRandCtx);
    if (OK != status)
        goto exit;
    
    /* Determine how this operator gets entropy */
    status = CRYPTO_getSeedType(pNewRandCtx, &seedType);
    if (OK != status)
        goto exit;
    
    /* Does this object support seeding? */
    status = ERR_RAND_SEED_METHOD_NOT_SUPPORTED;
    if (MOC_SYM_RAND_SEED_TYPE_NONE == seedType)
        goto exit;
    
    /* almost ready to populate seedInfo, do need to handle nonce and personalization */
    if (NULL != pNonce && nonceLen)
    {
        if (NULL != pPersonalization && personalizationLen)
        {
            customLen = nonceLen + personalizationLen;
            
            status = DIGI_MALLOC((void **) &pCustom, customLen);
            if (OK != status)
                goto exit;
            
            customAllocated = TRUE;
            
            status = DIGI_MEMCPY(pCustom, pNonce, nonceLen);
            if (OK != status)
                goto exit;
            
            status = DIGI_MEMCPY(pCustom + nonceLen, pPersonalization, personalizationLen);
            if (OK != status)
                goto exit;
        }
        else
        {
            pCustom = pNonce;
            customLen = nonceLen;
        }
    }
    else if (NULL != pPersonalization && personalizationLen)
    {
        pCustom = pPersonalization;
        customLen = personalizationLen;
    }
    
    /* now populate seedInfo */
    seedInfo.keyLenBytes = keyLenBytes;
    seedInfo.entropyCollectLen = entropyInputLen;
    seedInfo.useDf = useDf;
    seedInfo.pCustom = pCustom;
    seedInfo.customLen = customLen;

    /*
     if the operator wants a callback we use our getEntropyFunc
     defined above with the seed as the entropy context.
     */
    if (MOC_SYM_RAND_SEED_TYPE_CALLBACK == seedType)
    {
        seedInfo.EntropyFunc = getEntropyFunc;
        seedInfo.pEntropyCtx = (void *) pEntropyInput;
    }
    
    /* we leave it to the operator to validate the seedInfo params */
    status = CRYPTO_seedRandomContext (pNewRandCtx, (void *)&seedInfo, pEntropyInput, entropyInputLen);
    if (OK != status)
        goto exit;
    
    *ppNewContext = pNewRandCtx;
    pNewRandCtx = NULL;
    
exit:
    
    if (NULL != pNewRandCtx)
       CRYPTO_freeMocSymRandom(&pNewRandCtx); /* here on error only, no need to check return */
    
    if (customAllocated && NULL != pCustom)
    {
        MSTATUS fstatus = DIGI_FREE((void **) &pCustom);
        if (OK == status)
            status = fstatus;
    }
    
    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_NIST_CTRDRBG_newContext(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    randomContext **ppNewContext,
    const ubyte *pEntropyInput,
    ubyte4 keyLenBytes,
    ubyte4 outLenBytes,
    const ubyte *pPersonalization,
    ubyte4 personalizationLen
    )
{
    MSTATUS status;
    ubyte4 algoStatus;
    ubyte4 index;
    
    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_ctr_drbg_aes, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = CRYPTO_INTERFACE_NIST_CTRDRBG_generalNewCtx(MOC_SYM(hwAccelCtx) ppNewContext, keyLenBytes, (ubyte *) pEntropyInput,
                                                             keyLenBytes + outLenBytes, NULL, 0, (ubyte *) pPersonalization, personalizationLen, index, 0);
    }
    else
    {
        MOC_NIST_CTR_DRBG_NEW_CTX(status, ppNewContext, pEntropyInput, keyLenBytes, outLenBytes, pPersonalization, personalizationLen);
    }
    
exit:

    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_NIST_CTRDRBG_newDFContext(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    randomContext **ppNewContext,
    ubyte4 keyLenBytes,
    ubyte4 outLenBytes,
    const ubyte *pEntropyInput,
    ubyte4 entropyInputLen,
    const ubyte *pNonce,
    ubyte4 nonceLen,
    const ubyte *pPersonalization,
    ubyte4 personalizationLen
    )
{
    MSTATUS status;
    ubyte4 algoStatus;
    ubyte4 index;
   
    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_ctr_drbg_aes, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = CRYPTO_INTERFACE_NIST_CTRDRBG_generalNewCtx(MOC_SYM(hwAccelCtx) ppNewContext, keyLenBytes, (ubyte *) pEntropyInput,
                                                             entropyInputLen, (ubyte *) pNonce, nonceLen, (ubyte *) pPersonalization, personalizationLen, index, 1);
    }
    else
    {
        MOC_NIST_CTR_DRBG_NEW_CTX_DF(status, ppNewContext, keyLenBytes, outLenBytes, pEntropyInput, entropyInputLen, pNonce, nonceLen, pPersonalization, personalizationLen);
    }
    
exit:
    
    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_NIST_CTRDRBG_deleteContext(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    randomContext **ppContext
    )
{
    MSTATUS status;
    ubyte4 algoStatus;
    ubyte4 index;
    
    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_ctr_drbg_aes, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = CRYPTO_freeMocSymRandom(ppContext);
    }
    else
    {
        MOC_NIST_CTR_DRBG_DELETE(status, ppContext);
    }
    
exit:
    
    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_NIST_CTRDRBG_reseed(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    randomContext *pContext,
    const ubyte *pEntropyInput,
    ubyte4 entropyInputLen,
    const ubyte *pAdditionalInput,
    ubyte4 additionalInputLen
    )
{
    MSTATUS status;
    ubyte4 algoStatus;
    ubyte4 index;
    
    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_ctr_drbg_aes, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = CRYPTO_reseedRandomContext(pContext, (ubyte *) pEntropyInput, entropyInputLen, (ubyte *) pAdditionalInput, additionalInputLen);
    }
    else
    {
        MOC_NIST_CTR_DRBG_RESEED(status, pContext, pEntropyInput, entropyInputLen, pAdditionalInput, additionalInputLen);
    }
    
exit:
    
    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_NIST_CTRDRBG_generate(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    randomContext *pContext,
    const ubyte *pAdditionalInput,
    ubyte4 additionalInputLen,
    ubyte *pOutput,
    ubyte4 outputLenBits
    )
{
    MSTATUS status;
    ubyte4 algoStatus;
    ubyte4 index;
    
    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_ctr_drbg_aes, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = RANDOM_numberGeneratorAdd(pContext, pOutput, (outputLenBits + 7)/8, (ubyte *) pAdditionalInput, additionalInputLen);
    }
    else
    {
        MOC_NIST_CTR_DRBG_GENERATE(status, pContext, pAdditionalInput, additionalInputLen, pOutput, outputLenBits);
    }
    
exit:
    
    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_NIST_CTRDRBG_numberGenerator(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    randomContext *pContext,
    ubyte *pOutput,
    ubyte4 outputLenBytes
    )
{
    return CRYPTO_INTERFACE_NIST_CTRDRBG_generate(
        MOC_SYM(hwAccelCtx) pContext, NULL, 0, pOutput,
        outputLenBytes * 8);
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_NIST_CTRDRBG_generateSecret(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    randomContext* pContext,
    ubyte *pAdditionalInput,
    ubyte4 additionalInputLen,
    ubyte *pSecret,
    ubyte4 secretLen
    )
{
    MSTATUS status;
    ubyte4 algoStatus;
    ubyte4 index;
    MSymOperatorData operatorData = {0};
    
    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_ctr_drbg_aes, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_NULL_POINTER;
        RandomCtxWrapper *pWrapper = (RandomCtxWrapper *) pContext;
        MocRandCtx *pMocRandCtx = NULL;
        MocCtx pMocCtx = NULL;
        
        if (NULL == pWrapper)
            goto exit;
        
        status = ERR_RAND_INVALID_CONTEXT;
        if (!IS_MOC_RAND(pWrapper))
            goto exit;
        
        status = ERR_NULL_POINTER;
        pMocRandCtx = GET_MOC_RAND_CTX(pWrapper);
        if (NULL == pMocRandCtx)
            goto exit;
        
        /* Get the mocctx from the crypto interface core */
        status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
        if (OK != status)
            goto exit;
        
        /* Get the state of the ctr drbg, this allocates the buffer in operatorData */
        status = CRYPTO_getSymOperatorData((MocSymCtx) pMocRandCtx->pMocSymObj, pMocCtx, &operatorData);
        if (OK != status)
            goto exit;
        
        status = ERR_INVALID_ARG;
        if (secretLen < operatorData.length)
            goto exit;
        
        status = DIGI_MEMCPY(pSecret, operatorData.pData, operatorData.length);
        if (OK != status)
            goto exit;
        
        if (secretLen > operatorData.length)
            status = RANDOM_numberGeneratorAdd(pContext, pSecret + operatorData.length, secretLen - operatorData.length, (ubyte *) pAdditionalInput, additionalInputLen);
    }
    else
    {
        MOC_NIST_CTR_DRBG_GEN_SECRET(status, pContext, pAdditionalInput, additionalInputLen, pSecret, secretLen);
    }
    
exit:
    
    if (NULL != operatorData.pData)
    {
        MSTATUS fstatus = DIGI_FREE((void **) &operatorData.pData);
        if (OK == status)
            status = fstatus;
    }
    
    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_NIST_CTRDRBG_setStateFromSecret(
    MOC_SYM(hwAccelDescr hwAccelCtx)
    randomContext* pContext,
    ubyte *pAdditionalInput,
    ubyte4 additionalInputLen,
    ubyte *pSecret,
    ubyte4 secretLen
    )
{
    MSTATUS status;
    ubyte4 algoStatus;
    ubyte4 index;
    ubyte *pRecoveredGeneration = NULL;
    
    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_ctr_drbg_aes, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_NULL_POINTER;
        RandomCtxWrapper *pWrapper = (RandomCtxWrapper *) pContext;
        MocRandCtx *pMocRandCtx = NULL;
        MocCtx pMocCtx = NULL;
        MSymOperatorData operatorData = {0};
        
        if (NULL == pWrapper)
            goto exit;
        
        status = ERR_RAND_INVALID_CONTEXT;
        if (!IS_MOC_RAND(pWrapper))
            goto exit;
        
        status = ERR_NULL_POINTER;
        pMocRandCtx = GET_MOC_RAND_CTX(pWrapper);
        if (NULL == pMocRandCtx)
            goto exit;
        
        /* Get the mocctx from the crypto interface core */
        status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
        if (OK != status)
            goto exit;
        
        operatorData.pData = pSecret;
        
        /* CRYPTO_updateSymOperatorData will set the length in the operatorData object */
        status = CRYPTO_updateSymOperatorData((MocSymCtx) pMocRandCtx->pMocSymObj, pMocCtx, (void *) &operatorData);
        if (OK != status)
            goto exit;
        
        status = ERR_INVALID_ARG;
        if (secretLen < operatorData.length)
            goto exit;
        
        status = OK;
        if (secretLen > operatorData.length) /* validate the random data correctly comes from the state */
        {
            intBoolean differ;
            
            status = DIGI_MALLOC((void **) &pRecoveredGeneration, secretLen - operatorData.length);
            if (OK != status)
                goto exit;
            
            status = RANDOM_numberGeneratorAdd(pContext, pRecoveredGeneration, secretLen - operatorData.length, (ubyte *) pAdditionalInput, additionalInputLen);
            if (OK != status)
                goto exit;
            
            DIGI_CTIME_MATCH((void *) pRecoveredGeneration, (void *) (pSecret + operatorData.length), secretLen - operatorData.length, &differ);
            /* ok to ignore DIGI_CTIME_MATCH return code */
            
            if (differ)
                status = ERR_FALSE;
        }
    }
    else
    {
        MOC_NIST_CTR_DRBG_SET_SECRET(status, pContext, pAdditionalInput, additionalInputLen, pSecret, secretLen);
    }
    
exit:
    
    if (NULL != pRecoveredGeneration)
    {
        MSTATUS fstatus = DIGI_FREE((void **) &pRecoveredGeneration);
        if (OK == status)
            status = fstatus;
    }
    
    return status;
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_NIST_CTR_DRBG__ */
