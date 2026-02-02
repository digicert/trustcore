/*
 * crypto_interface_dsa.c
 *
 * Cryptographic Interface specification for DSA.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_DSA_INTERNAL__

#include "../crypto/mocasym.h"
#include "../common/initmocana.h"
#include "../common/base64.h"
#include "../crypto/ffc.h"
#include "../crypto/dsa.h"
#include "../crypto/dsa2.h"
#include "../crypto_interface/crypto_interface_priv.h"

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_DSA__))

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DSA_CREATE(_status, _ppCtx)                                       \
    _status = DSA_createKey(_ppCtx);
#else
#define MOC_DSA_CREATE(_status, _ppCtx)                                       \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DSA_FREE(_status, _ppCtx, _ppVQ)                                  \
    _status = DSA_freeKey(_ppCtx, _ppVQ);
#else
#define MOC_DSA_FREE(_status, _ppCtx, _ppVQ)                                  \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DSA_CLONE(_status, _ppNew, _pSrc)                                 \
    _status = DSA_cloneKey(MOC_DSA(hwAccelCtx) _ppNew, _pSrc);
#else
#define MOC_DSA_CLONE(_status, _ppNew, _pSrc)                                 \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DSA_COMPUTE_KEY_PAIR(_status, _pRng, _pKey, _ppVQ)                \
    _status = DSA_computeKeyPair (                                            \
        MOC_DSA(hwAccelCtx) _pRng, _pKey, _ppVQ);
#else
#define MOC_DSA_COMPUTE_KEY_PAIR(_status, _pRng, _pKey, _ppVQ)                \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DSA_MAKE_KEYBLOB(_status, _pKey, _pBlob, _pLen)                   \
    _status = DSA_makeKeyBlob(MOC_DSA(hwAccelCtx) _pKey, _pBlob, _pLen);
#else
#define MOC_DSA_MAKE_KEYBLOB(_status, _pKey, _pBlob, _pLen)                   \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DSA_EXTRACT_KEYBLOB(_status, _ppNew, _pBlob, _len)                \
    _status = DSA_extractKeyBlob(MOC_DSA(hwAccelCtx) _ppNew, _pBlob, _len);
#else
#define MOC_DSA_EXTRACT_KEYBLOB(_status, _ppNew, _pBlob, _len)                \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DSA_EQUAL_KEY(_status, _pKey1, _pKey2, _pRes)                     \
    _status = DSA_equalKey(MOC_DSA(hwAccelCtx) _pKey1, _pKey2, _pRes);
#else
#define MOC_DSA_EQUAL_KEY(_status, _pKey1, _pKey2, _pRes)                     \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DSA_GET_CIPHERTEXT_LEN(_status, _pKey, _pLen)                     \
    _status = DSA_getCipherTextLength(MOC_DSA(hwAccelCtx) _pKey, _pLen);
#else
#define MOC_DSA_GET_CIPHERTEXT_LEN(_status, _pKey, _pLen)                     \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DSA_GET_SIG_LEN(_status, _pKey, _pLen)                            \
    _status = DSA_getSignatureLength(MOC_DSA(hwAccelCtx) _pKey, _pLen);
#else
#define MOC_DSA_GET_SIG_LEN(_status, _pKey, _pLen)                            \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DSA_GENERATE_PQ(_status, _pRng, _pKey, _L, _N, _hType, _pC, _pS, _ppVQ) \
    _status = generatePQ (                                                          \
        MOC_DSA(hwAccelCtx) _pRng, _pKey, _L, _N, _hType, _pC, _pS, _ppVQ);
#else
#define MOC_DSA_GENERATE_PQ(_status, _pRng, _pKey, _L, _N, _hType, _pC, _pS, _ppVQ) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DSA_GENKEY(_status, _pRng, _pKey, _size, _ppVQ)                   \
    _status = DSA_generateKeyAux (                                            \
        MOC_DSA(hwAccelCtx) _pRng, _pKey, _size, _ppVQ);
#else
#define MOC_DSA_GENKEY(_status, _pRng, _pKey, _size, _ppVQ)                   \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DSA_GENKEY2(_status, _pRng, _pKey, _size, _qSize, _hType, _ppVQ)  \
    _status = DSA_generateKeyAux2 (                                           \
        MOC_DSA(hwAccelCtx) _pRng, _pKey, _size, _qSize, _hType, _ppVQ);
#else
#define MOC_DSA_GENKEY2(_status, _pRng, _pKey, _size, _qSize, _hType, _ppVQ)  \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DSA_COMPUTE_SIG(_status, _pRng, _pKey, _pM, _mLen, _pV, _ppR,     \
                            _pRLen, _ppS, _pSLen, _ppVQ)                      \
    _status = DSA_computeSignatureAux (                                       \
        MOC_DSA(hwAccelCtx) _pRng, _pKey, _pM, _mLen, _pV, _ppR, \
        _pRLen, _ppS, _pSLen, _ppVQ);
#else
#define MOC_DSA_COMPUTE_SIG(_status, _pRng, _pKey, _pM, _mLen, _pV, _ppR,     \
                            _pRLen, _ppS, _pSLen, _ppVQ)                      \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DSA_VERIFY_SIG(_status, _pKey, _pM, _mLen, _pR, _rLen, _pS, _sLen, \
                           _pIsGood, _ppVQ)                                    \
    _status = DSA_verifySignatureAux (                                         \
        MOC_DSA(hwAccelCtx) _pKey, _pM, _mLen, _pR, _rLen, _pS,   \
        _sLen, _pIsGood, _ppVQ);
#else
#define MOC_DSA_VERIFY_SIG(_status, _pKey, _pM, _mLen, _pR, _rLen, _pS, _sLen, \
                           _pIsGood, _ppVQ)                                    \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DSA_SET_KEY_PARAMS(_status, _pKey, _pTempl)                       \
    _status = DSA_setKeyParametersAux (                                       \
        MOC_DSA(hwAccelCtx) _pKey, _pTempl);
#else
#define MOC_DSA_SET_KEY_PARAMS(_status, _pKey, _pTempl)                       \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DSA_GET_KEY_PARAMS(_status, _pKey, _pTempl, _type)                 \
    _status = DSA_getKeyParametersAlloc(MOC_DSA(hwAccelCtx) _pKey, _pTempl, _type);
#else
#define MOC_DSA_GET_KEY_PARAMS(_status, _pKey, _pTempl, _type)                 \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DSA_FREE_KEY_TEMPLATE(_status, _pKey, _pTempl)                     \
    _status = DSA_freeKeyTemplate(_pKey, _pTempl);
#else
#define MOC_DSA_FREE_KEY_TEMPLATE(_status, _pKey, _pTempl)                     \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DSA_RAND_G(_status, _pKey, _pRandomContext, _ppH, _pHLen, _ppVlongQueue) \
    _status = DSA_generateRandomGAux(MOC_DSA(hwAccelCtx) _pKey, _pRandomContext, _ppH, _pHLen, _ppVlongQueue);
#else
#define MOC_DSA_RAND_G(_status, _pKey, _pRandomContext, _ppH, _pHLen, _ppVlongQueue) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DSA2_SIGN(_status, _pRngFun, _pRngCtx, _pKey, _pM, _mLen, _ppR, _pRLen, _ppS, _pSLen, _ppVQ) \
    _status = DSA_computeSignature2Aux(MOC_DSA(hwAccelCtx) _pRngFun, _pRngCtx, _pKey, _pM, _mLen, _ppR, _pRLen, _ppS, _pSLen, _ppVQ);
#else
#define MOC_DSA2_SIGN(_status, _pRngFun, _pRngCtx, _pKey, _pM, _mLen, _ppR, _pRLen, _ppS, _pSLen, _ppVQ) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_DSA2_VERIFY(_status, _pKey, _pM, _mLen, _pR, _rLen, _pS, _sLen, _pIsGood, _ppVQ) \
    _status = DSA_verifySignature2Aux (MOC_DSA(hwAccelCtx) _pKey, _pM, _mLen, _pR, _rLen, _pS, _sLen, _pIsGood, _ppVQ);
#else
#define MOC_DSA2_VERIFY(_status, _pKey, _pM, _mLen, _pR, _rLen, _pS, _sLen, _pIsGood, _ppVQ) \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_createKey (
    DSAKey **pp_dsaDescr
    )
{
    MSTATUS status;
    ubyte4 algoStatus, index;

    status = CRYPTO_INTERFACE_checkAsymAlgoStatus(moc_alg_dsa, &algoStatus, &index);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_DSA_CREATE(status, pp_dsaDescr)
    }

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_freeKey (
    DSAKey **pp_dsaDescr,
    vlong **ppVlongQueue
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if ( (NULL == pp_dsaDescr) || (NULL == (*pp_dsaDescr)) )
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == (*pp_dsaDescr)->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_DSA_FREE(status, pp_dsaDescr, ppVlongQueue)
    }

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_cloneKey (
    MOC_DSA(hwAccelDescr hwAccelCtx)
    DSAKey** ppNew,
    const DSAKey* pSrc
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pSrc)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pSrc->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_DSA_CLONE(status, ppNew, pSrc)
    }

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_computeKeyPair(
    MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
    DSAKey *p_dsaDescr,
    vlong **ppVlongQueue
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == p_dsaDescr)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == p_dsaDescr->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_DSA_COMPUTE_KEY_PAIR (
            status, pFipsRngCtx, p_dsaDescr, ppVlongQueue)
    }

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_makeKeyBlob (
    MOC_DSA(hwAccelDescr hwAccelCtx)
    const DSAKey *p_dsaDescr,
    ubyte *pKeyBlob,
    ubyte4 *pRetKeyBlobLength
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == p_dsaDescr)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == p_dsaDescr->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_DSA_MAKE_KEYBLOB (
            status, p_dsaDescr, pKeyBlob, pRetKeyBlobLength)
    }

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_extractKeyBlob (
    MOC_DSA(hwAccelDescr hwAccelCtx)
    DSAKey **pp_RetNewDsaDescr,
    const ubyte *pKeyBlob,
    ubyte4 keyBlobLength
    )
{
    MSTATUS status;
    ubyte4 algoStatus, index;

    status = CRYPTO_INTERFACE_checkAsymAlgoStatus(moc_alg_dsa, &algoStatus, &index);
    if (OK != status)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_DSA_EXTRACT_KEYBLOB(status, pp_RetNewDsaDescr, pKeyBlob, keyBlobLength)
    }

exit:
    return status;
}
/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_equalKey (
    MOC_DSA(hwAccelDescr hwAccelCtx)
    const DSAKey *pKey1,
    const DSAKey *pKey2,
    byteBoolean *pResult
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pKey1)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey1->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_DSA_EQUAL_KEY(status, pKey1, pKey2, pResult)
    }

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_getCipherTextLength (
    MOC_DSA(hwAccelDescr hwAccelCtx)
    const DSAKey *pKey,
    sbyte4* cipherTextLen
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pKey)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_DSA_GET_CIPHERTEXT_LEN(status, pKey, cipherTextLen)
    }

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_getSignatureLength (
    MOC_DSA(hwAccelDescr hwAccelCtx)
    DSAKey *pKey,
    ubyte4 *pSigLen
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pKey)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_DSA_GET_SIG_LEN(status, pKey, pSigLen)
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_generatePQ (
    MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
    DSAKey *p_dsaDescr,
    ubyte4 L,
    ubyte4 Nin,
    DSAHashType hashType,
    ubyte4 *pRetC,
    ubyte *pRetSeed,
    vlong **ppVlongQueue
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == p_dsaDescr)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == p_dsaDescr->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_DSA_GENERATE_PQ(
            status, pFipsRngCtx, p_dsaDescr, L, Nin, hashType, pRetC,
            pRetSeed, ppVlongQueue)
    }

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_generateKeyAux (
    MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
    DSAKey *p_dsaDescr,
    ubyte4 keySize,
    vlong **ppVlongQueue
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == p_dsaDescr)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == p_dsaDescr->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_DSA_GENKEY(status, pFipsRngCtx, p_dsaDescr, keySize, ppVlongQueue)
    }

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_generateKeyAux2 (
    MOC_DSA(hwAccelDescr hwAccelCtx) randomContext* pFipsRngCtx,
    DSAKey *p_dsaDescr,
    ubyte4 keySize,
    ubyte4 qSize,
    DSAHashType hashType,
    vlong **ppVlongQueue
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == p_dsaDescr)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == p_dsaDescr->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_DSA_GENKEY2 (status, pFipsRngCtx, p_dsaDescr, keySize, qSize, hashType, ppVlongQueue)
    }

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_computeSignatureAux (
    MOC_DSA(hwAccelDescr hwAccelCtx)
    randomContext *pRngCtx,
    DSAKey *pKey,
    ubyte *pM,
    ubyte4 mLen,
    intBoolean *pVerify,
    ubyte **ppR,
    ubyte4 *pRLen,
    ubyte **ppS,
    ubyte4 *pSLen,
    vlong **ppVlongQueue
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pKey)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_DSA_COMPUTE_SIG (
            status, pRngCtx, pKey, pM, mLen, pVerify, ppR, pRLen, ppS, pSLen, ppVlongQueue)
    }

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_verifySignatureAux (
    MOC_DSA(hwAccelDescr hwAccelCtx)
    DSAKey *pKey,
    ubyte *pM,
    ubyte4 mLen,
    ubyte *pR,
    ubyte4 rLen,
    ubyte *pS,
    ubyte4 sLen,
    intBoolean *pIsGoodSig,
    vlong **ppVlongQueue
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pKey)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_DSA_VERIFY_SIG (
            status, pKey, pM, mLen, pR, rLen, pS, sLen, pIsGoodSig, ppVlongQueue)
    }

exit:
    return status;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_setKeyParametersAux (
    MOC_DSA(hwAccelDescr hwAccelCtx)
    DSAKey *pKey,
    MDsaKeyTemplatePtr pTemplate
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pKey)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_DSA_SET_KEY_PARAMS(status, pKey, pTemplate)
    }

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_getKeyParametersAlloc (
    MOC_DSA(hwAccelDescr hwAccelCtx)
    DSAKey *pKey,
    MDsaKeyTemplatePtr pTemplate,
    ubyte keyType
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pKey)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_DSA_GET_KEY_PARAMS(status, pKey, pTemplate, keyType)
    }

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_freeKeyTemplate (
    DSAKey *pKey,
    MDsaKeyTemplatePtr pTemplate
    )
{
    MSTATUS status;

    if ((NULL != pKey) && CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_DSA_FREE_KEY_TEMPLATE(status, pKey, pTemplate)
    }

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_generateRandomGAux (
    MOC_DSA(hwAccelDescr hwAccelCtx)
    DSAKey *pKey,
    randomContext *pRandomContext,
    ubyte **ppH,
    ubyte4 *pHLen,
    vlong **ppVlongQueue
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    
    if (NULL == pKey)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_DSA_RAND_G(status, pKey, pRandomContext, ppH, pHLen, ppVlongQueue)
    }
    
exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_computeSignature2Aux(
    MOC_DSA(hwAccelDescr hwAccelCtx)
    RNGFun rngfun,
    void *pRngArg,
    DSAKey *pKey,
    ubyte *pM,
    ubyte4 mLen,
    ubyte **ppR,
    ubyte4 *pRLen,
    ubyte **ppS,
    ubyte4 *pSLen,
    vlong **ppVlongQueue
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    
    if (NULL == pKey)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_DSA2_SIGN(status, rngfun, pRngArg, pKey, pM, mLen, ppR, pRLen, ppS, pSLen, ppVlongQueue)
    }
    
exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_verifySignature2Aux(
    MOC_DSA(hwAccelDescr hwAccelCtx)
    DSAKey *pKey,
    ubyte *pM,
    ubyte4 mLen,
    ubyte *pR,
    ubyte4 rLen,
    ubyte *pS,
    ubyte4 sLen,
    intBoolean *pIsGoodSignature,
    vlong **ppVlongQueue
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    
    if (NULL == pKey)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
        MOC_DSA2_VERIFY(status, pKey, pM, mLen, pR, rLen, pS, sLen, pIsGoodSignature, ppVlongQueue)
    }
    
exit:
    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_verifyPublicKey(
    MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *pKey,
    intBoolean *pIsValid,
    vlong **ppVlongQueue)
{
    MSTATUS status = ERR_NULL_POINTER;
    
    if (NULL == pKey || NULL == pIsValid)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
        /* We don't have a passthrough until we're able to edit the FIPS layer. Call FFC code directly.
           Validate G does the same ops as public key validation */
        status = FFC_verifyG(MOC_FFC(hwAccelCtx) DSA_P(pKey), DSA_Q(pKey), 
                             DSA_Y(pKey), pIsValid, ppVlongQueue);
#else
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif
    }

exit:

    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_verifyKeyPair(
    MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *pKey,
    intBoolean *pIsValid,
    vlong **ppVlongQueue)
{
    MSTATUS status = ERR_NULL_POINTER;
    
    if (NULL == pKey || NULL == pIsValid)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
        vlong *pPubCmp = NULL;
        sbyte4 compare = -1;

        *pIsValid = FALSE;

        /* we must have a private and public key */
        if (NULL == DSA_P(pKey) || NULL == DSA_G(pKey) ||
            NULL == DSA_X(pKey) || NULL == DSA_Y(pKey))
            return ERR_INVALID_INPUT;

        status = VLONG_modexp(MOC_MOD(hwAccelCtx) DSA_G(pKey), DSA_X(pKey), DSA_P(pKey), &pPubCmp, ppVlongQueue);
        if (OK != status)
            goto exit;

        compare = VLONG_compareSignedVlongs(DSA_Y(pKey), pPubCmp);
        
        /* free in any case */
        status = VLONG_freeVlong(&pPubCmp, ppVlongQueue);
        if (0 != compare || OK != status)
        {
          *pIsValid = FALSE;
        }
        else
        {
          *pIsValid = TRUE;
        }
#else
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif
    }

exit:

    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DSA_verifyPrivateKey(
    MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey *pKey,
    intBoolean *pIsValid,
    vlong **ppVlongQueue)
{
    MSTATUS status = ERR_NULL_POINTER;
    
    if (NULL == pKey || NULL == pIsValid)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pKey->enabled)
    {
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
    }
    else
    {
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
        vlong *pQminus1 = NULL;
        sbyte4 compare = -1;
        sbyte4 bitLen = 0;

        *pIsValid = FALSE;

        /* we must have a private key */
        if (NULL == DSA_X(pKey))
            return ERR_INVALID_INPUT;

        /* compare with q if it's there, otherwise check the bitlength against P */
        if (NULL != DSA_Q(pKey))
        {
            /* make q-1 */
            status = VLONG_makeVlongFromVlong(DSA_Q(pKey), &pQminus1, ppVlongQueue);
            if (OK != status)
                goto exit;

            status = VLONG_decrement(pQminus1, ppVlongQueue);
            if (OK != status)
            {
                (void) VLONG_freeVlong(&pQminus1, ppVlongQueue);
                goto exit;
            }
    
            compare = VLONG_compareSignedVlongs(pQminus1, DSA_X(pKey));
            status = VLONG_freeVlong(&pQminus1, ppVlongQueue);
        }
        else if (NULL != DSA_P(pKey))
        {
            bitLen = (sbyte4) VLONG_bitLength(DSA_P(pKey));
            
            if ((sbyte4) VLONG_bitLength(DSA_X(pKey)) <= bitLen - 1)
                compare = 1;

            status = OK;
        }
        else
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        
        bitLen = (sbyte4) VLONG_bitLength(DSA_X(pKey));

        if (OK != status || compare <= 0 || bitLen <= 1)
        {
          *pIsValid = FALSE;
        }
        else
        {
          *pIsValid = TRUE;
        }
#else
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

#endif /* if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_DSA__)) */
