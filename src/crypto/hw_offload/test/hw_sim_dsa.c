/**
 * @file hw_sim_dsa.c
 *
 * @brief DSA test for hw simulator
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

#if defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_DSA__) \
    && defined(__ENABLE_DIGICERT_DSA__)

/* redefine existing methods to simulate that they are using a hw implementation */

#define DSA_generateKey             HW_DSA_generateKey
#define DSA_generateKeyEx           HW_DSA_generateKeyEx
#define DSA_computeKeyPair          HW_DSA_computeKeyPair
#define DSA_computeKeyPairEx        HW_DSA_computeKeyPairEx
#define DSA_getCipherTextLength     HW_DSA_getCipherTextLength
#define DSA_getSignatureLength      HW_DSA_getSignatureLength
#define DSA_computeSignatureEx      HW_DSA_computeSignatureEx
#define DSA_verifySignature         HW_DSA_verifySignature
#define DSA_verifyKeysEx            HW_DSA_verifyKeysEx
#define DSA_verifyPQ                HW_DSA_verifyPQ
#define DSA_makeKeyBlob             HW_DSA_makeKeyBlob
#define DSA_setAllKeyParameters     HW_DSA_setAllKeyParameters
#define DSA_setPublicKeyParameters  HW_DSA_setPublicKeyParameters
#define DSA_setKeyParameters        HW_DSA_setKeyParameters
#define DSA_generateRandomGAux      HW_DSA_generateRandomGAux
#define DSA_generateKeyAux          HW_DSA_generateKeyAux
#define DSA_generateKeyAux2         HW_DSA_generateKeyAux2
#define DSA_computeSignatureAux     HW_DSA_computeSignatureAux
#define DSA_verifySignatureAux      HW_DSA_verifySignatureAux
#define DSA_setKeyParametersAux     HW_DSA_setKeyParametersAux
#define DSA_getKeyParametersAlloc   HW_DSA_getKeyParametersAlloc
#define DSA_computeSignature2       HW_DSA_computeSignature2
#define DSA_verifySignature2        HW_DSA_verifySignature2
#define DSA_computeSignature2Aux    HW_DSA_computeSignature2Aux
#define DSA_verifySignature2Aux     HW_DSA_verifySignature2Aux
#define DSA_equalKey                HW_DSA_equalKey
#define DSA_cloneKey                HW_DSA_cloneKey

#include "../../dsa.c"
#include "../../dsa2.c"

#include "hw_sim_test.h"

/* undefine the macros so now we can give real definitions of these methdos */
#undef DSA_generateKey
#undef DSA_generateKeyEx
#undef DSA_computeKeyPair
#undef DSA_computeKeyPairEx
#undef DSA_getCipherTextLength
#undef DSA_getSignatureLength
#undef DSA_computeSignatureEx
#undef DSA_verifySignature
#undef DSA_verifyKeysEx
#undef DSA_verifyPQ
#undef DSA_makeKeyBlob
#undef DSA_setAllKeyParameters
#undef DSA_setPublicKeyParameters
#undef DSA_setKeyParameters
#undef DSA_generateRandomGAux
#undef DSA_generateKeyAux
#undef DSA_generateKeyAux2
#undef DSA_computeSignatureAux
#undef DSA_verifySignatureAux
#undef DSA_setKeyParametersAux
#undef DSA_getKeyParametersAlloc
#undef DSA_computeSignature2
#undef DSA_verifySignature2
#undef DSA_computeSignature2Aux
#undef DSA_verifySignature2Aux
#undef DSA_equalKey
#undef DSA_cloneKey

extern MSTATUS DSA_generateKey(hwAccelDescr hwAccelCtx, randomContext* pFipsRngCtx, DSAKey *p_dsaDescr, ubyte4 keySize, ubyte4 *pRetC, ubyte *pRetSeed, vlong **ppRetH, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_generateKey");
    if (OK != status)
        return status;
    
    return HW_DSA_generateKey(hwAccelCtx, pFipsRngCtx, p_dsaDescr, keySize, pRetC, pRetSeed, ppRetH, ppVlongQueue);
}

extern MSTATUS DSA_generateKeyEx(hwAccelDescr hwAccelCtx, randomContext* pFipsRngCtx, DSAKey *p_dsaDescr, ubyte4 keySize, ubyte4 qSize, DSAHashType hashType, ubyte4 *pRetC,
                                 ubyte *pRetSeed, vlong **ppRetH, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_generateKeyEx");
    if (OK != status)
        return status;
    
    return HW_DSA_generateKeyEx(hwAccelCtx, pFipsRngCtx, p_dsaDescr, keySize, qSize, hashType, pRetC, pRetSeed, ppRetH, ppVlongQueue);
}

extern MSTATUS DSA_computeKeyPair(hwAccelDescr hwAccelCtx, randomContext* pFipsRngCtx, DSAKey *p_dsaDescr, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_computeKeyPair");
    if (OK != status)
        return status;
    
    return HW_DSA_computeKeyPair(hwAccelCtx, pFipsRngCtx, p_dsaDescr, ppVlongQueue);
}

extern MSTATUS DSA_computeKeyPairEx(hwAccelDescr hwAccelCtx, randomContext* pFipsRngCtx, DSAKey *p_dsaDescr, ubyte4 Lin, ubyte4 Nin, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_computeKeyPairEx");
    if (OK != status)
        return status;
    
    return HW_DSA_computeKeyPairEx(hwAccelCtx, pFipsRngCtx, p_dsaDescr, Lin, Nin, ppVlongQueue);
}

extern MSTATUS DSA_getCipherTextLength(hwAccelDescr hwAccelCtx, const DSAKey *pKey, sbyte4* cipherTextLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_getCipherTextLength");
    if (OK != status)
        return status;

    return HW_DSA_getCipherTextLength(hwAccelCtx, pKey, cipherTextLen);
}

extern MSTATUS DSA_getSignatureLength(hwAccelDescr hwAccelCtx, DSAKey *pKey, ubyte4 *pSigLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_getSignatureLength");
    if (OK != status)
        return status;

    return HW_DSA_getSignatureLength(hwAccelCtx, pKey, pSigLen);
}

extern MSTATUS DSA_computeSignatureEx(hwAccelDescr hwAccelCtx, RNGFun rngfun, void* rngArg, const DSAKey *p_dsaDescr, vlong* m,
                                      intBoolean *pVerifySignature, vlong **ppR, vlong **ppS, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_computeSignatureEx");
    if (OK != status)
        return status;
    
    return HW_DSA_computeSignatureEx(hwAccelCtx, rngfun, rngArg, p_dsaDescr, m, pVerifySignature, ppR, ppS, ppVlongQueue);
}

extern MSTATUS DSA_verifySignature(hwAccelDescr hwAccelCtx, const DSAKey *p_dsaDescr, vlong *m, vlong *pR, vlong *pS, intBoolean *isGoodSignature, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_verifySignature");
    if (OK != status)
        return status;
    
    return HW_DSA_verifySignature(hwAccelCtx, p_dsaDescr, m, pR, pS, isGoodSignature, ppVlongQueue);
}

extern MSTATUS DSA_verifyKeysEx(hwAccelDescr hwAccelCtx, randomContext* pFipsRngCtx, ubyte *pSeed, ubyte4 seedSize, const DSAKey *p_dsaDescr, DSAHashType hashType,
                                DSAKeyType keyType, ubyte4 C, vlong *pH, intBoolean *isGoodKeys, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_verifyKeysEx");
    if (OK != status)
        return status;
    
    return HW_DSA_verifyKeysEx(hwAccelCtx, pFipsRngCtx, pSeed, seedSize, p_dsaDescr, hashType, keyType, C, pH, isGoodKeys, ppVlongQueue);
}

extern MSTATUS DSA_verifyPQ(hwAccelDescr hwAccelCtx, randomContext* pFipsRngCtx, DSAKey *p_dsaDescr, ubyte4 L, ubyte4 Nin, DSAHashType hashType, DSAKeyType keyType, ubyte4 C,
                            ubyte *pSeed, ubyte4 seedSize, intBoolean *pIsPrimePQ, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_verifyPQ");
    if (OK != status)
        return status;
    
    return HW_DSA_verifyPQ(hwAccelCtx, pFipsRngCtx, p_dsaDescr, L, Nin, hashType, keyType, C, pSeed, seedSize, pIsPrimePQ, ppVlongQueue);
}

extern MSTATUS DSA_makeKeyBlob(hwAccelDescr hwAccelCtx, const DSAKey *p_dsaDescr, ubyte *pKeyBlob, ubyte4 *pRetKeyBlobLength)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_makeKeyBlob");
    if (OK != status)
        return status;
    
    return HW_DSA_makeKeyBlob(hwAccelCtx, p_dsaDescr, pKeyBlob, pRetKeyBlobLength);
}

extern MSTATUS DSA_setAllKeyParameters(hwAccelDescr hwAccelCtx, DSAKey* pKey,  const ubyte* p, ubyte4 pLen, const ubyte* q, ubyte4 qLen,
                                       const ubyte* g, ubyte4 gLen, const ubyte* x, ubyte4 xLen, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_setAllKeyParameters");
    if (OK != status)
        return status;
    
    return HW_DSA_setAllKeyParameters(hwAccelCtx, pKey, p, pLen, q, qLen, g, gLen, x, xLen, ppVlongQueue);
}

extern MSTATUS DSA_setPublicKeyParameters(hwAccelDescr hwAccelCtx, DSAKey* pKey,  const ubyte* p, ubyte4 pLen, const ubyte* q, ubyte4 qLen,
                                          const ubyte* g, ubyte4 gLen, const ubyte* y, ubyte4 yLen, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_setPublicKeyParameters");
    if (OK != status)
        return status;
    
    return HW_DSA_setPublicKeyParameters(hwAccelCtx, pKey, p, pLen, q, qLen, g, gLen, y, yLen, ppVlongQueue);
}

extern MSTATUS DSA_setKeyParameters (hwAccelDescr hwAccelCtx, DSAKey *pKey, const ubyte* p, ubyte4 pLen,
                                     const ubyte* q, ubyte4 qLen, const ubyte* g, ubyte4 gLen, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_setKeyParameters");
    if (OK != status)
        return status;
    
    return HW_DSA_setKeyParameters(hwAccelCtx, pKey, p, pLen, q, qLen, g, gLen, ppVlongQueue);
}

extern MSTATUS DSA_generateRandomGAux (hwAccelDescr hwAccelCtx, DSAKey *p_dsaDescr, randomContext *pRandomContext, ubyte **ppH, ubyte4 *pHLen, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_generateRandomGAux");
    if (OK != status)
        return status;
    
    return HW_DSA_generateRandomGAux(hwAccelCtx, p_dsaDescr, pRandomContext, ppH, pHLen, ppVlongQueue);
}

extern MSTATUS DSA_generateKeyAux(hwAccelDescr hwAccelCtx, randomContext* pFipsRngCtx, DSAKey *p_dsaDescr, ubyte4 keySize, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_generateKeyAux");
    if (OK != status)
        return status;
    
    return HW_DSA_generateKeyAux(hwAccelCtx, pFipsRngCtx, p_dsaDescr, keySize, ppVlongQueue);
}

extern MSTATUS DSA_generateKeyAux2(hwAccelDescr hwAccelCtx, randomContext* pFipsRngCtx, DSAKey *p_dsaDescr, ubyte4 keySize,
                                   ubyte4 qSize, DSAHashType hashType, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_generateKeyAux2");
    if (OK != status)
        return status;
    
    return HW_DSA_generateKeyAux2(hwAccelCtx, pFipsRngCtx, p_dsaDescr, keySize, qSize, hashType, ppVlongQueue);
}

extern MSTATUS DSA_computeSignatureAux(hwAccelDescr hwAccelCtx, randomContext *pRngCtx, DSAKey *pKey, ubyte *pM, ubyte4 mLen, intBoolean *pVerify,
                                       ubyte **ppR, ubyte4 *pRLen, ubyte **ppS, ubyte4 *pSLen, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_computeSignatureAux");
    if (OK != status)
        return status;
    
    return HW_DSA_computeSignatureAux(hwAccelCtx, pRngCtx, pKey, pM, mLen, pVerify, ppR, pRLen, ppS, pSLen, ppVlongQueue);
}

extern MSTATUS DSA_verifySignatureAux(hwAccelDescr hwAccelCtx, DSAKey *pKey, ubyte *pM, ubyte4 mLen, ubyte *pR, ubyte4 rLen, ubyte *pS, ubyte4 sLen,
                                      intBoolean *pIsGoodSignature, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_verifySignatureAux");
    if (OK != status)
        return status;
 
    return HW_DSA_verifySignatureAux(hwAccelCtx, pKey, pM, mLen, pR, rLen, pS, sLen, pIsGoodSignature, ppVlongQueue);
}

extern MSTATUS DSA_setKeyParametersAux(hwAccelDescr hwAccelCtx, DSAKey *pKey, MDsaKeyTemplatePtr pTemplate)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_setKeyParametersAux");
    if (OK != status)
        return status;
    
    return HW_DSA_setKeyParametersAux(hwAccelCtx, pKey, pTemplate);
}

extern MSTATUS DSA_getKeyParametersAlloc(hwAccelDescr hwAccelCtx, DSAKey *pKey, MDsaKeyTemplatePtr pTemplate, ubyte keyType)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_getKeyParametersAlloc");
    if (OK != status)
        return status;
    
    return HW_DSA_getKeyParametersAlloc(hwAccelCtx, pKey, pTemplate, keyType);
}

extern MSTATUS DSA_computeSignature2(hwAccelDescr hwAccelCtx, RNGFun rngfun, void* rngArg, const DSAKey *p_dsaDescr, const ubyte* msg, ubyte4 msgLen,
                                     vlong **ppR, vlong **ppS, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_computeSignature2");
    if (OK != status)
        return status;
    
    return HW_DSA_computeSignature2(hwAccelCtx, rngfun, rngArg, p_dsaDescr, msg, msgLen, ppR, ppS, ppVlongQueue);
}

extern MSTATUS DSA_verifySignature2(hwAccelDescr hwAccelCtx, const DSAKey *p_dsaDescr, const ubyte *msg, ubyte4 msgLen, vlong *pR, vlong *pS,
                                    intBoolean *isGoodSignature, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_verifySignature2");
    if (OK != status)
        return status;
    
    return HW_DSA_verifySignature2(hwAccelCtx, p_dsaDescr, msg, msgLen, pR, pS, isGoodSignature, ppVlongQueue);
}

extern MSTATUS DSA_computeSignature2Aux(hwAccelDescr hwAccelCtx, RNGFun rngfun, void *pRngArg, DSAKey *pKey, ubyte *pM, ubyte4 mLen,
                                        ubyte **ppR, ubyte4 *pRLen, ubyte **ppS, ubyte4 *pSLen, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_computeSignature2Aux");
    if (OK != status)
        return status;
    
    return HW_DSA_computeSignature2Aux(hwAccelCtx, rngfun, pRngArg, pKey, pM, mLen, ppR, pRLen, ppS, pSLen, ppVlongQueue);
}

extern MSTATUS DSA_verifySignature2Aux(hwAccelDescr hwAccelCtx, DSAKey *pKey, ubyte *pM, ubyte4 mLen, ubyte *pR, ubyte4 rLen, ubyte *pS, ubyte4 sLen,
                                       intBoolean *pIsGoodSignature, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_verifySignature2Aux");
    if (OK != status)
        return status;
    
    return HW_DSA_verifySignature2Aux(hwAccelCtx, pKey, pM, mLen, pR, rLen, pS, sLen, pIsGoodSignature, ppVlongQueue);
}

extern MSTATUS DSA_equalKey(hwAccelDescr hwAccelCtx,  const DSAKey *pKey1, const DSAKey *pKey2, byteBoolean* pResult)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_equalKey");
    if (OK != status)
        return status;
    
    return HW_DSA_equalKey(hwAccelCtx, pKey1, pKey2, pResult);
}

extern MSTATUS DSA_cloneKey(hwAccelDescr hwAccelCtx, DSAKey** ppNew, const DSAKey* pSrc)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "DSA_cloneKey");
    if (OK != status)
        return status;
    
    return HW_DSA_cloneKey(hwAccelCtx, ppNew, pSrc);
}
#endif /* defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_DSA__) 
          && defined(__ENABLE_DIGICERT_DSA__) */
