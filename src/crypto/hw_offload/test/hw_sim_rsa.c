/**
 * @file hw_sim_rsa.c
 *
 * @brief RSA test for hw simulator
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

#if defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_RSA__)

/* redefine existing methods to simulate that they are using a hw implementation */

#define RSA_generateKeyFipsSteps    HW_RSA_generateKeyFipsSteps
#define RSA_cloneKey                HW_RSA_cloneKey
#define RSA_equalKey                HW_RSA_equalKey
#define RSA_setPublicKeyParameters  HW_RSA_setPublicKeyParameters
#define RSA_setPublicKeyData        HW_RSA_setPublicKeyData
#define RSA_setAllKeyParameters     HW_RSA_setAllKeyParameters
#define RSA_setAllKeyData           HW_RSA_setAllKeyData
#define RSA_getKeyParametersAlloc   HW_RSA_getKeyParametersAlloc
#define RSA_encrypt                 HW_RSA_encrypt
#define RSA_decrypt                 HW_RSA_decrypt
#define RSA_verifySignature         HW_RSA_verifySignature
#define RSA_signMessage             HW_RSA_signMessage
#define RSA_generateKeyFIPS         HW_RSA_generateKeyFIPS
#define RSA_generateKey             HW_RSA_generateKey
#define RSA_prepareKey              HW_RSA_prepareKey
#define RSA_keyFromByteString       HW_RSA_keyFromByteString
#define RSA_byteStringFromKey       HW_RSA_byteStringFromKey
#define RSA_getPrivateExponent      HW_RSA_getPrivateExponent
#define RSA_applyPublicKey          HW_RSA_applyPublicKey
#define RSA_applyPrivateKey         HW_RSA_applyPrivateKey
#define RSA_getCipherTextLength     HW_RSA_getCipherTextLength
#define RSA_verifyDigest            HW_RSA_verifyDigest

#include "../../rsa.c"
#include "hw_sim_test.h"

/* undefine the macros so now we can give real definitions of these methdos */
#undef RSA_generateKeyFipsSteps
#undef RSA_cloneKey
#undef RSA_equalKey
#undef RSA_setPublicKeyParameters
#undef RSA_setPublicKeyData
#undef RSA_setAllKeyParameters
#undef RSA_setAllKeyData
#undef RSA_getKeyParametersAlloc
#undef RSA_encrypt
#undef RSA_decrypt
#undef RSA_verifySignature
#undef RSA_signMessage
#undef RSA_generateKeyFIPS
#undef RSA_generateKey
#undef RSA_prepareKey
#undef RSA_keyFromByteString
#undef RSA_byteStringFromKey
#undef RSA_getPrivateExponent
#undef RSA_applyPublicKey
#undef RSA_applyPrivateKey
#undef RSA_getCipherTextLength
#undef RSA_verifyDigest

extern MSTATUS RSA_generateKeyFipsSteps(hwAccelDescr hwAccelCtx, randomContext *pRandomContext,
                         ubyte4 nLen, vlong *e, const vlong *pDebugX, ubyte4 length1, ubyte4 length2,
                         vlong **ppRetP1, vlong **ppRetP2, vlong **ppRetXp, vlong **ppRetPrime,
                         ubyte *pInputSeed, ubyte4 inputSeedLength,
                         ubyte *pRetPrimeSeed1, ubyte *pRetPrimeSeed2,
                         intBoolean *pRetFail,
                         MSTATUS (*completeDigest)(MOC_HASH(hwAccelDescr hwAccelCtx) const ubyte *pData, ubyte4 dataLen, ubyte *pDigestOutput),
                         ubyte4 hashResultSize,
                         vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "RSA_generateKeyFipsSteps");
    if (OK != status)
        return status;
    
    return HW_RSA_generateKeyFipsSteps(hwAccelCtx, pRandomContext, nLen, e, pDebugX, length1, length2,
                                       ppRetP1, ppRetP2, ppRetXp, ppRetPrime, pInputSeed, inputSeedLength,
                                       pRetPrimeSeed1, pRetPrimeSeed2, pRetFail, completeDigest,
                                       hashResultSize, ppVlongQueue);
}

extern MSTATUS RSA_cloneKey(hwAccelDescr hwAccelCtx, RSAKey **ppNew, const RSAKey *pSrc, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "RSA_cloneKey");
    if (OK != status)
        return status;
    
    return HW_RSA_cloneKey(hwAccelCtx, ppNew, pSrc, ppVlongQueue);
}

extern MSTATUS RSA_equalKey(hwAccelDescr hwAccelCtx, const RSAKey *pKey1, const RSAKey *pKey2, byteBoolean *pResult)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "RSA_equalKey");
    if (OK != status)
        return status;
    
    return HW_RSA_equalKey(hwAccelCtx, pKey1, pKey2, pResult);
}

extern MSTATUS RSA_setPublicKeyParameters(hwAccelDescr hwAccelCtx, RSAKey *pKey, ubyte4 exponent, const ubyte* modulus,
                                          ubyte4 modulusLen, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "RSA_setPublicKeyParameters");
    if (OK != status)
        return status;
    
    return HW_RSA_setPublicKeyParameters(hwAccelCtx, pKey, exponent, modulus, modulusLen, ppVlongQueue);
}

extern MSTATUS RSA_setPublicKeyData (hwAccelDescr hwAccelCtx, RSAKey *pKey, ubyte *pPubExpo, ubyte4 pubExpoLen,
                                     const ubyte *pModulus, ubyte4 modulusLen, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "RSA_setPublicKeyData");
    if (OK != status)
        return status;
    
    return HW_RSA_setPublicKeyData(hwAccelCtx, pKey, pPubExpo, pubExpoLen, pModulus, modulusLen, ppVlongQueue);
}

extern MSTATUS RSA_setAllKeyParameters(hwAccelDescr hwAccelCtx, RSAKey *pKey, ubyte4 exponent, const ubyte *modulus,
                                       ubyte4 modulusLen, const ubyte *prime1, ubyte4 prime1Len, const ubyte *prime2,
                                       ubyte4 prime2Len, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "RSA_setAllKeyParameters");
    if (OK != status)
        return status;
    
    return HW_RSA_setAllKeyParameters(hwAccelCtx, pKey, exponent, modulus, modulusLen, 
                                      prime1, prime1Len, prime2, prime2Len, ppVlongQueue);
}

extern MSTATUS RSA_setAllKeyData (hwAccelDescr hwAccelCtx, RSAKey *pKey, ubyte *pPubExpo, ubyte4 pubExpoLen,
                                  const ubyte *pModulus, ubyte4 modulusLen, const ubyte *pPrime1, ubyte4 prime1Len,
                                  const ubyte *pPrime2, ubyte4 prime2Len, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "RSA_setAllKeyData");
    if (OK != status)
        return status;
    
    return HW_RSA_setAllKeyData(hwAccelCtx, pKey, pPubExpo, pubExpoLen, pModulus, modulusLen, pPrime1, 
                                prime1Len, pPrime2, prime2Len, ppVlongQueue);
}

extern MSTATUS RSA_getKeyParametersAlloc (hwAccelDescr hwAccelCtx, RSAKey *pKey, MRsaKeyTemplatePtr pTemplate,
                                          ubyte keyType)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "RSA_getKeyParametersAlloc");
    if (OK != status)
        return status;
    
    return HW_RSA_getKeyParametersAlloc(hwAccelCtx, pKey, pTemplate, keyType);
}

extern MSTATUS RSA_encrypt(hwAccelDescr hwAccelCtx, const RSAKey *pKey, const ubyte* plainText, ubyte4 plainTextLen,
                           ubyte* cipherText, RNGFun rngFun, void* rngFunArg, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "RSA_encrypt");
    if (OK != status)
        return status;
    
    return HW_RSA_encrypt(hwAccelCtx, pKey, plainText, plainTextLen, cipherText, rngFun, rngFunArg, ppVlongQueue);
}

extern MSTATUS RSA_decrypt(hwAccelDescr hwAccelCtx, const RSAKey *pKey, const ubyte* cipherText, ubyte* plainText,
                           ubyte4* plainTextLen, RNGFun rngFun, void* rngFunArg, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "RSA_decrypt");
    if (OK != status)
        return status;
    
    return HW_RSA_decrypt(hwAccelCtx, pKey, cipherText, plainText, plainTextLen, rngFun, rngFunArg, ppVlongQueue);
}

extern MSTATUS RSA_verifySignature(hwAccelDescr hwAccelCtx, const RSAKey *pKey, const ubyte* cipherText,
                                   ubyte* plainText, ubyte4* plainTextLen, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "RSA_verifySignature");
    if (OK != status)
        return status;
    
    return HW_RSA_verifySignature(hwAccelCtx, pKey, cipherText, plainText, plainTextLen, ppVlongQueue);
}

extern MSTATUS RSA_signMessage(hwAccelDescr hwAccelCtx, const RSAKey *pKey, const ubyte* plainText,
                               ubyte4 plainTextLen, ubyte* cipherText, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "RSA_signMessage");
    if (OK != status)
        return status;
    
    return HW_RSA_signMessage(hwAccelCtx, pKey, plainText, plainTextLen, cipherText, ppVlongQueue);
}

extern MSTATUS RSA_generateKeyFIPS(hwAccelDescr hwAccelCtx, randomContext *pRandomContext, RSAKey *p_rsaKey, 
                                   ubyte4 keySize, vlong **Xp, vlong **Xp1, vlong **Xp2,
                                   vlong **Xq, vlong **Xq1, vlong **Xq2, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "RSA_generateKeyFIPS");
    if (OK != status)
        return status;
    
    return HW_RSA_generateKeyFIPS(hwAccelCtx, pRandomContext, p_rsaKey, keySize, Xp, Xp1, Xp2, Xq,
                                  Xq1, Xq2, ppVlongQueue);
}

extern MSTATUS RSA_generateKey(hwAccelDescr hwAccelCtx, randomContext *pRandomContext, RSAKey *p_rsaKey,
                               ubyte4 keySize, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "RSA_generateKey");
    if (OK != status)
        return status;
    
    return HW_RSA_generateKey(hwAccelCtx, pRandomContext, p_rsaKey, keySize, ppVlongQueue);
}

extern MSTATUS RSA_prepareKey(hwAccelDescr hwAccelCtx, RSAKey *pRSAKey, vlong** ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "RSA_prepareKey");
    if (OK != status)
        return status;
    
    return HW_RSA_prepareKey(hwAccelCtx, pRSAKey, ppVlongQueue);
}

extern MSTATUS RSA_keyFromByteString(hwAccelDescr hwAccelCtx, RSAKey **ppKey, const ubyte* byteString,
                                     ubyte4 len, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "RSA_keyFromByteString");
    if (OK != status)
        return status;
    
    return HW_RSA_keyFromByteString(hwAccelCtx, ppKey, byteString, len, ppVlongQueue);
}

extern MSTATUS RSA_byteStringFromKey(hwAccelDescr hwAccelCtx, const RSAKey *pKey, ubyte *pBuffer, ubyte4 *pRetLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "RSA_byteStringFromKey");
    if (OK != status)
        return status;
    
    return HW_RSA_byteStringFromKey(hwAccelCtx, pKey, pBuffer, pRetLen);
}

extern MSTATUS RSA_getPrivateExponent (hwAccelDescr hwAccelCtx, RSAKey *pRSAKey, vlong **ppRetD, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "RSA_getPrivateExponent");
    if (OK != status)
        return status;
    
    return HW_RSA_getPrivateExponent(hwAccelCtx, pRSAKey, ppRetD, ppVlongQueue);
}

extern MSTATUS RSA_applyPublicKey (hwAccelDescr hwAccelCtx, RSAKey *pPublicKey, ubyte *pInput,
                                   ubyte4 inputLen, ubyte **ppOutput, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "RSA_applyPublicKey");
    if (OK != status)
        return status;
    
    return HW_RSA_applyPublicKey(hwAccelCtx, pPublicKey, pInput, inputLen, ppOutput, ppVlongQueue);
}

extern MSTATUS RSA_applyPrivateKey (hwAccelDescr hwAccelCtx, RSAKey *pPrivateKey, RNGFun rngFun, void *rngFunArg,
                                    ubyte *pInput, ubyte4 inputLen, ubyte **ppOutput, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "RSA_applyPrivateKey");
    if (OK != status)
        return status;
 
    return HW_RSA_applyPrivateKey(hwAccelCtx, pPrivateKey, rngFun, rngFunArg, pInput, inputLen, ppOutput, ppVlongQueue);
}

extern MSTATUS RSA_getCipherTextLength(hwAccelDescr hwAccelCtx, const RSAKey *pKey, sbyte4 *pCipherTextLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "RSA_getCipherTextLength");
    if (OK != status)
        return status;
 
    return HW_RSA_getCipherTextLength(hwAccelCtx, pKey, pCipherTextLen);
}

extern MSTATUS RSA_verifyDigest(hwAccelDescr hwAccelCtx, RSAKey *pKey, ubyte *pMsgDigest, ubyte4 digestLen,
                                ubyte* pSignature, ubyte4 sigLen, intBoolean *pIsValid, vlong **ppVlongQueue)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "RSA_verifyDigest");
    if (OK != status)
        return status;

    return HW_RSA_verifyDigest(hwAccelCtx, pKey, pMsgDigest, digestLen, pSignature, sigLen, pIsValid, ppVlongQueue);
}

#endif /* defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_RSA__) */
