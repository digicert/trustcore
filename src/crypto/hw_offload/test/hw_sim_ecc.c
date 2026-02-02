/**
 * @file hw_sim_ecc.c
 *
 * @brief ECC test for hw simulator
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

#if defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_ECC__) \
    && defined(__ENABLE_DIGICERT_ECC__)

/* redefine existing methods to simulate that they are using a hw implementation */

#define EC_setKeyParametersEx                          HW_EC_setKeyParametersEx
#define EC_setPrivateKeyEx                             HW_EC_setPrivateKeyEx
#define EC_verifyKeyPairEx                             HW_EC_verifyKeyPairEx
#define EC_verifyPublicKeyEx                           HW_EC_verifyPublicKeyEx
#define EC_generateKeyPairEx                           HW_EC_generateKeyPairEx
#define EC_generateKeyPairAlloc                        HW_EC_generateKeyPairAlloc
#define EC_writePublicKeyToBuffer                      HW_EC_writePublicKeyToBuffer
#define EC_writePublicKeyToBufferAlloc                 HW_EC_writePublicKeyToBufferAlloc
#define EC_newPublicKeyFromByteString                  HW_EC_newPublicKeyFromByteString
#define EC_getKeyParametersAlloc                       HW_EC_getKeyParametersAlloc
#define EC_equalKeyEx                                  HW_EC_equalKeyEx
#define EC_cloneKeyEx                                  HW_EC_cloneKeyEx
#define ECDSA_signDigest                               HW_ECDSA_signDigest
#define ECDSA_verifySignatureDigest                    HW_ECDSA_verifySignatureDigest
#define ECDH_generateSharedSecretFromKeys              HW_ECDH_generateSharedSecretFromKeys
#define ECDH_generateSharedSecretFromPublicByteString  HW_ECDH_generateSharedSecretFromPublicByteString
#define ECDSA_signMessage                              HW_ECDSA_signMessage
#define ECDSA_verifyMessage                            HW_ECDSA_verifyMessage
#define ECDSA_initVerify                               HW_ECDSA_initVerify
#define ECDSA_updateVerify                             HW_ECDSA_updateVerify
#define ECDSA_finalVerify                              HW_ECDSA_finalVerify

#include "../../ecc.c"

#include "hw_sim_test.h"

/* undefine the macros so now we can give real definitions of these methdos */
#undef EC_setKeyParametersEx
#undef EC_setPrivateKeyEx
#undef EC_verifyKeyPairEx
#undef EC_verifyPublicKeyEx
#undef EC_generateKeyPairEx
#undef EC_generateKeyPairAlloc
#undef EC_writePublicKeyToBuffer
#undef EC_writePublicKeyToBufferAlloc
#undef EC_newPublicKeyFromByteString
#undef EC_getKeyParametersAlloc
#undef EC_equalKeyEx
#undef EC_cloneKeyEx
#undef ECDSA_signDigest
#undef ECDSA_verifySignatureDigest
#undef ECDH_generateSharedSecretFromKeys
#undef ECDH_generateSharedSecretFromPublicByteString
#undef ECDSA_signMessage
#undef ECDSA_verifyMessage
#undef ECDSA_initVerify
#undef ECDSA_updateVerify
#undef ECDSA_finalVerify

extern MSTATUS EC_setKeyParametersEx(hwAccelDescr hwAccelCtx, ECCKey *pKey, ubyte *pPoint, ubyte4 pointLen, ubyte *pScalar, ubyte4 scalarLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "EC_setKeyParametersEx");
    if (OK != status)
        return status;
    
    return HW_EC_setKeyParametersEx(hwAccelCtx, pKey, pPoint, pointLen, pScalar, scalarLen);
}

extern MSTATUS EC_setPrivateKeyEx(hwAccelDescr hwAccelCtx, ECCKey *pKey, ubyte *pScalar, ubyte4 scalarLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "EC_setPrivateKeyEx");
    if (OK != status)
        return status;
    
    return HW_EC_setPrivateKeyEx(hwAccelCtx, pKey, pScalar, scalarLen);
}

extern MSTATUS EC_verifyKeyPairEx(hwAccelDescr hwAccelCtx, ECCKey *pPrivateKey, ECCKey *pPublicKey, byteBoolean *pVfy)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "EC_verifyKeyPairEx");
    if (OK != status)
        return status;
    
    return HW_EC_verifyKeyPairEx(hwAccelCtx, pPrivateKey, pPublicKey, pVfy);
}

extern MSTATUS EC_verifyPublicKeyEx(hwAccelDescr hwAccelCtx, ECCKey *pPublicKey, byteBoolean *pIsValid)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "EC_verifyPublicKeyEx");
    if (OK != status)
        return status;
    
    return HW_EC_verifyPublicKeyEx(hwAccelCtx, pPublicKey, pIsValid);
}

extern MSTATUS EC_generateKeyPairEx(hwAccelDescr hwAccelCtx, ECCKey *pKey, RNGFun rngFun, void* rngArg)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "EC_generateKeyPairEx");
    if (OK != status)
        return status;
    
    return HW_EC_generateKeyPairEx (hwAccelCtx, pKey, rngFun, rngArg);
}

extern MSTATUS EC_generateKeyPairAlloc(hwAccelDescr hwAccelCtx, ubyte4 curveId, ECCKey **ppNewKey, RNGFun rngFun, void* rngArg)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "EC_generateKeyPairAlloc");
    if (OK != status)
        return status;
    
    return HW_EC_generateKeyPairAlloc(hwAccelCtx, curveId, ppNewKey, rngFun, rngArg);
}

extern MSTATUS EC_writePublicKeyToBuffer(hwAccelDescr hwAccelCtx, ECCKey *pKey, ubyte *pBuffer, ubyte4 bufferSize)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "EC_writePublicKeyToBuffer");
    if (OK != status)
        return status;
    
    return HW_EC_writePublicKeyToBuffer(hwAccelCtx, pKey, pBuffer, bufferSize);
}

extern MSTATUS EC_writePublicKeyToBufferAlloc(hwAccelDescr hwAccelCtx, ECCKey *pKey, ubyte **ppBuffer, ubyte4 *pBufferSize)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "EC_writePublicKeyToBufferAlloc");
    if (OK != status)
        return status;
    
    return HW_EC_writePublicKeyToBufferAlloc(hwAccelCtx, pKey, ppBuffer, pBufferSize);
}

extern MSTATUS EC_newPublicKeyFromByteString(hwAccelDescr hwAccelCtx, ubyte4 curveId, ECCKey **ppNewKey, ubyte *pByteString, ubyte4 byteStringLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "EC_newPublicKeyFromByteString");
    if (OK != status)
        return status;
    
    return HW_EC_newPublicKeyFromByteString(hwAccelCtx, curveId, ppNewKey, pByteString, byteStringLen);
}

extern MSTATUS EC_getKeyParametersAlloc(hwAccelDescr hwAccelCtx, ECCKey *pKey, MEccKeyTemplatePtr pTemplate, ubyte reqType)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "EC_getKeyParametersAlloc");
    if (OK != status)
        return status;
    
    return HW_EC_getKeyParametersAlloc(hwAccelCtx, pKey, pTemplate, reqType);
}

extern MSTATUS EC_equalKeyEx(hwAccelDescr hwAccelCtx, ECCKey *pKey1, ECCKey *pKey2, byteBoolean *pRes)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "EC_equalKeyEx");
    if (OK != status)
        return status;
    
    return HW_EC_equalKeyEx(hwAccelCtx, pKey1, pKey2, pRes);
}

extern MSTATUS EC_cloneKeyEx(hwAccelDescr hwAccelCtx, ECCKey **ppNew, ECCKey *pSrc)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "EC_cloneKeyEx");
    if (OK != status)
        return status;
    
    return HW_EC_cloneKeyEx(hwAccelCtx, ppNew, pSrc);
}

extern MSTATUS ECDSA_signDigest(hwAccelDescr hwAccelCtx, ECCKey *pKey, RNGFun rngFun, void* rngArg, ubyte *pHash, ubyte4 hashLen, ubyte *pSignature,
                                 ubyte4 bufferSize, ubyte4 *pSignatureLen)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "ECDSA_signDigest");
    if (OK != status)
        return status;
    
    return HW_ECDSA_signDigest(hwAccelCtx, pKey, rngFun, rngArg, pHash, hashLen, pSignature, bufferSize, pSignatureLen);
}

extern MSTATUS ECDSA_verifySignatureDigest(hwAccelDescr hwAccelCtx, ECCKey *pPublicKey, ubyte *pHash, ubyte4 hashLen, ubyte *pR, ubyte4 rLen, ubyte *pS,
                                           ubyte4 sLen, ubyte4 *pVerifyFailures)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "ECDSA_verifySignatureDigest");
    if (OK != status)
        return status;
    
    return HW_ECDSA_verifySignatureDigest(hwAccelCtx, pPublicKey, pHash, hashLen, pR, rLen, pS, sLen, pVerifyFailures);
}

extern MSTATUS ECDH_generateSharedSecretFromKeys(hwAccelDescr hwAccelCtx, ECCKey *pPrivateKey, ECCKey *pPublicKey,
                                                 ubyte **ppSharedSecret, ubyte4 *pSharedSecretLen, sbyte4 flag, void *pKdfInfo)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "ECDH_generateSharedSecretFromKeys");
    if (OK != status)
        return status;
    
    return HW_ECDH_generateSharedSecretFromKeys(hwAccelCtx, pPrivateKey, pPublicKey, ppSharedSecret, pSharedSecretLen, flag, pKdfInfo);
}

extern MSTATUS ECDH_generateSharedSecretFromPublicByteString(hwAccelDescr hwAccelCtx, ECCKey *pPrivateKey, ubyte *pPointByteString, ubyte4 pointByteStringLen,
                                                             ubyte **ppSharedSecret, ubyte4 *pSharedSecretLen, sbyte4 flag, void *pKdfInfo)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "ECDH_generateSharedSecretFromPublicByteString");
    if (OK != status)
        return status;
    
    return HW_ECDH_generateSharedSecretFromPublicByteString(hwAccelCtx, pPrivateKey, pPointByteString, pointByteStringLen, ppSharedSecret, pSharedSecretLen, flag, pKdfInfo);
}

extern MSTATUS ECDSA_signMessage(hwAccelDescr hwAccelCtx, ECCKey *pPrivateKey, RNGFun rngFun, void *pRngArg, ubyte hashAlgo, ubyte *pMessage, ubyte4 messageLen,
                                 ubyte *pSignature, ubyte4 bufferSize, ubyte4 *pSignatureLen, void *pExtCtx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "ECDSA_signMessage");
    if (OK != status)
        return status;
    
    return HW_ECDSA_signMessage(hwAccelCtx, pPrivateKey, rngFun, pRngArg, hashAlgo, pMessage, messageLen, pSignature, bufferSize, pSignatureLen, pExtCtx);
}

extern MSTATUS ECDSA_verifyMessage(hwAccelDescr hwAccelCtx, ECCKey *pPublicKey, ubyte hashAlgo, ubyte *pMessage, ubyte4 messageLen,
                                   ubyte *pSignature, ubyte4 signatureLen, ubyte4 *pVerifyFailures, void *pExtCtx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "ECDSA_verifyMessage");
    if (OK != status)
        return status;
    
    return HW_ECDSA_verifyMessage(hwAccelCtx, pPublicKey, hashAlgo, pMessage, messageLen, pSignature, signatureLen, pVerifyFailures, pExtCtx);
}

extern MSTATUS ECDSA_initVerify(hwAccelDescr hwAccelCtx, ECDSA_CTX *pCtx, ECCKey *pPublicKey, ubyte hashAlgo, ubyte *pSignature, ubyte4 signatureLen, void *pExtCtx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "ECDSA_initVerify");
    if (OK != status)
        return status;
    
    return HW_ECDSA_initVerify(hwAccelCtx, pCtx, pPublicKey, hashAlgo, pSignature, signatureLen, pExtCtx);
}

extern MSTATUS ECDSA_updateVerify(hwAccelDescr hwAccelCtx, ECDSA_CTX *pCtx, ubyte *pMessage, ubyte4 messageLen, void *pExtCtx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "ECDSA_updateVerify");
    if (OK != status)
        return status;
    
    return HW_ECDSA_updateVerify(hwAccelCtx, pCtx, pMessage, messageLen, pExtCtx);
}

extern MSTATUS ECDSA_finalVerify(hwAccelDescr hwAccelCtx, ECDSA_CTX *pCtx, ubyte4 *pVerifyFailures, void *pExtCtx)
{
    MSTATUS status = HW_SIM_testHwCtx(hwAccelCtx, "ECDSA_finalVerify");
    if (OK != status)
        return status;
 
    return HW_ECDSA_finalVerify(hwAccelCtx, pCtx, pVerifyFailures, pExtCtx);
}
#endif /* defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST__) && defined(__ENABLE_DIGICERT_HW_SIMULATOR_TEST_ECC__) 
          && defined(__ENABLE_DIGICERT_ECC__) */
