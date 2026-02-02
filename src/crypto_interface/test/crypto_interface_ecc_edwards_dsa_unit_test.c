/*
 * crypto_interface_ecc_edwards_dsa_unit_test.c
 *
 * test cases for crypto interface API, EDDSA
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
#include "../../common/initmocana.h"
#include "../../crypto/mocasym.h"
#include "../../crypto/ecc.h"
#include "../../crypto_interface/crypto_interface_priv.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__)

#define __DEBUG_VECTORS__

#ifdef __DEBUG_VECTORS__
#include <stdio.h>

static int gCurrentVector = 0;
static int gTestCurve = 0;

/* Use these macros to output which vector number is failing.
 Make sure retVal is defined. */
#define UNITTEST_VECTOR_STATUS( b, c) if ( UNITTEST_STATUS(b, c) ) {printf("for vector index %d in gTestVector_p%d\n", gCurrentVector, gTestCurve); retVal++;}
#define UNITTEST_VECTOR_INT( b, c, d) if ( UNITTEST_INT(b, c, d) ) {printf("for vector index %d in gTestVector_p%d\n", gCurrentVector, gTestCurve); retVal++;}

#else

/* Still make sure retVal is defined. */
#define UNITTEST_VECTOR_STATUS( b, c) retVal += UNITTEST_STATUS(b, c);
#define UNITTEST_VECTOR_INT( b, c, d) retVal += UNITTEST_INT(b, c, d);

#endif

typedef struct TestVector
{
    char *pPrivKey;
    char *pPubKey;
    char *pMsgDigest;
    char *pSignature;
    char *pCtx;
    byteBoolean preHash;
    ubyte4 verifyStatus;
    
} TestVector;

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_25519__
#include "../../crypto/test/ecc_edwards_dsa_data_25519_inc.h"
#endif

#ifdef __ENABLE_DIGICERT_ECC_EDDSA_448__
#include "../../crypto/test/ecc_edwards_dsa_data_448_inc.h"
#endif

static int testSign(ECCKey *pKey, ubyte *pMessage, ubyte4 messageLen, 
                    byteBoolean isPreHash, ubyte *pCtx, ubyte4 ctxLen,
                    ubyte *pExpectedSig, ubyte4 expectedSigLen)
{
    MSTATUS status;
    int retVal = 0;
    sbyte4 compare;
    
    ubyte pSignature[57*2] = {0}; /* big enough for either curve */
    ubyte4 signatureLen;
    
    /* Call with NULL pSignature to get the singatureLen */
    status = EdDSA_signInput(MOC_ECC(gpHwAccelCtx) pKey, pMessage, messageLen, isPreHash, pCtx, ctxLen,
                             NULL, 0, &signatureLen, NULL);
    UNITTEST_VECTOR_INT(__MOC_LINE__, status, ERR_BUFFER_TOO_SMALL);
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, signatureLen, expectedSigLen);
    
    status = EdDSA_signInput(MOC_ECC(gpHwAccelCtx) pKey, pMessage, messageLen, isPreHash, pCtx, ctxLen,
                             pSignature, sizeof(pSignature), &signatureLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, signatureLen, expectedSigLen);
    
    status = DIGI_MEMCMP(pSignature, pExpectedSig, signatureLen, &compare);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

    /* test the generic API when it's not prehash or context mode */
    if (!isPreHash && NULL == pCtx)
    {
        compare = -1;

        /* Call with NULL pSignature to get the singatureLen */
        status = ECDSA_signMessage(MOC_ECC(gpHwAccelCtx) pKey, NULL, NULL, 0, pMessage, messageLen, NULL, 0, &signatureLen, NULL);
        UNITTEST_VECTOR_INT(__MOC_LINE__, status, ERR_BUFFER_TOO_SMALL);
        
        UNITTEST_VECTOR_INT(__MOC_LINE__, signatureLen, expectedSigLen);
        
        status = ECDSA_signMessage(MOC_ECC(gpHwAccelCtx) pKey, NULL, NULL, 0, pMessage, messageLen, pSignature, sizeof(pSignature), &signatureLen, NULL);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        UNITTEST_VECTOR_INT(__MOC_LINE__, signatureLen, expectedSigLen);
        
        status = DIGI_MEMCMP(pSignature, pExpectedSig, signatureLen, &compare);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    }
 
exit:

    return retVal;
}

static int testVerifyEVP(ECCKey *pKey, ubyte *pMessage, ubyte4 messageLen, ubyte *pSignature, ubyte4 signatureLen, ubyte4 expectedVerifyStatus)
{
    MSTATUS status;
    int retVal = 0;
    ubyte4 verifyStatus;
    
    ECDSA_CTX ctx = {0};
    
    status = ECDSA_initVerify(MOC_ECC(gpHwAccelCtx) &ctx, pKey, 0, pSignature, signatureLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /*
     edDSA_update's message buffering is clearly relegated to the hash method used.
     The unit test for the hash method therefore has the responsibility for testing
     the buffering of pMessage into various size chunks. We will just make one straight call
     to edDSA_update.
     */
    status = ECDSA_updateVerify(MOC_ECC(gpHwAccelCtx) &ctx, pMessage, messageLen, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = ECDSA_finalVerify(MOC_ECC(gpHwAccelCtx) &ctx, &verifyStatus, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, verifyStatus, expectedVerifyStatus);
    
exit:
    
    return retVal;
}

static int testVerifyOneShot(ECCKey *pKey, ubyte *pMessage, ubyte4 messageLen,
                             byteBoolean isPreHash, ubyte *pCtx, ubyte4 ctxLen,
                             ubyte *pSignature, ubyte4 signatureLen, ubyte4 expectedVerifyStatus)
{
    MSTATUS status;
    int retVal = 0;
    ubyte4 verifyStatus = 1;
    
    status = EdDSA_verifyInput(MOC_ECC(gpHwAccelCtx) pKey, pMessage, messageLen, isPreHash, pCtx, ctxLen,
                               pSignature, signatureLen, &verifyStatus, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, verifyStatus, expectedVerifyStatus);

    /* test the generic API when it's not prehash or context mode */
    if (!isPreHash && NULL == pCtx)
    {
        verifyStatus = 1;

        status = ECDSA_verifyMessage(MOC_ECC(gpHwAccelCtx) pKey, 0, pMessage, messageLen, pSignature, signatureLen, &verifyStatus, NULL);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        UNITTEST_VECTOR_INT(__MOC_LINE__, verifyStatus, expectedVerifyStatus);
    }
exit:
    
    return retVal;
}

static int knownAnswerTest(TestVector *pTestVector, ubyte4 curve)
{
    MSTATUS status = OK;
    int retVal = 0;
    
    ECCKey *pPrivKey = NULL;
    ECCKey *pPubKey = NULL;
    
    ubyte *pPrivBytes = NULL;
    ubyte4 privLen = 0;
    
    ubyte *pPubBytes = NULL;
    ubyte4 pubLen = 0;
    
    ubyte *pMsgDigestBytes = NULL;
    ubyte4 msgDigestLen = 0;
    
    ubyte *pSignatureBytes = NULL;
    ubyte4 sigLen = 0;

    ubyte *pCtx = NULL;
    ubyte4 ctxLen = 0;
    
    ubyte4 expectedVerifyStatus = pTestVector->verifyStatus;
    
    if (NULL != pTestVector->pPrivKey)
        privLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPrivKey, &pPrivBytes);
    if (NULL != pTestVector->pPubKey)
        pubLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPubKey, &pPubBytes);
    if (NULL != pTestVector->pMsgDigest)
        msgDigestLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pMsgDigest, &pMsgDigestBytes);
    if (NULL != pTestVector->pSignature)
        sigLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pSignature, &pSignatureBytes);
    if (NULL != pTestVector->pCtx)
        ctxLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pCtx, &pCtx);

    if (NULL != pPrivBytes && NULL != pPubBytes)
    {
        status = EC_newKeyEx(curve, &pPrivKey);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pPrivKey, pPubBytes, pubLen, pPrivBytes, privLen);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    
    if (NULL != pPubBytes)
    {
        status = EC_newKeyEx(curve, &pPubKey);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        status = EC_setKeyParametersEx(MOC_ECC(gpHwAccelCtx) pPubKey, pPubBytes, pubLen, NULL, 0);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    
    /* If there is a private key we test both sign and verify. Otherwise we test just verify */
    
    if (NULL != pPrivKey)
    {
        retVal += testSign(pPrivKey, pMsgDigestBytes, msgDigestLen, pTestVector->preHash, pCtx, ctxLen, pSignatureBytes, sigLen);
    }
    
    retVal += testVerifyOneShot(pPubKey, pMsgDigestBytes, msgDigestLen, pTestVector->preHash, pCtx, ctxLen, pSignatureBytes, sigLen, expectedVerifyStatus);
    
    if (!pTestVector->preHash && NULL == pCtx)
    {
        retVal += testVerifyEVP(pPubKey, pMsgDigestBytes, msgDigestLen, pSignatureBytes, sigLen, expectedVerifyStatus);
    }
    
exit:
    
    if (NULL != pPrivKey)
    {
        status = EC_deleteKeyEx(&pPrivKey);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pPubKey)
    {
        status = EC_deleteKeyEx(&pPubKey);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pPrivBytes)
    {
        status = DIGI_FREE((void **) &pPrivBytes);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pPubBytes)
    {
        status = DIGI_FREE((void **) &pPubBytes);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pMsgDigestBytes)
    {
        status = DIGI_FREE((void **) &pMsgDigestBytes);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pSignatureBytes)
    {
        status = DIGI_FREE((void **) &pSignatureBytes);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pCtx)
    {
        status = DIGI_FREE((void **) &pCtx);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}


static int testErrorCases(ubyte4 curve)
{
    MSTATUS status;
    int retVal = 0;
    
    ECCKey keyUnalloc = {0};
    ECCKey *pKey = NULL;
    
    ubyte pMessage[1] = {0};
    ubyte4 messageLen = 1;
    
    ubyte4 signatureLen = (cid_EC_Ed25519 == curve) ? 64 : 114;
    
    ubyte pSignature[114] = {0};  /* big enough for either curve */
    
    ubyte4 verifyStatus = 0;
    
    ECDSA_CTX verifyCtx = {0};
    
    keyUnalloc.curveId = curve;
    
    /*
     Most error cases tested in crypto_interface_ecc_unit_test. We'll only
     test those particular to an Edward's form key.
     */
    
    /* create a valid key for testing */
    
    status = EC_newKeyEx(curve, &pKey);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /******* ECDSA_signMessage *******/
    
    /* null params */
    
    /* unallocated key, use keyUnalloc */
    status = ECDSA_signMessage(MOC_ECC(gpHwAccelCtx) &keyUnalloc, NULL, NULL, 0, pMessage, messageLen, pSignature, sizeof(pSignature), &signatureLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* ECDSA_verifyMessage *******/
    
    status = ECDSA_verifyMessage(MOC_ECC(gpHwAccelCtx) &keyUnalloc, 0, pMessage, messageLen, pSignature, signatureLen, &verifyStatus, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* invalid signature size */
    status = ECDSA_verifyMessage(MOC_ECC(gpHwAccelCtx) pKey, 0, pMessage, messageLen, pSignature, 0, &verifyStatus, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    
    status = ECDSA_verifyMessage(MOC_ECC(gpHwAccelCtx) pKey, 0, pMessage, messageLen, pSignature, 63, &verifyStatus, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    
    status = ECDSA_verifyMessage(MOC_ECC(gpHwAccelCtx) pKey, 0, pMessage, messageLen, pSignature, 113, &verifyStatus, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    
    if (cid_EC_Ed25519 == curve)
    { /* 114 is curve448's size */
        status = ECDSA_verifyMessage(MOC_ECC(gpHwAccelCtx) pKey, 0, pMessage, messageLen, pSignature, 114, &verifyStatus, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    }
    else  /* curveEd448 == curve */
    {     /* 64 is curve25519's size */
        status = ECDSA_verifyMessage(MOC_ECC(gpHwAccelCtx) pKey, 0, pMessage, messageLen, pSignature, 64, &verifyStatus, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    }
    
    /******* ECDSA_initVerify *******/
    
    /* unallocated key */
    status = ECDSA_initVerify(MOC_ECC(gpHwAccelCtx) &verifyCtx, &keyUnalloc, 0, pSignature, signatureLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* invalid signature size */
    status = ECDSA_initVerify(MOC_ECC(gpHwAccelCtx) &verifyCtx, pKey, 0, pSignature, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    
    status = ECDSA_initVerify(MOC_ECC(gpHwAccelCtx) &verifyCtx, pKey, 0, pSignature, 63, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    
    status = ECDSA_initVerify(MOC_ECC(gpHwAccelCtx) &verifyCtx, pKey, 0, pSignature, 113, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    
    if (cid_EC_Ed25519 == curve)
    { /* 114 is curve448's size */
        status = ECDSA_initVerify(MOC_ECC(gpHwAccelCtx) &verifyCtx, pKey, 0, pSignature, 114, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    }
    else  /* curve448 == curve */
    {     /* 64 is curve25519's size */
        status = ECDSA_initVerify(MOC_ECC(gpHwAccelCtx) &verifyCtx, pKey, 0, pSignature, 64, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_ECDSA_INVALID_SIGNATURE_SIZE);
    }
    
    /******* ECDSA_finalVerify *******/
    
    /* verifyCtx was never allocated */
    status = ECDSA_finalVerify(MOC_ECC(gpHwAccelCtx) &verifyCtx, &verifyStatus, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
exit:
    
    if (NULL != pKey)
    {
        status = EC_deleteKeyEx(&pKey);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}
#endif /* defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) */


int crypto_interface_ecc_edwards_dsa_unit_test_all()
{
    int retVal = 0;
    
#if !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) || !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC__) || !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__)
   
    MSTATUS status;
    int i;
    
    InitMocanaSetupInfo setupInfo = {
        .MocSymRandOperator = NULL,
        .pOperatorInfo = NULL,
        /**********************************************************
         *************** DO NOT USE MOC_NO_AUTOSEED ***************
         ***************** in any production code. ****************
         **********************************************************/
        .flags = MOC_NO_AUTOSEED,
        .pStaticMem = NULL,
        .staticMemSize = 0,
        .pDigestOperators = NULL,
        .digestOperatorCount = 0,
        .pSymOperators = NULL,
        .symOperatorCount = 0,
        .pKeyOperators = NULL,
        .keyOperatorCount = 0
    };
    
    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    retVal += UNITTEST_INT(__MOC_LINE__, status, OK);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
    
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
    
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
#endif

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) && !defined(__DISABLE_DIGICERT_SHA512__)
    
    /* Test edDSA on curve25519 */
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 25519;
#endif
    
    for (i = 0; i < COUNTOF(gTestVector_p25519); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p25519 + i, cid_EC_Ed25519);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    /* test Error cases */
    retVal += testErrorCases(cid_EC_Ed25519);
    
#endif /* defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) && !defined(__DISABLE_DIGICERT_SHA512__)  */

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) && defined(__ENABLE_DIGICERT_SHA3__)
    
    /* Test edDSA on curve448 */
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 448;
#endif
    
    for (i = 0; i < COUNTOF(gTestVector_p448); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p448 + i, cid_EC_Ed448);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    /* test Error cases, one shaSuite is sufficient as we'll modify it for some tests anyway */
    retVal += testErrorCases(cid_EC_Ed448);
    
#endif /* defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) && defined(__ENABLE_DIGICERT_SHA3__) */
exit:
    
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif
    
    status = DIGICERT_free(&gpMocCtx);
    retVal += UNITTEST_INT(__MOC_LINE__, status, OK);
    
#endif /* !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) || !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_ECC__) || !defined(__ENABLE_DIGICERT_MBED_KEY_OPERATORS__) */
    
    return retVal;
}
