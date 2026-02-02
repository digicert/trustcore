/*
 * crypto_interface_ecc_edwards_dh_unit_test.c
 *
 * test cases for crypto interface API, EDDH
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

#if defined(__ENABLE_DIGICERT_ECC_EDDH_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDH_448__)

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
    char *pSharedSecret;

} TestVector;

#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
#include "ecc_edwards_dh_data_25519_inc.h"
#endif

#ifdef __ENABLE_DIGICERT_ECC_EDDH_448__
#include "ecc_edwards_dh_data_448_inc.h"
#endif

static int knownAnswerTest(TestVector *pTestVector, ubyte4 curve)
{
    MSTATUS status = OK;
    int retVal = 0;
    int encodingSize = (cid_EC_X25519 == curve ? 32 : 56);
    sbyte4 compare;
    
    ECCKey *pPrivKey = NULL;
    
    ubyte *pPrivKeyBytes = NULL;
    ubyte4 privKeyLen = 0;
    
    ubyte *pPubKeyBytes = NULL;
    ubyte4 pubKeyLen = 0;
    
    ubyte *pExpectedSharedSecret = NULL;
    ubyte4 expectedSSLen = 0;
    
    ubyte *pSharedSecret = NULL;
    ubyte4 ssLen = 0;
    
    if (NULL != pTestVector->pPrivKey)
        privKeyLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPrivKey, &pPrivKeyBytes);
    if (NULL != pTestVector->pPubKey)
        pubKeyLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pPubKey, &pPubKeyBytes);
    if (NULL != pTestVector->pSharedSecret)
        expectedSSLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pSharedSecret, &pExpectedSharedSecret);
    
    status = EC_newKeyEx(curve, &pPrivKey);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* will incorrectly set our public key, but that is not used anyway */
    status = EC_setPrivateKeyEx(MOC_ECC(gpHwAccelCtx) pPrivKey, pPrivKeyBytes, privKeyLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = ECDH_generateSharedSecretFromPublicByteString(MOC_ECC(gpHwAccelCtx) pPrivKey, pPubKeyBytes, pubKeyLen, &pSharedSecret, &ssLen, 0, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, ssLen, encodingSize);
    
    status = DIGI_MEMCMP(pSharedSecret, pExpectedSharedSecret, ssLen, &compare);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

exit:
    
    if (NULL != pPrivKey)
    {
        status = EC_deleteKeyEx(&pPrivKey);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pPrivKeyBytes)
    {
        status = DIGI_FREE((void **) &pPrivKeyBytes);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pPubKeyBytes)
    {
        status = DIGI_FREE((void **) &pPubKeyBytes);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pExpectedSharedSecret)
    {
        status = DIGI_FREE((void **) &pExpectedSharedSecret);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pSharedSecret)
    {
        status = DIGI_FREE((void **) &pSharedSecret);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}


static int testErrorCases(char *pInvalidPubKeys[], ubyte4 curve, ubyte4 numInvalidKeys)
{
    MSTATUS status;
    int retVal = 0;
    int i;
    ubyte4 keyLen = (cid_EC_X25519 == curve ? 32 : 56);
    
    ECCKey keyUnalloc = {0};
    ECCKey *pPriv = NULL;
    ubyte *pInvalidPub = NULL;
    ubyte pPub[56] = {0};   /* big enough for all curves */
    ubyte pValidPriv[56] = {0};  /* big enough for all curves, gets pruned to be valid */
    
    ubyte *pSS = NULL;
    ubyte4 ssLen = 0;
    
    keyUnalloc.curveId = curve;

    /*
     Most error cases tested in crypto_interface_ecc_unit_test. We'll only
     test those particular to an Edward's form key.
     */
    
    /* Allocate private key for testing */
    status = EC_newKeyEx(curve, &pPriv);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* manually set the key to private for future tests */
    ((edECCKey *)(pPriv->pEdECCKey))->isPrivate = TRUE;
    ((edECCKey *)(pPriv->pEdECCKey))->pPrivKey = pValidPriv;

    status = ECDH_generateSharedSecretFromPublicByteString(MOC_ECC(gpHwAccelCtx) &keyUnalloc, pPub, keyLen, &pSS, &ssLen, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_UNALLOCATED_KEY);

    /* invalid public key length */
    status = ECDH_generateSharedSecretFromPublicByteString(MOC_ECC(gpHwAccelCtx) pPriv, pPub, 0, &pSS, &ssLen, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EDECC_INVALID_KEY_LENGTH);
    
    status = ECDH_generateSharedSecretFromPublicByteString(MOC_ECC(gpHwAccelCtx) pPriv, pPub, keyLen - 1, &pSS, &ssLen, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EDECC_INVALID_KEY_LENGTH);
    
    status = ECDH_generateSharedSecretFromPublicByteString(MOC_ECC(gpHwAccelCtx) pPriv, pPub, keyLen + 1, &pSS, &ssLen, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EDECC_INVALID_KEY_LENGTH);
    
    /* Invalid Public keys (get point at infinity and 0 shared secret) */
    for (i = 0; i < numInvalidKeys; ++i)
    {
        /* ok to re-use keyLen param */
        keyLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pInvalidPubKeys[i], &pInvalidPub);
        
        status = ECDH_generateSharedSecretFromPublicByteString(MOC_ECC(gpHwAccelCtx) pPriv, pInvalidPub, keyLen, &pSS, &ssLen, 0, NULL);
        retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EDDH_ZERO_SECRET);
        
        /* free pInvalidPub for next test */
        if(NULL != pInvalidPub)
        {
            status = DIGI_FREE((void **) &pInvalidPub);
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        }
    }
    
exit:
    
    /* pSS should never have been allocated */
    if (NULL != pSS)
    {
        retVal += UNITTEST_INT(__MOC_LINE__, 0, -1);  /* force error */
        status = DIGI_FREE((void **)&pSS);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
    if (NULL != pPriv)
    {
        status = EC_deleteKeyEx(&pPriv);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}
#endif /* defined(__ENABLE_DIGICERT_ECC_EDDH_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDH_448__) */


int crypto_interface_ecc_edwards_dh_unit_test_all()
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
    
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
    
    /* Test edDH on curve25519 */
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 25519;
#endif
    
    for (i = 0; i < COUNTOF(gTestVector_p25519); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p25519 + i, cid_EC_X25519);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }

    retVal += testErrorCases(gpInvalidPubKey_p25519, cid_EC_X25519, COUNTOF(gpInvalidPubKey_p25519));
    
#endif /* __ENABLE_DIGICERT_ECC_EDDH_25519__ */
    
#ifdef __ENABLE_DIGICERT_ECC_EDDH_448__
    
    /* Test edDH on curve448 */
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 448;
#endif
    
    for (i = 0; i < COUNTOF(gTestVector_p448); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p448 + i, cid_EC_X448);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    retVal += testErrorCases(gpInvalidPubKey_p448, cid_EC_X448, COUNTOF(gpInvalidPubKey_p448));
    
#endif /* __ENABLE_DIGICERT_ECC_EDDH_448__ */
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
