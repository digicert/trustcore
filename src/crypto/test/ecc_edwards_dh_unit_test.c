/*
 * ecc_edwards_dh_unit_test.c
 *
 *   unit test for ecc_edwards_dh.h
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

#include "../../common/initmocana.h"
#include "../../crypto/mocasym.h"
#include "../../crypto/ecc_edwards.h"
#include "../../crypto/ecc_edwards_dh.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

static MocCtx gpMocCtx = NULL;

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

static int knownAnswerTest(TestVector *pTestVector, edECCCurve curve)
{
    MSTATUS status = OK;
    int retVal = 0;
    int encodingSize = (curveX25519 == curve ? 32 : 56);
    sbyte4 compare;
    
    edECCKey *pPrivKey = NULL;
    
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
    
    status = edECC_newKey(&pPrivKey, curve, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* will incorrectly set our public key, but that is not used anyway */
    status = edECC_setKeyParameters(pPrivKey, pPubKeyBytes, pubKeyLen, pPrivKeyBytes, privKeyLen, NULL, NULL);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = edDH_GenerateSharedSecret(pPrivKey, pPubKeyBytes, pubKeyLen, &pSharedSecret, &ssLen, NULL);
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
        status = edECC_deleteKey(&pPrivKey, NULL);
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


static int testMultipleIterations(char *pVector[], edECCCurve curve)
{
    MSTATUS status = OK;
    int retVal = 0;
    int encodingSize = (curveX25519 == curve ? 32 : 56);
    sbyte4 compare;
    int count = 0;
    
    ubyte *pZeroIt = NULL;
    ubyte *pOneIt = NULL;
    ubyte *pThousandIt = NULL;
    ubyte *pMillionIt = NULL;
    
    ubyte pU[56] = {0};  /* big enough for either curve */
    ubyte pK[56] = {0};  /* big enough for either curve */
    ubyte pSS[56] = {0}; /* big enough for either curve */
    
    /* we don't need length return value */
    UNITTEST_UTILS_str_to_byteStr((sbyte *) pVector[0], &pZeroIt);
    UNITTEST_UTILS_str_to_byteStr((sbyte *) pVector[1], &pOneIt);
    UNITTEST_UTILS_str_to_byteStr((sbyte *) pVector[2], &pThousandIt);
    UNITTEST_UTILS_str_to_byteStr((sbyte *) pVector[3], &pMillionIt);
    
    DIGI_MEMCPY(pU, pZeroIt, encodingSize);
    DIGI_MEMCPY(pK, pZeroIt, encodingSize);
    
    /* We call the X25519 or X448 method directly */
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
    if (curveX25519 == curve)
    {
        status = CURVE25519_X25519(pSS, pK, pU);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        status = DIGI_MEMCMP(pSS, pOneIt, encodingSize, &compare);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
        count++;
        for (; count < 1000; ++count)
        {
            /* Ignore return codes in loop */
            DIGI_MEMCPY(pU, pK, encodingSize);
            DIGI_MEMCPY(pK, pSS, encodingSize);
            CURVE25519_X25519(pSS, pK, pU);
        }
        
        status = DIGI_MEMCMP(pSS, pThousandIt, encodingSize, &compare);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

#ifdef __ENABLE_MILLION_ITERATIONS__
        for (; count < 1000000; ++count)
        {
            /* Ignore return codes in loop */
            DIGI_MEMCPY(pU, pK, encodingSize);
            DIGI_MEMCPY(pK, pSS, encodingSize);
            CURVE25519_X25519(pSS, pK, pU);
        }
        
        status = DIGI_MEMCMP(pSS, pMillionIt, encodingSize, &compare);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
#endif
    }
#endif /* __ENABLE_DIGICERT_ECC_EDDH_25519__ */

    count = 0;
    
#ifdef __ENABLE_DIGICERT_ECC_EDDH_448__
    if (curveX448 == curve)
    {
        status = CURVE448_X448(pSS, pK, pU);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        status = DIGI_MEMCMP(pSS, pOneIt, encodingSize, &compare);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
        
        count++;
        for (; count < 1000; ++count)
        {
            /* Ignore return codes in loop */
            DIGI_MEMCPY(pU, pK, encodingSize);
            DIGI_MEMCPY(pK, pSS, encodingSize);
            CURVE448_X448(pSS, pK, pU);
        }
        
        status = DIGI_MEMCMP(pSS, pThousandIt, encodingSize, &compare);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

#ifdef __ENABLE_MILLION_ITERATIONS__
        for (; count < 1000000; ++count)
        {
            /* Ignore return codes in loop */
            DIGI_MEMCPY(pU, pK, encodingSize);
            DIGI_MEMCPY(pK, pSS, encodingSize);
            CURVE448_X448(pSS, pK, pU);
        }
        
        status = DIGI_MEMCMP(pSS, pMillionIt, encodingSize, &compare);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
        
        UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
#endif
    }
#endif /* __ENABLE_DIGICERT_ECC_EDDH_448__ */
    
exit:
    
    if (NULL != pZeroIt)
    {
        status = DIGI_FREE((void **) &pZeroIt);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pOneIt)
    {
        status = DIGI_FREE((void **) &pOneIt);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pThousandIt)
    {
        status = DIGI_FREE((void **) &pThousandIt);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pMillionIt)
    {
        status = DIGI_FREE((void **) &pMillionIt);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}


static int testErrorCases(char *pInvalidPubKeys[], edECCCurve curve, ubyte4 numInvalidKeys)
{
    MSTATUS status;
    int retVal = 0;
    int i;
    ubyte4 keyLen = (curveX25519 == curve ? MOC_CURVE25519_BYTE_SIZE : MOC_CURVE448_BYTE_SIZE);
    
    edECCKey keyUnalloc = {0};
    edECCKey *pPriv = NULL;
    ubyte *pInvalidPub = NULL;
    ubyte pValidPriv[MOC_CURVE448_BYTE_SIZE] = {0};  /* big enough for all curves, gets pruned to be valid */
    ubyte pPub[MOC_CURVE448_BYTE_SIZE] = {0};   /* big enough for all curves */
    
    ubyte *pSS = NULL;
    ubyte4 ssLen = 0;
    
    keyUnalloc.curve = curve;
    keyUnalloc.isPrivate = TRUE;

    /* Allocate private key for testing */
    status = edECC_newKey(&pPriv, curve, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* null param */
    status = edDH_GenerateSharedSecret(NULL, pPub, keyLen, &pSS, &ssLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edDH_GenerateSharedSecret(pPriv, NULL, keyLen, &pSS, &ssLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edDH_GenerateSharedSecret(pPriv, pPub, keyLen, NULL, &ssLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = edDH_GenerateSharedSecret(pPriv, pPub, keyLen, &pSS, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* invalid private key */
    status = edDH_GenerateSharedSecret(pPriv, pPub, keyLen, &pSS, &ssLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_INVALID_KEY_TYPE);
    
    status = edDH_GenerateSharedSecret(&keyUnalloc, pPub, keyLen, &pSS, &ssLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EC_UNALLOCATED_KEY);

    pPriv->isPrivate = TRUE;
    pPriv->pPrivKey = pValidPriv;
    
    /* wrong curve alg type */
    pPriv->curve = curveEd25519;
    status = edDH_GenerateSharedSecret(pPriv, pPub, keyLen, &pSS, &ssLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EDECC_INVALID_CURVE_ID_FOR_ALG);
    pPriv->curve = curve;
    
    /* invalid public key length */
    status = edDH_GenerateSharedSecret(pPriv, pPub, 0, &pSS, &ssLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EDECC_INVALID_KEY_LENGTH);
    
    status = edDH_GenerateSharedSecret(pPriv, pPub, keyLen - 1, &pSS, &ssLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EDECC_INVALID_KEY_LENGTH);
    
    status = edDH_GenerateSharedSecret(pPriv, pPub, keyLen + 1, &pSS, &ssLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_EDECC_INVALID_KEY_LENGTH);
    
    /* Invalid Public keys (get point at infinity and 0 shared secret) */
    for (i = 0; i < numInvalidKeys; ++i)
    {
        /* ok to re-use keyLen param */
        keyLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pInvalidPubKeys[i], &pInvalidPub);
        
        status = edDH_GenerateSharedSecret(pPriv, pInvalidPub, keyLen, &pSS, &ssLen, NULL);
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
        status = edECC_deleteKey(&pPriv, NULL);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}
#endif /* defined(__ENABLE_DIGICERT_ECC_EDDH_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDH_448__) */


int ecc_edwards_dh_unit_test_all()
{
    MSTATUS status;
    int retVal = 0;
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
    
#ifdef __ENABLE_DIGICERT_ECC_EDDH_25519__
    
    /* Test edDH on curve25519 */
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 25519;
#endif
    
    for (i = 0; i < COUNTOF(gTestVector_p25519); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p25519 + i, curveX25519);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }

    retVal += testMultipleIterations(gpIterationVector_p25519, curveX25519);
    retVal += testErrorCases(gpInvalidPubKey_p25519, curveX25519, COUNTOF(gpInvalidPubKey_p25519));
    
#endif /* __ENABLE_DIGICERT_ECC_EDDH_25519__ */
    
#ifdef __ENABLE_DIGICERT_ECC_EDDH_448__
    
    /* Test edDH on curve448 */
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 448;
#endif
    
    for (i = 0; i < COUNTOF(gTestVector_p448); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p448 + i, curveX448);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }

    retVal += testMultipleIterations(gpIterationVector_p448, curveX448);
    retVal += testErrorCases(gpInvalidPubKey_p448, curveX448, COUNTOF(gpInvalidPubKey_p448));
    
#endif /* __ENABLE_DIGICERT_ECC_EDDH_448__ */
    
exit:
    
    status = DIGICERT_free(&gpMocCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    
    return retVal;
}
