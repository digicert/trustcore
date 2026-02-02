/*
 * primefld25519_unit_test.c
 *
 *   unit test for primefld25519.c
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

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDH_25519__)

#include "../../crypto/primefld25519.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#define __DEBUG_VECTORS__

#ifdef __DEBUG_VECTORS__
#include <stdio.h>

static int gCurrentVector = 0;

/* Use these macros to output which vector number is failing.
 Make sure retVal is defined. */
#define UNITTEST_VECTOR_STATUS( b, c) if ( UNITTEST_STATUS(b, c) ) {printf("for vector index %d\n", gCurrentVector); retVal++;}
#define UNITTEST_VECTOR_INT( b, c, d) if ( UNITTEST_INT(b, c, d) ) {printf("for vector index %d\n", gCurrentVector); retVal++;}

#else

/* Still make sure retVal is defined. */
#define UNITTEST_VECTOR_STATUS( b, c) retVal += UNITTEST_STATUS(b, c);
#define UNITTEST_VECTOR_INT( b, c, d) retVal += UNITTEST_INT(b, c, d);

#endif

typedef enum TestVectorType {
    match = 0,
    add,
    subtract,
    multiply,
    square,
    specialExp,
    additiveInvert,
    extrema
} TestVectorType;

typedef struct TestVector
{
    char *pInput1;
    char *pInput2;
    char *pResult;
    byteBoolean byteResult;
    TestVectorType type;
    
} TestVector;

#include "primefld25519_data_inc.h"

/* This tests the PF_25519_match method */
static int testMatch(sbyte4 *pInput1, sbyte4 *pInput2, byteBoolean expectedResult)
{
    int retVal = 0;
    byteBoolean match;
    
    match = PF_25519_match(pInput1, pInput2);
    UNITTEST_VECTOR_INT(gCurrentVector, (int) match, (int) expectedResult);
    
    return retVal;
}

/* Tests PF_25519_add */
static int testAdd(sbyte4 *pInput1, sbyte4 *pInput2, sbyte4 *pExpectedResult)
{
    int retVal = 0;
    byteBoolean match;
    int i;
    
    sbyte4 pResult[MOC_NUM_25519_UNITS] = {0};
    
    PF_25519_add(pResult, pInput1, pInput2, i);
    
    match = PF_25519_match(pResult, pExpectedResult);
    UNITTEST_VECTOR_INT(gCurrentVector, (int) match, (int) TRUE);
    
    return retVal;
}

/* Tests PF_25519_subtract */
static int testSubtract(sbyte4 *pInput1, sbyte4 *pInput2, sbyte4 *pExpectedResult)
{
    int retVal = 0;
    byteBoolean match;
    int i;
    
    sbyte4 pResult[MOC_NUM_25519_UNITS] = {0};
    
    PF_25519_subtract(pResult, pInput1, pInput2, i);
    
    match = PF_25519_match(pResult, pExpectedResult);
    UNITTEST_VECTOR_INT(gCurrentVector, (int) match, (int) TRUE);
    
    return retVal;
}

/* Tests PF_25519_multiply */
static int testMultiply(sbyte4 *pInput1, sbyte4 *pInput2, sbyte4 *pExpectedResult)
{
    int retVal = 0;
    byteBoolean match;
    
    sbyte4 pResult[MOC_NUM_25519_UNITS] = {0};
    
    PF_25519_multiply(pResult, pInput1, pInput2);
    
    match = PF_25519_match(pResult, pExpectedResult);
    UNITTEST_VECTOR_INT(gCurrentVector, (int) match, (int) TRUE);
    
    return retVal;
}

/* Tests PF_25519_square */
static int testSquare(sbyte4 *pInput, sbyte4 *pExpectedResult)
{
    int retVal = 0;
    byteBoolean match;
    
    sbyte4 pResult[MOC_NUM_25519_UNITS] = {0};
    
    PF_25519_square(pResult, pInput);
    
    match = PF_25519_match(pResult, pExpectedResult);
    UNITTEST_VECTOR_INT(gCurrentVector, (int) match, (int) TRUE);
    
    return retVal;
}

/* Tests PF_25519_specialExp */
static int testSpecialExp(sbyte4 *pInput, byteBoolean isInverse, sbyte4 *pExpectedResult)
{
    MSTATUS status;
    int retVal = 0;
    byteBoolean match;
    
    sbyte4 pResult[MOC_NUM_25519_UNITS] = {0};
    
    status = PF_25519_specialExp(pResult, pInput, isInverse);
    UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    match = PF_25519_match(pResult, pExpectedResult);
    UNITTEST_VECTOR_INT(gCurrentVector, (int) match, (int) TRUE);
    
exit:
    
    return retVal;
}

/* Tests PF_25519_additiveInvert */
static int testAdditiveInvert(sbyte4 *pInput, sbyte4 *pExpectedResult)
{
    int retVal = 0;
    byteBoolean match;
    int i;
    
    PF_25519_additiveInvert(pInput, i);
    
    match = PF_25519_match(pInput, pExpectedResult);
    UNITTEST_VECTOR_INT(gCurrentVector, (int) match, (int) TRUE);
    
    return retVal;
}


/*
 This tests PF_25519_multiply and PF_25519_square and PF_25519_to_bytes on elements
 whose words reach their extreme values. This is 2^27 - 1 in absolute value for multiply
 and square and 2^26 - 1 for PF_25519_to_bytes. We have...
 
 pMax1 := (2^27-1) * (1 + 2^26 + 2^51 + 2^77 + 2^102 + 2^128 + 2^153 + 2^179 + 2^204 + 2^230);
 pMin1 := -pMax1
 
 pMax2 := (2^26-1) * (1 + 2^26 + 2^51 + 2^77 + 2^102 + 2^128 + 2^153 + 2^179 + 2^204 + 2^230);
 pMin2 := -pMax2
 
 which is in Big Endian hex mod p ...
 
 pMax1 = 0x40000030000008000006000001000000C000002000001800000400004B
 pMin1 = 0x7FFFFFBFFFFFCFFFFFF7FFFFF9FFFFFEFFFFFF3FFFFFDFFFFFE7FFFFFBFFFFA2
 
 pMax2 = 0x1000000000000200000000000040000000000008000000000025
 pMin2 = 0x7FFFFFFFFFFFEFFFFFFFFFFFFDFFFFFFFFFFFFBFFFFFFFFFFFF7FFFFFFFFFFC8
 
 The expected product and square are put in the test vectors to be passed into this method
 (remember pMin1 = - pMax1 so their squares are the same).
 
 Finally we test to bytes on the value 2^255 - 1 (ie 18 or 0x12), which is between
 2^255-19 and 2^255 after its initial reduction rounds and needs an extra reduction step.
 */
static int testExtrema(sbyte4 *pExpectedResult1, sbyte4 *pExpectedResult2)
{
    MSTATUS status;
    int retVal = 0;
    byteBoolean match;
    sbyte4 compare;
    
    /* all coefficients are 2^27 - 1 */
    sbyte4 pMax1[MOC_NUM_25519_UNITS] =
    {
        0x07ffffff,0x07ffffff,0x07ffffff,0x07ffffff,0x07ffffff,
        0x07ffffff,0x07ffffff,0x07ffffff,0x07ffffff,0x07ffffff
    };
    
    /* all coefficients are -2^27 + 1, use -1 * 0x07ffffff in case we're not on 2's compliment system */
    sbyte4 pMin1[MOC_NUM_25519_UNITS] =
    {
        -1 * 0x07ffffff, -1 * 0x07ffffff, -1 * 0x07ffffff, -1 * 0x07ffffff, -1 * 0x07ffffff,
        -1 * 0x07ffffff, -1 * 0x07ffffff, -1 * 0x07ffffff, -1 * 0x07ffffff, -1 * 0x07ffffff,
    };
    
    /* all coefficients are 2^26 - 1 */
    sbyte4 pMax2[MOC_NUM_25519_UNITS] =
    {
        0x03ffffff,0x03ffffff,0x03ffffff,0x03ffffff,0x03ffffff,
        0x03ffffff,0x03ffffff,0x03ffffff,0x03ffffff,0x03ffffff
    };
    
    /* all coefficients are -2^26 + 1, use -1 * 0x03ffffff in case we're not on 2's compliment system */
    sbyte4 pMin2[MOC_NUM_25519_UNITS] =
    {
        -1 * 0x03ffffff, -1 * 0x03ffffff, -1 * 0x03ffffff, -1 * 0x03ffffff, -1 * 0x03ffffff,
        -1 * 0x03ffffff, -1 * 0x03ffffff, -1 * 0x03ffffff, -1 * 0x03ffffff, -1 * 0x03ffffff,
    };
    
    /* all coefficients reach their max  */
    sbyte4 pMax3[MOC_NUM_25519_UNITS] =
    {
        0x03ffffff,0x01ffffff,0x03ffffff,0x01ffffff,0x03ffffff,
        0x01ffffff,0x03ffffff,0x01ffffff,0x03ffffff,0x01ffffff
    };
    
    sbyte4 pResult[MOC_NUM_25519_UNITS] = {0};
    ubyte pResultBuffer[MOC_NUM_25519_BYTES] = {0};
    
    /* expected results, little endian */
    ubyte pExpectedMax2[MOC_NUM_25519_BYTES] =
    {
        0x25,0x00,0x00,0x00,0x00,0x00,0x08,0x00,
        0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,
        0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,
        0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00
    };
    
    ubyte pExpectedMin2[MOC_NUM_25519_BYTES] =
    {
        0xc8,0xff,0xff,0xff,0xff,0xff,0xf7,0xff,
        0xff,0xff,0xff,0xff,0xbf,0xff,0xff,0xff,
        0xff,0xff,0xff,0xfd,0xff,0xff,0xff,0xff,
        0xff,0xef,0xff,0xff,0xff,0xff,0xff,0x7f
    };
    
    ubyte pExpectedMax3[MOC_NUM_25519_BYTES] =
    {
        0x12,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    
    /*  min x min  */
    PF_25519_multiply(pResult, pMin1, pMin1);
    
    match = PF_25519_match(pResult, pExpectedResult1);
    UNITTEST_VECTOR_INT(__MOC_LINE__, (int) match, (int) TRUE);
    
    PF_25519_square(pResult, pMin1);
    
    match = PF_25519_match(pResult, pExpectedResult1);
    UNITTEST_VECTOR_INT(__MOC_LINE__, (int) match, (int) TRUE);
    
    /*  min x max  */
    PF_25519_multiply(pResult, pMax1, pMin1);
    
    match = PF_25519_match(pResult, pExpectedResult2);
    UNITTEST_VECTOR_INT(__MOC_LINE__, (int) match, (int) TRUE);
    
    /*  max x max  */
    PF_25519_multiply(pResult, pMax1, pMax1);
    
    match = PF_25519_match(pResult, pExpectedResult1);
    UNITTEST_VECTOR_INT(__MOC_LINE__, (int) match, (int) TRUE);
    
    PF_25519_square(pResult, pMax1);
    
    match = PF_25519_match(pResult, pExpectedResult1);
    UNITTEST_VECTOR_INT(__MOC_LINE__, (int) match, (int) TRUE);
    
    /* test PF_25519_to_bytes */
    
    PF_25519_to_bytes(pResultBuffer, pMax2);
    
    status = DIGI_MEMCMP(pResultBuffer, pExpectedMax2, MOC_NUM_25519_BYTES, &compare);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
    PF_25519_to_bytes(pResultBuffer, pMin2);
    
    status = DIGI_MEMCMP(pResultBuffer, pExpectedMin2, MOC_NUM_25519_BYTES, &compare);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
    PF_25519_to_bytes(pResultBuffer, pMax3);
    
    status = DIGI_MEMCMP(pResultBuffer, pExpectedMax3, MOC_NUM_25519_BYTES, &compare);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
exit:
    
    return retVal;
}


static int knownAnswerTest(TestVector *pTestVector)
{
    MSTATUS status;
    int retVal = 0;
    int i;
    sbyte4 compare;
    
    sbyte4 pInput1[MOC_NUM_25519_UNITS] = {0};
    sbyte4 pInput2[MOC_NUM_25519_UNITS] = {0};
    sbyte4 pResult[MOC_NUM_25519_UNITS] = {0};
    
    ubyte *pByteBuffer = NULL;
    ubyte4 inputLen = 0;
    ubyte pInputBytes[MOC_NUM_25519_BYTES] = {0};
    
    byteBoolean byteResult = pTestVector->byteResult;
    TestVectorType type = pTestVector->type;
    
    /*
     Set the input and result elements from the test vector.
     Remember test vectors are Big Endian but PF_25519_to/from_bytes convert to/from Little Endian,
     and must have buffers of NUM_25519_BYTES in size. We'll swap Endianness and zero pad if necc.
     
     We'll also test PF_25519_to_bytes at this point for completeness. Note PF_25519_match also
     heavily relies on PF_25519_to_bytes and will certainly be tested many times too with
     "unreduced word" elements (say out of sums and products etc.).
     */
    if (NULL != pTestVector->pInput1)
    {
        inputLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pInput1, &pByteBuffer);
        
        /* sanity check */
        if (inputLen > MOC_NUM_25519_BYTES)
        {
            UNITTEST_STATUS(gCurrentVector, -1); /* force error */
            goto exit;
        }
        
        for (i = 0; i < inputLen; ++i)
        {
            pInputBytes[i] = pByteBuffer[inputLen - 1 - i];
        }
        for (; i < MOC_NUM_25519_BYTES; ++i)
        {
            pInputBytes[i] = 0;
        }
        
        status = PF_25519_from_bytes(pInput1, pInputBytes, TRUE);
        UNITTEST_VECTOR_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;
        
        /* free pByteBuffer to re-use */
        if (NULL != pByteBuffer)
        {
            status = DIGI_FREE((void **) &pByteBuffer);
            UNITTEST_VECTOR_STATUS(gCurrentVector, status);
        }
    }
    
    if (NULL != pTestVector->pInput2)
    {
        inputLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pInput2, &pByteBuffer);
        
        /* sanity check */
        if (inputLen > MOC_NUM_25519_BYTES)
        {
            UNITTEST_STATUS(gCurrentVector, -1); /* force error */
            goto exit;
        }
        
        for (i = 0; i < inputLen; ++i)
        {
            pInputBytes[i] = pByteBuffer[inputLen - 1 - i];
        }
        for (; i < MOC_NUM_25519_BYTES; ++i)
        {
            pInputBytes[i] = 0;
        }
        
        status = PF_25519_from_bytes(pInput2, pInputBytes, TRUE);
        UNITTEST_VECTOR_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;
        
        /* free pByteBuffer to re-use */
        if (NULL != pByteBuffer)
        {
            status = DIGI_FREE((void **) &pByteBuffer);
            UNITTEST_VECTOR_STATUS(gCurrentVector, status);
        }
    }
    
    if (NULL != pTestVector->pResult)
    {
        inputLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pResult, &pByteBuffer);
        
        /* sanity check */
        if (inputLen > MOC_NUM_25519_BYTES)
        {
            UNITTEST_STATUS(gCurrentVector, -1); /* force error */
            goto exit;
        }
        
        for (i = 0; i < inputLen; ++i)
        {
            pInputBytes[i] = pByteBuffer[inputLen - 1 - i];
        }
        for (; i < MOC_NUM_25519_BYTES; ++i)
        {
            pInputBytes[i] = 0;
        }
        
        status = PF_25519_from_bytes(pResult, pInputBytes, TRUE);
        UNITTEST_VECTOR_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;
        
        /* final free of pByteBuffer will happen in exit block */
    }
    
    switch(type)
    {
        case match:
            retVal += testMatch(pInput1, pInput2, byteResult);
            break;
        
        case add:
            retVal += testAdd(pInput1, pInput2, pResult);
            break;
            
        case subtract:
            retVal += testSubtract(pInput1, pInput2, pResult);
            break;
            
        case multiply:
            retVal += testMultiply(pInput1, pInput2, pResult);
            break;
            
        case square:
            retVal += testSquare(pInput1, pResult);
            break;
            
        case specialExp:
            
            /* Test both Inverse and Sqrt modes */
            retVal += testSpecialExp(pInput1, TRUE, pResult);
            retVal += testSpecialExp(pInput1, FALSE, pInput2);  /* use pInput2 as a result field */
            break;
            
        case additiveInvert:
            retVal += testAdditiveInvert(pInput1, pResult);
            break;
            
        case extrema:   /* use input fields as the two expected results */
            retVal += testExtrema(pInput1, pInput2);
        default:
            break;
    }

    if (NULL != pTestVector->pResult)
    {
        ubyte pResultBytes[MOC_NUM_25519_BYTES] = {0};
        
        /* Also test PF_25519_to_bytes on pResult (remember this method mangles the input now) */
        PF_25519_to_bytes(pResultBytes, pResult);
        status = DIGI_MEMCMP(pResultBytes, pInputBytes, MOC_NUM_25519_BYTES, &compare);
        UNITTEST_VECTOR_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;
        
        UNITTEST_VECTOR_INT(gCurrentVector, compare, 0);
    }
    
exit:
    
    if (NULL != pByteBuffer)
    {
        status = DIGI_FREE((void **) &pByteBuffer);
        UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    }
    
    return retVal;
}


/*
 Most methods are treated as internal and don't have error case returns.
 Only PF_25519_from_bytes needs to be tested.
 */
static int testErrorCases()
{
    int retVal = 0;
    MSTATUS status = OK;
    
    sbyte4 pResult[MOC_NUM_25519_UNITS] = {0};
    
    /* Little Endian p */
    ubyte pTooLarge[MOC_NUM_25519_BYTES] =
    {
        0xed,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f,
    };
    
    /******* PF_25519_from_bytes *******/
    
    /* p */
    status = PF_25519_from_bytes(pResult, pTooLarge, TRUE);
    retVal = UNITTEST_INT(__MOC_LINE__, (int) status, ERR_FF_DIFFERENT_FIELDS);
    
    /* p + 1 */
    pTooLarge[0]++;
    status = PF_25519_from_bytes(pResult, pTooLarge, TRUE);
    retVal = UNITTEST_INT(__MOC_LINE__, (int) status, ERR_FF_DIFFERENT_FIELDS);
    
    /* 2^255 - 1 */
    pTooLarge[0] = 0xff;
    status = PF_25519_from_bytes(pResult, pTooLarge, TRUE);
    retVal = UNITTEST_INT(__MOC_LINE__, (int) status, ERR_FF_DIFFERENT_FIELDS);
    
    /* 2^256 - 1 */
    pTooLarge[31] = 0xff;
    status = PF_25519_from_bytes(pResult, pTooLarge, TRUE);
    retVal = UNITTEST_INT(__MOC_LINE__, (int) status, ERR_FF_DIFFERENT_FIELDS);
    
    return retVal;
}
#endif /* defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDH_25519__) */

int primefld25519_unit_test_all()
{
    int retVal = 0;

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDH_25519__)
    int i;
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
#endif
    for (i = 0; i < COUNTOF(gTestVector); ++i)
    {
        retVal += knownAnswerTest(gTestVector+i);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    retVal += testErrorCases();
    
    DBG_DUMP
#endif /* defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDH_25519__) */

    return retVal;
}
