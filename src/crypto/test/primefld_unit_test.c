/*
 * primefld_unit_test.c
 *
 *   unit test for primefld.c
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
#include "../../crypto/primefld.h"
#include "../../crypto/primefld_priv.h"

#ifdef __ENABLE_DIGICERT_ECC__  /* test is ecc focused, no worry about __ENABLE_DIGICERT_RSA_SIMPLE__ */

#ifdef __ENABLE_DIGICERT_VLONG_ECC_CONVERSION__
#include "../../common/vlong.h"
#endif

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#define __DEBUG_VECTORS__

#ifdef __DEBUG_VECTORS__
#include <stdio.h>

static int gCurrentVector = 0;
static int gTestField = 0;

/* Use these macros to output which vector number is failing.
 Make sure retVal is defined. */
#define UNITTEST_VECTOR_STATUS( b, c) if ( UNITTEST_STATUS(b, c) ) {printf("for vector index %d in gTestVector_p%d\n", gCurrentVector, gTestField); retVal++;}
#define UNITTEST_VECTOR_INT( b, c, d) if ( UNITTEST_INT(b, c, d) ) {printf("for vector index %d in gTestVector_p%d\n", gCurrentVector, gTestField); retVal++;}

#else

/* Still make sure retVal is defined. */
#define UNITTEST_VECTOR_STATUS( b, c) retVal += UNITTEST_STATUS(b, c);
#define UNITTEST_VECTOR_INT( b, c, d) retVal += UNITTEST_INT(b, c, d);

#endif

typedef enum TestVectorType {
    cmp = 0,
    copy,
    add,
    subtract,
    xor,
    multiply,
    shiftR,
    getBit,
    inverse,
    divide,
    cmpToUnsigned,
    barrettMultiply,
    addAux,
    inverseAux,
    squareAux,
    exponentiate,
    specialExp,
    additiveInvert,
    squareRoot
} TestVectorType;

typedef struct TestVector
{
    char *pfInput1;
    char *pfInput2;
    char *pfResult;
    ubyte4 byteInput;
    sbyte4 byteResult;
    TestVectorType type;
    
} TestVector;

#ifdef __ENABLE_DIGICERT_ECC_P192__
#include "primefld_data_192_inc.h"
#endif

#ifndef __DISABLE_DIGICERT_ECC_P224__
#include "primefld_data_224_inc.h"
#endif

#ifndef __DISABLE_DIGICERT_ECC_P256__
#include "primefld_data_256_inc.h"
#endif

#ifndef __DISABLE_DIGICERT_ECC_P384__
#include "primefld_data_384_inc.h"
#endif

#ifndef __DISABLE_DIGICERT_ECC_P521__
#include "primefld_data_521_inc.h"
#endif

/* allocates memory for the PFEPtr result and sets it to the value in str */
static MSTATUS PrimeFldFromStr( PrimeFieldPtr pField, const char *str, ubyte4 *unitLen, PFEPtr *result)
{
    MSTATUS status = OK;
    ubyte *bytes = NULL;
    ubyte4 byteLen;
    
    status = PRIMEFIELD_newElement(pField, result);
    if(OK != status)
        goto exit;
    
    byteLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) str, &bytes);
    status = PRIMEFIELD_setToByteString(pField, *result, bytes, (sbyte4) byteLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    
    *unitLen = pField->n;
    
exit:
    
    if (NULL != bytes)
        status = DIGI_FREE((void **) &bytes);
    
    return status;
}

/* This tests PRIMEFIELD_cmp and PRIMEFIELD_match methods */
static int testCmp(PrimeFieldPtr pField, PFEPtr pfInput1, PFEPtr pfInput2, sbyte4 expectedResult)
{
    int retVal = 0;
    sbyte compare;
    intBoolean match;
    intBoolean expected_match = expectedResult ? FALSE : TRUE;
    
    compare = PRIMEFIELD_cmp(pField, pfInput1, pfInput2);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, expectedResult);
    
    /* we also test the PRIMEFIELD_match function */
    match = PRIMEFIELD_match(pField, pfInput1, pfInput2);
    UNITTEST_VECTOR_INT(__MOC_LINE__, match, expected_match);
    
    return retVal;
}

static int testCopy(PrimeFieldPtr pField, PFEPtr pfInput1, PFEPtr pExpectedResult)
{
    int retVal = 0;
    MSTATUS status = OK;
    int i;
    sbyte compare;
    
    PFEPtr pCopy = NULL;
    
    status = PRIMEFIELD_newElement(pField, &pCopy);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* set copy to junk just to ensure PRIMEFIELD_copyElement overwites all words */
    for (i = 0; i < pField->n; ++i)
    {
#ifdef __ENABLE_DIGICERT_64_BIT__
        pCopy->units[i] = 0xfedcba9876543210ULL;
#else
        pCopy->units[i] = 0xfedcba98;
#endif
    }
    
    status = PRIMEFIELD_copyElement(pField, pCopy, pfInput1);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* test they are the same */
    compare = PRIMEFIELD_cmp(pField, pCopy, pExpectedResult);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
exit:
    
    if (NULL != pCopy)
    {
        status = PRIMEFIELD_deleteElement(pField, &pCopy);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}

/* Tests PRIMEFIELD_add and if curve448 is enabled, PRIMEFIELD_add2 */
static int testAdd(PrimeFieldPtr pField, PFEPtr pfInput1, PFEPtr pfInput2, PFEPtr pExpectedResult)
{
    int retVal = 0;
    MSTATUS status = OK;
    sbyte4 compare;
    
    /* inplace addition, pfInput1 will hold the result */
    status = PRIMEFIELD_add(pField, pfInput1, pfInput2);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* test we got the expected result */
    compare = PRIMEFIELD_cmp(pField, pfInput1, pExpectedResult);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
exit:
    
    return retVal;
}

/* Tests PRIMEFIELD_subtract and if curve448 is enabled, PRIMEFIELD_subtract2 */
static int testSubtract(PrimeFieldPtr pField, PFEPtr pfInput1, PFEPtr pfInput2, PFEPtr pExpectedResult)
{
    int retVal = 0;
    MSTATUS status = OK;
    sbyte4 compare;
    
    /* inplace subtraction, pfInput1 will hold the result */
    status = PRIMEFIELD_subtract(pField, pfInput1, pfInput2);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* test we got the expected result */
    compare = PRIMEFIELD_cmp(pField, pfInput1, pExpectedResult);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
exit:
    
    return retVal;
}

static int testXor(PrimeFieldPtr pField, PFEPtr pfInput1, PFEPtr pfInput2, PFEPtr pExpectedResult)
{
    int retVal = 0;
    MSTATUS status = OK;
    sbyte4 compare;
    
    /* inplace xor, pfInput1 will hold the result */
    status = PRIMEFIELD_xor(pField, pfInput1, pfInput2);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* test we got the expected result */
    compare = PRIMEFIELD_cmp(pField, pfInput1, pExpectedResult);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
exit:
    
    return retVal;
}

/* Also tests the PRIMEFIELD_multiplyAux method */
static int testMultiply(PrimeFieldPtr pField, PFEPtr pfInput1, PFEPtr pfInput2, PFEPtr pExpectedResult)
{
    int retVal = 0;
    MSTATUS status = OK;
    sbyte compare;
    
#ifdef __ENABLE_DIGICERT_64_BIT__
    pf_unit hilo[34] = {0}; /* enough room for two p521 products */
#else
    pf_unit hilo[68] = {0}; /* enough room for two p521 products */
#endif
    
    PFEPtr pProduct = NULL;
    
    status = PRIMEFIELD_newElement(pField, &pProduct);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    status = PRIMEFIELD_multiply(pField, pProduct, pfInput1, pfInput2);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* test we got the expected result */
    compare = PRIMEFIELD_cmp(pField, pProduct, pExpectedResult);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
    /* Also reset product and test PRIMEFIELD_multiplyAux */
    if (NULL != pProduct)
    {
        status = PRIMEFIELD_deleteElement(pField, &pProduct);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    
    status = PRIMEFIELD_newElement(pField, &pProduct);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    status = PRIMEFIELD_multiplyAux(pField, pProduct, pfInput1, pfInput2, hilo);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* test we got the expected result */
    compare = PRIMEFIELD_cmp(pField, pProduct, pExpectedResult);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
exit:
    
    if (NULL != pProduct)
    {
        status = PRIMEFIELD_deleteElement(pField, &pProduct);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}

static int testShiftR(PrimeFieldPtr pField, PFEPtr pfInput1, PFEPtr pExpectedResult)
{
    int retVal = 0;
    MSTATUS status = OK;
    sbyte4 compare;
    
    /* inplace shift, pfInput1 will hold the result */
    status = PRIMEFIELD_shiftR(pField, pfInput1);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* test we got the expected result */
    compare = PRIMEFIELD_cmp(pField, pfInput1, pExpectedResult);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
exit:
    
    return retVal;
}

static int testGetBit(PrimeFieldPtr pField, PFEPtr pfInput1, ubyte4 bitNum, ubyte expectedResult)
{
    int retVal = 0;
    MSTATUS status = OK;
    ubyte result;
    
    /* inplace shift, pfInput1 will hold the result */
    status = PRIMEFIELD_getBit(pField, pfInput1, bitNum, &result);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* test we got the expected result */
    UNITTEST_VECTOR_INT(__MOC_LINE__, result, expectedResult);
    
exit:
    
    return retVal;
}

static int testInverse(PrimeFieldPtr pField, PFEPtr pfInput1, PFEPtr pExpectedResult)
{
    int retVal = 0;
    MSTATUS status = OK;
    sbyte compare;
    
    PFEPtr pInverse = NULL;
    
    status = PRIMEFIELD_newElement(pField, &pInverse);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    status = PRIMEFIELD_inverse(pField, pInverse, pfInput1);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* test we got the expected result */
    compare = PRIMEFIELD_cmp(pField, pInverse, pExpectedResult);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
exit:
    
    if (NULL != pInverse)
    {
        status = PRIMEFIELD_deleteElement(pField, &pInverse);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}

/* divide is multiplication by the inverse */
static int testDivide(PrimeFieldPtr pField, PFEPtr pfInput1, PFEPtr pfInput2, PFEPtr pExpectedResult)
{
    int retVal = 0;
    MSTATUS status = OK;
    sbyte compare;
    
    PFEPtr pResult = NULL;
    
    status = PRIMEFIELD_newElement(pField, &pResult);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    status = PRIMEFIELD_divide(pField, pResult, pfInput1, pfInput2);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* test we got the expected result */
    compare = PRIMEFIELD_cmp(pField, pResult, pExpectedResult);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
exit:
    
    if (NULL != pResult)
    {
        status = PRIMEFIELD_deleteElement(pField, &pResult);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}

static int testCmpToUnsigned(PrimeFieldPtr pField, PFEPtr pfInput1, ubyte4 byteInput, sbyte expectedResult)
{
    int retVal = 0;
    sbyte compare;
    
    compare = PRIMEFIELD_cmpToUnsigned(pField, pfInput1, byteInput);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, expectedResult);
    
    return retVal;
}

/*
 The BarrettMultiply routine is for a multiply and modular reduction via the curve order!
 This is used in ECDSA. The values being reduced are still already reduced mod p
 */
static int testBarrettMultiply(PrimeFieldPtr pField, PFEPtr pfInput1, PFEPtr pfInput2, pf_unit *pN, pf_unit *pMu, PFEPtr pExpectedResult)
{
    int retVal = 0;
    MSTATUS status = OK;
    sbyte compare;
    
    PFEPtr pProduct = NULL;
    
    status = PRIMEFIELD_newElement(pField, &pProduct);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* Test the PRIMEFIELD_barrettMultiply method */
    status = PRIMEFIELD_barrettMultiply(pField, pProduct, pfInput1, pfInput2, (PFEPtr) pN, (PFEPtr) pMu);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* test we got the expected result */
    compare = PRIMEFIELD_cmp(pField, pProduct, pExpectedResult);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
exit:
    
    if (NULL != pProduct)
    {
        status = PRIMEFIELD_deleteElement(pField, &pProduct);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}

/*
 The addAux routine is for addition and modular reduction via the curve order!
 This is used in ECDSA. The values being reduced are still already reduced mod p.
 */
static int testAddAux(PrimeFieldPtr pField, PFEPtr pfInput1, PFEPtr pfInput2, pf_unit *pN, PFEPtr pExpectedResult)
{
    int retVal = 0;
    MSTATUS status = OK;
    sbyte4 compare;
    
    /* inplace addition, pfInput1 will hold the result */
    status = PRIMEFIELD_addAux(pField, pfInput1, pfInput2, (PFEPtr) pN);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* test we got the expected result */
    compare = PRIMEFIELD_cmp(pField, pfInput1, pExpectedResult);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
exit:
    
    return retVal;
}

/*
 The addAux routine is for modular inverses via the curve order!
 This is used in ECDSA. The value being inverted is still already reduced mod p.
 */
static int testInverseAux(PrimeFieldPtr pField, PFEPtr pfInput1, pf_unit *pN, PFEPtr pExpectedResult)
{
    int retVal = 0;
    MSTATUS status = OK;
    sbyte compare;
    
    PFEPtr pInverse = NULL;
    
    status = PRIMEFIELD_newElement(pField, &pInverse);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    status = PRIMEFIELD_inverseAux(pField->n, pInverse, pfInput1, (PFEPtr) pN);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* test we got the expected result */
    compare = PRIMEFIELD_cmp(pField, pInverse, pExpectedResult);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
exit:
    
    if (NULL != pInverse)
    {
        status = PRIMEFIELD_deleteElement(pField, &pInverse);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}

static int testSquareAux(PrimeFieldPtr pField, PFEPtr pfInput1, PFEPtr pExpectedResult)
{
    int retVal = 0;
    MSTATUS status = OK;
    sbyte compare;
    
#ifdef __ENABLE_DIGICERT_64_BIT__
    pf_unit hilo[34] = {0}; /* enough room for two p521 products */
#else
    pf_unit hilo[68] = {0}; /* enough room for two p521 products */
#endif
    
    PFEPtr pSquare = NULL;
    
    status = PRIMEFIELD_newElement(pField, &pSquare);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    status = PRIMEFIELD_squareAux(pField, pSquare, pfInput1, hilo);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* test we got the expected result */
    compare = PRIMEFIELD_cmp(pField, pSquare, pExpectedResult);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
exit:
    
    if (NULL != pSquare)
    {
        status = PRIMEFIELD_deleteElement(pField, &pSquare);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}

static int testExponentiate(PrimeFieldPtr pField, PFEPtr pfInput1, PFEPtr pfInput2, PFEPtr pExpectedResult)
{
    int retVal = 0;
    MSTATUS status = OK;
    sbyte compare;
    
#ifdef __ENABLE_DIGICERT_64_BIT__
    pf_unit hilo[34] = {0}; /* enough room for two p521 products */
#else
    pf_unit hilo[68] = {0}; /* enough room for two p521 products */
#endif
    
    PFEPtr pResult = NULL;
    
    status = PRIMEFIELD_newElement(pField, &pResult);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    status = PRIMEFIELD_exp(pField, pResult, pfInput1, pfInput2, hilo);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* test we got the expected result */
    compare = PRIMEFIELD_cmp(pField, pResult, pExpectedResult);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
exit:
    
    if (NULL != pResult)
    {
        status = PRIMEFIELD_deleteElement(pField, &pResult);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}

/* square root method is only available for ecc ElGamal */
#ifdef __ENABLE_DIGICERT_ECC_ELGAMAL__
/*
 Tests the PRIMEFIELD_squareRoot method. If pExpectedResult is NULL it means that
 no square root exists
 */
static int testSquareRoot(PrimeFieldPtr pField, PFEPtr pfInput1, PFEPtr pExpectedResult)
{
    int retVal = 0;
    MSTATUS status = OK;
    sbyte compare;
    
    PFEPtr pSquareRoot = NULL;
    PFEPtr pTemp = NULL;
    
    status = PRIMEFIELD_newElement(pField, &pSquareRoot);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    status = PRIMEFIELD_squareRoot(pField, pSquareRoot, pfInput1);
    if (NULL != pExpectedResult)
    {
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;
    
        /* test we got the expected result OR its negative, either answer is fine */
        compare = PRIMEFIELD_cmp(pField, pSquareRoot, pExpectedResult);
        if (compare)
        {
            /* invert the long way since PRIMEFILED_additiveInvert may not be defined */
            status = PRIMEFIELD_newElement(pField, &pTemp); /* zero by default */
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
            if(OK != status)
                goto exit;
            
            status = PRIMEFIELD_subtract(pField, pTemp, pSquareRoot);
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
            if(OK != status)
                goto exit;
            
            compare = PRIMEFIELD_cmp(pField, pTemp, pExpectedResult);
        }
        UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    }
    else
    {
        UNITTEST_VECTOR_INT(__MOC_LINE__, (int) status, (int) ERR_NOT_FOUND);
    }

exit:
    
    if (NULL != pSquareRoot)
    {
        status = PRIMEFIELD_deleteElement(pField, &pSquareRoot);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    
    if (NULL != pTemp)
    {
        status = PRIMEFIELD_deleteElement(pField, &pTemp);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}
#endif /* __ENABLE_DIGICERT_ECC_ELGAMAL__ */

/*
 This test creates PFE elements using the PRIMEFIELD_setToUnsigned method. We look inside
 the structure of the PFE to ensure it was correctly formed.
 */
static int testSetElementUbyte(PrimeFieldPtr pField, ubyte4 value)
{
    MSTATUS status = OK;
    int retVal = 0;
    int i;
    
    PFEPtr pElement = NULL;
    
    /* Allocate space for a new pElement */
    status = PRIMEFIELD_newElement(pField, &pElement);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* Set units to garbage just to ensure they are overwritten */
    for (i = 0; i < pField->n; ++i)
    {
#ifdef __ENABLE_DIGICERT_64_BIT__
        pElement->units[i] = 0x123456789abcdef0ULL;
#else
        pElement->units[i] = 0x12345678;
#endif
    }
    
    /* Test PRIMEFIELD_setToUnsigned */
    
    status = PRIMEFIELD_setToUnsigned(pField, pElement, value);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* First unit should be the value, all others are zero (remember, Little Endian) */
    
#ifdef __ENABLE_DIGICERT_64_BIT__
    retVal += UNITTEST_INT(__MOC_LINE__, (int)(pElement->units[0] & 0xffffffffull), value);
#else
    retVal += UNITTEST_INT(__MOC_LINE__, pElement->units[0], value);
#endif
    
    for (i = 1; i < pField->n; ++i)
    {
        retVal += UNITTEST_INT(__MOC_LINE__, (int) pElement->units[i], 0);
    }
    
exit:
    
    if(NULL != pElement)
    {
        status = PRIMEFIELD_deleteElement(pField, &pElement);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}


/*
 This test creates PFE elements using the PRIMEFIELD_setToByteString method.
 We look inside the structure of the PFE to ensure it was correctly formed.
 Then we test the get methods have the correct output.
 */
static int testSetGetElementArray(PrimeFieldPtr pField, ubyte *pArray, sbyte4 arrayLen)
{
    MSTATUS status = OK;
    int retVal = 0;
    int i,j;
    
    pf_unit temp;
    
    PFEPtr pElement = NULL;
    
    ubyte *pOutBuffer = NULL;
    sbyte4 outLen = 0;
    ubyte writeBuffer[66] = {0x00};
    sbyte4 compare;
    
    /* Allocate space for a new pElement */
    status = PRIMEFIELD_newElement(pField, &pElement);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* set pElement to junk just to ensure set methods overwite all words */
    for (i = 0; i < pField->n; ++i)
    {
#ifdef __ENABLE_DIGICERT_64_BIT__
        pElement->units[i] = 0xfedcba9876543210ULL;
#else
        pElement->units[i] = 0xfedcba98;
#endif
    }
    
    /* Test PRIMEFIELD_setToByteString */
    status = PRIMEFIELD_setToByteString(pField, pElement, pArray, arrayLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /* create the value of each unit from the byte array directly */
    
    for (i = 0, j = arrayLen - 1; i < pField->n; ++i, j -= sizeof(pf_unit))
    {
        
#ifdef __ENABLE_DIGICERT_64_BIT__
        
        temp = 0ULL;
        
        if (j >= 7)
        {
            temp |= ((pf_unit) pArray[j - 7]) << 56;
        }
        if (j >= 6)
        {
            temp |= ((pf_unit) pArray[j - 6]) << 48;
        }
        if (j >= 5)
        {
            temp |= ((pf_unit) pArray[j - 5]) << 40;
        }
        if (j >= 4)
        {
            temp |= ((pf_unit) pArray[j - 4]) << 32;
        }
        if (j >= 3)
        {
            temp |= ((pf_unit) pArray[j - 3]) << 24;
        }
        if (j >= 2)
        {
            temp |= ((pf_unit) pArray[j - 2]) << 16;
        }
        if (j >= 1)
        {
            temp |= ((pf_unit) pArray[j - 1]) << 8;
        }
        if (j >= 0)
        {
            temp |= (pf_unit) pArray[j];
        }
        
        retVal += UNITTEST_INT(__MOC_LINE__, (int)(pElement->units[i] & 0xffffffffull), (int) (temp & 0xffffffffull));
        retVal += UNITTEST_INT(__MOC_LINE__, (int)((pElement->units[i]>>32) & 0xffffffffull), (int) ((temp>>32) & 0xffffffffull));
#else
        
        temp = 0;
        
        if (j >= 3)
        {
            temp |= pArray[j - 3] << 24;
        }
        if (j >= 2)
        {
            temp |= pArray[j - 2] << 16;
        }
        if (j >= 1)
        {
            temp |= pArray[j - 1] << 8;
        }
        if (j >= 0)
        {
            temp |= pArray[j];
        }
        
        retVal += UNITTEST_INT(__MOC_LINE__, pElement->units[i], temp);
        
#endif
        
    } /* end for */
    
    /* Test PRIMEFIELD_getElementByteStringLen */
    status = PRIMEFIELD_getElementByteStringLen(pField, &outLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    retVal += UNITTEST_INT(__MOC_LINE__, outLen, (pField->numBits + 7)/8);
    
    /* Now test PRIMEFIELD_getAsByteString */
    status = PRIMEFIELD_getAsByteString(pField, pElement, &pOutBuffer, &outLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    
    /* note: the above method allocates a buffer of (pField->numBits + 7)/8 length */
    retVal += UNITTEST_INT(__MOC_LINE__, outLen, (pField->numBits + 7)/8);
    
    /* Compare against the input buffer, consider padding */
    retVal += UNITTEST_STATUS(__MOC_LINE__, DIGI_MEMCMP(pOutBuffer + outLen - arrayLen, pArray, arrayLen, &compare));
    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);
    
    /* free pOutBuffer so it can be used again */
    status = DIGI_FREE((void **) &pOutBuffer);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    
    /* Now test PRIMEFIELD_getAsByteString2 (which just writes out 2 pElements to one buffer) */
    status = PRIMEFIELD_getAsByteString2(pField, pElement, pElement, &pOutBuffer, &outLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    
    /* note: the above method allocates a buffer of 2*(pField->numBits + 7)/8 length */
    retVal += UNITTEST_INT(__MOC_LINE__, outLen, 2*((pField->numBits + 7)/8));
    
    /* Compare each half of pOutBuffer against the input buffer, consider padding */
    retVal += UNITTEST_STATUS(__MOC_LINE__, DIGI_MEMCMP(pOutBuffer + outLen/2 - arrayLen, pArray, arrayLen, &compare));
    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);
    
    retVal += UNITTEST_STATUS(__MOC_LINE__, DIGI_MEMCMP(pOutBuffer + outLen - arrayLen, pArray, arrayLen, &compare));
    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);
    
    /* Test PRIMEFIELD_writeByteString which write to a preallocated buffer */
    
    status = PRIMEFIELD_writeByteString(pField, pElement, writeBuffer, (sbyte4) sizeof(writeBuffer));
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    
    /* Compare against the input buffer, consider padding */
    retVal += UNITTEST_STATUS(__MOC_LINE__, DIGI_MEMCMP(writeBuffer + sizeof(writeBuffer) - arrayLen, pArray, arrayLen, &compare));
    retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);
    
exit:
    
    if(NULL != pElement)
    {
        status = PRIMEFIELD_deleteElement(pField, &pElement);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if(NULL != pOutBuffer)
    {
        status = DIGI_FREE((void **) &pOutBuffer);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}

#ifdef __ENABLE_DIGICERT_VLONG_ECC_CONVERSION__

/*
 This tests the PRIMEFIELD_newVlongFromElement() method, followed by the
 PRIMEFIELD_newElementFromVlong() method (so a roundtrip from a PFE to
 a vlong to a PFE). The process is repeated with use of a vlong queue.
 */
static int testGetSetFromVlong(PrimeFieldPtr pField, ubyte *pArray, sbyte4 arrayLen)
{
    MSTATUS status = OK;
    int retVal = 0;
    
    vlong *pVlongElement = NULL;
    PFEPtr pElement = NULL;
    PFEPtr pElementConverted = NULL;
    
    sbyte4 compare;
    
    vlong *pQueue = NULL;
    
    /* Allocate space for a new pElement */
    status = PRIMEFIELD_newElement(pField, &pElement);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* Create the PFE element */
    status = PRIMEFIELD_setToByteString(pField, pElement, pArray, arrayLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* Convert to a vlong */
    status = PRIMEFIELD_newVlongFromElement(pField, pElement, &pVlongElement, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* Convert back to a PFE element */
    status = PRIMEFIELD_newElementFromVlong(pField, pVlongElement, &pElementConverted);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* Make sure pElementConverted is the same as pElement */
    compare = PRIMEFIELD_cmp(pField, pElementConverted, pElement);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
    /* Free pVlongElement and pElementConverted so we can retest with the vlong queue */
    if (NULL != pVlongElement)
    {
        status = VLONG_freeVlong( &pVlongElement, NULL);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;
    }
    if (NULL != pElementConverted)
    {
        status = PRIMEFIELD_deleteElement(pField, &pElementConverted);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;
    }
    
    /* Convert to a vlong using pQueue */
    status = PRIMEFIELD_newVlongFromElement(pField, pElement, &pVlongElement, &pQueue);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* Convert back to a PFE element */
    status = PRIMEFIELD_newElementFromVlong(pField, pVlongElement, &pElementConverted);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /* Make sure pElementConverted is the same as pElement */
    compare = PRIMEFIELD_cmp(pField, pElementConverted, pElement);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    
exit:
    
    if (NULL != pElement)
    {
        status = PRIMEFIELD_deleteElement(pField, &pElement);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pVlongElement)
    {
        status = VLONG_freeVlong( &pVlongElement, &pQueue);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pElementConverted)
    {
        status = PRIMEFIELD_deleteElement(pField, &pElementConverted);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pQueue)
    {
        status = VLONG_freeVlongQueue (&pQueue);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}

/*
 This tests the PRIMEFIELD_getPrime() method, which sets a vlong
 to the prime modulus. primeLen is the byte length of the prime.
 */
static int testGetPrime(PrimeFieldPtr pField, ubyte *primeBytes, ubyte4 primeLen)
{
    MSTATUS status = OK;
    int retVal = 0;
    int i,j;
    
    vlong *pPrime = NULL;
    vlong_unit temp;
    
    status = PRIMEFIELD_getPrime(pField, &pPrime);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
    
    /*
     check that pPrime is the correct value by recreating
     its digits from scratch.
     */
    for (i = 0, j = primeLen - 1; i < pField->n; ++i, j -= sizeof(vlong_unit))
    {
        
#ifdef __ENABLE_DIGICERT_64_BIT__
        
        temp = 0ULL;
        
        if (j >= 7)
        {
            temp |= ((vlong_unit) primeBytes[j - 7]) << 56;
        }
        if (j >= 6)
        {
            temp |= ((vlong_unit) primeBytes[j - 6]) << 48;
        }
        if (j >= 5)
        {
            temp |= ((vlong_unit) primeBytes[j - 5]) << 40;
        }
        if (j >= 4)
        {
            temp |= ((vlong_unit) primeBytes[j - 4]) << 32;
        }
        if (j >= 3)
        {
            temp |= ((vlong_unit) primeBytes[j - 3]) << 24;
        }
        if (j >= 2)
        {
            temp |= ((vlong_unit) primeBytes[j - 2]) << 16;
        }
        if (j >= 1)
        {
            temp |= ((vlong_unit) primeBytes[j - 1]) << 8;
        }
        if (j >= 0)
        {
            temp |= (vlong_unit) primeBytes[j];
        }
        
        retVal += UNITTEST_INT(__MOC_LINE__, (int)(pPrime->pUnits[i] & 0xffffffffull), (int) (temp & 0xffffffffull));
        retVal += UNITTEST_INT(__MOC_LINE__, (int)((pPrime->pUnits[i]>>32) & 0xffffffffull), (int) ((temp>>32) & 0xffffffffull));
        
#else
        
        temp = 0;
        
        if (j >= 3)
        {
            temp |= primeBytes[j - 3] << 24;
        }
        if (j >= 2)
        {
            temp |= primeBytes[j - 2] << 16;
        }
        if (j >= 1)
        {
            temp |= primeBytes[j - 1] << 8;
        }
        if (j >= 0)
        {
            temp |= primeBytes[j];
        }
        
        retVal += UNITTEST_INT(__MOC_LINE__, pPrime->pUnits[i], temp);
        
#endif /* __ENABLE_DIGICERT_64_BIT__ */
        
    } /* end for */
    
exit:
    
    if (NULL != pPrime)
    {
        status = VLONG_freeVlong( &pPrime, 0);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}

/*
 This tests the PRIMEFIELD_newElementFromMpint() method, followed by the
 PRIMEFIELD_newMpintFromElement() method (so a roundtrip from a byte array
 to a PFE element to a byte array). The process is repeated with use of a vlong queue.
 */
static int testGetSetFromMpint(PrimeFieldPtr pField, ubyte *pArray, ubyte4 arrayLen)
{
    MSTATUS status = OK;
    int retVal = 0;
    
    PFEPtr pElement = NULL;
    
    ubyte *pOutBuffer = NULL;
    sbyte4 outLen = 0;
    
    sbyte4 compare;
    ubyte4 arrayPosition = 0;
    ubyte4 previousPosition = 0; /* keeps track of the previous arrayPosition for buffer comparisons */
    
    vlong *pQueue = NULL;
    
    while (arrayPosition < arrayLen){
        
        previousPosition = arrayPosition;
        
        /* Test creating a PFE element from the byte array.
         This allocates the new element and increments arrayPosition to the next mpint */
        status = PRIMEFIELD_newElementFromMpint(pArray, arrayLen, &arrayPosition, pField, &pElement);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;
        
        /* Test converting that element back to a byte array */
        status = PRIMEFIELD_newMpintFromElement(pField, pElement, &pOutBuffer, &outLen, NULL);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;
        
        /* compare against the original, first check the number of bytes written */
        retVal += UNITTEST_INT(__MOC_LINE__, outLen, arrayPosition - previousPosition);
        retVal += UNITTEST_STATUS(__MOC_LINE__, DIGI_MEMCMP(pOutBuffer, pArray + previousPosition, outLen, &compare));
        retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);
        
        /* free pOutBuffer so we can test again with the vlong queue */
        if (NULL != pOutBuffer)
        {
            status = DIGI_FREE((void **) &pOutBuffer);
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            if(OK != status)
                goto exit;
        }
        
        /* Test converting that element back to a byte array with the vlong queue */
        status = PRIMEFIELD_newMpintFromElement(pField, pElement, &pOutBuffer, &outLen, &pQueue);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;
        
        /* compare against the original, first check the number of bytes written */
        retVal += UNITTEST_INT(__MOC_LINE__, outLen, arrayPosition - previousPosition);
        retVal += UNITTEST_STATUS(__MOC_LINE__, DIGI_MEMCMP(pOutBuffer, pArray + previousPosition, outLen, &compare));
        retVal += UNITTEST_INT(__MOC_LINE__, compare, 0);
        
        /* free pOutBuffer and pElement so they can be created and used again */
        if (NULL != pElement)
        {
            status = PRIMEFIELD_deleteElement(pField, &pElement);
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            if(OK != status)
                goto exit;
        }
        if (NULL != pOutBuffer)
        {
            status = DIGI_FREE((void **) &pOutBuffer);
            retVal += UNITTEST_STATUS(__MOC_LINE__, status);
            if(OK != status)
                goto exit;
        }
        
    }
    
exit:
    
    if (NULL != pElement)
    {
        status = PRIMEFIELD_deleteElement(pField, &pElement);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pOutBuffer)
    {
        status = DIGI_FREE((void **) &pOutBuffer);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pQueue)
    {
        status = VLONG_freeVlongQueue (&pQueue);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}

#endif /* __ENABLE_DIGICERT_VLONG_ECC_CONVERSION__ */

static int knownAnswerTest(TestVector *testVector, PrimeFieldPtr pField, pf_unit *pN, pf_unit *pMu)
{
    MSTATUS status = OK;
    int retVal = 0;
    
    PFEPtr pfInput1 = NULL;
    ubyte4 pfInputLen1 = 0;
    PFEPtr pfInput2 = NULL;
    ubyte4 pfInputLen2 = 0;
    PFEPtr pfResult = NULL;
    ubyte4 pfResultLen = 0;
    ubyte4 byteInput = testVector->byteInput;
    sbyte4 byteResult = testVector->byteResult;
    TestVectorType type = testVector->type;
    
    /* set the input and result vectors from the test vector */
    if (testVector->pfInput1 != NULL)
    {
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, PrimeFldFromStr( pField, testVector->pfInput1, &pfInputLen1, &pfInput1));
    }
    if (testVector->pfInput2 != NULL)
    {
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, PrimeFldFromStr( pField, testVector->pfInput2, &pfInputLen2, &pfInput2));
    }
    if (testVector->pfResult != NULL)
    {
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, PrimeFldFromStr( pField, testVector->pfResult, &pfResultLen, &pfResult));
    }
    
    switch(type)
    {
        case cmp:
            retVal += testCmp(pField, pfInput1, pfInput2, byteResult); /*also tests PRIMEFIELD_match*/
            break;
            
        case copy:
            retVal += testCopy(pField, pfInput1, pfResult);
            break;
            
        case add:
            retVal += testAdd(pField, pfInput1, pfInput2, pfResult);
            break;
            
        case subtract:
            retVal += testSubtract(pField, pfInput1, pfInput2, pfResult);
            break;
            
        case xor:
            retVal += testXor(pField, pfInput1, pfInput2, pfResult);
            break;
            
        case multiply:
            retVal += testMultiply(pField, pfInput1, pfInput2, pfResult);
            break;
            
        case shiftR:
            retVal += testShiftR(pField, pfInput1, pfResult);
            break;
            
        case getBit:
            retVal += testGetBit(pField, pfInput1, byteInput, (ubyte) byteResult);
            break;
            
        case inverse:
            retVal += testInverse(pField, pfInput1, pfResult);
            break;
            
        case divide:
            retVal += testDivide(pField, pfInput1, pfInput2, pfResult);
            break;
            
        case cmpToUnsigned:
            retVal += testCmpToUnsigned(pField, pfInput1, byteInput, byteResult);
            break;
            
        case barrettMultiply:
            
            /* Not applicable for all fields, test only if defined */
            if (NULL != pN && NULL != pMu )
                retVal += testBarrettMultiply(pField, pfInput1, pfInput2, pN, pMu, pfResult);
            else
                UNITTEST_VECTOR_STATUS(__MOC_LINE__, -1); /* force error */
            break;
            
        case addAux:
            
            /* Not applicable for all fields, test only if defined */
            if (NULL != pN)
                retVal += testAddAux(pField, pfInput1, pfInput2, pN, pfResult);
            else
                UNITTEST_VECTOR_STATUS(__MOC_LINE__, -1); /* force error */
            break;
            
        case inverseAux:
            
            /* Not applicable for all fields, test only if defined */
            if (NULL != pN)
                retVal += testInverseAux(pField, pfInput1, pN, pfResult);
            else
                UNITTEST_VECTOR_STATUS(__MOC_LINE__, -1); /* force error */
            break;

        case squareAux:
            retVal += testSquareAux(pField, pfInput1, pfResult);
            break;
            
        case exponentiate:
            retVal += testExponentiate(pField, pfInput1, pfInput2, pfResult);
            break;
            
        case specialExp:
            break;
            
        case additiveInvert:
            break;
      
        case squareRoot:
            
#ifdef __ENABLE_DIGICERT_ECC_ELGAMAL__
            retVal += testSquareRoot(pField, pfInput1, pfResult);
#endif
            break;
            
        default:
            break;
    }
    
exit:
    
    if(NULL != pfInput1)
    {
        status = PRIMEFIELD_deleteElement(pField, &pfInput1);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if(NULL != pfInput2)
    {
        status = PRIMEFIELD_deleteElement(pField, &pfInput2);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if(NULL != pfResult)
    {
        status = PRIMEFIELD_deleteElement(pField, &pfResult);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}

static int testErrorCases(PrimeFieldPtr pField, ubyte *pPrime, ubyte4 primeLen)
{
    
    int retVal = 0;
    MSTATUS status = OK;
    
    PFEPtr pElement = NULL;
    PFEPtr pElement2 = NULL;
    PFEPtr pElement3 = NULL;
    PFEPtr pElement4 = NULL;
    PFEPtr pElement5 = NULL;
    
    sbyte4 compare;
    intBoolean match;
    
    ubyte bit;
    
    ubyte tooLarge[66] = {
        0x02,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    };
    
    ubyte *pOutBuffer = NULL;
    sbyte4 outLen = 0;
    ubyte pWriteBuffer[66] = {0};
    
#ifdef __ENABLE_DIGICERT_64_BIT__
    pf_unit hilo[34] = {0}; /* enough room for two p521 products */
#else
    pf_unit hilo[68] = {0}; /* enough room for two p521 products */
#endif
    
#ifdef __ENABLE_DIGICERT_VLONG_ECC_CONVERSION__
    
    ubyte pNegMpint[5] =
    {
        0x00, 0x00, 0x00, 0x01, 0x81   /* first bit (after the 32 bit size) is the sign bit */
    };
    
    ubyte pTooLargeMpint[70] = {0x00}; /* buffer big enough for all primes */
    ubyte4 mpintPosition = 0;
    
    vlong *pVlongValue = NULL;
    
#endif
    
    /******* PRIMEFIELD_newElement *******/
    
    status = PRIMEFIELD_newElement(NULL, &pElement);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_newElement(pField, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* Correctly create new element for later tests */
    
    status = PRIMEFIELD_newElement(pField, &pElement);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /******* PRIMEFIELD_setToUnsigned *******/
    
    status = PRIMEFIELD_setToUnsigned(NULL, pElement, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_setToUnsigned(pField, NULL, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* PRIMEFIELD_setToByteString *******/
    
    /* NULL pointers */
    status = PRIMEFIELD_setToByteString(NULL, pElement, tooLarge, 24);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_setToByteString(pField, NULL, tooLarge, 24);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_setToByteString(pField, pElement, NULL, 24);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* Value equal to p */
    status = PRIMEFIELD_setToByteString(pField, pElement, pPrime, primeLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);
    
    /* Last primeLen bytes of tooLarge, hence all bytes 0xff */
    status = PRIMEFIELD_setToByteString(pField, pElement, tooLarge + sizeof(tooLarge) - primeLen, primeLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);
    
    /* Even bigger buffer than primeLen */
    status = PRIMEFIELD_setToByteString(pField, pElement, tooLarge, sizeof(tooLarge));
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);
    
    /* properly set element in order to test further methods */
    
    status = PRIMEFIELD_setToUnsigned(pField, pElement, 0xfedcba98);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /******* PRIMEFIELD_getElementByteStringLen *******/
    
    status = PRIMEFIELD_getElementByteStringLen(NULL, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_getElementByteStringLen(pField, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* PRIMEFIELD_getAsByteString *******/
    
    status = PRIMEFIELD_getAsByteString(NULL, pElement, &pOutBuffer, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_getAsByteString(pField, NULL, &pOutBuffer, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_getAsByteString(pField, pElement, NULL, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_getAsByteString(pField, pElement, &pOutBuffer, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* PRIMEFIELD_getAsByteString2 *******/
    
    status = PRIMEFIELD_getAsByteString2(NULL, pElement, pElement, &pOutBuffer, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_getAsByteString2(pField, NULL, pElement, &pOutBuffer, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_getAsByteString2(pField, pElement, NULL, &pOutBuffer, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_getAsByteString2(pField, pElement, pElement, NULL, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_getAsByteString2(pField, pElement, pElement, &pOutBuffer, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* PRIMEFIELD_writeByteString *******/
    
    status = PRIMEFIELD_writeByteString(NULL, pElement, pWriteBuffer, (sbyte4) sizeof(pWriteBuffer));
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_writeByteString(pField, NULL, pWriteBuffer, (sbyte4) sizeof(pWriteBuffer));
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_writeByteString(pField, pElement, NULL, (sbyte4) sizeof(pWriteBuffer));
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_writeByteString(pField, pElement, pWriteBuffer, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BUFFER_OVERFLOW);
    
    status = PRIMEFIELD_writeByteString(pField, pElement, pWriteBuffer, 23);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BUFFER_OVERFLOW);
    
#ifdef __ENABLE_DIGICERT_VLONG_ECC_CONVERSION__
    
    /******* PRIMEFIELD_newVlongFromElement *******/
    
    status = PRIMEFIELD_newVlongFromElement(NULL, pElement, &pVlongValue, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_newVlongFromElement(pField, NULL, &pVlongValue, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_newVlongFromElement(pField, pElement, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* PRIMEFIELD_newMpintFromElement *******/
    
    status = PRIMEFIELD_newMpintFromElement(NULL, pElement, &pOutBuffer, &outLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_newMpintFromElement(pField, NULL, &pOutBuffer, &outLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_newMpintFromElement(pField, pElement, NULL, &outLen, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_newMpintFromElement(pField, pElement, &pOutBuffer, NULL, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* PRIMEFIELD_getPrime *******/
    
    status = PRIMEFIELD_getPrime(NULL, &pVlongValue);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_getPrime(pField, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* clear element and create a proper vlong for the next tests */
    
    status = PRIMEFIELD_deleteElement(pField, &pElement);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    
    status = VLONG_vlongFromByteString(pPrime, primeLen, &pVlongValue, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /******* PRIMEFIELD_newElementFromVlong *******/
    
    status = PRIMEFIELD_newElementFromVlong(NULL, pVlongValue, &pElement);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_newElementFromVlong(pField, NULL, &pElement);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_newElementFromVlong(pField, pVlongValue, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_newElementFromVlong(pField, pVlongValue, &pElement);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);
    
    /* create way too large vlong */
    status = VLONG_vlongFromByteString(tooLarge, (sbyte4) sizeof(tooLarge), &pVlongValue, NULL);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = PRIMEFIELD_newElementFromVlong(pField, pVlongValue, &pElement);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);
    
    /******* PRIMEFIELD_newElementFromMpint *******/
    
    status = PRIMEFIELD_newElementFromMpint(NULL, (ubyte4) sizeof(pNegMpint), &mpintPosition, pField, &pElement);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    retVal += UNITTEST_INT(__MOC_LINE__, mpintPosition, 0);
    
    status = PRIMEFIELD_newElementFromMpint(pNegMpint, 0, &mpintPosition, pField, &pElement);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_PAYLOAD_EMPTY);
    retVal += UNITTEST_INT(__MOC_LINE__, mpintPosition, 0);
    
    status = PRIMEFIELD_newElementFromMpint(pNegMpint, 3, &mpintPosition, pField, &pElement);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BUFFER_TOO_SMALL);
    retVal += UNITTEST_INT(__MOC_LINE__, mpintPosition, 0);
    
    status = PRIMEFIELD_newElementFromMpint(pNegMpint, (ubyte4) sizeof(pNegMpint), NULL, pField, &pElement);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_newElementFromMpint(pNegMpint, (ubyte4) sizeof(pNegMpint), &mpintPosition, NULL, &pElement);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    retVal += UNITTEST_INT(__MOC_LINE__, mpintPosition, 0);
    
    status = PRIMEFIELD_newElementFromMpint(pNegMpint, (ubyte4) sizeof(pNegMpint), &mpintPosition, pField, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    retVal += UNITTEST_INT(__MOC_LINE__, mpintPosition, 0);
    
    status = PRIMEFIELD_newElementFromMpint(pNegMpint, (ubyte4) sizeof(pNegMpint), &mpintPosition, pField, &pElement);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);
    retVal += UNITTEST_INT(__MOC_LINE__, mpintPosition, 0);
    
    /* set size to something too large for all primes */
    pTooLargeMpint[3] = 0x42; /* 66 bytes */
    pTooLargeMpint[4] = 0x20; /* bigger than P521's first byte 0x1f, leading sign bit is 0 */
    
    status = PRIMEFIELD_newElementFromMpint(pTooLargeMpint, 69 , &mpintPosition, pField, &pElement);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BAD_LENGTH);
    retVal += UNITTEST_INT(__MOC_LINE__, mpintPosition, 0);
    
    status = PRIMEFIELD_newElementFromMpint(pTooLargeMpint, 70, &mpintPosition, pField, &pElement);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);
    retVal += UNITTEST_INT(__MOC_LINE__, mpintPosition, 0);
    
    status = PRIMEFIELD_newElementFromMpint(pTooLargeMpint, 71, &mpintPosition, pField, &pElement);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);
    retVal += UNITTEST_INT(__MOC_LINE__, mpintPosition, 0);
    
    /* set to p */
    pTooLargeMpint[3] = (ubyte) ((primeLen+1)& 0xff); /* extra leading byte for the sign bit */
    pTooLargeMpint[4] = 0x00; /* sign bit */
    
    status = DIGI_MEMCPY(pTooLargeMpint+5, pPrime, primeLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = PRIMEFIELD_newElementFromMpint(pTooLargeMpint, primeLen + 5, &mpintPosition, pField, &pElement);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);
    retVal += UNITTEST_INT(__MOC_LINE__, mpintPosition, 0);
    
    /* properly re-allocate pElement in order to test further methods */
    
    status = PRIMEFIELD_newElement(pField, &pElement);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
#endif /* __ENABLE_DIGICERT_VLONG_ECC_CONVERSION__ */
    
    /* properly allocate pElement2 through pElement5. No need to set them */
    status = PRIMEFIELD_newElement(pField, &pElement2);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = PRIMEFIELD_newElement(pField, &pElement3);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = PRIMEFIELD_newElement(pField, &pElement4);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = PRIMEFIELD_newElement(pField, &pElement5);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /******* PRIMEFIELD_copyElement *******/
    
    status = PRIMEFIELD_copyElement(NULL, pElement, pElement2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_copyElement(pField, NULL, pElement2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_copyElement(pField, pElement, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* PRIMEFIELD_add *******/
    
    status = PRIMEFIELD_add(NULL, pElement, pElement2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_add(pField, NULL, pElement2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_add(pField, pElement, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* PRIMEFIELD_subtract *******/
    
    status = PRIMEFIELD_subtract(NULL, pElement, pElement2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_subtract(pField, NULL, pElement2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_subtract(pField, pElement, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* PRIMEFIELD_xor *******/
    
    status = PRIMEFIELD_xor(NULL, pElement, pElement2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_xor(pField, NULL, pElement2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_xor(pField, pElement, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* PRIMEFIELD_multiply *******/
    
    status = PRIMEFIELD_multiply(NULL, pElement, pElement2, pElement3);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_multiply(pField, NULL, pElement2, pElement3);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_multiply(pField, pElement, NULL, pElement3);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_multiply(pField, pElement, pElement2, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* PRIMEFIELD_shiftR *******/
    
    status = PRIMEFIELD_shiftR(NULL, pElement);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_shiftR(pField, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* PRIMEFIELD_getBit *******/
    
    status = PRIMEFIELD_getBit(NULL, pElement, 0, &bit);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_getBit(pField, NULL, 0, &bit);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_getBit(pField, pElement, 0, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* PRIMEFIELD_getBit for a bitNum too large just sets bit to 0 */
    
    /******* PRIMEFIELD_inverse *******/
    
    status = PRIMEFIELD_inverse(NULL, pElement, pElement2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_inverse(pField, NULL, pElement2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_inverse(pField, pElement, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* set pElement2 to 0 in order to test inverting 0 */
    
    status = PRIMEFIELD_setToUnsigned(pField, pElement2, 0);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = PRIMEFIELD_inverse(pField, pElement, pElement2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_DIVIDE_BY_ZERO);
    
    /******* PRIMEFIELD_divide *******/
    
    status = PRIMEFIELD_divide(NULL, pElement, pElement2, pElement3);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_divide(pField, NULL, pElement2, pElement3);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_divide(pField, pElement, NULL, pElement3);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_divide(pField, pElement, pElement2, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* set pElement2 is still 0, test divide by 0 */
    
    status = PRIMEFIELD_divide(pField, pElement, pElement3, pElement2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_DIVIDE_BY_ZERO);
    
    /******* PRIMEFIELD_cmpToUnsigned *******/
    
    compare = PRIMEFIELD_cmpToUnsigned(NULL, pElement, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, compare, ERR_NULL_POINTER);
    
    compare = PRIMEFIELD_cmpToUnsigned(pField, NULL, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, compare, ERR_NULL_POINTER);
    
    /******* PRIMEFIELD_cmp *******/
    
    compare = PRIMEFIELD_cmp(NULL, pElement, pElement2);
    retVal += UNITTEST_INT(__MOC_LINE__, compare, ERR_NULL_POINTER);
    
    compare = PRIMEFIELD_cmp(pField, NULL, pElement2);
    retVal += UNITTEST_INT(__MOC_LINE__, compare, ERR_NULL_POINTER);
    
    compare = PRIMEFIELD_cmp(pField, pElement, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, compare, ERR_NULL_POINTER);
    
    /******* PRIMEFIELD_match *******/
    
    match = PRIMEFIELD_match(NULL, pElement, pElement2);
    retVal += UNITTEST_INT(__MOC_LINE__, match, FALSE);
    
    match = PRIMEFIELD_match(pField, NULL, pElement2);
    retVal += UNITTEST_INT(__MOC_LINE__, match, FALSE);
    
    match = PRIMEFIELD_match(pField, pElement, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, match, FALSE);
    
    /******* PRIMEFIELD_barrettMultiply *******/
    
    status = PRIMEFIELD_barrettMultiply(NULL, pElement, pElement2, pElement3, pElement4, pElement5);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_barrettMultiply(pField, NULL, pElement2, pElement3, pElement4, pElement5);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_barrettMultiply(pField, pElement, NULL, pElement3, pElement4, pElement5);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_barrettMultiply(pField, pElement, pElement2, NULL, pElement4, pElement5);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_barrettMultiply(pField, pElement, pElement2, pElement3, NULL, pElement5);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_barrettMultiply(pField, pElement, pElement2, pElement3, pElement4, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* PRIMEFIELD_addAux *******/
    
    status = PRIMEFIELD_addAux(NULL, pElement, pElement2, pElement3);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_addAux(pField, NULL, pElement2, pElement3);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_addAux(pField, pElement, NULL, pElement3);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_addAux(pField, pElement, pElement2, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* PRIMEFIELD_inverseAux *******/
    
    status = PRIMEFIELD_inverseAux(pField->n, NULL, pElement2, pElement3);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_inverseAux(pField->n, pElement, NULL, pElement3);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_inverseAux(pField->n, pElement, pElement2, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_inverseAux(0, pElement, pElement2, pElement3);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* pElement2 is still 0 */
    status = PRIMEFIELD_inverseAux(pField->n, pElement, pElement2, pElement3);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_DIVIDE_BY_ZERO);
    
    /* Test a nonzero noninvertible element (6 inverted mod 15) */
    
    status = PRIMEFIELD_setToUnsigned(pField, pElement2, 0x06);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = PRIMEFIELD_setToUnsigned(pField, pElement3, 0x0f);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = PRIMEFIELD_inverseAux(pField->n, pElement, pElement2, pElement3);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_DIVIDE_BY_ZERO);
    
    /******* PRIMEFIELD_multiplyAux *******/
    
    status = PRIMEFIELD_multiplyAux(NULL, pElement, pElement2, pElement3, hilo);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_multiplyAux(pField, NULL, pElement2, pElement3, hilo);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_multiplyAux(pField, pElement, NULL, pElement3, hilo);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_multiplyAux(pField, pElement, pElement2, NULL, hilo);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_multiplyAux(pField, pElement, pElement2, pElement3, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* PRIMEFIELD_squareAux *******/
    
    status = PRIMEFIELD_squareAux(NULL, pElement, pElement2, hilo);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_squareAux(pField, NULL, pElement2, hilo);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_squareAux(pField, pElement, NULL, hilo);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_squareAux(pField, pElement, pElement2, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******* PRIMEFIELD_exp *******/
    
    status = PRIMEFIELD_exp(NULL, pElement, pElement2, pElement3, hilo);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_exp(pField, NULL, pElement2, pElement3, hilo);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_exp(pField, pElement, NULL, pElement3, hilo);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_exp(pField, pElement, pElement2, NULL, hilo);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_exp(pField, pElement, pElement2, pElement3, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

#ifdef __ENABLE_DIGICERT_ECC_ELGAMAL__
    
    /******* PRIMEFIELD_squareRoot *******/
    
    status = PRIMEFIELD_squareRoot(NULL, pElement, pElement2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_squareRoot(pField, NULL, pElement2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_squareRoot(pField, pElement, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
#endif
    
    /******* PRIMEFIELD_deleteElement *******/
    
    status = PRIMEFIELD_deleteElement(NULL, &pElement);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = PRIMEFIELD_deleteElement(pField, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* Successfully delete pElement to test second deletion */
    if(NULL != pElement)
    {
        status = PRIMEFIELD_deleteElement(pField, &pElement);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }
    
    status = PRIMEFIELD_deleteElement(pField, &pElement);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
exit:
    
    /* pOutBuffer should never have been allocated */
    if (NULL != pOutBuffer)
    {
        retVal += UNITTEST_STATUS(__MOC_LINE__, -1); /* force error */
        status = DIGI_FREE((void **) &pOutBuffer);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if(NULL != pElement)
    {
        status = PRIMEFIELD_deleteElement(pField, &pElement);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if(NULL != pElement2)
    {
        status = PRIMEFIELD_deleteElement(pField, &pElement2);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if(NULL != pElement3)
    {
        status = PRIMEFIELD_deleteElement(pField, &pElement3);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if(NULL != pElement4)
    {
        status = PRIMEFIELD_deleteElement(pField, &pElement4);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if(NULL != pElement5)
    {
        status = PRIMEFIELD_deleteElement(pField, &pElement5);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
#ifdef __ENABLE_DIGICERT_VLONG_ECC_CONVERSION__
    
    if (NULL != pVlongValue)
    {
        status = VLONG_freeVlong( &pVlongValue, NULL);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
#endif
    
    return retVal;
}
#endif /* __ENABLE_DIGICERT_ECC__ */

int primefld_unit_test_all()
{
    int retVal = 0;
    
#ifdef __ENABLE_DIGICERT_ECC__
    
    int i;
    
    ubyte4 zero = 0;
    ubyte4 one = 1;
    ubyte4 large = 0xffffffff;
    
    ubyte zeroArray[1] = {0x00};
    ubyte zeroArrayLarge[24] = {0x00};
    
    ubyte oneArray[1] = {0x01};
    ubyte oneArrayLarge[24] =
    {
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
    };
    
    /* arbitrary random bytes for use in all fields. Smaller than p_521 but
     we'll also just use pieces of it as needed. */
    ubyte arbitrary[65] =
    {
        0xFE,
        0xE8,0xA7,0x2A,0x20,0x7C,0x9B,0x87,0xA6,
        0xF5,0x60,0x38,0x32,0x7E,0x91,0xEC,0xCB,
        0xE7,0xD4,0x79,0xD6,0xFD,0x19,0x40,0x2F,
        0x77,0x04,0xD8,0x18,0x6A,0x67,0x07,0xF4,
        0x73,0x34,0xFF,0x37,0x79,0xBE,0xDE,0x1D,
        0x32,0xF6,0x54,0x0A,0xBC,0x7A,0x77,0xA0,
        0x49,0x7A,0xA7,0xDD,0x58,0x3F,0x99,0x02,
        0x68,0x44,0x88,0xC9,0x64,0x96,0xAC,0xCD
    };
    
#if (defined(__ENABLE_DIGICERT_VLONG_ECC_CONVERSION__))
    
    /* Multiple precision ints are byte arrays where the first
     4 bytes are the length followed by bytes representing a
     signed integer in big endian */
    
    ubyte pZeroMpint[4] =
    {
        0x00,0x00,0x00,0x00
    };
    
    ubyte pOneMpint[5] =
    {
        0x00,0x00,0x00,0x01,
        0x01
    };
    
    ubyte pSmallMpint[6] =
    {
        0x00,0x00,0x00,0x02,
        0x7e,0xdc                                /* 2 byte positive number */
    };
    
    ubyte pMediumMpint[28] =
    {                                          /* works for all primes gpP_<n> */
        0x00,0x00,0x00,0x18,                     /* 24 byte number */
        0x78,0xA7,0x2A,0x20,0x7C,0x9B,0x87,0xA6, /* first bit 0 so positive */
        0xF5,0x60,0x38,0x32,0x7E,0x91,0xEC,0xCB,
        0xE7,0xD4,0x79,0xD6,0xFD,0x19,0x40,0x2F
    };
    
    ubyte pLargeMpint[69] =                     /* for values almost as large as p_521 */
    {
        0x00,0x00,0x00,0x41,                     /* we will re-set the size for each prime */
        0x1f,                                    /* will be a positive number for each prime */
        0xE8,0xA7,0x2A,0x20,0x7C,0x9B,0x87,0xA6,
        0xF5,0x60,0x38,0x32,0x7E,0x91,0xEC,0xCB,
        0xE7,0xD4,0x79,0xD6,0xFD,0x19,0x40,0x2F,
        0x77,0x04,0xD8,0x18,0x6A,0x67,0x07,0xF4,
        0x73,0x34,0xFF,0x37,0x79,0xBE,0xDE,0x1D,
        0x32,0xF6,0x54,0x0A,0xBC,0x7A,0x77,0xA0,
        0x49,0x7A,0xA7,0xDD,0x58,0x3F,0x99,0x02,
        0x68,0x44,0x88,0xC9,0x64,0x96,0xAC,0xCD
    };
    
    ubyte pAllMpints[112] =   /* all 5 of the above Mpints combined to a single buffer */
    {
        0x00,0x00,0x00,0x00,
        
        0x00,0x00,0x00,0x01,
        0x01,
        
        0x00,0x00,0x00,0x02,
        0x7e,0xdc,
        
        0x00,0x00,0x00,0x18,
        0x78,0xA7,0x2A,0x20,0x7C,0x9B,0x87,0xA6,
        0xF5,0x60,0x38,0x32,0x7E,0x91,0xEC,0xCB,
        0xE7,0xD4,0x79,0xD6,0xFD,0x19,0x40,0x2F,
        
        0x00,0x00,0x00,0x41,   /* we will re-set the size of this last mpint for each prime */
        0x1f,
        0xE8,0xA7,0x2A,0x20,0x7C,0x9B,0x87,0xA6,
        0xF5,0x60,0x38,0x32,0x7E,0x91,0xEC,0xCB,
        0xE7,0xD4,0x79,0xD6,0xFD,0x19,0x40,0x2F,
        0x77,0x04,0xD8,0x18,0x6A,0x67,0x07,0xF4,
        0x73,0x34,0xFF,0x37,0x79,0xBE,0xDE,0x1D,
        0x32,0xF6,0x54,0x0A,0xBC,0x7A,0x77,0xA0,
        0x49,0x7A,0xA7,0xDD,0x58,0x3F,0x99,0x02,
        0x68,0x44,0x88,0xC9,0x64,0x96,0xAC,0xCD
    };
    
#endif /* __ENABLE_DIGICERT_VLONG_ECC_CONVERSION__ */
    
#ifdef __ENABLE_DIGICERT_ECC_P192__
    
    /* Test P192 */
    
    retVal += testSetElementUbyte(PF_p192, zero);
    retVal += testSetElementUbyte(PF_p192, one);
    retVal += testSetElementUbyte(PF_p192, large);
    
    retVal += testSetGetElementArray(PF_p192, zeroArray, (sbyte4) sizeof(zeroArray));
    retVal += testSetGetElementArray(PF_p192, zeroArrayLarge, (sbyte4) sizeof(zeroArrayLarge));
    retVal += testSetGetElementArray(PF_p192, oneArray, (sbyte4) sizeof(oneArray));
    retVal += testSetGetElementArray(PF_p192, oneArrayLarge, (sbyte4) sizeof(oneArrayLarge));
    retVal += testSetGetElementArray(PF_p192, arbitrary, 24); /* 0 mod 4 number of bytes */
    retVal += testSetGetElementArray(PF_p192, arbitrary, 23); /* 3 mod 4 number of bytes */
    retVal += testSetGetElementArray(PF_p192, arbitrary, 22); /* 2 mod 4 number of bytes */
    retVal += testSetGetElementArray(PF_p192, arbitrary, 21); /* 1 mod 4 number of bytes */
    retVal += testSetGetElementArray(PF_p192, arbitrary, 16); /* at least a pf_unit less */
    
#if (defined(__ENABLE_DIGICERT_VLONG_ECC_CONVERSION__))
    
    retVal += testGetSetFromVlong(PF_p192, zeroArray, (sbyte4) sizeof(zeroArray));
    retVal += testGetSetFromVlong(PF_p192, oneArray, (sbyte4) sizeof(oneArray));
    retVal += testGetSetFromVlong(PF_p192, arbitrary, 24);
    retVal += testGetSetFromVlong(PF_p192, arbitrary, 23);
    retVal += testGetSetFromVlong(PF_p192, arbitrary, 22);
    retVal += testGetSetFromVlong(PF_p192, arbitrary, 21);
    retVal += testGetSetFromVlong(PF_p192, arbitrary, 16);
    
    retVal += testGetPrime(PF_p192, gpP_192, (ubyte4) sizeof(gpP_192));
    
    retVal += testGetSetFromMpint(PF_p192, pZeroMpint, (ubyte4) sizeof(pZeroMpint));
    retVal += testGetSetFromMpint(PF_p192, pOneMpint, (ubyte4) sizeof(pOneMpint));
    retVal += testGetSetFromMpint(PF_p192, pSmallMpint, (ubyte4) sizeof(pSmallMpint));
    retVal += testGetSetFromMpint(PF_p192, pMediumMpint, (ubyte4) sizeof(pMediumMpint));
    pLargeMpint[3] = pAllMpints[46] = 0x18;  /* 24 */
    retVal += testGetSetFromMpint(PF_p192, pLargeMpint, 28);
    retVal += testGetSetFromMpint(PF_p192, pAllMpints, 71);
    
#endif
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestField = 192;
#endif
    for (i = 0; i < COUNTOF(gTestVector_p192); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p192+i, PF_p192, gpN_192, gpMu_192);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    retVal += testErrorCases(PF_p192, gpP_192, (ubyte4) sizeof(gpP_192));
    
#endif /* __ENABLE_DIGICERT_ECC_P192__  */
    
#ifndef __DISABLE_DIGICERT_ECC_P224__
    
    /* Test P224 */
    
    retVal += testSetElementUbyte(PF_p224, zero);
    retVal += testSetElementUbyte(PF_p224, one);
    retVal += testSetElementUbyte(PF_p224, large);
    
    retVal += testSetGetElementArray(PF_p224, zeroArray, (sbyte4) sizeof(zeroArray));
    retVal += testSetGetElementArray(PF_p224, zeroArrayLarge, (sbyte4) sizeof(zeroArrayLarge));
    retVal += testSetGetElementArray(PF_p224, oneArray, (sbyte4) sizeof(oneArray));
    retVal += testSetGetElementArray(PF_p224, oneArrayLarge, (sbyte4) sizeof(oneArrayLarge));
    retVal += testSetGetElementArray(PF_p224, arbitrary, 24); /* 0 mod 4 number of bytes */
    retVal += testSetGetElementArray(PF_p224, arbitrary, 5);  /* 1 mod 4 number of bytes */
    retVal += testSetGetElementArray(PF_p224, arbitrary, 14); /* 2 mod 4 number of bytes */
    retVal += testSetGetElementArray(PF_p224, arbitrary, 15); /* 3 mod 4 number of bytes */
    
#if (defined(__ENABLE_DIGICERT_VLONG_ECC_CONVERSION__))
    
    retVal += testGetSetFromVlong(PF_p224, zeroArray, (sbyte4) sizeof(zeroArray));
    retVal += testGetSetFromVlong(PF_p224, oneArray, (sbyte4) sizeof(oneArray));
    retVal += testGetSetFromVlong(PF_p224, arbitrary, 28);
    retVal += testGetSetFromVlong(PF_p224, arbitrary, 24);
    retVal += testGetSetFromVlong(PF_p224, arbitrary, 5);
    retVal += testGetSetFromVlong(PF_p224, arbitrary, 14);
    retVal += testGetSetFromVlong(PF_p224, arbitrary, 15);
    
    retVal += testGetPrime(PF_p224, gpP_224, (ubyte4) sizeof(gpP_224));
    
    retVal += testGetSetFromMpint(PF_p224, pZeroMpint, (ubyte4) sizeof(pZeroMpint));
    retVal += testGetSetFromMpint(PF_p224, pOneMpint, (ubyte4) sizeof(pOneMpint));
    retVal += testGetSetFromMpint(PF_p224, pSmallMpint, (ubyte4) sizeof(pSmallMpint));
    retVal += testGetSetFromMpint(PF_p224, pMediumMpint, (ubyte4) sizeof(pMediumMpint));
    pLargeMpint[3] = pAllMpints[46] = 0x1c;  /* 28 */
    retVal += testGetSetFromMpint(PF_p224, pLargeMpint, 32);
    retVal += testGetSetFromMpint(PF_p224, pAllMpints, 75);
    
#endif
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestField = 224;
#endif
    for (i = 0; i < COUNTOF(gTestVector_p224); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p224+i, PF_p224, gpN_224, gpMu_224);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    retVal += testErrorCases(PF_p224, gpP_224, (ubyte4) sizeof(gpP_224));
    
#endif /* __DISABLE_DIGICERT_ECC_P224__ */
    
#ifndef __DISABLE_DIGICERT_ECC_P256__
    
    /* Test P256 */
    
    retVal += testSetElementUbyte(PF_p256, zero);
    retVal += testSetElementUbyte(PF_p256, one);
    retVal += testSetElementUbyte(PF_p256, large);
    
    retVal += testSetGetElementArray(PF_p256, zeroArray, (sbyte4) sizeof(zeroArray));
    retVal += testSetGetElementArray(PF_p256, zeroArrayLarge, (sbyte4) sizeof(zeroArrayLarge));
    retVal += testSetGetElementArray(PF_p256, oneArray, (sbyte4) sizeof(oneArray));
    retVal += testSetGetElementArray(PF_p256, oneArrayLarge, (sbyte4) sizeof(oneArrayLarge));
    retVal += testSetGetElementArray(PF_p256, arbitrary, 24); /* 0 mod 4 number of bytes */
    retVal += testSetGetElementArray(PF_p256, arbitrary, 29); /* 1 mod 4 number of bytes */
    retVal += testSetGetElementArray(PF_p256, arbitrary, 30); /* 2 mod 4 number of bytes */
    retVal += testSetGetElementArray(PF_p256, arbitrary, 3);  /* 3 mod 4 number of bytes */
    
#if (defined(__ENABLE_DIGICERT_VLONG_ECC_CONVERSION__))
    
    retVal += testGetSetFromVlong(PF_p256, zeroArray, (sbyte4) sizeof(zeroArray));
    retVal += testGetSetFromVlong(PF_p256, oneArray, (sbyte4) sizeof(oneArray));
    retVal += testGetSetFromVlong(PF_p256, arbitrary, 32);
    retVal += testGetSetFromVlong(PF_p256, arbitrary, 24);
    retVal += testGetSetFromVlong(PF_p256, arbitrary, 29);
    retVal += testGetSetFromVlong(PF_p256, arbitrary, 30);
    retVal += testGetSetFromVlong(PF_p256, arbitrary, 3);
    
    retVal += testGetPrime(PF_p256, gpP_256, (ubyte4) sizeof(gpP_256));
    
    retVal += testGetSetFromMpint(PF_p256, pZeroMpint, (ubyte4) sizeof(pZeroMpint));
    retVal += testGetSetFromMpint(PF_p256, pOneMpint, (ubyte4) sizeof(pOneMpint));
    retVal += testGetSetFromMpint(PF_p256, pSmallMpint, (ubyte4) sizeof(pSmallMpint));
    retVal += testGetSetFromMpint(PF_p256, pMediumMpint, (ubyte4) sizeof(pMediumMpint));
    pLargeMpint[3] = pAllMpints[46] = 0x20;  /* 32 */
    retVal += testGetSetFromMpint(PF_p256, pLargeMpint, 36);
    retVal += testGetSetFromMpint(PF_p256, pAllMpints, 79);
    
#endif
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestField = 256;
#endif
    for (i = 0; i < COUNTOF(gTestVector_p256); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p256+i, PF_p256, gpN_256, gpMu_256);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    retVal += testErrorCases(PF_p256, gpP_256, (ubyte4) sizeof(gpP_256));
    
#endif /* __DISABLE_DIGICERT_ECC_P256__ */
    
#ifndef __DISABLE_DIGICERT_ECC_P384__
    
    /* Test P384 */
    
    retVal += testSetElementUbyte(PF_p384, zero);
    retVal += testSetElementUbyte(PF_p384, one);
    retVal += testSetElementUbyte(PF_p384, large);
    
    retVal += testSetGetElementArray(PF_p384, zeroArray, (sbyte4) sizeof(zeroArray));
    retVal += testSetGetElementArray(PF_p384, zeroArrayLarge, (sbyte4) sizeof(zeroArrayLarge));
    retVal += testSetGetElementArray(PF_p384, oneArray, (sbyte4) sizeof(oneArray));
    retVal += testSetGetElementArray(PF_p384, oneArrayLarge, (sbyte4) sizeof(oneArrayLarge));
    retVal += testSetGetElementArray(PF_p384, arbitrary, 48); /* 0 mod 4 number of bytes */
    retVal += testSetGetElementArray(PF_p384, arbitrary, 1);  /* 1 mod 4 number of bytes */
    retVal += testSetGetElementArray(PF_p384, arbitrary, 26); /* 2 mod 4 number of bytes */
    retVal += testSetGetElementArray(PF_p384, arbitrary, 47); /* 3 mod 4 number of bytes */
    
#if (defined(__ENABLE_DIGICERT_VLONG_ECC_CONVERSION__))
    
    retVal += testGetSetFromVlong(PF_p384, zeroArray, (sbyte4) sizeof(zeroArray));
    retVal += testGetSetFromVlong(PF_p384, oneArray, (sbyte4) sizeof(oneArray));
    retVal += testGetSetFromVlong(PF_p384, arbitrary, 48);
    retVal += testGetSetFromVlong(PF_p384, arbitrary, 1);
    retVal += testGetSetFromVlong(PF_p384, arbitrary, 26);
    retVal += testGetSetFromVlong(PF_p384, arbitrary, 47);
    retVal += testGetSetFromVlong(PF_p384, arbitrary, 39);
    
    retVal += testGetPrime(PF_p384, gpP_384, (ubyte4) sizeof(gpP_384));
    
    retVal += testGetSetFromMpint(PF_p384, pZeroMpint, (ubyte4) sizeof(pZeroMpint));
    retVal += testGetSetFromMpint(PF_p384, pOneMpint, (ubyte4) sizeof(pOneMpint));
    retVal += testGetSetFromMpint(PF_p384, pSmallMpint, (ubyte4) sizeof(pSmallMpint));
    retVal += testGetSetFromMpint(PF_p384, pMediumMpint, (ubyte4) sizeof(pMediumMpint));
    pLargeMpint[3] = pAllMpints[46] = 0x30;  /* 48 */
    retVal += testGetSetFromMpint(PF_p384, pLargeMpint, 52);
    retVal += testGetSetFromMpint(PF_p384, pAllMpints, 95);
    
#endif
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestField = 384;
#endif
    for (i = 0; i < COUNTOF(gTestVector_p384); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p384+i, PF_p384, gpN_384, gpMu_384);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    retVal += testErrorCases(PF_p384, gpP_384, (ubyte4) sizeof(gpP_384));
    
#endif /* __DISABLE_DIGICERT_ECC_P384__ */
    
#ifndef __DISABLE_DIGICERT_ECC_P521__
    
    /* Test P521 */
    
    retVal += testSetElementUbyte(PF_p521, zero);
    retVal += testSetElementUbyte(PF_p521, one);
    retVal += testSetElementUbyte(PF_p521, large);
    
    retVal += testSetGetElementArray(PF_p521, zeroArray, (sbyte4) sizeof(zeroArray));
    retVal += testSetGetElementArray(PF_p521, zeroArrayLarge, (sbyte4) sizeof(zeroArrayLarge));
    retVal += testSetGetElementArray(PF_p521, oneArray, (sbyte4) sizeof(oneArray));
    retVal += testSetGetElementArray(PF_p521, oneArrayLarge, (sbyte4) sizeof(oneArrayLarge));
    retVal += testSetGetElementArray(PF_p521, arbitrary, 64); /* 0 mod 4 number of bytes */
    retVal += testSetGetElementArray(PF_p521, arbitrary, 65); /* 1 mod 4 number of bytes */
    retVal += testSetGetElementArray(PF_p521, arbitrary, 2);  /* 2 mod 4 number of bytes */
    retVal += testSetGetElementArray(PF_p521, arbitrary, 55); /* 3 mod 4 number of bytes */
    
#if (defined(__ENABLE_DIGICERT_VLONG_ECC_CONVERSION__))
    
    retVal += testGetSetFromVlong(PF_p521, zeroArray, (sbyte4) sizeof(zeroArray));
    retVal += testGetSetFromVlong(PF_p521, oneArray, (sbyte4) sizeof(oneArray));
    retVal += testGetSetFromVlong(PF_p521, arbitrary, 64);
    retVal += testGetSetFromVlong(PF_p521, arbitrary, 65);
    retVal += testGetSetFromVlong(PF_p521, arbitrary, 2);
    retVal += testGetSetFromVlong(PF_p521, arbitrary, 55);
    retVal += testGetSetFromVlong(PF_p521, arbitrary, 39);
    
    retVal += testGetPrime(PF_p521, gpP_521, (ubyte4) sizeof(gpP_521));
    
    retVal += testGetSetFromMpint(PF_p521, pZeroMpint, (ubyte4) sizeof(pZeroMpint));
    retVal += testGetSetFromMpint(PF_p521, pOneMpint, (ubyte4) sizeof(pOneMpint));
    retVal += testGetSetFromMpint(PF_p521, pSmallMpint, (ubyte4) sizeof(pSmallMpint));
    retVal += testGetSetFromMpint(PF_p521, pMediumMpint, (ubyte4) sizeof(pMediumMpint));
    pLargeMpint[3] = pAllMpints[46] = 0x41;  /* 65 */
    retVal += testGetSetFromMpint(PF_p521, pLargeMpint, 69);
    retVal += testGetSetFromMpint(PF_p521, pAllMpints, 112);
    
#endif
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestField = 521;
#endif
    for (i = 0; i < COUNTOF(gTestVector_p521); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p521+i, PF_p521, gpN_521, gpMu_521);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    retVal += testErrorCases(PF_p521, gpP_521, (ubyte4) sizeof(gpP_521));
    
#endif /* __DISABLE_DIGICERT_ECC_P521__ */
#endif /* __ENABLE_DIGICERT_ECC__ */
    
    DBG_DUMP
    return retVal;
}
