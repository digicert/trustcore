/*
 * primeec_unit_test.c
 *
 * unit test for primeec.c
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
#include "../../crypto/primeec.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_ECC__

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

typedef enum TestVectorType {
    addMultiply,
    multiply,
    computeYfromX,
    equalKey,
    cloneKey,
    verifyPoint,
    getSetPoint,
    verifyKeyPair,
    generateKeyPair,
    setKey,
    sign,
    verify,
    sharedSecret,
    sharedSecretAux
} TestVectorType;

typedef struct TestVector
{
    char *pfInput1;
    char *pfInput2;
    char *pfInput3;
    char *pfInput4;
    char *pfInput5;
    char *pfResult1;
    char *pfResult2;
    sbyte4 byteInput1;
    sbyte4 byteInput2;
    sbyte4 byteResult;
    TestVectorType type;

} TestVector;

#ifdef __ENABLE_DIGICERT_ECC_P192__
#include "primeec_data_192_inc.h"
#endif

#ifndef __DISABLE_DIGICERT_ECC_P224__
#include "primeec_data_224_inc.h"
#endif

#ifndef __DISABLE_DIGICERT_ECC_P256__
#include "primeec_data_256_inc.h"
#endif

#ifndef __DISABLE_DIGICERT_ECC_P384__
#include "primeec_data_384_inc.h"
#endif

#ifndef __DISABLE_DIGICERT_ECC_P521__
#include "primeec_data_521_inc.h"
#endif


/* Global variables so the "fake RNG" callback method will have access as what to return */
static ubyte gpNonce[72] = {0};
static ubyte4 gNonceLen = 0;

/*
 Method to copy a byte array representing a Big Endian integer to the gpNonce
 global variable in the correct format for creation of a PFE form point.
 */
static MSTATUS copyRNGdata(ubyte *pRngData, ubyte4 rngDataLen, ubyte4 curveWords){

    MSTATUS status = OK;
    int i;

#ifdef MOC_BIG_ENDIAN
    ubyte swap = 0x00;
    int j;
#endif

    /* The ECC code adds 1 to the raw result of the RNG, so subtract one here */
    /* in order to compensate, start with the last byte. */
    i = rngDataLen - 1;
    pRngData[i]--;

    /* keep borrowing if needbe */
    while (0xFF == pRngData[i] && i > 0)
    {
        i--;
        pRngData[i]--;
    }

    /* copy the rng data to the global variable so the callback method has access to it
       it'll be copied into a PFE directly so take into account word size and endianness */

    /* First just reverse to Little Endian bytewise and zero pad the end */

    for (i = 0; i < rngDataLen; ++i)
    {
        gpNonce[i] = pRngData[rngDataLen - i - 1];
    }

    if (rngDataLen < (ubyte4) (curveWords * sizeof(pf_unit)))
    {
        /* zero pad */
        status = DIGI_MEMSET(gpNonce + rngDataLen, 0x00, curveWords * sizeof(pf_unit) - rngDataLen);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            return status;
    }

    /* if platform stores a pf_unit Little Endian then we are done, else ... */

#ifdef MOC_BIG_ENDIAN

    /* revere each pf_unit that will be formed from within the byte array gpNonce */

    for (i = 0; i < curveWords; ++i)
    {
        for (j = 0; j < sizeof(pf_unit)/2; ++j)
        {
            swap = gpNonce[sizeof(pf_unit)*i + j];
            gpNonce[sizeof(pf_unit)*i + j] = gpNonce[sizeof(pf_unit)*i + sizeof(pf_unit) - j - 1];
            gpNonce[sizeof(pf_unit)*i + sizeof(pf_unit) - j - 1] = swap;
        }
    }
#endif

    /* set the global length */
    gNonceLen = (ubyte4) (curveWords * sizeof(pf_unit));

    return status;
}

/*
 A fake random number generator callBack method. It just write to the buffer
 the value of the global variable gpNonce. gpNonce is big enough for all curves,
 but we need to take into account the Endianness of the platforms pf_unit type.
 */
static sbyte4 rngCallback(void *rngFunArg, ubyte4 length, ubyte *pBuffer)
{
    MSTATUS status = OK;

    (void) rngFunArg;

    if (length > gNonceLen) /* uh oh, force error */
    {
        UNITTEST_STATUS(__MOC_LINE__, -1);
        return -1;
    }

    status = DIGI_MEMCPY(pBuffer, gpNonce, length);
    UNITTEST_STATUS(__MOC_LINE__, status);

    return (sbyte4) status;
}

/* allocates memory for the PFEPtr result and sets it to the value in str */
static MSTATUS PrimeFldFromStr( PrimeFieldPtr pField, const char *str, ubyte4 *unitLen, PFEPtr *pResult)
{
    MSTATUS status = OK;
    ubyte *bytes = NULL;
    ubyte4 byteLen;
    PFEPtr result = NULL;

    status = PRIMEFIELD_newElement(pField, &result);
    if(OK != status)
        goto exit;

    byteLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) str, &bytes);
    status = PRIMEFIELD_setToByteString(pField, result, bytes, (sbyte4) byteLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* delete old element if there is one */
    if (NULL != *pResult)
    {
        (void) PRIMEFIELD_deleteElement(pField, pResult);
    }
    *pResult = result; result = NULL;
    *unitLen = pField->n;

exit:

    if (NULL != bytes)
        (void) DIGI_FREE((void **) &bytes);

    if (NULL != result)
        (void) PRIMEFIELD_deleteElement(pField, &result);

    return status;
}

/* (pResX,pResy) = k * (pX,pY) + (pAddedX,pAddedY)  */
static int testAddMultiply(PEllipticCurvePtr pEC, PFEPtr pExpectedResX, PFEPtr pExpectedResY, PFEPtr pAddedX, PFEPtr pAddedY,
                           PFEPtr k, PFEPtr pX, PFEPtr pY)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare;

    PFEPtr pResX = NULL;
    PFEPtr pResY = NULL;

    status = PRIMEFIELD_newElement(pEC->pPF, &pResX);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(pEC->pPF, &pResY);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = EC_addMultiplyPoint(pEC->pPF, pResX, pResY, pAddedX, pAddedY, k, pX, pY);

    if (NULL != pExpectedResX && NULL != pExpectedResY)
    {
        UNITTEST_VECTOR_STATUS(__LINE__, status);
        if(OK != status)
            goto exit;

        /* test we got the expected result */
        compare = PRIMEFIELD_cmp(pEC->pPF, pResY, pExpectedResY);
        UNITTEST_VECTOR_INT(__LINE__, compare, 0);

        /* test we got the expected result */
        compare = PRIMEFIELD_cmp(pEC->pPF, pResY, pExpectedResY);
        UNITTEST_VECTOR_INT(__LINE__, compare, 0);
    }
    else
    {
        UNITTEST_VECTOR_INT(__LINE__, status, ERR_EC_INFINITE_RESULT);
    }

exit:

    if (NULL != pResX)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pResX);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    if (NULL != pResY)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pResY);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}

/* (pResX,pResy) = k * (pX,pY)  */
static int testMultiply(PEllipticCurvePtr pEC, PFEPtr pExpectedResX, PFEPtr pExpectedResY,
                        PFEPtr k, PFEPtr pX, PFEPtr pY)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare;

    PFEPtr pResX = NULL;
    PFEPtr pResY = NULL;

    status = PRIMEFIELD_newElement(pEC->pPF, &pResX);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(pEC->pPF, &pResY);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = EC_multiplyPoint(pEC->pPF, pResX, pResY, k, pX, pY);

    if (NULL != pExpectedResX && NULL != pExpectedResY)
    {
        UNITTEST_VECTOR_STATUS(__LINE__, status);
        if(OK != status)
            goto exit;

        /* test we got the expected result */
        compare = PRIMEFIELD_cmp(pEC->pPF, pResX, pExpectedResX);
        UNITTEST_VECTOR_INT(__LINE__, compare, 0);

        /* test we got the expected result */
        compare = PRIMEFIELD_cmp(pEC->pPF, pResY, pExpectedResY);
        UNITTEST_VECTOR_INT(__LINE__, compare, 0);
    }
    else
    {
        UNITTEST_VECTOR_INT(__LINE__, status, ERR_EC_INFINITE_RESULT);
    }

exit:

    if (NULL != pResX)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pResX);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    if (NULL != pResY)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pResY);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}

/* EC_computeYFromX is only used in ecc ElGamal, pExpectedResY non NULL means such a y is expected to exist */

#ifdef __ENABLE_DIGICERT_ECC_ELGAMAL__
static int testComputeYfromX(PEllipticCurvePtr pEC, PFEPtr pExpectedResY, PFEPtr pExpectedResNegY, PFEPtr pX)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare;

    PFEPtr pResY = NULL;

    status = PRIMEFIELD_newElement(pEC->pPF, &pResY);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = EC_computeYFromX(pEC, pX, pResY);

    if (NULL != pExpectedResY)
    {
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;

        /* test we got one of the expected results! */
        compare = PRIMEFIELD_cmp(pEC->pPF, pResY, pExpectedResY);

        if (0 != compare) /* check the other Y */
        {
            compare = PRIMEFIELD_cmp(pEC->pPF, pResY, pExpectedResNegY);
        }
        UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    }
    else  /* no such y exists */
    {
        UNITTEST_VECTOR_INT(__MOC_LINE__, status, ERR_NOT_FOUND);
    }

exit:

    if (NULL != pResY)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pResY);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}
#endif /* __ENABLE_DIGICERT_ECC_ELGAMAL__ */

static int testEqualKey(PEllipticCurvePtr pEC, byteBoolean expectedResult, ECCKey *pKey1, ECCKey *pKey2)
{
    MSTATUS status = OK;
    int retVal = 0;
    byteBoolean result;

    status = EC_equalKey(pKey1, pKey2, &result);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, result, expectedResult);

exit:

    return retVal;
}

static int testCloneKey(PEllipticCurvePtr pEC, ECCKey *pExpectedKey, ECCKey *pKey)
{
    MSTATUS status = OK;
    int retVal = 0;
    byteBoolean compare;

    ECCKey *pClone = NULL;

    status = EC_cloneKey(&pClone, pKey);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = EC_equalKey(pClone, pKey, &compare);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, (int) TRUE);

exit:

    if (NULL != pClone)
    {
        status = EC_deleteKey(&pClone);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}

/* This method also tests verifyPublicKey */
static int testVerifyPoint(PEllipticCurvePtr pEC, sbyte4 expectedResult, PFEPtr pX, PFEPtr pY)
{

    MSTATUS status = OK;
    int retVal = 0;

    status = EC_verifyPoint(pEC, pX, pY);
    UNITTEST_VECTOR_INT(__MOC_LINE__, status, (int) expectedResult);

    status = EC_verifyPublicKey(pEC, pX, pY);
    UNITTEST_VECTOR_INT(__MOC_LINE__, status, (int) expectedResult);

    return retVal;
}

static int testVerifyKeyPair(PEllipticCurvePtr pEC, sbyte4 expectedResult, PFEPtr k, PFEPtr pX, PFEPtr pY)
{

    MSTATUS status = OK;
    int retVal = 0;

    status = EC_verifyKeyPair(pEC, k, pX, pY);
    UNITTEST_VECTOR_INT(__MOC_LINE__, status, (int) expectedResult);

    return retVal;
}

static int testGenerateKeyPair(PEllipticCurvePtr pEC, PFEPtr pExpectedK, PFEPtr pExpectedQx, PFEPtr pExpectedQy, ubyte *pRngData, ubyte4 rngDataLen)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare;

    PFEPtr pK = NULL;
    PFEPtr pQx = NULL;
    PFEPtr pQy = NULL;

    /* copy the rng data to the global variable for use in the "fake" RNG */
    status = copyRNGdata(pRngData, rngDataLen, pEC->pPF->n);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* Allocate space for the elements to be generated */
    status = PRIMEFIELD_newElement(pEC->pPF, &pK);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(pEC->pPF, &pQx);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(pEC->pPF, &pQy);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = EC_generateKeyPair(pEC, rngCallback, NULL, pK, pQx, pQy);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* test we got the expected result */
    compare = PRIMEFIELD_cmp(pEC->pPF, pK, pExpectedK);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

    compare = PRIMEFIELD_cmp(pEC->pPF, pQx, pExpectedQx);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

    compare = PRIMEFIELD_cmp(pEC->pPF, pQy, pExpectedQy);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

exit:

    if (NULL != pK)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pK);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pQx)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pQx);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pQy)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pQy);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}

static int testSetKey(PEllipticCurvePtr pEC, ECCKey *pExpectedKey, ubyte *pPoint, ubyte4 pointLen, ubyte *pScalar, ubyte4 scalarLen){

    MSTATUS status = OK;
    int retVal = 0;
    byteBoolean result;
    sbyte4 compare;

    ECCKey *pKey = NULL;

    status = EC_newKey(pEC, &pKey);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = EC_setKeyParameters(pKey, pPoint, pointLen, pScalar, scalarLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* check that pKey is the expected key (at least the public part first) */
    status = EC_equalKey(pKey, pExpectedKey, &result);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, result, TRUE);

    /* since the above only compares public part, also check the private part */
    if (pKey->privateKey != pExpectedKey->privateKey)
    {
        /* force error */
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, -1);
        goto exit;
    }

    if (pKey->privateKey)
    {
        compare = PRIMEFIELD_cmp(pEC->pPF, pKey->k, pExpectedKey->k);
        UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    }

exit:

    if (NULL != pKey)
    {
        status = EC_deleteKey(&pKey);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    return retVal;
}

static int testDsaSign(PEllipticCurvePtr pEC, PFEPtr pExpectedR, PFEPtr pExpectedS,
                       PFEPtr d, ubyte *pNonce, ubyte4 nonceLen, ubyte *pHash, ubyte4 hashLen)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare;

    PFEPtr pResR = NULL;
    PFEPtr pResS = NULL;

    /* copy the nonce to the global variable for use in the "fake" RNG */
    status = copyRNGdata(pNonce, nonceLen, pEC->pPF->n);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* allocate memory for r and s */
    status = PRIMEFIELD_newElement(pEC->pPF, &pResR);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(pEC->pPF, &pResS);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* test Sign */
    status = ECDSA_signDigestAux(pEC, d, rngCallback, NULL, pHash, hashLen, pResR, pResS);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* test we got the expected result */
    compare = PRIMEFIELD_cmp(pEC->pPF, pResR, pExpectedR);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

    compare = PRIMEFIELD_cmp(pEC->pPF, pResS, pExpectedS);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

exit:

    if (NULL != pResR)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pResR);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pResS)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pResS);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}

#if defined(__ENABLE_DIGICERT_ECC_COMB__) || !defined( __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__)
/*
 If curveWinSize or pubKeyWinSize are nonzero this method tests ECDSA_verifySignatureEx.
 Otherwise it tests ECDSA_verifySignature (which actually just calls down to
 ECDSA_verifySignatureEx anyway with window sizes of 0).
 */
static int testDsaVerify(PEllipticCurvePtr pEC, sbyte4 expectedResult, PFEPtr pPubX, PFEPtr pPubY,
                         ubyte *pHash, ubyte4 hashLen, PFEPtr pR, PFEPtr pS, ubyte4 curveWinSize, ubyte pubKeyWinSize)
{
    MSTATUS status = OK;
    int retVal = 0;
    PFEPtr pCurveTable = NULL;
    PFEPtr pPubKeyTable = NULL;

    if (0 == curveWinSize && 0 == pubKeyWinSize)
    {
        /* test ECDSA_verifySignature */
        status = ECDSA_verifySignature(pEC, pPubX, pPubY, pHash, hashLen, pR, pS);
        UNITTEST_VECTOR_INT(__MOC_LINE__, (int) status, expectedResult);
    }
    else
    {
        if (curveWinSize >= 2 )
        {
            /* create the comb tables for G */

            status = EC_precomputeCombOfCurve(pEC, curveWinSize, &pCurveTable);
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
            if (OK != status)
                goto exit;
        }

        if (pubKeyWinSize >= 2 )
        {
            /* create the comb tables for G */

            status = EC_precomputeComb(pEC->pPF, pPubX, pPubY, pubKeyWinSize, &pPubKeyTable);
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
            if (OK != status)
                goto exit;
        }

        /* test ECDSA_verifySignatureEx */
        status = ECDSA_verifySignatureEx(pEC, pPubX, pPubY, pHash, hashLen, curveWinSize, pCurveTable, pubKeyWinSize, pPubKeyTable, pR, pS);
        UNITTEST_VECTOR_INT(__MOC_LINE__, (int) status, expectedResult);
    }

exit:

    if (NULL != pCurveTable)
    {
        status = EC_deleteComb(pEC->pPF, curveWinSize, &pCurveTable);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pPubKeyTable)
    {
        status = EC_deleteComb(pEC->pPF, pubKeyWinSize, &pPubKeyTable);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}
#else

/* Test ECDSA_verifySignature which makes just a straight call to ECDSA_verifySignatureEx */
static int testDsaVerify(PEllipticCurvePtr pEC, sbyte4 expectedResult, PFEPtr pPubX, PFEPtr pPubY,
                         ubyte *pHash, ubyte4 hashLen, PFEPtr pR, PFEPtr pS)
{
    MSTATUS status = OK;
    int retVal = 0;

    /* test ECDSA_verifySignature */
    status = ECDSA_verifySignature(pEC, pPubX, pPubY, pHash, hashLen, pR, pS);
    UNITTEST_VECTOR_INT(__MOC_LINE__, (int) status, expectedResult);

    return retVal;
}
#endif /* __ENABLE_DIGICERT_ECC_COMB__ or not __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__ */

static int testGenerateSharedSecret(PEllipticCurvePtr pEC, ubyte *pSSExpected,
                                    ubyte *pPointByteString, sbyte4 pointByteStringLen, PFEPtr pScalar)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare;

    ubyte *pSS = NULL;
    sbyte4 ssLen = 0;

    status = ECDH_generateSharedSecret(pEC, pPointByteString, pointByteStringLen, pScalar, &pSS, &ssLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Check that the correct shared secret was generated, note it is always zero padded */
    UNITTEST_VECTOR_INT(__MOC_LINE__, ssLen, (pEC->pPF->numBits + 7)/8);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, DIGI_MEMCMP(pSS, pSSExpected, ssLen, &compare));
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

exit:

    if (NULL != pSS)
    {
        status = DIGI_FREE((void **) &pSS);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}

static int testGenerateSharedSecretAux(PEllipticCurvePtr pEC, ubyte *pSSExpected,
                                       PFEPtr pX, PFEPtr pY, PFEPtr pScalar, sbyte4 flag)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare;
    /* note shared secret is always zero padded to this length */
    sbyte4 expectedLen = flag ? (pEC->pPF->numBits + 7)/8 : 2 * ((pEC->pPF->numBits + 7)/8);

    ubyte *pSS = NULL;
    sbyte4 ssLen = 0;

    status = ECDH_generateSharedSecretAux(pEC, pX, pY, pScalar, &pSS, &ssLen, flag);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Check that the correct shared secret was generated */
    UNITTEST_VECTOR_INT(__MOC_LINE__, ssLen, expectedLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, DIGI_MEMCMP(pSS, pSSExpected, ssLen, &compare));
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

exit:

    if (NULL != pSS)
    {
        status = DIGI_FREE((void **) &pSS);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}

#if defined(__ENABLE_DIGICERT_ECC_COMB__) || !defined( __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__)
/*
 This tests methods EC_combSize, EC_precomputeComb, EC_precomputeCombOfCurve.
 If a point P in the form of (pPxBytes, pPyBytes) is entered then EC_precomputeComb
 is called to create the comb table for P. If NULL is passed for either P param then
 the method defaults to test EC_precomputeCombOfCurve which tests creation of the
 comb table for the curve generator G.
 */
static int testCreateCombTables(PEllipticCurvePtr pEC, char **ppExpectedTable, char *pPxBytes, char *pPyBytes, sbyte4 windowSize)
{
    MSTATUS status = OK;
    int retVal = 0;
    int i;
    sbyte4 numPoints = (0x01 << windowSize) - 2;  /* table will not include O and P */
    sbyte4 coordSize = pEC->pPF->n;               /* in pf_unit words */
    sbyte4 combSize;
    sbyte4 compare;

    PFEPtr pTable = NULL;

    PFEPtr pPointX = NULL;
    PFEPtr pPointY = NULL;
    ubyte4 tempLen;

    /* First test EC_combSize */
    status = EC_combSize(pEC->pPF, windowSize, &combSize);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    UNITTEST_VECTOR_INT(__MOC_LINE__, combSize, numPoints * 2 * coordSize);  /* each point is 2 coords */

    if (NULL != pPxBytes && NULL != pPyBytes){

        UNITTEST_VECTOR_STATUS(__MOC_LINE__, PrimeFldFromStr( pEC->pPF, pPxBytes, &tempLen, &pPointX));
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, PrimeFldFromStr( pEC->pPF, pPyBytes, &tempLen, &pPointY));

        /* Test EC_precomputeComb */
        status = EC_precomputeComb(pEC->pPF, pPointX, pPointY, windowSize, &pTable);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

    }
    else
    {
        /* Test EC_precomputeCombOfCurve */
        status = EC_precomputeCombOfCurve(pEC, windowSize, &pTable);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    /* Verify the table against the expected table, re-use pPointX and pPointY PFEPtrs */
    for (i = 0; i < numPoints*2; i += 2)  /* each point is 2 coords */
    {
        /* Get the expected value and convert to PFE elements */
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, PrimeFldFromStr( pEC->pPF, ppExpectedTable[i], &tempLen, &pPointX));
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, PrimeFldFromStr( pEC->pPF, ppExpectedTable[i+1], &tempLen, &pPointY));

        /* test we got the expected x */
        compare = PRIMEFIELD_cmp(pEC->pPF, &(pTable[i*coordSize]), pPointX);
        UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

        /* test we got the expected y */
        compare = PRIMEFIELD_cmp(pEC->pPF, &(pTable[(i+1)*coordSize]), pPointY);
        UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);
    }

exit:

    if (NULL != pPointX)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pPointX);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    if (NULL != pPointY)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pPointY);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pTable)
    {
        status = EC_deleteComb(pEC->pPF, windowSize, &pTable);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    return retVal;
}
#endif /* __ENABLE_DIGICERT_ECC_COMB__ or not __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__ */

static int testGetSetPoint(PEllipticCurvePtr pEC, PFEPtr pExpectedX, PFEPtr pExpectedY, ubyte *pInput, sbyte4 inputLen)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare;

    PFEPtr pPointX = NULL;
    PFEPtr pPointY = NULL;

    ubyte *pOutBuffer = NULL;
    sbyte4 outLen = 0;
    sbyte4 expectedOutLen = 2*((pEC->pPF->numBits + 7)/8) + 1;

    ubyte pWriteBuffer[133] = {0}; /* big enough for point on P521 */

    /* First test EC_getPointByteStringLen */
    status = EC_getPointByteStringLen(pEC, &outLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    UNITTEST_VECTOR_INT(__MOC_LINE__, outLen, expectedOutLen);

    /* Test EC_byteStringToPoint which allocates the points for us */
    status = EC_byteStringToPoint(pEC, pInput, inputLen, &pPointX, &pPointY);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* check that the points are correct */
    compare = PRIMEFIELD_cmp(pEC->pPF, pPointX, pExpectedX);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

    compare = PRIMEFIELD_cmp(pEC->pPF, pPointY, pExpectedY);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

    /* test EC_pointToByteString */
    outLen = 0;
    status = EC_pointToByteString(pEC, pPointX, pPointY, &pOutBuffer, &outLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    UNITTEST_VECTOR_INT(__MOC_LINE__, outLen, expectedOutLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, DIGI_MEMCMP(pOutBuffer, pInput, outLen, &compare));
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

    /* delete the points and start over with pre-allocated points and buffers */
    if (NULL != pPointX)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pPointX);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pPointY)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pPointY);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    status = PRIMEFIELD_newElement(pEC->pPF, &pPointX);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(pEC->pPF, &pPointY);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* Test EC_setPointToByteString */
    status = EC_setPointToByteString(pEC, pInput, inputLen, pPointX, pPointY);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* check that the points are correct */
    compare = PRIMEFIELD_cmp(pEC->pPF, pPointX, pExpectedX);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

    compare = PRIMEFIELD_cmp(pEC->pPF, pPointY, pExpectedY);
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

    /* Test EC_writePointToBuffer */
    status = EC_writePointToBuffer(pEC, pPointX, pPointY, pWriteBuffer, (sbyte4) sizeof(pWriteBuffer));
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    UNITTEST_VECTOR_STATUS(__MOC_LINE__, DIGI_MEMCMP(pWriteBuffer, pInput, outLen, &compare));
    UNITTEST_VECTOR_INT(__MOC_LINE__, compare, 0);

exit:

    if (NULL != pPointX)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pPointX);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pPointY)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pPointY);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pOutBuffer)
    {
        status = DIGI_FREE((void **) &pOutBuffer);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    return retVal;
}

static int knownAnswerTest(TestVector *testVector, PEllipticCurvePtr pEC)
{
    MSTATUS status = OK;
    int retVal = 0;

    ECCKey *pKey1 = NULL;
    ECCKey *pKey2 = NULL;

    ubyte *pByteBufferInput = NULL;
    ubyte4 inputLen = 0;

    ubyte *pByteBufferInput2 = NULL;
    ubyte4 inputLen2 = 0;

    ubyte *pByteBufferResult = NULL;
    ubyte4 resultLen = 0;

    PFEPtr pfInput1 = NULL;
    ubyte4 pfInputLen1 = 0;
    PFEPtr pfInput2 = NULL;
    ubyte4 pfInputLen2 = 0;
    PFEPtr pfInput3 = NULL;
    ubyte4 pfInputLen3 = 0;
    PFEPtr pfInput4 = NULL;
    ubyte4 pfInputLen4 = 0;
    PFEPtr pfInput5 = NULL;
    ubyte4 pfInputLen5 = 0;
    PFEPtr pfResult1 = NULL;
    ubyte4 pfResultLen1 = 0;
    PFEPtr pfResult2 = NULL;
    ubyte4 pfResultLen2 = 0;
    sbyte4 byteInput1 = testVector->byteInput1;
    sbyte4 byteInput2 = testVector->byteInput2;
    sbyte4 byteResult = testVector->byteResult;
    TestVectorType type = testVector->type;

    /* set the input and result vectors from the test vector */
    if (testVector->pfInput1 != NULL)
    {
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, PrimeFldFromStr( pEC->pPF, testVector->pfInput1, &pfInputLen1, &pfInput1));
    }
    if (testVector->pfInput2 != NULL)
    {
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, PrimeFldFromStr( pEC->pPF, testVector->pfInput2, &pfInputLen2, &pfInput2));
    }
    if (testVector->pfInput3 != NULL)
    {
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, PrimeFldFromStr( pEC->pPF, testVector->pfInput3, &pfInputLen3, &pfInput3));
    }
    if (testVector->pfInput4 != NULL)
    {
        if (setKey == type || sign == type)
        {
            /* we put the pfInput4 string into a buffer rather than a PFE element. We us pByteBufferInput2 this time. */
            inputLen2 = UNITTEST_UTILS_str_to_byteStr((sbyte *) testVector->pfInput4, &pByteBufferInput2);
        }
        else
        {
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, PrimeFldFromStr( pEC->pPF, testVector->pfInput4, &pfInputLen4, &pfInput4));
        }
    }
    if (testVector->pfInput5 != NULL)
    {
        if (getSetPoint == type || setKey == type || generateKeyPair == type || sign == type || verify == type || sharedSecret == type)
        {
            /* we put the pfInput5 string into a buffer rather than a PFE element */
            inputLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) testVector->pfInput5, &pByteBufferInput);
        }
        else
        {
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, PrimeFldFromStr( pEC->pPF, testVector->pfInput5, &pfInputLen5, &pfInput5));
        }
    }
    if (testVector->pfResult1 != NULL)
    {
        if (sharedSecret == type || sharedSecretAux == type)
        {
            /* we put the pfResult1 string into a buffer rather than a PFE element */
            resultLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) testVector->pfResult1, &pByteBufferResult);
        }
        else
        {
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, PrimeFldFromStr( pEC->pPF, testVector->pfResult1, &pfResultLen1, &pfResult1));
        }
    }
    if (testVector->pfResult2 != NULL)
    {
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, PrimeFldFromStr( pEC->pPF, testVector->pfResult2, &pfResultLen2, &pfResult2));
    }

    switch(type)
    {
        case addMultiply:
            retVal += testAddMultiply(pEC, pfResult1, pfResult2, pfInput1, pfInput2, pfInput3, pfInput4, pfInput5);
            break;

        case multiply:
            retVal += testMultiply(pEC, pfResult1, pfResult2, pfInput3, pfInput4, pfInput5);
            break;

#ifdef __ENABLE_DIGICERT_ECC_ELGAMAL__
        case computeYfromX:
            retVal += testComputeYfromX(pEC, pfResult1, pfResult2, pfInput1);
            break;
#endif

        case equalKey:
        case cloneKey:

            /*
             IMPORTANT: For equalKey or cloneKey we need 6 PFE values,
             that is 3 for each key. Rather than adding another Result field
             to the TestVectors, we will just make use of what we have,
             and use pfInput1, pfInput2, pfInput3 in key 1
             and pfInput4, pfInput5, pfResult1 in key 2.
             */

            status = EC_newKey(pEC, &pKey1);
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
            if (OK != status)
                goto exit;

            status = PRIMEFIELD_copyElement(pEC->pPF, pKey1->k, pfInput1);
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
            if (OK != status)
                goto exit;

            status = PRIMEFIELD_copyElement(pEC->pPF, pKey1->Qx, pfInput2);
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
            if (OK != status)
                goto exit;

            status = PRIMEFIELD_copyElement(pEC->pPF, pKey1->Qy, pfInput3);
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
            if (OK != status)
                goto exit;

            pKey1->privateKey = (intBoolean) byteInput1;

            status = EC_newKey(pEC, &pKey2);
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
            if (OK != status)
                goto exit;

            status = PRIMEFIELD_copyElement(pEC->pPF, pKey2->k, pfInput4);
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
            if (OK != status)
                goto exit;

            status = PRIMEFIELD_copyElement(pEC->pPF, pKey2->Qx, pfInput5);
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
            if (OK != status)
                goto exit;

            status = PRIMEFIELD_copyElement(pEC->pPF, pKey2->Qy, pfResult1 /* make use as in input param */);
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
            if (OK != status)
                goto exit;

            pKey2->privateKey = (intBoolean) byteInput2;

            if (equalKey == type)
                retVal += testEqualKey(pEC, (byteBoolean) byteResult, pKey1, pKey2);
            else /* cloneKey == type */
                retVal += testCloneKey(pEC, pKey1, pKey2);

            break;

        case verifyPoint:
            retVal += testVerifyPoint(pEC, byteResult, pfInput1, pfInput2);
            break;

        case getSetPoint:
            retVal += testGetSetPoint(pEC, pfResult1, pfResult2, pByteBufferInput, inputLen);
            break;

        case verifyKeyPair:
            retVal += testVerifyKeyPair(pEC, byteResult, pfInput1, pfInput2, pfInput3);
            break;

        case generateKeyPair:
            retVal += testGenerateKeyPair(pEC, pfInput1 /* make use as a result param */, pfResult1, pfResult2, pByteBufferInput, inputLen);
            break;

        case setKey:

            /* set pKey1 to the expected key, we use pfInput 1 through pfInput3 and byteInput for the parameters */

            status = EC_newKey(pEC, &pKey1);
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
            if (OK != status)
                goto exit;

            /* pfInput 1 is allowed to be NULL if this is a public key */
            if (pfInput1 != NULL)
            {
                status = PRIMEFIELD_copyElement(pEC->pPF, pKey1->k, pfInput1);
                UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
                if (OK != status)
                    goto exit;
            }

            status = PRIMEFIELD_copyElement(pEC->pPF, pKey1->Qx, pfInput2);
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
            if (OK != status)
                goto exit;

            status = PRIMEFIELD_copyElement(pEC->pPF, pKey1->Qy, pfInput3);
            UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
            if (OK != status)
                goto exit;

            pKey1->privateKey = (intBoolean) byteInput1;

            retVal += testSetKey(pEC, pKey1, pByteBufferInput, inputLen, pByteBufferInput2, inputLen2);
            break;

        case sign:
            retVal += testDsaSign(pEC, pfResult1, pfResult2, pfInput1, pByteBufferInput2, inputLen2, pByteBufferInput, inputLen);
            break;

        case verify:

#if defined(__ENABLE_DIGICERT_ECC_COMB__) || !defined( __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__)

            /* won't test every possible window size but a decent portion of them (after 8 performace noticably slows down) */
            retVal += testDsaVerify(pEC, byteResult, pfInput1, pfInput2, pByteBufferInput, inputLen, pfInput3, pfInput4, 0, 0);
            retVal += testDsaVerify(pEC, byteResult, pfInput1, pfInput2, pByteBufferInput, inputLen, pfInput3, pfInput4, 2, 0);
            retVal += testDsaVerify(pEC, byteResult, pfInput1, pfInput2, pByteBufferInput, inputLen, pfInput3, pfInput4, 3, 0);
            retVal += testDsaVerify(pEC, byteResult, pfInput1, pfInput2, pByteBufferInput, inputLen, pfInput3, pfInput4, 4, 0);
            retVal += testDsaVerify(pEC, byteResult, pfInput1, pfInput2, pByteBufferInput, inputLen, pfInput3, pfInput4, 5, 0);
            retVal += testDsaVerify(pEC, byteResult, pfInput1, pfInput2, pByteBufferInput, inputLen, pfInput3, pfInput4, 6, 0);
            retVal += testDsaVerify(pEC, byteResult, pfInput1, pfInput2, pByteBufferInput, inputLen, pfInput3, pfInput4, 0, 2);
            retVal += testDsaVerify(pEC, byteResult, pfInput1, pfInput2, pByteBufferInput, inputLen, pfInput3, pfInput4, 0, 3);
            retVal += testDsaVerify(pEC, byteResult, pfInput1, pfInput2, pByteBufferInput, inputLen, pfInput3, pfInput4, 0, 4);
            retVal += testDsaVerify(pEC, byteResult, pfInput1, pfInput2, pByteBufferInput, inputLen, pfInput3, pfInput4, 0, 5);
            retVal += testDsaVerify(pEC, byteResult, pfInput1, pfInput2, pByteBufferInput, inputLen, pfInput3, pfInput4, 0, 6);
            retVal += testDsaVerify(pEC, byteResult, pfInput1, pfInput2, pByteBufferInput, inputLen, pfInput3, pfInput4, 2, 2);
            retVal += testDsaVerify(pEC, byteResult, pfInput1, pfInput2, pByteBufferInput, inputLen, pfInput3, pfInput4, 3, 3);
            retVal += testDsaVerify(pEC, byteResult, pfInput1, pfInput2, pByteBufferInput, inputLen, pfInput3, pfInput4, 4, 4);
            retVal += testDsaVerify(pEC, byteResult, pfInput1, pfInput2, pByteBufferInput, inputLen, pfInput3, pfInput4, 5, 5);
            retVal += testDsaVerify(pEC, byteResult, pfInput1, pfInput2, pByteBufferInput, inputLen, pfInput3, pfInput4, 6, 6);
            retVal += testDsaVerify(pEC, byteResult, pfInput1, pfInput2, pByteBufferInput, inputLen, pfInput3, pfInput4, 8, 8);
#else
            retVal += testDsaVerify(pEC, byteResult, pfInput1, pfInput2, pByteBufferInput, inputLen, pfInput3, pfInput4);

#endif /* __ENABLE_DIGICERT_ECC_COMB__ or not __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__ */

            break;

        case sharedSecret:
            retVal += testGenerateSharedSecret(pEC, pByteBufferResult, pByteBufferInput, inputLen, pfInput1);
            break;

        case sharedSecretAux:
            retVal += testGenerateSharedSecretAux(pEC, pByteBufferResult, pfInput2, pfInput3, pfInput1, byteInput1);
            break;

        default:
            break;
    }

exit:

    if(NULL != pfInput1)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pfInput1);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if(NULL != pfInput2)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pfInput2);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if(NULL != pfInput3)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pfInput3);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if(NULL != pfInput4)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pfInput4);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if(NULL != pfInput5)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pfInput5);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if(NULL != pfResult1)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pfResult1);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if(NULL != pfResult2)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pfResult2);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pKey1)
    {
        status = EC_deleteKey(&pKey1);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pKey2)
    {
        status = EC_deleteKey(&pKey2);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pByteBufferInput)
    {
        status = DIGI_FREE((void **) &pByteBufferInput);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pByteBufferInput2)
    {
        status = DIGI_FREE((void **) &pByteBufferInput2);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pByteBufferResult)
    {
        status = DIGI_FREE((void **) &pByteBufferResult);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }

    return retVal;
}

static int testGetUnderlyingField(PEllipticCurvePtr pEC, PrimeFieldPtr pExpectedField)
{
    PrimeFieldPtr pField = NULL;

    pField = EC_getUnderlyingField(pEC);

    if (!PRIMEFIELD_comparePrimeFields(pField, pExpectedField)) /* pointer comparison, only one instance of the field should exist */
    {
        /* force error */
        UNITTEST_STATUS(__MOC_LINE__, -1);
        return -1;
    }

    return 0;
}

static int testErrorCases(PEllipticCurvePtr pEC, ubyte *pPrime, ubyte4 primeLen)
{
    int retVal = 0;
    MSTATUS status = OK;

    PrimeFieldPtr pField = NULL;
    PFEPtr pPoint1 = NULL;
    PFEPtr pPoint2 = NULL;
    PFEPtr pPoint3 = NULL;
    PFEPtr pPoint4 = NULL;
    PFEPtr pPoint5 = NULL;
    PFEPtr pPoint6 = NULL;
    PFEPtr pPoint7 = NULL;

    ECCKey *pKey1 = NULL;
    ECCKey *pKey2 = NULL;

    PFEPtr pTable = NULL;

    byteBoolean res;
    ubyte pPointBuffer[133] = {0}; /* big enough for P521 */
    ubyte pScalarBuffer[66] = {0};
    ubyte4 coordByteLen = (ubyte4) ((pEC->pPF->numBits + 7)/8);

    ubyte pHashBuffer[64] = {0};

    ubyte *pOutBuffer = NULL;
    sbyte4 outLen = 0;

    /* properly allocate points in order to test APIs one field at a time */
    status = PRIMEFIELD_newElement(pEC->pPF, &pPoint1);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(pEC->pPF, &pPoint2);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(pEC->pPF, &pPoint3);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(pEC->pPF, &pPoint4);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(pEC->pPF, &pPoint5);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(pEC->pPF, &pPoint6);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = PRIMEFIELD_newElement(pEC->pPF, &pPoint7);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /******* Test EC_getUnderlyingField *******/

    pField = EC_getUnderlyingField(NULL);
    if (NULL != pField)
    { /* force an error */
        retVal += UNITTEST_INT(__MOC_LINE__, 0, ERR_NULL_POINTER);
    }

    /******* EC_multiplyPoint *******/

    status = EC_multiplyPoint(NULL, pPoint1, pPoint2, pPoint3, pPoint4, pPoint5);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_multiplyPoint(pEC->pPF, NULL, pPoint2, pPoint3, pPoint4, pPoint5);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_multiplyPoint(pEC->pPF, pPoint1, NULL, pPoint3, pPoint4, pPoint5);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_multiplyPoint(pEC->pPF, pPoint1, pPoint2, NULL, pPoint4, pPoint5);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_multiplyPoint(pEC->pPF, pPoint1, pPoint2, pPoint3, NULL, pPoint5);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_multiplyPoint(pEC->pPF, pPoint1, pPoint2, pPoint3, pPoint4, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /******* EC_addMultiplyPoint *******/

    status = EC_addMultiplyPoint(NULL, pPoint1, pPoint2, pPoint3, pPoint4, pPoint5, pPoint6, pPoint7);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_addMultiplyPoint(pEC->pPF, NULL, pPoint2, pPoint3, pPoint4, pPoint5, pPoint6, pPoint7);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_addMultiplyPoint(pEC->pPF, pPoint1, NULL, pPoint3, pPoint4, pPoint5, pPoint6, pPoint7);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_addMultiplyPoint(pEC->pPF, pPoint1, pPoint2, NULL, pPoint4, pPoint5, pPoint6, pPoint7);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_addMultiplyPoint(pEC->pPF, pPoint1, pPoint2, pPoint3, NULL, pPoint5, pPoint6, pPoint7);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_addMultiplyPoint(pEC->pPF, pPoint1, pPoint2, pPoint3, pPoint4, NULL, pPoint6, pPoint7);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_addMultiplyPoint(pEC->pPF, pPoint1, pPoint2, pPoint3, pPoint4, pPoint5, NULL, pPoint7);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_addMultiplyPoint(pEC->pPF, pPoint1, pPoint2, pPoint3, pPoint4, pPoint5, pPoint6, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

#ifdef __ENABLE_DIGICERT_ECC_ELGAMAL__

    /******* EC_computeYFromX *******/

    status = EC_computeYFromX(NULL, pPoint1, pPoint2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_computeYFromX(pEC, NULL, pPoint2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_computeYFromX(pEC, pPoint1, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

#endif

    /******* EC_newKey *******/

    status = EC_newKey(NULL, &pKey1);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_newKey(pEC, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* Properly allocate pKey1 for further tests */

    status = EC_newKey(pEC, &pKey1);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

    /******* EC_cloneKey *******/

    status = EC_cloneKey(NULL, pKey1);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_cloneKey(&pKey2, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /******* EC_equalKey *******/

    status = EC_equalKey(NULL, pKey1, &res);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_equalKey(pKey1, NULL, &res);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_equalKey(pKey1, pKey1, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /******* EC_setKeyParameters *******/

    status = EC_setKeyParameters(NULL, pPointBuffer, 2*coordByteLen + 1, pScalarBuffer, coordByteLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_setKeyParameters(pKey1, NULL, 2*coordByteLen + 1, NULL, coordByteLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* Note: scalar NULL is a proper use case for a public key */

    /* Note: scalar validation is handled before the point validation, make scalar nonzero */
    pScalarBuffer[0] = 0x80;

    /* scalar length too big */
    status = EC_setKeyParameters(pKey1, pPointBuffer, 2*coordByteLen + 1, pScalarBuffer, coordByteLen + 1);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);

    /* scalar of 0 TO DO UNCOMMENT IF disallowed, Add test of scalar = n if appropriate */

    /* status = EC_setKeyParameters(pKey1, pPointBuffer, 2*coordByteLen + 1, pScalarBuffer, coordByteLen);
     retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);*/

    /* Note: we allow scalars bigger than n (and do not reduce mod n). We do not allow a scalar of p or larger */

    status = EC_setKeyParameters(pKey1, pPointBuffer, 2*coordByteLen + 1, pPrime, primeLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);

    /* point length too small */

    status = EC_setKeyParameters(pKey1, pPointBuffer, 0, NULL, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);

    status = EC_setKeyParameters(pKey1, pPointBuffer, 2*coordByteLen, NULL, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);

    /* point length too big */

    status = EC_setKeyParameters(pKey1, pPointBuffer, 2*coordByteLen + 2, NULL, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);

    /* inproperly encoded point */

    status = EC_setKeyParameters(pKey1, pPointBuffer, 2*coordByteLen + 1, NULL, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_UNSUPPORTED_PT_REPRESENTATION);

    /* set a proper encoding type for the points first byte, for later tests */

    pPointBuffer[0] = 0x04;

    /* point (0,0) which is not on any of our curves */

    status = EC_setKeyParameters(pKey1, pPointBuffer, 2*coordByteLen + 1, NULL, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FALSE);

    /* point with second coord invalid, p or larger */

    status = DIGI_MEMCPY(pPointBuffer + 1 + coordByteLen, pPrime, primeLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = EC_setKeyParameters(pKey1, pPointBuffer, 2*coordByteLen + 1, NULL, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);

    /* point with first coord invalid, p or larger */

    status = DIGI_MEMCPY(pPointBuffer + 1, pPrime, primeLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = EC_setKeyParameters(pKey1, pPointBuffer, 2*coordByteLen + 1, NULL, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);

    /******* EC_verifyKeyPair *******/

    status = EC_verifyKeyPair(NULL, pPoint1, pPoint2, pPoint3);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_verifyKeyPair(pEC, NULL, pPoint2, pPoint3);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_verifyKeyPair(pEC, pPoint1, NULL, pPoint3);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_verifyKeyPair(pEC, pPoint1, pPoint2, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* Verifying an invalid scalar-Point product is part of the test vectors */

    /******* EC_generateKeyPair *******/

    status = EC_generateKeyPair(NULL, rngCallback, NULL, pPoint3, pPoint4, pPoint5);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_generateKeyPair(pEC, NULL, NULL, pPoint3, pPoint4, pPoint5);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_generateKeyPair(pEC, rngCallback, NULL, NULL, pPoint4, pPoint5);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_generateKeyPair(pEC, rngCallback, NULL, pPoint3, NULL, pPoint5);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_generateKeyPair(pEC, rngCallback, NULL, pPoint3, pPoint4, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /******* EC_deleteKey *******/

    status = EC_deleteKey(NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* a key that was never allocated */
    status = EC_deleteKey(&pKey2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /******* EC_verifyPublicKey *******/

    status = EC_verifyPublicKey(NULL, pPoint1, pPoint2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_verifyPublicKey(pEC, NULL, pPoint2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_verifyPublicKey(pEC, pPoint1, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* verifying a public key that is not on the curve is in the test vectors */

    /******* EC_verifyPoint *******/

    status = EC_verifyPoint(NULL, pPoint1, pPoint2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_verifyPoint(pEC, NULL, pPoint2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_verifyPoint(pEC, pPoint1, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* verifying a point that is not on the curve is in the test vectors */

    /******* EC_pointToByteString *******/

    status = EC_pointToByteString(NULL, pPoint1, pPoint2, &pOutBuffer, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_pointToByteString(pEC, NULL, pPoint2, &pOutBuffer, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_pointToByteString(pEC, pPoint1, NULL, &pOutBuffer, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_pointToByteString(pEC, pPoint1, pPoint2, NULL, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_pointToByteString(pEC, pPoint1, pPoint2, &pOutBuffer, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /******* EC_setPointToByteString *******/

    status = EC_setPointToByteString(NULL, pPointBuffer, 2*coordByteLen + 1, pPoint1, pPoint2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_setPointToByteString(pEC, NULL, 2*coordByteLen + 1, pPoint1, pPoint2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_setPointToByteString(pEC, pPointBuffer, 2*coordByteLen + 1, NULL, pPoint2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_setPointToByteString(pEC, pPointBuffer, 2*coordByteLen + 1, pPoint1, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* point length too small */

    status = EC_setPointToByteString(pEC, pPointBuffer, 0, pPoint1, pPoint2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);

    status = EC_setPointToByteString(pEC, pPointBuffer, 2*coordByteLen, pPoint1, pPoint2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);

    /* point length too big */

    status = EC_setPointToByteString(pEC, pPointBuffer, 2*coordByteLen + 2, pPoint1, pPoint2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);

    /* inproperly encoded point */

    pPointBuffer[0] = 0x03;
    status = EC_setPointToByteString(pEC, pPointBuffer, 2*coordByteLen + 1, pPoint1, pPoint2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_UNSUPPORTED_PT_REPRESENTATION);

    /* point (0,0) which is not on any of our curves */

    pPointBuffer[0] = 0x04;
    status = DIGI_MEMSET(pPointBuffer + 1, 0x00, 2*coordByteLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = EC_setPointToByteString(pEC, pPointBuffer, 2*coordByteLen + 1, pPoint1, pPoint2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FALSE);

    /* point with second coord invalid, p or larger */

    status = DIGI_MEMCPY(pPointBuffer + 1 + coordByteLen, pPrime, primeLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = EC_setPointToByteString(pEC, pPointBuffer, 2*coordByteLen + 1, pPoint1, pPoint2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);

    /* point with first coord invalid, p or larger */

    status = DIGI_MEMCPY(pPointBuffer + 1, pPrime, primeLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = EC_setPointToByteString(pEC, pPointBuffer, 2*coordByteLen + 1, pPoint1, pPoint2);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);

    /******* EC_getPointByteStringLen *******/

    status = EC_getPointByteStringLen(NULL, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_getPointByteStringLen(pEC, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /******* EC_writePointToBuffer *******/

    status = EC_writePointToBuffer(NULL, pPoint1, pPoint2, pPointBuffer, sizeof(pPointBuffer));
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_writePointToBuffer(pEC, NULL, pPoint2, pPointBuffer, sizeof(pPointBuffer));
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_writePointToBuffer(pEC, pPoint1, NULL, pPointBuffer, sizeof(pPointBuffer));
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_writePointToBuffer(pEC, pPoint1, pPoint2, NULL, sizeof(pPointBuffer));
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* out buffer too small */

    status = EC_writePointToBuffer(pEC, pPoint1, pPoint2, pPointBuffer, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BUFFER_OVERFLOW);

    /* make sure one of the coords is not 0 */
    pPoint1->units[0] = 0x01;
    status = EC_writePointToBuffer(pEC, pPoint1, pPoint2, pPointBuffer, 2*coordByteLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BUFFER_OVERFLOW);

    /******* EC_byteStringToPoint *******/

    /* free pPoint6 and pPoint7 for next test */

    if(NULL != pPoint6)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pPoint6);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if(NULL != pPoint7)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pPoint7);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = EC_byteStringToPoint(NULL, pPointBuffer, 2*coordByteLen + 1, &pPoint6, &pPoint7);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_byteStringToPoint(pEC, NULL, 2*coordByteLen + 1, &pPoint6, &pPoint7);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_byteStringToPoint(pEC, pPointBuffer, 2*coordByteLen + 1, NULL, &pPoint7);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_byteStringToPoint(pEC, pPointBuffer, 2*coordByteLen + 1, &pPoint6, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* point length too small */

    status = EC_byteStringToPoint(pEC, pPointBuffer, 0, &pPoint6, &pPoint7);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);

    status = EC_byteStringToPoint(pEC, pPointBuffer, 2*coordByteLen, &pPoint6, &pPoint7);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);

    /* point length too big */

    status = EC_byteStringToPoint(pEC, pPointBuffer, 2*coordByteLen + 2, &pPoint6, &pPoint7);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);

    /* inproperly encoded point */

    pPointBuffer[0] = 0x02;
    status = EC_byteStringToPoint(pEC, pPointBuffer, 2*coordByteLen + 1, &pPoint6, &pPoint7);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_UNSUPPORTED_PT_REPRESENTATION);

    /* point (0,0) which is not on any of our curves */

    pPointBuffer[0] = 0x04;
    status = DIGI_MEMSET(pPointBuffer + 1, 0x00, 2*coordByteLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = EC_byteStringToPoint(pEC, pPointBuffer, 2*coordByteLen + 1, &pPoint6, &pPoint7);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FALSE);

    /* point with second coord invalid, p or larger */

    status = DIGI_MEMCPY(pPointBuffer + 1 + coordByteLen, pPrime, primeLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = EC_byteStringToPoint(pEC, pPointBuffer, 2*coordByteLen + 1, &pPoint6, &pPoint7);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);

    /* point with first coord invalid, p or larger */

    status = DIGI_MEMCPY(pPointBuffer + 1, pPrime, primeLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = EC_byteStringToPoint(pEC, pPointBuffer, 2*coordByteLen + 1, &pPoint6, &pPoint7);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);

    /******* ECDSA_signDigestAux *******/

    status = ECDSA_signDigestAux(NULL, pPoint1, rngCallback, NULL, pHashBuffer, sizeof(pHashBuffer), pPoint2, pPoint3);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_signDigestAux(pEC, NULL, rngCallback, NULL, pHashBuffer, sizeof(pHashBuffer), pPoint2, pPoint3);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_signDigestAux(pEC, pPoint1, NULL, NULL, pHashBuffer, sizeof(pHashBuffer), pPoint2, pPoint3);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_signDigestAux(pEC, pPoint1, rngCallback, NULL, NULL, 0, pPoint2, pPoint3);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_signDigestAux(pEC, pPoint1, rngCallback, NULL, pHashBuffer, sizeof(pHashBuffer), NULL, pPoint3);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_signDigestAux(pEC, pPoint1, rngCallback, NULL, pHashBuffer, sizeof(pHashBuffer), pPoint2, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /******* ECDSA_verifySignature *******/

    status = ECDSA_verifySignature(NULL, pPoint1, pPoint2, pHashBuffer, sizeof(pHashBuffer), pPoint3, pPoint4);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_verifySignature(pEC, NULL, pPoint2, pHashBuffer, sizeof(pHashBuffer), pPoint3, pPoint4);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_verifySignature(pEC, pPoint1, NULL, pHashBuffer, sizeof(pHashBuffer), pPoint3, pPoint4);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_verifySignature(pEC, pPoint1, pPoint2, NULL, 0, pPoint3, pPoint4);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_verifySignature(pEC, pPoint1, pPoint2, pHashBuffer, sizeof(pHashBuffer), NULL, pPoint4);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_verifySignature(pEC, pPoint1, pPoint2, pHashBuffer, sizeof(pHashBuffer), pPoint3, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* invalid r,s parameters are tested in the test vectors */

    /******* ECDH_generateSharedSecretAux *******/

    status = ECDH_generateSharedSecretAux(NULL, pPoint1, pPoint2, pPoint3, &pOutBuffer, &outLen, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDH_generateSharedSecretAux(pEC, NULL, pPoint2, pPoint3, &pOutBuffer, &outLen, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDH_generateSharedSecretAux(pEC, pPoint1, NULL, pPoint3, &pOutBuffer, &outLen, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDH_generateSharedSecretAux(pEC, pPoint1, pPoint2, NULL, &pOutBuffer, &outLen, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDH_generateSharedSecretAux(pEC, pPoint1, pPoint2, pPoint3, NULL, &outLen, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDH_generateSharedSecretAux(pEC, pPoint1, pPoint2, pPoint3, &pOutBuffer, NULL, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /******* ECDH_generateSharedSecret *******/

    status = ECDH_generateSharedSecret(NULL, pPointBuffer, 2*coordByteLen + 1, pPoint3, &pOutBuffer, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDH_generateSharedSecret(pEC, NULL, 2*coordByteLen + 1, pPoint3, &pOutBuffer, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDH_generateSharedSecret(pEC, pPointBuffer, 2*coordByteLen + 1, NULL, &pOutBuffer, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDH_generateSharedSecret(pEC, pPointBuffer, 2*coordByteLen + 1, pPoint3, NULL, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDH_generateSharedSecret(pEC, pPointBuffer, 2*coordByteLen + 1, pPoint3, &pOutBuffer, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* point (public key) length too small */

    status = ECDH_generateSharedSecret(pEC, pPointBuffer, 0, pPoint3, &pOutBuffer, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);

    status = ECDH_generateSharedSecret(pEC, pPointBuffer, 2*coordByteLen, pPoint3, &pOutBuffer, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);

    /* point (public key) length too big */

    status = ECDH_generateSharedSecret(pEC, pPointBuffer, 2*coordByteLen + 2, pPoint3, &pOutBuffer, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_INVALID_PT_STRING);

    /* inproperly encoded point (public key) */

    pPointBuffer[0] = 0x01;
    status = ECDH_generateSharedSecret(pEC, pPointBuffer, 2*coordByteLen + 1, pPoint3, &pOutBuffer, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_UNSUPPORTED_PT_REPRESENTATION);

    /* point (public key) (0,0) which is not on any of our curves */

    pPointBuffer[0] = 0x04;
    status = DIGI_MEMSET(pPointBuffer + 1, 0x00, 2*coordByteLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = ECDH_generateSharedSecret(pEC, pPointBuffer, 2*coordByteLen + 1, pPoint3, &pOutBuffer, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FALSE);

    /* point (public key) with second coord invalid, p or larger */

    status = DIGI_MEMCPY(pPointBuffer + 1 + coordByteLen, pPrime, primeLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = ECDH_generateSharedSecret(pEC, pPointBuffer, 2*coordByteLen + 1, pPoint3, &pOutBuffer, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);

    /* point (public key) with first coord invalid, p or larger */

    status = DIGI_MEMCPY(pPointBuffer + 1, pPrime, primeLen);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = ECDH_generateSharedSecret(pEC, pPointBuffer, 2*coordByteLen + 1, pPoint3, &pOutBuffer, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_FF_DIFFERENT_FIELDS);

#if defined(__ENABLE_DIGICERT_ECC_COMB__) || !defined( __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__)

    /******* EC_combSize *******/

    status = EC_combSize(NULL, 2, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_combSize(pEC->pPF, 2, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* invalid window size */
    status = EC_combSize(pEC->pPF, 0, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    status = EC_combSize(pEC->pPF, 1, &outLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    /******* EC_precomputeComb *******/

    /* this allocates a table in the last arg, so use the already freed pPoint6 */
    status = EC_precomputeComb(NULL, pPoint1, pPoint2, 2, &pPoint6);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_precomputeComb(pEC->pPF, NULL, pPoint2, 2, &pPoint6);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_precomputeComb(pEC->pPF, pPoint1, NULL, 2, &pPoint6);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_precomputeComb(pEC->pPF, pPoint1, pPoint2, 2, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* invalid window size */
    status = EC_precomputeComb(pEC->pPF, pPoint1, pPoint2, -1, &pPoint6);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    status = EC_precomputeComb(pEC->pPF, pPoint1, pPoint2, 0, &pPoint6);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    status = EC_precomputeComb(pEC->pPF, pPoint1, pPoint2, 1, &pPoint6);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    /******* EC_precomputeCombOfCurve *******/

    /* this allocates a table in the last arg, so use the already freed pPoint6 */
    status = EC_precomputeCombOfCurve(NULL, 2, &pPoint6);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_precomputeCombOfCurve(pEC, 2, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* invalid window size */
    status = EC_precomputeCombOfCurve(pEC, -1, &pPoint6);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    status = EC_precomputeCombOfCurve(pEC, 0, &pPoint6);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    status = EC_precomputeCombOfCurve(pEC, 1, &pPoint6);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    /******* EC_deleteComb *******/

    status = EC_deleteComb(NULL, 2, &pTable);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = EC_deleteComb(pEC->pPF, 2, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* table never allocated */
    status = EC_deleteComb(pEC->pPF, 2, &pTable);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* allocate a table for next tests */
    status = EC_precomputeCombOfCurve(pEC, 2, &pTable);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = EC_deleteComb(pEC->pPF, -1, &pTable);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    status = EC_deleteComb(pEC->pPF, 0, &pTable);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    status = EC_deleteComb(pEC->pPF, 1, &pTable);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    /* properly delete the Comb, no longer needed */
    status = EC_deleteComb(pEC->pPF, 2, &pTable);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);

#endif /* __ENABLE_DIGICERT_ECC_COMB__ or not __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__ */

    /******* ECDSA_verifySignatureEx *******/

    status = ECDSA_verifySignatureEx(NULL, pPoint1, pPoint2, pHashBuffer, sizeof(pHashBuffer), 0, NULL, 0, NULL, pPoint3, pPoint4);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_verifySignatureEx(pEC, NULL, pPoint2, pHashBuffer, sizeof(pHashBuffer), 0, NULL, 0, NULL, pPoint3, pPoint4);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_verifySignatureEx(pEC, pPoint1, NULL, pHashBuffer, sizeof(pHashBuffer), 0, NULL, 0, NULL, pPoint3, pPoint4);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_verifySignatureEx(pEC, pPoint1, pPoint2, NULL, 0, 0, NULL, 0, NULL, pPoint3, pPoint4);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_verifySignatureEx(pEC, pPoint1, pPoint2, pHashBuffer, sizeof(pHashBuffer), 0, NULL, 0, NULL, NULL, pPoint4);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = ECDSA_verifySignatureEx(pEC, pPoint1, pPoint2, pHashBuffer, sizeof(pHashBuffer), 0, NULL, 0, NULL, pPoint3, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* invalid window sizes */

    status = ECDSA_verifySignatureEx(pEC, pPoint1, pPoint2, pHashBuffer, sizeof(pHashBuffer), -1, NULL, 0, NULL, pPoint3, pPoint4);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    status = ECDSA_verifySignatureEx(pEC, pPoint1, pPoint2, pHashBuffer, sizeof(pHashBuffer), 0, NULL, -1, NULL, pPoint3, pPoint4);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    status = ECDSA_verifySignatureEx(pEC, pPoint1, pPoint2, pHashBuffer, sizeof(pHashBuffer), 1, NULL, 0, NULL, pPoint3, pPoint4);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    status = ECDSA_verifySignatureEx(pEC, pPoint1, pPoint2, pHashBuffer, sizeof(pHashBuffer), 0, NULL, 1, NULL, pPoint3, pPoint4);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

#if defined(__ENABLE_DIGICERT_ECC_COMB__) || !defined( __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__)

    /* valid curve comb size but NULL comb */
    status = ECDSA_verifySignatureEx(pEC, pPoint1, pPoint2, pHashBuffer, sizeof(pHashBuffer), 2, NULL, 0, NULL, pPoint3, pPoint4);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* valid public key comb size but NULL comb */
    status = ECDSA_verifySignatureEx(pEC, pPoint1, pPoint2, pHashBuffer, sizeof(pHashBuffer), 0, NULL, 2, NULL, pPoint3, pPoint4);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

#else

    status = ECDSA_verifySignatureEx(pEC, pPoint1, pPoint2, pHashBuffer, sizeof(pHashBuffer), 2, NULL, 0, NULL, pPoint3, pPoint4);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

    status = ECDSA_verifySignatureEx(pEC, pPoint1, pPoint2, pHashBuffer, sizeof(pHashBuffer), 0, NULL, 2, NULL, pPoint3, pPoint4);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_INVALID_ARG);

#endif /* __ENABLE_DIGICERT_ECC_COMB__ or not __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__ */

    /* invalid r,s parameters are tested in the test vectors */

    /* pKey2 should never have been allocated */
    if (NULL != pKey2)
    { /* force error */
        retVal += UNITTEST_INT(__MOC_LINE__, -1, 0);
        status = EC_deleteKey(&pKey2);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

    /* pOutBuffer should never have been allocated */
    if (NULL != pOutBuffer)
    { /* force error */
        retVal += UNITTEST_INT(__MOC_LINE__, -1, 0);
        status = DIGI_FREE((void **) &pOutBuffer);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }

exit:

    if(NULL != pPoint1)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pPoint1);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if(NULL != pPoint2)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pPoint2);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if(NULL != pPoint3)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pPoint3);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if(NULL != pPoint4)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pPoint4);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if(NULL != pPoint5)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pPoint5);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if(NULL != pPoint6)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pPoint6);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if(NULL != pPoint7)
    {
        status = PRIMEFIELD_deleteElement(pEC->pPF, &pPoint7);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pKey1)
    {
        status = EC_deleteKey(&pKey1);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    /* pTable already deleted, no chance to have gone to exit first */

    return retVal;
}
#endif /* __ENABLE_DIGICERT_ECC__ */

int primeec_unit_test_all()
{
    int retVal = 0;
    int i;
    MSTATUS status = OK;

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

#ifdef __ENABLE_DIGICERT_ECC__
#ifdef __ENABLE_DIGICERT_ECC_P192__

    /* Test P192 */

    retVal += testGetUnderlyingField(EC_P192, PF_p192);

#if defined(__ENABLE_DIGICERT_ECC_COMB__) || !defined( __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__)

    retVal += testCreateCombTables(EC_P192, gpExpectedCombG_w2_p192, NULL, NULL, 2);
    retVal += testCreateCombTables(EC_P192, gpExpectedCombG_w3_p192, NULL, NULL, 3);
    retVal += testCreateCombTables(EC_P192, gpExpectedCombG_w4_p192, NULL, NULL, 4);
    retVal += testCreateCombTables(EC_P192, gpExpectedCombG_w5_p192, NULL, NULL, 5);
    retVal += testCreateCombTables(EC_P192, gpExpectedCombP_w2_p192, gpPointP_p192[0], gpPointP_p192[1], 2);
    retVal += testCreateCombTables(EC_P192, gpExpectedCombP_w3_p192, gpPointP_p192[0], gpPointP_p192[1], 3);
    retVal += testCreateCombTables(EC_P192, gpExpectedCombP_w4_p192, gpPointP_p192[0], gpPointP_p192[1], 4);
    retVal += testCreateCombTables(EC_P192, gpExpectedCombP_w5_p192, gpPointP_p192[0], gpPointP_p192[1], 5);

#endif /* __ENABLE_DIGICERT_ECC_COMB__ or not __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__ */

#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 192;
#endif
    for (i = 0; i < COUNTOF(gTestVector_p192); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p192+i, EC_P192);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }

    retVal += testErrorCases(EC_P192, gpP_192, (ubyte4) sizeof(gpP_192));

#endif /* __ENABLE_DIGICERT_ECC_P192__  */

#ifndef __DISABLE_DIGICERT_ECC_P224__

    /* Test P224 */

    retVal += testGetUnderlyingField(EC_P224, PF_p224);

#if defined(__ENABLE_DIGICERT_ECC_COMB__) || !defined( __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__)

    retVal += testCreateCombTables(EC_P224, gpExpectedCombG_w2_p224, NULL, NULL, 2);
    retVal += testCreateCombTables(EC_P224, gpExpectedCombG_w3_p224, NULL, NULL, 3);
    retVal += testCreateCombTables(EC_P224, gpExpectedCombG_w4_p224, NULL, NULL, 4);
    retVal += testCreateCombTables(EC_P224, gpExpectedCombG_w5_p224, NULL, NULL, 5);
    retVal += testCreateCombTables(EC_P224, gpExpectedCombP_w2_p224, gpPointP_p224[0], gpPointP_p224[1], 2);
    retVal += testCreateCombTables(EC_P224, gpExpectedCombP_w3_p224, gpPointP_p224[0], gpPointP_p224[1], 3);
    retVal += testCreateCombTables(EC_P224, gpExpectedCombP_w4_p224, gpPointP_p224[0], gpPointP_p224[1], 4);
    retVal += testCreateCombTables(EC_P224, gpExpectedCombP_w5_p224, gpPointP_p224[0], gpPointP_p224[1], 5);

#endif /* __ENABLE_DIGICERT_ECC_COMB__ or not __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__ */

#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 224;
#endif
    for (i = 0; i < COUNTOF(gTestVector_p224); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p224+i, EC_P224);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }

    retVal += testErrorCases(EC_P224, gpP_224, (ubyte4) sizeof(gpP_224));

#endif /* __DISABLE_DIGICERT_ECC_P224__ */

#ifndef __DISABLE_DIGICERT_ECC_P256__

    /* Test P256 */

    retVal += testGetUnderlyingField(EC_P256, PF_p256);

#if defined(__ENABLE_DIGICERT_ECC_COMB__) || !defined( __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__)

    retVal += testCreateCombTables(EC_P256, gpExpectedCombG_w2_p256, NULL, NULL, 2);
    retVal += testCreateCombTables(EC_P256, gpExpectedCombG_w3_p256, NULL, NULL, 3);
    retVal += testCreateCombTables(EC_P256, gpExpectedCombG_w4_p256, NULL, NULL, 4);
    retVal += testCreateCombTables(EC_P256, gpExpectedCombG_w5_p256, NULL, NULL, 5);
    retVal += testCreateCombTables(EC_P256, gpExpectedCombP_w2_p256, gpPointP_p256[0], gpPointP_p256[1], 2);
    retVal += testCreateCombTables(EC_P256, gpExpectedCombP_w3_p256, gpPointP_p256[0], gpPointP_p256[1], 3);
    retVal += testCreateCombTables(EC_P256, gpExpectedCombP_w4_p256, gpPointP_p256[0], gpPointP_p256[1], 4);
    retVal += testCreateCombTables(EC_P256, gpExpectedCombP_w5_p256, gpPointP_p256[0], gpPointP_p256[1], 5);

#endif /* __ENABLE_DIGICERT_ECC_COMB__ or not __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__ */

#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 256;
#endif
    for (i = 0; i < COUNTOF(gTestVector_p256); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p256+i, EC_P256);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }

    retVal += testErrorCases(EC_P256, gpP_256, (ubyte4) sizeof(gpP_256));

#endif /* __DISABLE_DIGICERT_ECC_P256__ */

#ifndef __DISABLE_DIGICERT_ECC_P384__

    /* Test P384 */

    retVal += testGetUnderlyingField(EC_P384, PF_p384);

#if defined(__ENABLE_DIGICERT_ECC_COMB__) || !defined( __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__)

    retVal += testCreateCombTables(EC_P384, gpExpectedCombG_w2_p384, NULL, NULL, 2);
    retVal += testCreateCombTables(EC_P384, gpExpectedCombG_w3_p384, NULL, NULL, 3);
    retVal += testCreateCombTables(EC_P384, gpExpectedCombG_w4_p384, NULL, NULL, 4);
    retVal += testCreateCombTables(EC_P384, gpExpectedCombG_w5_p384, NULL, NULL, 5);
    retVal += testCreateCombTables(EC_P384, gpExpectedCombP_w2_p384, gpPointP_p384[0], gpPointP_p384[1], 2);
    retVal += testCreateCombTables(EC_P384, gpExpectedCombP_w3_p384, gpPointP_p384[0], gpPointP_p384[1], 3);
    retVal += testCreateCombTables(EC_P384, gpExpectedCombP_w4_p384, gpPointP_p384[0], gpPointP_p384[1], 4);
    retVal += testCreateCombTables(EC_P384, gpExpectedCombP_w5_p384, gpPointP_p384[0], gpPointP_p384[1], 5);

#endif /* __ENABLE_DIGICERT_ECC_COMB__ or not __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__ */

#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 384;
#endif
    for (i = 0; i < COUNTOF(gTestVector_p384); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p384+i, EC_P384);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }

    retVal += testErrorCases(EC_P384, gpP_384, (ubyte4) sizeof(gpP_384));

#endif /* __DISABLE_DIGICERT_ECC_P384__ */

#ifndef __DISABLE_DIGICERT_ECC_P521__

    /* Test P521 */

    retVal += testGetUnderlyingField(EC_P521, PF_p521);

#if defined(__ENABLE_DIGICERT_ECC_COMB__) || !defined( __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__)

    retVal += testCreateCombTables(EC_P521, gpExpectedCombG_w2_p521, NULL, NULL, 2);
    retVal += testCreateCombTables(EC_P521, gpExpectedCombG_w3_p521, NULL, NULL, 3);
    retVal += testCreateCombTables(EC_P521, gpExpectedCombG_w4_p521, NULL, NULL, 4);
    retVal += testCreateCombTables(EC_P521, gpExpectedCombG_w5_p521, NULL, NULL, 5);
    retVal += testCreateCombTables(EC_P521, gpExpectedCombP_w2_p521, gpPointP_p521[0], gpPointP_p521[1], 2);
    retVal += testCreateCombTables(EC_P521, gpExpectedCombP_w3_p521, gpPointP_p521[0], gpPointP_p521[1], 3);
    retVal += testCreateCombTables(EC_P521, gpExpectedCombP_w4_p521, gpPointP_p521[0], gpPointP_p521[1], 4);
    retVal += testCreateCombTables(EC_P521, gpExpectedCombP_w5_p521, gpPointP_p521[0], gpPointP_p521[1], 5);

#endif /* __ENABLE_DIGICERT_ECC_COMB__ or not __ENABLE_DIGICERT_SMALL_CODE_FOOTPRINT__ */

#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 521;
#endif
    for (i = 0; i < COUNTOF(gTestVector_p521); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p521+i, EC_P521);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }

    retVal += testErrorCases(EC_P521, gpP_521, (ubyte4) sizeof(gpP_521));

#endif /* __DISABLE_DIGICERT_ECC_P521__ */
#endif /* __ENABLE_DIGICERT_ECC__ */

exit:

    DIGICERT_free(&gpMocCtx);

    DBG_DUMP
    return retVal;
}
