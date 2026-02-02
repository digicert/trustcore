/*
 * primeec_ecdh_unit_test.c
 *
 * unit test for ecdh modes primeec.c
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

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

static MocCtx gpMocCtx = NULL;

#if defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_ECDH_MODES__)

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
    ubyte4 mode;
    char *pUStaticK;
    char *pUStaticQ;
    char *pUEphemK;
    char *pUEphemQ;
    char *pVStaticQ;
    char *pVEphemQ;
    char *pZ;

} TestVector;

#include "primeec_ecdh_data.h"

static int testGenerateSharedSecret(ubyte4 mode, ECCKey *pStatic, ECCKey *pEphem, ubyte *pOtherStat, ubyte4 statLen, ubyte *pOtherEphem,
                                    ubyte4 ephemLen, ubyte *pSSExpected, ubyte4 ssExpectLen)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare;

    ubyte *pSS = NULL;
    sbyte4 ssLen = 0;

    status = ECDH_keyAgreementScheme(mode, pStatic, pEphem, pOtherStat, statLen, pOtherEphem, ephemLen, &pSS, &ssLen);
    UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* Check that the correct shared secret was generated, note it is always zero padded */
    UNITTEST_VECTOR_INT(__MOC_LINE__, ssLen, ssExpectLen);
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

static int knownAnswerTest(TestVector *testVector, ubyte4 curveId)
{
    MSTATUS status = OK;
    int retVal = 0;

    ECCKey *pStatic = NULL;
    ECCKey *pEphem = NULL;

    ubyte *pK = NULL;
    ubyte4 kLen = 0;

    ubyte *pQ = NULL;
    ubyte4 qLen = 0;

    ubyte *pOtherStat = NULL;
    ubyte4 otherStatLen = 0;

    ubyte *pOtherEphem = NULL;
    ubyte4 otherEphemLen = 0;

    ubyte *pSS = NULL;
    ubyte4 ssLen = 0;

    ubyte4 mode = testVector->mode;

    /* get private static key pair */
    if (testVector->pUStaticK != NULL)
    {
        kLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) testVector->pUStaticK, &pK);
    }
    if (testVector->pUStaticQ != NULL)
    {
        qLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) testVector->pUStaticQ, &pQ);
    }
    
    if (kLen)
    {
        status = EC_newKeyEx(curveId, &pStatic);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        status = EC_setKeyParametersEx(pStatic, pQ, qLen, pK, kLen);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        (void) DIGI_FREE((void **) &pK); kLen = 0;
        (void) DIGI_FREE((void **) &pQ); qLen = 0;
    }

    /* get private ephemeral key pair */
    if (testVector->pUEphemK != NULL)
    {
        kLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) testVector->pUEphemK, &pK);
    }
    if (testVector->pUEphemQ != NULL)
    {
        qLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) testVector->pUEphemQ, &pQ);
    }
    
    if (kLen)
    {
        status = EC_newKeyEx(curveId, &pEphem);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        status = EC_setKeyParametersEx(pEphem, pQ, qLen, pK, kLen);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;
    }

    /* get private ephemeral key pair */
    if (testVector->pVEphemQ != NULL)
    {
        otherEphemLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) testVector->pVEphemQ, &pOtherEphem);
    }
    if (testVector->pVStaticQ != NULL)
    {
        otherStatLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) testVector->pVStaticQ, &pOtherStat);
    }
    if (testVector->pZ != NULL)
    {
        ssLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) testVector->pZ, &pSS);
    }

    retVal += testGenerateSharedSecret(mode, pStatic, pEphem, pOtherStat, otherStatLen, pOtherEphem, otherEphemLen, pSS, ssLen);

exit:

    if (NULL != pK)
    {
        (void) DIGI_FREE((void **) &pK);
    }

    if (NULL != pQ)
    {
        (void) DIGI_FREE((void **) &pQ);
    }

    if (NULL != pOtherStat)
    {
        (void) DIGI_FREE((void **) &pOtherStat);
    }

    if (NULL != pOtherEphem)
    {
        (void) DIGI_FREE((void **) &pOtherEphem);
    }

    if (NULL != pSS)
    {
        (void) DIGI_FREE((void **) &pSS);
    }

    if (NULL != pStatic)
    {
        (void) EC_deleteKey(&pStatic);
    }

    if (NULL != pEphem)
    {
        (void) EC_deleteKey(&pEphem);
    }

    return retVal;
}
#endif /* __ENABLE_DIGICERT_ECC__ */

int primeec_ecdh_unit_test_all()
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

#if defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_ECDH_MODES__)

#ifndef __ENABLE_DIGICERT_ECC_P224__

    /* Test P224 */

#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 224;
#endif
    for (i = 0; i < COUNTOF(gTestVector_p224); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p224 + i, cid_EC_P224);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }

#endif /* __DISABLE_DIGICERT_ECC_P224__  */

#ifndef __ENABLE_DIGICERT_ECC_P256__

    /* Test P256 */

#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 256;
#endif
    for (i = 0; i < COUNTOF(gTestVector_p256); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p256 + i, cid_EC_P256);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }

#endif /* __DISABLE_DIGICERT_ECC_P256__  */

#ifndef __ENABLE_DIGICERT_ECC_P384__

    /* Test P384 */

#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 384;
#endif
    for (i = 0; i < COUNTOF(gTestVector_p384); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p384 + i, cid_EC_P384);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }

#endif /* __DISABLE_DIGICERT_ECC_P384__  */

#ifndef __ENABLE_DIGICERT_ECC_P521__

    /* Test P521 */

#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestCurve = 521;
#endif
    for (i = 0; i < COUNTOF(gTestVector_p521); ++i)
    {
        retVal += knownAnswerTest(gTestVector_p521 + i, cid_EC_P521);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }

#endif /* __DISABLE_DIGICERT_ECC_P521__  */
#endif 

exit:

    DIGICERT_free(&gpMocCtx);

    DBG_DUMP
    return retVal;
}
