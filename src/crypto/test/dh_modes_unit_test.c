/*
 * dh_modes_unit_test.c
 *
 *   unit test for dh modes in dh.c
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
#include "../../crypto/dh.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

static MocCtx gpMocCtx = NULL;

#if defined(__ENABLE_DIGICERT_DH_MODES__)

#define __DEBUG_VECTORS__

#ifdef __DEBUG_VECTORS__
#include <stdio.h>

static int gCurrentVector = 0;

/* Use these macros to output which vector number is failing.
 Make sure retVal is defined. */
#define UNITTEST_VECTOR_STATUS( b, c) if ( UNITTEST_STATUS(b, c) ) {printf("for vector index %d in gTestVector\n", gCurrentVector); retVal++;}
#define UNITTEST_VECTOR_INT( b, c, d) if ( UNITTEST_INT(b, c, d) ) {printf("for vector index %d in gTestVector\n", gCurrentVector); retVal++;}

#else

/* Still make sure retVal is defined. */
#define UNITTEST_VECTOR_STATUS( b, c) retVal += UNITTEST_STATUS(b, c);
#define UNITTEST_VECTOR_INT( b, c, d) retVal += UNITTEST_INT(b, c, d);

#endif

typedef struct TestVector
{
    ubyte4 mode;
    char *pP;
    char *pQ;
    char *pG;
    char *pUStaticY;
    char *pUStaticF;
    char *pUEphemY;
    char *pUEphemF;
    char *pVStaticF;
    char *pVEphemF;
    char *pZ;

} TestVector;

#include "dh_modes_data.h"

static int testGenerateSharedSecret(ubyte4 mode, diffieHellmanContext *pStatic, diffieHellmanContext *pEphem, ubyte *pOtherStat, ubyte4 statLen, ubyte *pOtherEphem,
                                    ubyte4 ephemLen, ubyte *pSSExpected, ubyte4 ssExpectLen)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare;

    ubyte *pSS = NULL;
    sbyte4 ssLen = 0;

    status = DH_keyAgreementScheme(mode, NULL, pStatic, pEphem, pOtherStat, statLen, pOtherEphem, ephemLen, &pSS, &ssLen);
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

static int knownAnswerTest(TestVector *testVector)
{
    MSTATUS status = OK;
    int retVal = 0;

    diffieHellmanContext *pStatic = NULL;
    diffieHellmanContext *pEphem = NULL;

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

    MDhKeyTemplate template = {0};
    
    /* get domain params */
    if (testVector->pP != NULL)
    {
        template.pLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) testVector->pP, &template.pP);
    }
    if (testVector->pG != NULL)
    {
        template.gLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) testVector->pG, &template.pG);
    }
    if (testVector->pQ != NULL)
    {
        template.qLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) testVector->pQ, &template.pQ);
    }

    /* get private static key pair */
    if (testVector->pUStaticY != NULL)
    {
        template.yLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) testVector->pUStaticY, &template.pY);
    }
    if (testVector->pUStaticF != NULL)
    {
        template.fLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) testVector->pUStaticF, &template.pF);
    }

    if (template.yLen)
    {
        status = DH_allocate(&pStatic);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        status = DH_setKeyParameters(pStatic, &template);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        (void) DIGI_FREE((void **) &template.pY); template.yLen = 0;
        (void) DIGI_FREE((void **) &template.pF); template.fLen = 0;
    }

    /* get private ephemeral key pair */
    if (testVector->pUEphemY != NULL)
    {
        template.yLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) testVector->pUEphemY, &template.pY);
    }
    if (testVector->pUEphemF != NULL)
    {
        template.fLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) testVector->pUEphemF, &template.pF);
    }

    if (template.yLen)
    {
        status = DH_allocate(&pEphem);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        status = DH_setKeyParameters(pEphem, &template);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
        if (OK != status)
            goto exit;

        (void) DIGI_FREE((void **) &template.pY); template.yLen = 0;
        (void) DIGI_FREE((void **) &template.pF); template.fLen = 0;
    }    

    /* get private ephemeral key pair */
    if (testVector->pVEphemF != NULL)
    {
        otherEphemLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) testVector->pVEphemF, &pOtherEphem);
    }
    if (testVector->pVStaticF != NULL)
    {
        otherStatLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) testVector->pVStaticF, &pOtherStat);
    }
    if (testVector->pZ != NULL)
    {
        ssLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) testVector->pZ, &pSS);
    }

    retVal += testGenerateSharedSecret(mode, pStatic, pEphem, pOtherStat, otherStatLen, pOtherEphem, otherEphemLen, pSS, ssLen);

exit:
    
    (void) DH_freeKeyTemplate(pEphem, &template);

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
        (void) DH_freeDhContext(&pStatic, NULL);
    }

    if (NULL != pEphem)
    {
        (void) DH_freeDhContext(&pEphem, NULL);
    }

    return retVal;
}
#endif /* __ENABLE_DIGICERT_DH_MODES__ */

int dh_modes_unit_test_all()
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

#if defined(__ENABLE_DIGICERT_ECDH_MODES__)

#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
#endif
    for (i = 0; i < COUNTOF(gTestVector); ++i)
    {
        retVal += knownAnswerTest(gTestVector + i);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
#endif 

exit:

    DIGICERT_free(&gpMocCtx);

    DBG_DUMP
    return retVal;
}
