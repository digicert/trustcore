/*
 * ffc_test.c
 *
 * unit test for ffc.c (via dsa.c and dh.c APIs)
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
#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/vlong.h"
#include "../../common/random.h"
#include "../../common/prime.h"
#include "../../common/debug_console.h"
#include "../../common/memory_debug.h"
#include "../../common/initmocana.h"

#include "../../crypto/dsa.h"
#include "../../crypto/dh.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#ifdef __RTOS_WIN32__
#include <stdio.h>
#include <string.h>
#endif

/* -------------------------------------------------------------------------------------------------- */

typedef struct TestVector
{
    char *pP;
    char *pQ;
    char *pG;
    char *pSeed;
    ubyte4 C;
    FFCHashType hashAlgo;
    intBoolean PQvalid;
    intBoolean Gvalid;
    
} TestVector;

#include "ffc_data_inc.h"

/* -------------------------------------------------------------------------------------------------- */

static int knownAnswerTestDH(int hint, randomContext *pRandomContext, ubyte4 C, vlong *pP, vlong *pQ, vlong *pG,
                             ubyte *pSeed, ubyte4 seedLen, FFCHashType hashAlgo, intBoolean expPQvalid, intBoolean expGvalid)
{
    MSTATUS status = OK;
    int retVal = 0;
    ubyte4 L, Nin;
    intBoolean isValid = FALSE;
    ubyte4 keyLen = 0;
    
    diffieHellmanContext *pCtx = NULL;
    
    status = DH_allocate(&pCtx);
    UNITTEST_STATUS_GOTO(hint, status, retVal, exit);
    
    /* We have the input params in vlong form so we'll just set them in the context directly */
    status = VLONG_makeVlongFromVlong(pP, &COMPUTED_VLONG_P(pCtx), NULL);
    UNITTEST_STATUS_GOTO(hint, status, retVal, exit);

    status = VLONG_makeVlongFromVlong(pG, &COMPUTED_VLONG_G(pCtx), NULL);
    UNITTEST_STATUS_GOTO(hint, status, retVal, exit);
    
    status = VLONG_makeVlongFromVlong(pQ, &COMPUTED_VLONG_Q(pCtx), NULL);
    UNITTEST_STATUS_GOTO(hint, status, retVal, exit);
    
    L = VLONG_bitLength(pP);
    Nin = VLONG_bitLength(pQ);

    status = DH_verifyPQ_FIPS1864(pRandomContext, pCtx, hashAlgo, C, pSeed, seedLen, &isValid, NULL);
    UNITTEST_STATUS_GOTO(hint, status, retVal, exit);

    if (isValid != expPQvalid)
    {
        UNITTEST_STATUS_GOTO(hint, -1, retVal, exit);
    }
    
    status = DH_verifyG(pCtx, &isValid, NULL);
    UNITTEST_STATUS_GOTO(hint, status, retVal, exit);
    
    if (isValid != expGvalid)
    {
        UNITTEST_STATUS_GOTO(hint, -1, retVal, exit);
    }
    
    /* also verify the API that does both */
    status = DH_validateDomainParams(pRandomContext, pCtx, hashAlgo, C, pSeed, seedLen, &isValid, &keyLen, NULL);
    UNITTEST_STATUS_GOTO(hint, status, retVal, exit);

    if ( isValid != (expPQvalid && expGvalid) )
    {
        UNITTEST_STATUS_GOTO(hint, -1, retVal, exit);
    }
    
    if (TRUE == isValid && 28 != keyLen)  /* 28 is the min for all FIPS 186-4 groups */
    {
        UNITTEST_STATUS_GOTO(hint, -1, retVal, exit);
    }

exit:
    
    DH_freeDhContext(&pCtx, NULL);
    
    return retVal;
}

/* -------------------------------------------------------------------------------------------------- */

static int testSafeGroupValidation(randomContext *pRandomContext, ubyte4 groupNum)
{
    int retVal = 0;
    MSTATUS status;
    diffieHellmanContext *pDhCtx = NULL;
    intBoolean isValid = FALSE;
    ubyte4 keyLen = 0;
    ubyte4 expKeyLen = 0;
    
    switch(groupNum)
    {
        case 14:
            expKeyLen = 28;
            break;
        case 15:
            expKeyLen = 32;
            break;
        case 16:
            expKeyLen = 38;
            break;
        case 17:
            expKeyLen = 44;
            break;
        case 18:
            expKeyLen = 50;
            break;
        default:
            UNITTEST_STATUS_GOTO(groupNum, -1, retVal, exit);
    }
    
    status = DH_allocateServer(pRandomContext, &pDhCtx, groupNum);
    UNITTEST_STATUS_GOTO(groupNum, status, retVal, exit);
    
    status = DH_verifySafePG(pDhCtx, &isValid, &keyLen, NULL);
    UNITTEST_STATUS_GOTO(groupNum, status, retVal, exit);
    
    if (TRUE != isValid)
    {
        UNITTEST_STATUS_GOTO(groupNum, -1, retVal, exit);
    }
    
    if (keyLen != expKeyLen)
    {
        UNITTEST_STATUS_GOTO(groupNum, -1, retVal, exit);
    }
    
    keyLen = 0; /* reset */
    
    /* also DH_validateDomainParams with NULL seed should validate */
    status = DH_validateDomainParams(pRandomContext, pDhCtx, 0, 0, NULL, 0, &isValid, &keyLen, NULL);
    UNITTEST_STATUS_GOTO(groupNum, status, retVal, exit);
    
    if (TRUE != isValid)
    {
        UNITTEST_STATUS_GOTO(groupNum, -1, retVal, exit);
    }
    
    if (keyLen != expKeyLen)
    {
        UNITTEST_STATUS_GOTO(groupNum, -1, retVal, exit);
    }
    
    /* Negative test, change G */
    
    status = VLONG_decrement(COMPUTED_VLONG_G(pDhCtx), NULL);
    UNITTEST_STATUS_GOTO(groupNum, status, retVal, exit);
    
    status = DH_verifySafePG(pDhCtx, &isValid, &keyLen, NULL);
    UNITTEST_STATUS_GOTO(groupNum, status, retVal, exit);
    
    if (FALSE != isValid)
    {
        UNITTEST_STATUS_GOTO(groupNum, -1, retVal, exit);
    }
    
    status = DH_validateDomainParams(pRandomContext, pDhCtx, 0, 0, NULL, 0, &isValid, &keyLen, NULL);
    UNITTEST_STATUS_GOTO(groupNum, status, retVal, exit);
    
    if (FALSE != isValid)
    {
        UNITTEST_STATUS_GOTO(groupNum, -1, retVal, exit);
    }
    
    /* put G back, change P */
    
    status = VLONG_increment(COMPUTED_VLONG_G(pDhCtx), NULL);
    UNITTEST_STATUS_GOTO(groupNum, status, retVal, exit);
    
    status = VLONG_decrement(COMPUTED_VLONG_P(pDhCtx), NULL);
    UNITTEST_STATUS_GOTO(groupNum, status, retVal, exit);
    
    status = DH_verifySafePG(pDhCtx, &isValid, &keyLen, NULL);
    UNITTEST_STATUS_GOTO(groupNum, status, retVal, exit);
    
    if (FALSE != isValid)
    {
        UNITTEST_STATUS_GOTO(groupNum, -1, retVal, exit);
    }
    
    status = DH_validateDomainParams(pRandomContext, pDhCtx, 0, 0, NULL, 0, &isValid, &keyLen, NULL);
    UNITTEST_STATUS_GOTO(groupNum, status, retVal, exit);
    
    if (FALSE != isValid)
    {
        UNITTEST_STATUS_GOTO(groupNum, -1, retVal, exit);
    }
    
exit:
    
    DH_freeDhContext(&pDhCtx, NULL);
    
    return retVal;
}

/* -------------------------------------------------------------------------------------------------- */

static int testErrorCasesDH(randomContext *pRandomContext)
{
    int retVal = 0;
    MSTATUS status = OK;
    intBoolean isValid = FALSE;
    ubyte4 keyLen = 0;
    
    /* dummy data, doens't need to be valid for error case testing */
    diffieHellmanContext *pCtx = NULL;
    
    ubyte pPbytes[256] = {0x80};
    ubyte pQbytes[32] = {0x80};
    ubyte pGbytes[256] = {0x80};
    
    ubyte pSeed[32] = {0};
    ubyte4 C = 0;
    
    /* Set P, Q, G to correctly sized dummy values */
    status = DH_allocate(&pCtx);
    UNITTEST_STATUS_GOTO(__LINE__, status, retVal, exit);
    
    status = VLONG_vlongFromByteString(pPbytes, sizeof(pPbytes), &COMPUTED_VLONG_P(pCtx), NULL);
    UNITTEST_STATUS_GOTO(__LINE__, status, retVal, exit);
    
    status = VLONG_vlongFromByteString(pQbytes, sizeof(pQbytes), &COMPUTED_VLONG_Q(pCtx), NULL);
    UNITTEST_STATUS_GOTO(__LINE__, status, retVal, exit);
    
    status = VLONG_vlongFromByteString(pGbytes, sizeof(pGbytes), &COMPUTED_VLONG_G(pCtx), NULL);
    UNITTEST_STATUS_GOTO(__LINE__, status, retVal, exit);
    
    /******* DH_verifyG *******/
    
    /* Use pH as an allocated vlong */
    status = DH_verifyG(NULL, &isValid, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_NULL_POINTER);
    
    status = DH_verifyG(pCtx, NULL, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_NULL_POINTER);
    
    /****** DH_verifySafePG *******/
    
    status = DH_verifySafePG(NULL, &isValid, &keyLen, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_NULL_POINTER);
    
    status = DH_verifySafePG(pCtx, NULL, &keyLen, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_NULL_POINTER);
    
    status = DH_verifySafePG(pCtx, &isValid, NULL, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_NULL_POINTER);
    
    /****** DH_verifyPQ_FIPS1864 and DH_validateDomainParams *******/

    /* null params */
    status = DH_verifyPQ_FIPS1864(NULL, pCtx, FFC_sha256, C, pSeed, sizeof(pSeed), &isValid, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_NULL_POINTER);
    
    status = DH_verifyPQ_FIPS1864(pRandomContext, NULL, FFC_sha256, C, pSeed, sizeof(pSeed), &isValid, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_NULL_POINTER);
    
    status = DH_verifyPQ_FIPS1864(pRandomContext, pCtx, FFC_sha256, C, NULL, sizeof(pSeed), &isValid, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_NULL_POINTER);
    
    status = DH_verifyPQ_FIPS1864(pRandomContext, pCtx, FFC_sha256, C, pSeed, sizeof(pSeed), NULL, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_NULL_POINTER);
    
    /* with pSeed non-null */
    status = DH_validateDomainParams(NULL, pCtx, FFC_sha256, C, pSeed, sizeof(pSeed), &isValid, &keyLen, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_NULL_POINTER);
    
    status = DH_validateDomainParams(pRandomContext, NULL, FFC_sha256, C, pSeed, sizeof(pSeed), &isValid, &keyLen, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_NULL_POINTER);
    
    status = DH_validateDomainParams(pRandomContext, pCtx, FFC_sha256, C, pSeed, sizeof(pSeed), NULL, &keyLen, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_NULL_POINTER);
    
    /* null keyLen is ok, you need vslid P and Q to test NULL G but DH_verifyG is tested with null G above, so ok. */
    
    /* with pSeed null */
    status = DH_validateDomainParams(pRandomContext, NULL, FFC_sha256, C, NULL, 0, &isValid, &keyLen, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_NULL_POINTER);
    
    status = DH_validateDomainParams(pRandomContext, pCtx, FFC_sha256, C, NULL, 0, NULL, &keyLen, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_NULL_POINTER);
    
    status = DH_validateDomainParams(pRandomContext, pCtx, FFC_sha256, C, NULL, 0, &isValid, NULL, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_NULL_POINTER);
    
    /* invlalid hash size */
    
    status = DH_verifyPQ_FIPS1864(pRandomContext, pCtx, FFC_sha1, C, pSeed, sizeof(pSeed), &isValid, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_DH_HASH_TOO_SMALL);
    
    status = DH_verifyPQ_FIPS1864(pRandomContext, pCtx, FFC_sha224, C, pSeed, sizeof(pSeed), &isValid, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_DH_HASH_TOO_SMALL);
    
    /* invlalid key sizes, reset p too small */
    
    status = VLONG_shrVlong(COMPUTED_VLONG_P(pCtx));
    UNITTEST_STATUS_GOTO(__LINE__, status, retVal, exit);
    
    status = DH_verifyPQ_FIPS1864(pRandomContext, pCtx, FFC_sha256, C, pSeed, sizeof(pSeed), &isValid, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_DH_INVALID_KEYLENGTH);
    
    status = DH_validateDomainParams(pRandomContext, pCtx, FFC_sha256, C, pSeed, sizeof(pSeed), &isValid, &keyLen, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_DH_INVALID_KEYLENGTH);
    
    /* put p back, make q too big */
    
    status = VLONG_shlVlong(COMPUTED_VLONG_P(pCtx));
    UNITTEST_STATUS_GOTO(__LINE__, status, retVal, exit);
    
    status = VLONG_shlVlong(COMPUTED_VLONG_Q(pCtx));
    UNITTEST_STATUS_GOTO(__LINE__, status, retVal, exit);
    
    status = DH_verifyPQ_FIPS1864(pRandomContext, pCtx, FFC_sha256, C, pSeed, sizeof(pSeed), &isValid, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_DH_INVALID_KEYLENGTH);
    
    status = DH_validateDomainParams(pRandomContext, pCtx, FFC_sha256, C, pSeed, sizeof(pSeed), &isValid, &keyLen, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_DH_INVALID_KEYLENGTH);
    
exit:
    
    DH_freeDhContext(&pCtx, NULL);
    
    return retVal;
}

/* -------------------------------------------------------------------------------------------------- */

#ifdef __ENABLE_DIGICERT_DSA__

static int knownAnswerTestDSA(int hint, randomContext *pRandomContext, ubyte4 C, vlong *pP, ubyte *pPbytes, ubyte4 pLen, vlong *pQ, ubyte *pQbytes, ubyte4 qLen,
                              vlong *pG, ubyte *pGbytes, ubyte4 gLen, ubyte *pSeed, ubyte4 seedLen, FFCHashType hashAlgo, intBoolean expPQvalid, intBoolean expGvalid)
{
    MSTATUS status = OK;
    int retVal = 0;
    ubyte4 L, Nin;
    intBoolean isValid = FALSE;
    /* dummy y, not tested */
    ubyte pY[24] = {0x01};
    ubyte4 yLen = 24;
    
    DSAKey *pKey = NULL;
    
    status = DSA_createKey(&pKey);
    UNITTEST_STATUS_GOTO(hint, status, retVal, exit);
    
    status = DSA_setPublicKeyParameters(pKey, pPbytes, pLen, pQbytes, qLen, pGbytes, gLen, pY, yLen, NULL);
    UNITTEST_STATUS_GOTO(hint, status, retVal, exit);
    
    L = VLONG_bitLength(pP);
    Nin = VLONG_bitLength(pQ);
    
    status = DSA_verifyPQ(pRandomContext, pKey, L, Nin, (DSAHashType) hashAlgo, DSA_186_4, C, pSeed, seedLen, &isValid, NULL);
    UNITTEST_STATUS_GOTO(hint, status, retVal, exit);

    if (isValid != expPQvalid)
    {
        UNITTEST_STATUS_GOTO(hint, -1, retVal, exit);
    }
    
    status = DSA_verifyG(pP, pQ, pG, &isValid, NULL);
    UNITTEST_STATUS_GOTO(hint, status, retVal, exit);
    
    if (isValid != expGvalid)
    {
        UNITTEST_STATUS_GOTO(hint, -1, retVal, exit);
    }
    
exit:
    
    DSA_freeKey(&pKey, NULL);
    
    return retVal;
}

/* -------------------------------------------------------------------------------------------------- */

static int testErrorCasesDSA(randomContext *pRandomContext)
{
    int retVal = 0;
    MSTATUS status = OK;
    intBoolean isValid = FALSE;
    
    ubyte pSeed[32] = {0};
    ubyte4 C = 0;
    vlong *pH = NULL;
    
    DSAKey *pKey = NULL;
    
    /* properly create a key, don't need to set params */
    status = DSA_createKey(&pKey);
    UNITTEST_STATUS_GOTO(__LINE__, status, retVal, exit);
    
    /****** DSA_verifyPQ *******/
    
    status = DSA_verifyPQ(NULL, pKey, 2048, 256, DSA_sha256, DSA_186_4, C, pSeed, sizeof(pSeed), &isValid, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_verifyPQ(pRandomContext, NULL, 2048, 256, DSA_sha256, DSA_186_4, C, pSeed, sizeof(pSeed), &isValid, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_verifyPQ(pRandomContext, pKey, 2048, 256, DSA_sha256, DSA_186_4, C, NULL, sizeof(pSeed), &isValid, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_verifyPQ(pRandomContext, pKey, 2048, 256, DSA_sha256, DSA_186_4, C, pSeed, sizeof(pSeed), NULL, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_NULL_POINTER);
    
    /* still no P and Q in pKey so still null */
    status = DSA_verifyPQ(pRandomContext, pKey, 2048, 256, DSA_sha256, DSA_186_4, C, pSeed, sizeof(pSeed), &isValid, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_NULL_POINTER);
    
    /* properly generate domain params to test further */
    
    status = DSA_generateKey(pRandomContext, pKey, 2048, &C, pSeed, &pH, NULL);
    UNITTEST_STATUS_GOTO(__LINE__, status, retVal, exit);
    
    status = DSA_verifyPQ(pRandomContext, pKey, 1023, 160, DSA_sha1, DSA_186_4, C, pSeed, sizeof(pSeed), &isValid, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_DSA_INVALID_KEYLENGTH);
    
    status = DSA_verifyPQ(pRandomContext, pKey, 3073, 256, DSA_sha256, DSA_186_4, C, pSeed, sizeof(pSeed), &isValid, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_DSA_INVALID_KEYLENGTH);
    
    status = DSA_verifyPQ(pRandomContext, pKey, 2048, 223, DSA_sha224, DSA_186_4, C, pSeed, sizeof(pSeed), &isValid, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_DSA_INVALID_KEYLENGTH);
    
    status = DSA_verifyPQ(pRandomContext, pKey, 2048, 257, DSA_sha256, DSA_186_4, C, pSeed, sizeof(pSeed), &isValid, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_DSA_INVALID_KEYLENGTH);
    
    status = DSA_verifyPQ(pRandomContext, pKey, 2048, 257, DSA_sha256, DSA_186_4, C, pSeed, sizeof(pSeed), &isValid, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_DSA_INVALID_KEYLENGTH);
    
    status = DSA_verifyPQ(pRandomContext, pKey, 2048, 256, DSA_sha1, DSA_186_4, C, pSeed, sizeof(pSeed), &isValid, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_DSA_HASH_TOO_SMALL);
    
    status = DSA_verifyPQ(pRandomContext, pKey, 2048, 256, DSA_sha224, DSA_186_4, C, pSeed, sizeof(pSeed), &isValid, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_DSA_HASH_TOO_SMALL);
    
    /******* DSA_verifyG *******/

    /* Use pH as an allocated vlong */
    status = DSA_verifyG(NULL, pH, pH, &isValid, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_verifyG(pH, NULL, pH, &isValid, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_verifyG(pH, pH, NULL, &isValid, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_NULL_POINTER);
    
    status = DSA_verifyG(pH, pH, pH, NULL, NULL);
    retVal += UNITTEST_INT(__LINE__, status, ERR_NULL_POINTER);

exit:
    
    DSA_freeKey(&pKey, NULL);
    VLONG_freeVlong(&pH, NULL);
    
    return retVal;
}
#endif

/* -------------------------------------------------------------------------------------------------- */
    
static int knownAnswerTest(int hint, TestVector *pTestVector, randomContext *pRandomContext)
{
    int retVal = 0;
    MSTATUS status = OK;
    
    vlong *pP = NULL;
    vlong *pQ = NULL;
    vlong *pG = NULL;
    
    ubyte *pPbytes = NULL;
    ubyte4 pLen = 0;
    
    ubyte *pQbytes = NULL;
    ubyte4 qLen = 0;
    
    ubyte *pGbytes = NULL;
    ubyte4 gLen = 0;
    
    ubyte *pSeed = NULL;
    ubyte4 seedLen = 0;
    
    pLen = UNITTEST_UTILS_str_to_byteStr((const sbyte *) pTestVector->pP, &pPbytes);
    
    status = VLONG_vlongFromByteString(pPbytes, pLen, &pP, NULL);
    UNITTEST_STATUS_GOTO(hint, status, retVal, exit);
    
    qLen = UNITTEST_UTILS_str_to_byteStr((const sbyte *) pTestVector->pQ, &pQbytes);
    
    status = VLONG_vlongFromByteString(pQbytes, qLen, &pQ, NULL);
    UNITTEST_STATUS_GOTO(hint, status, retVal, exit);
    
    gLen = UNITTEST_UTILS_str_to_byteStr((const sbyte *) pTestVector->pG, &pGbytes);
    
    status = VLONG_vlongFromByteString(pGbytes, gLen, &pG, NULL);
    UNITTEST_STATUS_GOTO(hint, status, retVal, exit);
    
    seedLen = UNITTEST_UTILS_str_to_byteStr((const sbyte *) pTestVector->pSeed, &pSeed);

    /* valid DH groups are only the 2048 bit ones */
    if(256 == pLen)
    {
        retVal += knownAnswerTestDH(hint, pRandomContext, pTestVector->C, pP, pQ, pG, pSeed, seedLen, pTestVector->hashAlgo, pTestVector->PQvalid, pTestVector->Gvalid);
    }
    
#ifdef __ENABLE_DIGICERT_DSA__

    retVal += knownAnswerTestDSA(hint, pRandomContext, pTestVector->C, pP, pPbytes, pLen, pQ, pQbytes, qLen, pG, pGbytes, gLen,
                                 pSeed, seedLen, pTestVector->hashAlgo, pTestVector->PQvalid, pTestVector->Gvalid);
#endif
    
exit:
    
    VLONG_freeVlong(&pP, NULL);
    VLONG_freeVlong(&pQ, NULL);
    VLONG_freeVlong(&pG, NULL);
    
    if (NULL != pPbytes)
    {
        DIGI_FREE((void **) &pPbytes);
    }
    
    if (NULL != pQbytes)
    {
        DIGI_FREE((void **) &pQbytes);
    }
    
    if (NULL != pGbytes)
    {
        DIGI_FREE((void **) &pGbytes);
    }
    
    if (NULL != pSeed)
    {
        DIGI_FREE((void **) &pSeed);
    }
    
    return retVal;
}

/* -------------------------------------------------------------------------------------------------- */

int ffc_test_all()
{
    int retVal = 0;

    ubyte4 i = 0;
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
    
    if (OK > (MSTATUS)(retVal = DIGICERT_initialize(&setupInfo, NULL)))
        return retVal;

    for (i = 0; i < COUNTOF(gTestVector); ++i)
    {
        retVal += knownAnswerTest(i, gTestVector + i, g_pRandomContext);
    }

    retVal += testSafeGroupValidation(g_pRandomContext, 14);
    retVal += testSafeGroupValidation(g_pRandomContext, 15);
    retVal += testSafeGroupValidation(g_pRandomContext, 16);
    retVal += testSafeGroupValidation(g_pRandomContext, 17);
    retVal += testSafeGroupValidation(g_pRandomContext, 18);
    
    retVal += testErrorCasesDH(g_pRandomContext);
    
#ifdef __ENABLE_DIGICERT_DSA__
    retVal += testErrorCasesDSA(g_pRandomContext);
#endif
    
    DIGICERT_freeDigicert();

    return retVal;
}
