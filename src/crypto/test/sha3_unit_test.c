/*
 * sha3_unit_test.c
 *
 * unit test for sha3.c
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

#ifdef __ENABLE_DIGICERT_SHA3__

#include "../../crypto/sha3.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#define __DEBUG_VECTORS__

#ifdef __DEBUG_VECTORS__
#include <stdio.h>

static int gCurrentVector = 0;
static int gTestMode = 0;

/* Use these macros to output which vector number is failing.
 Make sure retVal is defined. */
#define UNITTEST_VECTOR_STATUS( b, c) if ( UNITTEST_STATUS(b, c) ) {printf("for vector index %d in gTestVector_mode%d\n", gCurrentVector, gTestMode); retVal++;}
#define UNITTEST_VECTOR_INT( b, c, d) if ( UNITTEST_INT(b, c, d) ) {printf("for vector index %d in gTestVector_mode%d\n", gCurrentVector, gTestMode); retVal++;}

#else

/* Still make sure retVal is defined. */
#define UNITTEST_VECTOR_STATUS( b, c) retVal += UNITTEST_STATUS(b, c);
#define UNITTEST_VECTOR_INT( b, c, d) retVal += UNITTEST_INT(b, c, d);

#endif

typedef struct TestVector
{
    char *pInput;
    ubyte4 desiredResultLen;
    char *pResult;
    
} TestVector;


#include "sha3_data_224_inc.h"
#include "sha3_data_256_inc.h"
#include "sha3_data_384_inc.h"
#include "sha3_data_512_inc.h"
#include "sha3_data_shake128_inc.h"
#include "sha3_data_shake256_inc.h"

/********************************************************************************************/

/*
 Tests the sha evp methods. pBufferIndices must include the end of the message, ie the last
 value should always be the length of the message (ie the index after the last byte).
 This ensures the while loop will finish before we start accessing data beyond the length
 of pBufferIndices.
 */
static int testSha3Evp(ubyte4 mode, ubyte *pMessage, ubyte4 messageLen, ubyte *pExpectedResult, ubyte4 desiredResultLen, ubyte4 *pBufferIndices)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare;
    
    sbyte4 messageLeft = (sbyte4) messageLen;
    ubyte4 nextBlockLen;
    ubyte *pMsgPtr = pMessage;
    ubyte4 *pBufferIndexPtr = pBufferIndices;
    
    SHA3_CTX *pSha3_ctx = NULL;
    
    ubyte pResult[250] = {0}; /* big enough for all tests */
    
    status = SHA3_allocDigest((BulkCtx *) &pSha3_ctx);
    UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    status = SHA3_initDigest(pSha3_ctx, mode);
    UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    while(messageLeft > 0)
    {
        nextBlockLen = *(pBufferIndexPtr + 1) - *pBufferIndexPtr;
        
        status = SHA3_updateDigest(pSha3_ctx, pMsgPtr, nextBlockLen);
        UNITTEST_VECTOR_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;
        
        messageLeft -= nextBlockLen;
        pMsgPtr += nextBlockLen;
        pBufferIndexPtr++;
    }
    
    status = SHA3_finalDigest(pSha3_ctx, pResult, desiredResultLen);
    UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    status = DIGI_MEMCMP(pResult, pExpectedResult, desiredResultLen, &compare);
    UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    UNITTEST_VECTOR_INT(gCurrentVector, compare, 0);
    
exit:
    
    if (NULL != pSha3_ctx)
    {
        status = SHA3_freeDigest((BulkCtx *) &pSha3_ctx);
        UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    }
    
    return retVal;
}


static int knownAnswerTest(TestVector *testVector, ubyte4 mode)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare;
    
    /* sha3 rates based on mode, used to choose buffering boundaries */
    ubyte4 pSha3RateTable[6] = {144, 136, 104, 72, 168, 136};
    ubyte4 sha3Rate = pSha3RateTable[mode];
    ubyte4 pBufferIndices[4] = {0};
    
    ubyte *pByteBufferInput = NULL;
    ubyte4 inputLen = 0;
    
    ubyte *pByteBufferResult = NULL;
    ubyte4 resultLen = 0;
    
    ubyte pResult[250] = {0}; /* big enough for all tests */
    
    ubyte4 desiredResultLen = testVector->desiredResultLen;
    
    if (NULL != testVector->pInput)
        inputLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) testVector->pInput, &pByteBufferInput);
    if (NULL != testVector->pResult)
        resultLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) testVector->pResult, &pByteBufferResult);
    
    /* Test one shot API */
    status = SHA3_completeDigest(mode, pByteBufferInput, inputLen, pResult, desiredResultLen);
    UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    status = DIGI_MEMCMP(pResult, pByteBufferResult, desiredResultLen, &compare);
    UNITTEST_VECTOR_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;
    
    UNITTEST_VECTOR_INT(gCurrentVector, compare, 0);
    
    /* Test evp API's for various buffer configurations (depending on the size of the message) */
    
    /* for all size, test splitting buffer up into 3 pieces (some possibly empty) */
    pBufferIndices[1] = inputLen/5;
    pBufferIndices[2] = (2*inputLen)/3;
    pBufferIndices[3] = inputLen;
    
    retVal += testSha3Evp(mode, pByteBufferInput, inputLen, pByteBufferResult, desiredResultLen, pBufferIndices);
    
    if (inputLen >= sha3Rate)
    {
        /* test crossing the first block boundary at a single byte */
        pBufferIndices[1] = sha3Rate - 1;
        pBufferIndices[2] = sha3Rate;
        /* pBufferIndices[3] = inputLen; still holds */
        
        retVal += testSha3Evp(mode, pByteBufferInput, inputLen, pByteBufferResult, desiredResultLen, pBufferIndices);
        
        if (inputLen >= 2*sha3Rate)
        {
            /* test crossing the first block boundary at 2 bytes */
            
            pBufferIndices[1] = sha3Rate - 1;
            pBufferIndices[2] = sha3Rate + 1;
            /* pBufferIndices[3] = inputLen; still holds */
            
            retVal += testSha3Evp(mode, pByteBufferInput, inputLen, pByteBufferResult, desiredResultLen, pBufferIndices);
            
            /* test crossing the first block boundary with over a full block */
            
            pBufferIndices[1] = sha3Rate - 1;
            pBufferIndices[2] = inputLen;
            
            retVal += testSha3Evp(mode, pByteBufferInput, inputLen, pByteBufferResult, desiredResultLen, pBufferIndices);
            
            /* test crossing the first block boundary with the first chunk */
            
            pBufferIndices[1] = sha3Rate + 1;
            /* pBufferIndices[2] = inputLen; still holds */
            
            retVal += testSha3Evp(mode, pByteBufferInput, inputLen, pByteBufferResult, desiredResultLen, pBufferIndices);
            
            /* test buffering within the second block */
            
            pBufferIndices[1] = sha3Rate + 1;
            pBufferIndices[2] = 2*sha3Rate - 1;
            /* pBufferIndices[3] = inputLen; still holds */
            
            retVal += testSha3Evp(mode, pByteBufferInput, inputLen, pByteBufferResult, desiredResultLen, pBufferIndices);
            
            if (inputLen >= 3*sha3Rate)
            {
                
                /* test crossing the first block boundary with over two full blocks, land on boundary */
                
                pBufferIndices[1] = sha3Rate - 1;
                pBufferIndices[2] = 3*sha3Rate;
                /* pBufferIndices[3] = inputLen; still holds */
                
                retVal += testSha3Evp(mode, pByteBufferInput, inputLen, pByteBufferResult, desiredResultLen, pBufferIndices);
                
                if (inputLen >= 3*sha3Rate + 1)
                {
                    /* test crossing the first block boundary with over two full blocks, land after boundary */
                    
                    pBufferIndices[1] = sha3Rate - 1;
                    pBufferIndices[2] = 3*sha3Rate + 1;
                    /* pBufferIndices[3] = inputLen; still holds */
                    
                    retVal += testSha3Evp(mode, pByteBufferInput, inputLen, pByteBufferResult, desiredResultLen, pBufferIndices);
                    
                }
            }
        }
    }
    
exit:
    
    if (NULL != pByteBufferInput)
    {
        status = DIGI_FREE((void **) &pByteBufferInput);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    if (NULL != pByteBufferResult)
    {
        status = DIGI_FREE((void **) &pByteBufferResult);
        UNITTEST_VECTOR_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}


static int testErrorCases()
{
    MSTATUS status;
    int retVal = 0;
    ubyte4 mode = MOCANA_SHA3_MODE_SHA3_224;   /* default */
    
    ubyte pMessage[1] = {0};
    ubyte4 messageLen = 1;
    
    ubyte pResult[28] = {0};
    ubyte4 desiredResultLen = 28;
    
    SHA3_CTX *pSha3_ctx = NULL;
    
    /******* SHA3_completeDigest *******/
    
    /* null params */
    status = SHA3_completeDigest(mode, NULL, messageLen, pResult, desiredResultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = SHA3_completeDigest(mode, pMessage, messageLen, NULL, desiredResultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* invalid mode */
    status = SHA3_completeDigest(6, pMessage, messageLen, pResult, desiredResultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_SHA3_INVALID_MODE);
    
    /******** SHA3_allocDigest *******/
    
    status = SHA3_allocDigest(NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* properly allocate for future tests */
    status = SHA3_allocDigest((BulkCtx *) &pSha3_ctx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    /******** SHA3_initDigest *******/
    
    /* null param */
    status = SHA3_initDigest(NULL, mode);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* invalid mode */
    status = SHA3_initDigest(pSha3_ctx, 6);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_SHA3_INVALID_MODE);
    
    /* test SHA3_updateDigest and SHA3_finalDigest with uninitialized ctx */
    
    status = SHA3_updateDigest(pSha3_ctx, pMessage, messageLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_SHA3_UNINITIALIZED_CTX);
    
    status = SHA3_finalDigest(pSha3_ctx, pResult, desiredResultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_SHA3_UNINITIALIZED_CTX);
    
    /* correctly init for future tests */
    status = SHA3_initDigest(pSha3_ctx, mode);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    
    /******** SHA3_updateDigest *******/
    
    /* null params */
    status = SHA3_updateDigest(NULL, pMessage, messageLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = SHA3_updateDigest(pSha3_ctx, NULL, messageLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******** SHA3_finalDigest *******/
    
    /* null params */
    status = SHA3_finalDigest(NULL, pResult, desiredResultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    status = SHA3_finalDigest(pSha3_ctx, NULL, desiredResultLen);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /******** SHA3_freeDigest *******/
    
    status = SHA3_freeDigest((BulkCtx *) NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);
    
    /* properly free */
    status = SHA3_freeDigest((BulkCtx *) &pSha3_ctx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* free again, should be no-op that returns OK */
    status = SHA3_freeDigest((BulkCtx *) &pSha3_ctx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    
exit:
    
    if (NULL != pSha3_ctx)
    {
        status = SHA3_freeDigest((BulkCtx *) &pSha3_ctx);
        retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    }
    
    return retVal;
}
#endif /* __ENABLE_DIGICERT_SHA3__ */


int sha3_unit_test_all()
{
    int retVal = 0;
#ifdef __ENABLE_DIGICERT_SHA3__
    int i;
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestMode = 0;
#endif
    
    for (i = 0; i < COUNTOF(gTestVector_mode_0); ++i)
    {
        retVal += knownAnswerTest(gTestVector_mode_0 + i, MOCANA_SHA3_MODE_SHA3_224);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestMode = 1;
#endif
    
    for (i = 0; i < COUNTOF(gTestVector_mode_1); ++i)
    {
        retVal += knownAnswerTest(gTestVector_mode_1 + i, MOCANA_SHA3_MODE_SHA3_256);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestMode = 2;
#endif
    
    for (i = 0; i < COUNTOF(gTestVector_mode_2); ++i)
    {
        retVal += knownAnswerTest(gTestVector_mode_2 + i, MOCANA_SHA3_MODE_SHA3_384);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestMode = 3;
#endif
    
    for (i = 0; i < COUNTOF(gTestVector_mode_3); ++i)
    {
        retVal += knownAnswerTest(gTestVector_mode_3 + i, MOCANA_SHA3_MODE_SHA3_512);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestMode = 4;
#endif
    
    for (i = 0; i < COUNTOF(gTestVector_mode_4); ++i)
    {
        retVal += knownAnswerTest(gTestVector_mode_4 + i, MOCANA_SHA3_MODE_SHAKE128);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    
#ifdef __DEBUG_VECTORS__
    gCurrentVector = 0;
    gTestMode = 5;
#endif
    
    for (i = 0; i < COUNTOF(gTestVector_mode_5); ++i)
    {
        retVal += knownAnswerTest(gTestVector_mode_5 + i, MOCANA_SHA3_MODE_SHAKE256);
#ifdef __DEBUG_VECTORS__
        gCurrentVector++;
#endif
    }
    
    /* error cases are mostly mode independent */
    retVal += testErrorCases();
#endif /* __ENABLE_DIGICERT_SHA3__ */
    
    return retVal;
}
