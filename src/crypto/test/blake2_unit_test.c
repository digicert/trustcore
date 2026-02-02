/*
 * blake2_unit_test.c
 *
 *   unit test for blake2.c
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
#include "../../common/mdefs.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"
#include "../../common/mrtos.h"
#include "../../crypto/hw_accel.h"
#include "../../crypto/blake2.h"
#include "../../../unit_tests/unittest_utils.h"
#include "../../../unit_tests/unittest.h"

typedef struct TestVector
{
    char *pInput;
    char *pKey;
    char *pResult;

} TestVector;

#ifdef __ENABLE_DIGICERT_BLAKE_2B__
#include "../../crypto/test/blake2B_data_inc.h"
#endif

#ifdef __ENABLE_DIGICERT_BLAKE_2S__
#include "../../crypto/test/blake2S_data_inc.h"
#endif

static ubyte4 gCurrentVector = 0;

#define MAX_BUFFER_INDICES 3

/*
 Tests the blake2 evp methods. pBufferIndices must include the end of the message, ie the last
 value should always be the length of the message (ie the index after the last byte).
 This ensures the while loop will finish before we start accessing data beyond the length
 of pBufferIndices.
 */
static int testBlake2BEvp(ubyte *pMessage, ubyte4 messageLen, ubyte *pKey, ubyte4 keyLen, ubyte *pExpectedResult, ubyte4 expectedResultLen, ubyte4 *pBufferIndices)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare;
    int count = 0;

    sbyte4 messageLeft = (sbyte4) messageLen;
    ubyte4 nextBlockLen;
    ubyte *pMsgPtr = pMessage;
    ubyte4 *pBufferIndexPtr = pBufferIndices;

    BulkCtx pBlakeCtx = NULL;

    ubyte pResult[MOC_BLAKE2B_MAX_OUTLEN] = {0};

    status = BLAKE2B_alloc(&pBlakeCtx);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    status = BLAKE2B_init(pBlakeCtx, expectedResultLen, pKey, keyLen);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    while(messageLeft > 0 && count < MAX_BUFFER_INDICES - 1)
    {
        nextBlockLen = *(pBufferIndexPtr + 1) - *pBufferIndexPtr;
        if (nextBlockLen > messageLeft)
            nextBlockLen = messageLeft;

        status = BLAKE2B_update(pBlakeCtx, pMsgPtr, nextBlockLen);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;

        messageLeft -= nextBlockLen;
        pMsgPtr += nextBlockLen;
        pBufferIndexPtr++;
        count++;
    }

    if (messageLeft)
    {
        status = BLAKE2B_update(pBlakeCtx, pMsgPtr, messageLeft);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;
    }

    status = BLAKE2B_final(pBlakeCtx, pResult);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pResult, pExpectedResult, expectedResultLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(gCurrentVector, compare, 0);

exit:

    if (NULL != pBlakeCtx)
    {
        status = BLAKE2B_delete(&pBlakeCtx);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }

    return retVal;
}

static int testBlake2SEvp(ubyte *pMessage, ubyte4 messageLen, ubyte *pKey, ubyte4 keyLen, ubyte *pExpectedResult, ubyte4 expectedResultLen, ubyte4 *pBufferIndices)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare;
    int count = 0;

    sbyte4 messageLeft = (sbyte4) messageLen;
    ubyte4 nextBlockLen;
    ubyte *pMsgPtr = pMessage;
    ubyte4 *pBufferIndexPtr = pBufferIndices;

    BulkCtx pBlakeCtx = NULL;

    ubyte pResult[MOC_BLAKE2S_MAX_OUTLEN] = {0};

    status = BLAKE2S_alloc(&pBlakeCtx);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    status = BLAKE2S_init(pBlakeCtx, expectedResultLen, pKey, keyLen);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    while(messageLeft > 0 && count < MAX_BUFFER_INDICES - 1)
    {
        nextBlockLen = *(pBufferIndexPtr + 1) - *pBufferIndexPtr;
        if (nextBlockLen > messageLeft)
            nextBlockLen = messageLeft;

        status = BLAKE2S_update(pBlakeCtx, pMsgPtr, nextBlockLen);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;

        messageLeft -= nextBlockLen;
        pMsgPtr += nextBlockLen;
        pBufferIndexPtr++;
        count++;
    }

    if (messageLeft)
    {
        status = BLAKE2S_update(pBlakeCtx, pMsgPtr, messageLeft);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
        if (OK != status)
            goto exit;
    }

    status = BLAKE2S_final(pBlakeCtx, pResult);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pResult, pExpectedResult, expectedResultLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(gCurrentVector, compare, 0);

exit:

    if (NULL != pBlakeCtx)
    {
        status = BLAKE2S_delete(&pBlakeCtx);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }

    return retVal;
}


static int knownAnswerTest(TestVector *pTestVector, byteBoolean is2B, ubyte4 pIndices[][MAX_BUFFER_INDICES], ubyte4 numEVPtests)
{
    MSTATUS status = OK;
    int retVal = 0;
    sbyte4 compare;
    int i;

    ubyte *pByteBufferInput = NULL;
    ubyte4 inputLen = 0;

    ubyte *pByteBufferKey = NULL;
    ubyte4 keyLen = 0;

    ubyte *pByteBufferResult = NULL;
    ubyte4 resultLen = 0;

    ubyte pResult[MOC_BLAKE2B_MAX_OUTLEN] = {0}; /* big enough for all tests */

    if (NULL != pTestVector->pInput)
        inputLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pInput, &pByteBufferInput);
    if (NULL != pTestVector->pKey)
        keyLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pKey, &pByteBufferKey);
    if (NULL != pTestVector->pResult)
        resultLen = UNITTEST_UTILS_str_to_byteStr((sbyte *) pTestVector->pResult, &pByteBufferResult);

    if (is2B)
    {
        status = BLAKE2B_complete(pByteBufferKey, keyLen, pByteBufferInput, inputLen, pResult, resultLen);
    }
    else /* is 2S */
    {
        status = BLAKE2S_complete(pByteBufferKey, keyLen, pByteBufferInput, inputLen, pResult, resultLen);
    }
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCMP(pResult, pByteBufferResult, resultLen, &compare);
    retVal += UNITTEST_STATUS(gCurrentVector, status);
    if (OK != status)
        goto exit;

    retVal += UNITTEST_INT(gCurrentVector, compare, 0);

    /* Test evp API's for various buffer configurations, that is if the message is almost a full block or more */
    if (is2B && inputLen >= 127)
    {
        for (i = 0; i < numEVPtests; ++i)
        {
            retVal += testBlake2BEvp(pByteBufferInput, inputLen, pByteBufferKey, keyLen, pByteBufferResult, resultLen, pIndices[i]);
        }
    }
    else if (!is2B && inputLen >= 63)
    {
        for (i = 0; i < numEVPtests; ++i)
        {
            retVal += testBlake2SEvp(pByteBufferInput, inputLen, pByteBufferKey, keyLen, pByteBufferResult, resultLen, pIndices[i]);
        }
    }

exit:

    if (NULL != pByteBufferInput)
    {
        status = DIGI_FREE((void **) &pByteBufferInput);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pByteBufferKey)
    {
        status = DIGI_FREE((void **) &pByteBufferKey);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }
    if (NULL != pByteBufferResult)
    {
        status = DIGI_FREE((void **) &pByteBufferResult);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }

    return retVal;
}


static int testErrorCases2B()
{
    MSTATUS status;
    int retVal = 0;

    ubyte pData[128] = {0};
    ubyte pKey[MOC_BLAKE2B_MAX_KEYLEN] = {0};

    BulkCtx pBlakeCtx = NULL;

    ubyte pResult[MOC_BLAKE2B_MAX_OUTLEN] = {0};

    /******* BLAKE2B_alloc *******/

    status = BLAKE2B_alloc(NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* properly allocated for further tests */
    status = BLAKE2B_alloc(&pBlakeCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /*
     NOTE we do not have an initialized flag in the blake2b ctx, calling init, update, final
     out of order will just result in bad results
     */

    /******* BLAKE2B_init *******/

    /* Null params */
    status = BLAKE2B_init(NULL, MOC_BLAKE2B_MAX_OUTLEN, pKey, sizeof(pKey));
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = BLAKE2B_init(pBlakeCtx, MOC_BLAKE2B_MAX_OUTLEN, NULL, sizeof(pKey));
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* invalid outLen */
    status = BLAKE2B_init(pBlakeCtx, 0, pKey, sizeof(pKey));
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BLAKE2_INVALID_OUTLEN);

    status = BLAKE2B_init(pBlakeCtx, MOC_BLAKE2B_MAX_OUTLEN + 1, pKey, sizeof(pKey));
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BLAKE2_INVALID_OUTLEN);

    /* invalid keyLen */
    status = BLAKE2B_init(pBlakeCtx, MOC_BLAKE2B_MAX_OUTLEN, pKey, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BLAKE2_INVALID_KEYLEN);

    status = BLAKE2B_init(pBlakeCtx, MOC_BLAKE2B_MAX_OUTLEN, pKey, sizeof(pKey) + 1);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BLAKE2_INVALID_KEYLEN);

    /* properly init for further tests */
    status = BLAKE2B_init(pBlakeCtx, MOC_BLAKE2B_MAX_OUTLEN, pKey, sizeof(pKey));
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /******* BLAKE2B_update *******/

    /* Null params */
    status = BLAKE2B_update(NULL, pData, sizeof(pData));
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = BLAKE2B_update(pBlakeCtx, NULL, sizeof(pData));
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /******* BLAKE2B_final *******/

    /* Null params */
    status = BLAKE2B_final(NULL, pResult);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = BLAKE2B_final(pBlakeCtx, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* call final twice correctly */
    status = BLAKE2B_final(pBlakeCtx, pResult);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = BLAKE2B_final(pBlakeCtx, pResult);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BLAKE2_ALREADY_PROCESSED_LAST_BLOCK);

    /******* BLAKE2B_delete *******/

    status = BLAKE2B_delete(NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* deleting an already deleted context is an OK no-op */

    /******* BLAKE2B_complete *******/

    status = BLAKE2B_complete(NULL, sizeof(pKey), pData, sizeof(pData), pResult, MOC_BLAKE2B_MAX_OUTLEN);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = BLAKE2B_complete(pKey, sizeof(pKey), NULL, sizeof(pData), pResult, MOC_BLAKE2B_MAX_OUTLEN);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = BLAKE2B_complete(pKey, sizeof(pKey), pData, sizeof(pData), NULL, MOC_BLAKE2B_MAX_OUTLEN);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* invalid outLen */
    status = BLAKE2B_complete(pKey, sizeof(pKey), pData, sizeof(pData), pResult, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BLAKE2_INVALID_OUTLEN);

    status = BLAKE2B_complete(pKey, sizeof(pKey), pData, sizeof(pData), pResult, MOC_BLAKE2B_MAX_OUTLEN + 1);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BLAKE2_INVALID_OUTLEN);

    /* invalid keyLen */
    status = BLAKE2B_complete(pKey, 0, pData, sizeof(pData), pResult, MOC_BLAKE2B_MAX_OUTLEN);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BLAKE2_INVALID_KEYLEN);

    status = BLAKE2B_complete(pKey, sizeof(pKey) + 1, pData, sizeof(pData), pResult, MOC_BLAKE2B_MAX_OUTLEN);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BLAKE2_INVALID_KEYLEN);

exit:

    if (NULL != pBlakeCtx)
    {
        status = BLAKE2B_delete(&pBlakeCtx);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }

    return retVal;
 }

static int testErrorCases2S()
{
    MSTATUS status;
    int retVal = 0;

    ubyte pData[64] = {0};
    ubyte pKey[MOC_BLAKE2S_MAX_KEYLEN] = {0};

    BulkCtx pBlakeCtx = NULL;

    ubyte pResult[MOC_BLAKE2S_MAX_OUTLEN] = {0};

    /******* BLAKE2S_alloc *******/

    status = BLAKE2S_alloc(NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* properly allocated for further tests */
    status = BLAKE2S_alloc(&pBlakeCtx);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /*
     NOTE we do not have an initialized flag in the blake2b ctx, calling init, update, final
     out of order will just result in bad results
     */

    /******* BLAKE2S_init *******/

    /* Null params */
    status = BLAKE2S_init(NULL, MOC_BLAKE2S_MAX_OUTLEN, pKey, sizeof(pKey));
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = BLAKE2S_init(pBlakeCtx, MOC_BLAKE2S_MAX_OUTLEN, NULL, sizeof(pKey));
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* invalid outLen */
    status = BLAKE2S_init(pBlakeCtx, 0, pKey, sizeof(pKey));
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BLAKE2_INVALID_OUTLEN);

    status = BLAKE2S_init(pBlakeCtx, MOC_BLAKE2S_MAX_OUTLEN + 1, pKey, sizeof(pKey));
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BLAKE2_INVALID_OUTLEN);

    /* invalid keyLen */
    status = BLAKE2S_init(pBlakeCtx, MOC_BLAKE2S_MAX_OUTLEN, pKey, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BLAKE2_INVALID_KEYLEN);

    status = BLAKE2S_init(pBlakeCtx, MOC_BLAKE2S_MAX_OUTLEN, pKey, sizeof(pKey) + 1);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BLAKE2_INVALID_KEYLEN);

    /* properly init for further tests */
    status = BLAKE2S_init(pBlakeCtx, MOC_BLAKE2S_MAX_OUTLEN, pKey, sizeof(pKey));
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /******* BLAKE2S_update *******/

    /* Null params */
    status = BLAKE2S_update(NULL, pData, sizeof(pData));
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = BLAKE2S_update(pBlakeCtx, NULL, sizeof(pData));
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /******* BLAKE2S_final *******/

    /* Null params */
    status = BLAKE2S_final(NULL, pResult);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = BLAKE2S_final(pBlakeCtx, NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* call final twice correctly */
    status = BLAKE2S_final(pBlakeCtx, pResult);
    retVal += UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = BLAKE2S_final(pBlakeCtx, pResult);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BLAKE2_ALREADY_PROCESSED_LAST_BLOCK);

    /******* BLAKE2S_delete *******/

    status = BLAKE2S_delete(NULL);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* deleting an already deleted context is an OK no-op */

    /******* BLAKE2S_complete *******/

    status = BLAKE2S_complete(NULL, sizeof(pKey), pData, sizeof(pData), pResult, MOC_BLAKE2S_MAX_OUTLEN);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = BLAKE2S_complete(pKey, sizeof(pKey), NULL, sizeof(pData), pResult, MOC_BLAKE2S_MAX_OUTLEN);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    status = BLAKE2S_complete(pKey, sizeof(pKey), pData, sizeof(pData), NULL, MOC_BLAKE2S_MAX_OUTLEN);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_NULL_POINTER);

    /* invalid outLen */
    status = BLAKE2S_complete(pKey, sizeof(pKey), pData, sizeof(pData), pResult, 0);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BLAKE2_INVALID_OUTLEN);

    status = BLAKE2S_complete(pKey, sizeof(pKey), pData, sizeof(pData), pResult, MOC_BLAKE2S_MAX_OUTLEN + 1);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BLAKE2_INVALID_OUTLEN);

    /* invalid keyLen */
    status = BLAKE2S_complete(pKey, 0, pData, sizeof(pData), pResult, MOC_BLAKE2S_MAX_OUTLEN);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BLAKE2_INVALID_KEYLEN);

    status = BLAKE2S_complete(pKey, sizeof(pKey) + 1, pData, sizeof(pData), pResult, MOC_BLAKE2S_MAX_OUTLEN);
    retVal += UNITTEST_INT(__MOC_LINE__, status, ERR_BLAKE2_INVALID_KEYLEN);

exit:

    if (NULL != pBlakeCtx)
    {
        status = BLAKE2S_delete(&pBlakeCtx);
        retVal += UNITTEST_STATUS(gCurrentVector, status);
    }

    return retVal;
}


int blake2_unit_test_all()
{
    int retVal = 0;
#if defined(__ENABLE_DIGICERT_BLAKE_2B__) || defined(__ENABLE_DIGICERT_BLAKE_2S__)
    int i;
#endif

#ifdef __ENABLE_DIGICERT_BLAKE_2B__

    gCurrentVector = 0;

    for (i = 0; i < sizeof(gTestVector2B)/sizeof(gTestVector2B[0]); ++i)
    {
        retVal += knownAnswerTest(gTestVector2B + i, TRUE, gpIndices2B, sizeof(gpIndices2B)/sizeof(gpIndices2B[0]));
        gCurrentVector++;
    }

    retVal += testErrorCases2B();
#endif /* __ENABLE_DIGICERT_BLAKE_2B__*/

#ifdef __ENABLE_DIGICERT_BLAKE_2S__

    gCurrentVector = 0;

    for (i = 0; i < sizeof(gTestVector2S)/sizeof(gTestVector2S[0]); ++i)
    {
        retVal += knownAnswerTest(gTestVector2S + i, FALSE, gpIndices2S, sizeof(gpIndices2S)/sizeof(gpIndices2S[0]));
        gCurrentVector++;
    }

    retVal += testErrorCases2S();
#endif /* __ENABLE_DIGICERT_BLAKE_2B__*/

    return retVal;
}
