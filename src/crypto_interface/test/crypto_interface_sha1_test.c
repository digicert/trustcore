/*
 * crypto_interface_sha1_test.c
 *
 * SHA1 test
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
#include "../../../unit_tests/unittest.h"

#include "../../common/initmocana.h"
#include "../../crypto/mocasym.h"

#include "../../crypto/sha1.h"
#include "../../../unit_tests/unittest_utils.h"


/* struct used in sha1Tests and sha1LongTests files */
typedef struct Sha1Test
{
    ubyte4  msgLen;
    ubyte*  pMsg;
    ubyte*  pMD;
} Sha1Test;

#include "../../crypto_interface/test/sha1Tests.h"
#include "../../crypto_interface/test/sha1LongTests.h"

static MocCtx gpMocCtx = NULL;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

/* indices for splitting msg into multiple update calls */
static int gUpdateIndices[][6] =
{
    {  0,   0,   0,   0,   0,   0},
    {  0,   0,   0,  63, 128, 192},
    {  0,   0,   0,  64, 128, 192},

    {  0,   0,   0,  65, 128, 192},
    {  0,   0,   1,  63, 128, 192},
    {  0,   0,   1,  64, 128, 192},

    {  0,   0,   1,  65, 128, 192},
    { 63,  63,  64,  64,  65,  65},
    { 63,  63,  65,  66, 128, 256},

    { 63,  64,  65, 127, 128, 192},
    { 63,  64,  65, 128, 130, 256},
    { 63,  64,  65, 129, 191, 257},

    { 63,  64, 127, 192, 255, 320},
    { 63,  64, 128, 192, 256, 320},
    { 63,  64, 129, 192, 257, 320},

    { 63,  65, 127, 192, 256, 319},
    { 63,  65, 128, 192, 256, 320},
    { 63,  65, 129, 192, 256, 321},

    { 63, 129, 191, 256, 321, 383},
    {  1,  65, 129, 193, 257, 321},
    {  0,  65, 127, 191, 255, 319}
};

/*----------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA1__))
static int testCryptoInterface()
{
    MSTATUS status = OK;

    shaDescr *pSha1Digester = NULL;
    MocSymCtx pShaCtx = NULL;

#ifdef __ENABLE_DIGICERT_SHA1_MBED__
    /* allocate memory for object that will do digesting */
    status = SHA1_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pSha1Digester);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* this must be called before any fuction that actually computes
     * digest can be used. */
    status = SHA1_initDigest(MOC_HASH(gpHwAccelCtx) pSha1Digester);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pShaCtx = pSha1Digester->pMocSymCtx;
    if(NULL == pShaCtx)
    {
        status = ERR_INVALID_ARG;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if(FALSE == pSha1Digester->enabled)
    {
        status = ERR_INVALID_ARG;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }
#endif

exit:

    if(NULL != pSha1Digester)
    {
        SHA1_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx *)&pSha1Digester);
    }

    if(OK != status)
        return 1;
    return 0;
}
#endif


/*----------------------------------------------------------------------------*/

static int singleSha1Test(
    ubyte *pMsg,
    ubyte4 msgLen,
    ubyte *pMD
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    SHA1_CTX *pShaCtx = NULL;
    ubyte pDigest[SHA1_RESULT_SIZE];
    sbyte4 cmpRes = -1;

    status = SHA1_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA1_initDigest(MOC_HASH(gpHwAccelCtx) pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg, msgLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA1_finalDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* compare digest with expected digest */
    status = DIGI_MEMCMP(pDigest, pMD, SHA1_RESULT_SIZE, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:

    if (NULL != pShaCtx)
    {
        SHA1_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx *)&pShaCtx);
    }

    if(OK != status)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

static int cloneTest(
    ubyte *pMsg,
    ubyte4 blockLen,
    ubyte4 msgLen,
    ubyte *pMD
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    SHA1_CTX *pShaCtx = NULL;
    SHA1_CTX *pShaCtxCopy = NULL;
    ubyte pDigest[SHA1_RESULT_SIZE];
    sbyte4 cmpRes = -1;

    status = SHA1_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA1_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtxCopy);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* Begin hashing with pShaCtx */
    status = SHA1_initDigest(MOC_HASH(gpHwAccelCtx) pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg, blockLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* Now make a copy */
    status = SHA1_cloneCtx(MOC_HASH(gpHwAccelCtx) pShaCtxCopy, pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
 
    /* Now finish hashing */
    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtxCopy, pMsg + blockLen, msgLen - blockLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA1_finalDigest(MOC_HASH(gpHwAccelCtx) pShaCtxCopy, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* compare digest with expected digest */
    status = DIGI_MEMCMP(pDigest, pMD, SHA1_RESULT_SIZE, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:

    if (NULL != pShaCtx)
    {
        (void) SHA1_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx *)&pShaCtx);
    }

    if (NULL != pShaCtxCopy)
    {
        (void) SHA1_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx *)&pShaCtxCopy);
    }

    if(OK != status)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

static int sevenUpdateSha1Test(
    ubyte *pMsg,
    ubyte4 msgLen,
    ubyte *pMD,
    ubyte4 first,
    ubyte4 second,
    ubyte4 third,
    ubyte4 fourth,
    ubyte4 fifth,
    ubyte4 sixth
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    SHA1_CTX *pShaCtx = NULL;
    ubyte pDigest[SHA1_RESULT_SIZE];
    sbyte4 cmpRes = -1;

    status = SHA1_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA1_initDigest(MOC_HASH(gpHwAccelCtx) pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg, first);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg + first, second - first);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg + second, third - second);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg + third, fourth - third);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg + fourth, fifth - fourth);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg + fifth, sixth - fifth);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg + sixth, msgLen - sixth);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA1_finalDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* compare digest with expected digest */
    status = DIGI_MEMCMP(pDigest, pMD, SHA1_RESULT_SIZE, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }
exit:

    if (NULL != pShaCtx)
    {
        SHA1_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx *)&pShaCtx);
    }

    if(OK != status)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

static int fourUpdateSha1Test(
    ubyte *pMsg,
    ubyte4 msgLen,
    ubyte *pMD,
    ubyte4 first,
    ubyte4 second,
    ubyte4 third
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    SHA1_CTX *pShaCtx = NULL;
    ubyte pDigest[SHA1_RESULT_SIZE];
    sbyte4 cmpRes = -1;

    status = SHA1_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA1_initDigest(MOC_HASH(gpHwAccelCtx) pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg, first);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg + first, second - first);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg + second, third - second);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg + third, msgLen - third);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA1_finalDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* compare digest with expected digest */
    status = DIGI_MEMCMP(pDigest, pMD, SHA1_RESULT_SIZE, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:

    if (NULL != pShaCtx)
    {
        SHA1_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx *)&pShaCtx);
    }

    if(OK != status)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

static int tripleCutTest(
    ubyte *pMsg,
    ubyte4 msgLen,
    ubyte *pMD
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    int errorCount = 0;
    int i = 0, j = 0, k = 0;

    for(;i < msgLen;i++)
        for(j=i;j < msgLen;j++)
            for(k=j;k < msgLen;k++)
                errorCount += fourUpdateSha1Test(pMsg, msgLen, pMD, i, j, k);
exit:
    return errorCount;
}

/*----------------------------------------------------------------------------*/

static int perByteTest(
    ubyte *pMsg,
    ubyte4 msgLen,
    ubyte *pMD
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    SHA1_CTX *pShaCtx = NULL;
    ubyte pDigest[SHA1_RESULT_SIZE];
    sbyte4 cmpRes = -1;
    int i = 0;

    status = SHA1_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA1_initDigest(MOC_HASH(gpHwAccelCtx) pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    for(i = 0; i < msgLen; i++)
    {
        status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg + i, 1);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;
    }

    status = SHA1_finalDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* compare digest with expected digest */
    status = DIGI_MEMCMP(pDigest, pMD, SHA1_RESULT_SIZE, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:

    if (NULL != pShaCtx)
    {
        SHA1_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx *)&pShaCtx);
    }

    if(OK != status)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

static int runTests()
{
    int errorCount = 0, i = 0, j = 0, singleShotRes = 0;
    ubyte4 msgLen = 0, mdLen = 0;
    ubyte *pMsg = NULL;
    ubyte *pMD = NULL;

    /* 65 tests in the sha1Tests.h file */
    for(i = 0;i < 65;i++)
    {
        /* get byte array from string of hex values */
        msgLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)gpSha1ShortTests[i].pMsg, &pMsg);
        mdLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)gpSha1ShortTests[i].pMD, &pMD);

        /* hash msg in one go */
        singleShotRes = singleSha1Test(pMsg, msgLen, pMD);
        if(0 == singleShotRes)
        {
            errorCount = (errorCount + tripleCutTest(pMsg, msgLen, pMD));
            errorCount = (errorCount + perByteTest(pMsg, msgLen, pMD));
        }
        else
        {
            errorCount = (errorCount + 1);
        }

        if (msgLen > 48)
        {
            errorCount += cloneTest(pMsg, 48, msgLen, pMD);
        }

        DIGI_FREE((void**)&pMsg);
        DIGI_FREE((void**)&pMD);
    }

    /* 64 tests for sha1LongTests */
    for(i = 0;i < 64; i++)
    {
        /* get byte array from string of hex values */
        msgLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)gpSha1LongTests[i].pMsg, &pMsg);
        mdLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)gpSha1LongTests[i].pMD, &pMD);

        singleShotRes = singleSha1Test(pMsg, msgLen, pMD);
        if((0 == singleShotRes) && (msgLen >= 383))
        {
            for(j=0;j < 21; j++)
            {
                errorCount = (errorCount + sevenUpdateSha1Test(pMsg, msgLen,
                    pMD, gUpdateIndices[j][0], gUpdateIndices[j][1],
                    gUpdateIndices[j][2], gUpdateIndices[j][3],
                    gUpdateIndices[j][4], gUpdateIndices[j][5]));
            }
        }
        else if(1 == singleShotRes)
        {
            errorCount = (errorCount + 1);
        }

        if (msgLen > 512)
        {
            errorCount += cloneTest(pMsg, 512, msgLen, pMD);
        }

        DIGI_FREE((void**)&pMsg);
        DIGI_FREE((void**)&pMD);
    }

    return errorCount;
}


/*----------------------------------------------------------------------------*/

static int negativeTests()
{
    MSTATUS status = ERR_NULL_POINTER;
    int errorCount = 0;
    SHA1_CTX *pShaCtx = NULL;

    ubyte pMsg[100];
    ubyte4 msgLen = 100;

    ubyte pDigest[SHA1_RESULT_SIZE];
    sbyte4 cmpRes = -1;

    /* NULL values passed to alloc */
    status = SHA1_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)pShaCtx);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = SHA1_allocDigest(MOC_HASH(gpHwAccelCtx) NULL);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    /* NULL values to init */
    status = SHA1_initDigest(MOC_HASH(gpHwAccelCtx) pShaCtx);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = SHA1_initDigest(MOC_HASH(gpHwAccelCtx) NULL);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    /* NULL for context to update calls */
    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) NULL, NULL, 0);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) NULL, pMsg, 0);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) NULL, NULL, msgLen);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) NULL, pMsg, msgLen);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }


    status = SHA1_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* Uninitialized context used for update */
    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, NULL, 0);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, NULL, msgLen);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    /* No CI option currently returning OK */
    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg, 0);
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_MBED_SYM_OPERATORS__))
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }
#endif

    /* No CI option currently returning OK */
    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg, msgLen);
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_MBED_SYM_OPERATORS__))
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }
#endif

    /* final with null and uniitialized */
    status = SHA1_finalDigest(MOC_HASH(gpHwAccelCtx) NULL, NULL);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = SHA1_finalDigest(MOC_HASH(gpHwAccelCtx) NULL, pDigest);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = SHA1_finalDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, NULL);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    /* No CI option currently returning OK */
    status = SHA1_finalDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pDigest);
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_MBED_SYM_OPERATORS__))
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }
#endif

    /* 16 error cases, CI with embed returns bad status on all 16,
     * but No CI and passthrough both only return bad status' on
     * 13 cases */
exit:
    SHA1_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);

    return errorCount;
}

/*----------------------------------------------------------------------------*/

static int twoContextTest()
{
    MSTATUS status = ERR_NULL_POINTER;
    SHA1_CTX *pShaCtx = NULL;
    SHA1_CTX *pOtherShaCtx = NULL;
    ubyte pDigest[SHA1_RESULT_SIZE];
    ubyte pOtherDigest[SHA1_RESULT_SIZE];
    sbyte4 cmpRes = -1;

    ubyte *pMsg1 = NULL;
    ubyte4 msg1Len = 0;
    ubyte *pMD1 = NULL;
    ubyte4 md1Len = 0;

    msg1Len = UNITTEST_UTILS_str_to_byteStr(
        (const sbyte*)gpSha1LongTests[0].pMsg, &pMsg1);
    md1Len = UNITTEST_UTILS_str_to_byteStr(
        (const sbyte*)gpSha1LongTests[0].pMD, &pMD1);

    ubyte *pMsg2 = NULL;
    ubyte4 msg2Len = 0;
    ubyte *pMD2 = NULL;
    ubyte4 md2Len = 0;

    msg2Len = UNITTEST_UTILS_str_to_byteStr(
        (const sbyte*)gpSha1LongTests[1].pMsg, &pMsg2);
    md2Len = UNITTEST_UTILS_str_to_byteStr(
        (const sbyte*)gpSha1LongTests[1].pMD, &pMD2);

    if((SHA1_RESULT_SIZE != md1Len) || (SHA1_RESULT_SIZE != md2Len))
    {
        goto exit;
    }

    /* split points for hashing in two updates */
    ubyte4 msg1MidPoint = msg1Len/2;
    ubyte4 msg2MidPoint = msg2Len/2;

    /* first context object */
    status = SHA1_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* initialize context for hashing */
    status = SHA1_initDigest(MOC_HASH(gpHwAccelCtx) pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* second context object */
    status = SHA1_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pOtherShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* initialize context for hashing */
    status = SHA1_initDigest(MOC_HASH(gpHwAccelCtx) pOtherShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* call update with first half of msg1 (FIRST MESSAGE) */
    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg1, msg1MidPoint);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* call update with first half of msg2 (SECOND MESSAGE) */
    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pOtherShaCtx, pMsg2, msg2MidPoint);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* call update with second half of msg1 (FIRST MESSAGE) */
    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg1 + msg1MidPoint,
        msg1Len - msg1MidPoint);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* call update with second half of msg2 (SECOND MESSAGE) */
    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pOtherShaCtx, pMsg2 + msg2MidPoint,
        msg2Len - msg2MidPoint);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* get digest of FIRST MESSAGE */
    status = SHA1_finalDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* check if it the expected value */
    status = DIGI_MEMCMP(pDigest, pMD1, SHA1_RESULT_SIZE, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* get digest of SECOND MESSAGE */
    status = SHA1_finalDigest(MOC_HASH(gpHwAccelCtx) pOtherShaCtx, pOtherDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* compare digest of second context with expected value */
    status = DIGI_MEMCMP(pOtherDigest, pMD2, SHA1_RESULT_SIZE, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:

    SHA1_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);
    SHA1_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pOtherShaCtx);

    if (NULL != pMsg1)
    {
        DIGI_FREE((void **)&pMsg1);
    }
    if (NULL != pMD1)
    {
        DIGI_FREE((void **)&pMD1);
    }
    if (NULL != pMsg2)
    {
        DIGI_FREE((void **)&pMsg2);
    }
    if (NULL != pMD2)
    {
        DIGI_FREE((void **)&pMD2);
    }

    if(OK != status)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

static int testMultipleHashes()
{
    MSTATUS status = ERR_NULL_POINTER;
    SHA1_CTX *pShaCtx = NULL;
    ubyte pDigest[SHA1_RESULT_SIZE];
    sbyte4 cmpRes = -1;

    ubyte *pMsg1 = NULL;
    ubyte4 msg1Len = 0;
    ubyte *pMD1 = NULL;
    ubyte4 md1Len = 0;

    msg1Len = UNITTEST_UTILS_str_to_byteStr(
        (const sbyte*)gpSha1LongTests[0].pMsg, &pMsg1);
    md1Len = UNITTEST_UTILS_str_to_byteStr(
        (const sbyte*)gpSha1LongTests[0].pMD, &pMD1);

    ubyte *pMsg2 = NULL;
    ubyte4 msg2Len = 0;
    ubyte *pMD2 = NULL;
    ubyte4 md2Len = 0;

    msg2Len = UNITTEST_UTILS_str_to_byteStr(
        (const sbyte*)gpSha1LongTests[1].pMsg, &pMsg2);
    md2Len = UNITTEST_UTILS_str_to_byteStr(
        (const sbyte*)gpSha1LongTests[1].pMD, &pMD2);

    if((SHA1_RESULT_SIZE != md1Len) || (SHA1_RESULT_SIZE != md2Len))
    {
        goto exit;
    }

    /* split points for hashing in two updates */
    ubyte4 msg1MidPoint = msg1Len/2;
    ubyte4 msg2MidPoint = msg2Len/2;

    /* allocate memory for context */
    status = SHA1_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* initialize context for hashing */
    status = SHA1_initDigest(MOC_HASH(gpHwAccelCtx) pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* call update with first half of msg1 (FIRST MESSAGE) */
    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg1, msg1MidPoint);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* REINITIALIZE context for new hash */
    status = SHA1_initDigest(MOC_HASH(gpHwAccelCtx) pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* call update on first half of msg2 (SECOND MESSAGE) */
    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg2, msg2MidPoint);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* call update on second half of msg2 (SECOND MESSAGE) */
    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg2 + msg2MidPoint,
        msg2Len - msg2MidPoint);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* call final to retrieve hash value for msg2 (SECOND MESSAGE) */
    status = SHA1_finalDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* compare msg2 digest with expected digest */
    status = DIGI_MEMCMP(pDigest, pMD2, SHA1_RESULT_SIZE, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    if(0 != cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* call update before reinitializing on msg1 (FIRST MESSAGE) */
    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg1, msg1Len);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* call final to retrieve hash value (FIRST MESSAGE) */
    status = SHA1_finalDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* compare msg1 digest with expected digest */
    cmpRes = -1;
    status = DIGI_MEMCMP(pDigest, pMD1, SHA1_RESULT_SIZE, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* the buffers should not be equal, we didn't initialize context */
    if(0 == cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    /* REINITIALIZE context for new hash */
    status = SHA1_initDigest(MOC_HASH(gpHwAccelCtx) pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* call final without any update calls */
    status = SHA1_finalDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* call update after final call with msg2 (SECOND MESSAGE) */
    status = SHA1_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg2, msg2Len);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* call final after update to compute digest */
    status = SHA1_finalDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;


    /* compare this digest with expected digest. */
    status = DIGI_MEMCMP(pDigest, pMD2, SHA1_RESULT_SIZE, &cmpRes);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* shouldn't be the same value, we did update after a final */
    if(0 == cmpRes)
    {
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

exit:

    SHA1_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);

    if (NULL != pMsg1)
    {
        DIGI_FREE((void **)&pMsg1);
    }
    if (NULL != pMD1)
    {
        DIGI_FREE((void **)&pMD1);
    }
    if (NULL != pMsg2)
    {
        DIGI_FREE((void **)&pMsg2);
    }
    if (NULL != pMD2)
    {
        DIGI_FREE((void **)&pMD2);
    }

    if(OK != status)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RNG__

typedef struct
{
    ubyte pInput[SHA1_BLOCK_SIZE];
    ubyte pG[SHA1_RESULT_SIZE];
    ubyte pGK[SHA1_RESULT_SIZE];
    
} TestVector;

static TestVector gTestVector[2] =
{
    {
        {
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        },
        {0x92,0xb4,0x04,0xe5,0x56,0x58,0x8c,0xed,0x6c,0x1a,0xcd,0x4e,0xbf,0x05,0x3f,0x68,0x09,0xf7,0x3a,0x93},
        {0xdd,0x40,0x04,0x90,0x49,0xbe,0xc3,0xef,0x35,0x87,0x31,0xc8,0x6e,0x2f,0xc4,0x29,0xff,0x0b,0xdd,0x33}
    },
    {
        {
            0xe5,0x56,0x58,0x8c,0xed,0x6c,0x1a,0xcd,0x4e,0xbf,0x05,0x3f,0x68,0x09,0xf7,0x3a,
            0x40,0x04,0x90,0x49,0xbe,0xc3,0xef,0x35,0x87,0x31,0xc8,0x6e,0x2f,0xc4,0x29,0xff,
            0xc3,0xef,0x35,0xcd,0x4e,0xbf,0x05,0xff,0x0b,0xdd,0x33,0xe5,0x56,0x58,0x8c,0x05,
            0x35,0xad,0x4e,0xcf,0x05,0x39,0x83,0x31,0xc8,0x6e,0xff,0x0b,0xdd,0xc3,0xef,0x35
        },
        {0x20,0x68,0x91,0x21,0x7e,0x3b,0x4c,0x89,0xed,0xba,0x67,0xaa,0xdb,0x60,0xd7,0xcc,0x77,0x0a,0x17,0xf5},
        {0x15,0xb5,0x96,0xac,0x3c,0x99,0x32,0x83,0x47,0xec,0xfd,0x59,0xd3,0xc3,0x64,0x79,0xee,0xb2,0x09,0x1f}
    }
};

static int testSha1GandGK()
{
    MSTATUS status = OK;
    sbyte4 cmpRes;
    int i;

    ubyte pInput[SHA1_BLOCK_SIZE] = {0};
    ubyte pOutput[SHA1_RESULT_SIZE];
    
    for (i = 0; i < sizeof(gTestVector)/sizeof(TestVector); ++i)
    {
        /* make a mutable copy of input */
        status = DIGI_MEMCPY(pInput, gTestVector[i].pInput, SHA1_BLOCK_SIZE);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;
        
        /* test SHA1_G */
        status = SHA1_G(pInput, pOutput);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;

        
        /* compare this output with the expected output. */
        status = DIGI_MEMCMP(pOutput, gTestVector[i].pG, SHA1_RESULT_SIZE, &cmpRes);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;
        
        /* should be the same */
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
        
        /* make a mutable copy of input again */
        status = DIGI_MEMCPY(pInput, gTestVector[i].pInput, SHA1_BLOCK_SIZE);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;
        
        /* test SHA1_GK */
        status = SHA1_GK(pInput, pOutput);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;
        
        /* compare this output with the expected output. */
        status = DIGI_MEMCMP(pOutput, gTestVector[i].pGK, SHA1_RESULT_SIZE, &cmpRes);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;
        
        /* should be the same */
        if(0 != cmpRes)
        {
            status = ERR_CMP;
            UNITTEST_STATUS(__MOC_LINE__, status);
            goto exit;
        }
    }
    
exit:
    
    if(OK != status)
        return 1;
    return 0;
}
#endif

extern int crypto_interface_sha1_test_init()
{
    MSTATUS status = ERR_NULL_POINTER;
    int errorCount = 0;

    InitMocanaSetupInfo setupInfo = { 0 };
    /**********************************************************
     *************** DO NOT USE MOC_NO_AUTOSEED ***************
     ***************** in any production code. ****************
     **********************************************************/
    setupInfo.flags = MOC_NO_AUTOSEED;

    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    if (OK != status)
    {
        errorCount = 1;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        errorCount = 1;
        goto exit;
    }
    
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    if (OK != status)
    {
        errorCount = 1;
        goto exit;
    }
#endif

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA1__))

    errorCount = (errorCount + testCryptoInterface());
#endif

    /* TESTS GO HERE */
    errorCount = (errorCount + runTests());
    errorCount = (errorCount + negativeTests());
    errorCount = (errorCount + twoContextTest());
    errorCount = (errorCount + testMultipleHashes());
  
#ifndef __DISABLE_DIGICERT_RNG__
    errorCount = (errorCount + testSha1GandGK());
#endif

exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

    DIGICERT_free(&gpMocCtx);
    return errorCount;
}

