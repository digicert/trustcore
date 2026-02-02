/*
 * crypto_interface_sha256_test.c
 *
 * SHA2-256 test
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

#include "../../crypto/sha256.h"
#include "../../../unit_tests/unittest_utils.h"

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
static void *gpHwAccelCtx = NULL;
#endif

static MocCtx gpMocCtx = NULL;

/* struct used in sha256Tests and SHA256LongTests files */
typedef struct Sha256Test
{
    ubyte4  msgLen;
    ubyte*  pMsg;
    ubyte*  pMD;
} Sha256Test;

#include "../../crypto_interface/test/sha256Tests.h"
#include "../../crypto_interface/test/sha256LongTests.h"


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
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA256__))
static int testCryptoInterface()
{
    MSTATUS status = OK;

    SHA256_CTX* pSha256Ctx = NULL;
    MocSymCtx pShaCtx = NULL;

#ifdef __ENABLE_DIGICERT_SHA256_MBED__
    /* allocate memory for object that will do digesting */
    status = SHA256_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pSha256Ctx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* this must be called before any fuction that actually computes
     * digest can be used. */
    status = SHA256_initDigest(MOC_HASH(gpHwAccelCtx) pSha256Ctx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    pShaCtx = pSha256Ctx->pMocSymCtx;
    if(NULL == pShaCtx)
    {
        status = ERR_INVALID_ARG;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }

    if(FALSE == pSha256Ctx->enabled)
    {
        status = ERR_INVALID_ARG;
        UNITTEST_STATUS(__MOC_LINE__, status);
        goto exit;
    }
#endif

exit:

    if(NULL != pSha256Ctx)
    {
        SHA256_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx *)&pSha256Ctx);
    }

    if(OK != status)
        return 1;
    return 0;
}
#endif

/*----------------------------------------------------------------------------*/

static int singleSha256Test(
    ubyte *pMsg,
    ubyte4 msgLen,
    ubyte *pMD
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    SHA256_CTX *pShaCtx = NULL;
    ubyte pDigest[SHA256_RESULT_SIZE];
    sbyte4 cmpRes = -1;

    status = SHA256_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA256_initDigest(MOC_HASH(gpHwAccelCtx) pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg, msgLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA256_finalDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* compare digest with expected digest */
    status = DIGI_MEMCMP(pDigest, pMD, SHA256_RESULT_SIZE, &cmpRes);
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
        SHA256_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx *)&pShaCtx);
    }

    if(OK != status)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

static int sevenUpdateSha256Test(
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
    SHA256_CTX *pShaCtx = NULL;
    ubyte pDigest[SHA256_RESULT_SIZE];
    sbyte4 cmpRes = -1;

    status = SHA256_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA256_initDigest(MOC_HASH(gpHwAccelCtx) pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg, first);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg + first, second - first);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg + second, third - second);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg + third, fourth - third);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg + fourth, fifth - fourth);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg + fifth, sixth - fifth);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg + sixth, msgLen - sixth);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA256_finalDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* compare digest with expected digest */
    status = DIGI_MEMCMP(pDigest, pMD, SHA256_RESULT_SIZE, &cmpRes);
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
        SHA256_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx *)&pShaCtx);
    }

    if(OK != status)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

static int fourUpdateSha256Test(
    ubyte *pMsg,
    ubyte4 msgLen,
    ubyte *pMD,
    ubyte4 first,
    ubyte4 second,
    ubyte4 third
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    SHA256_CTX *pShaCtx = NULL;
    ubyte pDigest[SHA256_RESULT_SIZE];
    sbyte4 cmpRes = -1;

    status = SHA256_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA256_initDigest(MOC_HASH(gpHwAccelCtx) pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg, first);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg + first, second - first);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg + second, third - second);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg + third, msgLen - third);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA256_finalDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* compare digest with expected digest */
    status = DIGI_MEMCMP(pDigest, pMD, SHA256_RESULT_SIZE, &cmpRes);
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
        SHA256_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx *)&pShaCtx);
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
    SHA256_CTX *pShaCtx = NULL;
    SHA256_CTX *pShaCtxCopy = NULL;
    ubyte pDigest[SHA256_RESULT_SIZE];
    sbyte4 cmpRes = -1;

    status = SHA256_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA256_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtxCopy);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* Begin hashing with pShaCtx */
    status = SHA256_initDigest(MOC_HASH(gpHwAccelCtx) pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg, blockLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* Now make a copy */
    status = SHA256_cloneCtx(MOC_HASH(gpHwAccelCtx) pShaCtxCopy, pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;
 
    /* Now finish hashing */
    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtxCopy, pMsg + blockLen, msgLen - blockLen);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA256_finalDigest(MOC_HASH(gpHwAccelCtx) pShaCtxCopy, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* compare digest with expected digest */
    status = DIGI_MEMCMP(pDigest, pMD, SHA256_RESULT_SIZE, &cmpRes);
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
        (void) SHA256_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx *)&pShaCtx);
    }

    if (NULL != pShaCtxCopy)
    {
        (void) SHA256_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx *)&pShaCtxCopy);
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
        for(j = i;j < msgLen;j++)
            for(k = j;k < msgLen;k++)
                errorCount += fourUpdateSha256Test(pMsg, msgLen, pMD, i, j, k);
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
    SHA256_CTX *pShaCtx = NULL;
    ubyte pDigest[SHA256_RESULT_SIZE];
    sbyte4 cmpRes = -1;
    int i = 0;

    status = SHA256_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = SHA256_initDigest(MOC_HASH(gpHwAccelCtx) pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    for(i = 0; i < msgLen; i++)
    {
        status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg + i, 1);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if(OK != status)
            goto exit;
    }

    status = SHA256_finalDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* compare digest with expected digest */
    status = DIGI_MEMCMP(pDigest, pMD, SHA256_RESULT_SIZE, &cmpRes);
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
        SHA256_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx *)&pShaCtx);
    }

    if(OK != status)
        return 1;
    return 0;
}

/*----------------------------------------------------------------------------*/

static int runTests()
{
    MSTATUS status;
    int errorCount = 0, i = 0, j = 0, singleShotRes = 0;
    ubyte4 msgLen = 0, mdLen = 0;
    ubyte *pMsg = NULL;
    ubyte *pMD = NULL;
    ubyte *pOutput = NULL;
    sbyte4 cmpRes = -1;

    /* 65 tests in the sha256Tests.h file */
    for(i = 0;i < 65;i++)
    {
        /* get byte array from string of hex values */
        msgLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)gpSha256ShortTests[i].pMsg, &pMsg);
        mdLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)gpSha256ShortTests[i].pMD, &pMD);

        /* hash msg in one go */
        singleShotRes = singleSha256Test(pMsg, msgLen, pMD);
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

    /* 64 tests for sha256LongTests */
    for(i = 0;i < 64; i++)
    {
        /* get byte array from string of hex values */
        msgLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)gpSha256LongTests[i].pMsg, &pMsg);
        mdLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)gpSha256LongTests[i].pMD, &pMD);

        singleShotRes = singleSha256Test(pMsg, msgLen, pMD);
        if((0 == singleShotRes) && (msgLen >= 383))
        {
            for(j=0;j < 21; j++)
            {
                errorCount = (errorCount + sevenUpdateSha256Test(pMsg, msgLen,
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

    /* 64 tests for sha256LongTests */
    for(i = 0;i < 64; i++)
    {
        /* get byte array from string of hex values */
        msgLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)gpSha256LongTests[i].pMsg, &pMsg);
        mdLen = UNITTEST_UTILS_str_to_byteStr(
            (const sbyte*)gpSha256LongTests[i].pMD, &pMD);

        DIGI_MALLOC((void**)&pOutput, mdLen);

        status = SHA256_completeDigest(MOC_HASH(gpHwAccelCtx) (const ubyte*)pMsg, msgLen, pOutput);
        UNITTEST_STATUS(i, status);
        if(OK != status)
        {
            errorCount = (errorCount + 1);
        }
        else
        {
            DIGI_MEMCMP(pOutput, pMD, mdLen, &cmpRes);
            if(0 != cmpRes)
            {
                UNITTEST_STATUS(i, ERR_CMP);
                errorCount = (errorCount + 1);
            }
        }

        DIGI_FREE((void**)&pMsg);
        DIGI_FREE((void**)&pMD);
        DIGI_FREE((void**)&pOutput);
    }

    return errorCount;
}

/*----------------------------------------------------------------------------*/

static int negativeTests()
{
    MSTATUS status = ERR_NULL_POINTER;
    int errorCount = 0;
    SHA256_CTX *pShaCtx = NULL;

    ubyte pMsg[100] = {0};
    ubyte4 msgLen = 100;

    ubyte pDigest[SHA256_RESULT_SIZE];
    sbyte4 cmpRes = -1;

    /* NULL values passed to alloc */
    status = SHA256_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)pShaCtx);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = SHA256_allocDigest(MOC_HASH(gpHwAccelCtx) NULL);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    /* NULL values to init */
    status = SHA256_initDigest(MOC_HASH(gpHwAccelCtx) pShaCtx);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = SHA256_initDigest(MOC_HASH(gpHwAccelCtx) NULL);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    /* NULL for context to update calls */
    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) NULL, NULL, 0);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) NULL, pMsg, 0);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) NULL, NULL, msgLen);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) NULL, pMsg, msgLen);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }


    status = SHA256_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* Uninitialized context used for update */
    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, NULL, 0);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, NULL, msgLen);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    /* No CI option currently returning OK */
    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg, 0);
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
    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg, msgLen);
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
    status = SHA256_finalDigest(MOC_HASH(gpHwAccelCtx) NULL, NULL);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = SHA256_finalDigest(MOC_HASH(gpHwAccelCtx) NULL, pDigest);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = SHA256_finalDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, NULL);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    /* No CI option currently returning OK */
    status = SHA256_finalDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pDigest);
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_MBED_SYM_OPERATORS__))
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }
#endif

    status = SHA256_completeDigest(MOC_HASH(gpHwAccelCtx) pMsg, msgLen, NULL);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    status = SHA256_completeDigest(MOC_HASH(gpHwAccelCtx) NULL, msgLen, pDigest);
    if(OK == status)
    {
        errorCount = (errorCount + 1);
        status = ERR_CMP;
        UNITTEST_STATUS(__MOC_LINE__, status);
    }

    /* 16 error cases, CI with embed returns bad status on all 16,
     * but No CI and passthrough both only return bad status' on
     * 13 cases */
exit:
    SHA256_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);

    return errorCount;
}

/*----------------------------------------------------------------------------*/

static int twoContextTest()
{
    MSTATUS status = ERR_NULL_POINTER;
    SHA256_CTX *pShaCtx = NULL;
    SHA256_CTX *pOtherShaCtx = NULL;
    ubyte pDigest[SHA256_RESULT_SIZE];
    ubyte pOtherDigest[SHA256_RESULT_SIZE];
    sbyte4 cmpRes = -1;

    ubyte *pMsg1 = NULL;
    ubyte4 msg1Len = 0;
    ubyte *pMD1 = NULL;
    ubyte4 md1Len = 0;

    msg1Len = UNITTEST_UTILS_str_to_byteStr(
        (const sbyte*)gpSha256LongTests[0].pMsg, &pMsg1);
    md1Len = UNITTEST_UTILS_str_to_byteStr(
        (const sbyte*)gpSha256LongTests[0].pMD, &pMD1);

    ubyte *pMsg2 = NULL;
    ubyte4 msg2Len = 0;
    ubyte *pMD2 = NULL;
    ubyte4 md2Len = 0;

    msg2Len = UNITTEST_UTILS_str_to_byteStr(
        (const sbyte*)gpSha256LongTests[1].pMsg, &pMsg2);
    md2Len = UNITTEST_UTILS_str_to_byteStr(
        (const sbyte*)gpSha256LongTests[1].pMD, &pMD2);

    if((SHA256_RESULT_SIZE != md1Len) || (SHA256_RESULT_SIZE != md2Len))
    {
        goto exit;
    }

    /* split points for hashing in two updates */
    ubyte4 msg1MidPoint = msg1Len/2;
    ubyte4 msg2MidPoint = msg2Len/2;

    /* first context object */
    status = SHA256_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* initialize context for hashing */
    status = SHA256_initDigest(MOC_HASH(gpHwAccelCtx) pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* second context object */
    status = SHA256_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pOtherShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* initialize context for hashing */
    status = SHA256_initDigest(MOC_HASH(gpHwAccelCtx) pOtherShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* call update with first half of msg1 (FIRST MESSAGE) */
    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg1, msg1MidPoint);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* call update with first half of msg2 (SECOND MESSAGE) */
    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pOtherShaCtx, pMsg2, msg2MidPoint);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* call update with second half of msg1 (FIRST MESSAGE) */
    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg1 + msg1MidPoint,
        msg1Len - msg1MidPoint);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* call update with second half of msg2 (SECOND MESSAGE) */
    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pOtherShaCtx, pMsg2 + msg2MidPoint,
        msg2Len - msg2MidPoint);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* get digest of FIRST MESSAGE */
    status = SHA256_finalDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* check if it the expected value */
    status = DIGI_MEMCMP(pDigest, pMD1, SHA256_RESULT_SIZE, &cmpRes);
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
    status = SHA256_finalDigest(MOC_HASH(gpHwAccelCtx) pOtherShaCtx, pOtherDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* compare digest of second context with expected value */
    status = DIGI_MEMCMP(pOtherDigest, pMD2, SHA256_RESULT_SIZE, &cmpRes);
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

    SHA256_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);
    SHA256_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pOtherShaCtx);

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
    SHA256_CTX *pShaCtx = NULL;
    ubyte pDigest[SHA256_RESULT_SIZE];
    sbyte4 cmpRes = -1;

    ubyte *pMsg1 = NULL;
    ubyte4 msg1Len = 0;
    ubyte *pMD1 = NULL;
    ubyte4 md1Len = 0;

    msg1Len = UNITTEST_UTILS_str_to_byteStr(
        (const sbyte*)gpSha256LongTests[0].pMsg, &pMsg1);
    md1Len = UNITTEST_UTILS_str_to_byteStr(
        (const sbyte*)gpSha256LongTests[0].pMD, &pMD1);

    ubyte *pMsg2 = NULL;
    ubyte4 msg2Len = 0;
    ubyte *pMD2 = NULL;
    ubyte4 md2Len = 0;

    msg2Len = UNITTEST_UTILS_str_to_byteStr(
        (const sbyte*)gpSha256LongTests[1].pMsg, &pMsg2);
    md2Len = UNITTEST_UTILS_str_to_byteStr(
        (const sbyte*)gpSha256LongTests[1].pMD, &pMD2);

    if((SHA256_RESULT_SIZE != md1Len) || (SHA256_RESULT_SIZE != md2Len))
    {
        goto exit;
    }

    /* split points for hashing in two updates */
    ubyte4 msg1MidPoint = msg1Len/2;
    ubyte4 msg2MidPoint = msg2Len/2;

    /* allocate memory for context */
    status = SHA256_allocDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* initialize context for hashing */
    status = SHA256_initDigest(MOC_HASH(gpHwAccelCtx) pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* call update with first half of msg1 (FIRST MESSAGE) */
    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg1, msg1MidPoint);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* REINITIALIZE context for new hash */
    status = SHA256_initDigest(MOC_HASH(gpHwAccelCtx) pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* call update on first half of msg2 (SECOND MESSAGE) */
    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg2, msg2MidPoint);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* call update on second half of msg2 (SECOND MESSAGE) */
    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg2 + msg2MidPoint,
        msg2Len - msg2MidPoint);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* call final to retrieve hash value for msg2 (SECOND MESSAGE) */
    status = SHA256_finalDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* compare msg2 digest with expected digest */
    status = DIGI_MEMCMP(pDigest, pMD2, SHA256_RESULT_SIZE, &cmpRes);
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
    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg1, msg1Len);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* call final to retrieve hash value (FIRST MESSAGE) */
    status = SHA256_finalDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* compare msg1 digest with expected digest */
    cmpRes = -1;
    status = DIGI_MEMCMP(pDigest, pMD1, SHA256_RESULT_SIZE, &cmpRes);
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
    status = SHA256_initDigest(MOC_HASH(gpHwAccelCtx) pShaCtx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* call final without any update calls */
    status = SHA256_finalDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* call update after final call with msg2 (SECOND MESSAGE) */
    status = SHA256_updateDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pMsg2, msg2Len);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    /* call final after update to compute digest */
    status = SHA256_finalDigest(MOC_HASH(gpHwAccelCtx) pShaCtx, pDigest);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;


    /* compare this digest with expected digest. */
    status = DIGI_MEMCMP(pDigest, pMD2, SHA256_RESULT_SIZE, &cmpRes);
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

    SHA256_freeDigest(MOC_HASH(gpHwAccelCtx) (BulkCtx*)&pShaCtx);

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

int crypto_interface_sha256_test_init()
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
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_SHA256__))
    errorCount = (errorCount + testCryptoInterface());
#endif

    /* TESTS GO HERE */
    errorCount = (errorCount + runTests());
    errorCount = (errorCount + negativeTests());
    errorCount = (errorCount + testMultipleHashes());
    errorCount = (errorCount + twoContextTest());

exit:
    
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &gpHwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif
    
    DIGICERT_free(&gpMocCtx);
    return errorCount;
}

