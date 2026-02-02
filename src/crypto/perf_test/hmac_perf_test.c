/*
 * hmac_perf_test.c
 *
 * performance test for sha1.c, sha256.c and sha512.c
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

#if !defined( __RTOS_LINUX__) && !defined( __RTOS_OSX__) && !defined(__RTOS_CYGWIN__) && !defined(__RTOS_IRIX__) && !defined (__RTOS_SOLARIS__) && !defined (__RTOS_OPENBSD__)
#error Timing Performance test only for linux, darwin, cygwin, irix, solaris, openbsd
#endif

#include "../../common/initmocana.h"
#include "../../crypto/mocasym.h"

#include "../../crypto/crypto.h"
#include "../../crypto/md5.h"
#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#include "../../crypto/hmac.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../../crypto_interface/crypto_interface_sha1.h"
#include "../../crypto_interface/crypto_interface_sha256.h"
#include "../../crypto_interface/crypto_interface_sha512.h"
#include "../../crypto_interface/crypto_interface_hmac.h"
#endif

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/times.h>
#include <unistd.h>
#include <signal.h>

static volatile int mContinueTest;

#ifndef TEST_SECONDS
#define TEST_SECONDS (3)
#endif

#define START_ALARM(secs) { signal(SIGALRM, stop_test); \
mContinueTest = 1;          \
alarm(secs);                }

#define ALARM_OFF         (mContinueTest)

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
const BulkHashAlgo SHA1Suite =
{
    SHA1_RESULT_SIZE, SHA1_BLOCK_SIZE, CRYPTO_INTERFACE_SHA1_allocDigest, CRYPTO_INTERFACE_SHA1_freeDigest,
    (BulkCtxInitFunc)CRYPTO_INTERFACE_SHA1_initDigest, (BulkCtxUpdateFunc)CRYPTO_INTERFACE_SHA1_updateDigest, (BulkCtxFinalFunc)CRYPTO_INTERFACE_SHA1_finalDigest, NULL, NULL, NULL, ht_sha1
};

const BulkHashAlgo SHA224Suite =
{
    SHA224_RESULT_SIZE, SHA224_BLOCK_SIZE, CRYPTO_INTERFACE_SHA256_allocDigest, CRYPTO_INTERFACE_SHA256_freeDigest,
    (BulkCtxInitFunc)CRYPTO_INTERFACE_SHA224_initDigest, (BulkCtxUpdateFunc)CRYPTO_INTERFACE_SHA256_updateDigest, (BulkCtxFinalFunc)CRYPTO_INTERFACE_SHA224_finalDigest, NULL, NULL, NULL, ht_sha224
};

const BulkHashAlgo SHA256Suite =
{
    SHA256_RESULT_SIZE, SHA256_BLOCK_SIZE, CRYPTO_INTERFACE_SHA256_allocDigest, CRYPTO_INTERFACE_SHA256_freeDigest,
    (BulkCtxInitFunc)CRYPTO_INTERFACE_SHA256_initDigest, (BulkCtxUpdateFunc)CRYPTO_INTERFACE_SHA256_updateDigest, (BulkCtxFinalFunc)CRYPTO_INTERFACE_SHA256_finalDigest, NULL, NULL, NULL, ht_sha256
};

const BulkHashAlgo SHA384Suite =
{
    SHA384_RESULT_SIZE, SHA384_BLOCK_SIZE, CRYPTO_INTERFACE_SHA512_allocDigest, CRYPTO_INTERFACE_SHA512_freeDigest,
    (BulkCtxInitFunc)CRYPTO_INTERFACE_SHA384_initDigest, (BulkCtxUpdateFunc)CRYPTO_INTERFACE_SHA512_updateDigest, (BulkCtxFinalFunc)CRYPTO_INTERFACE_SHA384_finalDigest, NULL, NULL, NULL, ht_sha384
};

const BulkHashAlgo SHA512Suite =
{
    SHA512_RESULT_SIZE, SHA512_BLOCK_SIZE, CRYPTO_INTERFACE_SHA512_allocDigest, CRYPTO_INTERFACE_SHA512_freeDigest,
    (BulkCtxInitFunc)CRYPTO_INTERFACE_SHA512_initDigest, (BulkCtxUpdateFunc)CRYPTO_INTERFACE_SHA512_updateDigest, (BulkCtxFinalFunc)CRYPTO_INTERFACE_SHA512_finalDigest, NULL, NULL, NULL, ht_sha512
};
#else
const BulkHashAlgo SHA1Suite =
{
    SHA1_RESULT_SIZE, SHA1_BLOCK_SIZE, SHA1_allocDigest, SHA1_freeDigest,
    (BulkCtxInitFunc)SHA1_initDigest, (BulkCtxUpdateFunc)SHA1_updateDigest, (BulkCtxFinalFunc)SHA1_finalDigest, NULL, NULL, NULL, ht_sha1
};

const BulkHashAlgo SHA224Suite =
{
    SHA224_RESULT_SIZE, SHA224_BLOCK_SIZE, SHA256_allocDigest, SHA256_freeDigest,
    (BulkCtxInitFunc)SHA224_initDigest, (BulkCtxUpdateFunc)SHA256_updateDigest, (BulkCtxFinalFunc)SHA224_finalDigest, NULL, NULL, NULL, ht_sha224
};

const BulkHashAlgo SHA256Suite =
{
    SHA256_RESULT_SIZE, SHA256_BLOCK_SIZE, SHA256_allocDigest, SHA256_freeDigest,
    (BulkCtxInitFunc)SHA256_initDigest, (BulkCtxUpdateFunc)SHA256_updateDigest, (BulkCtxFinalFunc)SHA256_finalDigest, NULL, NULL, NULL, ht_sha256
};

const BulkHashAlgo SHA384Suite =
{
    SHA384_RESULT_SIZE, SHA384_BLOCK_SIZE, SHA512_allocDigest, SHA512_freeDigest,
    (BulkCtxInitFunc)SHA384_initDigest, (BulkCtxUpdateFunc)SHA384_updateDigest, (BulkCtxFinalFunc)SHA384_finalDigest, NULL, NULL, NULL, ht_sha384
};

const BulkHashAlgo SHA512Suite =
{
    SHA512_RESULT_SIZE, SHA512_BLOCK_SIZE, SHA512_allocDigest, SHA512_freeDigest,
    (BulkCtxInitFunc)SHA512_initDigest, (BulkCtxUpdateFunc)SHA512_updateDigest, (BulkCtxFinalFunc)SHA512_finalDigest, NULL, NULL, NULL, ht_sha512
};
#endif

/*------------------------------------------------------------------*/
/* SIGALRM signal handler */
static void stop_test( int sig)
{
    (void) sig; /* to get rid of unused warnings */
    mContinueTest = 0;
}

/* for hmac-sha1-96 */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
static int perfTestHmacSha196(ubyte4 inLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    ubyte pResult[20];
    ubyte pKey[20] = { 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b };
    int i;

    struct tms tstart, tend;
    double diffTime, kbytes;
    ubyte4 counter = 0;

    status = DIGI_MALLOC((void **) &pMessage, inLen);
    if (OK != status)
        goto exit;

    /* set the message to some dummy data but not all zero */
    for (i = 0; i < inLen; i++)
        pMessage[i] = (ubyte) (i & 0xff);

    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while (ALARM_OFF)
    {
        CRYPTO_INTERFACE_HMAC_SHA1_96(pKey, 20, pMessage, inLen, NULL, 0, pResult);
        counter++;
        pMessage[0]++;
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING ONE SHOT HMAC-SHA1-96, input length = %d bytes\n", inLen);

    printf("Result:\n\t%d test hashes in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

exit:

    if (NULL != pMessage)
        DIGI_FREE((void **) &pMessage);

    if (OK != status)
    {
        printf("TEST FAILURE, status = %d\n", status);
        return 1;
    }

    return 0;
}
#endif

static int perfTestHmacSha1(ubyte4 inLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    ubyte pResult[20];
    ubyte pKey[20] = { 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b };
    int i;
    HMAC_CTX *pCtx = NULL;

    struct tms tstart, tend;
    double diffTime, kbytes;
    ubyte4 counter = 0;

    status = DIGI_MALLOC((void **) &pMessage, inLen);
    if (OK != status)
        goto exit;

    /* set the message to some dummy data but not all zero */
    for (i = 0; i < inLen; i++)
        pMessage[i] = (ubyte) (i & 0xff);

    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while (ALARM_OFF)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_HMAC_SHA1(pKey, 20, pMessage, inLen, NULL, 0, pResult);
#else
        HMAC_SHA1(pKey, 20, pMessage, inLen, NULL, 0, pResult);
#endif
        counter++;
        pMessage[0]++;
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING ONE SHOT HMAC-SHA1, input length = %d bytes\n", inLen);

    printf("Result:\n\t%d test hashes in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

    counter = 0;
    DIGI_MEMSET(pResult, 0x00, 20);
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_HmacCreate(&pCtx, &SHA1Suite);
#else
    HmacCreate(&pCtx, &SHA1Suite);
#endif

    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_HmacKey(pCtx, pKey, 20);
        CRYPTO_INTERFACE_HmacUpdate(pCtx, pMessage, inLen);
        CRYPTO_INTERFACE_HmacFinal(pCtx, pResult);
#else
        HmacKey(pCtx, pKey, 20);
        HmacUpdate(pCtx, pMessage, inLen);
        HmacFinal(pCtx, pResult);
#endif
        counter++;
        pMessage[0]++; /* change the message for the next test */
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING HMAC-SHA1, input length = %d bytes\n", inLen);

    printf("Result:\n\t%d test hashes in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

exit:
    if (NULL != pCtx)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_HmacDelete(&pCtx);
#else
        HmacDelete(&pCtx);
#endif

    if (NULL != pMessage)
        DIGI_FREE((void **) &pMessage);

    if (OK != status)
    {
        printf("TEST FAILURE, status = %d\n", status);
        return 1;
    }

    return 0;
}

static int perfTestHmacSha224(ubyte4 inLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    ubyte pResult[28];
    int i;
    ubyte pKey[32] = { 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b };
    HMAC_CTX *pCtx = NULL;

    struct tms tstart, tend;
    double diffTime, kbytes;
    ubyte4 counter = 0;

    status = DIGI_MALLOC((void **) &pMessage, inLen);
    if (OK != status)
        goto exit;

    /* set the message to some dummy data but not all zero */
    for (i = 0; i < inLen; i++)
        pMessage[i] = (ubyte) (i & 0xff);

    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while (ALARM_OFF)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_HmacQuick(pKey, 32, pMessage, inLen, pResult, &SHA224Suite);
#else
        HmacQuick(pKey, 32, pMessage, inLen, pResult, &SHA224Suite);
#endif
        counter++;
        pMessage[0]++;
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING ONE SHOT HMAC-SHA224, input length = %d bytes\n", inLen);

    printf("Result:\n\t%d test hashes in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

    counter = 0;
    DIGI_MEMSET(pResult, 0x00, 28);
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_HmacCreate(&pCtx, &SHA224Suite);
#else
    HmacCreate(&pCtx, &SHA224Suite);
#endif

    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_HmacKey(pCtx, pKey, 32);
        CRYPTO_INTERFACE_HmacUpdate(pCtx, pMessage, inLen);
        CRYPTO_INTERFACE_HmacFinal(pCtx, pResult);
#else
        HmacKey(pCtx, pKey, 32);
        HmacUpdate(pCtx, pMessage, inLen);
        HmacFinal(pCtx, pResult);
#endif
        counter++;
        pMessage[0]++; /* change the message for the next test */
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING HMAC-SHA224, input length = %d bytes\n", inLen);

    printf("Result:\n\t%d test hashes in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

exit:
    if (NULL != pCtx)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_HmacDelete(&pCtx);
#else
        HmacDelete(&pCtx);
#endif

    if (NULL != pMessage)
        DIGI_FREE((void **) &pMessage);

    if (OK != status)
    {
        printf("TEST FAILURE, status = %d\n", status);
        return 1;
    }

    return 0;
}

static int perfTestHmacSha256(ubyte4 inLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    ubyte pResult[32];
    int i;
    ubyte pKey[32] = { 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b };
    HMAC_CTX *pCtx = NULL;

    struct tms tstart, tend;
    double diffTime, kbytes;
    ubyte4 counter = 0;

    status = DIGI_MALLOC((void **) &pMessage, inLen);
    if (OK != status)
        goto exit;

    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while (ALARM_OFF)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_HmacQuick(pKey, 32, pMessage, inLen, pResult, &SHA256Suite);
#else
        HmacQuick(pKey, 32, pMessage, inLen, pResult, &SHA256Suite);
#endif
        counter++;
        pMessage[0]++;
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING ONE SHOT HMAC-SHA256, input length = %d bytes\n", inLen);

    printf("Result:\n\t%d test hashes in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

    counter = 0;
    DIGI_MEMSET(pResult, 0x00, 32);
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_HmacCreate(&pCtx, &SHA256Suite);
#else
    HmacCreate(&pCtx, &SHA256Suite);
#endif

    /* set the message to some dummy data but not all zero */
    for (i = 0; i < inLen; i++)
        pMessage[i] = (ubyte) (i & 0xff);

    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_HmacKey(pCtx, pKey, 32);
        CRYPTO_INTERFACE_HmacUpdate(pCtx, pMessage, inLen);
        CRYPTO_INTERFACE_HmacFinal(pCtx, pResult);
#else
        HmacKey(pCtx, pKey, 32);
        HmacUpdate(pCtx, pMessage, inLen);
        HmacFinal(pCtx, pResult);
#endif
        counter++;
        pMessage[0]++; /* change the message for the next test */
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING HMAC-SHA256, input length = %d bytes\n", inLen);

    printf("Result:\n\t%d test hashes in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

exit:
    if (NULL != pCtx)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_HmacDelete(&pCtx);
#else
        HmacDelete(&pCtx);
#endif

    if (NULL != pMessage)
        DIGI_FREE((void **) &pMessage);

    if (OK != status)
    {
        printf("TEST FAILURE, status = %d\n", status);
        return 1;
    }

    return 0;
}

static int perfTestHmacSha384(ubyte4 inLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    ubyte pResult[48];
    int i;
    ubyte pKey[32] = { 0x01,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b };
    HMAC_CTX *pCtx = NULL;

    struct tms tstart, tend;
    double diffTime, kbytes;
    ubyte4 counter = 0;

    status = DIGI_MALLOC((void **) &pMessage, inLen);
    if (OK != status)
        goto exit;

    /* set the message to some dummy data but not all zero */
    for (i = 0; i < inLen; i++)
        pMessage[i] = (ubyte) (i & 0xff);

    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_HmacQuick(pKey, 32, pMessage, inLen, pResult, &SHA384Suite);
#else
        HmacQuick(pKey, 32, pMessage, inLen, pResult, &SHA384Suite);
#endif
        counter++;
        pMessage[0]++; /* change the message for the next test */
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING ONE SHOT HMAC-SHA384, input length = %d bytes\n", inLen);

    printf("Result:\n\t%d test hashes in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

    counter = 0;
    DIGI_MEMSET(pResult, 0x00, 48);
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_HmacCreate(&pCtx, &SHA256Suite);
#else
    HmacCreate(&pCtx, &SHA256Suite);
#endif

    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_HmacKey(pCtx, pKey, 32);
        CRYPTO_INTERFACE_HmacUpdate(pCtx, pMessage, inLen);
        CRYPTO_INTERFACE_HmacFinal(pCtx, pResult);
#else
        HmacKey(pCtx, pKey, 32);
        HmacUpdate(pCtx, pMessage, inLen);
        HmacFinal(pCtx, pResult);
#endif
        counter++;
        pMessage[0]++; /* change the message for the next test */
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING HMAC-SHA384, input length = %d bytes\n", inLen);

    printf("Result:\n\t%d test hashes in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

exit:
    if (NULL != pCtx)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_HmacDelete(&pCtx);
#else
        HmacDelete(&pCtx);
#endif

    if (NULL != pMessage)
        DIGI_FREE((void **) &pMessage);

    if (OK != status)
    {
        printf("TEST FAILURE, status = %d\n", status);
        return 1;
    }

    return 0;
}

static int perfTestHmacSha512(ubyte4 inLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    ubyte pResult[64];
    int i;

    ubyte pKey[32] = { 0x01,0x02,0x03,0x04, 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b, 0x0b,0x0b,0x0b,0x0b };
    HMAC_CTX *pCtx = NULL;

    struct tms tstart, tend;
    double diffTime, kbytes;
    ubyte4 counter = 0;

    status = DIGI_MALLOC((void **) &pMessage, inLen);
    if (OK != status)
        goto exit;

    /* set the message to some dummy data but not all zero */
    for (i = 0; i < inLen; i++)
        pMessage[i] = (ubyte) (i & 0xff);

    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_HmacQuick(pKey, 32, pMessage, inLen, pResult, &SHA512Suite);
#else
        HmacQuick(pKey, 32, pMessage, inLen, pResult, &SHA512Suite);
#endif
        counter++;
        pMessage[0]++; /* change the message for the next test */
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING HMAC-SHA512, input length = %d bytes\n", inLen);

    printf("Result:\n\t%d test hashes in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

    counter = 0;
    DIGI_MEMSET(pResult, 0x00, 64);
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_HmacCreate(&pCtx, &SHA256Suite);
#else
    HmacCreate(&pCtx, &SHA256Suite);
#endif

    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_HmacKey(pCtx, pKey, 32);
        CRYPTO_INTERFACE_HmacUpdate(pCtx, pMessage, inLen);
        CRYPTO_INTERFACE_HmacFinal(pCtx, pResult);
#else
        HmacKey(pCtx, pKey, 32);
        HmacUpdate(pCtx, pMessage, inLen);
        HmacFinal(pCtx, pResult);
#endif
        counter++;
        pMessage[0]++; /* change the message for the next test */
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING HMAC-SHA512, input length = %d bytes\n", inLen);

    printf("Result:\n\t%d test hashes in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

exit:
    if (NULL != pCtx)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_HmacDelete(&pCtx);
#else
        HmacDelete(&pCtx);
#endif

    if (NULL != pMessage)
        DIGI_FREE((void **) &pMessage);

    if (OK != status)
    {
        printf("TEST FAILURE, status = %d\n", status);
        return 1;
    }

    return 0;
}

int hmac_perf_test_all()
{
    int retVal = 0;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    /* hmac-sha1-96 */
    retVal += perfTestHmacSha196(64);
    retVal += perfTestHmacSha196(16384);
#endif

    /* A single blocksize of input */
    retVal += perfTestHmacSha1(64);
    retVal += perfTestHmacSha1(16384);

    retVal += perfTestHmacSha224(64);
    retVal += perfTestHmacSha224(16384);

    retVal += perfTestHmacSha256(64);
    retVal += perfTestHmacSha256(16384);

    retVal += perfTestHmacSha384(128);
    retVal += perfTestHmacSha384(16384);

    retVal += perfTestHmacSha512(128);
    retVal += perfTestHmacSha512(16384);

    return retVal;
}
