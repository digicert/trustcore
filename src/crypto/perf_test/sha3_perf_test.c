/*
 * sha3_perf_test.c
 *
 * performance test for sha3.c
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

#ifdef __ENABLE_DIGICERT_SHA3__

#include "../../crypto/sha3.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/times.h>
#include <unistd.h>
#include <signal.h>

static const char *gModes[6] =
{
    "MOCANA_SHA3_MODE_SHA3_224",
    "MOCANA_SHA3_MODE_SHA3_256",
    "MOCANA_SHA3_MODE_SHA3_384",
    "MOCANA_SHA3_MODE_SHA3_512",
    "MOCANA_SHA3_MODE_SHAKE128",
    "MOCANA_SHA3_MODE_SHAKE256"
};

static volatile int mContinueTest;

#ifndef TEST_SECONDS
#define TEST_SECONDS (3)
#endif

#define START_ALARM(secs) { signal(SIGALRM, stop_test); \
mContinueTest = 1;          \
alarm(secs);                }

#define ALARM_OFF         (mContinueTest)

/*------------------------------------------------------------------*/
/* SIGALRM signal handler */
static void stop_test( int sig)
{
    (void) sig; /* to get rid of unused warnings */
    mContinueTest = 0;
}

static int perfTestHash(ubyte4 mode, ubyte4 inLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    ubyte pResult[64]; /* big enough for all 4 hash modes */
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
    while( ALARM_OFF)
    {
        SHA3_completeDigest(mode, pMessage, inLen, pResult, 0); /* ignore status */
        counter++;
        pMessage[0]++; /* change the message for the next test */
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING %s, input length = %d bytes\n", gModes[mode], inLen);

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

static int perfTestShake(ubyte4 mode, ubyte4 inLen, ubyte4 outLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    ubyte *pResult = NULL;
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

    status = DIGI_MALLOC((void **) &pResult, outLen);
    if (OK != status)
        goto exit;

    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        SHA3_completeDigest(mode, pMessage, inLen, pResult, outLen); /* ignore status */
        counter++;
        pMessage[0]++; /* change the message for the next test */
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);

    printf("TESTING %s, input length = %d bytes, output length = %d bytes\n", gModes[mode], inLen, outLen);

    printf("Result:\n\t%d test shakes in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

exit:

    if (NULL != pResult)
        DIGI_FREE((void **) &pResult);

    if (NULL != pMessage)
        DIGI_FREE((void **) &pMessage);

    if (OK != status)
    {
        printf("TEST FAILURE, status = %d\n", status);
        return 1;
    }

    return 0;
}

#ifdef __ENABLE_DIGICERT_OQS_OPERATORS__
#include "../../src/crypto/mocasymkeys/oqs/liboqs/sha3.h"

static int perfOQSSHA3(ubyte4 inLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    ubyte pResult[64]; /* big enough for all 4 hash modes */
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
    while( ALARM_OFF)
    {
        OQS_SHA3_sha3_512(pResult, pMessage, inLen);
        counter++;
        pMessage[0]++; /* change the message for the next test */
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING %s, input length = %d bytes\n", "liboqs SHA3_512", inLen);

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

static int perfOQSShake(ubyte4 inLen, ubyte4 outLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    ubyte *pResult = NULL;
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

    status = DIGI_MALLOC((void **) &pResult, outLen);
    if (OK != status)
        goto exit;

    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        OQS_SHA3_shake256(pResult, outLen, pMessage, inLen);
        counter++;
        pMessage[0]++; /* change the message for the next test */
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);

    printf("TESTING %s, input length = %d bytes, output length = %d bytes\n", "liboqs SHAKE256", inLen, outLen);

    printf("Result:\n\t%d test shakes in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

exit:

    if (NULL != pResult)
        DIGI_FREE((void **) &pResult);

    if (NULL != pMessage)
        DIGI_FREE((void **) &pMessage);

    if (OK != status)
    {
        printf("TEST FAILURE, status = %d\n", status);
        return 1;
    }

    return 0;
}

#else
static int perfOQSSHA3(ubyte4 inLen)
{
    return 0;
}

static int perfOQSShake(ubyte4 inLen, ubyte4 outLen)
{
    return 0;
}
#endif /* __ENABLE_DIGICERT_OQS_OPERATORS__ */

#endif /* __ENABLE_DIGICERT_SHA3__ */


int sha3_perf_test_all()
{
    int retVal = 0;
#ifdef __ENABLE_DIGICERT_SHA3__

    /* A single blocksize of input */
    retVal += perfTestHash(MOCANA_SHA3_MODE_SHA3_224, 144);
    retVal += perfTestHash(MOCANA_SHA3_MODE_SHA3_224, 16384);

    retVal += perfTestHash(MOCANA_SHA3_MODE_SHA3_256, 136);
    retVal += perfTestHash(MOCANA_SHA3_MODE_SHA3_256, 16384);

    retVal += perfTestHash(MOCANA_SHA3_MODE_SHA3_384, 104);
    retVal += perfTestHash(MOCANA_SHA3_MODE_SHA3_384, 16384);

    retVal += perfTestHash(MOCANA_SHA3_MODE_SHA3_512, 72);
    retVal += perfTestHash(MOCANA_SHA3_MODE_SHA3_512, 16384);

    retVal += perfTestShake(MOCANA_SHA3_MODE_SHAKE128, 168, 128);
    retVal += perfTestShake(MOCANA_SHA3_MODE_SHAKE128, 16384, 128);
    retVal += perfTestShake(MOCANA_SHA3_MODE_SHAKE128, 168, 16384);
    retVal += perfTestShake(MOCANA_SHA3_MODE_SHAKE128, 16384, 16384);

    retVal += perfTestShake(MOCANA_SHA3_MODE_SHAKE256, 136, 128);
    retVal += perfTestShake(MOCANA_SHA3_MODE_SHAKE256, 16384, 128);
    retVal += perfTestShake(MOCANA_SHA3_MODE_SHAKE256, 136, 16384);
    retVal += perfTestShake(MOCANA_SHA3_MODE_SHAKE256, 16384, 16384);

    retVal += perfOQSSHA3(72);
    retVal += perfOQSSHA3(16384);

    retVal += perfOQSShake(136, 128);
    retVal += perfOQSShake(16384, 128);
    retVal += perfOQSShake(136, 16384);
    retVal += perfOQSShake(16384, 16384);

#else
    printf("\tSHA3: DISABLED, NO TESTS RUN\n");
#endif /* __ENABLE_DIGICERT_SHA3__ */

    return retVal;
}
