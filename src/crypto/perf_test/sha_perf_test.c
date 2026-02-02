/*
 * sha_perf_test.c
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

#include "../../crypto/sha1.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"

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

/*------------------------------------------------------------------*/
/* SIGALRM signal handler */
static void stop_test( int sig)
{
    (void) sig; /* to get rid of unused warnings */
    mContinueTest = 0;
}

static int perfTestSha1(ubyte4 inLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    ubyte pResult[20];
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
        SHA1_completeDigest(pMessage, inLen, pResult);
        counter++;
        pMessage[0]++; /* change the message for the next test */
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING SHA1, input length = %d bytes\n", inLen);
    
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

static int perfTestSha224(ubyte4 inLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    ubyte pResult[28];
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
        SHA224_completeDigest(pMessage, inLen, pResult);
        counter++;
        pMessage[0]++; /* change the message for the next test */
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING SHA224, input length = %d bytes\n", inLen);
    
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

static int perfTestSha256(ubyte4 inLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    ubyte pResult[32];
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
        SHA256_completeDigest(pMessage, inLen, pResult);
        counter++;
        pMessage[0]++; /* change the message for the next test */
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING SHA256, input length = %d bytes\n", inLen);
    
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

static int perfTestSha384(ubyte4 inLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    ubyte pResult[48];
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
        SHA384_completeDigest(pMessage, inLen, pResult);
        counter++;
        pMessage[0]++; /* change the message for the next test */
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING SHA384, input length = %d bytes\n", inLen);
    
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

static int perfTestSha512(ubyte4 inLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    ubyte pResult[64];
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
        SHA512_completeDigest(pMessage, inLen, pResult);
        counter++;
        pMessage[0]++; /* change the message for the next test */
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING SHA512, input length = %d bytes\n", inLen);
    
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

int sha_perf_test_all()
{
    int retVal = 0;
    
    /* A single blocksize of input */
    retVal += perfTestSha1(64);
    retVal += perfTestSha1(16384);
    
    retVal += perfTestSha224(64);
    retVal += perfTestSha224(16384);
    
    retVal += perfTestSha256(64);
    retVal += perfTestSha256(16384);
    
    retVal += perfTestSha384(128);
    retVal += perfTestSha384(16384);
    
    retVal += perfTestSha512(128);
    retVal += perfTestSha512(16384);
    
    return retVal;
}
