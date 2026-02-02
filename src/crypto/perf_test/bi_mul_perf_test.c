/*
 * bi_mul_perf_test.c
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

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../crypto/primefld.h"
#include "../../crypto/primefld_priv.h"

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/times.h>
#include <unistd.h>
#include <signal.h>

#ifdef __ENABLE_PERF_TEST_OPENSSL__
#include <openssl/bn.h>
#endif

#ifdef __ENABLE_PERF_TEST_MBEDTLS__
#include <mbedtls/bignum.h>
#endif

static volatile int mContinueTest;

#ifndef TEST_SECONDS
#define TEST_SECONDS (1)
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

static int doTest(ubyte4 intSize)
{
    MSTATUS status;
    int retVal = 0;
    ubyte4 i;

    ubyte *pABin = NULL;
    ubyte *pBBin = NULL;
    ubyte *pResBin = NULL;
    
#ifdef __ENABLE_PERF_TEST_OPENSSL__
    BN_CTX *ctx = BN_CTX_new();

    BIGNUM *r = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
#endif

#ifdef __ENABLE_PERF_TEST_MBEDTLS__

    mbedtls_mpi mbr;
    mbedtls_mpi mba;
    mbedtls_mpi mbb;

#endif

    struct tms tstart, tend;
    double diffTime;
    ubyte4 counter = 0;

    pf_unit *pA;
    pf_unit *pB;
    pf_unit *pRes;

    ubyte4 wordSize = intSize/sizeof(pf_unit);
    ubyte4 resSize = 2*wordSize;

    printf("Testing Multiplication of two %d byte integers.\n", intSize);

    /* Malloc pABin, pBin, pResult so they are on the heap (as will be openssl and mbed integers) */
    status = DIGI_MALLOC((void **) &pABin, intSize);
    if (OK != status)
        goto exit;
    
    status = DIGI_MALLOC((void **) &pBBin, intSize);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pResBin, 2*intSize);
    if (OK != status)
        goto exit;
    
    pA = (pf_unit *) pABin;
    pB = (pf_unit *) pBBin;
    pRes = (pf_unit *) pResBin;
    
    /* make what looks to be random big integers */
    for (i = 0; i < intSize; i++)
    {
        pABin[i] = (ubyte) ((i + 1) * 47);
        pABin[i] = (ubyte) ((i + 1) * 79);
    }
    
#ifdef __ENABLE_PERF_TEST_OPENSSL__
    BN_bin2bn(pABin, intSize, a);
    BN_bin2bn(pBBin, intSize, b);

    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
        BN_mul(r, a, b, ctx);
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    
    printf("SSL Result:\n\t%d Multiplies done in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g multiplies/second (CPU time)\n\n", counter/diffTime);

    BN_free(r);
    BN_free(a);
    BN_free(b);
#endif

#ifdef __ENABLE_PERF_TEST_MBEDTLS__
    counter = 0;

    mbedtls_mpi_init(&mbr);
    mbedtls_mpi_init(&mba);
    mbedtls_mpi_init(&mbb);

    mbedtls_mpi_read_binary(&mba, pABin, intSize);
    mbedtls_mpi_read_binary(&mbb, pBBin, intSize);

    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
        mbedtls_mpi_mul_mpi(&mbr, &mba, &mbb);
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    
    printf("MBED Result:\n\t%d Multiplies done in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g multiplies/second (CPU time)\n\n", counter/diffTime);

    mbedtls_mpi_free(&mbr);
    mbedtls_mpi_free(&mba);
    mbedtls_mpi_free(&mbb);
#endif

    counter = 0;

    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
        BI_mul(wordSize, pRes, pA, pB, resSize);
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    
    printf("OUR Result:\n\t%d Multiplies done in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g multiplies/second (CPU time)\n\n", counter/diffTime);

exit:
    
    if (pABin)
        DIGI_FREE((void **) &pABin);
    
    if (pBBin)
        DIGI_FREE((void **) &pBBin);
    
    if (pResBin)
        DIGI_FREE((void **) &pResBin);
    
    /* no cleanup needed for our test */
    return retVal;
}


int bi_mul_perf_test_all()
{
    int retVal = 0;

    retVal += doTest(16);
    retVal += doTest(32);
    retVal += doTest(64);
    retVal += doTest(128);
    retVal += doTest(256);

    return retVal;
}
