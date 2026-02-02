/*
 * dh_perf_test.c
 *
 * performance test for ffdh
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
#include "../../common/random.h"
#include "../../crypto/mocasym.h"
#include "../../crypto/dh.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../../crypto_interface/crypto_interface_dh.h"
#endif

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

static MocCtx gpMocCtx = NULL;

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

static int perfTestDH(ubyte4 groupNum, char * groupName)
{
    MSTATUS status;
    
    diffieHellmanContext *pKey = NULL;
    ubyte *pPub = NULL;
    ubyte4 pubLen = 0;
    ubyte *pSS = NULL;
    ubyte4 ssLen = 0;
    
    randomContext *pRandomContext = NULL;
    
    struct tms tstart, tend;
    double diffTime;
    ubyte4 counter = 0;
    
    status = RANDOM_acquireContext(&pRandomContext);
    if (OK != status)
        goto exit;
    
    /* Test allocate Server (including key gen) */
    
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DH_allocateServer(pRandomContext, &pKey, groupNum);
        CRYPTO_INTERFACE_DH_freeDhContext(&pKey, NULL);
#else
        DH_allocateServer(pRandomContext, &pKey, groupNum);
        DH_freeDhContext(&pKey, NULL);
#endif
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    
    printf("TESTING DH Allocate Server, %s\n", groupName);
    
    printf("Result:\n\t%d tests in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g tests/second\n", counter/diffTime);
    
    /* Allocate again for further tests */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DH_allocateServer(pRandomContext, &pKey, groupNum);
#else
    status = DH_allocateServer(pRandomContext, &pKey, groupNum);
#endif
    if (OK != status)
        goto exit;
    
    /* We will use our own public key */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DH_getPublicKey(pKey, &pPub, &pubLen);
#else
    status = DH_getPublicKey(pKey, &pPub, &pubLen);
#endif
    if (OK != status)
        goto exit;
    
    /* Test SS no blinding */
    counter = 0;
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DH_computeKeyExchangeEx(pKey, NULL, pPub, pubLen, &pSS, &ssLen);
#else
        DH_computeKeyExchangeEx(pKey, NULL, pPub, pubLen, &pSS, &ssLen);
#endif
        DIGI_FREE((void **) &pSS);
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    
    printf("TESTING DH compute Shared Secret, %s, without blinding\n", groupName);
    
    printf("Result:\n\t%d test secrets in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g secrets/second\n", counter/diffTime);

    /* Test SS with blinding */
    counter = 0;
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DH_computeKeyExchangeEx(pKey, pRandomContext, pPub, pubLen, &pSS, &ssLen);
#else
        DH_computeKeyExchangeEx(pKey, pRandomContext, pPub, pubLen, &pSS, &ssLen);
#endif
        DIGI_FREE((void **) &pSS);
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    
    printf("TESTING DH compute Shared Secret, %s, with blinding\n", groupName);
    
    printf("Result:\n\t%d test secrets in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g secrets/second\n", counter/diffTime);
    
exit:

    if (NULL != pSS)
        DIGI_FREE((void **) &pSS);
    
    if (NULL != pPub)
        DIGI_FREE((void **) &pPub);
    
    if (NULL != pKey)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DH_freeDhContext(&pKey, NULL);
#else
        DH_freeDhContext(&pKey, NULL);
#endif
    
    if (NULL != pRandomContext)
        RANDOM_releaseContext(&pRandomContext);
    
    if (OK != status)
    {
        printf("TEST FAILURE, status = %d\n", status);
        return 1;
    }

    return 0;
}

int dh_perf_test_all()
{
    MSTATUS status;
    int retVal = 0;
    
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
    
    retVal += perfTestDH(DH_GROUP_1, "DH_GROUP_1");
    retVal += perfTestDH(DH_GROUP_2, "DH_GROUP_2");
    retVal += perfTestDH(DH_GROUP_5, "DH_GROUP_5");
    retVal += perfTestDH(DH_GROUP_14, "DH_GROUP_14");
    retVal += perfTestDH(DH_GROUP_15, "DH_GROUP_15");
    retVal += perfTestDH(DH_GROUP_16, "DH_GROUP_16");
    retVal += perfTestDH(DH_GROUP_17, "DH_GROUP_17");
    retVal += perfTestDH(DH_GROUP_18, "DH_GROUP_18");
    retVal += perfTestDH(DH_GROUP_24, "DH_GROUP_24");
    
    retVal += perfTestDH(DH_GROUP_FFDHE2048, "DH_GROUP_FFDHE2048");
    retVal += perfTestDH(DH_GROUP_FFDHE3072, "DH_GROUP_FFDHE3072");
    retVal += perfTestDH(DH_GROUP_FFDHE4096, "DH_GROUP_FFDHE4096");
    retVal += perfTestDH(DH_GROUP_FFDHE6144, "DH_GROUP_FFDHE6144");
    retVal += perfTestDH(DH_GROUP_FFDHE8192, "DH_GROUP_FFDHE8192");

exit:
    
    DIGICERT_free(&gpMocCtx);
    
    return retVal;
}
