/*
 * random_test.c
 *
 *
 * unit test for random.c
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 */

#include "../random.c"

#include "../../../unit_tests/unittest.h"

#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_SOLARIS__) || defined(__RTOS_OSX__)
#include <stdio.h>
#include <sys/types.h>
#include <sys/times.h>
#include <unistd.h>
#include <signal.h>
#elif defined (__RTOS_WIN32__)
#include <stdio.h>
#endif


/*------------------------------------------------------------------*/
#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_SOLARIS__) || defined(__RTOS_OSX__)

static int mContinueTest;

#ifndef TEST_SECONDS
#define TEST_SECONDS (10)
#endif

#define START_ALARM(secs) { signal(SIGALRM, stop_test); \
                             mContinueTest = 1;          \
                             alarm(secs);                }

#define ALARM_OFF         (mContinueTest)

/*------------------------------------------------------------------*/
/* SIGALRM signal handler */
static void stop_test( int sig)
{
    sig; /* to get rid of unused warnings */
    mContinueTest = 0;
}

#endif   /* defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__)    */


/*---------------------------------------------------------------------------*/

int random_test_perf_start()
{
    int retVal = 0;

    /* performance test on linux machines and other Unix machines */
#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_SOLARIS__) || defined(__RTOS_OSX__)
    randomContext* pRandomContext = NULL;
    MSTATUS status;
    
    /* Since the default is now MODE_DRBG_CTR, the alarm time is increased to 30 */
    START_ALARM(30);
    
    status = RANDOM_acquireContext( &pRandomContext);

    /* the function should complete in less than 10 seconds */
    retVal += UNITTEST_TRUE( 0, ALARM_OFF);
    retVal += UNITTEST_STATUS(0, status);

    RANDOM_releaseContext( &pRandomContext);
#endif

    return retVal;
}

int random_test_perf_start_fips186()
{
    int retVal = 0;

    /* performance test on linux machines and other Unix machines */
#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_SOLARIS__) || defined(__RTOS_OSX__)
    randomContext* pRandomContext = NULL;
    MSTATUS status;
    
    START_ALARM(TEST_SECONDS);
    
    status = RANDOM_acquireContextEx( &pRandomContext, MODE_RNG_FIPS186);

    /* the function should complete in less than 10 seconds */
    retVal += UNITTEST_TRUE( 0, ALARM_OFF);
    retVal += UNITTEST_STATUS(0, status);

    RANDOM_releaseContext( &pRandomContext);
#endif

    return retVal;
}

int random_test_perf_start_any()
{
    int retVal = 0;

    /* performance test on linux machines and other Unix machines */
#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_SOLARIS__) || defined(__RTOS_OSX__)
    randomContext* pRandomContext = NULL;
    MSTATUS status;
    
    /* Since the default is now MODE_DRBG_CTR, the alarm time is increased to 30 */
    START_ALARM(30);
    
    status = RANDOM_acquireContextEx( &pRandomContext, MODE_RNG_ANY);

    /* the function should complete in less than 10 seconds */
    retVal += UNITTEST_TRUE( 0, ALARM_OFF);
    retVal += UNITTEST_STATUS(0, status);

    RANDOM_releaseContext( &pRandomContext);
#endif

    return retVal;
}

#if 0
int random_test_perf_start_ecc()
{
    int retVal = 0;

#if (defined(__ENABLE_DIGICERT_RNG_DRBG_ECC__))
    /* performance test on linux machines and other Unix machines */
#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_SOLARIS__) || defined(__RTOS_OSX__)
    randomContext* pRandomContext = NULL;
    MSTATUS status;
    
    START_ALARM(30);
    
    status = RANDOM_acquireContextEx( &pRandomContext, MODE_DRBG_ECC);

    /* the function should complete in less than 10 seconds */
    retVal += UNITTEST_TRUE( 0, ALARM_OFF);
    retVal += UNITTEST_STATUS(0, status);

    RANDOM_releaseContext( &pRandomContext);
#endif
#endif
    return retVal;
}
#endif

int random_test_perf_start_ctr()
{
    int retVal = 0;
	
#if (defined(__ENABLE_DIGICERT_RNG_DRBG_CTR__))
    /* performance test on linux machines and other Unix machines */
#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_SOLARIS__) || defined(__RTOS_OSX__)
    randomContext* pRandomContext = NULL;
    MSTATUS status;
    
    START_ALARM(30);
    
    status = RANDOM_acquireContextEx( &pRandomContext, MODE_DRBG_CTR);

    /* the function should complete in less than 10 seconds */
    retVal += UNITTEST_TRUE( 0, ALARM_OFF);
    retVal += UNITTEST_STATUS(0, status);

    RANDOM_releaseContext( &pRandomContext);
#endif
#endif
    return retVal;
}

