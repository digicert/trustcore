/*
 * ecdh_perf_test.c
 *
 * performance test for ecdh
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
#include "../../crypto/ecc.h"
#include "../../crypto/ca_mgmt.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../../crypto_interface/crypto_interface_ecc.h"
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

#ifdef __ENABLE_DIGICERT_ECC__
static int perfTestECDH(ubyte4 curveId, char * pCurveName)
{
    MSTATUS status;
    
    ECCKey *pKey = NULL;
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
    
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_generateKeyPairAllocAux(curveId, &pKey, RANDOM_rngFun, (void *) pRandomContext);
#else
    status = EC_generateKeyPairAlloc(curveId, &pKey, RANDOM_rngFun, (void *) pRandomContext);
#endif
    if (OK != status)
        goto exit;
    
    /* We will use our own public key */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAllocAux(pKey, &pPub, &pubLen);
#else
    status = EC_writePublicKeyToBufferAlloc(pKey, &pPub, &pubLen);
#endif
    if (OK != status)
        goto exit;
    
    /* Test Compute SS */
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteStringAux (pKey, pPub, pubLen, &pSS, &ssLen, 1, NULL);
#else
        ECDH_generateSharedSecretFromPublicByteString (pKey, pPub, pubLen, &pSS, &ssLen, 1, NULL);
#endif
        DIGI_FREE((void **) &pSS);
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    
    printf("TESTING ECDH, %s\n", pCurveName);
    
    printf("Result:\n\t%d test secrets in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g secrets/second\n", counter/diffTime);

exit:

    if (NULL != pSS)
        DIGI_FREE((void **) &pSS);

    if (NULL != pPub)
        DIGI_FREE((void **) &pPub);
    
    if (NULL != pKey)
        EC_deleteKeyEx(&pKey);
    
    if (NULL != pRandomContext)
        RANDOM_releaseContext(&pRandomContext);
    
    if (OK != status)
    {
        printf("TEST FAILURE, status = %d\n", status);
        return 1;
    }

    return 0;
}
#endif /* __ENABLE_DIGICERT_ECC__ */

int ecdh_perf_test_all()
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
    
#ifdef __ENABLE_DIGICERT_ECC_P192__
    retVal += perfTestECDH(cid_EC_P192, "P192");
#endif
#ifndef __DISABLE_DIGICERT_ECC_P224__
    retVal += perfTestECDH(cid_EC_P224, "P224");
#endif
#ifndef __DISABLE_DIGICERT_ECC_P256__
    retVal += perfTestECDH(cid_EC_P256, "P256");
#endif
#ifndef __DISABLE_DIGICERT_ECC_P384__
    retVal += perfTestECDH(cid_EC_P384, "P384");
#endif
#ifndef __DISABLE_DIGICERT_ECC_P521__
    retVal += perfTestECDH(cid_EC_P521, "P521");
#endif

exit:
    
    DIGICERT_free(&gpMocCtx);
    
    return retVal;
}
