/*
 * qs_kem_perf_test.c
 *
 * performance test for quantum safe key exchange mechanisms
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

/* ans1 redefine in parseasn1.h doesn't work, redefine here */
#ifdef __ENABLE_PERF_TEST_OPENSSL__
#define ASN1_ITEM MOC_ASN1_ITEM
#endif

#include "../../common/initmocana.h"
#include "../../common/random.h"
#include "../../crypto/mocasym.h"
#include "../../crypto_interface/crypto_interface_qs.h"
#include "../../crypto_interface/crypto_interface_qs_kem.h"

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

#ifdef __ENABLE_DIGICERT_PQC__
static int perfTestKem(ubyte4 id, char * pTestName)
{
    MSTATUS status;
    
    QS_CTX *pCtx = NULL;
    ubyte *pCipher = NULL;
    ubyte4 cipherLen;
    ubyte *pSS = NULL;
    ubyte4 ssLen = 0;
    ubyte *pSS2 = NULL;
    ubyte4 pubLen;
    sbyte4 compare = 0;
    
    struct tms tstart, tend;
    double diffTime;
    ubyte4 counter = 0;
    
    status = CRYPTO_INTERFACE_QS_newCtx(&pCtx, id);
    if (OK != status)
        goto exit;

    printf("*******  TESTING %s *******\n\n", pTestName);
    
    status = CRYPTO_INTERFACE_QS_getPublicKeyLen(pCtx, &pubLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_KEM_getCipherTextLen(pCtx, &cipherLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_KEM_getSharedSecretLen(pCtx, &ssLen);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pCipher, cipherLen);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pSS, ssLen);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pSS2, ssLen);
    if (OK != status)
        goto exit;

    printf("public key len = %d, ciphertext len = %d, shared secret len = %d\n", pubLen, cipherLen, ssLen);
    
     /* Test Generate Key */
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        (void) CRYPTO_INTERFACE_QS_deleteCtx(&pCtx);
        (void) CRYPTO_INTERFACE_QS_newCtx(&pCtx, id);
        (void) CRYPTO_INTERFACE_QS_generateKeyPair(pCtx, RANDOM_rngFun, g_pRandomContext);
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    
    printf("key generation...\n");

    printf("Result:\n\t%d test keys in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g keys generated/second\n", counter/diffTime);
    
    /* Test Encapsulate */
    counter = 0;
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
        (void) CRYPTO_INTERFACE_QS_KEM_encapsulate(pCtx, RANDOM_rngFun, g_pRandomContext, pCipher, cipherLen, pSS, ssLen);
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    
    printf("encapsulate...\n");
    
    printf("Result:\n\t%d test encapsulations in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g encaps/second\n", counter/diffTime);

    /* Test Decapsulate, reset counter */
    counter = 0;
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
        (void) CRYPTO_INTERFACE_QS_KEM_decapsulate(pCtx, pCipher, cipherLen, pSS2, ssLen);
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);

    printf("decapsulate...\n");
    
    printf("Result:\n\t%d test decapsulations in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g decaps/second\n\n", counter/diffTime);

    /* sanity check they are the same shared secret */
    (void) DIGI_MEMCMP(pSS, pSS2, ssLen, &compare);

exit:

    if (NULL != pCtx)
    {
        (void) CRYPTO_INTERFACE_QS_deleteCtx(&pCtx);
    }

    if (NULL != pCipher)
    {
        (void) DIGI_FREE((void **) &pCipher);
    }

    if (NULL != pSS)
    {
        (void) DIGI_FREE((void **) &pSS);
    }

    if (NULL != pSS2)
    {
        (void) DIGI_FREE((void **) &pSS2);
    }
    
    if (OK != status)
    {
        printf("TEST FAILURE, status = %d\n\n", status);
        return 1;
    }

    if (0 != compare)
    {
        printf("TEST FAILURE, compare = %d\n\n", compare);
        return 1;
    }

    return 0;
}
#endif 

int qs_kem_perf_test_all()
{
    int retVal = 0;
#ifdef __ENABLE_DIGICERT_PQC__
    MSTATUS status;
    
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

    printf("\n");

    /* OQS test will be of kyber, not mlkem */
    retVal += perfTestKem(cid_PQC_MLKEM_512, "cid_PQC_MLKEM_512");
    retVal += perfTestKem(cid_PQC_MLKEM_768, "cid_PQC_MLKEM_768");
    retVal += perfTestKem(cid_PQC_MLKEM_1024, "cid_PQC_MLKEM_1024");

exit:
    
    DIGICERT_free(&gpMocCtx);
#endif
    return retVal;
}
