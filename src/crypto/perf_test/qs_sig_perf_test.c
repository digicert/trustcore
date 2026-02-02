/*
 * qs_sig_perf_test.c
 *
 * performance test for quantum safe signature algorithms
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
#include "../../crypto_interface/crypto_interface_qs_sig.h"

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

static int perfTestSig(ubyte4 id, char * pTestName)
{
    MSTATUS status;
    
    QS_CTX *pCtx = NULL;
    ubyte pDigest[64]; /* big enough for mainstream hash algs */
    ubyte4 digestLen = 64;
    ubyte *pSig = NULL;
    ubyte4 sigLen;
    ubyte4 actSigLen;
    ubyte4 pubLen;
    ubyte4 vStatus = 0;
        
    int i;
    
    struct tms tstart, tend;
    double diffTime;
    ubyte4 counter = 0;
    
    /* set the message to some dummy data but not all zero */
    for (i = 0; i < digestLen; i++)
        pDigest[i] = (ubyte) (i & 0xff);
    
    status = CRYPTO_INTERFACE_QS_newCtx(&pCtx, id);
    if (OK != status)
        goto exit;

    printf("*******  TESTING %s *******\n\n", pTestName);
    
    status = CRYPTO_INTERFACE_QS_getPublicKeyLen(pCtx, &pubLen);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_SIG_getSignatureLen(pCtx, &sigLen);
    if (OK != status)
        goto exit;

    status = DIGI_MALLOC((void **) &pSig, sigLen);
    if (OK != status)
        goto exit;

    printf("public key len = %d, signature (max) len = %d\n", pubLen, sigLen);
    
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
    
    /* Test Sign */
    counter = 0;
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
        (void) CRYPTO_INTERFACE_QS_SIG_sign(pCtx, RANDOM_rngFun, g_pRandomContext, pDigest, digestLen, pSig, sigLen, &actSigLen);
        counter++;
        pDigest[0]++;  /* change message for next iteration */
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    
    printf("signing, digest length = %d bytes\n", digestLen);
    
    printf("Result:\n\t%d test signatures in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g signatures/second\n", counter/diffTime);

    /* Test Verify, we'll just test the last signature which should verify as valid, reset digest and counter */
    pDigest[0]--;
    counter = 0;
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
        (void) CRYPTO_INTERFACE_QS_SIG_verify(pCtx, pDigest, digestLen, pSig, actSigLen, &vStatus);
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    
    printf("verify, digest length = %d bytes\n", digestLen);
    
    printf("Result:\n\t%d test verifies in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g verifies/second\n\n", counter/diffTime);

exit:

    if (NULL != pCtx)
    {
        (void) CRYPTO_INTERFACE_QS_deleteCtx(&pCtx);
    }

    if (NULL != pSig)
    {
        (void) DIGI_FREE((void **) &pSig);
    }
    
    if (OK != status)
    {
        printf("TEST FAILURE, status = %d\n\n", status);
        return 1;
    }

    if (0 != vStatus)
    {
        printf("TEST FAILURE, vStatus = %d\n\n", vStatus);
        return 1;
    }

    return 0;
}
#endif /* __ENABLE_DIGICERT_PQC__ */

int qs_sig_perf_test_all()
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
    
    /* OQS test will be of dilithium, not mldsa */
    retVal += perfTestSig(cid_PQC_MLDSA_44, "cid_PQC_MLDSA_44");
    retVal += perfTestSig(cid_PQC_MLDSA_65, "cid_PQC_MLDSA_65");
    retVal += perfTestSig(cid_PQC_MLDSA_87, "cid_PQC_MLDSA_87");

#ifdef __ENABLE_DIGICERT_SIG_OQS_FALCON__
    retVal += perfTestSig(cid_PQC_FNDSA_512, "cid_PQC_FNDSA_512");
    retVal += perfTestSig(cid_PQC_FNDSA_1024, "cid_PQC_FNDSA_1024");
#endif

    retVal += perfTestSig(cid_PQC_SLHDSA_SHA2_128S, "cid_PQC_SLHDSA_SHA2_128S");
    retVal += perfTestSig(cid_PQC_SLHDSA_SHA2_128F, "cid_PQC_SLHDSA_SHA2_128F");
    retVal += perfTestSig(cid_PQC_SLHDSA_SHAKE_128S, "cid_PQC_SLHDSA_SHAKE_128S");
    retVal += perfTestSig(cid_PQC_SLHDSA_SHAKE_128F, "cid_PQC_SLHDSA_SHAKE_128F");

    retVal += perfTestSig(cid_PQC_SLHDSA_SHA2_192S, "cid_PQC_SLHDSA_SHA2_192S");
    retVal += perfTestSig(cid_PQC_SLHDSA_SHA2_192F, "cid_PQC_SLHDSA_SHA2_192F");
    retVal += perfTestSig(cid_PQC_SLHDSA_SHAKE_192S, "cid_PQC_SLHDSA_SHAKE_192S");
    retVal += perfTestSig(cid_PQC_SLHDSA_SHAKE_192F, "cid_PQC_SLHDSA_SHAKE_192F");

    retVal += perfTestSig(cid_PQC_SLHDSA_SHA2_256S, "cid_PQC_SLHDSA_SHA2_256S");
    retVal += perfTestSig(cid_PQC_SLHDSA_SHA2_256F, "cid_PQC_SLHDSA_SHA2_256F");
    retVal += perfTestSig(cid_PQC_SLHDSA_SHAKE_256S, "cid_PQC_SLHDSA_SHAKE_256S");
    retVal += perfTestSig(cid_PQC_SLHDSA_SHAKE_256F, "cid_PQC_SLHDSA_SHAKE_256F");

exit:
    
    DIGICERT_free(&gpMocCtx);
#endif    
    return retVal;
}
