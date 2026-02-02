/*
 * wolf_perf_test.c
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

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

static MocCtx gpMocCtx = NULL;

#include <stdio.h>
#include <sys/types.h>
#include <sys/times.h>
#include <unistd.h>
#include <signal.h>

#ifdef __ENABLE_PERF_TEST_WOLF__ /* our unittest ruby file chokes on wolfssl so this is the hideous workaround. */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/wc_kyber.h>
#include <wolfssl/wolfcrypt/kyber.h>
#endif

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

static int perfTestKem(ubyte4 id, char * pTestName)
{
    int ret = 0;
    MlKemKey key = {0};
    WC_RNG rng = {0};

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

    ret = wc_InitRng(&rng);
    if (0 != ret)
        goto exit;

    ret = wc_MlKemKey_Init(&key, id, NULL, 0);
    if (0 != ret)
        goto exit;

    printf("*******  TESTING %s *******\n\n", pTestName);

    ret = wc_MlKemKey_PublicKeySize(&key, &pubLen);
    if (0 != ret)
        goto exit;

    ret = wc_MlKemKey_CipherTextSize(&key, &cipherLen);
    if (0 != ret)
        goto exit;

    ret = wc_MlKemKey_SharedSecretSize(&key, &ssLen);
    if (ret != 0)
        goto exit;

    DIGI_MALLOC((void **) &pCipher, cipherLen);
    DIGI_MALLOC((void **) &pSS, ssLen);
    DIGI_MALLOC((void **) &pSS2, ssLen);

    printf("public key len = %d, ciphertext len = %d, shared secret len = %d\n", pubLen, cipherLen, ssLen);

     /* Test Generate Key */
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF) {
        wc_MlKemKey_MakeKey(&key, &rng);
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
    while( ALARM_OFF) {
        wc_MlKemKey_Encapsulate(&key, pCipher, pSS, &rng);
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
    while( ALARM_OFF) {
        /* Currently uskey the KyberKey interface because the MLKEM version of decapsulate actually calls encapsulate (5.7.6-stable)
         **/
        wc_KyberKey_Decapsulate(&key, pSS2, pCipher, cipherLen);
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

    if (NULL != pCipher) {
        (void) DIGI_FREE((void **) &pCipher);
    }

    if (NULL != pSS) {
        (void) DIGI_FREE((void **) &pSS);
    }

    if (NULL != pSS2) {
        (void) DIGI_FREE((void **) &pSS2);
    }

    if (ret != 0) {
        printf("TEST FAILURE, status = %d\n\n", ret);
        return 1;
    }

    if (0 != compare) {
        printf("TEST FAILURE, compare = %d\n\n", compare);
        return 1;
    }

    return 0;
}

static int perfTestSig(ubyte4 id, char *pTestName)
{
    int ret = 0;
    MlDsaKey key = {0};
    WC_RNG rng = {0};

    ubyte pDigest[64]; /* big enough for mainstream hash algs */
    int digestLen = 64;
    ubyte *pSig = NULL;
    int sigLen;
    int actSigLen;
    int pubLen;
    int vStatus = 0;

    int i;

    struct tms tstart, tend;
    double diffTime;
    ubyte4 counter = 0;

    /* set the message to some dummy data but not all zero */
    for (i = 0; i < digestLen; i++)
        pDigest[i] = (ubyte) (i & 0xff);

    ret = wc_InitRng(&rng);
    if (0 != ret)
        goto exit;

    ret = wc_MlDsaKey_SetParams(&key, id);
    if (0 != ret)
        goto exit;

    printf("*******  TESTING %s *******\n\n", pTestName);

    ret = wc_MlDsaKey_GetPubLen(&key, &pubLen);
    if (0 != ret)
        goto exit;

    ret = wc_MlDsaKey_GetSigLen(&key, &sigLen);
    if (0 != ret)
        goto exit;

    DIGI_MALLOC((void **) &pSig, sigLen);

    printf("public key len = %d, signature (max) len = %d\n", pubLen, sigLen);

     /* Test Generate Key */
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        wc_MlDsaKey_MakeKey(&key, &rng);
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
        wc_MlDsaKey_Sign(&key, pSig, (word32 *) &sigLen, pDigest, digestLen, &rng);
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
        wc_MlDsaKey_Verify(&key, pSig, sigLen, pDigest, digestLen, &vStatus);
        counter++;
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);

    printf("verify, digest length = %d bytes\n", digestLen);

    printf("Result:\n\t%d test verifies in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g verifies/second\n\n", counter/diffTime);

exit:

    if (NULL != pSig)
    {
        (void) DIGI_FREE((void **) &pSig);
    }

    if (OK != ret)
    {
        printf("TEST FAILURE, status = %d\n\n", ret);
        return 1;
    }

    if (1 != vStatus)
    {
        printf("TEST FAILURE, vStatus = %d\n\n", vStatus);
        return 1;
    }

    return 0;
}

int wolf_perf_test_all()
{
    int retVal = 0;

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

    printf("start\n");
    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    retVal += UNITTEST_INT(__MOC_LINE__, status, OK);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

    printf("\n");

    retVal += perfTestKem(WC_ML_KEM_512, "WOLF_MLKEM_512");
    retVal += perfTestKem(WC_ML_KEM_768, "WOLF_MLKEM_768");
    retVal += perfTestKem(WC_ML_KEM_1024, "WOLF_MLKEM_1024");

    retVal += perfTestSig(WC_ML_DSA_44, "WOLF_MLDSA_44");
    retVal += perfTestSig(WC_ML_DSA_65, "WOLF_MLDSA_65");
    retVal += perfTestSig(WC_ML_DSA_87, "WOLF_MLDSA_87");

exit:
    DIGICERT_free(&gpMocCtx);

    return retVal;
}

