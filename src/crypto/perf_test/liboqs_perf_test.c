/*
 * liboqs_perf_test.c
 *
 * performance test for liboqs kems and signatures
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

#ifdef __ENABLE_PERF_TEST_OQS_DIRECT__ 
#include <oqs/oqs.h>
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

static int perfTestKem(char * pTestName)
{
    int ret = 0;
    OQS_KEM *key;

    ubyte *pCipher = NULL;
    ubyte4 cipherLen;
    ubyte *pSS = NULL;
    ubyte4 ssLen = 0;
    ubyte *pSS2 = NULL;
    uint8_t *pubKey = NULL;
    uint8_t *secretKey = NULL;
    ubyte4 pubLen;
    sbyte4 compare = 0;

    struct tms tstart, tend;
    double diffTime;
    ubyte4 counter = 0;

    key = OQS_KEM_new(pTestName);
    if (key == NULL)
        goto exit;

    printf("*******  TESTING OQS-%s *******\n\n", pTestName);

    pubLen = key->length_public_key;
    cipherLen = key->length_ciphertext;
    ssLen = key->length_shared_secret;

    DIGI_MALLOC((void **) &pubKey, pubLen);
    DIGI_MALLOC((void **) &secretKey, key->length_secret_key);
    DIGI_MALLOC((void **) &pCipher, cipherLen);
    DIGI_MALLOC((void **) &pSS, ssLen);
    DIGI_MALLOC((void **) &pSS2, ssLen);

    printf("public key len = %d, ciphertext len = %d, shared secret len = %d\n", pubLen, cipherLen, ssLen);

     /* Test Generate Key */
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF) {
        OQS_KEM_keypair(key, pubKey, secretKey);
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
        OQS_KEM_encaps(key, pCipher, pSS, pubKey);
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
        OQS_KEM_decaps(key, pSS2, pCipher, secretKey);
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
    DIGI_FREE((void **)&secretKey);
    DIGI_FREE((void **)&pubKey);

    OQS_KEM_free(key);

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

static int perfTestSig(char *pTestName)
{
    int ret = 0;
    OQS_SIG * key;

    ubyte pDigest[64]; /* big enough for mainstream hash algs */
    int digestLen = 64;
    ubyte *pSig = NULL;
    uint8_t *pubKey;
    uint8_t *secretKey;
    size_t sigLen;
    int actSigLen;
    int pubLen;

    int i;

    struct tms tstart, tend;
    double diffTime;
    ubyte4 counter = 0;

    /* set the message to some dummy data but not all zero */
    for (i = 0; i < digestLen; i++)
        pDigest[i] = (ubyte) (i & 0xff);

    key = OQS_SIG_new(pTestName);
    if (key == NULL)
        goto exit;

    printf("*******  TESTING OQS-%s *******\n\n", pTestName);

    pubLen = key->length_public_key;
    sigLen = key->length_signature;

    DIGI_MALLOC((void **) &pubKey, pubLen);
    DIGI_MALLOC((void **) &secretKey, key->length_secret_key);
    DIGI_MALLOC((void **) &pSig, sigLen);

    printf("public key len = %d, signature (max) len = %zu\n", pubLen, sigLen);

     /* Test Generate Key */
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        OQS_SIG_keypair(key, pubKey, secretKey);
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
        OQS_SIG_sign(key, pSig, &sigLen, pDigest, digestLen, secretKey);
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
        OQS_SIG_verify(key, pDigest, digestLen, pSig, sigLen, pubKey);
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
    DIGI_FREE((void **)&secretKey);
    DIGI_FREE((void **)&pubKey);
    OQS_SIG_free(key);

    if (OK != ret)
    {
        printf("TEST FAILURE, status = %d\n\n", ret);
        return 1;
    }

    return 0;
}

int liboqs_perf_test_all()
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

    retVal += perfTestKem("ML-KEM-512");
    retVal += perfTestKem("ML-KEM-768");
    retVal += perfTestKem("ML-KEM-1024");

    retVal += perfTestSig("ML-DSA-44");
    retVal += perfTestSig("ML-DSA-65");
    retVal += perfTestSig("ML-DSA-87");

exit:
    DIGICERT_free(&gpMocCtx);

    return retVal;
}

