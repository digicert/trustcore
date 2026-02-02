/*
 * dsa_perf_test.c
 *
 * performance test for dsa
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
#include "../../crypto/dsa.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../../crypto_interface/crypto_interface_dsa.h"
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

#define MAX_SEED_SIZE 32

static int perfTestKeyGen(ubyte4 keySize, ubyte4 qSize, DSAHashType hashType, randomContext *pRandomContext)
{
    DSAKey *pKey = NULL;
    ubyte4 C = 0;
    ubyte seed[MAX_SEED_SIZE] = {0};
    ubyte4 seedSize = MAX_SEED_SIZE;

    struct tms tstart, tend;
    double diffTime;
    ubyte4 counter = 0;

    /* key gen is much slower, run more time */
    /* START_ALARM(TEST_SECONDS * (4096 == keySize ? 20 : 10)); */
    START_ALARM(TEST_SECONDS * 10);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DSA_createKey(&pKey);
        CRYPTO_INTERFACE_DSA_generateKeyAux2(pRandomContext, pKey, keySize, qSize, hashType, NULL);
        CRYPTO_INTERFACE_DSA_freeKey(&pKey, NULL);
#else
        DSA_createKey(&pKey);
        DSA_generateKeyAux2(pRandomContext, pKey, keySize, qSize, hashType, NULL);
        DSA_freeKey(&pKey, NULL);
#endif
        counter++;
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);

    printf("TESTING DSA Key Generation, %d bits with %d bit prime\n", keySize, qSize);

    printf("Result:\n\t%d keys in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g keys/second\n\n", counter/diffTime);


    /* keep pKey as is for future tests */

exit:

    if (NULL != pKey) /* sanity check */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DSA_freeKey(&pKey, NULL);
#else
        DSA_freeKey(&pKey, NULL);
#endif
    
    return 0;
}

static int perfTestSignVerify(ubyte4 keySize, DSAKey *pKey, ubyte4 digestLen, randomContext *pRandomContext)
{
    /* big enough for SHA512 digest length, output digest needs full buffer len */
    ubyte pDigest[512];
    ubyte pSig[512];
    ubyte *pR = NULL;
    ubyte4 rLen;
    ubyte *pS = NULL;
    ubyte4 sLen;
    intBoolean pValid = FALSE;
    ubyte4 recLen = 0;
    ubyte4 i;

    struct tms tstart, tend;
    double diffTime, kbytes;
    ubyte4 counter = 0;

    /* set the digest to something nonzero */
    for (i = 0; i < digestLen; ++i)
        pDigest[i] = (ubyte) (i + 1);

    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status, this API actually signs a digest */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DSA_computeSignatureAux(pRandomContext, pKey, pDigest, digestLen, &pValid, &pR, &rLen, &pS, &sLen, NULL);
#else
        DSA_computeSignatureAux(pRandomContext, pKey, pDigest, digestLen, &pValid, &pR, &rLen, &pS, &sLen, NULL);
#endif
        DIGI_FREE((void **)&pR);
        DIGI_FREE((void **)&pS);
        counter++;
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = digestLen * (counter / 1024.0);

    printf("TESTING DSA Signs, %d bit key, %d byte digest\n", keySize, digestLen);

    printf("Result:\n\t%d signatures in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g signatures/second\n", counter/diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

    /* Verify */
    counter = 0;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DSA_computeSignatureAux(pRandomContext, pKey, pDigest, digestLen, &pValid, &pR, &rLen, &pS, &sLen, NULL);
#else
        DSA_computeSignatureAux(pRandomContext, pKey, pDigest, digestLen, &pValid, &pR, &rLen, &pS, &sLen, NULL);
#endif

    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DSA_verifySignatureAux(pKey, pDigest, digestLen, pR, rLen, pS, sLen, &pValid, NULL);
#else
        DSA_verifySignatureAux(pKey, pDigest, digestLen, pR, rLen, pS, sLen, &pValid, NULL);
#endif
        counter++;
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = digestLen * (counter / 1024.0);

    printf("TESTING DSA Verification, %d bit key, %d byte digest\n", keySize, digestLen);

    printf("Result:\n\t%d verifications in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g verifications/second\n", counter/diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

    DIGI_FREE((void **)&pR);
    DIGI_FREE((void **)&pS);

    return 0;
}

int dsa_perf_test_all()
{
    MSTATUS status;
    int retVal = 0;
    DSAKey *pKey = NULL;
    randomContext *pRandomContext = NULL;

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

    status = RANDOM_acquireContext(&pRandomContext);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_DSA_768__
    /* Test 768 */
    retVal += perfTestKeyGen(768, 160, DSA_sha1, pRandomContext);

    /* create another key for enc/dec/sign/v */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_createKey(&pKey);
#else
    status = DSA_createKey(&pKey);
#endif
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_generateKeyAux2(pRandomContext, pKey, 768, 160, DSA_sha1, NULL);
#else
    status = DSA_generateKeyAux2(pRandomContext, pKey, 768, 160, DSA_sha1, NULL);
#endif
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

    retVal += perfTestSignVerify(768, pKey, 12, pRandomContext);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_freeKey(&pKey, NULL);
#else
    status = DSA_freeKey(&pKey, NULL);
#endif
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
#endif

#ifdef __ENABLE_DIGICERT_DSA_ALL_KEYSIZE__
    /* Test 1024 with 160 */
    retVal += perfTestKeyGen(1024, 160, DSA_sha1, pRandomContext);

    /* create another key for enc/dec/sign/v */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_createKey(&pKey);
#else
    status = DSA_createKey(&pKey);
#endif
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }


#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_generateKeyAux2(pRandomContext, pKey, 1024, 160, DSA_sha1, NULL);
#else
    status = DSA_generateKeyAux2(pRandomContext, pKey, 1024, 160, DSA_sha1, NULL);
#endif
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

    retVal += perfTestSignVerify(1024, pKey, 16, pRandomContext);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_freeKey(&pKey, NULL);
#else
    status = DSA_freeKey(&pKey, NULL);
#endif
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
#endif

    /* Test 2048 with 224 */
    retVal += perfTestKeyGen(2048, 224, DSA_sha256, pRandomContext);

    /* create another key for enc/dec/sign/v */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_createKey(&pKey);
#else
    status = DSA_createKey(&pKey);
#endif
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_generateKeyAux2(pRandomContext, pKey, 2048, 224, DSA_sha256, NULL);
#else
    status = DSA_generateKeyAux2(pRandomContext, pKey, 2048, 224, DSA_sha256, NULL);
#endif
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

    retVal += perfTestSignVerify(2048, pKey, 32, pRandomContext);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_freeKey(&pKey, NULL);
#else
    status = DSA_freeKey(&pKey, NULL);
#endif
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

    /* Test 2048 with 256 */
    retVal += perfTestKeyGen(2048, 256, DSA_sha256, pRandomContext);

    /* create another key for enc/dec/sign/v */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_createKey(&pKey);
#else
    status = DSA_createKey(&pKey);
#endif
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_generateKeyAux2(pRandomContext, pKey, 2048, 256, DSA_sha256, NULL);
#else
    status = DSA_generateKeyAux2(pRandomContext, pKey, 2048, 256, DSA_sha256, NULL);
#endif
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

    retVal += perfTestSignVerify(2048, pKey, 32, pRandomContext);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_freeKey(&pKey, NULL);
#else
    status = DSA_freeKey(&pKey, NULL);
#endif
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }

exit:

    if (NULL != pKey)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DSA_freeKey(&pKey, NULL);
#else
        DSA_freeKey(&pKey, NULL);
#endif

    if (NULL != pRandomContext)
        RANDOM_releaseContext(&pRandomContext);

    DIGICERT_free(&gpMocCtx);

    return retVal;
}
