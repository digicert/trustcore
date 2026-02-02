/*
 * ecdsa_perf_test.c
 *
 * performance test for ecdsa sign and verify
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

#ifdef __ENABLE_PERF_TEST_OPENSSL__
#undef ASN1_ITEM
#include <openssl/crypto.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>
#endif

#ifdef __ENABLE_PERF_TEST_MBEDTLS__
#include <mbedtls/ecdsa.h>
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

#ifdef __ENABLE_DIGICERT_ECC__
static int perfTestECDSA(ubyte4 curveId, ubyte4 digestLen, char * pCurveName)
{
    MSTATUS status;
    
    ECCKey *pKey = NULL;
    ubyte pDigest[64]; /* big enough for mainstream hash algs */
    ubyte pSignature[66*2] = {0}; /* big enough for any curve */
    ubyte4 sigLen;
    
    ubyte *pR;
    ubyte *pS;
    ubyte4 rsLen;
    ubyte4 verStatus;
    
    randomContext *pRandomContext = NULL;
    
    int i;
    
    struct tms tstart, tend;
    double diffTime, kbytes;
    ubyte4 counter = 0;
    
    /* set the message to some dummy data but not all zero */
    for (i = 0; i < digestLen; i++)
        pDigest[i] = (ubyte) (i & 0xff);
    
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
    
    /* Test Sign */
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_ECDSA_signDigestAux (pKey, RANDOM_rngFun, (void *) pRandomContext, pDigest, digestLen, pSignature, 132, &sigLen);
#else
        ECDSA_signDigest (pKey, RANDOM_rngFun, (void *) pRandomContext, pDigest, digestLen, pSignature, 132, &sigLen);
#endif
        counter++;
        pDigest[0]++;  /* change message for next iteration */
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = digestLen * (counter / 1024.0);
    
    printf("TESTING ECDSA SIGN, %s, digest length = %d bytes\n", pCurveName, digestLen);
    
    printf("Result:\n\t%d test signatures in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g signatures/second\n", counter/diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

    /* Test Verify, verify failure is the same time as a verify success */
    pKey->privateKey = FALSE;
    pR = pSignature;
    rsLen = sigLen/2;
    pS = pSignature + rsLen;
    
    counter = 0;
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_ECDSA_verifySignatureDigestAux (pKey, pDigest, digestLen, pR, rsLen, pS, rsLen, &verStatus);
#else
        ECDSA_verifySignatureDigest (pKey, pDigest, digestLen, pR, rsLen, pS, rsLen, &verStatus);
#endif
        counter++;
        pDigest[0]++;  /* change message for next iteration */
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = digestLen * (counter / 1024.0);
    
    printf("TESTING ECDSA VERIFY, %s, digest length = %d bytes\n", pCurveName, digestLen);
    
    printf("Result:\n\t%d test verifies in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g verifies/second\n", counter/diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

exit:

    if (NULL != pKey)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_EC_deleteKeyAux(&pKey);
#else
        EC_deleteKeyEx(&pKey);
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
#endif /* __ENABLE_DIGICERT_ECC__ */

#ifdef __ENABLE_PERF_TEST_OPENSSL__
static int perfTestOSSL(int curve, int digestLen, char *pCurveName)
{
    EC_KEY *pKey = NULL;
    ubyte pDigest[64]; /* big enough for mainstream hash algs */
    ubyte pSignature[150] = {0}; /* big enough for any curve, der encoded signature */
    int sigLen;

    struct tms tstart, tend;
    double diffTime, kbytes;
    ubyte4 counter = 0;
    
    int i;
    int status;
    
    /* set the message to some dummy data but not all zero */
    for (i = 0; i < digestLen; i++)
        pDigest[i] = (ubyte) (i & 0xff);
    
    pKey = EC_KEY_new_by_curve_name(curve);
    if (NULL == pKey)
    {
       status = -1;
       goto exit;
    }
    
    status = EC_KEY_generate_key(pKey);
    if (1 != status)
        goto exit;
    
    /* Test Sign */
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
        ECDSA_sign(0, pDigest, digestLen, pSignature, &sigLen, pKey);
        counter++;
        pDigest[0]++;  /* change message for next iteration */
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = digestLen * (counter / 1024.0);
    
    printf("OPENSSL TESTING ECDSA SIGN, %s, digest length = %d bytes\n", pCurveName, digestLen);
    
    printf("Result:\n\t%d test signatures in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g signatures/second\n", counter/diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);
    
    /* Test Verify, verify failure is the same time as a verify success */
    
    counter = 0;
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
        ECDSA_verify(0, pDigest, digestLen, pSignature, sigLen, pKey);
        counter++;
        pDigest[0]++;  /* change message for next iteration */
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = digestLen * (counter / 1024.0);
    
    printf("OPENSSL TESTING ECDSA VERIFY, %s, digest length = %d bytes\n", pCurveName, digestLen);
    
    printf("Result:\n\t%d test verifies in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g verifies/second\n", counter/diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);
    
exit:
    
    EC_KEY_free(pKey);
    
    if (1 != status)
    {
        printf("OPENSSL TEST FAILURE, status = %d\n", status);
        return 1;
    }
    
    return 0;
}
#endif /* __ENABLE_PERF_TEST_OPENSSL__ */

#ifdef __ENABLE_PERF_TEST_MBEDTLS__
static int MBED_rngFun(void *pRandInfo, unsigned char *pBuffer, size_t byteCount)
{
    return (int) RANDOM_rngFun(pRandInfo, (ubyte4) byteCount, pBuffer);
}

static int perfTestMBED(mbedtls_ecp_group_id groupId, size_t digestLen, char * pCurveName)
{
    mbedtls_ecp_keypair key;
    mbedtls_mpi r, s;
    mbedtls_mpi *d;
    mbedtls_ecp_point *Q;
    mbedtls_ecp_group *pGroup;
    ubyte4 format;
    
    ubyte pDigest[64]; /* big enough for mainstream hash algs */
    
    struct tms tstart, tend;
    double diffTime, kbytes;
    ubyte4 counter = 0;
    
    randomContext *pRandomContext = NULL;
    
    int i;
    int status;
    
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    
    status = (int) RANDOM_acquireContext(&pRandomContext);
    if (0 != status)
        goto exit;
    
    /* set the message to some dummy data but not all zero */
    for (i = 0; i < digestLen; i++)
        pDigest[i] = (ubyte) (i & 0xff);
    
    mbedtls_ecp_keypair_init(&key);
    
    status = mbedtls_ecp_gen_key(groupId, &key, MBED_rngFun, pRandomContext);
    if (0 != status)
        goto exit;

    d = &(key.d);
    Q = &(key.Q);
    pGroup = &(key.grp);
    
    /* Test Sign */
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
        mbedtls_ecdsa_sign(pGroup, &r, &s, d, pDigest, digestLen, MBED_rngFun, pRandomContext);
        counter++;
        pDigest[0]++;  /* change message for next iteration */
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = digestLen * (counter / 1024.0);
    
    printf("MBEDTLS TESTING ECDSA SIGN, %s, digest length = %d bytes\n", pCurveName, digestLen);
    
    printf("Result:\n\t%d test signatures in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g signatures/second\n", counter/diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);
    
    /* Test Verify, verify failure is the same time as a verify success */
    
    counter = 0;
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
        mbedtls_ecdsa_verify(pGroup, pDigest, digestLen, Q, &r, &s);
        counter++;
        pDigest[0]++;  /* change message for next iteration */
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = digestLen * (counter / 1024.0);
    
    printf("MBEDTLS TESTING ECDSA VERIFY, %s, digest length = %d bytes\n", pCurveName, digestLen);
    
    printf("Result:\n\t%d test verifies in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g verifies/second\n", counter/diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);
    
exit:
    
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    
    mbedtls_ecp_keypair_free(&key);
    
    if (NULL != pRandomContext)
        RANDOM_releaseContext(&pRandomContext);
    
    if (0 != status)
    {
        printf("MBEDTLS TEST FAILURE, status = %d\n", status);
        return 1;
    }
    
    return 0;
}
#endif /* __ENABLE_PERF_TEST_MBEDTLS__ */

int ecdsa_perf_test_all()
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
    retVal += perfTestECDSA(cid_EC_P192, 20, "P192");
#endif
#ifdef __ENABLE_PERF_TEST_OPENSSL__
    OPENSSL_init();
    retVal += perfTestOSSL(NID_X9_62_prime192v1, 20, "P192");
#endif
#ifdef __ENABLE_PERF_TEST_MBEDTLS__
    retVal += perfTestMBED(MBEDTLS_ECP_DP_SECP192R1, 20, "P192");
#endif

#ifndef __DISABLE_DIGICERT_ECC_P224__
    retVal += perfTestECDSA(cid_EC_P224, 24, "P224");
#endif
#ifdef __ENABLE_PERF_TEST_OPENSSL__
    retVal += perfTestOSSL(NID_secp224r1, 24, "P224");
#endif
#ifdef __ENABLE_PERF_TEST_MBEDTLS__
    retVal += perfTestMBED(MBEDTLS_ECP_DP_SECP224R1, 24, "P224");
#endif
    
#ifndef __DISABLE_DIGICERT_ECC_P256__
    retVal += perfTestECDSA(cid_EC_P256, 32, "P256");
#endif
#ifdef __ENABLE_PERF_TEST_OPENSSL__
    retVal += perfTestOSSL(NID_X9_62_prime256v1, 32, "P256");
#endif
#ifdef __ENABLE_PERF_TEST_MBEDTLS__
    retVal += perfTestMBED(MBEDTLS_ECP_DP_SECP256R1, 32, "P256");
#endif
    
#ifndef __DISABLE_DIGICERT_ECC_P384__
    retVal += perfTestECDSA(cid_EC_P384, 48, "P384");
#endif
#ifdef __ENABLE_PERF_TEST_OPENSSL__
    retVal += perfTestOSSL(NID_secp384r1, 48, "P384");
#endif
#ifdef __ENABLE_PERF_TEST_MBEDTLS__
    retVal += perfTestMBED(MBEDTLS_ECP_DP_SECP384R1, 48, "P384");
#endif
    
#ifndef __DISABLE_DIGICERT_ECC_P521__
    retVal += perfTestECDSA(cid_EC_P521, 64, "P521");
#endif
#ifdef __ENABLE_PERF_TEST_OPENSSL__
    retVal += perfTestOSSL(NID_secp521r1, 64, "521");
#endif
#ifdef __ENABLE_PERF_TEST_MBEDTLS__
    retVal += perfTestMBED(MBEDTLS_ECP_DP_SECP521R1, 64, "P521");
#endif

exit:
    
    DIGICERT_free(&gpMocCtx);
    
    return retVal;
}
