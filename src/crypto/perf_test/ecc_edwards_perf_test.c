/*
 * ecc_edwards_perf_test.c
 *
 * performance test for ecc_edwards_keys.c, ecc_edwards_dsa.c, and ecc_edwards_dh.c
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
#include "../../crypto/sha3.h"
#include "../../crypto/sha512.h"
#include "../../crypto/ecc_edwards_dsa.h"
#include "../../crypto/ecc_edwards_dh.h"

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

#ifdef __ENABLE_DIGICERT_SHA3__

/* shake256 wrappers of sha3 in the BulkHashAlgo form */
static MSTATUS shake256_digest(ubyte *pMessage, ubyte4 messageLen, ubyte *pResult, ubyte4 desiredResultLen)
{
    return SHA3_completeDigest(MOCANA_SHA3_MODE_SHAKE256, pMessage, messageLen, pResult, desiredResultLen);
}

#endif /* __ENABLE_DIGICERT_SHA3__ */

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) || \
    defined(__ENABLE_DIGICERT_ECC_EDDH_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDH_448__)
static int perfTestGenKey(edECCKey **ppKey, edECCCurve curve, BulkHashAlgo *pShaSuite, char *pCurve)
{
    MSTATUS status;
    edECCKey *pKey = NULL;
    struct tms tstart, tend;
    double diffTime;
    ubyte4 counter = 0;
    randomContext *pRandomContext = NULL;
    
    status = RANDOM_acquireContext(&pRandomContext);
    if (OK != status)
        goto exit;
    
    status = edECC_newKey(&pKey, curve, NULL);
    if (OK != status)
        goto exit;
    
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
        edECC_generateKeyPair(pKey, RANDOM_rngFun, (void *) pRandomContext, pShaSuite, NULL);
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    
    printf("TESTING key generation, %s\n", pCurve);
    
    printf("Result:\n\t%d keys created in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g keys/second (CPU time)\n\n", counter/diffTime);
    
    /* save one of the keys for later tests */
    *ppKey = pKey; pKey = NULL;
    
exit:
    
    if (NULL != pRandomContext)
        RANDOM_releaseContext(&pRandomContext);
    
    if (NULL != pKey)
        edECC_deleteKey(&pKey, NULL);
    
    if (OK != status)
    {
        printf("TEST FAILURE, status = %d\n", status);
        return 1;
    }
    
    return 0;
}
#endif /* any ED curve */

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDSA_448__)
static int perfTestSign(edECCKey *pKey, ubyte4 messageLen, BulkHashAlgo *pShaSuite, char *pCurve)
{
    MSTATUS status;
    ubyte *pMessage = NULL;
    ubyte pSignature[57*2] = {0}; /* big enough for either curve */
    ubyte4 signatureLen;
    int i;
    
    struct tms tstart, tend;
    double diffTime, kbytes;
    ubyte4 counter = 0;
    
    status = DIGI_MALLOC((void **) &pMessage, messageLen);
    if (OK != status) 
        goto exit;
    
    /* set the message to some dummy data but not all zero */
    for (i = 0; i < messageLen; i++)
        pMessage[i] = (ubyte) (i & 0xff);
    
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
        edDSA_Sign(pKey, pMessage, messageLen, pSignature, sizeof(pSignature), &signatureLen, pShaSuite, FALSE, NULL, 0, NULL);
        counter++;
        pMessage[0]++;  /* change message for next iteration */
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = messageLen * (counter / 1024.0);
    
    printf("TESTING EdDSA SIGN, %s, message length = %d bytes\n", pCurve, messageLen);
    
    printf("Result:\n\t%d test signatures in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);
    
exit:

    if (NULL != pMessage)
        DIGI_FREE((void **) &pMessage);
    
    if (OK != status)
    {
        printf("TEST FAILURE, status = %d\n", status);
        return 1;
    }

    return 0;
}

static ubyte g25519ValidSig[] =
{
    0xe5,0x56,0x43,0x00,0xc3,0x60,0xac,0x72,0x90,0x86,0xe2,0xcc,0x80,0x6e,0x82,0x8a,
    0x84,0x87,0x7f,0x1e,0xb8,0xe5,0xd9,0x74,0xd8,0x73,0xe0,0x65,0x22,0x49,0x01,0x55,
    0x5f,0xb8,0x82,0x15,0x90,0xa3,0x3b,0xac,0xc6,0x1e,0x39,0x70,0x1c,0xf9,0xb4,0x6b,
    0xd2,0x5b,0xf5,0xf0,0x59,0x5b,0xbe,0x24,0x65,0x51,0x41,0x43,0x8e,0x7a,0x10,0x0b
};

static ubyte g448ValidSig[] =
{
    0x53,0x3a,0x37,0xf6,0xbb,0xe4,0x57,0x25,0x1f,0x02,0x3c,0x0d,0x88,0xf9,0x76,0xae,
    0x2d,0xfb,0x50,0x4a,0x84,0x3e,0x34,0xd2,0x07,0x4f,0xd8,0x23,0xd4,0x1a,0x59,0x1f,
    0x2b,0x23,0x3f,0x03,0x4f,0x62,0x82,0x81,0xf2,0xfd,0x7a,0x22,0xdd,0xd4,0x7d,0x78,
    0x28,0xc5,0x9b,0xd0,0xa2,0x1b,0xfd,0x39,0x80,0xff,0x0d,0x20,0x28,0xd4,0xb1,0x8a,
    0x9d,0xf6,0x3e,0x00,0x6c,0x5d,0x1c,0x2d,0x34,0x5b,0x92,0x5d,0x8d,0xc0,0x0b,0x41,
    0x04,0x85,0x2d,0xb9,0x9a,0xc5,0xc7,0xcd,0xda,0x85,0x30,0xa1,0x13,0xa0,0xf4,0xdb,
    0xb6,0x11,0x49,0xf0,0x5a,0x73,0x63,0x26,0x8c,0x71,0xd9,0x58,0x08,0xff,0x2e,0x65,
    0x26,0x00
};

static int perfTestVerify(edECCKey *pKey, ubyte4 messageLen, BulkHashAlgo *pShaSuite, char *pCurve)
{
    MSTATUS status;
    ubyte *pMessage = NULL;
    /* use a signature that is valid at least for some message */
    ubyte *pSignature = (curveEd25519 == pKey->curve ? g25519ValidSig : g448ValidSig);
    ubyte4 signatureLen = (curveEd25519 == pKey->curve ? 64 : 114);
    ubyte4 vStatus = 1;
    int i;
    
    struct tms tstart, tend;
    double diffTime, kbytes;
    ubyte4 counter = 0;
    
    status = DIGI_MALLOC((void **) &pMessage, messageLen);
    if (OK != status)
        goto exit;
    
    /* set the message to some dummy data but not all zero */
    for (i = 0; i < messageLen; i++)
        pMessage[i] = (ubyte) (i & 0xff);
    
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
        edDSA_VerifySignature(pKey, pMessage, messageLen, pSignature, signatureLen, &vStatus, pShaSuite, FALSE, NULL, 0, NULL);
        counter++;
        pMessage[0]++;  /* change message for next iteration */
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = messageLen * (counter / 1024.0);
    
    printf("TESTING EdDSA VERIFY, %s, message length = %d bytes\n", pCurve, messageLen);
    
    printf("Result:\n\t%d test verifies in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);
    
exit:
    
    if (NULL != pMessage)
        DIGI_FREE((void **) &pMessage);
    
    if (OK != status)
    {
        printf("TEST FAILURE, status = %d\n", status);
        return 1;
    }
    
    return 0;
}
#endif /* EDDSA */

#if defined(__ENABLE_DIGICERT_ECC_EDDH_25519__) || defined(__ENABLE_DIGICERT_ECC_EDDH_448__)
static ubyte g25519ValidPub[] =
{
    0xe6,0xdb,0x68,0x67,0x58,0x30,0x30,0xdb,0x35,0x94,0xc1,0xa4,0x24,0xb1,0x5f,0x7c,
    0x72,0x66,0x24,0xec,0x26,0xb3,0x35,0x3b,0x10,0xa9,0x03,0xa6,0xd0,0xab,0x1c,0x4c
};

static ubyte g448ValidPub[] =
{
    0x06,0xfc,0xe6,0x40,0xfa,0x34,0x87,0xbf,0xda,0x5f,0x6c,0xf2,0xd5,0x26,0x3f,0x8a,
    0xad,0x88,0x33,0x4c,0xbd,0x07,0x43,0x7f,0x02,0x0f,0x08,0xf9,0x81,0x4d,0xc0,0x31,
    0xdd,0xbd,0xc3,0x8c,0x19,0xc6,0xda,0x25,0x83,0xfa,0x54,0x29,0xdb,0x94,0xad,0xa1,
    0x8a,0xa7,0xa7,0xfb,0x4e,0xf8,0xa0,0x86
};

static int perfTestGenSecret(edECCKey *pKey, char *pCurve)
{
    /* use a signature that is valid at least for some message */
    ubyte *pPubKey = (curveX25519 == pKey->curve ? g25519ValidPub : g448ValidPub);
    ubyte4 pubKeyLen = (curveX25519 == pKey->curve ? 32 : 56);

    ubyte *pSS = NULL;
    ubyte4 ssLen = 0;
    
    struct tms tstart, tend;
    double diffTime;
    ubyte4 counter = 0;
    
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
        edDH_GenerateSharedSecret(pKey, pPubKey, pubKeyLen, &pSS, &ssLen, NULL);
        counter++;
        DIGI_FREE((void **) &pSS);
        /* nothing to modify for next iteration (at least for now) */
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    
    printf("TESTING EDDH Gen Secret, %s\n", pCurve);
    
    printf("Result:\n\t%d test secrets in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g secrets/second (CPU time, 1 kbyte = 1024 bytes)\n\n", counter/diffTime);
    
exit:
    
    if (NULL != pSS)
        DIGI_FREE((void **) &pSS);
    
    return 0;
}
#endif /* EDDH */

int ecc_edwards_perf_test_all()
{
    MSTATUS status;
    int retVal = 0;
    
    BulkHashAlgo shaSuite = {0};
    edECCKey *pKey = NULL;
    
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
    
#if defined(__ENABLE_DIGICERT_ECC_EDDSA_25519__) && !defined(__DISABLE_DIGICERT_SHA512__)
    
    /* Test edDSA on curve25519 */
    
    shaSuite.digestFunc = (BulkCtxDigestFunc) &SHA512_completeDigest;

    retVal += perfTestGenKey(&pKey, curveEd25519, &shaSuite, "EdDSA Curve 25519");
    
    retVal += perfTestSign(pKey, 64, &shaSuite, "EdDSA Curve 25519");
    retVal += perfTestSign(pKey, 1024, &shaSuite, "EdDSA Curve 25519");
    retVal += perfTestSign(pKey, 16384, &shaSuite, "EdDSA Curve 25519");
    
    /* Trick the key into being a public key */
    pKey->isPrivate = FALSE;
    
    retVal += perfTestVerify(pKey, 64, &shaSuite, "EdDSA Curve 25519");
    retVal += perfTestVerify(pKey, 1024, &shaSuite, "EdDSA Curve 25519");
    retVal += perfTestVerify(pKey, 16384, &shaSuite, "EdDSA Curve 25519");
    
    /* Done testing, delete the key */
    edECC_deleteKey(&pKey, NULL);
    
#endif

#if defined(__ENABLE_DIGICERT_ECC_EDDSA_448__) && defined(__ENABLE_DIGICERT_SHA3__)
    
    /* Test edDSA on curve448 */
    
    shaSuite.digestFunc = NULL;
    shaSuite.digestXOFFunc = (BulkCtxDigestXOFFunc) &shake256_digest;
    
    retVal += perfTestGenKey(&pKey, curveEd448, &shaSuite, "EdDSA Curve 448");
    
    retVal += perfTestSign(pKey, 64, &shaSuite, "EdDSA Curve 448");
    retVal += perfTestSign(pKey, 1024, &shaSuite, "EdDSA Curve 448");
    retVal += perfTestSign(pKey, 16384, &shaSuite, "EdDSA Curve 448");
    
    /* Trick the key into being a public key */
    pKey->isPrivate = FALSE;
    
    retVal += perfTestVerify(pKey, 64, &shaSuite, "EdDSA Curve 448");
    retVal += perfTestVerify(pKey, 1024, &shaSuite, "EdDSA Curve 448");
    retVal += perfTestVerify(pKey, 16384, &shaSuite, "EdDSA Curve 448");
    
    /* Done testing, delete the key */
    edECC_deleteKey(&pKey, NULL);
    
#endif
    
#if defined(__ENABLE_DIGICERT_ECC_EDDH_448__)
    
    /* Test EDDH on curve448 */
    
    retVal += perfTestGenKey(&pKey, curveX25519, NULL, "EDDH Curve 25519");
    retVal += perfTestGenSecret(pKey, "EDDH Curve 25519");
    
    /* Done testing, delete the key */
    edECC_deleteKey(&pKey, NULL);
    
#endif
    
#if defined(__ENABLE_DIGICERT_ECC_EDDH_448__)
    
    /* Test EDDH on curve448 */

    retVal += perfTestGenKey(&pKey, curveX448, NULL, "EDDH Curve 448");
    retVal += perfTestGenSecret(pKey, "EDDH Curve 448");
    
    /* Done testing, delete the key */
    edECC_deleteKey(&pKey, NULL);
    
#endif
   
exit:
    
    DIGICERT_free(&gpMocCtx);
    
    return retVal;
}
