/*
 * primeec_eg_perf_test.c
 *
 * performance test for primeec_eg.c
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
#include "../../crypto/mocasym.h"
#include "../../crypto/primeec_eg.h"

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

#if defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_ECC_ELGAMAL__)
static int perfTestEncrypt(ubyte4 curveId, ubyte4 plainLen, ubyte4 cipherLen, char *pCurveName, ECCKey **ppSavedKey, ubyte **ppSavedCipher)
{
    MSTATUS status;
    randomContext *pRandomContext = NULL;
    ECCKey *pKey = NULL;
    ubyte pPlain[32];    /* Test typical use case of encrypting up to a 32 byte symmetric keys */
    ubyte *pCipher = NULL;
    int i;

    struct tms tstart, tend;
    double diffTime;
    ubyte4 counter = 0;
    
    /* set the plain to some dummy data but not all zero */
    for (i = 0; i < plainLen; i++)
        pPlain[i] = (ubyte) ((i + 1) & 0xff);
    
    /* allocate memory for the cipher text */
    status = DIGI_MALLOC((void **) &pCipher, cipherLen);
    if (OK != status)
        goto exit;
    
    status = RANDOM_acquireContext(&pRandomContext);
    if (OK != status)
        goto exit;
    
    status = EC_newKeyEx(curveId, &pKey);
    if (OK != status)
        goto exit;
    
    status = EC_generateKeyPairEx(pKey, RANDOM_rngFun, pRandomContext);
    if (OK != status)
        goto exit;
    
    /* make sure the key is used as a public key */
    pKey->privateKey = FALSE;
    
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
        ECEG_encryptPKCSv1p5(pKey, RANDOM_rngFun, pRandomContext, pPlain, plainLen, pCipher, NULL);
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    
    printf("TESTING EGEC ENCRYPT %s, input len %d bytes\n", pCurveName, plainLen);
    
    printf("Result:\n\t%d Encryptions done in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g encryptions/second (CPU time)\n\n", counter/diffTime);
    
    pKey->privateKey = TRUE;
    
    *ppSavedKey = pKey; pKey = NULL;
    *ppSavedCipher = pCipher; pCipher = NULL;

exit:
    
    if (NULL != pRandomContext)
        RANDOM_releaseContext(&pRandomContext);
    
    if (NULL != pKey)
        EC_deleteKeyEx(&pKey);
    
    if (NULL != pCipher)
        DIGI_FREE((void **) &pCipher);
    
    if (OK != status)
    {
        printf("TEST FAILURE, status = %d\n", status);
        return 1;
    }
    
    return 0;
}

static int perfTestDecrypt(ECCKey *pKey, ubyte *pCipher, ubyte4 cipherLen, char *pCurveName)
{
    ubyte pPlain[32];    /* big enough for all curves */
    
    struct tms tstart, tend;
    double diffTime;
    ubyte4 counter = 0;
    
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        /* ignore status */
        ECEG_decryptPKCSv1p5(pKey, pCipher, cipherLen, pPlain, NULL);
        counter++;
        /* nothing to change for next iteration (at least for now) */
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    
    printf("TESTING EGEC DECRYPT %s, input len %d bytes\n", pCurveName, cipherLen);
    
    printf("Result:\n\t%d Decryptions done in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g decryptions/second (CPU time)\n\n", counter/diffTime);
    
    return 0;
}
#endif /* defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_ECC_ELGAMAL__) */

int primeec_eg_perf_test_all()
{
    int retVal = 0;

#if defined(__ENABLE_DIGICERT_ECC__) && defined(__ENABLE_DIGICERT_ECC_ELGAMAL__)
    MSTATUS status = OK;
    ECCKey *pKey = NULL;
    ubyte *pCipher = NULL;
    
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
    retVal += perfTestEncrypt(cid_EC_P192, 9, 24*4, "P192", &pKey, &pCipher);
    retVal += perfTestDecrypt(pKey, pCipher, 24*4, "P192");
    
    EC_deleteKeyEx(&pKey);
    DIGI_FREE((void **) &pCipher);
#endif /* __ENABLE_DIGICERT_ECC_P192__  */
    
#ifndef __DISABLE_DIGICERT_ECC_P224__
    retVal += perfTestEncrypt(cid_EC_P224, 13, 28*4, "P224", &pKey, &pCipher);
    retVal += perfTestDecrypt(pKey, pCipher, 28*4, "P224");
    
    EC_deleteKeyEx(&pKey);
    DIGI_FREE((void **) &pCipher);
#endif /* __DISABLE_DIGICERT_ECC_P224__  */
    
#ifndef __DISABLE_DIGICERT_ECC_P256__
    retVal += perfTestEncrypt(cid_EC_P256, 16, 32*4, "P256", &pKey, &pCipher);
    retVal += perfTestDecrypt(pKey, pCipher, 32*4, "P256");
    
    EC_deleteKeyEx(&pKey);
    DIGI_FREE((void **) &pCipher);
#endif /* __DISABLE_DIGICERT_ECC_P256__  */
    
#ifndef __DISABLE_DIGICERT_ECC_P384__
    retVal += perfTestEncrypt(cid_EC_P384, 24, 48*4, "P384", &pKey, &pCipher);
    retVal += perfTestDecrypt(pKey, pCipher, 48*4, "P384");
    
    EC_deleteKeyEx(&pKey);
    DIGI_FREE((void **) &pCipher);
#endif /* __DISABLE_DIGICERT_ECC_P384__  */
    
#ifndef __DISABLE_DIGICERT_ECC_P521__
    retVal += perfTestEncrypt(cid_EC_P521, 32, 66*4, "P521", &pKey, &pCipher);
    retVal += perfTestDecrypt(pKey, pCipher, 66*4, "P521");
    
    EC_deleteKeyEx(&pKey);
    DIGI_FREE((void **) &pCipher);
#endif /* __DISABLE_DIGICERT_ECC_P521__  */
    
exit:
    
    DIGICERT_free(&gpMocCtx);
    
#else
    printf("ECC EG DISABLED, no tests run!\n\n");
#endif
    
    return retVal;
}
