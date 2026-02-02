/*
 * blake2_perf_test.c
 *
 * performance test for blake2.c
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

#include "../../crypto/blake2.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../../crypto_interface/crypto_interface_blake2.h"
#endif

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

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

#ifdef __ENABLE_DIGICERT_BLAKE_2B__
static int perfTestBlake2B(ubyte4 inLen, byteBoolean isMac)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    ubyte pResult[MOC_BLAKE2B_MAX_OUTLEN];
    ubyte pKey[MOC_BLAKE2B_MAX_KEYLEN];
    ubyte *pKeyPtr = (isMac ? pKey : NULL);
    ubyte4 keyLen = (isMac ? MOC_BLAKE2B_MAX_KEYLEN : 0);
    int i;
    
    struct tms tstart, tend;
    double diffTime, kbytes;
    ubyte4 counter = 0;
    
    status = DIGI_MALLOC((void **) &pMessage, inLen);
    if (OK != status)
        goto exit;
   
    /* set the message to some dummy data but not all zero */
    for (i = 0; i < inLen; i++)
        pMessage[i] = (ubyte) (i & 0xff);
    
    if(isMac)
    {
        /* set the key to some dummy data but not all zero */
        for (i = 0; i < MOC_BLAKE2B_MAX_KEYLEN; i++)
            pKey[i] = (ubyte) ((i + 1) & 0xff);
    }
   
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_BLAKE_2B_complete(pKeyPtr, keyLen, pMessage, inLen, pResult, MOC_BLAKE2B_MAX_OUTLEN); /* ignore status */
#else
        BLAKE2B_complete(pKeyPtr, keyLen, pMessage, inLen, pResult, MOC_BLAKE2B_MAX_OUTLEN); /* ignore status */
#endif
        counter++;
        pMessage[0]++; /* change the message for the next test */
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING BLAKE2B %s, input length = %d bytes\n", isMac ? "MAC" : "HASH", inLen);
    
    printf("Result:\n\t%d test hashes in %g seconds of CPU time\n", counter, diffTime);
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
#endif /* __ENABLE_DIGICERT_BLAKE_2B__ */

#ifdef __ENABLE_DIGICERT_BLAKE_2S__
static int perfTestBlake2S(ubyte4 inLen, byteBoolean isMac)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    ubyte pResult[MOC_BLAKE2S_MAX_OUTLEN];
    ubyte pKey[MOC_BLAKE2S_MAX_KEYLEN];
    ubyte *pKeyPtr = (isMac ? pKey : NULL);
    ubyte4 keyLen = (isMac ? MOC_BLAKE2S_MAX_KEYLEN : 0);
    int i;
    
    struct tms tstart, tend;
    double diffTime, kbytes;
    ubyte4 counter = 0;
    
    status = DIGI_MALLOC((void **) &pMessage, inLen);
    if (OK != status)
        goto exit;
    
    /* set the message to some dummy data but not all zero */
    for (i = 0; i < inLen; i++)
        pMessage[i] = (ubyte) (i & 0xff);
    
    if(isMac)
    {
        /* set the key to some dummy data but not all zero */
        for (i = 0; i < MOC_BLAKE2S_MAX_KEYLEN; i++)
            pKey[i] = (ubyte) ((i + 1) & 0xff);
    }
    
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_BLAKE_2S_complete(pKeyPtr, keyLen, pMessage, inLen, pResult, MOC_BLAKE2S_MAX_OUTLEN); /* ignore status */
#else
        BLAKE2S_complete(pKeyPtr, keyLen, pMessage, inLen, pResult, MOC_BLAKE2S_MAX_OUTLEN); /* ignore status */
#endif
        counter++;
        pMessage[0]++; /* change the message for the next test */
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING BLAKE2S %s, input length = %d bytes\n", isMac ? "MAC" : "HASH", inLen);
    
    printf("Result:\n\t%d test hashes in %g seconds of CPU time\n", counter, diffTime);
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
#endif /* __ENABLE_DIGICERT_BLAKE_2S__ */

int blake2_perf_test_all()
{
    int retVal = 0;
    
#ifdef __ENABLE_DIGICERT_BLAKE_2B__
    /* A single blocksize of input */
    retVal += perfTestBlake2B(MOC_BLAKE2B_BLOCKLEN, FALSE);
    retVal += perfTestBlake2B(16384, FALSE);
    
    retVal += perfTestBlake2B(MOC_BLAKE2B_BLOCKLEN, TRUE);
    retVal += perfTestBlake2B(16384, TRUE);
#else
    printf("BLAKE2B: DISABLED, NO TESTS RUN\n");
#endif
    
#ifdef __ENABLE_DIGICERT_BLAKE_2S__
    /* A single blocksize of input */
    retVal += perfTestBlake2S(MOC_BLAKE2S_BLOCKLEN, FALSE);
    retVal += perfTestBlake2S(16384, FALSE);
    
    retVal += perfTestBlake2S(MOC_BLAKE2S_BLOCKLEN, TRUE);
    retVal += perfTestBlake2S(16384, TRUE);
#else
    printf("BLAKE2S: DISABLED, NO TESTS RUN\n");
#endif
    
    return retVal;
}
