/*
 * chachapoly_perf_test.c
 *
 * performance test for chacha20 and chacha20_poly1305 AEAD
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

#include "../../crypto/chacha20.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../../crypto_interface/crypto_interface_chacha20.h"
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

#ifdef __ENABLE_DIGICERT_CHACHA20__
static int perfTestChaCha20(ubyte4 inLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    BulkCtx pCtx = NULL;

    ubyte pKey[48];
    int i;
    
    struct tms tstart, tend;
    double diffTime, kbytes;
    ubyte4 counter = 0;
    
    status = DIGI_MALLOC((void **) &pMessage, inLen);
    if (OK != status)
        goto exit;
   
    /* set the message and key to some dummy data but not all zero */
    for (i = 0; i < inLen; i++)
        pMessage[i] = (ubyte) (i & 0xff);
    
    for (i = 0; i < 48; i++)
        pKey[i] = (ubyte) (i & 0xff);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    pCtx = CRYPTO_INTERFACE_CreateChaCha20Ctx(pKey, 48, 1);
#else
    pCtx = CreateChaCha20Ctx(pKey, 48, 1);
#endif
    if (NULL == pCtx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DoChaCha20(pCtx, pMessage, inLen, 1, NULL); /* ignore status */
#else
        DoChaCha20(pCtx, pMessage, inLen, 1, NULL); /* ignore status */
#endif
        counter++;
        pMessage[0]++; /* change the message for the next test */
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING CHACHA20, input length = %d bytes\n", inLen);
    
    printf("Result:\n\t%d test encryptions in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

    
exit:
    
    if (NULL != pCtx)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DeleteChaCha20Ctx(&pCtx);
#else
        DeleteChaCha20Ctx(&pCtx);
#endif
    
    if (NULL != pMessage)
        DIGI_FREE((void **) &pMessage);
    
    if (OK != status)
    {
        printf("TEST FAILURE, status = %d\n", status);
        return 1;
    }
    
    return 0;
}

#ifdef __ENABLE_DIGICERT_POLY1305__
static int perfTestChaChaPoly(ubyte4 inLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    BulkCtx pCtx = NULL;
    
    ubyte pKey[44];
    ubyte *pNonce = pKey + 32; /* 12 byte nonce */
    int i;
    
    struct tms tstart, tend;
    double diffTime, kbytes;
    ubyte4 counter = 0;
    
    status = DIGI_MALLOC((void **) &pMessage, inLen + 16); /* add room for the tag */
    if (OK != status)
        goto exit;
    
    /* set the message and key to some dummy data but not all zero */
    for (i = 0; i < inLen; i++)
        pMessage[i] = (ubyte) (i & 0xff);
    
    for (i = 0; i < 44; i++)
        pKey[i] = (ubyte) (i & 0xff);
    
    /* Encrypt, tag */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    pCtx = CRYPTO_INTERFACE_ChaCha20Poly1305_createCtx(pKey, 32, 1);
#else
    pCtx = ChaCha20Poly1305_createCtx(pKey, 32, 1);
#endif
    if (NULL == pCtx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_ChaCha20Poly1305_cipher(pCtx, pNonce, 12, NULL, 0, pMessage, inLen, 16, 1); /* ignore status */
#else
        ChaCha20Poly1305_cipher(pCtx, pNonce, 12, NULL, 0, pMessage, inLen, 16, 1); /* ignore status */
#endif
        counter++;
        pMessage[0]++; /* change the message for the next test */
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING CHACHA20_POLY1305 AEAD Encrypt, input length = %d bytes. (no aad).\n", inLen);
    
    printf("Result:\n\t%d test encryptions in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);
    
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_ChaCha20Poly1305_deleteCtx(&pCtx);
#else
    status = ChaCha20Poly1305_deleteCtx(&pCtx);
#endif
    if (OK != status)
        goto exit;
    
    /* Decrypt, verify */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    pCtx = CRYPTO_INTERFACE_ChaCha20Poly1305_createCtx(pKey, 32, 0);
#else
    pCtx = ChaCha20Poly1305_createCtx(pKey, 32, 0);
#endif
    if (NULL == pCtx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_ChaCha20Poly1305_cipher(pCtx, pNonce, 12, NULL, 0, pMessage, inLen, 16, 0); /* ignore status, verify failure time is same as success */
#else
        ChaCha20Poly1305_cipher(pCtx, pNonce, 12, NULL, 0, pMessage, inLen, 16, 0); /* ignore status, verify failure time is same as success */
#endif
        counter++;
        pMessage[0]++; /* change the message for the next test */
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING CHACHA20_POLY1305 AEAD Decrypt/Verify, input length = %d bytes. (no aad).\n", inLen);
    
    printf("Result:\n\t%d test decryptions in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);
    
exit:
    
    if (NULL != pCtx)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_ChaCha20Poly1305_deleteCtx(&pCtx);
#else
        ChaCha20Poly1305_deleteCtx(&pCtx);
#endif
    
    if (NULL != pMessage)
        DIGI_FREE((void **) &pMessage);
    
    if (OK != status)
    {
        printf("TEST FAILURE, status = %d\n", status);
        return 1;
    }
    
    return 0;
}
#endif /* __ENABLE_DIGICERT_POLY1305__ */
#endif /* __ENABLE_DIGICERT_CHACHA20__ */

int chachapoly_perf_test_all()
{
    int retVal = 0;
    
#ifdef __ENABLE_DIGICERT_CHACHA20__
    /* A single blocksize of input */
    retVal += perfTestChaCha20(64);
    retVal += perfTestChaCha20(1024);
    retVal += perfTestChaCha20(16384);

#ifdef __ENABLE_DIGICERT_POLY1305__
    /* A single blocksize of input */
    retVal += perfTestChaChaPoly(64);
    retVal += perfTestChaChaPoly(1024);
    retVal += perfTestChaChaPoly(16384);
#else
    printf("POLY1305: DISABLED, NO AEAD TESTS RUN\n");
#endif
    
#else
    printf("CHACHA20: DISABLED, NO TESTS RUN\n");
#endif
    
    return retVal;
}
