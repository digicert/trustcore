/*
 * aes_gcm_perf_test.c
 *
 * performance test for aes-gcm
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

#include "../../crypto/aes.h"
#include "../../crypto/aes_ctr.h"
#include "../../crypto/gcm.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../../crypto_interface/crypto_interface_aes_gcm.h"
#endif

#include "../../../unit_tests/unittest.h"
#include "../../../unit_tests/unittest_utils.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/times.h>
#include <unistd.h>
#include <signal.h>

#ifdef __ENABLE_PERF_TEST_OPENSSL__
#undef ASN1_ITEM
#include <openssl/crypto.h>
#include <openssl/obj_mac.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
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

#ifdef __ENABLE_DIGICERT_GCM_256B__
static int testGcm256b(ubyte4 keyLen, ubyte4 inLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    BulkCtx pCtx = NULL;

    ubyte pKey[32];  /* big enough for all sizes */
    ubyte pIv[12];
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
    
    for (i = 0; i < keyLen; i++)
        pKey[i] = (ubyte) ((i + 1) & 0xff);

    for (i = 0; i < 12; i++)
        pIv[i] = (ubyte) ((i + 2) & 0xff);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    pCtx = CRYPTO_INTERFACE_GCM_createCtx_256b(pKey, keyLen, 1);
#else
    pCtx = GCM_createCtx_256b(pKey, keyLen, 1);
#endif
    if (NULL == pCtx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_GCM_init_256b(pCtx, pIv, 12, NULL, 0);
#else
    status = GCM_init_256b(pCtx, pIv, 12, NULL, 0);
#endif
    if (OK != status)
        goto exit;

    /* Testing throughput only, no Aad and no reason to get the tag */    
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {   
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_GCM_update_encrypt_256b(pCtx, pMessage, inLen);
#else
        GCM_update_encrypt_256b(pCtx, pMessage, inLen);
#endif
        counter++;
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING AES-GCM ENCRYPT (256b), key size = %d bits, input length = %d bytes\n", keyLen * 8, inLen);
    
    printf("Result:\n\t%d test encryptions in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

    /* Reset and decrypt */

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_GCM_deleteCtx_256b(&pCtx);
#else
    status = GCM_deleteCtx_256b(&pCtx);
#endif
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    pCtx = CRYPTO_INTERFACE_GCM_createCtx_256b(pKey, keyLen, 0);
#else
    pCtx = GCM_createCtx_256b(pKey, keyLen, 0);
#endif
    if (NULL == pCtx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_GCM_init_256b(pCtx, pIv, 12, NULL, 0);
#else
    status = GCM_init_256b(pCtx, pIv, 12, NULL, 0);
#endif
    if (OK != status)
        goto exit;

    /* Testing throughput only, no Aad and no reason to get the tag */  
    counter = 0;  
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_GCM_update_decrypt_256b(pCtx, pMessage, inLen);
#else
        GCM_update_decrypt_256b(pCtx, pMessage, inLen);
#endif
        counter++;
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING AES-GCM DECRYPT (256b), key size = %d bits, input length = %d bytes\n", keyLen * 8, inLen);
    
    printf("Result:\n\t%d test decryptions in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

exit:
        
    if (NULL != pCtx)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_GCM_deleteCtx_256b(&pCtx);
#else
        GCM_deleteCtx_256b(&pCtx);
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
#endif /* __ENABLE_DIGICERT_GCM_256B__ */

#ifdef __ENABLE_DIGICERT_GCM_4K__
static int testGcm4k(ubyte4 keyLen, ubyte4 inLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    BulkCtx pCtx = NULL;

    ubyte pKey[32];  /* big enough for all sizes */
    ubyte pIv[12];
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
    
    for (i = 0; i < keyLen; i++)
        pKey[i] = (ubyte) ((i + 1) & 0xff);

    for (i = 0; i < 12; i++)
        pIv[i] = (ubyte) ((i + 2) & 0xff);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    pCtx = CRYPTO_INTERFACE_GCM_createCtx_4k(pKey, keyLen, 1);
#else
    pCtx = GCM_createCtx_4k(pKey, keyLen, 1);
#endif
    if (NULL == pCtx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_GCM_init_4k(pCtx, pIv, 12, NULL, 0);
#else
    status = GCM_init_4k(pCtx, pIv, 12, NULL, 0);
#endif
    if (OK != status)
        goto exit;

    /* Testing throughput only, no Aad and no reason to get the tag */    
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_GCM_update_encrypt_4k(pCtx, pMessage, inLen);
#else
        GCM_update_encrypt_4k(pCtx, pMessage, inLen);
#endif
        counter++;
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING AES-GCM ENCRYPT (4k), key size = %d bits, input length = %d bytes\n", keyLen * 8, inLen);
    
    printf("Result:\n\t%d test encryptions in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

    /* Reset and decrypt */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_GCM_deleteCtx_4k(&pCtx);
#else
    status = GCM_deleteCtx_4k(&pCtx);
#endif
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    pCtx = CRYPTO_INTERFACE_GCM_createCtx_4k(pKey, keyLen, 0);
#else
    pCtx = GCM_createCtx_4k(pKey, keyLen, 0);
#endif
    if (NULL == pCtx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_GCM_init_4k(pCtx, pIv, 12, NULL, 0);
#else
    status = GCM_init_4k(pCtx, pIv, 12, NULL, 0);
#endif
    if (OK != status)
        goto exit;

    /* Testing throughput only, no Aad and no reason to get the tag */  
    counter = 0;  
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_GCM_update_decrypt_4k(pCtx, pMessage, inLen);
#else
        GCM_update_decrypt_4k(pCtx, pMessage, inLen);
#endif
        counter++;
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING AES-GCM DECRYPT (4k), key size = %d bits, input length = %d bytes\n", keyLen * 8, inLen);
    
    printf("Result:\n\t%d test decryptions in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

exit:
        
    if (NULL != pCtx)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_GCM_deleteCtx_4k(&pCtx);
#else
        GCM_deleteCtx_4k(&pCtx);
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
#endif /* __ENABLE_DIGICERT_GCM_4K__ */

#ifdef __ENABLE_DIGICERT_GCM_64K__
static int testGcm64k(ubyte4 keyLen, ubyte4 inLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    BulkCtx pCtx = NULL;

    ubyte pKey[32];  /* big enough for all sizes */
    ubyte pIv[12];
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
    
    for (i = 0; i < keyLen; i++)
        pKey[i] = (ubyte) ((i + 1) & 0xff);

    for (i = 0; i < 12; i++)
        pIv[i] = (ubyte) ((i + 2) & 0xff);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    pCtx = CRYPTO_INTERFACE_GCM_createCtx_64k(pKey, keyLen, 1);
#else
    pCtx = GCM_createCtx_64k(pKey, keyLen, 1);
#endif
    if (NULL == pCtx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_GCM_init_64k(pCtx, pIv, 12, NULL, 0);
#else
    status = GCM_init_64k(pCtx, pIv, 12, NULL, 0);
#endif
    if (OK != status)
        goto exit;

    /* Testing throughput only, no Aad and no reason to get the tag */    
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_GCM_update_encrypt_64k(pCtx, pMessage, inLen);
#else
        GCM_update_encrypt_64k(pCtx, pMessage, inLen);
#endif
        counter++;
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING AES-GCM ENCRYPT (64k), key size = %d bits, input length = %d bytes\n", keyLen * 8, inLen);
    
    printf("Result:\n\t%d test encryptions in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

    /* Reset and decrypt */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_GCM_deleteCtx_64k(&pCtx);
#else
    status = GCM_deleteCtx_64k(&pCtx);
#endif
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    pCtx = CRYPTO_INTERFACE_GCM_createCtx_64k(pKey, keyLen, 0);
#else
    pCtx = GCM_createCtx_64k(pKey, keyLen, 0);
#endif
    if (NULL == pCtx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_GCM_init_64k(pCtx, pIv, 12, NULL, 0);
#else
    status = GCM_init_64k(pCtx, pIv, 12, NULL, 0);
#endif
    if (OK != status)
        goto exit;

    /* Testing throughput only, no Aad and no reason to get the tag */  
    counter = 0;  
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_GCM_update_decrypt_64k(pCtx, pMessage, inLen);
#else
        GCM_update_decrypt_64k(pCtx, pMessage, inLen);
#endif
        counter++;
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING AES-GCM DECRYPT (64k), key size = %d bits, input length = %d bytes\n", keyLen * 8, inLen);
    
    printf("Result:\n\t%d test decryptions in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

exit:
        
    if (NULL != pCtx)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_GCM_deleteCtx_64k(&pCtx);
#else
        GCM_deleteCtx_64k(&pCtx);
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
#endif /* __ENABLE_DIGICERT_GCM_64K__ */

#ifdef __ENABLE_PERF_TEST_OPENSSL__
static int testGcmOssl(ubyte4 keyLen, ubyte4 inLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    GCM128_CONTEXT *pCtx = NULL;
    AES_KEY key = {0};

    ubyte pKey[32];  /* big enough for all keys */
    ubyte pIv[12];
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
    
    for (i = 0; i < keyLen; i++)
        pKey[i] = (ubyte) ((i + 1) & 0xff);

    for (i = 0; i < 12; i++)
        pIv[i] = (ubyte) ((i + 2) & 0xff);

    status = (MSTATUS) AES_set_encrypt_key(pKey, keyLen * 8, &key);
    if (OK != status)
        goto exit;

    pCtx = CRYPTO_gcm128_new(&key, (block128_f) AES_encrypt);
    if (NULL == pCtx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    CRYPTO_gcm128_init(pCtx, &key, (block128_f) AES_encrypt);
    CRYPTO_gcm128_setiv(pCtx, (const unsigned char *) pIv, 12);

    /* Testing throughput only, no Aad and no reason to get the tag */  
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {   
        CRYPTO_gcm128_encrypt(pCtx, (const unsigned char *) pMessage, pMessage, (size_t) inLen); /* ignore return status */
        counter++;
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("OPENSSL TESTING AES-GCM ENCRYPT, key size = %d bits, input length = %d bytes\n", keyLen * 8, inLen);
    
    printf("Result:\n\t%d test decryptions in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

    /* reset and decrypt */
    CRYPTO_gcm128_release(pCtx);

    status = (MSTATUS) AES_set_decrypt_key(pKey, keyLen * 8, &key);
    if (OK != status)
        goto exit;

    pCtx = CRYPTO_gcm128_new(&key, (block128_f) AES_decrypt);
    if (NULL == pCtx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    CRYPTO_gcm128_init(pCtx, &key, (block128_f) AES_decrypt);
    CRYPTO_gcm128_setiv(pCtx, (const unsigned char *) pIv, 12);

    /* Testing throughput only, no Aad and no reason to get the tag */  
    counter = 0;
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {   
        CRYPTO_gcm128_decrypt(pCtx, (const unsigned char *) pMessage, pMessage, (size_t) inLen); /* ignore return status */
        counter++;
    }
    times(&tend);

    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("OPENSSL TESTING AES-GCM DECRYPT, key size = %d bits, input length = %d bytes\n", keyLen * 8, inLen);
    
    printf("Result:\n\t%d test decryptions in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

exit:

    if (NULL != pMessage)
        DIGI_FREE((void **) &pMessage);

    if (NULL != pCtx)
        CRYPTO_gcm128_release(pCtx);

    if (OK != status)
    {
        printf("OPENSSL GCM TEST FAIL, status = %d\n", (int) status);
        return 1;
    }
    
    return 0;
}
#endif

int aes_gcm_perf_test_all()
{
    int retVal = 0;

#ifdef __ENABLE_DIGICERT_GCM_256B__
#ifdef __ENABLE_PERF_TEST_ALL_BLOCK_SIZES__
    retVal += testGcm256b(16, 16);
    retVal += testGcm256b(24, 16);
    retVal += testGcm256b(32, 16);
    retVal += testGcm256b(16, 1024);
    retVal += testGcm256b(24, 1024);
    retVal += testGcm256b(32, 1024);
#endif
    retVal += testGcm256b(16, 16384);
    retVal += testGcm256b(24, 16384);
    retVal += testGcm256b(32, 16384);
#endif


#ifdef __ENABLE_DIGICERT_GCM_4K__
#ifdef __ENABLE_PERF_TEST_ALL_BLOCK_SIZES__
    retVal += testGcm4k(16, 16);
    retVal += testGcm4k(24, 16);
    retVal += testGcm4k(32, 16);
    retVal += testGcm4k(16, 1024);
    retVal += testGcm4k(24, 1024);
    retVal += testGcm4k(32, 1024);
#endif
    retVal += testGcm4k(16, 16384);
    retVal += testGcm4k(24, 16384);
    retVal += testGcm4k(32, 16384);
#endif

#ifdef __ENABLE_DIGICERT_GCM_64K__
#ifdef __ENABLE_PERF_TEST_ALL_BLOCK_SIZES__
    retVal += testGcm64k(16, 16);
    retVal += testGcm64k(24, 16);
    retVal += testGcm64k(32, 16);
    retVal += testGcm64k(16, 1024);
    retVal += testGcm64k(24, 1024);
    retVal += testGcm64k(32, 1024);
#endif
    retVal += testGcm64k(16, 16384);
    retVal += testGcm64k(24, 16384);
    retVal += testGcm64k(32, 16384);
#endif

#ifdef __ENABLE_PERF_TEST_OPENSSL__
#ifdef __ENABLE_PERF_TEST_ALL_BLOCK_SIZES__
    retVal += testGcmOssl(16, 16);
    retVal += testGcmOssl(24, 16);
    retVal += testGcmOssl(32, 16);
    retVal += testGcmOssl(16, 1024);
    retVal += testGcmOssl(24, 1024);
    retVal += testGcmOssl(32, 1024);
#endif
    retVal += testGcmOssl(16, 16384);
    retVal += testGcmOssl(24, 16384);
    retVal += testGcmOssl(32, 16384);
#endif

    return retVal;
}
