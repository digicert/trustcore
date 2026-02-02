/*
 * aes_perf_test.c
 *
 * performance test for aes-cbc and aes-ctr 
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

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../../crypto_interface/crypto_interface_aes.h"
#include "../../crypto_interface/crypto_interface_aes_ctr.h"
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

static int perfTestAesCbc(ubyte4 keyLen, ubyte4 inLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    BulkCtx pCtx = NULL;

    ubyte pKey[32];  /* big enough for all sizes */
    ubyte pIv[16];
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

    for (i = 0; i < 16; i++)
        pIv[i] = (ubyte) ((i + 2) & 0xff);


#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    pCtx = CRYPTO_INTERFACE_CreateAESCtx(pKey, keyLen, 1);
#else
    pCtx = CreateAESCtx(pKey, keyLen, 1);
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
        CRYPTO_INTERFACE_DoAES(pCtx, pMessage, inLen, 1, pIv); /* ignore status */
#else
        DoAES(pCtx, pMessage, inLen, 1, pIv); /* ignore status */
#endif
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING AES-CBC ENCRYPT, key size = %d bits, input length = %d bytes\n", keyLen * 8, inLen);
    
    printf("Result:\n\t%d test encryptions in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);
     
    /* reset and now time decryption */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DeleteAESCtx(&pCtx);
#else
    status = DeleteAESCtx(&pCtx);
#endif
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    pCtx = CRYPTO_INTERFACE_CreateAESCtx(pKey, keyLen, 0);
#else
    pCtx = CreateAESCtx(pKey, keyLen, 0);
#endif
    if (NULL == pCtx)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    
    counter = 0;
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DoAES(pCtx, pMessage, inLen, 0, pIv); /* ignore status */
#else
        DoAES(pCtx, pMessage, inLen, 0, pIv); /* ignore status */
#endif
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING AES-CBC DECRYPT, key size = %d bits, input length = %d bytes\n", keyLen * 8, inLen);
    
    printf("Result:\n\t%d test decryptions in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);

exit:
    
    if (NULL != pCtx)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DeleteAESCtx(&pCtx);
#else
        DeleteAESCtx(&pCtx);
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

static int perfTestAesCtr(ubyte4 keyLen, ubyte4 inLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    BulkCtx pCtx = NULL;

    ubyte pKey[48];  /* big enough for all sizes */
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
    
    keyLen += 16; /* we'll add the 16 byte initial ctr after the key */
    for (i = 0; i < keyLen; i++)   
        pKey[i] = (ubyte) ((i + 1) & 0xff);

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    pCtx = CRYPTO_INTERFACE_CreateAESCTRCtx(pKey, keyLen, 0);
#else
    pCtx = CreateAESCTRCtx(pKey, keyLen, 0);
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
        CRYPTO_INTERFACE_DoAESCTR(pCtx, pMessage, inLen, 0, NULL); /* ignore status */
#else
        DoAESCTR(pCtx, pMessage, inLen, 0, NULL); /* ignore status */
#endif
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("TESTING AES-CTR, key size = %d bits, input length = %d bytes\n", (keyLen - 16) * 8, inLen);
    
    printf("Result:\n\t%d test encryptions (or decryptions) in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);
     
exit:
    
    if (NULL != pCtx)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_DeleteAESCTRCtx(&pCtx);
#else
        DeleteAESCTRCtx(&pCtx);
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

#ifdef __ENABLE_PERF_TEST_OPENSSL__

static int perfTestAesCbcOssl(ubyte4 keyLen, ubyte4 inLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    AES_KEY key = {0};

    ubyte pKey[32];  /* big enough for all sizes */
    ubyte pIv[16];
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

    for (i = 0; i < 16; i++)
        pIv[i] = (ubyte) ((i + 2) & 0xff);

    status = (MSTATUS) AES_set_encrypt_key(pKey, keyLen * 8, &key);
    if (OK != status)
        goto exit;

    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        CRYPTO_cbc128_encrypt((const unsigned char *) pMessage, pMessage, (size_t) inLen, &key, pIv, (block128_f) AES_encrypt);
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("OPENSSL TESTING AES-CBC ENCRYPT, key size = %d bits, input length = %d bytes\n", keyLen * 8, inLen);
    
    printf("Result:\n\t%d test encryptions in %g seconds of CPU time\n", counter, diffTime);
    printf("\t%g kbytes/second (CPU time, 1 kbyte = 1024 bytes)\n\n", kbytes/diffTime);
     
    /* reset and now time decryption */
    status = DIGI_MEMSET((ubyte *) &key, 0x00, sizeof(AES_KEY));
    if (OK != status)
        goto exit;

    status = (MSTATUS) AES_set_decrypt_key(pKey, keyLen * 8, &key);
    if (OK != status)
        goto exit;

    counter = 0;
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        CRYPTO_cbc128_decrypt((const unsigned char *) pMessage, pMessage, (size_t) inLen, &key, pIv, (block128_f) AES_decrypt);
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("OPENSSL TESTING AES-CBC DECRYPT, key size = %d bits, input length = %d bytes\n", keyLen * 8, inLen);
    
    printf("Result:\n\t%d test decryptions in %g seconds of CPU time\n", counter, diffTime);
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

static int perfTestAesCtrOssl(ubyte4 keyLen, ubyte4 inLen)
{
    MSTATUS status = OK;
    ubyte *pMessage = NULL;
    AES_KEY key = {0};
    ubyte pECountBuf[16] = {0};
    ubyte4 num = 0;

    ubyte pIv[16];
    ubyte pKey[32];  /* big enough for all sizes */
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
    
    for (i = 0; i < 16; i++)
        pIv[i] = (ubyte) ((i + 2) & 0xff);

    status = (MSTATUS) AES_set_encrypt_key(pKey, keyLen * 8, &key);
    if (OK != status)
        goto exit;
        
    START_ALARM(TEST_SECONDS);
    times(&tstart);
    while( ALARM_OFF)
    {
        CRYPTO_ctr128_encrypt((const unsigned char *) pMessage, pMessage, (size_t) inLen, &key, pIv, pECountBuf, &num, (block128_f) AES_encrypt);
        counter++;
    }
    times(&tend);
    
    diffTime = tend.tms_utime-tstart.tms_utime;
    diffTime /= sysconf(_SC_CLK_TCK);
    kbytes = inLen * (counter / 1024.0);
    printf("OPENSSL TESTING AES-CTR, key size = %d bits, input length = %d bytes\n", keyLen * 8, inLen);
    
    printf("Result:\n\t%d test encryptions (or decryptions) in %g seconds of CPU time\n", counter, diffTime);
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
#endif /* __ENABLE_PERF_TEST_OPENSSL__ */

int aes_perf_test_all()
{
    int retVal = 0;

#ifdef __ENABLE_PERF_TEST_ALL_BLOCK_SIZES__
    retVal += perfTestAesCbc(16, 16);
    retVal += perfTestAesCbc(16, 1024);
#endif
    retVal += perfTestAesCbc(16, 16384);

#ifdef __ENABLE_PERF_TEST_ALL_BLOCK_SIZES__
    retVal += perfTestAesCbc(24, 16);
    retVal += perfTestAesCbc(24, 1024);
#endif
    retVal += perfTestAesCbc(24, 16384);

#ifdef __ENABLE_PERF_TEST_ALL_BLOCK_SIZES__
    retVal += perfTestAesCbc(32, 16);
    retVal += perfTestAesCbc(32, 1024);
#endif
    retVal += perfTestAesCbc(32, 16384);

#ifdef __ENABLE_PERF_TEST_OPENSSL__

#ifdef __ENABLE_PERF_TEST_ALL_BLOCK_SIZES__
    retVal += perfTestAesCbcOssl(16, 16); 
    retVal += perfTestAesCbcOssl(16, 1024);
#endif
    retVal += perfTestAesCbcOssl(16, 16384);

#ifdef __ENABLE_PERF_TEST_ALL_BLOCK_SIZES__
    retVal += perfTestAesCbcOssl(24, 16);
    retVal += perfTestAesCbcOssl(24, 1024);
#endif
    retVal += perfTestAesCbcOssl(24, 16384);

#ifdef __ENABLE_PERF_TEST_ALL_BLOCK_SIZES__
    retVal += perfTestAesCbcOssl(32, 16);
    retVal += perfTestAesCbcOssl(32, 1024);
#endif
    retVal += perfTestAesCbcOssl(32, 16384);

#endif /* __ENABLE_PERF_TEST_OPENSSL__ */

#ifdef __ENABLE_PERF_TEST_ALL_BLOCK_SIZES__
    retVal += perfTestAesCtr(16, 16);
    retVal += perfTestAesCtr(16, 1024);
#endif
    retVal += perfTestAesCtr(16, 16384);

#ifdef __ENABLE_PERF_TEST_ALL_BLOCK_SIZES__
    retVal += perfTestAesCtr(24, 16);
    retVal += perfTestAesCtr(24, 1024);
#endif
    retVal += perfTestAesCtr(24, 16384);

#ifdef __ENABLE_PERF_TEST_ALL_BLOCK_SIZES__
    retVal += perfTestAesCtr(32, 16);
    retVal += perfTestAesCtr(32, 1024);
#endif
    retVal += perfTestAesCtr(32, 16384);
 
#ifdef __ENABLE_PERF_TEST_OPENSSL__

#ifdef __ENABLE_PERF_TEST_ALL_BLOCK_SIZES__
    retVal += perfTestAesCtrOssl(16, 16);
    retVal += perfTestAesCtrOssl(16, 1024);
#endif
    retVal += perfTestAesCtrOssl(16, 16384);

#ifdef __ENABLE_PERF_TEST_ALL_BLOCK_SIZES__
    retVal += perfTestAesCtrOssl(24, 16);
    retVal += perfTestAesCtrOssl(24, 1024);
#endif
    retVal += perfTestAesCtrOssl(24, 16384);

#ifdef __ENABLE_PERF_TEST_ALL_BLOCK_SIZES__
    retVal += perfTestAesCtrOssl(32, 16);
    retVal += perfTestAesCtrOssl(32, 1024);
#endif
    retVal += perfTestAesCtrOssl(32, 16384);

#endif /* __ENABLE_PERF_TEST_OPENSSL__ */

    return retVal;
}
