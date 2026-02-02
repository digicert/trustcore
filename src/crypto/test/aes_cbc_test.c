/*
 * aes_cbc_test.c
 *
 * unit test for aes.c
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
 *
 */

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"

#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mstdlib.h"
#include "../../common/debug_console.h"
#include "../../crypto/aesalgo.h"
#include "../../crypto/aes.h"
#include "../../harness/harness.h"
#include "../../../unit_tests/unittest.h"


/* for performance testing */
#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__) || defined(__RTOS_OSX__)
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
    /* to get rid of unused warnings */
    mContinueTest = 0;
}

#endif   /* defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined( __RTOS_SOLARIS__) || defined(__RTOS_OPENBSD__) || defined(__RTOS_OSX__) */


/*------------------------------------------------------------------*/

//#define __ENABLE_AES_CBC_TEST_DEBUG__

#if (defined(__ENABLE_AES_CBC_TEST_DEBUG__))
#include <stdio.h>
#endif


/*------------------------------------------------------------------*/

#define MAX_AES_TEXT_STRING     1024


/*------------------------------------------------------------------*/

typedef struct TestDescr
{
    ubyte           key[32];
    ubyte           iv[16];
    ubyte           text[32];

    /* for test verification */
    ubyte           encrypt[32];
    ubyte           final_iv[16];

} TestDescr;


/*------------------------------------------------------------------*/

TestDescr aesCbcTestVectors128[] = 
{
    { "00112233001122330011223300112233", "0011223300112233", "The eagle flies at midnight.1234", "\x3b\xbe\x24\xc5\xe4\x7b\x79\x69\xd4\x61\x4c\x2b\x35\xbc\x8a\x5c\x13\x04\xfc\x56\xba\xa1\x36\xac\xd2\xac\xee\xb2\xd1\x22\x6b\x21", "\x13\x04\xfc\x56\xba\xa1\x36\xac\xd2\xac\xee\xb2\xd1\x22\x6b\x21" },
    { "ss1d33001122330011223300112233dd", "aa11223dd0112233", "One test to rule them. Muwhaaaaa", "\xe8\x58\x96\x94\x75\x7e\x83\xd6\x31\xa2\x9f\x32\xe5\xc2\x97\x3d\xb7\xfb\x30\x99\xb3\xc5\x98\x9b\x0b\x88\x10\x28\x3b\x1a\x4a\xe0", "\xb7\xfb\x30\x99\xb3\xc5\x98\x9b\x0b\x88\x10\x28\x3b\x1a\x4a\xe0" },
    { "01122330011223300112233001122330", "bb112233001vvv33", "They dance at dawn from the West", "\x14\xd4\x6a\x7f\x62\x96\xa6\x5c\x74\xac\xa2\x69\xde\xa7\x4e\x80\xe6\x82\x10\xb0\xc8\x4b\xef\x63\x3a\x22\x45\x55\x95\xc2\xbe\x0c", "\xe6\x82\x10\xb0\xc8\x4b\xef\x63\x3a\x22\x45\x55\x95\xc2\xbe\x0c" },
    { "zzz12233001122xxx01122330011qqq3", "0ccc223300rrr233", "One last hillarious test vector!", "\x9b\x14\x0c\x2c\x09\x2a\x61\xd8\x12\xe2\x87\x77\x9d\x69\xf4\xb6\xd7\x04\x2d\xc2\x4b\x05\xf6\x11\x80\x47\x8c\x88\xe4\x96\x06\xb4", "\xd7\x04\x2d\xc2\x4b\x05\xf6\x11\x80\x47\x8c\x88\xe4\x96\x06\xb4" }
};


/*------------------------------------------------------------------*/

TestDescr aesCbcTestVectors192[] = 
{
    { "00112233001122330011223300112233", "0011223300112233", "The eagle flies at midnight.1234", "\x14\x58\xf6\x8d\x8e\x40\xe7\x11\x20\xf9\xbe\x05\x2c\x61\xe9\x85\x78\xf2\xdd\xef\xf6\xb6\xb2\xc5\x2f\x7d\xeb\xba\xe3\xf5\xd4\x51", "\x78\xf2\xdd\xef\xf6\xb6\xb2\xc5\x2f\x7d\xeb\xba\xe3\xf5\xd4\x51" },
    { "ss1d33001122330011223300112233dd", "aa11223dd0112233", "One test to rule them. Muwhaaaaa", "\x05\xa4\xe5\x66\xbc\x99\x6e\xc5\x5d\xb9\x51\x6b\x84\x77\x3a\x33\x46\xb1\x24\x8f\x75\x2b\xd0\x78\x93\xb7\x2f\xdb\x76\xeb\x34\x24", "\x46\xb1\x24\x8f\x75\x2b\xd0\x78\x93\xb7\x2f\xdb\x76\xeb\x34\x24" },
    { "01122330011223300112233001122330", "bb112233001vvv33", "They dance at dawn from the West", "\x84\x26\xc4\xdd\x44\xa5\x15\xf1\xff\xf6\xe3\x7e\x2c\x3f\x55\x54\xae\xe9\xb5\xa1\xb7\x02\x86\x7f\x99\xb1\x43\xbd\xe5\xb1\x77\x02", "\xae\xe9\xb5\xa1\xb7\x02\x86\x7f\x99\xb1\x43\xbd\xe5\xb1\x77\x02" },
    { "zzz12233001122xxx01122330011qqq3", "0ccc223300rrr233", "One last hillarious test vector!", "\xf7\xe7\x77\x85\x78\xf0\xff\xd6\x10\x20\x26\x57\xa7\x45\xcd\x6d\x5e\xf6\xb3\x58\x0a\x03\xcd\x60\xd0\xc6\x16\x76\x18\xb8\x8f\xed", "\x5e\xf6\xb3\x58\x0a\x03\xcd\x60\xd0\xc6\x16\x76\x18\xb8\x8f\xed" }
};


/*------------------------------------------------------------------*/

TestDescr aesCbcTestVectors256[] = 
{
    { "00112233001122330011223300112233", "0011223300112233", "The eagle flies at midnight.1234", "\x4b\xdc\x26\xda\x26\x1b\x58\xd9\xe6\xeb\x5b\x45\x5d\x59\xb5\x4e\xf9\xaa\x4d\x4b\x34\x46\x36\xea\x35\xd0\x5a\x9a\x2a\xd1\x52\xf9", "\xf9\xaa\x4d\x4b\x34\x46\x36\xea\x35\xd0\x5a\x9a\x2a\xd1\x52\xf9" },
    { "ss1d33001122330011223300112233dd", "aa11223dd0112233", "One test to rule them. Muwhaaaaa", "\x0f\xdd\xdd\xc8\xee\x07\x87\x32\x23\x4a\x09\x35\xe2\xee\x19\x7f\x4f\xec\xb7\xa0\x7b\x8a\x39\xb2\x54\x27\xed\xeb\xb1\x01\xad\xbe", "\x4f\xec\xb7\xa0\x7b\x8a\x39\xb2\x54\x27\xed\xeb\xb1\x01\xad\xbe" },
    { "01122330011223300112233001122330", "bb112233001vvv33", "They dance at dawn from the West", "\xda\x7e\xca\x34\xcd\xc9\x73\x6b\xbe\xdc\xa7\x42\xa8\x39\xc8\x0d\x10\x45\x9d\xc7\x99\x48\xbd\x2c\x57\xd1\xcb\xb7\x48\x4c\x37\xdc", "\x10\x45\x9d\xc7\x99\x48\xbd\x2c\x57\xd1\xcb\xb7\x48\x4c\x37\xdc" },
    { "zzz12233001122xxx01122330011qqq3", "0ccc223300rrr233", "One last hillarious test vector!", "\x7e\x3c\x56\x8f\x60\x37\xe6\x97\xe1\x84\x5f\xed\x26\x05\x30\x91\xad\x48\x12\xa8\x17\x8b\xbf\x8a\x75\x01\xdd\x59\x85\x76\xa3\x4a", "\xad\x48\x12\xa8\x17\x8b\xbf\x8a\x75\x01\xdd\x59\x85\x76\xa3\x4a" }
};


/*------------------------------------------------------------------*/

#if (defined(__ENABLE_AES_CBC_TEST_DEBUG__))
static void
dumpHex(char *pMesg, ubyte *pData, ubyte4 length)
{
    ubyte4 index;

    printf("%s[length = %u] =\n", pMesg, length);

    for (index = 0; index < length; index++)
        printf("\\x%02x", pData[index]);

    printf("\n");
}
#endif


/*------------------------------------------------------------------*/

static int
generic_aes_cbc_test(TestDescr aesCbcTestVectors[], sbyte4 numVectors, sbyte4 keySize)
{
    ubyte4          retVal = 1;
    BulkCtx         ctx;
    sbyte4          i, cmpResult;
    ubyte*          pKey  = NULL;
    ubyte*          pIvEncrypt = NULL;
    ubyte*          pIvDecrypt = NULL;
    ubyte*          pText = NULL;
    hwAccelDescr    hwAccelCtx;
    MSTATUS         status;

    if (OK > (MSTATUS)(retVal = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return retVal;

    /* for harness test... */
    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, 32, TRUE, &pKey)))
        goto exit;

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, 16, TRUE, &pIvEncrypt)))
        goto exit;

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, 16, TRUE, &pIvDecrypt)))
        goto exit;

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, MAX_AES_TEXT_STRING, TRUE, &pText)))
        goto exit;

    /* timing test can use full buffer initialized to all 0x00 */
    (void) DIGI_MEMSET(pText, 0x00, MAX_AES_TEXT_STRING);
    retVal = 0;

    for (i = 0; i < numVectors; ++i)
    {
        /* clone data for test */
        DIGI_MEMCPY(pKey,       (ubyte *)(aesCbcTestVectors[i].key), keySize);
        DIGI_MEMCPY(pIvEncrypt, (ubyte *)(aesCbcTestVectors[i].iv), 16);
        DIGI_MEMCPY(pIvDecrypt, (ubyte *)(aesCbcTestVectors[i].iv), 16);
        DIGI_MEMCPY(pText,      (ubyte *)(aesCbcTestVectors[i].text), 32);

#if (defined(__ENABLE_AES_CBC_TEST_DEBUG__))
        printf("{\n");
        dumpHex("plain text", pText, 32);
        printf("======\n");
#endif

        /* encrypt test */
        if (NULL == (ctx = CreateAESCtx(MOC_SYM(hwAccelCtx) pKey, keySize, TRUE)))
        {
            retVal++;
            continue;
        }

        if (OK > (status = DoAES(MOC_SYM(hwAccelCtx) ctx, pText, 32, TRUE, pIvEncrypt)))
        {
            retVal++;
            continue;
        }

        if (OK > (status = DeleteAESCtx(MOC_SYM(hwAccelCtx) &ctx)))
        {
            retVal++;
            continue;
        }

#if (defined(__ENABLE_AES_CBC_TEST_DEBUG__))
        dumpHex("encrypted text", pText, 32);
        dumpHex("key", pKey, keySize);
        dumpHex("iv", pIvEncrypt, 16);
        printf("======\n");
#endif

        /* verify encryption */
        if (OK > (status = DIGI_MEMCMP((ubyte *)(aesCbcTestVectors[i].encrypt), pText, 32, &cmpResult)))
        {
            retVal++;
            continue;
        }

        if (0 != cmpResult)
        {
#if (defined(__ENABLE_AES_CBC_TEST_DEBUG__))
            printf("generic_aes_cbc_test: encryption test failed, keySize = %d.\n", keySize);
#endif
            retVal++;
        }

        if (OK > (status = DIGI_MEMCMP((ubyte *)(aesCbcTestVectors[i].final_iv), pIvEncrypt, 16, &cmpResult)))
        {
            retVal++;
            continue;
        }

        if (0 != cmpResult)
        {
#if (defined(__ENABLE_AES_CBC_TEST_DEBUG__))
            printf("generic_aes_cbc_test: encryption iv test failed, keySize = %d.\n", keySize);
#endif
            retVal++;
        }

        /* decrypt test */
        if (NULL == (ctx = CreateAESCtx(MOC_SYM(hwAccelCtx) pKey, keySize, FALSE)))
        {
            retVal++;
            continue;
        }

        if (OK > (status = DoAES(MOC_SYM(hwAccelCtx) ctx, pText, 32, FALSE, pIvDecrypt)))
        {
            retVal++;
            continue;
        }

        if (OK > (status = DeleteAESCtx(MOC_SYM(hwAccelCtx) &ctx)))
        {
            retVal++;
            continue;
        }

#if (defined(__ENABLE_AES_CBC_TEST_DEBUG__))
        dumpHex("decrypted text", pText, 32);
        dumpHex("key", pKey, keySize);
        dumpHex("iv", pIvDecrypt, 16);
        printf("}\n");
#endif

        /* verify decryption */
        if (OK > (status = DIGI_MEMCMP((ubyte *)(aesCbcTestVectors[i].text), pText, 32, &cmpResult)))
        {
            retVal++;
            continue;
        }

        if (0 != cmpResult)
        {
#if (defined(__ENABLE_AES_CBC_TEST_DEBUG__))
            printf("generic_aes_cbc_test: decryption test failed, keySize = %d.\n", keySize);
#endif
            retVal++;
        }

        if (OK > (status = DIGI_MEMCMP((ubyte *)(aesCbcTestVectors[i].final_iv), pIvDecrypt, 16, &cmpResult)))
        {
            retVal++;
            continue;
        }

        if (0 != cmpResult)
        {
#if (defined(__ENABLE_AES_CBC_TEST_DEBUG__))
            printf("generic_aes_cbc_test: decryption iv test failed, keySize = %d.\n", keySize);
#endif
            retVal++;
        }
    }
    /* for linux we do a speed test that will be captured in the logs */
#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined (__RTOS_OPENBSD__) || defined(__RTOS_OSX__)
    if (0 == retVal)
    {
        struct tms tstart, tend;
        double diffTime;
        ubyte4 counter;

        /* we are using whatever is there */
        ctx = CreateAESCtx(MOC_SYM(hwAccelCtx) pKey, keySize, TRUE);

        START_ALARM(TEST_SECONDS);
        times(&tstart);
        counter = 0;
        while( ALARM_OFF)
        {
            /* process 1024 bytes */
            DoAES(MOC_SYM(hwAccelCtx) ctx, pText, MAX_AES_TEXT_STRING, TRUE, pIvEncrypt);
            counter++;
        }
        times(&tend);
        diffTime = tend.tms_utime-tstart.tms_utime;
        diffTime /= sysconf(_SC_CLK_TCK);

        printf("\tAES_CBC (%d): %d kbytes in %g seconds of CPU time\n", 
               keySize*8, counter, diffTime);
        printf("AES_CBC (%d): %g kbytes/second (CPU time) (1 kbyte = 1024 bytes)\n", 
               keySize*8, counter/diffTime);

        DeleteAESCtx(MOC_SYM(hwAccelCtx) &ctx);
    }
#endif

exit:

    if (OK > (status = CRYPTO_FREE(hwAccelCtx, TRUE, &pKey)))
        goto exit;

    if (OK > (status = CRYPTO_FREE(hwAccelCtx, TRUE, &pIvEncrypt)))
        goto exit;

    if (OK > (status = CRYPTO_FREE(hwAccelCtx, TRUE, &pIvDecrypt)))
        goto exit;

    if (OK > (status = CRYPTO_FREE(hwAccelCtx, TRUE, &pText)))
        goto exit;
    
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return retVal;
}


/*------------------------------------------------------------------*/

int aes_cbc_test_vectors128()
{
    int retVal = 0;
  
    retVal += generic_aes_cbc_test(aesCbcTestVectors128, (sizeof(aesCbcTestVectors128)/ sizeof(TestDescr)), 16);
  
    DBG_DUMP
    return retVal;
}


/*------------------------------------------------------------------*/

int aes_cbc_test_vectors192()
{
    int retVal = 0;
  
    retVal += generic_aes_cbc_test(aesCbcTestVectors192, (sizeof(aesCbcTestVectors192)/ sizeof(TestDescr)), 24);
  
    DBG_DUMP
    return retVal;
}


/*------------------------------------------------------------------*/

int aes_cbc_test_vectors256()
{
    int retVal = 0;
  
    retVal += generic_aes_cbc_test(aesCbcTestVectors256, (sizeof(aesCbcTestVectors256)/ sizeof(TestDescr)), 32);
  
    DBG_DUMP
    return retVal;
}

