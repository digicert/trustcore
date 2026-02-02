/*
 * aes_ofb_test.c
 *
 * unit test for aes.c OFB mode
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
    sig; /* to get rid of unused warnings */
    mContinueTest = 0;
}

#endif   /* defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined( __RTOS_SOLARIS__) || defined(__RTOS_OPENBSD__) */


/*------------------------------------------------------------------*/

/* #define __ENABLE_AES_OFB_TEST_DEBUG__ */

#if (defined(__ENABLE_AES_OFB_TEST_DEBUG__))
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

TestDescr aesOfbTestVectors128[] =
{
    {
        "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",   
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",   
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51",   
        "\x3b\x3f\xd9\x2e\xb7\x2d\xad\x20\x33\x34\x49\xf8\xe8\x3c\xfb\x4a\x77\x89\x50\x8d\x16\x91\x8f\x03\xf5\x3c\x52\xda\xc5\x4e\xd8\x25",
        "\xD9\xA4\xDA\xDA\x08\x92\x23\x9F\x6B\x8B\x3D\x76\x80\xE1\x56\x74",
    },
};


/*------------------------------------------------------------------*/

TestDescr aesOfbTestVectors192[] =
{
    {
        "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51",
        "\xcd\xc8\x0d\x6f\xdd\xf1\x8c\xab\x34\xc2\x59\x09\xc9\x9a\x41\x74\xfc\xc2\x8b\x8d\x4c\x63\x83\x7c\x09\xe8\x17\x00\xc1\x10\x04\x01",
        "\x52\xEF\x01\xDA\x52\x60\x2F\xE0\x97\x5F\x78\xAC\x84\xBF\x8A\x50",
    },
};




/*------------------------------------------------------------------*/

TestDescr aesOfbTestVectors256[] =
{
    {
        "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51",
        "\xdc\x7e\x84\xbf\xda\x79\x16\x4b\x7e\xcd\x84\x86\x98\x5d\x38\x60\x4f\xeb\xdc\x67\x40\xd2\x0b\x3a\xc8\x8f\x6a\xd8\x2a\x4f\xb0\x8d",
        "\xE1\xC6\x56\x30\x5E\xD1\xA7\xA6\x56\x38\x05\x74\x6F\xE0\x3E\xDC",
     },
};



/*------------------------------------------------------------------*/

#if (defined(__ENABLE_AES_OFB_TEST_DEBUG__))
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
generic_aes_ofb_test(TestDescr aesOfbTestVectors[], sbyte4 numVectors, sbyte4 keySize)
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

    retVal = 0;

    for (i = 0; i < numVectors; ++i)
    {
        /* clone data for test */
        DIGI_MEMCPY(pKey,       (ubyte *)(aesOfbTestVectors[i].key), keySize);
        DIGI_MEMCPY(pIvEncrypt, (ubyte *)(aesOfbTestVectors[i].iv), 16);
        DIGI_MEMCPY(pIvDecrypt, (ubyte *)(aesOfbTestVectors[i].iv), 16);
        DIGI_MEMCPY(pText,      (ubyte *)(aesOfbTestVectors[i].text), 32);

#if (defined(__ENABLE_AES_OFB_TEST_DEBUG__))
        printf("{\n");
        dumpHex("plain text", pText, 32);
        printf("======\n");
#endif
 
        /* encrypt test */
	
        if (NULL == (ctx = CreateAESOFBCtx(MOC_SYM(hwAccelCtx) pKey, keySize, TRUE)))
        {
 #if (defined(__ENABLE_AES_OFB_TEST_DEBUG__))
            printf("generic_aes_ofb_test: CreateAESOFBCtx failed, keySize = %d.\n", keySize);
#endif
           retVal++;
           continue;
        }

        if (OK > (status = DoAES(MOC_SYM(hwAccelCtx) ctx, pText, 32, TRUE, pIvEncrypt)))
        {
#if (defined(__ENABLE_AES_OFB_TEST_DEBUG__))
            printf("generic_aes_ofb_test: DoAES failed, keySize = %d.\n", keySize);
#endif
            retVal++;
            continue;
        }
		
        if (OK > (status = DeleteAESCtx(MOC_SYM(hwAccelCtx) &ctx)))
        {
#if (defined(__ENABLE_AES_OFB_TEST_DEBUG__))
    printf("generic_aes_ofb_test: DeleteAESCtx failed, keySize = %d\n", keySize);
#endif
            retVal++;
            continue;
        }

#if (defined(__ENABLE_AES_OFB_TEST_DEBUG__))        
        dumpHex("encrypted text", pText, 32);
        dumpHex("key", pKey, keySize);
        dumpHex("iv", pIvEncrypt, 16);
        printf("======\n");
#endif

        /* verify encryption */
        if (OK > (status = DIGI_MEMCMP((ubyte *)(aesOfbTestVectors[i].encrypt), pText, 32, &cmpResult)))
        {
            retVal++;
            continue;
        }

        if (0 != cmpResult)
        {
#if (defined(__ENABLE_AES_OFB_TEST_DEBUG__))
            printf("generic_aes_ofb_test: encryption test failed, keySize = %d.\n", keySize);
#endif
            retVal++;
        }

        if (OK > (status = DIGI_MEMCMP((ubyte *)(aesOfbTestVectors[i].final_iv), pIvEncrypt, 16, &cmpResult)))
        {
            retVal++;
            continue;
        }

        if (0 != cmpResult)
        {
#if (defined(__ENABLE_AES_OFB_TEST_DEBUG__))
            printf("generic_aes_ofb_test: encryption iv test failed, keySize = %d.\n", keySize);
#endif
            retVal++;
        }

        /* decrypt test */
        if (NULL == (ctx = CreateAESOFBCtx(MOC_SYM(hwAccelCtx) pKey, keySize, FALSE)))
        {
#if (defined(__ENABLE_AES_OFB_TEST_DEBUG__))
            printf("generic_aes_ofb_test: CreateAESOFBCtx failed, keySize = %d.\n", keySize);
#endif
            retVal++;
            continue;
        }

        if (OK > (status = DoAES(MOC_SYM(hwAccelCtx) ctx, pText, 32, FALSE, pIvDecrypt)))
        {
#if (defined(__ENABLE_AES_OFB_TEST_DEBUG__))
            printf("generic_aes_ofb_test: DoAES failed, keySize = %d.\n", keySize);
#endif
            retVal++;
            continue;
        }

        if (OK > (status = DeleteAESCtx(MOC_SYM(hwAccelCtx) &ctx)))
        {
#if (defined(__ENABLE_AES_OFB_TEST_DEBUG__))
    printf("generic_aes_ofb_test: DeleteAESCtx failed, keySize = %d\n", keySize);
#endif
            retVal++;
            continue;
        }

#if (defined(__ENABLE_AES_OFB_TEST_DEBUG__))
        dumpHex("decrypted text", pText, 32);
        dumpHex("key", pKey, keySize);
        dumpHex("iv", pIvDecrypt, 16);
        printf("}\n");
#endif

        /* verify decryption */
        if (OK > (status = DIGI_MEMCMP((ubyte *)(aesOfbTestVectors[i].text), pText, 32, &cmpResult)))
        {
            retVal++;
            continue;
        }

        if (0 != cmpResult)
        {
#if (defined(__ENABLE_AES_OFB_TEST_DEBUG__))
            printf("generic_aes_ofb_test: decryption test failed, keySize = %d.\n", keySize);
#endif
            retVal++;
        }

        if (OK > (status = DIGI_MEMCMP((ubyte *)(aesOfbTestVectors[i].final_iv), pIvDecrypt, 16, &cmpResult)))
        {
            retVal++;
            continue;
        }

        if (0 != cmpResult)
        {
#if (defined(__ENABLE_AES_OFB_TEST_DEBUG__))
            printf("generic_aes_ofb_test: decryption iv test failed, keySize = %d.\n", keySize);
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
        ctx = CreateAESOFBCtx(MOC_SYM(hwAccelCtx) pKey, keySize, TRUE);

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

        printf("\tAES_OFB (%d): %d kbytes in %g seconds of CPU time\n",
               keySize*8, counter, diffTime);
        printf("AES_OFB (%d): %g kbytes/second (CPU time) (1 kbyte = 1024 bytes)\n",
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

int aes_ofb_test_vectors128()
{
    return generic_aes_ofb_test(aesOfbTestVectors128, (sizeof(aesOfbTestVectors128)/ sizeof(TestDescr)), 16);
}


/*------------------------------------------------------------------*/

int aes_ofb_test_vectors192()
{
    return generic_aes_ofb_test(aesOfbTestVectors192, (sizeof(aesOfbTestVectors192)/ sizeof(TestDescr)), 24);
}


/*------------------------------------------------------------------*/

int aes_ofb_test_vectors256()
{
    return generic_aes_ofb_test(aesOfbTestVectors256, (sizeof(aesOfbTestVectors256)/ sizeof(TestDescr)), 32);
}

