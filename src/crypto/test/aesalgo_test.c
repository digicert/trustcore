/*
 * aesalgo_test.c
 *
 * unit test for AES
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

#endif   /* defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined( __RTOS_SOLARIS__) || defined(__RTOS_OPENBSD__) || defined(__RTOS_OSX__) */


/*------------------------------------------------------------------*/

//#define __ENABLE_AES_TEST_DEBUG__

#if (defined(__ENABLE_AES_TEST_DEBUG__))
#include <stdio.h>
#endif


/*------------------------------------------------------------------*/

#define MAX_AES_TEXT_STRING     1024


/*------------------------------------------------------------------*/

typedef struct TestDescr
{
    ubyte*           key;
    ubyte*           plainText;
    /* for test verification */
    ubyte*           cipherText;
} TestDescr;


/*------------------------------------------------------------------*/

static TestDescr aesTestVectors128[] =
{
    {
        (ubyte*) "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        (ubyte*) "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        (ubyte*) "\x66\xE9\x4B\xD4\xEF\x8A\x2C\x3B\x88\x4C\xFA\x59\xCA\x34\x2B\x2E"
    },
    /* FIPS 197 test vector */
    {
        (ubyte*) "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
        (ubyte*) "\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34",
        (ubyte*) "\x39\x25\x84\x1d\x02\xdc\x09\xfb\xdc\x11\x85\x97\x19\x6a\x0b\x32"
    },
    /* FIPS 197 test vector */
    {
        (ubyte*) "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        (ubyte*) "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
        (ubyte*) "\x69\xc4\xe0\xd8\x6a\x7b\x04\x30\xd8\xcd\xb7\x80\x70\xb4\xc5\x5a"
    },
};


/*------------------------------------------------------------------*/

static TestDescr aesTestVectors192[] =
{
    {
        (ubyte*) "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        (ubyte*) "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        (ubyte*) "\xAA\xE0\x69\x92\xAC\xBF\x52\xA3\xE8\xF4\xA9\x6E\xC9\x30\x0B\xD7"
    },
    /* FIPS 197 test vector */
    {
        (ubyte*) "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
                 "\x10\x11\x12\x13\x14\x15\x16\x17",
        (ubyte*) "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
        (ubyte*) "\xdd\xa9\x7c\xa4\x86\x4c\xdf\xe0\x6e\xaf\x70\xa0\xec\x0d\x71\x91"
    },
};


/*------------------------------------------------------------------*/

static TestDescr aesTestVectors256[] =
{
    {
        (ubyte*) "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        (ubyte*) "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
        (ubyte*) "\xDC\x95\xC0\x78\xA2\x40\x89\x89\xAD\x48\xA2\x14\x92\x84\x20\x87"
    },
    /* FIPS 197 test vector */
    {
        (ubyte*) "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
                 "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
        (ubyte*) "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
        (ubyte*) "\x8e\xa2\xb7\xca\x51\x67\x45\xbf\xea\xfc\x49\x90\x4b\x49\x60\x89"
    },
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
generic_aesalgo_test(int hint, TestDescr* aesTestVector, sbyte4 keySize,
                     sbyte4 expNumRounds)
{
    ubyte4 retVal = 0;
    sbyte4 cmpResult;
    ubyte4 rk[4 * 15]; /* 4 * (MAX_NR(14)+ 1) */
    ubyte  res[16];
    sbyte4 numRounds;

    numRounds = aesKeySetupEnc(rk, aesTestVector->key, keySize);
    retVal += UNITTEST_INT(hint, numRounds, expNumRounds);

    aesEncrypt(rk, numRounds, aesTestVector->plainText, res);
    DIGI_MEMCMP(aesTestVector->cipherText, res, 16, &cmpResult);
    retVal += UNITTEST_INT(hint, cmpResult, 0);

    numRounds = aesKeySetupDec(rk, aesTestVector->key, keySize);
    retVal += UNITTEST_INT(hint, numRounds, expNumRounds);

    aesDecrypt(rk, numRounds, aesTestVector->cipherText, res);
    DIGI_MEMCMP(aesTestVector->plainText, res, 16, &cmpResult);
    retVal += UNITTEST_INT(hint, cmpResult, 0);


    return retVal;
}


/*------------------------------------------------------------------*/

int aesalgo_test_vectors()
{
    int i, hint = 0, retVal = 0;

    for (i = 0, hint = 1280; i < COUNTOF(aesTestVectors128); ++i, ++hint)
    {
        retVal += generic_aesalgo_test(hint, aesTestVectors128+i, 128, 10);
    }
    for (i = 0, hint = 1920; i < COUNTOF(aesTestVectors192); ++i, ++hint)
    {
        retVal += generic_aesalgo_test(hint, aesTestVectors192+i, 192, 12);
    }
    for (i = 0, hint = 2560; i < COUNTOF(aesTestVectors256); ++i, ++hint)
    {
        retVal += generic_aesalgo_test(hint, aesTestVectors256+i, 256, 14);
    }


    return retVal;

}

