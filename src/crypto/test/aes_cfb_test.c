/*
 * aes_cfb_test.c
 *
 * unit test for aes.c CFB mode
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
    sig; /* to get rid of unused warnings */
    mContinueTest = 0;
}

#endif   /* defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined( __RTOS_SOLARIS__) || defined(__RTOS_OPENBSD__) || defined(__RTOS_OSX__) */


/*------------------------------------------------------------------*/



#if (defined(__ENABLE_AES_CFB_TEST_DEBUG__))
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

TestDescr aesCfbTestVectors128[] =
{
    {
        "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",   
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",   
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51",   
        "\x3b\x3f\xd9\x2e\xb7\x2d\xad\x20\x33\x34\x49\xf8\xe8\x3c\xfb\x4a\xc8\xa6\x45\x37\xa0\xb3\xa9\x3f\xcd\xe3\xcd\xad\x9f\x1c\xe5\x8b",  
        "\xc8\xa6\x45\x37\xa0\xb3\xa9\x3f\xcd\xe3\xcd\xad\x9f\x1c\xe5\x8b", 
    },
    {
        "\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",   
        "\xc8\xa6\x45\x37\xa0\xb3\xa9\x3f\xcd\xe3\xcd\xad\x9f\x1c\xe5\x8b", 
        "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
        "\x26\x75\x1f\x67\xa3\xcb\xb1\x40\xb1\x80\x8c\xf1\x87\xa4\xf4\xdf\xc0\x4b\x05\x35\x7c\x5d\x1c\x0e\xea\xc4\xc6\x6f\x9f\xf7\xf2\xe6",
        "\xc0\x4b\x05\x35\x7c\x5d\x1c\x0e\xea\xc4\xc6\x6f\x9f\xf7\xf2\xe6", 
    },
    {
        "00112233001122330011223300112233",
        "0011223300112233",
        "I have deposited in the county o",
        "\x9a\x2d\xcb\xf5\xb0\x39\x86\xd4\x34\x0f\x34\x3f\x21\x96\xff\xb0\xd4\x70\xa7\xee\xc6\x98\x78\x07\x27\x22\xbf\xc1\xa4\xab\x5b\xfe",
        "\xd4\x70\xa7\xee\xc6\x98\x78\x07\x27\x22\xbf\xc1\xa4\xab\x5b\xfe",
    },
    /* 128-bit Key, Segment 1 */
    {
        "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        "I have deposited in the county o",
        "\x6e\xbf\xdf\x2b\x03\x17\x33\x3a\xea\xeb\xe1\x85\xb8\x9a\x85\x67\x77\x8d\x14\xe8\x4f\x7f\x0d\x9e\x63\x81\x19\x27\xcc\x5e\x3d\x13",
        "\x77\x8d\x14\xe8\x4f\x7f\x0d\x9e\x63\x81\x19\x27\xcc\x5e\x3d\x13",
    },
    /* 128-bit Key, Segment 2 */
    {
        "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        "f Bedford, about four miles from",
        "\x41\xbf\xf5\x2f\x11\x14\x7c\x2c\xeb\xb7\xae\x97\xb3\x81\x95\x77\xc5\x33\x3f\x55\x88\x62\xbd\x4c\x63\x2c\x22\x21\x91\x28\x27\x8f",
        "\xc5\x33\x3f\x55\x88\x62\xbd\x4c\x63\x2c\x22\x21\x91\x28\x27\x8f",
    },
    /* 128-bit Key, Segment 3 */
    {
        "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        " Buford's, in an excavation or v",
        "\x07\xdd\xc2\x2c\x1a\x00\x77\x79\xfc\xb7\xae\x9f\xbf\xce\x81\x6d\x64\x9d\x57\x02\x6d\x5e\xb8\xc9\xd7\x64\x6b\xe4\xd1\x78\x19\x1c",
        "\x64\x9d\x57\x02\x6d\x5e\xb8\xc9\xd7\x64\x6b\xe4\xd1\x78\x19\x1c",
    },
    /* 128-bit Key, Segment 4 */
    {
        "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff",
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        "ault, six feet below the surface",
        "\x46\xea\xdb\x3e\x59\x52\x60\x37\xf7\xbb\xe8\x93\xb4\x9a\xc0\x61\x8b\x97\x4c\xa5\x40\x7b\xa7\xe3\x64\xed\x6e\x44\x3e\xbe\x95\x19",
        "\x8b\x97\x4c\xa5\x40\x7b\xa7\xe3\x64\xed\x6e\x44\x3e\xbe\x95\x19",
    },


};


/*------------------------------------------------------------------*/

TestDescr aesCfbTestVectors192[] =
{
    {
        "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51",
        "\xcd\xc8\x0d\x6f\xdd\xf1\x8c\xab\x34\xc2\x59\x09\xc9\x9a\x41\x74\x67\xce\x7f\x7f\x81\x17\x36\x21\x96\x1a\x2b\x70\x17\x1d\x3d\x7a",
        "\x67\xce\x7f\x7f\x81\x17\x36\x21\x96\x1a\x2b\x70\x17\x1d\x3d\x7a",
     },
     {
        "\x8e\x73\xb0\xf7\xda\x0e\x64\x52\xc8\x10\xf3\x2b\x80\x90\x79\xe5\x62\xf8\xea\xd2\x52\x2c\x6b\x7b",
        "\x67\xce\x7f\x7f\x81\x17\x36\x21\x96\x1a\x2b\x70\x17\x1d\x3d\x7a",
        "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
        "\x2e\x1e\x8a\x1d\xd5\x9b\x88\xb1\xc8\xe6\x0f\xed\x1e\xfa\xc4\xc9\xc0\x5f\x9f\x9c\xa9\x83\x4f\xa0\x42\xae\x8f\xba\x58\x4b\x09\xff",
        "\xc0\x5f\x9f\x9c\xa9\x83\x4f\xa0\x42\xae\x8f\xba\x58\x4b\x09\xff",
     },
    /* 192-bit Key, Part 1 */
    {
        "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77", 
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 
        "I have deposited in the county o", 
        "\x6b\xfa\x05\xc0\xdd\x7a\x73\x41\x1b\x58\xe2\xb8\x68\x0e\x70\x17\x65\xd2\x6b\x17\x2a\xcb\x75\xf7\xcd\xb0\x1d\x16\x65\x50\x7b\x4a", 
        "\x65\xd2\x6b\x17\x2a\xcb\x75\xf7\xcd\xb0\x1d\x16\x65\x50\x7b\x4a", 
    },
    /* 192-bit Key, Part 2 */
    {
        "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77", 
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 
        "f Bedford, about four miles from", 
        "\x44\xfa\x2f\xc4\xcf\x79\x3c\x57\x1a\x04\xad\xaa\x63\x15\x60\x07\xbd\xca\x3d\x18\x33\xd1\x6f\x6c\xd8\xee\x95\xc2\x0e\x21\x33\x40", 
        "\xbd\xca\x3d\x18\x33\xd1\x6f\x6c\xd8\xee\x95\xc2\x0e\x21\x33\x40", 
    },
    /* 192-bit Key, Part 3 */
    {
        "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77", 
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 
        " Buford's, in an excavation or v", 
        "\x02\x98\x18\xc7\xc4\x6d\x37\x02\x0d\x04\xad\xa2\x6f\x5a\x74\x1d\x97\xf0\xf2\xd5\x14\x7d\x14\x72\xb1\x16\xa2\xa5\x87\xff\xa3\x35", 
        "\x97\xf0\xf2\xd5\x14\x7d\x14\x72\xb1\x16\xa2\xa5\x87\xff\xa3\x35", 
    },
    /* 192-bit Key, Part 4 */
    {
        "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77", 
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 
        "ault, six feet below the surface", 
        "\x43\xaf\x01\xd5\x87\x3f\x20\x4c\x06\x08\xeb\xae\x64\x0e\x35\x11\xca\x99\xf6\xb2\xd3\xd9\x5f\x77\xa6\x7f\xb1\xdb\xc5\xc4\x28\xea", 
        "\xca\x99\xf6\xb2\xd3\xd9\x5f\x77\xa6\x7f\xb1\xdb\xc5\xc4\x28\xea", 
    },


};




/*------------------------------------------------------------------*/

TestDescr aesCfbTestVectors256[] =
{
    {
        "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
        "\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51",
        "\xdc\x7e\x84\xbf\xda\x79\x16\x4b\x7e\xcd\x84\x86\x98\x5d\x38\x60\x39\xff\xed\x14\x3b\x28\xb1\xc8\x32\x11\x3c\x63\x31\xe5\x40\x7b",
        "\x39\xff\xed\x14\x3b\x28\xb1\xc8\x32\x11\x3c\x63\x31\xe5\x40\x7b",
     },
     {
        "\x60\x3d\xeb\x10\x15\xca\x71\xbe\x2b\x73\xae\xf0\x85\x7d\x77\x81\x1f\x35\x2c\x07\x3b\x61\x08\xd7\x2d\x98\x10\xa3\x09\x14\xdf\xf4",
        "\x39\xff\xed\x14\x3b\x28\xb1\xc8\x32\x11\x3c\x63\x31\xe5\x40\x7b",
        "\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10",
        "\xdf\x10\x13\x24\x15\xe5\x4b\x92\xa1\x3e\xd0\xa8\x26\x7a\xe2\xf9\x75\xa3\x85\x74\x1a\xb9\xce\xf8\x20\x31\x62\x3d\x55\xb1\xe4\x71",
        "\x75\xa3\x85\x74\x1a\xb9\xce\xf8\x20\x31\x62\x3d\x55\xb1\xe4\x71",
     },
     
    /* 256-bit Key, Part 1 */
    {
        "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff", 
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 
        "I have deposited in the county o", 
        "\x4f\x19\x80\x1c\x78\x53\xe0\x78\xca\xf8\x74\x78\x31\x81\x65\xf3\x4f\xcc\xad\xa7\x50\x4e\x49\xe3\xea\xb6\xcd\xa0\x66\xa3\x72\xf9", 
        "\x4f\xcc\xad\xa7\x50\x4e\x49\xe3\xea\xb6\xcd\xa0\x66\xa3\x72\xf9", 
    },
    /* 256-bit Key, Part 2 */
    {
        "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff", 
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 
        "f Bedford, about four miles from", 
        "\x60\x19\xaa\x18\x6a\x50\xaf\x6e\xcb\xa4\x3b\x6a\x3a\x9a\x75\xe3\x6e\x8b\x72\xb5\x5c\x5f\x27\x1a\x32\xed\x7b\x8e\xfd\x72\x0e\xfe", 
        "\x6e\x8b\x72\xb5\x5c\x5f\x27\x1a\x32\xed\x7b\x8e\xfd\x72\x0e\xfe", 
    },
    /* 256-bit Key, Part 3 */
    {
        "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff", 
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 
        " Buford's, in an excavation or v", 
        "\x26\x7b\x9d\x1b\x61\x44\xa4\x3b\xdc\xa4\x3b\x62\x36\xd5\x61\xf9\x99\x92\xfd\x05\x81\x98\xd6\xdf\xd8\x4b\x4a\x61\x0e\xd0\x74\xcf", 
        "\x99\x92\xfd\x05\x81\x98\xd6\xdf\xd8\x4b\x4a\x61\x0e\xd0\x74\xcf", 
    },
    /* 256-bit Key, Part 4 */
    {
        "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff", 
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 
        "ault, six feet below the surface", 
        "\x67\x4c\x84\x09\x22\x16\xb3\x75\xd7\xa8\x7d\x6e\x3d\x81\x20\xf5\x7b\x86\xdf\xe4\x8b\xf3\xf6\x54\x5d\x35\x0e\xa5\x03\x9d\xf7\x72", 
        "\x7b\x86\xdf\xe4\x8b\xf3\xf6\x54\x5d\x35\x0e\xa5\x03\x9d\xf7\x72", 
    },

};



/*------------------------------------------------------------------*/

#if (defined(__ENABLE_AES_CFB_TEST_DEBUG__))
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
generic_aes_cfb_test(TestDescr aesCfbTestVectors[], sbyte4 numVectors, sbyte4 keySize)
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

    if (OK > (status = DIGI_MEMSET(pText, 0x00, MAX_AES_TEXT_STRING)))
        goto exit;

    retVal = 0;

    for (i = 0; i < numVectors; ++i)
    {
        /* clone data for test */
        DIGI_MEMCPY(pKey,       (ubyte *)(aesCfbTestVectors[i].key), keySize);
        DIGI_MEMCPY(pIvEncrypt, (ubyte *)(aesCfbTestVectors[i].iv), 16);
        DIGI_MEMCPY(pIvDecrypt, (ubyte *)(aesCfbTestVectors[i].iv), 16);
        DIGI_MEMCPY(pText,      (ubyte *)(aesCfbTestVectors[i].text), 32);

#if (defined(__ENABLE_AES_CFB_TEST_DEBUG__))
        printf("{\n");
        dumpHex("plain text", pText, 32);
        printf("======\n");
#endif
 
        /* encrypt test */
	
        if (NULL == (ctx = CreateAESCFBCtx(MOC_SYM(hwAccelCtx) pKey, keySize, TRUE)))
        {
 #if (defined(__ENABLE_AES_CFB_TEST_DEBUG__))
            printf("generic_aes_cfb_test: CreateAESCFBCtx failed, keySize = %d.\n", keySize);
#endif
           retVal++;
           continue;
        }

        if (OK > (status = DoAES(MOC_SYM(hwAccelCtx) ctx, pText, 32, TRUE, pIvEncrypt)))
        {
#if (defined(__ENABLE_AES_CFB_TEST_DEBUG__))
            printf("generic_aes_cfb_test: DoAES failed, keySize = %d.\n", keySize);
#endif
            retVal++;
            continue;
        }
		
        if (OK > (status = DeleteAESCtx(MOC_SYM(hwAccelCtx) &ctx)))
        {
#if (defined(__ENABLE_AES_CFB_TEST_DEBUG__))
    printf("generic_aes_cfb_test: DeleteAESCtx failed, keySize = %d\n", keySize);
#endif
            retVal++;
            continue;
        }

#if (defined(__ENABLE_AES_CFB_TEST_DEBUG__))        
        dumpHex("encrypted text", pText, 32);
        dumpHex("key", pKey, keySize);
        dumpHex("iv", pIvEncrypt, 16);
        printf("======\n");
#endif

        /* verify encryption */
        if (OK > (status = DIGI_MEMCMP((ubyte *)(aesCfbTestVectors[i].encrypt), pText, 32, &cmpResult)))
        {
            retVal++;
            continue;
        }

        if (0 != cmpResult)
        {
#if (defined(__ENABLE_AES_CFB_TEST_DEBUG__))
            printf("generic_aes_cfb_test: encryption test failed, keySize = %d.\n", keySize);
#endif
            retVal++;
        }

        if (OK > (status = DIGI_MEMCMP((ubyte *)(aesCfbTestVectors[i].final_iv), pIvEncrypt, 16, &cmpResult)))
        {
            retVal++;
            continue;
        }

        if (0 != cmpResult)
        {
#if (defined(__ENABLE_AES_CFB_TEST_DEBUG__))
            printf("generic_aes_cfb_test: encryption iv test failed, keySize = %d.\n", keySize);
#endif
            retVal++;
        }

        /* decrypt test */
        if (NULL == (ctx = CreateAESCFBCtx(MOC_SYM(hwAccelCtx) pKey, keySize, FALSE)))
        {
#if (defined(__ENABLE_AES_CFB_TEST_DEBUG__))
            printf("generic_aes_cfb_test: CreateAESCFBCtx failed, keySize = %d.\n", keySize);
#endif
            retVal++;
            continue;
        }

        if (OK > (status = DoAES(MOC_SYM(hwAccelCtx) ctx, pText, 32, FALSE, pIvDecrypt)))
        {
#if (defined(__ENABLE_AES_CFB_TEST_DEBUG__))
            printf("generic_aes_cfb_test: DoAES failed, keySize = %d.\n", keySize);
#endif
            retVal++;
            continue;
        }



        if (OK > (status = DeleteAESCtx(MOC_SYM(hwAccelCtx) &ctx)))
        {
#if (defined(__ENABLE_AES_CFB_TEST_DEBUG__))
    printf("generic_aes_cfb_test: DeleteAESCtx failed, keySize = %d\n", keySize);
#endif
            retVal++;
            continue;
        }

#if (defined(__ENABLE_AES_CFB_TEST_DEBUG__))
        dumpHex("decrypted text", pText, 32);
        dumpHex("key", pKey, keySize);
        dumpHex("iv", pIvDecrypt, 16);
        printf("}\n");
#endif

        /* verify decryption */
        if (OK > (status = DIGI_MEMCMP((ubyte *)(aesCfbTestVectors[i].text), pText, 32, &cmpResult)))
        {
            retVal++;
            continue;
        }

        if (0 != cmpResult)
        {
#if (defined(__ENABLE_AES_CFB_TEST_DEBUG__))
            printf("generic_aes_cfb_test: decryption test failed, keySize = %d.\n", keySize);
#endif
            retVal++;
        }

        if (OK > (status = DIGI_MEMCMP((ubyte *)(aesCfbTestVectors[i].final_iv), pIvDecrypt, 16, &cmpResult)))
        {
            retVal++;
            continue;
        }

        if (0 != cmpResult)
        {
#if (defined(__ENABLE_AES_CFB_TEST_DEBUG__))
            printf("generic_aes_cfb_test: decryption iv test failed, keySize = %d.\n", keySize);
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
        ctx = CreateAESCFBCtx(MOC_SYM(hwAccelCtx) pKey, keySize, TRUE);

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

        printf("\tAES_CFB (%d): %d kbytes in %g seconds of CPU time\n",
               keySize*8, counter, diffTime);
        printf("AES_CFB (%d): %g kbytes/second (CPU time) (1 kbyte = 1024 bytes)\n",
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

int aes_cfb_test_vectors128()
{
    return generic_aes_cfb_test(aesCfbTestVectors128, (sizeof(aesCfbTestVectors128)/ sizeof(TestDescr)), 16);
}


/*------------------------------------------------------------------*/

int aes_cfb_test_vectors192()
{
    return generic_aes_cfb_test(aesCfbTestVectors192, (sizeof(aesCfbTestVectors192)/ sizeof(TestDescr)), 24);
}


/*------------------------------------------------------------------*/

int aes_cfb_test_vectors256()
{
    return generic_aes_cfb_test(aesCfbTestVectors256, (sizeof(aesCfbTestVectors256)/ sizeof(TestDescr)), 32);
}

