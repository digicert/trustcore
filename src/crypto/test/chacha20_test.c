/*
 * chacha20_test.c
 *
 * ChaCha20 Encryption Test
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

#include "../chacha20.c"


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


/*------------------------------------------------------------------*/

static void
chacha20_speed_test()
{
    ubyte* buffer = 0;
    int i;
    ubyte4 sizes[] = { 16, 64, 256, 1024, 8192 };
    ubyte zeroes[48] = { 0};

    buffer = (ubyte*) MALLOC(8192);

    if ( buffer)
    {
        for (i = 0; i < 8192; ++i)
        {
            buffer[i] = (ubyte) i;
        }

        for ( i = 0; i < COUNTOF(sizes); ++i)
        {
            struct tms tstart, tend;
            double diffTime, kbytes;
            ubyte4 counter;
            BulkCtx ctx;

            START_ALARM(TEST_SECONDS);
            times(&tstart);
            counter = 0;
            ctx = CreateChaCha20Ctx(zeroes, 48, 1);
            while( ALARM_OFF)
            {
                DoChaCha20(ctx, buffer, sizes[i], 1, NULL);
                counter++;
            }
            DeleteChaCha20Ctx(&ctx);
            times(&tend);
            diffTime = tend.tms_utime-tstart.tms_utime;
            diffTime /= sysconf(_SC_CLK_TCK);
            kbytes = sizes[i] * (counter / 1024.0);
            printf("\tChaCha20: %d blocks of %d bytes in %g seconds of CPU time\n",
                   counter, sizes[i], diffTime);
            printf("ChaCha20: %g kbytes/second (CPU time)(%d bytes block) (1 kbyte = 1024 bytes)\n",
                   kbytes/diffTime, sizes[i]);

        }
        FREE(buffer);
    }    
}

#endif   /* defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined( __RTOS_SOLARIS__) || defined(__RTOS_OPENBSD__)  || defined(__RTOS_OSX__) */

#ifdef __ENABLE_DIGICERT_CHACHA20__
static const char* kPlainText = "Ladies and Gentlemen of the class of '99: "
"If I could offer you only one tip for the future, sunscreen would be it.";
#endif /* __ENABLE_DIGICERT_CHACHA20__ */

/*---------------------------------------------------------------------*/

int chacha20_test_quarter_round()
{
#ifdef __ENABLE_DIGICERT_CHACHA20__
   int retVal = 0;
    ubyte4 a, b, c, d;

    /* RFC 7539 test vector */
    a = 0x11111111;
    b = 0x01020304;
    c = 0x9b8d6f43;
    d = 0x01234567;

    QUARTERROUND(a,b,c,d);

    retVal += UNITTEST_TRUE( 0, a == 0xea2a92f4);
    retVal += UNITTEST_TRUE( 0, b == 0xcb1cf8ce);
    retVal += UNITTEST_TRUE( 0, c == 0x4581472e);
    retVal += UNITTEST_TRUE( 0, d == 0x5881c4bb);
    return retVal;
#else
    return 0;
#endif
}


/*---------------------------------------------------------------------*/

int chacha20_test_block()
{
#ifdef __ENABLE_DIGICERT_CHACHA20__
    int i, retVal = 0;
    ChaCha20Ctx ctx;
    ubyte key[32];
    ubyte nonce[12] =
    {
        0x00, 0x00, 0x00, 0x09,
        0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };
    ubyte counter[4] = { 0x01, 0x00, 0x00, 0x00 }; /* 1 in little endian */

    ubyte expectedKeyStream[64] =
    {
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
        0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
        0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
        0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
        0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
    };

    ubyte4 expectedSchedule[16] =
    {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        0x00000001, 0x09000000, 0x4a000000, 0x00000000,
    };

    /* the key used in RFC 7539 */
    for (i = 0; i < 32; ++i)
    {
        key[i] = (ubyte) i ;
    }

    CHACHA20_setup(&ctx, key, nonce, counter);

    for (i = 0; i < 16; ++i)
    {
        retVal += UNITTEST_INT(i, ctx.schedule[i], expectedSchedule[i] );
    }

    CHACHA20_block(&ctx);

    for (i = 0; i < 64; ++i)
    {
        retVal += UNITTEST_TRUE(i, expectedKeyStream[i] == ctx.keystream[i]);
    }

    return retVal;
#else
    return 0;
#endif
}



/*---------------------------------------------------------------------*/

int chacha20_test_encrypt()
{
#ifdef __ENABLE_DIGICERT_CHACHA20__
    int i, retVal = 0;
    BulkCtx ctx = 0;
    sbyte4 resCmp;
    ubyte key[48];
    ubyte nonce[12] =
    {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };
    ubyte counter[4] = { 0x01, 0x00, 0x00, 0x00 };

    int ptLen = DIGI_STRLEN((const sbyte*) kPlainText);
    ubyte* ct = 0;
    ubyte expectedCt[] =
    {
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d,
    };

    ct = MALLOC(ptLen);
    retVal += UNITTEST_VALIDPTR(0, ct);
    if (retVal) goto exit;

    DIGI_MEMCPY(ct, kPlainText, ptLen);

    /* the key used in RFC 7539 */
    for (i = 0; i < 32; ++i)
    {
        key[i] = (ubyte) i ;
    }
    DIGI_MEMCPY(key+32, counter, 4);
    DIGI_MEMCPY(key+36, nonce, 12);

    ctx = CreateChaCha20Ctx(key, 48, 1);

    DoChaCha20(ctx, ct, ptLen, 1, NULL);

    DIGI_MEMCMP(ct, expectedCt, ptLen, &resCmp);

    retVal += UNITTEST_TRUE(0, 0 == resCmp);

#if defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined (__RTOS_SOLARIS__) || defined(__RTOS_OPENBSD__) || defined(__RTOS_OSX__)
    if ( 0 == retVal)
    {
        chacha20_speed_test();
    }
#endif

exit:
    DeleteChaCha20Ctx(&ctx);

    free( ct);

    return retVal;
#else
    return 0;
#endif
}


/*---------------------------------------------------------------------*/

int chacha20_test_poly1305_key_gen_rfc7539()
{
#ifdef __ENABLE_DIGICERT_CHACHA20__
    int i, retVal = 0;
    sbyte4 resCmp;
    ubyte key[32];
    ubyte nonce[12] =
    {
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07
    };
    ubyte counter[4] = { 0x00, 0x00, 0x00, 0x00 };
    ubyte poly1305Key[32] =
    {
        0x8a, 0xd5, 0xa0, 0x8b, 0x90, 0x5f, 0x81, 0xcc,
        0x81, 0x50, 0x40, 0x27, 0x4a, 0xb2, 0x94, 0x71,
        0xa8, 0x33, 0xb6, 0x37, 0xe3, 0xfd, 0x0d, 0xa5,
        0x08, 0xdb, 0xb8, 0xe2, 0xfd, 0xd1, 0xa6, 0x46
    };
    ChaCha20Ctx ctx;

    /* the key used in RFC 7539 */
    for (i = 0; i < 32; ++i)
    {
        key[i] = 0x80 + ((ubyte) i) ;
    }

    CHACHA20_setup(&ctx, key, nonce, counter);

    CHACHA20_GetNewKeyStream(&ctx);

    /* verify expected value */
    DIGI_MEMCMP(poly1305Key, ctx.keystream, sizeof(poly1305Key), &resCmp);

    retVal += UNITTEST_TRUE(0, 0 == resCmp);

    /* verify ChaCha20 counter is 1 */
    retVal += UNITTEST_INT(0, ctx.schedule[12], 1);

    /* verify streamOffset is 0 */
    retVal += UNITTEST_INT(0, ctx.streamOffset, 0);

    return retVal;
#else
    return 0;
#endif
}


/*---------------------------------------------------------------------*/

int chacha20_test_aead()
{
#if defined( __ENABLE_DIGICERT_CHACHA20__) && defined(__ENABLE_DIGICERT_POLY1305__)
    int i, retVal = 0;
    sbyte4 resCmp;
    MSTATUS status;
    BulkCtx ctx = 0;
    ubyte nonce[] =
    {
        0x07, 0x00, 0x00, 0x00,
        0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47
    };

    ubyte expectedCt[] =
    {
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb,
        0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
        0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe,
        0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
        0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
        0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
        0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
        0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
        0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c,
        0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
        0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94,
        0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
        0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d,
        0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
        0x61, 0x16
    };
    ubyte expectedTag[] =
    {
        0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
        0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
    };

    ubyte AAD[] =
    {
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1,
        0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7
    };
    ubyte key[32];

    ubyte* data = 0;
    int ptLen = DIGI_STRLEN(kPlainText);

    /* the key used in RFC 7539 */
    for (i = 0; i < 32; ++i)
    {
        key[i] = 0x80 + ((ubyte) i) ;
    }

    data = MALLOC(ptLen+16);
    retVal += UNITTEST_VALIDPTR(0, data);
    if (retVal) goto exit;
    DIGI_MEMCPY(data, kPlainText, ptLen);

    ctx = ChaCha20Poly1305_createCtx(key, sizeof(key), 1);
    retVal += UNITTEST_VALIDPTR(0, ctx);
    if (retVal) goto exit;

    status = ChaCha20Poly1305_cipher(ctx, nonce, sizeof(nonce), AAD, sizeof(AAD),
                                     data, ptLen, 16, 1);
    UNITTEST_STATUS_GOTO(0, status, retVal, exit);

    /* verify cipher text */
    DIGI_MEMCMP(data, expectedCt, ptLen, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);
    
    /* verify tag */
    DIGI_MEMCMP(data + ptLen, expectedTag, 16, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);

    /* delete the context and recreate for decrypt */
    ChaCha20Poly1305_deleteCtx(&ctx);
    
    ctx = ChaCha20Poly1305_createCtx(key, sizeof(key), 0);
    retVal += UNITTEST_VALIDPTR(0, ctx);
    if (retVal) goto exit;

    status = ChaCha20Poly1305_cipher(ctx, nonce, sizeof(nonce), AAD, sizeof(AAD),
                                     data, ptLen, 16, 0);
    UNITTEST_STATUS_GOTO(0, status, retVal, exit);

    /* verify cipher text */
    DIGI_MEMCMP(data, kPlainText, ptLen, &resCmp);
    retVal += UNITTEST_INT(0, resCmp, 0);

exit:
    FREE(data);

    ChaCha20Poly1305_deleteCtx(&ctx);

    return retVal;
#else
    return 0;
#endif
}





