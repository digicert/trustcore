/*
 * crypto_interface_poly1305_test.c
 *
 * Poly1305 MAC Test
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

#include "../../../unit_tests/unittest.h"
#include "../../common/initmocana.h"
#include "../../crypto/poly1305.h"

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
#include "../../crypto_interface/crypto_interface_poly1305.h"
#endif

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
    MOC_UNUSED (sig);
    mContinueTest = 0;
}

#endif   /* defined( __RTOS_LINUX__) || defined(__RTOS_CYGWIN__) || defined(__RTOS_IRIX__) || defined( __RTOS_SOLARIS__) || defined(__RTOS_OPENBSD__)  || defined(__RTOS_OSX__) */

static MocCtx gpMocCtx = NULL;


int
crypto_interface_poly1305_test_negative_bad_ordering (void)
{
    MSTATUS status = ERR_CRYPTO_INTERFACE;
    int retVal = 0;
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    void *hwAccelCtx = NULL;
#endif

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_POLY1305__))

    Poly1305Ctx ctx = { 0 };
    ubyte pData[32] = { 0 };
    ubyte pKey[32] = { 0 };
    ubyte pMac[16] = { 0 };

    InitMocanaSetupInfo setupInfo = { 0 };
    setupInfo.flags = MOC_NO_AUTOSEED;

    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
    
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
#endif

    /* Calling Update(...) without doing Init(...) first */
    status = Poly1305Update(MOC_HASH(hwAccelCtx) &ctx, pData, 5);
    retVal += UNITTEST_TRUE(__MOC_LINE__, (OK != status) );
    if (OK == status)
        goto exit;

    /* Calling Final(...) without doing Init(...) first */
    status = Poly1305Final(MOC_HASH(hwAccelCtx) &ctx, pMac);
    retVal += UNITTEST_TRUE(__MOC_LINE__, (OK != status) );
    if (OK == status)
        goto exit;

    /* Calling Update(...) after calling Final(...) */
    status = Poly1305Init(MOC_HASH(hwAccelCtx) &ctx, pKey);
    if (OK != status)
      goto exit;

    status = Poly1305Update(MOC_HASH(hwAccelCtx) &ctx, pData, sizeof (pData));
    if (OK != status)
      goto exit;

    status = Poly1305Final(MOC_HASH(hwAccelCtx) &ctx, pMac);
    if (OK != status)
      goto exit;

    status = Poly1305Update(MOC_HASH(hwAccelCtx) &ctx, pData, 1);
    retVal += UNITTEST_TRUE(__MOC_LINE__, (OK != status) );

exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

    DIGICERT_free(&gpMocCtx);

#endif

    return ( 0 == retVal ) ? 0 : 1;

}


/*----------------------------------------------------------------------------*/

int
crypto_interface_poly1305_test_negative_null_ctx (void)
{
    MSTATUS status = ERR_CRYPTO_INTERFACE;
    int retVal = 0;
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    void *hwAccelCtx = NULL;
#endif

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_POLY1305__))

    ubyte pKey[32] = { 0 };

    InitMocanaSetupInfo setupInfo = { 0 };
    setupInfo.flags = MOC_NO_AUTOSEED;

    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    if (OK != status)
       goto exit;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
    
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
#endif

    status = Poly1305Init(MOC_HASH(hwAccelCtx) NULL, pKey);
    retVal += UNITTEST_TRUE(__MOC_LINE__, (OK != status) );

exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

    DIGICERT_free(&gpMocCtx);

#endif

    return ( 0 == retVal ) ? 0 : 1;
}


/*----------------------------------------------------------------------------*/
int
crypto_interface_poly1305_test_negative_null_key (void)
{
    MSTATUS status = ERR_CRYPTO_INTERFACE;
    int retVal = 0;
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    void *hwAccelCtx = NULL;
#endif

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_POLY1305__))

    Poly1305Ctx ctx = { 0 };

    InitMocanaSetupInfo setupInfo = { 0 };
    setupInfo.flags = MOC_NO_AUTOSEED;

    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    if (OK != status)
       goto exit;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
    
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
#endif

    status = Poly1305Init(MOC_HASH(hwAccelCtx) &ctx, NULL);
    retVal += UNITTEST_TRUE(__MOC_LINE__, (OK != status) );

exit:

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

    DIGICERT_free(&gpMocCtx);

#endif

    return ( 0 == retVal ) ? 0 : 1;
}


/*----------------------------------------------------------------------------*/

int
crypto_interface_poly1305_test_enabled (void)
{
    MSTATUS status = OK;
    int retVal = 0;
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    void *hwAccelCtx = NULL;
#endif

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_POLY1305__))

    Poly1305Ctx ctx = { 0 };
    MocSymCtx pMocSymCtx = NULL;

    const ubyte pKey[32] = { 0 };
    ubyte mac[16] = {0};

    InitMocanaSetupInfo setupInfo = { 0 };
    setupInfo.flags = MOC_NO_AUTOSEED;

    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    retVal += UNITTEST_STATUS (__MOC_LINE__, status);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
    
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
#endif

    /* Initialize context for Poly1305 */
    status = Poly1305Init(MOC_HASH(hwAccelCtx) &ctx, pKey);
    retVal += UNITTEST_STATUS (__MOC_LINE__, status);
    if (OK != status)
      goto exit;

    pMocSymCtx = ctx.pMocSymCtx;

#ifdef __ENABLE_DIGICERT_POLY1305_MBED__

    status = ERR_INVALID_ARG;
    if (NULL == pMocSymCtx)
    {
        retVal += UNITTEST_STATUS (__MOC_LINE__, status);
        goto exit;
    }

    if (FALSE == ctx.enabled)
    {
        retVal += UNITTEST_STATUS (__MOC_LINE__, status);
        goto exit;
    }

    status = OK;

#endif

exit:

    /* call final in order to free memory */
    (void) Poly1305Final(MOC_HASH(hwAccelCtx) &ctx, mac);
    (void) DIGICERT_free(&gpMocCtx);

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

#endif

    return ( (OK == status) && (0 == retVal) ) ? 0 : 1;
}


/*----------------------------------------------------------------------------*/

/* test a few basic operations */
int
crypto_interface_poly1305_test_simple(void)
{
    MSTATUS status = OK;
    int retVal = 0;
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    void *hwAccelCtx = NULL;
#endif

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_POLY1305__))

    InitMocanaSetupInfo setupInfo = { 0 };
    setupInfo.flags = MOC_NO_AUTOSEED;

    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    if (OK != status)
          goto exit;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
    
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
#endif

    /* example from nacl */
    static const ubyte nacl_key[32] = {
        0xee,0xa6,0xa7,0x25,0x1c,0x1e,0x72,0x91,
        0x6d,0x11,0xc2,0xcb,0x21,0x4d,0x3c,0x25,
        0x25,0x39,0x12,0x1d,0x8e,0x23,0x4e,0x65,
        0x2d,0x65,0x1f,0xa4,0xc8,0xcf,0xf8,0x80,
    };

    static const ubyte nacl_msg[131] = {
        0x8e,0x99,0x3b,0x9f,0x48,0x68,0x12,0x73,
        0xc2,0x96,0x50,0xba,0x32,0xfc,0x76,0xce,
        0x48,0x33,0x2e,0xa7,0x16,0x4d,0x96,0xa4,
        0x47,0x6f,0xb8,0xc5,0x31,0xa1,0x18,0x6a,
        0xc0,0xdf,0xc1,0x7c,0x98,0xdc,0xe8,0x7b,
        0x4d,0xa7,0xf0,0x11,0xec,0x48,0xc9,0x72,
        0x71,0xd2,0xc2,0x0f,0x9b,0x92,0x8f,0xe2,
        0x27,0x0d,0x6f,0xb8,0x63,0xd5,0x17,0x38,
        0xb4,0x8e,0xee,0xe3,0x14,0xa7,0xcc,0x8a,
        0xb9,0x32,0x16,0x45,0x48,0xe5,0x26,0xae,
        0x90,0x22,0x43,0x68,0x51,0x7a,0xcf,0xea,
        0xbd,0x6b,0xb3,0x73,0x2b,0xc0,0xe9,0xda,
        0x99,0x83,0x2b,0x61,0xca,0x01,0xb6,0xde,
        0x56,0x24,0x4a,0x9e,0x88,0xd5,0xf9,0xb3,
        0x79,0x73,0xf6,0x22,0xa4,0x3d,0x14,0xa6,
        0x59,0x9b,0x1f,0x65,0x4c,0xb4,0x5a,0x74,
        0xe3,0x55,0xa5
    };

    static const ubyte nacl_mac[16] = {
        0xf3,0xff,0xc7,0x70,0x3f,0x94,0x00,0xe5,
        0x2a,0x7d,0xfb,0x4b,0x3d,0x33,0x05,0xd9
    };

    /* generates a final value of (2^130 - 2) == 3 */
    static const ubyte wrap_key[32] = {
        0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    };

    static const ubyte wrap_msg[16] = {
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    };

    static const ubyte wrap_mac[16] = {
        0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    };

    /*
     mac of the macs of messages of length 0 to 256, where the key and messages
     have all their values set to the length
     */
    static const ubyte total_key[32] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0xff,0xfe,0xfd,0xfc,0xfb,0xfa,0xf9,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff
    };

    static const ubyte total_mac[16] = {
        0x64,0xaf,0xe2,0xe8,0xd6,0xad,0x7b,0xbd,
        0xd2,0x87,0xf9,0x7c,0x44,0x62,0x3d,0x39
    };

    Poly1305Ctx ctx;
    Poly1305Ctx total_ctx;
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
    Poly1305Ctx clone;
#endif
    ubyte all_key[32];
    ubyte all_msg[256];
    ubyte mac[16];
    int i, j;
    intBoolean differ;

    status = DIGI_MEMSET (mac, 0x00, sizeof (mac));
    if (OK != status)
        goto exit;

    status = Poly1305_completeDigest(MOC_HASH(hwAccelCtx) mac, nacl_msg, sizeof(nacl_msg), nacl_key);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    DIGI_CTIME_MATCH(nacl_mac, mac, 16, &differ);
    retVal += UNITTEST_TRUE(0, 0 == differ);

    status = DIGI_MEMSET (mac, 0x00, sizeof (mac));
    if (OK != status)
        goto exit;

    status = Poly1305Init(MOC_HASH(hwAccelCtx) &ctx, nacl_key);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
          goto exit;

    status = Poly1305Update(MOC_HASH(hwAccelCtx) &ctx, nacl_msg +   0, 32);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = Poly1305Update(MOC_HASH(hwAccelCtx) &ctx, nacl_msg +  32, 64);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = Poly1305Update(MOC_HASH(hwAccelCtx) &ctx, nacl_msg +  96, 16);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = Poly1305Update(MOC_HASH(hwAccelCtx) &ctx, nacl_msg + 112,  8);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = Poly1305Update(MOC_HASH(hwAccelCtx) &ctx, nacl_msg + 120,  4);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = Poly1305Update(MOC_HASH(hwAccelCtx) &ctx, nacl_msg + 124,  2);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = Poly1305Update(MOC_HASH(hwAccelCtx) &ctx, nacl_msg + 126,  1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = Poly1305Update(MOC_HASH(hwAccelCtx) &ctx, nacl_msg + 127,  1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = Poly1305Update(MOC_HASH(hwAccelCtx) &ctx, nacl_msg + 128,  1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = Poly1305Update(MOC_HASH(hwAccelCtx) &ctx, nacl_msg + 129,  1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    /* test clone if not export. Clone can be added to mbed operator at a later date */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && !defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)
    status = CRYPTO_INTERFACE_Poly1305_cloneCtx(MOC_HASH(hwAccelCtx) &clone, &ctx);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if(OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_Poly1305Update(MOC_HASH(hwAccelCtx) &clone, nacl_msg + 130,  1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_Poly1305Final(MOC_HASH(hwAccelCtx) &clone, mac);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
#else  
    status = Poly1305Update(MOC_HASH(hwAccelCtx) &ctx, nacl_msg + 130,  1);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    status = Poly1305Final(MOC_HASH(hwAccelCtx) &ctx, mac);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
#endif

    DIGI_CTIME_MATCH(nacl_mac, mac, 16, &differ);
    retVal += UNITTEST_TRUE(0, 0 == differ);

    status = DIGI_MEMSET (mac, 0x00, sizeof (mac));
    if (OK != status)
        goto exit;

    status = Poly1305_completeDigest(MOC_HASH(hwAccelCtx) mac, wrap_msg, sizeof(wrap_msg), wrap_key);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    DIGI_CTIME_MATCH(wrap_mac, mac, 16, &differ);
    retVal += UNITTEST_TRUE(0, 0 == differ);


    status = Poly1305Init(MOC_HASH(hwAccelCtx) &total_ctx, total_key);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    for (i = 0; i < 256; i++) {
        /* set key and message to 'i,i,i..' */
        for (j = 0; j < sizeof(all_key); j++)
            all_key[j] = ((ubyte) i);
        for (j = 0; j < i; j++)
            all_msg[j] = ((ubyte) i);
        status = Poly1305_completeDigest(MOC_HASH(hwAccelCtx) mac, all_msg, ((ubyte4) i), all_key);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
              goto exit;

        status = Poly1305Update(MOC_HASH(hwAccelCtx) &total_ctx, mac, 16);
        UNITTEST_STATUS(__MOC_LINE__, status);
        if (OK != status)
              goto exit;
    }
    status = Poly1305Final(MOC_HASH(hwAccelCtx) &total_ctx, mac);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
          goto exit;

    DIGI_CTIME_MATCH(total_mac, mac, 16, &differ);
    retVal += UNITTEST_TRUE(0, 0 == differ);

exit:

    DIGICERT_free(&gpMocCtx);

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

#endif

    return ( (OK == status) && (0 == retVal) ) ? 0 : 1;
}


/*----------------------------------------------------------------------------*/

/* RFC 7539 test vector */
int
crypto_interface_poly1305_test_ietf(void)
{
    MSTATUS status = OK;
    int retVal = 0;
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    void *hwAccelCtx = NULL;
#endif

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
     defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_POLY1305__))

    InitMocanaSetupInfo setupInfo = { 0 };
    setupInfo.flags = MOC_NO_AUTOSEED;

    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
    
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
#endif

    /* example from nacl */
    static const ubyte ietf_key[32] =
    {
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
    };

    static const ubyte ietf_msg[34] =
    {
        0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72,
        0x61, 0x70, 0x68, 0x69, 0x63, 0x20, 0x46, 0x6f,
        0x72, 0x75, 0x6d, 0x20, 0x52, 0x65, 0x73, 0x65,
        0x61, 0x72, 0x63, 0x68, 0x20, 0x47, 0x72, 0x6f,
        0x75, 0x70
    };

    static const ubyte ietf_mac[16] =
    {
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9
    };

    intBoolean differ;
    int i;
    ubyte mac[16];

    status = DIGI_MEMSET (mac, 0x00, sizeof (mac));
    if (OK != status)
        goto exit;

    status = Poly1305_completeDigest(MOC_HASH(hwAccelCtx) mac, ietf_msg, sizeof(ietf_msg), ietf_key);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;

    DIGI_CTIME_MATCH(ietf_mac, mac, 16, &differ);
    retVal += UNITTEST_TRUE(0, 0 == differ);

exit:

    DIGICERT_free(&gpMocCtx);

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

#endif

    return ( (OK == status) && (0 == retVal) ) ? 0 : 1;

}


/* Collision test for using the same key! */
int crypto_interface_poly1305_test_same_key_collision(void)
{
    
    MSTATUS status = OK;
    int retVal = 0;
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    void *hwAccelCtx = NULL;
#endif

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && \
defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_POLY1305__))
    
    static const ubyte pKey[32] =
    {
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
    };
    
    static const ubyte pMsg[16] =
    {
        0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72,
        0x61, 0x70, 0x68, 0x69, 0x63, 0x20, 0x46, 0x7f,
    };
    
    /*
     Our goal is to choose 16 arbitray bytes and then compute
     an additional block of 16 bytes that will make the MAC come
     out to the same value as the mac of pMsg. All we need to do
     is solve the equation as follows...
     
     r is the first half of the key, considered little endian bytewise,
     and pruned.
     
     r = 0x806d5400e52447c036d555408bed685;
     
     c is the msg considered as a litte Endian bytewise integer plus 2^128;
     
     c = 0x17f4620636968706172676f7470797243;
     
     b1 is the bad msg's first block considered as a litte Endian
     bytewise integer plus 2^128;
     
     b1 = 0x1000abdfb8a800301a806d542fe52447f;
     
     b2 is the unknown bad msg's second block.
     
     The mac of the first message will come out to c * r mod p
     before adding s and reducing mod 2^128 (p is 2^130-5 of course).
     We want the mac of the bad message to be the same, ie we want
     
     b1 * r^2 + b2 * r = c * r mod p and solving for b2 this is just
     
     b2 = (c - b1 * r) mod p.                          (1)
     
     We remove the leading 2^128 from b2 and the rest in little endian
     is the second 16 byte block of pBadMsg.
     
     NOTE: If b2 >= 2^129 then just solve the above equation (1) mod 2^128
     as the final step of the algorithm will reduce by 2^128 anyway.
     */
    static const ubyte pBadMsg[32] =
    {
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0xbd, 0x0a, 0x00,
        0x7d, 0x6e, 0xa2, 0x82, 0xb4, 0x77, 0xce, 0x34,
        0x60, 0xd0, 0xff, 0x99, 0xe3, 0x63, 0x4a, 0x90
    };

    intBoolean differ;
    ubyte pMac1[16] = {0};
    ubyte pMac2[16] = {0};
    
    InitMocanaSetupInfo setupInfo = { 0 };
    setupInfo.flags = MOC_NO_AUTOSEED;
    
    status = DIGICERT_initialize(&setupInfo, &gpMocCtx);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    status = (MSTATUS) HARDWARE_ACCEL_INIT();
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
    
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
    {
        retVal = 1;
        goto exit;
    }
#endif

    status = Poly1305_completeDigest(MOC_HASH(hwAccelCtx) pMac1, pMsg, sizeof(pMsg), pKey);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    status = Poly1305_completeDigest(MOC_HASH(hwAccelCtx) pMac2, pBadMsg, sizeof(pBadMsg), pKey);
    UNITTEST_STATUS(__MOC_LINE__, status);
    if (OK != status)
        goto exit;
    
    DIGI_CTIME_MATCH(pMac1, pMac2, 16, &differ);
    retVal += UNITTEST_TRUE(0, 0 == differ);
    
exit:
    
#ifdef __ENABLE_DIGICERT_HW_SIMULATOR_TEST__
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    HARDWARE_ACCEL_UNINIT();
#endif

    DIGICERT_free(&gpMocCtx);
    
#endif
    
    return ( (OK == status) && (0 == retVal) ) ? 0 : 1;
}


/*----------------------------------------------------------------------------*/
