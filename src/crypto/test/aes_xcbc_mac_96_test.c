/*
 *  ca_mgmt_test.c
 *
 *   unit test for ca_mgmt.c
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

#include "../aes_xcbc_mac_96.c"

#include "../../../unit_tests/unittest.h"

/* Test vectors from RFC 3566 ***********************************
Test Case #1 : AES-XCBC-MAC-96 with 0-byte input
Key (K) : 000102030405060708090a0b0c0d0e0f
Message (M) : <empty string>
AES-XCBC-MAC : 75f0251d528ac01c4573dfd584d79f29
AES-XCBC-MAC-96: 75f0251d528ac01c4573dfd5

Test Case #2 : AES-XCBC-MAC-96 with 3-byte input
Key (K) : 000102030405060708090a0b0c0d0e0f
Message (M) : 000102
AES-XCBC-MAC : 5b376580ae2f19afe7219ceef172756f
AES-XCBC-MAC-96: 5b376580ae2f19afe7219cee

Test Case #3 : AES-XCBC-MAC-96 with 16-byte input
Key (K) : 000102030405060708090a0b0c0d0e0f
Message (M) : 000102030405060708090a0b0c0d0e0f
AES-XCBC-MAC : d2a246fa349b68a79998a4394ff7a263
AES-XCBC-MAC-96: d2a246fa349b68a79998a439

Test Case #4 : AES-XCBC-MAC-96 with 20-byte input
Key (K) : 000102030405060708090a0b0c0d0e0f
Message (M) : 000102030405060708090a0b0c0d0e0f10111213
AES-XCBC-MAC : 47f51b4564966215b8985c63055ed308
AES-XCBC-MAC-96: 47f51b4564966215b8985c63

Test Case #5 : AES-XCBC-MAC-96 with 32-byte input
Key (K) : 000102030405060708090a0b0c0d0e0f
Message (M) : 000102030405060708090a0b0c0d0e0f10111213141516171819
1a1b1c1d1e1f
AES-XCBC-MAC : f54f0ec8d2b9f3d36807734bd5283fd4
AES-XCBC-MAC-96: f54f0ec8d2b9f3d36807734b

Test Case #6 : AES-XCBC-MAC-96 with 34-byte input
Key (K) : 000102030405060708090a0b0c0d0e0f
Message (M) : 000102030405060708090a0b0c0d0e0f10111213141516171819
1a1b1c1d1e1f2021
AES-XCBC-MAC : becbb3bccdb518a30677d5481fb6b4d8
AES-XCBC-MAC-96: becbb3bccdb518a30677d548

Test Case #7 : AES-XCBC-MAC-96 with 1000-byte input
Key (K) : 000102030405060708090a0b0c0d0e0f
Message (M) : 00000000000000000000 ... 00000000000000000000
[1000 bytes]
AES-XCBC-MAC : f0dafee895db30253761103b5d84528f
AES-XCBC-MAC-96: f0dafee895db30253761103b

****************************************************************/

/* Test vectors from RFC 4434 ***********************************

(duplicate of TestCase #4 of RFC 3566 )
   Test Case AES-XCBC-PRF-128 with 20-byte input
   Key        : 000102030405060708090a0b0c0d0e0f
   Key Length : 16
   Message    : 000102030405060708090a0b0c0d0e0f10111213
   PRF Output : 47f51b4564966215b8985c63055ed308

   Test Case AES-XCBC-PRF-128 with 20-byte input
   Key        : 00010203040506070809
   Key Length : 10
   Message    : 000102030405060708090a0b0c0d0e0f10111213
   PRF Output : 0fa087af7d866e7653434e602fdde835

   Test Case AES-XCBC-PRF-128 with 20-byte input
   Key        : 000102030405060708090a0b0c0d0e0fedcb
   Key Length : 18
   Message    : 000102030405060708090a0b0c0d0e0f10111213
   PRF Output : 8cd3c93ae598a9803006ffb67c40e9e4

****************************************************************/

typedef struct AES_CBC_MAC_96_TestVector
{
    const ubyte*    message;
    sbyte4          messageLen;
    const ubyte     mac[AES_XCBC_MAC_96_RESULT_SIZE];
} AES_CBC_MAC_96_TestVector;

static AES_CBC_MAC_96_TestVector mac96TV[] =
{
/* Test Case #1 : AES-XCBC-MAC-96 with 0-byte input     */
    { "\x00", 0,
    { 0x75, 0xf0, 0x25, 0x1d, 0x52, 0x8a, 0xc0, 0x1c, 0x45, 0x73, 0xdf, 0xd5} },

/* Test Case #2 : AES-XCBC-MAC-96 with 3-byte input */
    { "\x00\x01\x02", 3,
    { 0x5b, 0x37, 0x65, 0x80, 0xae, 0x2f, 0x19, 0xaf, 0xe7, 0x21, 0x9c, 0xee} },

/* Test Case #3 : AES-XCBC-MAC-96 with 16-byte input */
    { "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16,
    { 0xd2, 0xa2, 0x46, 0xfa, 0x34, 0x9b, 0x68, 0xa7, 0x99, 0x98, 0xa4, 0x39} },

/* Test Case #4 : AES-XCBC-MAC-96 with 20-byte input */
    { "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        "\x10\x11\x12\x13", 20,
    { 0x47, 0xf5, 0x1b, 0x45, 0x64, 0x96, 0x62, 0x15, 0xb8, 0x98, 0x5c, 0x63} },

/* Test Case #5 : AES-XCBC-MAC-96 with 32-byte input */
    { "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
      "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f", 32,
    { 0xf5, 0x4f, 0x0e, 0xc8, 0xd2, 0xb9, 0xf3, 0xd3, 0x68, 0x07, 0x73, 0x4b} },

/* Test Case #6 : AES-XCBC-MAC-96 with 34-byte input */
    { "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
      "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
      "\x20\x21", 34,
    { 0xbe, 0xcb, 0xb3, 0xbc, 0xcd, 0xb5, 0x18, 0xa3, 0x06, 0x77, 0xd5, 0x48} },
};


/* key */
static const ubyte K[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };


typedef struct AES_CBC_PRF_128_TestVector
{
    const ubyte*    key;
    sbyte4          keyLen;
    const ubyte*    message;
    sbyte4          messageLen;
    const ubyte     mac[AES_XCBC_PRF_128_RESULT_SIZE];
} AES_CBC_PRF_128_TestVector;


static AES_CBC_PRF_128_TestVector prf128TV[] =
{
/* Test Case #1 : AES-XCBC-PRF-128 with 0-byte input     */
    {
       "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16,
       "\x00", 0,
    { 0x75, 0xf0, 0x25, 0x1d, 0x52, 0x8a, 0xc0, 0x1c, 0x45, 0x73, 0xdf, 0xd5, 0x84, 0xd7, 0x9f, 0x29 } },

/* Test Case #2 : AES-XCBC-PRF-128 with 3-byte input */
    {
       "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16,
        "\x00\x01\x02", 3,
    { 0x5b, 0x37, 0x65, 0x80, 0xae, 0x2f, 0x19, 0xaf, 0xe7, 0x21, 0x9c, 0xee, 0xf1, 0x72, 0x75, 0x6f } },

/* Test Case #3 : AES-XCBC-PRF-128 with 16-byte input */
    {
       "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16,
       "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16,
    { 0xd2, 0xa2, 0x46, 0xfa, 0x34, 0x9b, 0x68, 0xa7, 0x99, 0x98, 0xa4, 0x39, 0x4f, 0xf7, 0xa2, 0x63 } },

/* Test Case #4 : AES-XCBC-PRF-128 with 20-byte input */
    {
       "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16,
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        "\x10\x11\x12\x13", 20,
    { 0x47, 0xf5, 0x1b, 0x45, 0x64, 0x96, 0x62, 0x15, 0xb8, 0x98, 0x5c, 0x63, 0x05, 0x5e, 0xd3, 0x08 } },

/* Test Case #5 : AES-XCBC-PRF-128 with 32-byte input */
    {
       "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16,
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f", 32,
    { 0xf5, 0x4f, 0x0e, 0xc8, 0xd2, 0xb9, 0xf3, 0xd3, 0x68, 0x07, 0x73, 0x4b, 0xd5, 0x28, 0x3f, 0xd4 } },

/* Test Case #6 : AES-XCBC-PRF-128 with 34-byte input */
    {
       "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 16,
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
        "\x20\x21", 34,
    { 0xbe, 0xcb, 0xb3, 0xbc, 0xcd, 0xb5, 0x18, 0xa3, 0x06, 0x77, 0xd5, 0x48, 0x1f, 0xb6, 0xb4, 0xd8 } },

/* Test Case #7: Test Case #4 with key length = 10 */
    {
       "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09", 10,
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        "\x10\x11\x12\x13", 20,
    { 0x0f, 0xa0, 0x87, 0xaf, 0x7d, 0x86, 0x6e, 0x76, 0x53, 0x43, 0x4e, 0x60, 0x2f, 0xdd, 0xe8, 0x35 } },

/* Test Case #8: Test Case #4 with key length = 18 */
    {
       "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\xed\xcb", 18,
        "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        "\x10\x11\x12\x13", 20,
    { 0x8c, 0xd3, 0xc9, 0x3a, 0xe5, 0x98, 0xa9, 0x80, 0x30, 0x06, 0xff, 0xb6, 0x7c, 0x40, 0xe9, 0xe4 } },
};


/*---------------------------------------------------------------------------*/

static int
big_test_mac_96()
{
    /* Test Case #7 : AES-XCBC-MAC-96 with 1000-byte input */
    const ubyte k1000ZeroMac[] = { 0xf0, 0xda, 0xfe, 0xe8,
                                    0x95, 0xdb, 0x30, 0x25,
                                    0x37, 0x61, 0x10, 0x3b};
    AES_XCBC_MAC_96_Ctx ctx;
    int                 errors = 0;
    sbyte4              i, cmpRes;
    ubyte               mac[AES_XCBC_MAC_96_RESULT_SIZE];
    MSTATUS             status;
    ubyte               message[100] = {0};
    hwAccelDescr        hwAccelCtx;

    if (OK > (MSTATUS)(errors = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return errors;

    /* send the message byte by byte, 2 bytes by 2 bytes, etc... */
    for ( i = 1; i <= 100; ++i)
    {
        sbyte4 sent = 0;

        status = AES_XCBC_MAC_96_init(MOC_SYM(hwAccelCtx)K, &ctx);
        errors += UNITTEST_STATUS( 0, status);
        while ( sent < 1000)
        {
            sbyte4 toSend;
            toSend = i;
            if ( toSend > 1000 - sent)
            {
                toSend = 1000 - sent;
            }
            status = AES_XCBC_MAC_96_update(MOC_SYM(hwAccelCtx) message, toSend, &ctx);
            errors += UNITTEST_STATUS( 0, status);
            sent += toSend;

        }

        DIGI_MEMSET(mac, 0, AES_XCBC_MAC_96_RESULT_SIZE);
        status = AES_XCBC_MAC_96_final(MOC_SYM(hwAccelCtx) mac, &ctx);
        errors += UNITTEST_STATUS( 0, status);

        DIGI_MEMCMP( mac, k1000ZeroMac, AES_XCBC_MAC_96_RESULT_SIZE, &cmpRes);
        errors += UNITTEST_INT( 0, cmpRes + i, i); /* trick to get the i info in error message */

        /* test reset */
        sent = 0;
        status = AES_XCBC_MAC_96_reset(MOC_SYM(hwAccelCtx) &ctx);
        errors += UNITTEST_STATUS( 0, status);
        while ( sent < 1000)
        {
            sbyte4 toSend;
            toSend = i;
            if ( toSend > 1000 - sent)
            {
                toSend = 1000 - sent;
            }
            status = AES_XCBC_MAC_96_update(MOC_SYM(hwAccelCtx) message, toSend, &ctx);
            errors += UNITTEST_STATUS( 0, status);
            sent += toSend;

        }
        DIGI_MEMSET(mac, 0, AES_XCBC_MAC_96_RESULT_SIZE);
        status = AES_XCBC_MAC_96_final(MOC_SYM(hwAccelCtx) mac, &ctx);
        errors += UNITTEST_STATUS( 0, status);

        DIGI_MEMCMP( mac, k1000ZeroMac, AES_XCBC_MAC_96_RESULT_SIZE, &cmpRes);
        errors += UNITTEST_INT( 0, cmpRes + i, i); /* trick to get the i info in error message */

        status = AES_XCBC_clear (MOC_SYM(hwAccelCtx) &ctx);
        errors += UNITTEST_STATUS( 0, status);
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return errors;
}


/*---------------------------------------------------------------------------*/

static int
big_test_prf_128()
{
    /* Test Case #7 : AES-XCBC-PRF-128 with 1000-byte input */
    const ubyte k1000ZeroMac[] = { 0xf0, 0xda, 0xfe, 0xe8,
                                    0x95, 0xdb, 0x30, 0x25,
                                    0x37, 0x61, 0x10, 0x3b,
                                    0x5d, 0x84, 0x52, 0x8f};
    AES_XCBC_PRF_128_Ctx ctx;
    int                 errors = 0;
    sbyte4              i, cmpRes;
    ubyte               mac[AES_XCBC_PRF_128_RESULT_SIZE];
    MSTATUS             status;
    ubyte               message[100] = {0};
    hwAccelDescr        hwAccelCtx;

    if (OK > (MSTATUS)(errors = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return errors;

    /* send the message byte by byte, 2 bytes by 2 bytes, etc... */
    for ( i = 1; i <= 100; ++i)
    {
        sbyte4 sent = 0;

        status = AES_XCBC_PRF_128_init(MOC_SYM(hwAccelCtx)K, 16, &ctx);
        errors += UNITTEST_STATUS( 0, status);
        while ( sent < 1000)
        {
            sbyte4 toSend;
            toSend = i;
            if ( toSend > 1000 - sent)
            {
                toSend = 1000 - sent;
            }
            status = AES_XCBC_PRF_128_update(MOC_SYM(hwAccelCtx) message, toSend, &ctx);
            errors += UNITTEST_STATUS( 0, status);
            sent += toSend;

        }

        DIGI_MEMSET(mac, 0, AES_XCBC_PRF_128_RESULT_SIZE);
        status = AES_XCBC_PRF_128_final(MOC_SYM(hwAccelCtx) mac, &ctx);
        errors += UNITTEST_STATUS( 0, status);

        DIGI_MEMCMP( mac, k1000ZeroMac, AES_XCBC_PRF_128_RESULT_SIZE, &cmpRes);
        errors += UNITTEST_INT( 0, cmpRes + i, i); /* trick to get the i info in error message */

        /* test reset */
        sent = 0;
        status = AES_XCBC_PRF_128_reset(MOC_SYM(hwAccelCtx) &ctx);
        errors += UNITTEST_STATUS( 0, status);
        while ( sent < 1000)
        {
            sbyte4 toSend;
            toSend = i;
            if ( toSend > 1000 - sent)
            {
                toSend = 1000 - sent;
            }
            status = AES_XCBC_PRF_128_update(MOC_SYM(hwAccelCtx) message, toSend, &ctx);
            errors += UNITTEST_STATUS( 0, status);
            sent += toSend;

        }

        DIGI_MEMSET(mac, 0, AES_XCBC_PRF_128_RESULT_SIZE);
        status = AES_XCBC_PRF_128_final(MOC_SYM(hwAccelCtx) mac, &ctx);
        errors += UNITTEST_STATUS( 0, status);

        DIGI_MEMCMP( mac, k1000ZeroMac, AES_XCBC_PRF_128_RESULT_SIZE, &cmpRes);
        errors += UNITTEST_INT( 0, cmpRes + i, i); /* trick to get the i info in error message */

        status = AES_XCBC_clear (MOC_SYM(hwAccelCtx) &ctx);
        errors += UNITTEST_STATUS( 0, status);
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return errors;
}


/*---------------------------------------------------------------------------*/

static int
test_vector_mac_96(  AES_CBC_MAC_96_TestVector* pWhichTest, int hint)
{
    AES_XCBC_MAC_96_Ctx ctx;
    int         errors = 0;
    sbyte4      i, cmpRes;
    ubyte       mac[AES_XCBC_MAC_96_RESULT_SIZE];
    MSTATUS     status;
    hwAccelDescr        hwAccelCtx;

    if (OK > (MSTATUS)(errors = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return errors;

    /* special case */
    if (  0 == pWhichTest->messageLen)
    {
        status = AES_XCBC_MAC_96_init(MOC_SYM(hwAccelCtx)K, &ctx);
        errors += UNITTEST_STATUS( hint, status);

        status = AES_XCBC_MAC_96_final(MOC_SYM(hwAccelCtx) mac, &ctx);
        errors += UNITTEST_STATUS( hint, status);

        DIGI_MEMCMP( mac, pWhichTest->mac, AES_XCBC_MAC_96_RESULT_SIZE, &cmpRes);
        errors += UNITTEST_INT( hint, cmpRes, 0);

        /* test reset */
        status = AES_XCBC_MAC_96_reset(MOC_SYM(hwAccelCtx) &ctx);
        errors += UNITTEST_STATUS( hint, status);

        DIGI_MEMSET(mac, 0, AES_XCBC_MAC_96_RESULT_SIZE);
        status = AES_XCBC_MAC_96_final(MOC_SYM(hwAccelCtx) mac, &ctx);
        errors += UNITTEST_STATUS( hint, status);

        DIGI_MEMCMP( mac, pWhichTest->mac, AES_XCBC_MAC_96_RESULT_SIZE, &cmpRes);
        errors += UNITTEST_INT( hint, cmpRes, 0);

        status = AES_XCBC_clear (MOC_SYM(hwAccelCtx) &ctx);
        errors += UNITTEST_STATUS( hint, status);

        goto exit;
    }

    /* send the message byte by byte, 2 bytes by 2 bytes, etc... */
    for ( i = 1; i <= pWhichTest->messageLen; ++i)
    {
        sbyte4 sent = 0;

        status = AES_XCBC_MAC_96_init(MOC_SYM(hwAccelCtx)K, &ctx);
        errors += UNITTEST_STATUS( hint, status);
        while ( sent < pWhichTest->messageLen)
        {
            sbyte4 toSend;
            toSend = i;
            if ( toSend > pWhichTest->messageLen - sent)
            {
                toSend = pWhichTest->messageLen - sent;
            }
            status = AES_XCBC_MAC_96_update(MOC_SYM(hwAccelCtx) pWhichTest->message + sent, toSend, &ctx);
            errors += UNITTEST_STATUS( hint, status);
            sent += toSend;

        }
        DIGI_MEMSET(mac, 0, AES_XCBC_MAC_96_RESULT_SIZE);
        status = AES_XCBC_MAC_96_final(MOC_SYM(hwAccelCtx) mac, &ctx);
        errors += UNITTEST_STATUS( hint, status);

        DIGI_MEMCMP( mac, pWhichTest->mac, AES_XCBC_MAC_96_RESULT_SIZE, &cmpRes);
        errors += UNITTEST_INT( hint, cmpRes + i, i); /* trick to get the i info in error message */

        /* test reset */
        sent = 0;
        status = AES_XCBC_MAC_96_reset(MOC_SYM(hwAccelCtx) &ctx);
        errors += UNITTEST_STATUS( hint, status);
        while ( sent < pWhichTest->messageLen)
        {
            sbyte4 toSend;
            toSend = i;
            if ( toSend > pWhichTest->messageLen - sent)
            {
                toSend = pWhichTest->messageLen - sent;
            }
            status = AES_XCBC_MAC_96_update(MOC_SYM(hwAccelCtx) pWhichTest->message + sent, toSend, &ctx);
            errors += UNITTEST_STATUS( hint, status);
            sent += toSend;

        }
        DIGI_MEMSET(mac, 0, AES_XCBC_MAC_96_RESULT_SIZE);
        status = AES_XCBC_MAC_96_final(MOC_SYM(hwAccelCtx) mac, &ctx);
        errors += UNITTEST_STATUS( hint, status);

        DIGI_MEMCMP( mac, pWhichTest->mac, AES_XCBC_MAC_96_RESULT_SIZE, &cmpRes);
        errors += UNITTEST_INT( hint, cmpRes + i, i); /* trick to get the i info in error message */

        status = AES_XCBC_clear (MOC_SYM(hwAccelCtx) &ctx);
        errors += UNITTEST_STATUS( hint, status);
    }

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return errors;
}


/*---------------------------------------------------------------------------*/

static int
test_vector_prf_128(  AES_CBC_PRF_128_TestVector* pWhichTest, int hint)
{
    AES_XCBC_PRF_128_Ctx ctx;
    int         errors = 0;
    sbyte4      i, cmpRes;
    ubyte       mac[AES_XCBC_PRF_128_RESULT_SIZE];
    MSTATUS     status;
    hwAccelDescr        hwAccelCtx;

    if (OK > (MSTATUS)(errors = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_SSL, &hwAccelCtx)))
        return errors;

    /* special case */
    if (  0 == pWhichTest->messageLen)
    {
        status = AES_XCBC_PRF_128_init(MOC_SYM(hwAccelCtx)pWhichTest->key, pWhichTest->keyLen, &ctx);
        errors += UNITTEST_STATUS( hint, status);

        status = AES_XCBC_PRF_128_final(MOC_SYM(hwAccelCtx) mac, &ctx);
        errors += UNITTEST_STATUS( hint, status);

        DIGI_MEMCMP( mac, pWhichTest->mac, AES_XCBC_PRF_128_RESULT_SIZE, &cmpRes);
        errors += UNITTEST_INT( hint, cmpRes, 0);

        /* test reset */
        status = AES_XCBC_PRF_128_reset(MOC_SYM(hwAccelCtx) &ctx);
        errors += UNITTEST_STATUS( hint, status);

        DIGI_MEMSET( mac, 0, AES_XCBC_PRF_128_RESULT_SIZE);
        status = AES_XCBC_PRF_128_final(MOC_SYM(hwAccelCtx) mac, &ctx);
        errors += UNITTEST_STATUS( hint, status);

        DIGI_MEMCMP( mac, pWhichTest->mac, AES_XCBC_PRF_128_RESULT_SIZE, &cmpRes);
        errors += UNITTEST_INT( hint, cmpRes, 0);

        status = AES_XCBC_clear (MOC_SYM(hwAccelCtx) &ctx);
        errors += UNITTEST_STATUS( hint, status);

        goto exit;
    }

    /* send the message byte by byte, 2 bytes by 2 bytes, etc... */
    for ( i = 1; i <= pWhichTest->messageLen; ++i)
    {
        sbyte4 sent = 0;

        status = AES_XCBC_PRF_128_init(MOC_SYM(hwAccelCtx)pWhichTest->key, pWhichTest->keyLen, &ctx);
        errors += UNITTEST_STATUS( hint, status);
        while ( sent < pWhichTest->messageLen)
        {
            sbyte4 toSend;
            toSend = i;
            if ( toSend > pWhichTest->messageLen - sent)
            {
                toSend = pWhichTest->messageLen - sent;
            }
            status = AES_XCBC_PRF_128_update(MOC_SYM(hwAccelCtx) pWhichTest->message + sent, toSend, &ctx);
            errors += UNITTEST_STATUS( hint, status);
            sent += toSend;

        }
        DIGI_MEMSET(mac, 0, AES_XCBC_PRF_128_RESULT_SIZE);
        status = AES_XCBC_PRF_128_final(MOC_SYM(hwAccelCtx) mac, &ctx);
        errors += UNITTEST_STATUS( hint, status);

        DIGI_MEMCMP( mac, pWhichTest->mac, AES_XCBC_PRF_128_RESULT_SIZE, &cmpRes);
        errors += UNITTEST_INT( hint, cmpRes + i, i); /* trick to get the i info in error message */

        /* test reset */
        sent = 0;
        status = AES_XCBC_PRF_128_reset(MOC_SYM(hwAccelCtx) &ctx);
        errors += UNITTEST_STATUS( hint, status);
        while ( sent < pWhichTest->messageLen)
        {
            sbyte4 toSend;
            toSend = i;
            if ( toSend > pWhichTest->messageLen - sent)
            {
                toSend = pWhichTest->messageLen - sent;
            }
            status = AES_XCBC_PRF_128_update(MOC_SYM(hwAccelCtx) pWhichTest->message + sent, toSend, &ctx);
            errors += UNITTEST_STATUS( hint, status);
            sent += toSend;

        }
        DIGI_MEMSET(mac, 0, AES_XCBC_PRF_128_RESULT_SIZE);
        status = AES_XCBC_PRF_128_final(MOC_SYM(hwAccelCtx) mac, &ctx);
        errors += UNITTEST_STATUS( hint, status);

        DIGI_MEMCMP( mac, pWhichTest->mac, AES_XCBC_PRF_128_RESULT_SIZE, &cmpRes);
        errors += UNITTEST_INT( hint, cmpRes + i, i); /* trick to get the i info in error message */

        status = AES_XCBC_clear (MOC_SYM(hwAccelCtx) &ctx);
        errors += UNITTEST_STATUS( hint, status);
    }

exit:
    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_SSL, &hwAccelCtx);

    return errors;
}


/*---------------------------------------------------------------------------*/

int aes_xcbc_mac_96_test_mac_96()
{
    int retVal = 0;
    int i;

    for (i = 0; i < COUNTOF(mac96TV); ++i)
    {
        retVal +=  test_vector_mac_96( mac96TV+i, i);
    }

    retVal += big_test_mac_96();

    return retVal;
}


/*---------------------------------------------------------------------------*/

int aes_xcbc_mac_96_test_prf_128()
{
    int retVal = 0;
    int i;

    for (i = 0; i < COUNTOF(prf128TV); ++i)
    {
        retVal +=  test_vector_prf_128( prf128TV+i, i);
    }

    retVal += big_test_prf_128();

    return retVal;
}

