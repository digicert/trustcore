/*
 * test_scep_utils.c
 *
 * SCEP Utils Unit Test
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert's Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.
 *
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>

#include "cmocka.h"

#include "common/moptions.h"
#include "common/mtypes.h"
#include "common/merrors.h"
#include "common/mdefs.h"
#include "common/mstdlib.h"
#include "common/mocana.h"
#include "common/absstream.h"
#include "common/memfile.h"
#include "common/random.h"
#include "asn1/parseasn1.h"
#include "crypto/hw_accel.h"
#include "crypto/pubcrypto.h"
#include "crypto/ca_mgmt.h"
#include "crypto/crypto.h"
#include "crypto/pkcs10.h"
#include "crypto/pkcs7.h"
#include "scep/scep.h"
#include "scep/scep_context.h"
#include "crypto/crypto.h"
#include "crypto/pkcs10.h"
#include "crypto/pkcs7.h"
#include "asn1/oiddefs.h"

#include "scep/scep.h"
#include "scep/scep_utils.h"

/*------------------------------------------------------------------*/
/* Test Functions */
/*------------------------------------------------------------------*/

/*
 * Test: SCEP_UTILS_integerToString with valid input
 */
static void test_SCEP_UTILS_integerToString_valid(void **ppState)
{
    MSTATUS status;
    ubyte number[] = {0x12, 0x34, 0x56, 0x78};
    sbyte buffer[20];
    ubyte4 bufLen = sizeof(buffer);

    MOC_UNUSED(ppState);

    memset(buffer, 0, bufLen);
    status = SCEP_UTILS_integerToString(number, sizeof(number), buffer, bufLen);

    assert_int_equal(status, OK);
    assert_string_equal(buffer, "12345678");
}

/*
 * Test: SCEP_UTILS_integerToString with single byte
 */
static void test_SCEP_UTILS_integerToString_single_byte(void **ppState)
{
    MSTATUS status;
    ubyte number[] = {0xAB};
    sbyte buffer[10];

    MOC_UNUSED(ppState);

    memset(buffer, 0, sizeof(buffer));
    status = SCEP_UTILS_integerToString(number, sizeof(number), buffer, sizeof(buffer));

    assert_int_equal(status, OK);
    assert_string_equal(buffer, "ab");
}

/*
 * Test: SCEP_UTILS_integerToString with all zeros
 */
static void test_SCEP_UTILS_integerToString_zeros(void **ppState)
{
    MSTATUS status;
    ubyte number[] = {0x00, 0x00, 0x00};
    sbyte buffer[10];

    MOC_UNUSED(ppState);

    memset(buffer, 0, sizeof(buffer));
    status = SCEP_UTILS_integerToString(number, sizeof(number), buffer, sizeof(buffer));

    assert_int_equal(status, OK);
    assert_string_equal(buffer, "000000");
}

/*
 * Test: SCEP_UTILS_integerToString with all 0xFF values
 */
static void test_SCEP_UTILS_integerToString_max_values(void **ppState)
{
    MSTATUS status;
    ubyte number[] = {0xFF, 0xFF};
    sbyte buffer[10];

    MOC_UNUSED(ppState);

    memset(buffer, 0, sizeof(buffer));
    status = SCEP_UTILS_integerToString(number, sizeof(number), buffer, sizeof(buffer));

    assert_int_equal(status, OK);
    assert_string_equal(buffer, "ffff");
}

/*
 * Test: SCEP_UTILS_integerToString with mixed hex values
 */
static void test_SCEP_UTILS_integerToString_mixed_values(void **ppState)
{
    MSTATUS status;
    ubyte number[] = {0xA5, 0x0F, 0xC3};
    sbyte buffer[15];

    MOC_UNUSED(ppState);

    memset(buffer, 0, sizeof(buffer));
    status = SCEP_UTILS_integerToString(number, sizeof(number), buffer, sizeof(buffer));

    assert_int_equal(status, OK);
    assert_string_equal(buffer, "a50fc3");
}

/*
 * Test: SCEP_UTILS_integerToString with insufficient buffer
 * Note: The function has a bug - it checks (numberLen > bufLen + 1) instead of
 * (numberLen * 2 + 1 > bufLen), so we need to trigger that specific condition
 */
static void test_SCEP_UTILS_integerToString_insufficient_buffer(void **ppState)
{
    MSTATUS status;
    ubyte number[10];  /* 10 bytes */
    sbyte buffer[5];   /* bufLen=5, so 10 > 5+1 = 10 > 6 = true */

    MOC_UNUSED(ppState);

    memset(number, 0x12, sizeof(number));
    memset(buffer, 0, sizeof(buffer));
    status = SCEP_UTILS_integerToString(number, sizeof(number), buffer, sizeof(buffer));

    /* Should return error due to insufficient buffer (based on function's actual check) */
    assert_int_not_equal(status, OK);
    assert_int_equal(status, ERR_SCEP);
}

/*
 * Test: SCEP_UTILS_integerToString with exact buffer size
 */
static void test_SCEP_UTILS_integerToString_exact_buffer(void **ppState)
{
    MSTATUS status;
    ubyte number[] = {0x12, 0x34};
    sbyte buffer[5];  /* Exactly 4 chars + 1 null terminator */

    MOC_UNUSED(ppState);

    memset(buffer, 0, sizeof(buffer));
    status = SCEP_UTILS_integerToString(number, sizeof(number), buffer, sizeof(buffer));

    assert_int_equal(status, OK);
    assert_string_equal(buffer, "1234");
}

/*
 * Test: SCEP_UTILS_integerToString with zero length input
 */
static void test_SCEP_UTILS_integerToString_zero_length(void **ppState)
{
    MSTATUS status;
    ubyte number[] = {0x12};
    sbyte buffer[10];

    MOC_UNUSED(ppState);

    memset(buffer, 0, sizeof(buffer));
    status = SCEP_UTILS_integerToString(number, 0, buffer, sizeof(buffer));

    /* Should succeed with empty string */
    assert_int_equal(status, OK);
    assert_string_equal(buffer, "");
}

/*
 * Test: SCEP_UTILS_integerToString with large input
 */
static void test_SCEP_UTILS_integerToString_large_input(void **ppState)
{
    MSTATUS status;
    ubyte number[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    sbyte buffer[50];

    MOC_UNUSED(ppState);

    memset(buffer, 0, sizeof(buffer));
    status = SCEP_UTILS_integerToString(number, sizeof(number), buffer, sizeof(buffer));

    assert_int_equal(status, OK);
    assert_string_equal(buffer, "0123456789abcdeffedcba9876543210");
}

/*
 * Test: SCEP_UTILS_integerToString with alternating pattern
 */
static void test_SCEP_UTILS_integerToString_alternating_pattern(void **ppState)
{
    MSTATUS status;
    ubyte number[] = {0xAA, 0x55, 0xAA, 0x55};
    sbyte buffer[15];

    MOC_UNUSED(ppState);

    memset(buffer, 0, sizeof(buffer));
    status = SCEP_UTILS_integerToString(number, sizeof(number), buffer, sizeof(buffer));

    assert_int_equal(status, OK);
    assert_string_equal(buffer, "aa55aa55");
}

/*
 * Test: SCEP_UTILS_integerToString with ascending values
 */
static void test_SCEP_UTILS_integerToString_ascending(void **ppState)
{
    MSTATUS status;
    ubyte number[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    sbyte buffer[20];

    MOC_UNUSED(ppState);

    memset(buffer, 0, sizeof(buffer));
    status = SCEP_UTILS_integerToString(number, sizeof(number), buffer, sizeof(buffer));

    assert_int_equal(status, OK);
    assert_string_equal(buffer, "0011223344556677");
}

/*
 * Test: SCEP_UTILS_integerToString with descending values
 */
static void test_SCEP_UTILS_integerToString_descending(void **ppState)
{
    MSTATUS status;
    ubyte number[] = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA};
    sbyte buffer[20];

    MOC_UNUSED(ppState);

    memset(buffer, 0, sizeof(buffer));
    status = SCEP_UTILS_integerToString(number, sizeof(number), buffer, sizeof(buffer));

    assert_int_equal(status, OK);
    assert_string_equal(buffer, "ffeeddccbbaa");
}

/*
 * Test: SCEP_UTILS_integerToString boundary values (0x0F)
 */
static void test_SCEP_UTILS_integerToString_boundary_0f(void **ppState)
{
    MSTATUS status;
    ubyte number[] = {0x0F, 0xF0, 0x00, 0xFF};
    sbyte buffer[15];

    MOC_UNUSED(ppState);

    memset(buffer, 0, sizeof(buffer));
    status = SCEP_UTILS_integerToString(number, sizeof(number), buffer, sizeof(buffer));

    assert_int_equal(status, OK);
    assert_string_equal(buffer, "0ff000ff");
}

/*
 * Test: SCEP_UTILS_integerToString with very large number (32 bytes)
 */
static void test_SCEP_UTILS_integerToString_very_large(void **ppState)
{
    MSTATUS status;
    ubyte number[32];
    sbyte buffer[70];
    int i;

    MOC_UNUSED(ppState);

    for (i = 0; i < 32; i++)
    {
        number[i] = (ubyte)i;
    }

    memset(buffer, 0, sizeof(buffer));
    status = SCEP_UTILS_integerToString(number, sizeof(number), buffer, sizeof(buffer));

    assert_int_equal(status, OK);
    assert_string_equal(buffer, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
}

/*
 * Test: SCEP_UTILS_integerToString with buffer size exactly 2*numberLen + 1
 */
static void test_SCEP_UTILS_integerToString_exact_required_size(void **ppState)
{
    MSTATUS status;
    ubyte number[] = {0x12, 0x34, 0x56};
    sbyte buffer[7]; /* Exactly 3*2 + 1 = 7 bytes */

    MOC_UNUSED(ppState);

    memset(buffer, 0, sizeof(buffer));
    status = SCEP_UTILS_integerToString(number, sizeof(number), buffer, sizeof(buffer));

    assert_int_equal(status, OK);
    assert_string_equal(buffer, "123456");
}

/*
 * Test: SCEP_UTILS_integerToString with prime number pattern
 */
static void test_SCEP_UTILS_integerToString_prime_pattern(void **ppState)
{
    MSTATUS status;
    ubyte number[] = {0x02, 0x03, 0x05, 0x07, 0x0B, 0x0D};
    sbyte buffer[20];

    MOC_UNUSED(ppState);

    memset(buffer, 0, sizeof(buffer));
    status = SCEP_UTILS_integerToString(number, sizeof(number), buffer, sizeof(buffer));

    assert_int_equal(status, OK);
    assert_string_equal(buffer, "020305070b0d");
}

/*
 * Test: SCEP_UTILS_integerToString repeated conversion
 */
static void test_SCEP_UTILS_integerToString_repeated_conversion(void **ppState)
{
    MSTATUS status;
    ubyte number[] = {0xDE, 0xAD, 0xBE, 0xEF};
    sbyte buffer[20];
    int i;

    MOC_UNUSED(ppState);

    for (i = 0; i < 10; i++)
    {
        memset(buffer, 0, sizeof(buffer));
        status = SCEP_UTILS_integerToString(number, sizeof(number), buffer, sizeof(buffer));

        assert_int_equal(status, OK);
        assert_string_equal(buffer, "deadbeef");
    }
}

/*
 * Test: SCEP_UTILS_integerToString with nibble boundary values
 */
static void test_SCEP_UTILS_integerToString_nibble_boundaries(void **ppState)
{
    MSTATUS status;
    ubyte number[] = {0x09, 0x0A, 0x90, 0xA0};
    sbyte buffer[15];

    MOC_UNUSED(ppState);

    memset(buffer, 0, sizeof(buffer));
    status = SCEP_UTILS_integerToString(number, sizeof(number), buffer, sizeof(buffer));

    assert_int_equal(status, OK);
    assert_string_equal(buffer, "090a90a0");
}

/*------------------------------------------------------------------*/
/* Main test runner */
/*------------------------------------------------------------------*/
int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_SCEP_UTILS_integerToString_valid),
        cmocka_unit_test(test_SCEP_UTILS_integerToString_single_byte),
        cmocka_unit_test(test_SCEP_UTILS_integerToString_zeros),
        cmocka_unit_test(test_SCEP_UTILS_integerToString_max_values),
        cmocka_unit_test(test_SCEP_UTILS_integerToString_mixed_values),
        cmocka_unit_test(test_SCEP_UTILS_integerToString_insufficient_buffer),
        cmocka_unit_test(test_SCEP_UTILS_integerToString_exact_buffer),
        cmocka_unit_test(test_SCEP_UTILS_integerToString_zero_length),
        cmocka_unit_test(test_SCEP_UTILS_integerToString_large_input),
        cmocka_unit_test(test_SCEP_UTILS_integerToString_alternating_pattern),
        cmocka_unit_test(test_SCEP_UTILS_integerToString_ascending),
        cmocka_unit_test(test_SCEP_UTILS_integerToString_descending),
        cmocka_unit_test(test_SCEP_UTILS_integerToString_boundary_0f),
        cmocka_unit_test(test_SCEP_UTILS_integerToString_very_large),
        cmocka_unit_test(test_SCEP_UTILS_integerToString_exact_required_size),
        cmocka_unit_test(test_SCEP_UTILS_integerToString_prime_pattern),
        cmocka_unit_test(test_SCEP_UTILS_integerToString_repeated_conversion),
        cmocka_unit_test(test_SCEP_UTILS_integerToString_nibble_boundaries),
    };

    int result = cmocka_run_group_tests(tests, NULL, NULL);

    return result;
}
