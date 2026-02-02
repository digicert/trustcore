/*
 * test_est_utils.c
 *
 * EST Utils Unit Test
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert's Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include "cmocka.h"

#include "common/moptions.h"
#include "common/mtypes.h"
#include "common/merrors.h"
#include "common/mdefs.h"
#include "common/mstdlib.h"
#include "common/mocana.h"

#include "est/est_utils.h"

/*------------------------------------------------------------------*/
/* Test Functions */
/*------------------------------------------------------------------*/

static void test_EST_UTILS_filterPkcs7Message_valid_base64(void **ppState)
{
    /* Valid base64 string with no whitespace */
    ubyte input1[] = "SGVsbG9Xb3JsZA==";
    ubyte4 len1 = DIGI_STRLEN((sbyte *)input1);
    ubyte4 result1;

    result1 = EST_UTILS_filterPkcs7Message(input1, len1);
    assert_int_equal(result1, len1);
}

static void test_EST_UTILS_filterPkcs7Message_with_newlines(void **ppState)
{
    /* Base64 with newlines (should be filtered) */
    ubyte input2[] = "SGVsbG9\nXb3JsZA==";
    ubyte4 len2 = DIGI_STRLEN((sbyte *)input2);
    ubyte4 result2;
    ubyte4 expected_len2 = len2 - 1; /* One newline to filter */

    result2 = EST_UTILS_filterPkcs7Message(input2, len2);
    assert_int_equal(result2, expected_len2);
}

static void test_EST_UTILS_filterPkcs7Message_with_spaces(void **ppState)
{
    /* Base64 with spaces (should be filtered) */
    ubyte input3[] = "SGVs bG9X b3Js ZA==";
    ubyte4 len3 = DIGI_STRLEN((sbyte *)input3);
    ubyte4 result3;
    ubyte4 expected_len3 = len3 - 3; /* Three spaces to filter */

    result3 = EST_UTILS_filterPkcs7Message(input3, len3);
    assert_int_equal(result3, expected_len3);
}

static void test_EST_UTILS_filterPkcs7Message_mixed_whitespace(void **ppState)
{
    /* Base64 with mixed whitespace */
    ubyte input4[] = "SGVs\nbG9X\r\nb3Js\tZA==";
    ubyte4 len4 = DIGI_STRLEN((sbyte *)input4);
    ubyte4 result4;

    result4 = EST_UTILS_filterPkcs7Message(input4, len4);
    assert_true(result4 < len4);
}

static void test_EST_UTILS_filterPkcs7Message_empty_input(void **ppState)
{
    ubyte input5[] = "";
    ubyte4 len5 = 0;
    ubyte4 result5;

    result5 = EST_UTILS_filterPkcs7Message(input5, len5);
    assert_int_equal(result5, 0);
}

static void test_EST_UTILS_filterPkcs7Message_verify_filtered_content(void **ppState)
{
    ubyte input[] = "SGVs\nbG9X\r\nb3Js\tZA==";
    ubyte4 len = DIGI_STRLEN((sbyte *)input);
    ubyte4 result;
    ubyte expected[] = "SGVsbG9Xb3JsZA==";
    sbyte4 cmp;

    result = EST_UTILS_filterPkcs7Message(input, len);

    assert_int_equal(result, DIGI_STRLEN((sbyte *)expected));

    DIGI_MEMCMP(input, expected, result, &cmp);
    assert_int_equal(cmp, 0);
}

static void test_EST_UTILS_filterPkcs7Message_real_base64_cert(void **ppState)
{
    ubyte input[] = "MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiIMA0GCSqGSIb3Df\n"
                    "EBBQUAA4GBADLm88kLG3t/v1bh2BdNBh8VnkjCO8P4sNBT\n"
                    "pQUX5UPgEMbOCO8P4sNBTXMfUdM9k=";
    ubyte4 len = DIGI_STRLEN((sbyte *)input);
    ubyte4 result;
    ubyte4 originalLen = len;

    result = EST_UTILS_filterPkcs7Message(input, len);

    assert_true(result < originalLen);
    assert_true(result > 0);
}

static void test_EST_UTILS_filterPkcs7Message_only_base64_chars(void **ppState)
{
    ubyte input[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/==";
    ubyte4 len = DIGI_STRLEN((sbyte *)input);
    ubyte4 originalLen = len;
    ubyte4 result;

    result = EST_UTILS_filterPkcs7Message(input, len);

    assert_int_equal(result, originalLen);
}

static void test_EST_UTILS_filterPkcs7Message_leading_trailing_whitespace(void **ppState)
{
    ubyte input[] = "\n\r\t  SGVsbG9Xb3JsZA==  \n\r\t";
    ubyte4 len = DIGI_STRLEN((sbyte *)input);
    ubyte4 result;
    ubyte expected[] = "SGVsbG9Xb3JsZA==";
    sbyte4 cmp;

    result = EST_UTILS_filterPkcs7Message(input, len);

    assert_int_equal(result, DIGI_STRLEN((sbyte *)expected));

    DIGI_MEMCMP(input, expected, result, &cmp);
    assert_int_equal(cmp, 0);
}

static void test_EST_UTILS_filterPkcs7Message_multiple_equal_signs(void **ppState)
{
    ubyte input[] = "SGVsbG9Xb3JsZA==";
    ubyte4 len = DIGI_STRLEN((sbyte *)input);
    ubyte4 originalLen = len;
    ubyte4 result;

    result = EST_UTILS_filterPkcs7Message(input, len);

    assert_int_equal(result, originalLen);
}

static void test_EST_UTILS_filterPkcs7Message_pem_header_footer(void **ppState)
{
    ubyte input[] = "MIIDXTCCAk\nWgAwIBAgIJ\nAJC1HiIAZA";
    ubyte4 len = DIGI_STRLEN((sbyte *)input);
    ubyte4 result;
    ubyte expected[] = "MIIDXTCCAkWgAwIBAgIJAJC1HiIAZA";
    sbyte4 cmp;

    result = EST_UTILS_filterPkcs7Message(input, len);

    assert_int_equal(result, DIGI_STRLEN((sbyte *)expected));

    DIGI_MEMCMP(input, expected, result, &cmp);
    assert_int_equal(cmp, 0);
}

static void test_EST_UTILS_filterPkcs7Message_invalid_chars_filtered(void **ppState)
{
    ubyte input[] = "SGVs#bG9X@b3Js!ZA==";
    ubyte4 len = DIGI_STRLEN((sbyte *)input);
    ubyte4 result;

    result = EST_UTILS_filterPkcs7Message(input, len);

    assert_true(result < len);
}

/*------------------------------------------------------------------*/
/* Setup/Teardown Functions */
/*------------------------------------------------------------------*/

static int testSetup(void **ppState)
{
    MSTATUS status;
    int ret = -1;

    status = DIGICERT_initDigicert();
    if (OK == status)
        ret = 0;

    return ret;
}

static int testTeardown(void **ppState)
{
    MSTATUS status;
    int ret = -1;

    status = DIGICERT_freeDigicert();
    if (OK == status)
        ret = 0;

    return ret;
}

/*------------------------------------------------------------------*/
/* Main Test Runner */
/*------------------------------------------------------------------*/

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_EST_UTILS_filterPkcs7Message_valid_base64),
        cmocka_unit_test(test_EST_UTILS_filterPkcs7Message_with_newlines),
        cmocka_unit_test(test_EST_UTILS_filterPkcs7Message_with_spaces),
        cmocka_unit_test(test_EST_UTILS_filterPkcs7Message_mixed_whitespace),
        cmocka_unit_test(test_EST_UTILS_filterPkcs7Message_empty_input),
        cmocka_unit_test(test_EST_UTILS_filterPkcs7Message_verify_filtered_content),
        cmocka_unit_test(test_EST_UTILS_filterPkcs7Message_real_base64_cert),
        cmocka_unit_test(test_EST_UTILS_filterPkcs7Message_only_base64_chars),
        cmocka_unit_test(test_EST_UTILS_filterPkcs7Message_leading_trailing_whitespace),
        cmocka_unit_test(test_EST_UTILS_filterPkcs7Message_multiple_equal_signs),
        cmocka_unit_test(test_EST_UTILS_filterPkcs7Message_pem_header_footer),
        cmocka_unit_test(test_EST_UTILS_filterPkcs7Message_invalid_chars_filtered),
    };

    return cmocka_run_group_tests(tests, testSetup, testTeardown);
}
