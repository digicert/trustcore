/**
 * sshc_str_house_test.c
 *
 * SSH Client String House Unit Tests
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../../common/moptions.h"

#ifdef __ENABLE_DIGICERT_SSH_CLIENT__

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include "cmocka.h"

#include "../../common/mtypes.h"
#include "../../common/mocana.h"
#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../common/mstdlib.h"
#include "../../common/mrtos.h"
#include "../../common/mtcp.h"
#include "../../ssh/ssh_defs.h"
#include "../../ssh/ssh_str.h"
#include "../../ssh/client/sshc_str_house.h"

/* External string buffers for testing */
extern sshStringBuffer sshc_disconnectMesg;
extern sshStringBuffer sshc_languageTag;
extern sshStringBuffer sshc_userAuthService;
extern sshStringBuffer sshc_authMethods;

/*------------------------------------------------------------------*/
/* Mock callback function for testing createFromList */
/*------------------------------------------------------------------*/

static sbyte* mock_string_list_callback(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie)
{
    MOC_UNUSED(cookie);

    static const char* test_strings[] = {
        "method1",
        "method2",
        "method3",
        NULL
    };

    if (index < 3)
    {
        *pRetStringLength = DIGI_STRLEN(test_strings[index]);
        return (sbyte*)test_strings[index];
    }

    return NULL;
}

static sbyte* mock_empty_list_callback(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie)
{
    MOC_UNUSED(index);
    MOC_UNUSED(pRetStringLength);
    MOC_UNUSED(cookie);

    return NULL;
}

static sbyte* mock_single_item_callback(ubyte4 index, ubyte4 *pRetStringLength, ubyte4 cookie)
{
    MOC_UNUSED(cookie);

    if (0 == index)
    {
        *pRetStringLength = 6;
        return (sbyte*)"single";
    }

    return NULL;
}

/*------------------------------------------------------------------*/
/* Tests for SSHC_STR_HOUSE_initStringBuffer */
/*------------------------------------------------------------------*/

static void test_SSHC_STR_HOUSE_initStringBuffer_empty_string(void **ppState)
{
    MOC_UNUSED(ppState);

    sshStringBuffer testBuffer;
    MSTATUS status;

    /* Initialize test buffer */
    DIGI_MEMSET((ubyte*)&testBuffer, 0, sizeof(sshStringBuffer));

    /* Test with empty string */
    status = SSHC_STR_HOUSE_initStringBuffer(&testBuffer, (sbyte*)"");
    assert_int_equal(OK, status);
    assert_non_null(testBuffer.pString);
    assert_int_equal(4, testBuffer.stringLen); /* 4 bytes for length field + 0 string length */

    /* Verify length encoding (big-endian) */
    assert_int_equal(0, (ubyte)testBuffer.pString[0]); /* length >> 24 */
    assert_int_equal(0, (ubyte)testBuffer.pString[1]); /* length >> 16 */
    assert_int_equal(0, (ubyte)testBuffer.pString[2]); /* length >> 8 */
    assert_int_equal(0, (ubyte)testBuffer.pString[3]); /* length */

    /* Cleanup */
    if (testBuffer.pString)
        FREE(testBuffer.pString);
}

static void test_SSHC_STR_HOUSE_initStringBuffer_normal_string(void **ppState)
{
    MOC_UNUSED(ppState);

    sshStringBuffer testBuffer;
    MSTATUS status;
    sbyte* testString = "hello";
    ubyte4 expectedLen = 5;

    /* Initialize test buffer */
    DIGI_MEMSET((ubyte*)&testBuffer, 0, sizeof(sshStringBuffer));

    /* Test with normal string */
    status = SSHC_STR_HOUSE_initStringBuffer(&testBuffer, (sbyte*)testString);
    assert_int_equal(OK, status);
    assert_non_null(testBuffer.pString);
    assert_int_equal(4 + expectedLen, testBuffer.stringLen);

    /* Verify length encoding (big-endian) */
    assert_int_equal(0, (ubyte)testBuffer.pString[0]); /* expectedLen >> 24 */
    assert_int_equal(0, (ubyte)testBuffer.pString[1]); /* expectedLen >> 16 */
    assert_int_equal(0, (ubyte)testBuffer.pString[2]); /* expectedLen >> 8 */
    assert_int_equal(expectedLen, (ubyte)testBuffer.pString[3]); /* expectedLen */

    /* Verify string content */
    assert_memory_equal(testString, &testBuffer.pString[4], expectedLen);

    /* Cleanup */
    if (testBuffer.pString)
        FREE(testBuffer.pString);
}

static void test_SSHC_STR_HOUSE_initStringBuffer_long_string(void **ppState)
{
    MOC_UNUSED(ppState);

    sshStringBuffer testBuffer;
    MSTATUS status;
    const char* testString = "Test_String_this_is_a_very_long_string_for_testing_purposes_with_more_than_255_characters_to_test_multi_byte_length_encoding_in_the_ssh_string_buffer_initialization_function_and_verify_that_it_handles_longer_strings_properly_without_any_issues_or_buffer_overflows";
    ubyte4 expectedLen = DIGI_STRLEN(testString);

    /* Initialize test buffer */
    DIGI_MEMSET((ubyte*)&testBuffer, 0, sizeof(sshStringBuffer));

    /* Test with long string */
    status = SSHC_STR_HOUSE_initStringBuffer(&testBuffer, (sbyte*)testString);
    assert_int_equal(OK, status);
    assert_non_null(testBuffer.pString);
    assert_int_equal(4 + expectedLen, testBuffer.stringLen);

    /* Verify length encoding for multi-byte length */
    ubyte4 encodedLen = ((ubyte4)testBuffer.pString[0] << 24) |
                        ((ubyte4)testBuffer.pString[1] << 16) |
                        ((ubyte4)testBuffer.pString[2] << 8) |
                        ((ubyte4)testBuffer.pString[3]);
    assert_int_equal(expectedLen, encodedLen);

    /* Verify string content */
    assert_memory_equal(testString, &testBuffer.pString[4], expectedLen);

    /* Cleanup */
    if (testBuffer.pString)
        FREE(testBuffer.pString);
}

/*------------------------------------------------------------------*/
/* Tests for SSHC_STR_HOUSE_createFromList */
/*------------------------------------------------------------------*/

static void test_SSHC_STR_HOUSE_createFromList_empty_list(void **ppState)
{
    MOC_UNUSED(ppState);

    sshStringBuffer testBuffer;
    MSTATUS status;

    /* Initialize test buffer */
    DIGI_MEMSET((ubyte*)&testBuffer, 0, sizeof(sshStringBuffer));

    /* Test with empty list callback */
    status = SSHC_STR_HOUSE_createFromList(&testBuffer, mock_empty_list_callback, 0);
    assert_int_equal(OK, status);
    assert_non_null(testBuffer.pString);
    assert_int_equal(4, testBuffer.stringLen); /* 4 bytes for length field + 0 content length */

    /* Verify length encoding */
    assert_int_equal(0, (ubyte)testBuffer.pString[0]);
    assert_int_equal(0, (ubyte)testBuffer.pString[1]);
    assert_int_equal(0, (ubyte)testBuffer.pString[2]);
    assert_int_equal(0, (ubyte)testBuffer.pString[3]);

    /* Cleanup */
    if (testBuffer.pString)
        FREE(testBuffer.pString);
}

static void test_SSHC_STR_HOUSE_createFromList_single_item(void **ppState)
{
    MOC_UNUSED(ppState);

    sshStringBuffer testBuffer;
    MSTATUS status;
    sbyte* expectedContent = "single";
    ubyte4 expectedContentLen = 6;

    /* Initialize test buffer */
    DIGI_MEMSET((ubyte*)&testBuffer, 0, sizeof(sshStringBuffer));

    /* Test with single item callback */
    status = SSHC_STR_HOUSE_createFromList(&testBuffer, mock_single_item_callback, 0);
    assert_int_equal(OK, status);
    assert_non_null(testBuffer.pString);
    assert_int_equal(4 + expectedContentLen, testBuffer.stringLen);

    /* Verify length encoding */
    ubyte4 encodedLen = ((ubyte4)testBuffer.pString[0] << 24) |
                        ((ubyte4)testBuffer.pString[1] << 16) |
                        ((ubyte4)testBuffer.pString[2] << 8) |
                        ((ubyte4)testBuffer.pString[3]);
    assert_int_equal(expectedContentLen, encodedLen);

    /* Verify content */
    assert_memory_equal(expectedContent, &testBuffer.pString[4], expectedContentLen);

    /* Cleanup */
    if (testBuffer.pString)
        FREE(testBuffer.pString);
}

static void test_SSHC_STR_HOUSE_createFromList_multiple_items(void **ppState)
{
    MOC_UNUSED(ppState);

    sshStringBuffer testBuffer;
    MSTATUS status;
    const char* expectedContent = "method1,method2,method3";
    ubyte4 expectedContentLen = DIGI_STRLEN(expectedContent);

    /* Initialize test buffer */
    DIGI_MEMSET((ubyte*)&testBuffer, 0, sizeof(sshStringBuffer));

    /* Test with multiple items callback */
    status = SSHC_STR_HOUSE_createFromList(&testBuffer, mock_string_list_callback, 0);
    assert_int_equal(OK, status);
    assert_non_null(testBuffer.pString);
    assert_int_equal(4 + expectedContentLen, testBuffer.stringLen);

    /* Verify length encoding */
    ubyte4 encodedLen = ((ubyte4)testBuffer.pString[0] << 24) |
                        ((ubyte4)testBuffer.pString[1] << 16) |
                        ((ubyte4)testBuffer.pString[2] << 8) |
                        ((ubyte4)testBuffer.pString[3]);
    assert_int_equal(expectedContentLen, encodedLen);

    /* Verify content (should be comma-separated list) */
    assert_memory_equal(expectedContent, &testBuffer.pString[4], expectedContentLen);

    /* Cleanup */
    if (testBuffer.pString)
        FREE(testBuffer.pString);
}

/*------------------------------------------------------------------*/
/* Tests for SSHC_STR_HOUSE_initStringBuffers */
/*------------------------------------------------------------------*/

static void test_SSHC_STR_HOUSE_initStringBuffers_success(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;

    /* Test successful initialization */
    status = SSHC_STR_HOUSE_initStringBuffers();
    assert_int_equal(OK, status);

    /* Verify some key string buffers were initialized */
    assert_non_null(sshc_disconnectMesg.pString);
    assert_non_null(sshc_languageTag.pString);
    assert_non_null(sshc_userAuthService.pString);

    /* Verify string lengths are as expected */
    assert_int_equal(sshc_disconnectMesg.stringLen, 15);
    assert_int_equal(sshc_languageTag.stringLen, 6);
    assert_int_equal(sshc_userAuthService.stringLen, 16);

    /* Verify specific content */
    ubyte4 userAuthLen = ((ubyte4)sshc_userAuthService.pString[0] << 24) |
                         ((ubyte4)sshc_userAuthService.pString[1] << 16) |
                         ((ubyte4)sshc_userAuthService.pString[2] << 8) |
                         ((ubyte4)sshc_userAuthService.pString[3]);
    assert_int_equal(12, userAuthLen);
    assert_memory_equal("ssh-userauth", &sshc_userAuthService.pString[4], 12);

    SSHC_STR_HOUSE_freeStringBuffers();
}

/*------------------------------------------------------------------*/
/* Tests for SSHC_STR_HOUSE_freeStringBuffers */
/*------------------------------------------------------------------*/

static void test_SSHC_STR_HOUSE_freeStringBuffers_success(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;

    /* First initialize buffers */
    status = SSHC_STR_HOUSE_initStringBuffers();
    assert_int_equal(OK, status);

    /* Verify buffers are allocated */
    assert_non_null(sshc_disconnectMesg.pString);
    assert_non_null(sshc_languageTag.pString);
    assert_non_null(sshc_userAuthService.pString);

    /* Test successful cleanup */
    status = SSHC_STR_HOUSE_freeStringBuffers();
    assert_int_equal(OK, status);

    /* Verify buffers were freed and set to NULL */
    assert_null(sshc_disconnectMesg.pString);
    assert_null(sshc_languageTag.pString);
    assert_null(sshc_userAuthService.pString);
}

static void test_SSHC_STR_HOUSE_freeStringBuffers_double_free(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;

    /* First initialize buffers */
    status = SSHC_STR_HOUSE_initStringBuffers();
    assert_int_equal(OK, status);

    /* Free once */
    status = SSHC_STR_HOUSE_freeStringBuffers();
    assert_int_equal(OK, status);

    /* Free again */
    status = SSHC_STR_HOUSE_freeStringBuffers();
    assert_int_equal(OK, status);
}

/*------------------------------------------------------------------*/
/* Integration Tests */
/*------------------------------------------------------------------*/

static void test_string_house_lifecycle(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;

    /* Test complete lifecycle */
    status = SSHC_STR_HOUSE_initStringBuffers();
    assert_int_equal(OK, status);

    /* Verify critical buffers exist and have expected content */
    assert_non_null(sshc_userAuthService.pString);
    assert_non_null(sshc_disconnectMesg.pString);
    assert_non_null(sshc_languageTag.pString);

    /* Verify disconnect message content */
    ubyte4 disconnectLen = ((ubyte4)sshc_disconnectMesg.pString[0] << 24) |
                           ((ubyte4)sshc_disconnectMesg.pString[1] << 16) |
                           ((ubyte4)sshc_disconnectMesg.pString[2] << 8) |
                           ((ubyte4)sshc_disconnectMesg.pString[3]);
    assert_memory_equal("Logged out.", &sshc_disconnectMesg.pString[4], 11);
    assert_int_equal(11, disconnectLen);

    /* Verify language tag content */
    ubyte4 langLen = ((ubyte4)sshc_languageTag.pString[0] << 24) |
                     ((ubyte4)sshc_languageTag.pString[1] << 16) |
                     ((ubyte4)sshc_languageTag.pString[2] << 8) |
                     ((ubyte4)sshc_languageTag.pString[3]);
    assert_memory_equal("en", &sshc_languageTag.pString[4], 2);
    assert_int_equal(2, langLen);

    /* Test cleanup */
    status = SSHC_STR_HOUSE_freeStringBuffers();
    assert_int_equal(OK, status);

    /* Verify cleanup was successful */
    assert_null(sshc_userAuthService.pString);
    assert_null(sshc_disconnectMesg.pString);
    assert_null(sshc_languageTag.pString);
}

/*------------------------------------------------------------------*/
/* Test Setup and Teardown */
/*------------------------------------------------------------------*/

static int testSetup(void **ppState)
{
    MOC_UNUSED(ppState);
    MSTATUS status;

    status = DIGICERT_initDigicert();
    if (OK != status)
        goto exit;

exit:
    return (OK == status) ? 0 : -1;
}

static int testTeardown(void **ppState)
{
    MOC_UNUSED(ppState);
    MSTATUS status;

    /* Ensure string buffers are cleaned up */
    status = SSHC_STR_HOUSE_freeStringBuffers();

    status = DIGICERT_freeDigicert();

    return (OK == status) ? 0 : -1;
}

/*------------------------------------------------------------------*/
/* Main Test Runner */
/*------------------------------------------------------------------*/

int main(int argc, char* argv[])
{
    MOC_UNUSED(argc);
    MOC_UNUSED(argv);

#ifdef __ENABLE_DIGICERT_SSH_CLIENT__
    const struct CMUnitTest tests[] = {
        /* SSHC_STR_HOUSE_initStringBuffer tests */
        cmocka_unit_test(test_SSHC_STR_HOUSE_initStringBuffer_empty_string),
        cmocka_unit_test(test_SSHC_STR_HOUSE_initStringBuffer_normal_string),
        cmocka_unit_test(test_SSHC_STR_HOUSE_initStringBuffer_long_string),

        /* SSHC_STR_HOUSE_createFromList tests */
        cmocka_unit_test(test_SSHC_STR_HOUSE_createFromList_empty_list),
        cmocka_unit_test(test_SSHC_STR_HOUSE_createFromList_single_item),
        cmocka_unit_test(test_SSHC_STR_HOUSE_createFromList_multiple_items),

        /* SSHC_STR_HOUSE_initStringBuffers tests */
        cmocka_unit_test(test_SSHC_STR_HOUSE_initStringBuffers_success),

        /* SSHC_STR_HOUSE_freeStringBuffers tests */
        cmocka_unit_test(test_SSHC_STR_HOUSE_freeStringBuffers_success),
        cmocka_unit_test(test_SSHC_STR_HOUSE_freeStringBuffers_double_free),

        /* Integration tests */
        cmocka_unit_test(test_string_house_lifecycle)
    };

    return cmocka_run_group_tests(tests, testSetup, testTeardown);
#else
    return 0;
#endif
}

#endif /* __ENABLE_DIGICERT_SSH_CLIENT__ */