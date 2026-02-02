/*
 * test_est_cert_utils.c
 *
 * EST Certificate Utils Unit Test
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: contact DigiCert at sales@digicert.com.*
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

#include "est/est_cert_utils.h"

/*------------------------------------------------------------------*/
/* Test Functions */
/*------------------------------------------------------------------*/

static void test_EST_CERT_UTIL_getFullPath_valid(void **ppState)
{
    char *pFullPath = NULL;
    char *result;
    const char *directory = "/tmp/test";
    const char *name = "file.txt";

    result = EST_CERT_UTIL_getFullPath(directory, name, &pFullPath);

    assert_non_null(result);
    assert_non_null(pFullPath);
    assert_true(strstr(pFullPath, directory) != NULL);
    assert_true(strstr(pFullPath, name) != NULL);

    if (pFullPath)
        DIGI_FREE((void**)&pFullPath);
}

static void test_EST_CERT_UTIL_getFullPath_null_directory(void **ppState)
{
    char *pFullPath = NULL;
    char *result;
    const char *name = "file.txt";

    result = EST_CERT_UTIL_getFullPath(NULL, name, &pFullPath);

    assert_true(result == NULL || pFullPath != NULL);

    if (pFullPath)
        DIGI_FREE((void**)&pFullPath);
}

static void test_EST_CERT_UTIL_getFullPath_null_name(void **ppState)
{
    char *pFullPath = NULL;
    char *result;
    const char *directory = "/tmp/test";

    result = EST_CERT_UTIL_getFullPath(directory, NULL, &pFullPath);

    assert_true(result == NULL || pFullPath != NULL);

    if (pFullPath)
        DIGI_FREE((void**)&pFullPath);
}

static void test_EST_CERT_UTIL_setIsWriteExtensions(void **ppState)
{
    EST_CERT_UTIL_setIsWriteExtensions(TRUE);
    EST_CERT_UTIL_setIsWriteExtensions(FALSE);
}

/*------------------------------------------------------------------*/
/* Test: EST_CERT_UTIL_createDirectory with valid path */
/*------------------------------------------------------------------*/
static void test_EST_CERT_UTIL_createDirectory_valid(void **ppState)
{
    (void) ppState;

    char testDir[] = "/tmp/est_test_dir_12345";

    MSTATUS status = EST_CERT_UTIL_createDirectory(testDir);

    (void)status;
}

/*------------------------------------------------------------------*/
/* Test: EST_CERT_UTIL_createDirectory with NULL */
/*------------------------------------------------------------------*/
static void test_EST_CERT_UTIL_createDirectory_null(void **ppState)
{
    (void) ppState;

    MSTATUS status = EST_CERT_UTIL_createDirectory(NULL);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_CERT_UTIL_getPkiDBPtr returns pointer */
/*------------------------------------------------------------------*/
static void test_EST_CERT_UTIL_getPkiDBPtr(void **ppState)
{
    (void) ppState;

    sbyte *ptr = EST_CERT_UTIL_getPkiDBPtr();

    (void)ptr;
}

/*------------------------------------------------------------------*/
/* Test: EST_CERT_UTIL_createPkiDB with valid path */
/*------------------------------------------------------------------*/
static void test_EST_CERT_UTIL_createPkiDB_valid(void **ppState)
{
    (void) ppState;

    sbyte testDb[] = "/tmp/est_test_db_12345";

    MSTATUS status = EST_CERT_UTIL_createPkiDB(testDb);

    (void)status;
}

/*------------------------------------------------------------------*/
/* Test: EST_CERT_UTIL_buildKeyStoreFullPath with valid parameters */
/*------------------------------------------------------------------*/
static void test_EST_CERT_UTIL_buildKeyStoreFullPath_valid(void **ppState)
{
    (void) ppState;

    char *result = EST_CERT_UTIL_buildKeyStoreFullPath("/tmp/keystore", "certs");

    assert_non_null(result);

    if (result)
        FREE(result);
}

/*------------------------------------------------------------------*/
/* Test: EST_CERT_UTIL_buildKeyStoreFullPath with NULL keystore */
/*------------------------------------------------------------------*/
static void test_EST_CERT_UTIL_buildKeyStoreFullPath_null_keystore(void **ppState)
{
    (void) ppState;

    char *result = EST_CERT_UTIL_buildKeyStoreFullPath(NULL, "subdir");

    if (result)
        FREE(result);
}

/*------------------------------------------------------------------*/
/* Test: EST_CERT_UTIL_buildKeyStoreFullPath with NULL subdir */
/*------------------------------------------------------------------*/
static void test_EST_CERT_UTIL_buildKeyStoreFullPath_null_subdir(void **ppState)
{
    (void) ppState;

    char *result = EST_CERT_UTIL_buildKeyStoreFullPath("/tmp/keystore", NULL);

    if (result)
        FREE(result);
}

/*------------------------------------------------------------------*/
/* Test: EST_CERT_UTIL_generateOIDFromString with NULL output */
/*------------------------------------------------------------------*/
static void test_EST_CERT_UTIL_generateOIDFromString_null_output(void **ppState)
{
    (void) ppState;

    const sbyte *oidStr = "1.2.840.113549.1.1.1";

    MSTATUS status = EST_CERT_UTIL_generateOIDFromString(oidStr, NULL, NULL);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_CERT_UTIL_convertStringToBmpByteArray with valid input */
/*------------------------------------------------------------------*/
static void test_EST_CERT_UTIL_convertStringToBmpByteArray_valid(void **ppState)
{
    (void) ppState;

    char input[] = "test";
    ubyte results[100] = {0};

    MSTATUS status = EST_CERT_UTIL_convertStringToBmpByteArray(input, results);

    assert_int_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_CERT_UTIL_writeExtensionToFile with NULL filename */
/*------------------------------------------------------------------*/
static void test_EST_CERT_UTIL_writeExtensionToFile_null(void **ppState)
{
    (void) ppState;

    ubyte data[] = "test data";

    MSTATUS status = EST_CERT_UTIL_writeExtensionToFile(NULL, data, sizeof(data));

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_CERT_UTIL_makeExtensionsFromBuffer with NULL buffer */
/*------------------------------------------------------------------*/
static void test_EST_CERT_UTIL_makeExtensionsFromBuffer_null(void **ppState)
{
    (void) ppState;

    certExtensions *pExt = NULL;

    MSTATUS status = EST_CERT_UTIL_makeExtensionsFromBuffer(NULL, 0, &pExt);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_CERT_UTIL_makeExtensionsFromBuffer with zero length */
/*------------------------------------------------------------------*/
static void test_EST_CERT_UTIL_makeExtensionsFromBuffer_zero_len(void **ppState)
{
    (void) ppState;

    char data[] = "test data";
    certExtensions *pExt = NULL;

    MSTATUS status = EST_CERT_UTIL_makeExtensionsFromBuffer(data, 0, &pExt);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_CERT_UTIL_makeExtensionsFromConfigFile with NULL filename */
/*------------------------------------------------------------------*/
static void test_EST_CERT_UTIL_makeExtensionsFromConfigFile_null(void **ppState)
{
    (void) ppState;

    certExtensions *pExt = NULL;

    MSTATUS status = EST_CERT_UTIL_makeExtensionsFromConfigFile(NULL, &pExt);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_CERT_UTIL_convertStringToByteArray validates output */
/*------------------------------------------------------------------*/
static void test_EST_CERT_UTIL_convertStringToByteArray_validates_output(void **ppState)
{
    MSTATUS status;
    char input[32];
    ubyte results[32];
    ubyte4 count = 0;
    ubyte expected[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    sbyte4 cmp;

    DIGI_MEMSET(input, 0, sizeof(input));
    DIGI_MEMSET(results, 0, sizeof(results));
    DIGI_MEMCPY(input, "01 02 03 04 05", 14);

    status = EST_CERT_UTIL_convertStringToByteArray(input, results, &count);

    assert_int_equal(status, OK);
    assert_int_equal(count, 5);

    DIGI_MEMCMP(results, expected, count, &cmp);
    assert_int_equal(cmp, 0);
}

/*------------------------------------------------------------------*/
/* Test: EST_CERT_UTIL_convertStringToByteArray with hex values */
/*------------------------------------------------------------------*/
static void test_EST_CERT_UTIL_convertStringToByteArray_hex_values(void **ppState)
{
    MSTATUS status;
    char input[32];
    ubyte results[32];
    ubyte4 count = 0;
    ubyte expected[] = {0xFF, 0xAA, 0xBB, 0xCC, 0xDD};
    sbyte4 cmp;

    DIGI_MEMSET(input, 0, sizeof(input));
    DIGI_MEMSET(results, 0, sizeof(results));
    DIGI_MEMCPY(input, "FF AA BB CC DD", 14);

    status = EST_CERT_UTIL_convertStringToByteArray(input, results, &count);

    assert_int_equal(status, OK);
    assert_int_equal(count, 5);

    DIGI_MEMCMP(results, expected, count, &cmp);
    assert_int_equal(cmp, 0);
}

/*------------------------------------------------------------------*/
/* Test: EST_CERT_UTIL_generateOIDFromString validates RSA OID */
/*------------------------------------------------------------------*/
static void test_EST_CERT_UTIL_generateOIDFromString_validates_rsa_oid(void **ppState)
{
    MSTATUS status;
    const sbyte *oidStr = "1.2.840.113549.1.1.1";  /* RSA encryption OID */
    ubyte *oid = NULL;
    ubyte4 oid_len = 0;

    status = EST_CERT_UTIL_generateOIDFromString(oidStr, &oid, &oid_len);

    if (OK == status)
    {
        assert_non_null(oid);
        assert_true(oid_len > 0);

        /* First byte should be constructed OID (0x06 is ASN.1 OID tag, but implementation may vary) */
        /* OID encoding starts with combined first two numbers: 40*1 + 2 = 42 (0x2A) */
        /* We verify at least the length is reasonable for this OID */
        assert_true(oid_len >= 9);  /* RSA OID is 9 bytes in DER encoding */
    }

    if (oid)
    {
        oid = oid - 1;
        FREE(oid);
    }
}

/*------------------------------------------------------------------*/
/* Test: EST_CERT_UTIL_generateOIDFromString validates SHA256 OID */
/*------------------------------------------------------------------*/
static void test_EST_CERT_UTIL_generateOIDFromString_validates_sha256_oid(void **ppState)
{
    MSTATUS status;
    const sbyte *oidStr = "2.16.840.1.101.3.4.2.1";  /* SHA-256 OID */
    ubyte *oid = NULL;
    ubyte4 oid_len = 0;

    status = EST_CERT_UTIL_generateOIDFromString(oidStr, &oid, &oid_len);

    if (OK == status)
    {
        assert_non_null(oid);
        assert_true(oid_len > 0);
        /* SHA-256 OID is typically 9 bytes in DER encoding */
        assert_true(oid_len >= 9);
    }

    if (oid)
    {
        oid = oid - 1;
        FREE(oid);
    }
}

/*------------------------------------------------------------------*/
/* Test: EST_CERT_UTIL_getFullPath creates correct path */
/*------------------------------------------------------------------*/
static void test_EST_CERT_UTIL_getFullPath_creates_correct_path(void **ppState)
{
    char *pFullPath = NULL;
    char *result;
    const char *directory = "/opt/certs";
    const char *name = "mycert.pem";

    result = EST_CERT_UTIL_getFullPath(directory, name, &pFullPath);

    assert_non_null(result);
    assert_non_null(pFullPath);

    assert_true(strstr(pFullPath, "/") != NULL);

    assert_true(strstr(pFullPath, "opt") != NULL);
    assert_true(strstr(pFullPath, "mycert.pem") != NULL);

    if (pFullPath)
        DIGI_FREE((void**)&pFullPath);
}

/*------------------------------------------------------------------*/
/* Test: EST_CERT_UTIL_buildKeyStoreFullPath validates path structure */
/*------------------------------------------------------------------*/
static void test_EST_CERT_UTIL_buildKeyStoreFullPath_validates_structure(void **ppState)
{
    char *result = EST_CERT_UTIL_buildKeyStoreFullPath("/opt/trustpoint/Keystore", "ca");

    assert_non_null(result);

    assert_true(strstr(result, "/opt/trustpoint/Keystore") != NULL);
    assert_true(strstr(result, "ca") != NULL);

    assert_true(strstr(result, "/") != NULL);

    if (result)
        FREE(result);
}

/*------------------------------------------------------------------*/
/* Test: EST_CERT_UTIL_convertStringToBmpByteArray validates BMP encoding */
/*------------------------------------------------------------------*/
static void test_EST_CERT_UTIL_convertStringToBmpByteArray_validates_encoding(void **ppState)
{
    MSTATUS status;
    char input[] = "AB";
    ubyte results[100] = {0};

    status = EST_CERT_UTIL_convertStringToBmpByteArray(input, results);

    assert_int_equal(status, OK);

    /* BMP (UCS-2) encoding should be 2 bytes per character */
    /* For 'A' (0x41), expect 0x00 0x41 in big-endian BMP */
    /* For 'B' (0x42), expect 0x00 0x42 */
    /* Verify first character encoding */
    assert_true(results[0] == 0x00 && results[1] == 0x41);
    assert_true(results[2] == 0x00 && results[3] == 0x42);
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
    sbyte *pPkiDB = NULL;

    pPkiDB = EST_CERT_UTIL_getPkiDBPtr();
    if (pPkiDB)
    {
        FREE(pPkiDB);
    }

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
        cmocka_unit_test(test_EST_CERT_UTIL_getFullPath_valid),
        cmocka_unit_test(test_EST_CERT_UTIL_getFullPath_null_directory),
        cmocka_unit_test(test_EST_CERT_UTIL_getFullPath_null_name),
        cmocka_unit_test(test_EST_CERT_UTIL_setIsWriteExtensions),
        cmocka_unit_test(test_EST_CERT_UTIL_createDirectory_valid),
        cmocka_unit_test(test_EST_CERT_UTIL_createDirectory_null),
        cmocka_unit_test(test_EST_CERT_UTIL_getPkiDBPtr),
        cmocka_unit_test(test_EST_CERT_UTIL_createPkiDB_valid),
        cmocka_unit_test(test_EST_CERT_UTIL_buildKeyStoreFullPath_valid),
        cmocka_unit_test(test_EST_CERT_UTIL_buildKeyStoreFullPath_null_keystore),
        cmocka_unit_test(test_EST_CERT_UTIL_buildKeyStoreFullPath_null_subdir),
        cmocka_unit_test(test_EST_CERT_UTIL_generateOIDFromString_null_output),
        cmocka_unit_test(test_EST_CERT_UTIL_convertStringToBmpByteArray_valid),
        cmocka_unit_test(test_EST_CERT_UTIL_writeExtensionToFile_null),
        cmocka_unit_test(test_EST_CERT_UTIL_makeExtensionsFromBuffer_null),
        cmocka_unit_test(test_EST_CERT_UTIL_makeExtensionsFromBuffer_zero_len),
        cmocka_unit_test(test_EST_CERT_UTIL_makeExtensionsFromConfigFile_null),
        cmocka_unit_test(test_EST_CERT_UTIL_convertStringToByteArray_validates_output),
        cmocka_unit_test(test_EST_CERT_UTIL_convertStringToByteArray_hex_values),
        cmocka_unit_test(test_EST_CERT_UTIL_generateOIDFromString_validates_rsa_oid),
        cmocka_unit_test(test_EST_CERT_UTIL_generateOIDFromString_validates_sha256_oid),
        cmocka_unit_test(test_EST_CERT_UTIL_getFullPath_creates_correct_path),
        cmocka_unit_test(test_EST_CERT_UTIL_buildKeyStoreFullPath_validates_structure),
        cmocka_unit_test(test_EST_CERT_UTIL_convertStringToBmpByteArray_validates_encoding),
    };

    return cmocka_run_group_tests(tests, testSetup, testTeardown);
}
