/*
 * test_est_connection.c - Unit tests for EST connection and parsing APIs
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

typedef struct httpContext httpContext;
typedef struct certStore certStore;

extern MSTATUS EST_parseEndpoint(sbyte *pEndpoint, sbyte **ppServerName, sbyte **ppUrl);
extern MSTATUS EST_filterPkcs7Message(ubyte *pOrigMsg, ubyte4 origLen, ubyte4 *pFilteredLen);

typedef struct EST_nameStr {
    ubyte* name;
    ubyte4 nameLen;
} EST_nameStr;

typedef struct estSettings {
    EST_nameStr *pContentTypeMediaTypes;
    EST_nameStr *pContentTypePkcs7Parameter;
} estSettings;

extern estSettings* EST_estSettings(void);
extern EST_nameStr mEstContentTypeMediaTypes[];
extern EST_nameStr mEstContentTypePkcs7Parameter[];

/*------------------------------------------------------------------*/
/* Test: Parse EST endpoint with valid URL */
/*------------------------------------------------------------------*/
static void test_EST_parseEndpoint_valid(void **ppState)
{
    (void) ppState;

    sbyte endpoint[] = "https://server.example.com/.well-known/est/label";
    sbyte *pServerName = NULL;
    sbyte *pUrl = NULL;

    MSTATUS status = EST_parseEndpoint(endpoint, &pServerName, &pUrl);

    assert_int_equal(status, OK);
    assert_non_null(pServerName);
    assert_non_null(pUrl);

    if (pServerName) DIGI_FREE((void**)&pServerName);
    if (pUrl) DIGI_FREE((void**)&pUrl);
}

/*------------------------------------------------------------------*/
/* Test: Parse endpoint without label */
/*------------------------------------------------------------------*/
static void test_EST_parseEndpoint_no_label(void **ppState)
{
    (void) ppState;

    sbyte endpoint[] = "https://server.example.com/.well-known/est/";
    sbyte *pServerName = NULL;
    sbyte *pUrl = NULL;

    MSTATUS status = EST_parseEndpoint(endpoint, &pServerName, &pUrl);

    assert_int_equal(status, OK);
    assert_non_null(pServerName);

    if (pServerName) DIGI_FREE((void**)&pServerName);
    if (pUrl) DIGI_FREE((void**)&pUrl);
}

/*------------------------------------------------------------------*/
/* Test: Parse endpoint with NULL input */
/*------------------------------------------------------------------*/
static void test_EST_parseEndpoint_null_input(void **ppState)
{
    (void) ppState;

    sbyte *pServerName = NULL;
    sbyte *pUrl = NULL;

    MSTATUS status = EST_parseEndpoint(NULL, &pServerName, &pUrl);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: Filter PKCS7 message from valid PEM input */
/*------------------------------------------------------------------*/
static void test_EST_filterPkcs7Message_valid(void **ppState)
{
    (void) ppState;

    ubyte input[] = "-----BEGIN PKCS7-----\nMIIBAgYJKoZIhvcNAQcCoIH/MIH8\n-----END PKCS7-----\n\n\r\n";
    ubyte4 inputLen = strlen((char*)input);
    ubyte4 filteredLen = 0;

    MSTATUS status = EST_filterPkcs7Message(input, inputLen, &filteredLen);

    assert_int_equal(status, OK);
    assert_true(filteredLen > 0);
    assert_true(filteredLen <= inputLen);
}

/*------------------------------------------------------------------*/
/* Test: Filter PKCS7 message with NULL input */
/*------------------------------------------------------------------*/
static void test_EST_filterPkcs7Message_null_input(void **ppState)
{
    (void) ppState;

    ubyte4 filteredLen = 0;

    MSTATUS status = EST_filterPkcs7Message(NULL, 0, &filteredLen);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_estSettings returns non-NULL pointer */
/*------------------------------------------------------------------*/
static void test_EST_estSettings_returns_valid(void **ppState)
{
    (void) ppState;

    estSettings *pSettings = EST_estSettings();

    assert_non_null(pSettings);
}

/*------------------------------------------------------------------*/
/* Test: EST_parseEndpoint validates server name extraction */
/*------------------------------------------------------------------*/
static void test_EST_parseEndpoint_validates_server_extraction(void **ppState)
{
    (void) ppState;

    sbyte endpoint[] = "https://example.mocana.com/.well-known/est/label";
    sbyte *pServerName = NULL;
    sbyte *pUrl = NULL;

    MSTATUS status = EST_parseEndpoint(endpoint, &pServerName, &pUrl);

    assert_int_equal(status, OK);
    assert_non_null(pServerName);

    assert_true(strstr((char*)pServerName, "example.mocana.com") != NULL);
    if (pUrl) {
        assert_true(strstr((char*)pUrl, ".well-known/est") != NULL);
    }

    if (pServerName) DIGI_FREE((void**)&pServerName);
    if (pUrl) DIGI_FREE((void**)&pUrl);
}

/*------------------------------------------------------------------*/
/* Test: EST_parseEndpoint with port number */
/*------------------------------------------------------------------*/
static void test_EST_parseEndpoint_with_port(void **ppState)
{
    (void) ppState;

    sbyte endpoint[] = "https://server.example.com:8443/.well-known/est/";
    sbyte *pServerName = NULL;
    sbyte *pUrl = NULL;

    MSTATUS status = EST_parseEndpoint(endpoint, &pServerName, &pUrl);

    assert_int_equal(status, OK);
    assert_non_null(pServerName);

    assert_true(strstr((char*)pServerName, "server.example.com") != NULL);

    if (pServerName) DIGI_FREE((void**)&pServerName);
    if (pUrl) DIGI_FREE((void**)&pUrl);
}

/*------------------------------------------------------------------*/
/* Test: EST_parseEndpoint with simple enroll path */
/*------------------------------------------------------------------*/
static void test_EST_parseEndpoint_simpleenroll_path(void **ppState)
{
    (void) ppState;

    sbyte endpoint[] = "https://est.example.org/.well-known/est/simpleenroll";
    sbyte *pServerName = NULL;
    sbyte *pUrl = NULL;

    MSTATUS status = EST_parseEndpoint(endpoint, &pServerName, &pUrl);

    assert_int_equal(status, OK);

    if (pUrl) {
        assert_true(strstr((char*)pUrl, "simpleenroll") != NULL);
    }

    if (pServerName) DIGI_FREE((void**)&pServerName);
    if (pUrl) DIGI_FREE((void**)&pUrl);
}

/*------------------------------------------------------------------*/
/* Test: EST_parseEndpoint with cacerts path */
/*------------------------------------------------------------------*/
static void test_EST_parseEndpoint_cacerts_path(void **ppState)
{
    (void) ppState;

    sbyte endpoint[] = "https://ca.example.com/.well-known/est/cacerts";
    sbyte *pServerName = NULL;
    sbyte *pUrl = NULL;

    MSTATUS status = EST_parseEndpoint(endpoint, &pServerName, &pUrl);

    assert_int_equal(status, OK);

    if (pUrl) {
        assert_true(strstr((char*)pUrl, "cacerts") != NULL);
    }

    if (pServerName) DIGI_FREE((void**)&pServerName);
    if (pUrl) DIGI_FREE((void**)&pUrl);
}

/*------------------------------------------------------------------*/
/* Test: EST_filterPkcs7Message validates filtered base64 content */
/*------------------------------------------------------------------*/
static void test_EST_filterPkcs7Message_validates_content(void **ppState)
{
    (void) ppState;

    ubyte input[] = "MIIBAgYJKo\nZIhvcNAQcC\noIH/MIH8";
    ubyte4 inputLen = strlen((char*)input);
    ubyte4 filteredLen = 0;
    ubyte expected[] = "MIIBAgYJKoZIhvcNAQcCoIH/MIH8";
    sbyte4 cmp;

    MSTATUS status = EST_filterPkcs7Message(input, inputLen, &filteredLen);

    assert_int_equal(status, OK);
    assert_true(filteredLen > 0);
    assert_int_equal(filteredLen, strlen((char*)expected));

    DIGI_MEMCMP(input, expected, filteredLen, &cmp);
    assert_int_equal(cmp, 0);
}

/*------------------------------------------------------------------*/
/* Test: EST_filterPkcs7Message with PEM formatted data */
/*------------------------------------------------------------------*/
static void test_EST_filterPkcs7Message_pem_format(void **ppState)
{
    (void) ppState;

    ubyte input[] = "-----BEGIN CERTIFICATE-----\n"
                    "MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiIMA0GCSqGSIb3Df\n"
                    "-----END CERTIFICATE-----";
    ubyte4 inputLen = strlen((char*)input);
    ubyte4 filteredLen = 0;

    MSTATUS status = EST_filterPkcs7Message(input, inputLen, &filteredLen);

    assert_int_equal(status, OK);
    assert_true(filteredLen < inputLen);
}

/*------------------------------------------------------------------*/
/* Test: EST_parseEndpoint with IPv4 address */
/*------------------------------------------------------------------*/
static void test_EST_parseEndpoint_ipv4_address(void **ppState)
{
    (void) ppState;

    sbyte endpoint[] = "https://192.168.1.100/.well-known/est/";
    sbyte *pServerName = NULL;
    sbyte *pUrl = NULL;

    MSTATUS status = EST_parseEndpoint(endpoint, &pServerName, &pUrl);

    assert_int_equal(status, OK);
    assert_non_null(pServerName);

    assert_true(strstr((char*)pServerName, "192.168.1.100") != NULL);

    if (pServerName) DIGI_FREE((void**)&pServerName);
    if (pUrl) DIGI_FREE((void**)&pUrl);
}

/*------------------------------------------------------------------*/
/* Test: EST_estSettings validates content type media types */
/*------------------------------------------------------------------*/
static void test_EST_estSettings_validates_content_types(void **ppState)
{
    (void) ppState;

    assert_non_null(mEstContentTypeMediaTypes);
    assert_non_null(mEstContentTypeMediaTypes[0].name);
    assert_true(mEstContentTypeMediaTypes[0].nameLen > 0);
}

/*------------------------------------------------------------------*/
/* Test: EST_estSettings validates PKCS7 parameters */
/*------------------------------------------------------------------*/
static void test_EST_estSettings_validates_pkcs7_params(void **ppState)
{
    (void) ppState;

    assert_non_null(mEstContentTypePkcs7Parameter);
    assert_non_null(mEstContentTypePkcs7Parameter[0].name);
    assert_true(mEstContentTypePkcs7Parameter[0].nameLen > 0);
}

/*------------------------------------------------------------------*/
/* Main test runner */
/*------------------------------------------------------------------*/
int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_EST_parseEndpoint_valid),
        cmocka_unit_test(test_EST_parseEndpoint_no_label),
        cmocka_unit_test(test_EST_parseEndpoint_null_input),
        cmocka_unit_test(test_EST_filterPkcs7Message_valid),
        cmocka_unit_test(test_EST_filterPkcs7Message_null_input),
        cmocka_unit_test(test_EST_estSettings_returns_valid),
        cmocka_unit_test(test_EST_parseEndpoint_validates_server_extraction),
        cmocka_unit_test(test_EST_parseEndpoint_with_port),
        cmocka_unit_test(test_EST_parseEndpoint_simpleenroll_path),
        cmocka_unit_test(test_EST_parseEndpoint_cacerts_path),
        cmocka_unit_test(test_EST_filterPkcs7Message_validates_content),
        cmocka_unit_test(test_EST_filterPkcs7Message_pem_format),
        cmocka_unit_test(test_EST_parseEndpoint_ipv4_address),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
