/*
 * test_est_client_operations.c
 *
 * EST Client Operations Unit Test - Tests for enroll, reenroll, and cacerts
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
#include "crypto/hw_accel.h"
#include "crypto/ca_mgmt.h"


typedef struct httpContext httpContext;
typedef struct certStore certStore;
typedef struct AsymmetricKey AsymmetricKey;
typedef struct certDistinguishedName certDistinguishedName;

extern MSTATUS EST_sendCaCertsRequest(httpContext *pHttpContext, ubyte4 connectionSSLInstance,
                                      ubyte *pRequestUrl, ubyte4 requestUrlLen,
                                      ubyte *pServerIdentity, ubyte4 serverIdentityLen,
                                      sbyte *pUserAgent);

extern MSTATUS EST_sendSimpleEnrollRequest(httpContext *pHttpContext, ubyte4 connectionSSLInstance,
                                           ubyte *pRequestUrl, ubyte4 requestUrlLen,
                                           ubyte4 csrReqLen, ubyte *pServerIdentity,
                                           ubyte4 serverIdentityLen, sbyte *pUserAgent);



extern MSTATUS EST_sendCsrAttrsRequest(httpContext *pHttpContext, ubyte4 connectionSSLInstance,
                                       ubyte *pRequestUrl, ubyte4 requestUrlLen,
                                       ubyte *pServerIdentity, ubyte4 serverIdentityLen,
                                       sbyte *pUserAgent);

extern MSTATUS EST_sendServerKeyGenRequest(httpContext *pHttpContext, ubyte4 connectionSSLInstance,
                                           ubyte *pRequestUrl, ubyte4 requestUrlLen,
                                           ubyte4 csrReqLen, ubyte *pServerIdentity,
                                           ubyte4 serverIdentityLen, sbyte *pUserAgent);

extern MSTATUS EST_sendFullCmcRequest(httpContext *pHttpContext, ubyte4 connectionSSLInstance,
                                      ubyte *pRequestUrl, ubyte4 requestUrlLen,
                                      ubyte4 csrReqLen, ubyte *pServerIdentity,
                                      ubyte4 serverIdentityLen, ubyte4 requestType,
                                      sbyte *pUserAgent);

extern MSTATUS EST_openConnection(struct certStore *pCertStore, ubyte *pServerIpAddr,
                                  ubyte4 serverAddrLen, ubyte4 port, ubyte *pServerIdentity,
                                  ubyte4 serverIdentityLen, sbyte4 *pConnectionSSLInstance,
                                  httpContext **ppHttpContext, sbyte *pTLSCertAlias,
                                  ubyte4 tlsCertAliasLen, intBoolean ocspRequired,
                                  intBoolean enforcePQC);

extern MSTATUS EST_closeConnection(httpContext *pHttpContext, ubyte4 connectionSSLInstance);

extern MSTATUS EST_generateCSRRequestFromConfig(
    MOC_HW(hwAccelDescr hwAccelCtx)
    struct certStore *pCertStore,
    sbyte4 connectionSSLInstance,
    sbyte *pConfigFile,
    sbyte *pExtendedAttrsFile,
    ubyte4 config_type,
    sbyte *pKeyAlias,
    ubyte4 keyAliasLen,
    AsymmetricKey *pKey,
    ubyte4 keyType,
    ubyte *pHashType,
    ubyte4 hashTypeLen,
    ubyte **ppCsr,
    ubyte4 *pCsrLen);

extern MSTATUS EST_setCookie(httpContext *pHttpContext, ubyte *pRequestBody, ubyte4 reqBodyLen);

extern MSTATUS EST_freeCookie(httpContext *pHttpContext);

/*------------------------------------------------------------------*/
/* Test: EST_sendCaCertsRequest with NULL context */
/*------------------------------------------------------------------*/
static void test_EST_sendCaCertsRequest_null_context(void **ppState)
{
    (void) ppState;

    ubyte requestUrl[] = "/.well-known/est/cacerts";
    ubyte serverIdentity[] = "est.example.com";
    sbyte userAgent[] = "TestAgent/1.0";

    MSTATUS status = EST_sendCaCertsRequest(NULL, 0, requestUrl,
                                           DIGI_STRLEN((sbyte*)requestUrl),
                                           serverIdentity,
                                           DIGI_STRLEN((sbyte*)serverIdentity),
                                           userAgent);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_sendCaCertsRequest with NULL URL */
/*------------------------------------------------------------------*/
static void test_EST_sendCaCertsRequest_null_url(void **ppState)
{
    (void) ppState;

    ubyte serverIdentity[] = "est.example.com";
    sbyte userAgent[] = "TestAgent/1.0";

    MSTATUS status = EST_sendCaCertsRequest(NULL, 0, NULL, 0,
                                           serverIdentity,
                                           DIGI_STRLEN((sbyte*)serverIdentity),
                                           userAgent);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_sendSimpleEnrollRequest with NULL context */
/*------------------------------------------------------------------*/
static void test_EST_sendSimpleEnrollRequest_null_context(void **ppState)
{
    (void) ppState;

    ubyte requestUrl[] = "/.well-known/est/simpleenroll";
    ubyte serverIdentity[] = "est.example.com";
    sbyte userAgent[] = "TestAgent/1.0";

    MSTATUS status = EST_sendSimpleEnrollRequest(NULL, 0, requestUrl,
                                                 DIGI_STRLEN((sbyte*)requestUrl),
                                                 100, serverIdentity,
                                                 DIGI_STRLEN((sbyte*)serverIdentity),
                                                 userAgent);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_sendSimpleEnrollRequest with zero CSR length */
/*------------------------------------------------------------------*/
static void test_EST_sendSimpleEnrollRequest_zero_csr_length(void **ppState)
{
    (void) ppState;

    ubyte requestUrl[] = "/.well-known/est/simpleenroll";
    ubyte serverIdentity[] = "est.example.com";
    sbyte userAgent[] = "TestAgent/1.0";

    MSTATUS status = EST_sendSimpleEnrollRequest(NULL, 0, requestUrl,
                                                 DIGI_STRLEN((sbyte*)requestUrl),
                                                 0, /* Zero CSR length */
                                                 serverIdentity,
                                                 DIGI_STRLEN((sbyte*)serverIdentity),
                                                 userAgent);

    assert_int_not_equal(status, OK);
}



/*------------------------------------------------------------------*/
/* Test: EST_sendCsrAttrsRequest with NULL context */
/*------------------------------------------------------------------*/
static void test_EST_sendCsrAttrsRequest_null_context(void **ppState)
{
    (void) ppState;

    ubyte requestUrl[] = "/.well-known/est/csrattrs";
    ubyte serverIdentity[] = "est.example.com";
    sbyte userAgent[] = "TestAgent/1.0";

    MSTATUS status = EST_sendCsrAttrsRequest(NULL, 0, requestUrl,
                                            DIGI_STRLEN((sbyte*)requestUrl),
                                            serverIdentity,
                                            DIGI_STRLEN((sbyte*)serverIdentity),
                                            userAgent);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_sendServerKeyGenRequest with NULL context */
/*------------------------------------------------------------------*/
static void test_EST_sendServerKeyGenRequest_null_context(void **ppState)
{
    (void) ppState;

    ubyte requestUrl[] = "/.well-known/est/serverkeygen";
    ubyte serverIdentity[] = "est.example.com";
    sbyte userAgent[] = "TestAgent/1.0";

    MSTATUS status = EST_sendServerKeyGenRequest(NULL, 0, requestUrl,
                                                 DIGI_STRLEN((sbyte*)requestUrl),
                                                 100, serverIdentity,
                                                 DIGI_STRLEN((sbyte*)serverIdentity),
                                                 userAgent);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_sendFullCmcRequest with NULL context */
/*------------------------------------------------------------------*/
static void test_EST_sendFullCmcRequest_null_context(void **ppState)
{
    (void) ppState;

    ubyte requestUrl[] = "/.well-known/est/fullcmc";
    ubyte serverIdentity[] = "est.example.com";
    sbyte userAgent[] = "TestAgent/1.0";

    MSTATUS status = EST_sendFullCmcRequest(NULL, 0, requestUrl,
                                           DIGI_STRLEN((sbyte*)requestUrl),
                                           100, serverIdentity,
                                           DIGI_STRLEN((sbyte*)serverIdentity),
                                           0, /* ENROLL */
                                           userAgent);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_openConnection with NULL parameters */
/*------------------------------------------------------------------*/
static void test_EST_openConnection_null_params(void **ppState)
{
    (void) ppState;

    MSTATUS status = EST_openConnection(NULL, NULL, 0, 443, NULL, 0,
                                       NULL, NULL, NULL, 0, FALSE, FALSE);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_openConnection with invalid port */
/*------------------------------------------------------------------*/
static void test_EST_openConnection_invalid_port(void **ppState)
{
    (void) ppState;

    ubyte serverIp[] = "192.168.1.1";
    ubyte serverIdentity[] = "est.example.com";
    sbyte4 connectionInstance = -1;
    httpContext *pHttpContext = NULL;

    MSTATUS status = EST_openConnection(NULL, serverIp,
                                       DIGI_STRLEN((sbyte*)serverIp),
                                       0, /* Invalid port */
                                       serverIdentity,
                                       DIGI_STRLEN((sbyte*)serverIdentity),
                                       &connectionInstance,
                                       &pHttpContext, NULL, 0, FALSE, FALSE);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_closeConnection with NULL context */
/*------------------------------------------------------------------*/
static void test_EST_closeConnection_null_context(void **ppState)
{
    (void) ppState;

    MSTATUS status = EST_closeConnection(NULL, 0);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_generateCSRRequestFromConfig with NULL params */
/*------------------------------------------------------------------*/
static void test_EST_generateCSRRequestFromConfig_null_params(void **ppState)
{
    (void) ppState;

    ubyte *pCsr = NULL;
    ubyte4 csrLen = 0;

    MSTATUS status = EST_generateCSRRequestFromConfig(
        MOC_ASYM(NULL)
        NULL, /* certStore */
        0,
        NULL, /* config file */
        NULL, /* extended attrs */
        0,
        NULL, /* key alias */
        0,
        NULL, /* key */
        0,
        NULL, /* hash type */
        0,
        &pCsr,
        &csrLen);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_sendCaCertsRequest validates URL format */
/*------------------------------------------------------------------*/
static void test_EST_sendCaCertsRequest_validates_url_format(void **ppState)
{
    (void) ppState;

    ubyte requestUrl[] = "/.well-known/est/cacerts";
    ubyte serverIdentity[] = "ca.digicert.com";
    sbyte userAgent[] = "DigiCertEST/2.0";

    MSTATUS status = EST_sendCaCertsRequest(NULL, 0, requestUrl,
                                           DIGI_STRLEN((sbyte*)requestUrl),
                                           serverIdentity,
                                           DIGI_STRLEN((sbyte*)serverIdentity),
                                           userAgent);

    assert_int_not_equal(status, OK);

    assert_true(strstr((char*)requestUrl, "cacerts") != NULL);
}

/*------------------------------------------------------------------*/
/* Test: EST_sendSimpleEnrollRequest validates request path */
/*------------------------------------------------------------------*/
static void test_EST_sendSimpleEnrollRequest_validates_path(void **ppState)
{
    (void) ppState;

    ubyte requestUrl[] = "/.well-known/est/label/simpleenroll";
    ubyte serverIdentity[] = "est-server.example.org";
    sbyte userAgent[] = "EST-Client/1.0";

    MSTATUS status = EST_sendSimpleEnrollRequest(NULL, 0, requestUrl,
                                                 DIGI_STRLEN((sbyte*)requestUrl),
                                                 256, /* CSR length */
                                                 serverIdentity,
                                                 DIGI_STRLEN((sbyte*)serverIdentity),
                                                 userAgent);

    assert_int_not_equal(status, OK);

    assert_true(strstr((char*)requestUrl, "simpleenroll") != NULL);
}

/*------------------------------------------------------------------*/
/* Test: EST_sendCsrAttrsRequest validates server identity */
/*------------------------------------------------------------------*/
static void test_EST_sendCsrAttrsRequest_validates_server_identity(void **ppState)
{
    (void) ppState;

    ubyte requestUrl[] = "/.well-known/est/csrattrs";
    ubyte serverIdentity[] = "artemis.mocana.com";
    ubyte4 identityLen = DIGI_STRLEN((sbyte*)serverIdentity);
    sbyte userAgent[] = "TestAgent/1.0";

    MSTATUS status = EST_sendCsrAttrsRequest(NULL, 0, requestUrl,
                                            DIGI_STRLEN((sbyte*)requestUrl),
                                            serverIdentity,
                                            identityLen,
                                            userAgent);

    assert_int_not_equal(status, OK);

    assert_true(identityLen > 0 && identityLen < 256);
}

/*------------------------------------------------------------------*/
/* Test: EST_sendServerKeyGenRequest with valid parameters */
/*------------------------------------------------------------------*/
static void test_EST_sendServerKeyGenRequest_validates_params(void **ppState)
{
    (void) ppState;

    ubyte requestUrl[] = "/.well-known/est/serverkeygen";
    ubyte serverIdentity[] = "keygen.est.com";
    sbyte userAgent[] = "EST-KeyGen/1.0";
    ubyte4 csrLen = 512;

    MSTATUS status = EST_sendServerKeyGenRequest(NULL, 0, requestUrl,
                                                 DIGI_STRLEN((sbyte*)requestUrl),
                                                 csrLen,
                                                 serverIdentity,
                                                 DIGI_STRLEN((sbyte*)serverIdentity),
                                                 userAgent);

    assert_int_not_equal(status, OK);

    assert_true(csrLen > 0);
}

/*------------------------------------------------------------------*/
/* Test: EST_sendFullCmcRequest validates request types */
/*------------------------------------------------------------------*/
static void test_EST_sendFullCmcRequest_validates_request_types(void **ppState)
{
    (void) ppState;

    ubyte requestUrl[] = "/.well-known/est/fullcmc";
    ubyte serverIdentity[] = "cmc.est.example.com";
    sbyte userAgent[] = "EST-CMC/1.0";

    MSTATUS status = EST_sendFullCmcRequest(NULL, 0, requestUrl,
                                           DIGI_STRLEN((sbyte*)requestUrl),
                                           300,
                                           serverIdentity,
                                           DIGI_STRLEN((sbyte*)serverIdentity),
                                           0, /* ENROLL = 0 */
                                           userAgent);
    assert_int_not_equal(status, OK);

    status = EST_sendFullCmcRequest(NULL, 0, requestUrl,
                                   DIGI_STRLEN((sbyte*)requestUrl),
                                   300,
                                   serverIdentity,
                                   DIGI_STRLEN((sbyte*)serverIdentity),
                                   1, /* RENEW = 1 */
                                   userAgent);
    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_openConnection validates port numbers */
/*------------------------------------------------------------------*/
static void test_EST_openConnection_validates_ports(void **ppState)
{
    (void) ppState;

    ubyte serverIp[] = "10.0.0.1";
    ubyte serverIdentity[] = "est.internal.com";
    sbyte4 connectionInstance = -1;
    httpContext *pHttpContext = NULL;

    MSTATUS status = EST_openConnection(NULL, serverIp,
                                       DIGI_STRLEN((sbyte*)serverIp),
                                       443,
                                       serverIdentity,
                                       DIGI_STRLEN((sbyte*)serverIdentity),
                                       &connectionInstance,
                                       &pHttpContext, NULL, 0, FALSE, FALSE);
    assert_int_not_equal(status, OK);

    status = EST_openConnection(NULL, serverIp,
                               DIGI_STRLEN((sbyte*)serverIp),
                               8443,
                               serverIdentity,
                               DIGI_STRLEN((sbyte*)serverIdentity),
                               &connectionInstance,
                               &pHttpContext, NULL, 0, FALSE, FALSE);
    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_openConnection with OCSP required */
/*------------------------------------------------------------------*/
static void test_EST_openConnection_with_ocsp(void **ppState)
{
    (void) ppState;

    ubyte serverIp[] = "192.168.100.50";
    ubyte serverIdentity[] = "ocsp-est.example.com";
    sbyte4 connectionInstance = -1;
    httpContext *pHttpContext = NULL;

    MSTATUS status = EST_openConnection(NULL, serverIp,
                                       DIGI_STRLEN((sbyte*)serverIp),
                                       443,
                                       serverIdentity,
                                       DIGI_STRLEN((sbyte*)serverIdentity),
                                       &connectionInstance,
                                       &pHttpContext, NULL, 0,
                                       TRUE, /* OCSP required */
                                       FALSE);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_openConnection with PQC enforcement */
/*------------------------------------------------------------------*/
static void test_EST_openConnection_with_pqc(void **ppState)
{
    (void) ppState;

    ubyte serverIp[] = "172.16.0.10";
    ubyte serverIdentity[] = "pqc-est.quantum.com";
    sbyte4 connectionInstance = -1;
    httpContext *pHttpContext = NULL;

    MSTATUS status = EST_openConnection(NULL, serverIp,
                                       DIGI_STRLEN((sbyte*)serverIp),
                                       443,
                                       serverIdentity,
                                       DIGI_STRLEN((sbyte*)serverIdentity),
                                       &connectionInstance,
                                       &pHttpContext, NULL, 0,
                                       FALSE,
                                       TRUE); /* PQC enforced */

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_closeConnection with valid connection instance */
/*------------------------------------------------------------------*/
static void test_EST_closeConnection_with_valid_instance(void **ppState)
{
    (void) ppState;

    MSTATUS status = EST_closeConnection(NULL, 42);

    assert_int_not_equal(status, OK);
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
/* Test: EST_setCookie with NULL context */
/*------------------------------------------------------------------*/
static void test_EST_setCookie_null_context(void **ppState)
{
    (void) ppState;

    ubyte requestBody[] = "test request body";

    MSTATUS status = EST_setCookie(NULL, requestBody, sizeof(requestBody));

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_setCookie with NULL body */
/*------------------------------------------------------------------*/
static void test_EST_setCookie_null_body(void **ppState)
{
    (void) ppState;

    MSTATUS status = EST_setCookie(NULL, NULL, 100);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_setCookie with zero length */
/*------------------------------------------------------------------*/
static void test_EST_setCookie_zero_length(void **ppState)
{
    (void) ppState;

    ubyte requestBody[] = "test request body";

    MSTATUS status = EST_setCookie(NULL, requestBody, 0);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_freeCookie with NULL context */
/*------------------------------------------------------------------*/
static void test_EST_freeCookie_null_context(void **ppState)
{
    (void) ppState;

    MSTATUS status = EST_freeCookie(NULL);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Main Test Runner */
/*------------------------------------------------------------------*/

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_EST_sendCaCertsRequest_null_context),
        cmocka_unit_test(test_EST_sendCaCertsRequest_null_url),
        cmocka_unit_test(test_EST_sendSimpleEnrollRequest_null_context),
        cmocka_unit_test(test_EST_sendSimpleEnrollRequest_zero_csr_length),
        cmocka_unit_test(test_EST_sendCsrAttrsRequest_null_context),
        cmocka_unit_test(test_EST_sendServerKeyGenRequest_null_context),
        cmocka_unit_test(test_EST_sendFullCmcRequest_null_context),
        cmocka_unit_test(test_EST_openConnection_null_params),
        cmocka_unit_test(test_EST_openConnection_invalid_port),
        cmocka_unit_test(test_EST_closeConnection_null_context),
        cmocka_unit_test(test_EST_generateCSRRequestFromConfig_null_params),
        cmocka_unit_test(test_EST_sendCaCertsRequest_validates_url_format),
        cmocka_unit_test(test_EST_sendSimpleEnrollRequest_validates_path),
        cmocka_unit_test(test_EST_sendCsrAttrsRequest_validates_server_identity),
        cmocka_unit_test(test_EST_sendServerKeyGenRequest_validates_params),
        cmocka_unit_test(test_EST_sendFullCmcRequest_validates_request_types),
        cmocka_unit_test(test_EST_openConnection_validates_ports),
        cmocka_unit_test(test_EST_openConnection_with_ocsp),
        cmocka_unit_test(test_EST_openConnection_with_pqc),
        cmocka_unit_test(test_EST_closeConnection_with_valid_instance),
        cmocka_unit_test(test_EST_setCookie_null_context),
        cmocka_unit_test(test_EST_setCookie_null_body),
        cmocka_unit_test(test_EST_setCookie_zero_length),
        cmocka_unit_test(test_EST_freeCookie_null_context),
    };

    return cmocka_run_group_tests(tests, testSetup, testTeardown);
}
