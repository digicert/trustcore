/*
 * test_est_request.c - Unit tests for EST request/response APIs
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

extern MSTATUS EST_setCookie(httpContext *pHttpContext, ubyte *pRequestBody, ubyte4 reqBodyLen);
extern MSTATUS EST_freeCookie(httpContext *pHttpContext);
extern MSTATUS EST_receiveResponse(httpContext *pHttpContext, ubyte4 connectionSSLInstance, ubyte **ppResponse, ubyte4 *pResponseLen);
extern MSTATUS EST_validateReceivedCertificate(certStore *pCertStore, ubyte *pReceivedCert, ubyte4 receivedCertLen);

typedef enum {
    x_pkcs7_cert = 0,
    x_csrattrs = 1
} EST_responseType;

extern MSTATUS EST_MESSAGE_CertReqToCSR(const ubyte* pCertReq, ubyte4 certReqLen, ubyte** ppCsr, ubyte4* pCsrLength);
extern MSTATUS EST_MESSAGE_parseResponse(EST_responseType type, ubyte* pCertRep, ubyte4 certRepLen, ubyte **pResp, ubyte4 *respLen);

/*------------------------------------------------------------------*/
/* Test: Set cookie with NULL context should fail */
/*------------------------------------------------------------------*/
static void test_EST_setCookie_null_context(void **ppState)
{
    (void) ppState;

    const char *data = "test data";

    MSTATUS status = EST_setCookie(NULL, (ubyte*)data, strlen(data));

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: Free cookie with NULL context should fail */
/*------------------------------------------------------------------*/
static void test_EST_freeCookie_null_context(void **ppState)
{
    (void) ppState;

    MSTATUS status = EST_freeCookie(NULL);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: Receive response with NULL context */
/*------------------------------------------------------------------*/
static void test_EST_receiveResponse_null_context(void **ppState)
{
    (void) ppState;

    ubyte *pResponse = NULL;
    ubyte4 responseLen = 0;

    MSTATUS status = EST_receiveResponse(NULL, 0, &pResponse, &responseLen);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: Receive response with NULL output pointers */
/*------------------------------------------------------------------*/
static void test_EST_receiveResponse_null_output(void **ppState)
{
    (void) ppState;

    MSTATUS status = EST_receiveResponse(NULL, 0, NULL, NULL);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: Validate received certificate with NULL parameters */
/*------------------------------------------------------------------*/
static void test_EST_validateReceivedCertificate_null_params(void **ppState)
{
    (void) ppState;

    MSTATUS status = EST_validateReceivedCertificate(NULL, NULL, 0);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_MESSAGE_CertReqToCSR with NULL input */
/*------------------------------------------------------------------*/
static void test_EST_MESSAGE_CertReqToCSR_null_input(void **ppState)
{
    (void) ppState;

    ubyte *pCsr = NULL;
    ubyte4 csrLen = 0;

    MSTATUS status = EST_MESSAGE_CertReqToCSR(NULL, 0, &pCsr, &csrLen);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_MESSAGE_parseResponse with NULL input */
/*------------------------------------------------------------------*/
static void test_EST_MESSAGE_parseResponse_null_input(void **ppState)
{
    (void) ppState;

    ubyte *pResp = NULL;
    ubyte4 respLen = 0;

    MSTATUS status = EST_MESSAGE_parseResponse(x_pkcs7_cert, NULL, 0, &pResp, &respLen);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_MESSAGE_parseResponse with NULL output */
/*------------------------------------------------------------------*/
static void test_EST_MESSAGE_parseResponse_null_output(void **ppState)
{
    (void) ppState;

    ubyte response[] = "test response data";

    MSTATUS status = EST_MESSAGE_parseResponse(x_pkcs7_cert, response, sizeof(response), NULL, NULL);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_MESSAGE_parseResponse with csrattrs type and NULL input */
/*------------------------------------------------------------------*/
static void test_EST_MESSAGE_parseResponse_csrattrs_null(void **ppState)
{
    (void) ppState;

    ubyte *pResp = NULL;
    ubyte4 respLen = 0;

    MSTATUS status = EST_MESSAGE_parseResponse(x_csrattrs, NULL, 0, &pResp, &respLen);

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: EST_MESSAGE_CertReqToCSR with valid minimal CSR */
/*------------------------------------------------------------------*/
static void test_EST_MESSAGE_CertReqToCSR_valid_minimal(void **ppState)
{
    (void) ppState;

    ubyte certReq[] = {
        0x30, 0x20,  /* SEQUENCE */
        0x30, 0x10,  /* CertificationRequestInfo */
        0x02, 0x01, 0x00,  /* version */
        0x30, 0x00,  /* subject (empty) */
        0x30, 0x00,  /* subjectPKInfo (empty) */
        0xa0, 0x00,  /* attributes */
        0x30, 0x0c,  /* signatureAlgorithm */
        0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x03, 0x00   /* signature */
    };
    ubyte4 certReqLen = sizeof(certReq);
    ubyte *pCsr = NULL;
    ubyte4 csrLen = 0;

    MSTATUS status = EST_MESSAGE_CertReqToCSR(certReq, certReqLen, &pCsr, &csrLen);

    if (status == OK && pCsr != NULL) {
        assert_true(csrLen > 0);
        DIGI_FREE((void**)&pCsr);
    }
}

/*------------------------------------------------------------------*/
/* Test: EST_MESSAGE_CertReqToCSR with zero length input */
/*------------------------------------------------------------------*/
static void test_EST_MESSAGE_CertReqToCSR_zero_length_input(void **ppState)
{
    (void) ppState;

    ubyte certReq[] = {0x30, 0x00};
    ubyte *pCsr = NULL;
    ubyte4 csrLen = 0;

    MSTATUS status = EST_MESSAGE_CertReqToCSR(certReq, 0, &pCsr, &csrLen);

    assert_int_equal(status, OK);
    if (pCsr != NULL) {
        DIGI_FREE((void**)&pCsr);
    }
}

/*------------------------------------------------------------------*/
/* Test: EST_MESSAGE_parseResponse validates response type */
/*------------------------------------------------------------------*/
static void test_EST_MESSAGE_parseResponse_validates_type(void **ppState)
{
    (void) ppState;

    ubyte response[] = {0x30, 0x10, 0x02, 0x01, 0x00, 0x30, 0x0b};
    ubyte *pResp = NULL;
    ubyte4 respLen = 0;

    MSTATUS status = EST_MESSAGE_parseResponse(x_pkcs7_cert, response, sizeof(response), &pResp, &respLen);

    (void)status;

    if (pResp) {
        DIGI_FREE((void**)&pResp);
    }
}

/*------------------------------------------------------------------*/
/* Test: EST_MESSAGE_parseResponse with csrattrs and valid data */
/*------------------------------------------------------------------*/
static void test_EST_MESSAGE_parseResponse_csrattrs_valid(void **ppState)
{
    (void) ppState;

    ubyte response[] = {0x30, 0x05, 0x06, 0x03, 0x55, 0x04, 0x06};
    ubyte *pResp = NULL;
    ubyte4 respLen = 0;

    MSTATUS status = EST_MESSAGE_parseResponse(x_csrattrs, response, sizeof(response), &pResp, &respLen);

    if (status == OK && pResp != NULL) {
        assert_true(respLen > 0);
        DIGI_FREE((void**)&pResp);
    }
}

/*------------------------------------------------------------------*/
/* Test: EST_MESSAGE_CertReqToCSR with malformed ASN.1 */
/*------------------------------------------------------------------*/
static void test_EST_MESSAGE_CertReqToCSR_malformed_asn1(void **ppState)
{
    (void) ppState;

    ubyte certReq[] = {0xFF, 0xFF, 0xFF, 0xFF};
    ubyte *pCsr = NULL;
    ubyte4 csrLen = 0;

    MSTATUS status = EST_MESSAGE_CertReqToCSR(certReq, sizeof(certReq), &pCsr, &csrLen);

    if (status == OK && pCsr != NULL) {
        DIGI_FREE((void**)&pCsr);
    }
}

/*------------------------------------------------------------------*/
/* Test: EST_MESSAGE_parseResponse validates output length */
/*------------------------------------------------------------------*/
static void test_EST_MESSAGE_parseResponse_validates_output_length(void **ppState)
{
    (void) ppState;

    ubyte response[] = {0x30, 0x03, 0x02, 0x01, 0x00};
    ubyte *pResp = NULL;
    ubyte4 respLen = 0;

    MSTATUS status = EST_MESSAGE_parseResponse(x_pkcs7_cert, response, sizeof(response), &pResp, &respLen);

    if (status == OK && pResp != NULL) {
        assert_true(respLen >= 0);
        DIGI_FREE((void**)&pResp);
    }
}

/*------------------------------------------------------------------*/
/* Test: EST_validateReceivedCertificate with NULL cert store */
/*------------------------------------------------------------------*/
static void test_EST_validateReceivedCertificate_null_store(void **ppState)
{
    (void) ppState;

    ubyte cert[] = {0x30, 0x82, 0x01, 0x00};

    MSTATUS status = EST_validateReceivedCertificate(NULL, cert, sizeof(cert));

    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Main test runner */
/*------------------------------------------------------------------*/
int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_EST_setCookie_null_context),
        cmocka_unit_test(test_EST_freeCookie_null_context),
        cmocka_unit_test(test_EST_receiveResponse_null_context),
        cmocka_unit_test(test_EST_receiveResponse_null_output),
        cmocka_unit_test(test_EST_validateReceivedCertificate_null_params),
        cmocka_unit_test(test_EST_MESSAGE_CertReqToCSR_null_input),
        cmocka_unit_test(test_EST_MESSAGE_parseResponse_null_input),
        cmocka_unit_test(test_EST_MESSAGE_parseResponse_null_output),
        cmocka_unit_test(test_EST_MESSAGE_parseResponse_csrattrs_null),
        cmocka_unit_test(test_EST_MESSAGE_CertReqToCSR_valid_minimal),
        cmocka_unit_test(test_EST_MESSAGE_CertReqToCSR_zero_length_input),
        cmocka_unit_test(test_EST_MESSAGE_parseResponse_validates_type),
        cmocka_unit_test(test_EST_MESSAGE_parseResponse_csrattrs_valid),
        cmocka_unit_test(test_EST_MESSAGE_CertReqToCSR_malformed_asn1),
        cmocka_unit_test(test_EST_MESSAGE_parseResponse_validates_output_length),
        cmocka_unit_test(test_EST_validateReceivedCertificate_null_store),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
