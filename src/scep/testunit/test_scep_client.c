/*
 * test_scep_client.c
 *
 * SCEP Client Unit Test
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
#include "asn1/parseasn1.h"
#include "common/absstream.h"
#include "common/memfile.h"
#include "crypto/hw_accel.h"
#include "crypto/pubcrypto.h"
#include "crypto/crypto.h"
#include "crypto/pkcs10.h"
#include "crypto/pkcs7.h"
#include "asn1/oiddefs.h"
#include "http/http_context.h"
#include "http/http.h"
#include "http/http_common.h"

#include "scep/scep.h"
#include "scep/scep_context.h"
#include "scep/scep_client.h"
#include "scep/scep_utils.h"

/*------------------------------------------------------------------*/
/* Mock test data and callback functions */
/*------------------------------------------------------------------*/

static ubyte g_mockCert[] = {
    0x30, 0x82, 0x01, 0x75, 0x30, 0x82, 0x01, 0x1f, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x14, 0x1d, 0xe5, 0xdd, 0xe3, 0x35, 0x37, 0xbc, 0x27, 0x93,
    0xc0, 0x05, 0xa9, 0xb6, 0x9d, 0xae, 0x54, 0x85, 0x96, 0x87, 0xf6, 0x30,
    0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
    0x05, 0x00, 0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0c, 0x04, 0x54, 0x65, 0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32,
    0x36, 0x30, 0x31, 0x32, 0x32, 0x31, 0x30, 0x31, 0x38, 0x32, 0x35, 0x5a,
    0x17, 0x0d, 0x32, 0x37, 0x30, 0x31, 0x32, 0x32, 0x31, 0x30, 0x31, 0x38,
    0x32, 0x35, 0x5a, 0x30, 0x0f, 0x31, 0x0d, 0x30, 0x0b, 0x06, 0x03, 0x55,
    0x04, 0x03, 0x0c, 0x04, 0x54, 0x65, 0x73, 0x74, 0x30, 0x5c, 0x30, 0x0d,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
    0x00, 0x03, 0x4b, 0x00, 0x30, 0x48, 0x02, 0x41, 0x00, 0xf1, 0xa0, 0x26,
    0xe9, 0xac, 0x2a, 0x6b, 0xce, 0x75, 0xaa, 0xd6, 0xf6, 0x78, 0xd6, 0x5b,
    0x45, 0x59, 0x51, 0x65, 0x21, 0xfa, 0xe5, 0x9d, 0x11, 0x3b, 0x62, 0xfb,
    0xe0, 0x92, 0xdf, 0xc4, 0x68, 0x24, 0xf8, 0x20, 0xe4, 0xa1, 0x3a, 0x84,
    0xdc, 0x51, 0xe2, 0x67, 0xe7, 0x04, 0x8d, 0x9a, 0xb6, 0x62, 0xd1, 0x4e,
    0x45, 0x30, 0xc4, 0x60, 0xac, 0x85, 0xed, 0x70, 0x79, 0x4e, 0xf6, 0x6d,
    0x41, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d,
    0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x69, 0x10, 0x3a,
    0x95, 0xdd, 0x0c, 0x2b, 0xe6, 0xf9, 0x5a, 0xe3, 0x5a, 0x76, 0xbc, 0x7b,
    0x73, 0xed, 0x2b, 0xa0, 0x70, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23,
    0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x69, 0x10, 0x3a, 0x95, 0xdd, 0x0c,
    0x2b, 0xe6, 0xf9, 0x5a, 0xe3, 0x5a, 0x76, 0xbc, 0x7b, 0x73, 0xed, 0x2b,
    0xa0, 0x70, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff,
    0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0d, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x41,
    0x00, 0xe1, 0x1c, 0xf2, 0xe1, 0x4e, 0xf3, 0x3c, 0xff, 0xa8, 0x58, 0x5d,
    0xbd, 0x67, 0xb8, 0x91, 0xa0, 0xce, 0x42, 0x7f, 0x20, 0x24, 0x79, 0xbf,
    0xe0, 0x86, 0xa1, 0x4c, 0x16, 0xc9, 0xfa, 0xb6, 0xac, 0xa4, 0x22, 0xe5,
    0x79, 0x78, 0xba, 0x9f, 0x31, 0x14, 0x85, 0xb6, 0x9b, 0xc6, 0x2d, 0x05,
    0x4e, 0xd8, 0xe3, 0xa8, 0xbe, 0x0c, 0x11, 0xfb, 0xe5, 0xb7, 0x96, 0x96,
    0x81, 0x3c, 0x65, 0xc7, 0x97
};

static sbyte4 mock_certificate_store_lookup(void* reserved, certDistinguishedName *pLookupCertDN, certDescriptor *pReturnCert)
{
    MOC_UNUSED(reserved);
    MOC_UNUSED(pLookupCertDN);

    if (!pReturnCert)
        return ERR_NULL_POINTER;

    pReturnCert->pCertificate = g_mockCert;
    pReturnCert->certLength = sizeof(g_mockCert);
    pReturnCert->cookie = 0;

    return OK;
}

static sbyte4 mock_key_pair_lookup(void* reserved, certDistinguishedName *pLookupKeyDN,
                                   ubyte** keyBlob, ubyte4* keyBlobLen,
                                   ubyte** signKeyBlob, ubyte4* signKeyBlobLen,
                                   intBoolean *pKeyRequired)
{
    MOC_UNUSED(reserved);
    MOC_UNUSED(pLookupKeyDN);

    if (keyBlob) *keyBlob = NULL;
    if (keyBlobLen) *keyBlobLen = 0;
    if (signKeyBlob) *signKeyBlob = NULL;
    if (signKeyBlobLen) *signKeyBlobLen = 0;
    if (pKeyRequired) *pKeyRequired = FALSE;

    return OK;
}

static void init_mock_requestInfo(requestInfo *pReqInfo)
{
    certDistinguishedName *pDN;

    memset(pReqInfo, 0, sizeof(requestInfo));

    pDN = (certDistinguishedName*)malloc(sizeof(certDistinguishedName));
    if (pDN) {
        memset(pDN, 0, sizeof(certDistinguishedName));
    }

    pReqInfo->type = scep_PKCSReq;

    pReqInfo->value.certInfoAndReqAttrs.pSubject = pDN;
}

/*------------------------------------------------------------------*/
/* Setup and Teardown Functions */
/*------------------------------------------------------------------*/

static int testSetup(void **ppState)
{
    MSTATUS status;

    MOC_UNUSED(ppState);

    status = DIGICERT_initDigicert();
    if (OK > status)
        return -1;

    status = HTTP_initClient(10);
    if (OK > status)
    {
        DIGICERT_freeDigicert();
        return -1;
    }

    SCEP_scepSettings()->funcPtrCertificateStoreLookup = mock_certificate_store_lookup;
    SCEP_scepSettings()->funcPtrKeyPairLookup = mock_key_pair_lookup;

    return 0;
}

static int testTeardown(void **ppState)
{
    MOC_UNUSED(ppState);

    DIGICERT_freeDigicert();

    return 0;
}

/*------------------------------------------------------------------*/
/* Test Functions */
/*------------------------------------------------------------------*/

/*
 * Test: SCEP_CLIENT_initContext with valid parameter
 */
static void test_SCEP_CLIENT_initContext_valid(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_initContext(&pContext);
    assert_int_equal(status, OK);
    assert_non_null(pContext);

    if (pContext)
    {
        SCEP_CLIENT_releaseContext(&pContext);
        assert_null(pContext);
    }
}

/*
 * Test: SCEP_CLIENT_initContext with NULL parameter
 */
static void test_SCEP_CLIENT_initContext_null_param(void **ppState)
{
    MSTATUS status;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_initContext(NULL);
    assert_int_not_equal(status, OK);
}

/*
 * Test: SCEP_CLIENT_releaseContext with NULL parameter
 */
static void test_SCEP_CLIENT_releaseContext_null_param(void **ppState)
{
    MSTATUS status;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_releaseContext(NULL);
    assert_int_equal(status, OK);
}

/*
 * Test: SCEP_CLIENT_releaseContext with NULL pointer content
 */
static void test_SCEP_CLIENT_releaseContext_null_pointer_content(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_releaseContext(&pContext);
    assert_int_equal(status, OK);
}

/*
 * Test: SCEP_CLIENT_setRequestInfo with NULL context
 */
static void test_SCEP_CLIENT_setRequestInfo_null_context(void **ppState)
{
    MSTATUS status;
    requestInfo reqInfo;

    MOC_UNUSED(ppState);

    memset(&reqInfo, 0, sizeof(reqInfo));
    reqInfo.type = scep_PKCSReq;

    status = SCEP_CLIENT_setRequestInfo(NULL, &reqInfo);
    assert_int_not_equal(status, OK);
}

/*
 * Test: SCEP_CLIENT_setRequestInfo with NULL requestInfo
 */
static void test_SCEP_CLIENT_setRequestInfo_null_requestinfo(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_initContext(&pContext);
    if (status == OK && pContext)
    {
        status = SCEP_CLIENT_setRequestInfo(pContext, NULL);
        assert_int_not_equal(status, OK);

        SCEP_CLIENT_releaseContext(&pContext);
    }
}

/*
 * Test: SCEP_CLIENT_generateRequestEx with HTTP POST flag
 */
static void test_SCEP_CLIENT_generateRequestEx_http_post(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;
    requestInfo *pReqInfo = NULL;
    ubyte *pQuery = NULL;
    ubyte4 queryLen = 0;
    ubyte4 bodyLen = 0;
    void *pCookie = NULL;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_initContext(&pContext);
    assert_int_equal(status, OK);

    if (pContext)
    {
        pReqInfo = (requestInfo*)malloc(sizeof(requestInfo));
        assert_non_null(pReqInfo);

        init_mock_requestInfo(pReqInfo);

        status = SCEP_CLIENT_setRequestInfo(pContext, pReqInfo);

        status = SCEP_CLIENT_generateRequestEx(pContext, FALSE, &pQuery, &queryLen, &bodyLen, &pCookie);
        assert_int_not_equal(status, OK);

        SCEP_CLIENT_releaseContext(&pContext);
    }
}

/*
 * Test: SCEP_CLIENT_generateRequestEx with HTTP GET flag
 */
static void test_SCEP_CLIENT_generateRequestEx_http_get(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;
    requestInfo *pReqInfo = NULL;
    ubyte *pQuery = NULL;
    ubyte4 queryLen = 0;
    ubyte4 bodyLen = 0;
    void *pCookie = NULL;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_initContext(&pContext);
    assert_int_equal(status, OK);

    if (pContext)
    {
        pReqInfo = (requestInfo*)malloc(sizeof(requestInfo));
        assert_non_null(pReqInfo);

        init_mock_requestInfo(pReqInfo);

        status = SCEP_CLIENT_setRequestInfo(pContext, pReqInfo);

        status = SCEP_CLIENT_generateRequestEx(pContext, TRUE, &pQuery, &queryLen, &bodyLen, &pCookie);
        assert_int_not_equal(status, OK);

        SCEP_CLIENT_releaseContext(&pContext);
    }
}

/*
 * Test: SCEP_CLIENT_http_responseBodyCallback with zero length
 */
static void test_SCEP_CLIENT_http_responseBodyCallback_zero_length(void **ppState)
{
    sbyte4 result;
    httpContext mockContext;
    ubyte mockData[128];

    MOC_UNUSED(ppState);
    memset(&mockContext, 0, sizeof(mockContext));
    memset(mockData, 0, sizeof(mockData));

    result = SCEP_CLIENT_http_responseBodyCallback(&mockContext, mockData, 0, FALSE);
    assert_true(result <= OK || result == ERR_NULL_POINTER);
}

/*
 * Test: SCEP_CLIENT_http_responseBodyCallback with NULL data
 */
static void test_SCEP_CLIENT_http_responseBodyCallback_null_data(void **ppState)
{
    sbyte4 result;
    httpContext mockContext;

    MOC_UNUSED(ppState);
    memset(&mockContext, 0, sizeof(mockContext));

    result = SCEP_CLIENT_http_responseBodyCallback(&mockContext, NULL, 0, FALSE);
    assert_int_not_equal(result, OK);
}

/*
 * Test: Multiple context initialization and release
 */
static void test_SCEP_CLIENT_multiple_contexts(void **ppState)
{
    MSTATUS status;
    scepContext *pContext1 = NULL;
    scepContext *pContext2 = NULL;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_initContext(&pContext1);
    assert_int_equal(status, OK);
    assert_non_null(pContext1);

    status = SCEP_CLIENT_initContext(&pContext2);
    assert_int_equal(status, OK);
    assert_non_null(pContext2);

    assert_ptr_not_equal(pContext1, pContext2);

    if (pContext1)
    {
        SCEP_CLIENT_releaseContext(&pContext1);
        assert_null(pContext1);
    }

    if (pContext2)
    {
        SCEP_CLIENT_releaseContext(&pContext2);
        assert_null(pContext2);
    }
}

/*
 * Test: SCEP_CLIENT_initContextEx with NULL parameter
 */
static void test_SCEP_CLIENT_initContextEx_null_param(void **ppState)
{
    MSTATUS status;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_initContextEx(NULL, NULL);
    assert_int_not_equal(status, OK);
}

/*
 * Test: SCEP_CLIENT_initContextEx with valid parameters
 */
static void test_SCEP_CLIENT_initContextEx_valid(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;
    void *cookie = (void*)0x12345678;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_initContextEx(&pContext, cookie);
    assert_int_equal(status, OK);
    assert_non_null(pContext);

    if (pContext)
    {
        SCEP_CLIENT_releaseContext(&pContext);
        assert_null(pContext);
    }
}

/*
 * Test: SCEP_CLIENT_getStatus with valid context
 */
static void test_SCEP_CLIENT_getStatus_valid_context(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;
    SCEP_pkiStatus pkiStatus;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_initContext(&pContext);
    assert_int_equal(status, OK);
    assert_non_null(pContext);

    if (pContext)
    {
        pkiStatus = SCEP_CLIENT_getStatus(pContext);
        assert_true(pkiStatus == scep_FAILURE || pkiStatus == scep_PENDING || pkiStatus == scep_SUCCESS);

        SCEP_CLIENT_releaseContext(&pContext);
    }
}

/*
 * Test: SCEP_CLIENT_isDoneReceivingResponse with valid context
 */
static void test_SCEP_CLIENT_isDoneReceivingResponse_valid_context(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;
    byteBoolean result;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_initContext(&pContext);
    assert_int_equal(status, OK);
    assert_non_null(pContext);

    if (pContext)
    {
        result = SCEP_CLIENT_isDoneReceivingResponse(pContext);
        assert_int_equal(result, FALSE);

        SCEP_CLIENT_releaseContext(&pContext);
    }
}

/*
 * Test: SCEP_CLIENT_getHTTPStatusCode with NULL context
 */
static void test_SCEP_CLIENT_getHTTPStatusCode_null_context(void **ppState)
{
    sbyte4 statusCode;

    MOC_UNUSED(ppState);

    statusCode = SCEP_CLIENT_getHTTPStatusCode(NULL);
    assert_true(statusCode <= 0);
}

/*
 * Test: SCEP_CLIENT_getHTTPStatusCode with valid context
 */
static void test_SCEP_CLIENT_getHTTPStatusCode_valid_context(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;
    sbyte4 statusCode;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_initContext(&pContext);
    assert_int_equal(status, OK);
    assert_non_null(pContext);

    if (pContext)
    {
        statusCode = SCEP_CLIENT_getHTTPStatusCode(pContext);
        assert_true(statusCode >= 0);

        SCEP_CLIENT_releaseContext(&pContext);
    }
}

/*
 * Test: SCEP_CLIENT_getMessageType with NULL parameters
 */
static void test_SCEP_CLIENT_getMessageType_null_params(void **ppState)
{
    MSTATUS status;
    SCEP_messageType msgType;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_getMessageType(NULL, &msgType);
    assert_int_not_equal(status, OK);

    status = SCEP_CLIENT_getMessageType(NULL, NULL);
    assert_int_not_equal(status, OK);
}

/*
 * Test: SCEP_CLIENT_getFailInfo with NULL parameters
 */
static void test_SCEP_CLIENT_getFailInfo_null_params(void **ppState)
{
    MSTATUS status;
    SCEP_failInfo failInfo;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_getFailInfo(NULL, &failInfo);
    assert_int_not_equal(status, OK);

    status = SCEP_CLIENT_getFailInfo(NULL, NULL);
    assert_int_not_equal(status, OK);
}

/*
 * Test: SCEP_CLIENT_recvResponse with zero length
 */
static void test_SCEP_CLIENT_recvResponse_zero_length(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;
    ubyte mockResponse[128];
    ubyte contentType[] = "application/x-pki-message";

    MOC_UNUSED(ppState);
    memset(mockResponse, 0, sizeof(mockResponse));

    status = SCEP_CLIENT_initContext(&pContext);
    if (status == OK && pContext)
    {
        status = SCEP_CLIENT_recvResponse(pContext, contentType, sizeof(contentType) - 1,
                                         mockResponse, 0);
        assert_int_not_equal(status, OK);

        SCEP_CLIENT_releaseContext(&pContext);
    }
}

/*
 * Test: SCEP_CLIENT_generatePollServerRequest with NULL parameters
 */
static void test_SCEP_CLIENT_generatePollServerRequest_null_params(void **ppState)
{
    MSTATUS status;
    ubyte *pQuery = NULL;
    ubyte4 queryLen = 0;
    ubyte4 bodyLen = 0;
    void *pCookie = NULL;
    void *pPollingCookie = NULL;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_generatePollServerRequest(NULL, &pQuery, &queryLen,
                                                  &bodyLen, &pCookie, &pPollingCookie);
    assert_int_not_equal(status, OK);
}

/*
 * Test: SCEP_CLIENT_generatePollServerRequest with valid context
 */
static void test_SCEP_CLIENT_generatePollServerRequest_valid_context(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;
    ubyte *pQuery = NULL;
    ubyte4 queryLen = 0;
    ubyte4 bodyLen = 0;
    void *pCookie = NULL;
    void *pPollingCookie = NULL;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_initContext(&pContext);
    if (status == OK && pContext)
    {
        status = SCEP_CLIENT_generatePollServerRequest(pContext, &pQuery, &queryLen,
                                                      &bodyLen, &pCookie, &pPollingCookie);
        assert_int_not_equal(status, OK);

        SCEP_CLIENT_releaseContext(&pContext);
    }
}

/*
 * Test: SCEP_CLIENT_releaseCookie with NULL
 */
static void test_SCEP_CLIENT_releaseCookie_null(void **ppState)
{
    MSTATUS status;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_releaseCookie(NULL);
    assert_int_equal(status, OK);
}

/*
 * Test: SCEP_CLIENT_releasePollCookie with NULL
 */
static void test_SCEP_CLIENT_releasePollCookie_null(void **ppState)
{
    MSTATUS status;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_releasePollCookie(NULL);
    assert_int_equal(status, OK);
}

/*
 * Test: SCEP_CLIENT_http_responseHeaderCallback with NULL context
 */
static void test_SCEP_CLIENT_http_responseHeaderCallback_null_context(void **ppState)
{
    sbyte4 result;

    MOC_UNUSED(ppState);

    result = SCEP_CLIENT_http_responseHeaderCallback(NULL, FALSE);
    assert_int_equal(result, OK);
}

/*
 * Test: SCEP_CLIENT_http_responseHeaderCallback with continue flag
 */
static void test_SCEP_CLIENT_http_responseHeaderCallback_continue_flag(void **ppState)
{
    sbyte4 result;
    httpContext mockContext;

    MOC_UNUSED(ppState);
    memset(&mockContext, 0, sizeof(mockContext));

    result = SCEP_CLIENT_http_responseHeaderCallback(&mockContext, TRUE);
    assert_true(result <= OK || result == ERR_NULL_POINTER);
}

/*
 * Test: SCEP_CLIENT_getMessageType with valid context
 */
static void test_SCEP_CLIENT_getMessageType_valid_context(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;
    SCEP_messageType msgType;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_initContext(&pContext);
    if (status == OK && pContext)
    {
        status = SCEP_CLIENT_getMessageType(pContext, &msgType);
        assert_int_not_equal(status, OK);

        SCEP_CLIENT_releaseContext(&pContext);
    }
}

/*
 * Test: SCEP_CLIENT_getFailInfo with valid context
 */
static void test_SCEP_CLIENT_getFailInfo_valid_context(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;
    SCEP_failInfo failInfo;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_initContext(&pContext);
    if (status == OK && pContext)
    {
        status = SCEP_CLIENT_getFailInfo(pContext, &failInfo);
        assert_int_not_equal(status, OK);

        SCEP_CLIENT_releaseContext(&pContext);
    }
}

/*
 * Test: SCEP_CLIENT_setRequestInfo with valid PKCSReq
 */
static void test_SCEP_CLIENT_setRequestInfo_valid_pkcs_req(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;
    requestInfo *pReqInfo = NULL;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_initContext(&pContext);
    if (status == OK && pContext)
    {
        pReqInfo = (requestInfo*)malloc(sizeof(requestInfo));
        if (pReqInfo)
        {
            init_mock_requestInfo(pReqInfo);

            status = SCEP_CLIENT_setRequestInfo(pContext, pReqInfo);
            assert_true(status <= OK);

            if (status != OK)
            {
                if (pReqInfo->value.certInfoAndReqAttrs.pSubject)
                    FREE(pReqInfo->value.certInfoAndReqAttrs.pSubject);
                FREE(pReqInfo);
            }
        }

        SCEP_CLIENT_releaseContext(&pContext);
    }
}

/*
 * Test: SCEP_CLIENT_setRequestInfo called multiple times
 */
static void test_SCEP_CLIENT_setRequestInfo_multiple_calls(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;
    requestInfo *pReqInfo1 = NULL;
    requestInfo *pReqInfo2 = NULL;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_initContext(&pContext);
    if (status == OK && pContext)
    {
        pReqInfo1 = (requestInfo*)malloc(sizeof(requestInfo));
        pReqInfo2 = (requestInfo*)malloc(sizeof(requestInfo));

        if (pReqInfo1 && pReqInfo2)
        {
            byteBoolean reqInfo1Owned = FALSE;
            byteBoolean reqInfo2Owned = FALSE;

            init_mock_requestInfo(pReqInfo1);
            init_mock_requestInfo(pReqInfo2);

            status = SCEP_CLIENT_setRequestInfo(pContext, pReqInfo1);
            if (status == OK)
            {
                reqInfo1Owned = TRUE;
            }
            assert_true(status <= OK);

            status = SCEP_CLIENT_setRequestInfo(pContext, pReqInfo2);
            if (status == OK)
            {
                reqInfo2Owned = TRUE;
                reqInfo1Owned = FALSE;
            }
            assert_true(status <= OK);

            if (!reqInfo1Owned)
            {
                if (pReqInfo1->value.certInfoAndReqAttrs.pSubject)
                    FREE(pReqInfo1->value.certInfoAndReqAttrs.pSubject);
                FREE(pReqInfo1);
            }
            if (!reqInfo2Owned)
            {
                if (pReqInfo2->value.certInfoAndReqAttrs.pSubject)
                    FREE(pReqInfo2->value.certInfoAndReqAttrs.pSubject);
                FREE(pReqInfo2);
            }
        }
        else
        {
            if (pReqInfo1)
            {
                if (pReqInfo1->value.certInfoAndReqAttrs.pSubject)
                    FREE(pReqInfo1->value.certInfoAndReqAttrs.pSubject);
                FREE(pReqInfo1);
            }
            if (pReqInfo2)
            {
                if (pReqInfo2->value.certInfoAndReqAttrs.pSubject)
                    FREE(pReqInfo2->value.certInfoAndReqAttrs.pSubject);
                FREE(pReqInfo2);
            }
        }

        SCEP_CLIENT_releaseContext(&pContext);
    }
}

/*
 * Test: Create context, set request, generate request, release
 */
static void test_SCEP_CLIENT_workflow_sequence(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;
    requestInfo *pReqInfo = NULL;
    ubyte *pQuery = NULL;
    ubyte4 queryLen = 0;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_initContext(&pContext);
    assert_int_equal(status, OK);

    if (pContext)
    {
        pReqInfo = (requestInfo*)malloc(sizeof(requestInfo));
        if (pReqInfo)
        {
            init_mock_requestInfo(pReqInfo);
            status = SCEP_CLIENT_setRequestInfo(pContext, pReqInfo);
        }

        status = SCEP_CLIENT_generateRequest(pContext, &pQuery, &queryLen);
        assert_int_not_equal(status, OK);

        SCEP_CLIENT_releaseContext(&pContext);
        assert_null(pContext);
    }
}

/*
 * Test: Context reuse after reset
 */
static void test_SCEP_CLIENT_context_reuse(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;
    requestInfo *pReqInfo1 = NULL;
    requestInfo *pReqInfo2 = NULL;

    MOC_UNUSED(ppState);

    status = SCEP_CLIENT_initContext(&pContext);
    assert_int_equal(status, OK);

    if (pContext)
    {
        pReqInfo1 = (requestInfo*)malloc(sizeof(requestInfo));
        if (pReqInfo1)
        {
            init_mock_requestInfo(pReqInfo1);
            SCEP_CLIENT_setRequestInfo(pContext, pReqInfo1);
        }

        status = SCEP_CONTEXT_resetContext(pContext);
        assert_int_equal(status, OK);

        pReqInfo2 = (requestInfo*)malloc(sizeof(requestInfo));
        if (pReqInfo2)
        {
            init_mock_requestInfo(pReqInfo2);
            SCEP_CLIENT_setRequestInfo(pContext, pReqInfo2);
        }

        SCEP_CLIENT_releaseContext(&pContext);
    }
}

/*------------------------------------------------------------------*/
/* Main test runner */
/*------------------------------------------------------------------*/
int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_SCEP_CLIENT_initContext_valid),
        cmocka_unit_test(test_SCEP_CLIENT_initContext_null_param),
        cmocka_unit_test(test_SCEP_CLIENT_initContextEx_null_param),
        cmocka_unit_test(test_SCEP_CLIENT_initContextEx_valid),
        cmocka_unit_test(test_SCEP_CLIENT_releaseContext_null_param),
        cmocka_unit_test(test_SCEP_CLIENT_releaseContext_null_pointer_content),
        cmocka_unit_test(test_SCEP_CLIENT_setRequestInfo_null_context),
        cmocka_unit_test(test_SCEP_CLIENT_setRequestInfo_null_requestinfo),
        cmocka_unit_test(test_SCEP_CLIENT_setRequestInfo_valid_pkcs_req),
        cmocka_unit_test(test_SCEP_CLIENT_setRequestInfo_multiple_calls),
        cmocka_unit_test(test_SCEP_CLIENT_generateRequestEx_http_post),
        cmocka_unit_test(test_SCEP_CLIENT_generateRequestEx_http_get),
        cmocka_unit_test(test_SCEP_CLIENT_recvResponse_zero_length),
        cmocka_unit_test(test_SCEP_CLIENT_generatePollServerRequest_null_params),
        cmocka_unit_test(test_SCEP_CLIENT_generatePollServerRequest_valid_context),
        cmocka_unit_test(test_SCEP_CLIENT_releaseCookie_null),
        cmocka_unit_test(test_SCEP_CLIENT_releasePollCookie_null),
        cmocka_unit_test(test_SCEP_CLIENT_http_responseHeaderCallback_null_context),
        cmocka_unit_test(test_SCEP_CLIENT_http_responseHeaderCallback_continue_flag),
        cmocka_unit_test(test_SCEP_CLIENT_http_responseBodyCallback_zero_length),
        cmocka_unit_test(test_SCEP_CLIENT_http_responseBodyCallback_null_data),
        cmocka_unit_test(test_SCEP_CLIENT_multiple_contexts),
        cmocka_unit_test(test_SCEP_CLIENT_getStatus_valid_context),
        cmocka_unit_test(test_SCEP_CLIENT_isDoneReceivingResponse_valid_context),
        cmocka_unit_test(test_SCEP_CLIENT_getHTTPStatusCode_null_context),
        cmocka_unit_test(test_SCEP_CLIENT_getHTTPStatusCode_valid_context),
        cmocka_unit_test(test_SCEP_CLIENT_getMessageType_null_params),
        cmocka_unit_test(test_SCEP_CLIENT_getMessageType_valid_context),
        cmocka_unit_test(test_SCEP_CLIENT_getFailInfo_null_params),
        cmocka_unit_test(test_SCEP_CLIENT_getFailInfo_valid_context),
        cmocka_unit_test(test_SCEP_CLIENT_workflow_sequence),
        cmocka_unit_test(test_SCEP_CLIENT_context_reuse),
    };

    int result = cmocka_run_group_tests(tests, testSetup, testTeardown);

    return result;
}
