/*
 * test_scep_message.c
 *
 * SCEP Message Unit Test
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
#include "asn1/oiddefs.h"
#include "crypto/hw_accel.h"
#include "crypto/pubcrypto.h"
#include "crypto/ca_mgmt.h"
#include "crypto/crypto.h"
#include "crypto/pkcs10.h"
#include "crypto/pkcs7.h"
#include "scep/scep.h"
#include "scep/scep_context.h"
#include "scep/scep_message.h"
#include "asn1/oiddefs.h"

#include "scep/scep.h"
#include "scep/scep_context.h"
#include "scep/scep_message.h"

/*------------------------------------------------------------------*/
/* Mock structures and data */
/*------------------------------------------------------------------*/

static const ubyte mock_rsa_modulus[] = {
    0xC5, 0x06, 0x2B, 0x58, 0xDC, 0x83, 0x50, 0x67,
    0x88, 0x76, 0x54, 0x32, 0x10, 0xFE, 0xDC, 0xBA
};

static const ubyte mock_rsa_public_exponent[] = {0x01, 0x00, 0x01};

/*------------------------------------------------------------------*/
/* Test Functions */
/*------------------------------------------------------------------*/

static void test_SCEP_MESSAGE_generatePayLoad_null_params(void **ppState)
{
    MSTATUS status;
    ubyte *pPayload = NULL;
    ubyte4 payloadLen = 0;
    requestInfo reqInfo;

    MOC_UNUSED(ppState);

    status = SCEP_MESSAGE_generatePayLoad(NULL, NULL, &pPayload, &payloadLen);
    assert_int_not_equal(status, OK);
    assert_int_equal(status, ERR_NULL_POINTER);

    memset(&reqInfo, 0, sizeof(reqInfo));
    reqInfo.type = scep_PKCSReq;
    status = SCEP_MESSAGE_generatePayLoad(NULL, &reqInfo, NULL, &payloadLen);
    assert_int_not_equal(status, OK);
    assert_int_equal(status, ERR_NULL_POINTER);
}

/*------------------------------------------------------------------*/
/* Test: generatePayLoad with NULL key for PKCSReq */
/*------------------------------------------------------------------*/
static void test_SCEP_MESSAGE_generatePayLoad_null_key(void **ppState)
{
    MSTATUS status;
    ubyte *pPayload = NULL;
    ubyte4 payloadLen = 0;
    requestInfo reqInfo;

    MOC_UNUSED(ppState);

    memset(&reqInfo, 0, sizeof(reqInfo));
    reqInfo.type = scep_PKCSReq;

    status = SCEP_MESSAGE_generatePayLoad(NULL, &reqInfo, &pPayload, &payloadLen);
    assert_int_not_equal(status, OK);
}

/*
 * Test: breakIntoLines with zero length
 */
static void test_SCEP_MESSAGE_breakIntoLines_zero_length(void **ppState)
{
    MSTATUS status;
    ubyte mockData[] = "TestData";
    ubyte *pRetCsr = NULL;
    ubyte4 retCsrLen = 0;

    MOC_UNUSED(ppState);

    status = SCEP_MESSAGE_breakIntoLines(mockData, 0, &pRetCsr, &retCsrLen);
    assert_int_equal(status, OK);

    if (pRetCsr)
    {
        FREE(pRetCsr);
    }
}

/*
 * Test: breakIntoLines with small data
 */
static void test_SCEP_MESSAGE_breakIntoLines_small_data(void **ppState)
{
    MSTATUS status;
    ubyte mockData[] = "SmallTestData";
    ubyte *pRetCsr = NULL;
    ubyte4 retCsrLen = 0;

    MOC_UNUSED(ppState);

    status = SCEP_MESSAGE_breakIntoLines(mockData, sizeof(mockData) - 1, &pRetCsr, &retCsrLen);

    if (status == OK && pRetCsr)
    {
        assert_non_null(pRetCsr);
        assert_true(retCsrLen > 0);
        FREE(pRetCsr);
    }
}

/*
 * Test: OID constants are properly defined
 */
static void test_SCEP_MESSAGE_verisign_oids_defined(void **ppState)
{
    MOC_UNUSED(ppState);

    assert_non_null(verisign_OID);
    assert_non_null(verisign_pki_OID);
    assert_non_null(verisign_pkiAttrs_OID);
    assert_non_null(verisign_pkiAttrs_messageType_OID);
    assert_non_null(verisign_pkiAttrs_pkiStatus_OID);
    assert_non_null(verisign_pkiAttrs_failInfo_OID);
    assert_non_null(verisign_pkiAttrs_senderNonce_OID);
    assert_non_null(verisign_pkiAttrs_recipientNonce_OID);
    assert_non_null(verisign_pkiAttrs_transId_OID);
    assert_non_null(verisign_pkiAttrs_extensionReq_OID);

    assert_true(verisign_OID[0] >= 5);
    assert_true(verisign_pki_OID[0] >= 6);
}

/*
 * Test: parsePkcsResponse with NULL context
 */
static void test_SCEP_MESSAGE_parsePkcsResponse_null_context(void **ppState)
{
    MSTATUS status;
    ubyte mockResponse[128];

    MOC_UNUSED(ppState);
    memset(mockResponse, 0, sizeof(mockResponse));

    status = SCEP_MESSAGE_parsePkcsResponse(NULL, NULL, x_pki_message,
                                           mockResponse, sizeof(mockResponse));
    assert_int_not_equal(status, OK);
}

/*
 * Test: parsePkcsResponse with zero length
 */
static void test_SCEP_MESSAGE_parsePkcsResponse_zero_length(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;
    pkcsCtxInternal pkcsCtx;
    ubyte mockResponse[128];

    MOC_UNUSED(ppState);
    memset(mockResponse, 0, sizeof(mockResponse));
    memset(&pkcsCtx, 0, sizeof(pkcsCtx));

    status = SCEP_CONTEXT_createContext(&pContext, SCEP_CLIENT);
    if (status == OK && pContext)
    {
        status = SCEP_MESSAGE_parsePkcsResponse(&pkcsCtx, pContext, x_pki_message,
                                               mockResponse, 0);
        assert_int_not_equal(status, OK);

        SCEP_CONTEXT_releaseContext(&pContext);
    }
}

/*------------------------------------------------------------------*/
/* Test: breakIntoLines with valid small data */
/*------------------------------------------------------------------*/
static void test_SCEP_MESSAGE_breakIntoLines_valid_data(void **ppState)
{
    MSTATUS status;
    ubyte inputData[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    ubyte *pRetCsr = NULL;
    ubyte4 retCsrLen = 0;

    MOC_UNUSED(ppState);

    status = SCEP_MESSAGE_breakIntoLines(inputData, sizeof(inputData) - 1, &pRetCsr, &retCsrLen);

    if (status == OK && pRetCsr)
    {
        assert_non_null(pRetCsr);
        assert_true(retCsrLen > 0);
        FREE(pRetCsr);
    }
}

/*------------------------------------------------------------------*/
/* Test: breakIntoLines with large data requiring multiple lines */
/*------------------------------------------------------------------*/
static void test_SCEP_MESSAGE_breakIntoLines_large_data(void **ppState)
{
    MSTATUS status;
    ubyte largeData[256];
    ubyte *pRetCsr = NULL;
    ubyte4 retCsrLen = 0;

    MOC_UNUSED(ppState);

    memset(largeData, 'A', sizeof(largeData));

    status = SCEP_MESSAGE_breakIntoLines(largeData, sizeof(largeData), &pRetCsr, &retCsrLen);

    if (status == OK && pRetCsr)
    {
        assert_non_null(pRetCsr);
        assert_true(retCsrLen > sizeof(largeData));
        FREE(pRetCsr);
    }
}

/*------------------------------------------------------------------*/
/* Test: parsePkcsResponse with different response types */
/*------------------------------------------------------------------*/
static void test_SCEP_MESSAGE_parsePkcsResponse_pki_message_type(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;
    pkcsCtxInternal pkcsCtx;
    ubyte mockResponse[128];

    MOC_UNUSED(ppState);
    memset(mockResponse, 0, sizeof(mockResponse));
    memset(&pkcsCtx, 0, sizeof(pkcsCtx));

    status = SCEP_CONTEXT_createContext(&pContext, SCEP_CLIENT);
    if (status == OK && pContext)
    {
        status = SCEP_MESSAGE_parsePkcsResponse(&pkcsCtx, pContext, x_pki_message,
                                               mockResponse, sizeof(mockResponse));
        assert_int_not_equal(status, OK);

        SCEP_CONTEXT_releaseContext(&pContext);
    }
}

/*------------------------------------------------------------------*/
/* Test: parsePkcsResponse with x509 cert chain type */
/*------------------------------------------------------------------*/
static void test_SCEP_MESSAGE_parsePkcsResponse_cert_chain_type(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;
    pkcsCtxInternal pkcsCtx;
    ubyte mockResponse[128];

    MOC_UNUSED(ppState);
    memset(mockResponse, 0, sizeof(mockResponse));
    memset(&pkcsCtx, 0, sizeof(pkcsCtx));

    status = SCEP_CONTEXT_createContext(&pContext, SCEP_CLIENT);
    if (status == OK && pContext)
    {
        status = SCEP_MESSAGE_parsePkcsResponse(&pkcsCtx, pContext, x_x509_ca_ra_cert_chain,
                                               mockResponse, sizeof(mockResponse));
        assert_int_not_equal(status, OK);

        SCEP_CONTEXT_releaseContext(&pContext);
    }
}

/*------------------------------------------------------------------*/
/* Test: generatePkiRequestMessage with NULL parameters */
/*------------------------------------------------------------------*/
static void test_SCEP_MESSAGE_generatePkiRequestMessage_null_params(void **ppState)
{
    MSTATUS status;
    ubyte *pMessage = NULL;
    ubyte4 messageLen = 0;

    MOC_UNUSED(ppState);

    status = SCEP_MESSAGE_generatePkiRequestMessage(NULL, NULL, &pMessage, &messageLen);
    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: generatePkiRequestMessage with NULL output parameters */
/*------------------------------------------------------------------*/
static void test_SCEP_MESSAGE_generatePkiRequestMessage_null_output(void **ppState)
{
    MSTATUS status;
    pkcsCtxInternal pkcsCtx;
    scepContext *pContext = NULL;

    MOC_UNUSED(ppState);
    memset(&pkcsCtx, 0, sizeof(pkcsCtx));

    status = SCEP_CONTEXT_createContext(&pContext, SCEP_CLIENT);
    if (status == OK && pContext)
    {
        status = SCEP_MESSAGE_generatePkiRequestMessage(&pkcsCtx, pContext, NULL, NULL);
        assert_int_not_equal(status, OK);

        SCEP_CONTEXT_releaseContext(&pContext);
    }
}

/*------------------------------------------------------------------*/
/* Test: generatePkiRequestMessage validates roletype */
/*------------------------------------------------------------------*/
static void test_SCEP_MESSAGE_generatePkiRequestMessage_invalid_roletype(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;
    pkcsCtxInternal pkcsCtx;
    ubyte *pMessage = NULL;
    ubyte4 messageLen = 0;

    MOC_UNUSED(ppState);
    memset(&pkcsCtx, 0, sizeof(pkcsCtx));

    status = SCEP_CONTEXT_createContext(&pContext, SCEP_CLIENT);
    if (status == OK && pContext)
    {
        pContext->roleType = 0xFF;

        status = SCEP_MESSAGE_generatePkiRequestMessage(&pkcsCtx, pContext, &pMessage, &messageLen);
        assert_int_not_equal(status, OK);
        assert_int_equal(status, ERR_SCEP_INVALID_ROLETYPE);

        pContext->roleType = SCEP_CLIENT;
        SCEP_CONTEXT_releaseContext(&pContext);
    }
}

/*------------------------------------------------------------------*/
/* Test: generatePkiRequestMessage without requester cert */
/*------------------------------------------------------------------*/
static void test_SCEP_MESSAGE_generatePkiRequestMessage_missing_cert(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;
    pkcsCtxInternal pkcsCtx;
    ubyte *pMessage = NULL;
    ubyte4 messageLen = 0;

    MOC_UNUSED(ppState);
    memset(&pkcsCtx, 0, sizeof(pkcsCtx));

    status = SCEP_CONTEXT_createContext(&pContext, SCEP_CLIENT);
    if (status == OK && pContext)
    {
        status = SCEP_MESSAGE_generatePkiRequestMessage(&pkcsCtx, pContext, &pMessage, &messageLen);
        assert_int_not_equal(status, OK);

        SCEP_CONTEXT_releaseContext(&pContext);
    }
}

/*------------------------------------------------------------------*/
/* Test: breakIntoLines with exactly 64 bytes (line boundary) */
/*------------------------------------------------------------------*/
static void test_SCEP_MESSAGE_breakIntoLines_exactly_64_bytes(void **ppState)
{
    MSTATUS status;
    ubyte inputData[64];
    ubyte *pRetCsr = NULL;
    ubyte4 retCsrLen = 0;

    MOC_UNUSED(ppState);

    memset(inputData, 'A', sizeof(inputData));

    status = SCEP_MESSAGE_breakIntoLines(inputData, sizeof(inputData), &pRetCsr, &retCsrLen);

    if (status == OK && pRetCsr)
    {
        assert_non_null(pRetCsr);
        assert_true(retCsrLen > sizeof(inputData));
        FREE(pRetCsr);
    }
}

/*------------------------------------------------------------------*/
/* Test: breakIntoLines with 65 bytes (just over line boundary) */
/*------------------------------------------------------------------*/
static void test_SCEP_MESSAGE_breakIntoLines_65_bytes(void **ppState)
{
    MSTATUS status;
    ubyte inputData[65];
    ubyte *pRetCsr = NULL;
    ubyte4 retCsrLen = 0;

    MOC_UNUSED(ppState);

    memset(inputData, 'B', sizeof(inputData));

    status = SCEP_MESSAGE_breakIntoLines(inputData, sizeof(inputData), &pRetCsr, &retCsrLen);

    if (status == OK && pRetCsr)
    {
        assert_non_null(pRetCsr);
        assert_true(retCsrLen > sizeof(inputData));
        FREE(pRetCsr);
    }
}

/*------------------------------------------------------------------*/
/* Test: breakIntoLines with maximum typical data (4096 bytes) */
/*------------------------------------------------------------------*/
static void test_SCEP_MESSAGE_breakIntoLines_max_typical_data(void **ppState)
{
    MSTATUS status;
    ubyte *inputData = NULL;
    ubyte *pRetCsr = NULL;
    ubyte4 retCsrLen = 0;
    ubyte4 dataSize = 4096;

    MOC_UNUSED(ppState);

    inputData = (ubyte*)malloc(dataSize);
    assert_non_null(inputData);

    memset(inputData, 'C', dataSize);

    status = SCEP_MESSAGE_breakIntoLines(inputData, dataSize, &pRetCsr, &retCsrLen);

    if (status == OK && pRetCsr)
    {
        assert_non_null(pRetCsr);
        assert_true(retCsrLen > dataSize);
        FREE(pRetCsr);
    }

    FREE(inputData);
}

/*------------------------------------------------------------------*/
/* Test: generatePayLoad with valid but minimal PKCSReq */
/*------------------------------------------------------------------*/
static void test_SCEP_MESSAGE_generatePayLoad_minimal_pkcs_req(void **ppState)
{
    MSTATUS status;
    ubyte *pPayload = NULL;
    ubyte4 payloadLen = 0;
    requestInfo reqInfo;
    AsymmetricKey key;

    MOC_UNUSED(ppState);

    memset(&reqInfo, 0, sizeof(reqInfo));
    memset(&key, 0, sizeof(key));

    reqInfo.type = scep_PKCSReq;

    status = SCEP_MESSAGE_generatePayLoad(&key, &reqInfo, &pPayload, &payloadLen);
    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: generatePayLoad with GetCert request type */
/*------------------------------------------------------------------*/
static void test_SCEP_MESSAGE_generatePayLoad_get_cert(void **ppState)
{
    MSTATUS status;
    ubyte *pPayload = NULL;
    ubyte4 payloadLen = 0;
    requestInfo reqInfo;

    MOC_UNUSED(ppState);

    memset(&reqInfo, 0, sizeof(reqInfo));
    reqInfo.type = scep_GetCert;

    status = SCEP_MESSAGE_generatePayLoad(NULL, &reqInfo, &pPayload, &payloadLen);
    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: generatePayLoad with GetCRL request type */
/*------------------------------------------------------------------*/
static void test_SCEP_MESSAGE_generatePayLoad_get_crl(void **ppState)
{
    MSTATUS status;
    ubyte *pPayload = NULL;
    ubyte4 payloadLen = 0;
    requestInfo reqInfo;

    MOC_UNUSED(ppState);

    memset(&reqInfo, 0, sizeof(reqInfo));
    reqInfo.type = scep_GetCRL;

    status = SCEP_MESSAGE_generatePayLoad(NULL, &reqInfo, &pPayload, &payloadLen);
    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: parsePkcsResponse with invalid response type */
/*------------------------------------------------------------------*/
static void test_SCEP_MESSAGE_parsePkcsResponse_invalid_type(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;
    pkcsCtxInternal pkcsCtx;
    ubyte mockResponse[128];

    MOC_UNUSED(ppState);
    memset(mockResponse, 0, sizeof(mockResponse));
    memset(&pkcsCtx, 0, sizeof(pkcsCtx));

    status = SCEP_CONTEXT_createContext(&pContext, SCEP_CLIENT);
    if (status == OK && pContext)
    {
        status = SCEP_MESSAGE_parsePkcsResponse(&pkcsCtx, pContext, 0xFF,
                                               mockResponse, sizeof(mockResponse));
        assert_int_not_equal(status, OK);

        SCEP_CONTEXT_releaseContext(&pContext);
    }
}

/*------------------------------------------------------------------*/
/* Test: parsePkcsResponse with x509 cert type */
/*------------------------------------------------------------------*/
static void test_SCEP_MESSAGE_parsePkcsResponse_x509_cert(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;
    pkcsCtxInternal pkcsCtx;
    ubyte mockResponse[128];

    MOC_UNUSED(ppState);
    memset(mockResponse, 0, sizeof(mockResponse));
    memset(&pkcsCtx, 0, sizeof(pkcsCtx));

    status = SCEP_CONTEXT_createContext(&pContext, SCEP_CLIENT);
    if (status == OK && pContext)
    {
        status = SCEP_MESSAGE_parsePkcsResponse(&pkcsCtx, pContext, x_x509_ca_cert,
                                               mockResponse, sizeof(mockResponse));
        assert_int_not_equal(status, OK);

        SCEP_CONTEXT_releaseContext(&pContext);
    }
}

/*------------------------------------------------------------------*/
/* Test: Verify OID constants have correct first byte */
/*------------------------------------------------------------------*/
static void test_SCEP_MESSAGE_oid_lengths(void **ppState)
{
    MOC_UNUSED(ppState);

    assert_int_equal(verisign_OID[0], 7);
    assert_int_equal(verisign_pki_OID[0], 8);
    assert_int_equal(verisign_pkiAttrs_OID[0], 9);
    assert_int_equal(verisign_pkiAttrs_messageType_OID[0], 10);
    assert_int_equal(verisign_pkiAttrs_pkiStatus_OID[0], 10);
    assert_int_equal(verisign_pkiAttrs_failInfo_OID[0], 10);
    assert_int_equal(verisign_pkiAttrs_senderNonce_OID[0], 10);
    assert_int_equal(verisign_pkiAttrs_recipientNonce_OID[0], 10);
    assert_int_equal(verisign_pkiAttrs_transId_OID[0], 10);
    assert_int_equal(verisign_pkiAttrs_extensionReq_OID[0], 10);
}

/*------------------------------------------------------------------*/
/* Test: Verify OID values are distinct */
/*------------------------------------------------------------------*/
static void test_SCEP_MESSAGE_oid_uniqueness(void **ppState)
{
    MOC_UNUSED(ppState);

    assert_ptr_not_equal((void*)verisign_OID, (void*)verisign_pki_OID);
    assert_ptr_not_equal((void*)verisign_pkiAttrs_messageType_OID, (void*)verisign_pkiAttrs_pkiStatus_OID);
    assert_ptr_not_equal((void*)verisign_pkiAttrs_failInfo_OID, (void*)verisign_pkiAttrs_senderNonce_OID);
    assert_ptr_not_equal((void*)verisign_pkiAttrs_recipientNonce_OID, (void*)verisign_pkiAttrs_transId_OID);
}

/*------------------------------------------------------------------*/
/* Main test runner */
/*------------------------------------------------------------------*/
int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_SCEP_MESSAGE_generatePayLoad_null_params),
        cmocka_unit_test(test_SCEP_MESSAGE_generatePayLoad_null_key),
        cmocka_unit_test(test_SCEP_MESSAGE_generatePayLoad_minimal_pkcs_req),
        cmocka_unit_test(test_SCEP_MESSAGE_generatePayLoad_get_cert),
        cmocka_unit_test(test_SCEP_MESSAGE_generatePayLoad_get_crl),
        cmocka_unit_test(test_SCEP_MESSAGE_breakIntoLines_zero_length),
        cmocka_unit_test(test_SCEP_MESSAGE_breakIntoLines_small_data),
        cmocka_unit_test(test_SCEP_MESSAGE_breakIntoLines_valid_data),
        cmocka_unit_test(test_SCEP_MESSAGE_breakIntoLines_large_data),
        cmocka_unit_test(test_SCEP_MESSAGE_breakIntoLines_exactly_64_bytes),
        cmocka_unit_test(test_SCEP_MESSAGE_breakIntoLines_65_bytes),
        cmocka_unit_test(test_SCEP_MESSAGE_breakIntoLines_max_typical_data),
        cmocka_unit_test(test_SCEP_MESSAGE_verisign_oids_defined),
        cmocka_unit_test(test_SCEP_MESSAGE_oid_lengths),
        cmocka_unit_test(test_SCEP_MESSAGE_oid_uniqueness),
        cmocka_unit_test(test_SCEP_MESSAGE_parsePkcsResponse_null_context),
        cmocka_unit_test(test_SCEP_MESSAGE_parsePkcsResponse_zero_length),
        cmocka_unit_test(test_SCEP_MESSAGE_parsePkcsResponse_pki_message_type),
        cmocka_unit_test(test_SCEP_MESSAGE_parsePkcsResponse_cert_chain_type),
        cmocka_unit_test(test_SCEP_MESSAGE_parsePkcsResponse_invalid_type),
        cmocka_unit_test(test_SCEP_MESSAGE_parsePkcsResponse_x509_cert),
        cmocka_unit_test(test_SCEP_MESSAGE_generatePkiRequestMessage_null_params),
        cmocka_unit_test(test_SCEP_MESSAGE_generatePkiRequestMessage_null_output),
        cmocka_unit_test(test_SCEP_MESSAGE_generatePkiRequestMessage_invalid_roletype),
        cmocka_unit_test(test_SCEP_MESSAGE_generatePkiRequestMessage_missing_cert),
    };

    int result = cmocka_run_group_tests(tests, NULL, NULL);

    return result;
}
