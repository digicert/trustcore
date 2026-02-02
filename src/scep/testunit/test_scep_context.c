/*
 * test_scep_context.c - Unit tests for SCEP context APIs
 *
 * Copyright 2026 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: contact DigiCert at sales@digicert.com.
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

/*------------------------------------------------------------------*/
/* Test: Create SCEP context */
/*------------------------------------------------------------------*/
static void test_SCEP_CONTEXT_createContext_valid(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;

    MOC_UNUSED(ppState);

    status = SCEP_CONTEXT_createContext(&pContext, SCEP_CLIENT);
    assert_int_equal(status, OK);
    assert_non_null(pContext);

    SCEP_CONTEXT_releaseContext(&pContext);
}

static void test_SCEP_CONTEXT_createContext_null_param(void **ppState)
{
    MSTATUS status;

    MOC_UNUSED(ppState);

    status = SCEP_CONTEXT_createContext(NULL, SCEP_CLIENT);
    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: Reset SCEP context */
/*------------------------------------------------------------------*/
static void test_SCEP_CONTEXT_resetContext_valid(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;

    MOC_UNUSED(ppState);

    status = SCEP_CONTEXT_createContext(&pContext, SCEP_CLIENT);
    assert_int_equal(status, OK);

    status = SCEP_CONTEXT_resetContext(pContext);
    assert_int_equal(status, OK);

    SCEP_CONTEXT_releaseContext(&pContext);
}

static void test_SCEP_CONTEXT_resetContext_null_param(void **ppState)
{
    MSTATUS status;

    MOC_UNUSED(ppState);

    status = SCEP_CONTEXT_resetContext(NULL);
    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: Release SCEP context */
/*------------------------------------------------------------------*/
static void test_SCEP_CONTEXT_releaseContext_valid(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;

    MOC_UNUSED(ppState);

    status = SCEP_CONTEXT_createContext(&pContext, SCEP_CLIENT);
    assert_int_equal(status, OK);

    status = SCEP_CONTEXT_releaseContext(&pContext);
    assert_int_equal(status, OK);
    assert_null(pContext);
}

static void test_SCEP_CONTEXT_releaseContext_null_param(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;

    MOC_UNUSED(ppState);

    status = SCEP_CONTEXT_releaseContext(&pContext);
    assert_int_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: Reset context extended */
/*------------------------------------------------------------------*/
static void test_SCEP_CONTEXT_resetContextEx_valid(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;

    MOC_UNUSED(ppState);

    status = SCEP_CONTEXT_createContext(&pContext, SCEP_CLIENT);
    assert_int_equal(status, OK);

    status = SCEP_CONTEXT_resetContextEx(pContext, FALSE);
    assert_int_equal(status, OK);

    status = SCEP_CONTEXT_resetContextEx(pContext, TRUE);
    assert_int_equal(status, OK);

    SCEP_CONTEXT_releaseContext(&pContext);
}

static void test_SCEP_CONTEXT_resetContextEx_null_param(void **ppState)
{
    MSTATUS status;

    MOC_UNUSED(ppState);

    status = SCEP_CONTEXT_resetContextEx(NULL, FALSE);
    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: Create context with invalid role type */
/*------------------------------------------------------------------*/
static void test_SCEP_CONTEXT_createContext_invalid_role(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;

    MOC_UNUSED(ppState);

    status = SCEP_CONTEXT_createContext(&pContext, 0xFF);
    assert_int_not_equal(status, OK);
    assert_int_equal(status, ERR_SCEP_INVALID_ROLETYPE);
    assert_null(pContext);
}

/*------------------------------------------------------------------*/
/* Test: Multiple context creation and release */
/*------------------------------------------------------------------*/
static void test_SCEP_CONTEXT_multiple_contexts(void **ppState)
{
    MSTATUS status;
    scepContext *pContext1 = NULL;
    scepContext *pContext2 = NULL;
    scepContext *pContext3 = NULL;

    MOC_UNUSED(ppState);

    status = SCEP_CONTEXT_createContext(&pContext1, SCEP_CLIENT);
    assert_int_equal(status, OK);
    assert_non_null(pContext1);

    status = SCEP_CONTEXT_createContext(&pContext2, SCEP_CLIENT);
    assert_int_equal(status, OK);
    assert_non_null(pContext2);

    status = SCEP_CONTEXT_createContext(&pContext3, SCEP_CLIENT);
    assert_int_equal(status, OK);
    assert_non_null(pContext3);

    assert_ptr_not_equal(pContext1, pContext2);
    assert_ptr_not_equal(pContext2, pContext3);
    assert_ptr_not_equal(pContext1, pContext3);

    SCEP_CONTEXT_releaseContext(&pContext1);
    assert_null(pContext1);

    SCEP_CONTEXT_releaseContext(&pContext2);
    assert_null(pContext2);

    SCEP_CONTEXT_releaseContext(&pContext3);
    assert_null(pContext3);
}

/*------------------------------------------------------------------*/
/* Test: Reset context after release should fail */
/*------------------------------------------------------------------*/
static void test_SCEP_CONTEXT_reset_after_release(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;

    MOC_UNUSED(ppState);

    status = SCEP_CONTEXT_createContext(&pContext, SCEP_CLIENT);
    assert_int_equal(status, OK);
    assert_non_null(pContext);

    SCEP_CONTEXT_releaseContext(&pContext);
    assert_null(pContext);

    status = SCEP_CONTEXT_resetContext(pContext);
    assert_int_not_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: Create, reset multiple times, then release */
/*------------------------------------------------------------------*/
static void test_SCEP_CONTEXT_multiple_reset(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;
    int i;

    MOC_UNUSED(ppState);

    status = SCEP_CONTEXT_createContext(&pContext, SCEP_CLIENT);
    assert_int_equal(status, OK);
    assert_non_null(pContext);

    for (i = 0; i < 5; i++)
    {
        status = SCEP_CONTEXT_resetContext(pContext);
        assert_int_equal(status, OK);
    }

    SCEP_CONTEXT_releaseContext(&pContext);
    assert_null(pContext);
}

/*------------------------------------------------------------------*/
/* Test: ResetContextEx with different flags */
/*------------------------------------------------------------------*/
static void test_SCEP_CONTEXT_resetContextEx_flags(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;

    MOC_UNUSED(ppState);

    status = SCEP_CONTEXT_createContext(&pContext, SCEP_CLIENT);
    assert_int_equal(status, OK);
    assert_non_null(pContext);

    status = SCEP_CONTEXT_resetContextEx(pContext, FALSE);
    assert_int_equal(status, OK);

    status = SCEP_CONTEXT_resetContextEx(pContext, TRUE);
    assert_int_equal(status, OK);

    status = SCEP_CONTEXT_resetContextEx(pContext, 0);
    assert_int_equal(status, OK);

    status = SCEP_CONTEXT_resetContextEx(pContext, 1);
    assert_int_equal(status, OK);

    SCEP_CONTEXT_releaseContext(&pContext);
    assert_null(pContext);
}

/*------------------------------------------------------------------*/
/* Test: Verify context structure after creation */
/*------------------------------------------------------------------*/
static void test_SCEP_CONTEXT_verify_context_structure(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;

    MOC_UNUSED(ppState);

    status = SCEP_CONTEXT_createContext(&pContext, SCEP_CLIENT);
    assert_int_equal(status, OK);
    assert_non_null(pContext);

    assert_int_equal(pContext->roleType, SCEP_CLIENT);
    assert_non_null(pContext->pPkcsCtx);
    assert_int_equal(pContext->receivedDataLength, 0);
    assert_int_equal(pContext->sendingDataLength, 0);
    assert_null(pContext->pReceivedData);
    assert_null(pContext->pSendingData);

    SCEP_CONTEXT_releaseContext(&pContext);
    assert_null(pContext);
}

/*------------------------------------------------------------------*/
/* Test: Reset context and verify it's reusable */
/*------------------------------------------------------------------*/
static void test_SCEP_CONTEXT_reset_reusability(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;
    void *originalPkcsCtx;

    MOC_UNUSED(ppState);

    status = SCEP_CONTEXT_createContext(&pContext, SCEP_CLIENT);
    assert_int_equal(status, OK);
    assert_non_null(pContext);

    originalPkcsCtx = pContext->pPkcsCtx;
    assert_non_null(originalPkcsCtx);

    status = SCEP_CONTEXT_resetContext(pContext);
    assert_int_equal(status, OK);

    assert_non_null(pContext->pPkcsCtx);
    assert_ptr_equal(pContext->pPkcsCtx, originalPkcsCtx);

    SCEP_CONTEXT_releaseContext(&pContext);
    assert_null(pContext);
}

/*------------------------------------------------------------------*/
/* Test: Double release should be safe */
/*------------------------------------------------------------------*/
static void test_SCEP_CONTEXT_double_release(void **ppState)
{
    MSTATUS status;
    scepContext *pContext = NULL;

    MOC_UNUSED(ppState);

    status = SCEP_CONTEXT_createContext(&pContext, SCEP_CLIENT);
    assert_int_equal(status, OK);
    assert_non_null(pContext);

    status = SCEP_CONTEXT_releaseContext(&pContext);
    assert_int_equal(status, OK);
    assert_null(pContext);

    status = SCEP_CONTEXT_releaseContext(&pContext);
    assert_int_equal(status, OK);
    assert_null(pContext);
}

/*------------------------------------------------------------------*/
/* Test: Release requestInfo with NULL should succeed */
/*------------------------------------------------------------------*/
static void test_SCEP_CONTEXT_releaseRequestInfo_null(void **ppState)
{
    MSTATUS status;

    MOC_UNUSED(ppState);

    status = SCEP_CONTEXT_releaseRequestInfo(NULL);
    assert_int_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: Release requestInfo with PKCSReq type */
/*------------------------------------------------------------------*/
static void test_SCEP_CONTEXT_releaseRequestInfo_pkcs_req(void **ppState)
{
    MSTATUS status;
    requestInfo *pReqInfo;
    certDistinguishedName *pDN;

    MOC_UNUSED(ppState);

    pReqInfo = (requestInfo*)malloc(sizeof(requestInfo));
    assert_non_null(pReqInfo);
    memset(pReqInfo, 0, sizeof(requestInfo));

    pDN = (certDistinguishedName*)malloc(sizeof(certDistinguishedName));
    assert_non_null(pDN);
    memset(pDN, 0, sizeof(certDistinguishedName));

    pReqInfo->type = scep_PKCSReq;
    pReqInfo->value.certInfoAndReqAttrs.pSubject = pDN;

    status = SCEP_CONTEXT_releaseRequestInfo(pReqInfo);
    assert_int_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Test: Release requestInfo with GetCACert type */
/*------------------------------------------------------------------*/
static void test_SCEP_CONTEXT_releaseRequestInfo_get_ca_cert(void **ppState)
{
    MSTATUS status;
    requestInfo *pReqInfo;
    sbyte *ident;

    MOC_UNUSED(ppState);

    pReqInfo = (requestInfo*)malloc(sizeof(requestInfo));
    assert_non_null(pReqInfo);
    memset(pReqInfo, 0, sizeof(requestInfo));

    ident = (sbyte*)malloc(10);
    assert_non_null(ident);
    memcpy(ident, "TestIdent", 10);

    pReqInfo->type = scep_GetCACert;
    pReqInfo->value.caIdent.ident = ident;
    pReqInfo->value.caIdent.identLen = 10;

    status = SCEP_CONTEXT_releaseRequestInfo(pReqInfo);
    assert_int_equal(status, OK);
}

/*------------------------------------------------------------------*/
/* Main test runner */
/*------------------------------------------------------------------*/
int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_SCEP_CONTEXT_createContext_valid),
        cmocka_unit_test(test_SCEP_CONTEXT_createContext_null_param),
        cmocka_unit_test(test_SCEP_CONTEXT_createContext_invalid_role),
        cmocka_unit_test(test_SCEP_CONTEXT_resetContext_valid),
        cmocka_unit_test(test_SCEP_CONTEXT_resetContext_null_param),
        cmocka_unit_test(test_SCEP_CONTEXT_releaseContext_valid),
        cmocka_unit_test(test_SCEP_CONTEXT_releaseContext_null_param),
        cmocka_unit_test(test_SCEP_CONTEXT_resetContextEx_valid),
        cmocka_unit_test(test_SCEP_CONTEXT_resetContextEx_null_param),
        cmocka_unit_test(test_SCEP_CONTEXT_multiple_contexts),
        cmocka_unit_test(test_SCEP_CONTEXT_reset_after_release),
        cmocka_unit_test(test_SCEP_CONTEXT_multiple_reset),
        cmocka_unit_test(test_SCEP_CONTEXT_resetContextEx_flags),
        cmocka_unit_test(test_SCEP_CONTEXT_verify_context_structure),
        cmocka_unit_test(test_SCEP_CONTEXT_reset_reusability),
        cmocka_unit_test(test_SCEP_CONTEXT_double_release),
        cmocka_unit_test(test_SCEP_CONTEXT_releaseRequestInfo_null),
        cmocka_unit_test(test_SCEP_CONTEXT_releaseRequestInfo_pkcs_req),
        cmocka_unit_test(test_SCEP_CONTEXT_releaseRequestInfo_get_ca_cert),
    };

    int result = cmocka_run_group_tests(tests, NULL, NULL);

    return result;
}
