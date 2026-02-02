/**
 * sshc_trans_test.c
 *
 * SSH Client Transport Layer Unit Tests
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
#include "../../crypto/hw_accel.h"

#define __ENABLE_INBOUND_SSH_DEFINITIONS__

#include "../../common/mdefs.h"
#include "../../common/merrors.h"
#include "../../crypto/secmod.h"
#include "../../common/mrtos.h"
#include "../../common/mtcp.h"
#include "../../common/mstdlib.h"
#include "../../common/random.h"
#include "../../common/vlong.h"
#include "../../common/mem_pool.h"
#include "../../common/absstream.h"
#include "../../common/tree.h"
#include "../../common/memfile.h"
#include "../../common/circ_buf.h"
#include "../../crypto/crypto.h"
#include "../../ssh/ssh_defs.h"
#include "../../ssh/ssh_str.h"
#include "../../ssh/client/sshc.h"
#include "../../ssh/client/sshc_context.h"
#include "../../ssh/client/sshc_auth.h"
#include "../../ssh/client/sshc_in_mesg.h"
#include "../../ssh/client/sshc_out_mesg.h"
#include "../../ssh/client/sshc_client.h"
#include "../../ssh/client/sshc_session.h"
#include "../../ssh/client/sshc_trans.h"
#include "../../ssh/client/sshc_str_house.h"
#include "../../harness/harness.h"

/*------------------------------------------------------------------*/
/* Test Helper Functions */
/*------------------------------------------------------------------*/

static sshClientContext* createTestContext(void)
{
    sshClientContext* pContext = NULL;
    MSTATUS status;

    status = SSHC_CONTEXT_allocStructures(&pContext);
    if (OK != status || NULL == pContext)
        return NULL;

    return pContext;
}

static void destroyTestContext(sshClientContext** ppContext)
{
    if (ppContext && *ppContext)
    {
       SSHC_CONTEXT_deallocStructures(ppContext);
    }
}

/*------------------------------------------------------------------*/
/* Tests for Algorithm Verification Functions */
/*------------------------------------------------------------------*/

static void test_SSHC_TRANS_cipherVerify_null_params(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;
    intBoolean isAvailable;
    ubyte testCipher[] = "aes128-ctr";

    /* Test with null cipher */
    status = SSHC_TRANS_cipherVerify(NULL, &isAvailable);
    assert_int_equal(ERR_NULL_POINTER, status);

    /* Test with null availability pointer */
    status = SSHC_TRANS_cipherVerify(testCipher, NULL);
    assert_int_equal(ERR_NULL_POINTER, status);

    /* Test with both null */
    status = SSHC_TRANS_cipherVerify(NULL, NULL);
    assert_int_equal(ERR_NULL_POINTER, status);
}

static void test_SSHC_TRANS_cipherVerify_known_ciphers(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;
    intBoolean isAvailable;

    ubyte aes128[] = "aes128-ctr";
    status = SSHC_TRANS_cipherVerify(aes128, &isAvailable);
    assert_int_equal(OK, status);
#ifndef __DISABLE_AES_CIPHERS__
#ifndef __DISABLE_AES128_CIPHER__
    assert_true(isAvailable);
#else
    assert_false(isAvailable);
#endif
#endif
    /* Test unknown cipher */
    ubyte unknown[] = "unknown-cipher-xyz";
    status = SSHC_TRANS_cipherVerify(unknown, &isAvailable);
    assert_int_equal(OK, status);
    assert_false(isAvailable);
}

static void test_SSHC_TRANS_hmacVerify_null_params(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;
    intBoolean isAvailable;
    ubyte testHmac[] = "hmac-sha2-256";

    /* Test with null hmac */
    status = SSHC_TRANS_hmacVerify(NULL, &isAvailable);
    assert_int_equal(ERR_NULL_POINTER, status);

    /* Test with null availability pointer */
    status = SSHC_TRANS_hmacVerify(testHmac, NULL);
    assert_int_equal(ERR_NULL_POINTER, status);

    /* Test with both null */
    status = SSHC_TRANS_hmacVerify(NULL, NULL);
    assert_int_equal(ERR_NULL_POINTER, status);
}

static void test_SSHC_TRANS_hmacVerify_known_hmacs(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;
    intBoolean isAvailable;

    /* Test HMAC-SHA2-256 */
    ubyte hmacSha256[] = "hmac-sha2-256";
    status = SSHC_TRANS_hmacVerify(hmacSha256, &isAvailable);
    assert_int_equal(OK, status);
#ifndef __DISABLE_DIGICERT_SHA256__
    assert_true(isAvailable);
#else
    assert_false(isAvailable);
#endif

    /* Test unknown HMAC */
    ubyte unknown[] = "unknown-hmac-xyz";
    status = SSHC_TRANS_hmacVerify(unknown, &isAvailable);
    assert_int_equal(OK, status);
    assert_false(isAvailable);
}

/*------------------------------------------------------------------*/
/* Tests for SSHC_TRANS_sendHello */
/*------------------------------------------------------------------*/

static void test_SSHC_TRANS_sendHello_invalid_socket(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Set invalid socket */
    SOCKET(pContext) = -1;

    /* Test send hello with invalid socket */
    status = SSHC_TRANS_sendHello(pContext);
    assert_int_equal(ERR_TCP_WRITE_ERROR, status);

    /* Cleanup */
    destroyTestContext(&pContext);
}

/*------------------------------------------------------------------*/
/* Tests for SSHC_TRANS_setMessageTimer */
/*------------------------------------------------------------------*/

static void test_SSHC_TRANS_setMessageTimer_null_context(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;

    /* Test with null context */
    status = SSHC_TRANS_setMessageTimer(NULL, 5000);
    assert_int_equal(ERR_NULL_POINTER, status);
}

static void test_SSHC_TRANS_setMessageTimer_success(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Test successful timer setting */
    status = SSHC_TRANS_setMessageTimer(pContext, 5000);
    assert_int_equal(OK, status);

    /* Verify timer was set */
    assert_int_equal(5000, SSH_TIMER_MS_EXPIRE(pContext));

    /* Cleanup */
    destroyTestContext(&pContext);
}

static void test_SSHC_TRANS_setMessageTimer_zero_timeout(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Test with zero timeout */
    status = SSHC_TRANS_setMessageTimer(pContext, 0);
    assert_int_equal(OK, status);

    /* Verify timer was set */
    assert_int_equal(0, SSH_TIMER_MS_EXPIRE(pContext));

    /* Cleanup */
    destroyTestContext(&pContext);
}

/*------------------------------------------------------------------*/
/* Tests for SSHC_TRANS_versionExchange */
/*------------------------------------------------------------------*/

static void test_SSHC_TRANS_versionExchange_success(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Set invalid socket to prevent actual network I/O */
    SOCKET(pContext) = -1;

    /* Test version exchange */
    status = SSHC_TRANS_versionExchange(pContext);
    assert_int_equal(ERR_TCP_WRITE_ERROR, status);

    /* Verify client hello comment was set */
    assert_non_null(CLIENT_HELLO_COMMENT(pContext));
    assert_true(CLIENT_HELLO_COMMENT_LEN(pContext) > 0);

    /* Cleanup */
    destroyTestContext(&pContext);
}

/*------------------------------------------------------------------*/
/* Tests for SSHC_TRANS_doProtocol */
/*------------------------------------------------------------------*/

static void test_SSHC_TRANS_doProtocol_ignore_message(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;
    ubyte ignoreMessage[] = {SSH_MSG_IGNORE, 0x00, 0x00, 0x00, 0x00};

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Set initial state */
    SSH_UPPER_STATE(pContext) = kTransAlgorithmExchange;

    /* Test ignore message handling */
    status = SSHC_TRANS_doProtocol(pContext, ignoreMessage, sizeof(ignoreMessage));
    assert_int_equal(OK, status);

    /* State should remain unchanged */
    assert_int_equal(kTransAlgorithmExchange, SSH_UPPER_STATE(pContext));

    /* Cleanup */
    destroyTestContext(&pContext);
}

static void test_SSHC_TRANS_doProtocol_debug_message(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;
    ubyte debugMessage[] = {SSH_MSG_DEBUG, 0x00, 0x00, 0x00, 0x00, 0x00};

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Set initial state */
    SSH_UPPER_STATE(pContext) = kTransAlgorithmExchange;

    /* Test debug message handling */
    status = SSHC_TRANS_doProtocol(pContext, debugMessage, sizeof(debugMessage));
    assert_int_equal(OK, status);

    /* State should remain unchanged */
    assert_int_equal(kTransAlgorithmExchange, SSH_UPPER_STATE(pContext));

    /* Cleanup */
    destroyTestContext(&pContext);
}

static void test_SSHC_TRANS_doProtocol_disconnect_message(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;
    ubyte disconnectMessage[] = {SSH_MSG_DISCONNECT, 0x00, 0x00, 0x00, 0x02, 0x00};

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Set initial state */
    SSH_UPPER_STATE(pContext) = kTransAlgorithmExchange;

    /* Test disconnect message handling */
    status = SSHC_TRANS_doProtocol(pContext, disconnectMessage, sizeof(disconnectMessage));
    assert_int_equal(ERR_SSH_DISCONNECT_PROTOCOL_ERROR, status);

    /* Cleanup */
    destroyTestContext(&pContext);
}

static void test_SSHC_TRANS_doProtocol_invalid_state(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;
    ubyte testMessage[] = {SSH_MSG_KEXINIT, 0x00, 0x00, 0x00, 0x00};

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Set invalid state */
    SSH_UPPER_STATE(pContext) = 9999; /* Invalid state */

    /* Test with invalid state */
    status = SSHC_TRANS_doProtocol(pContext, testMessage, sizeof(testMessage));
    assert_int_equal(ERR_SSH_BAD_TRANS_RECEIVE_STATE, status);

    /* Cleanup */
    destroyTestContext(&pContext);
}

/*------------------------------------------------------------------*/
/* Tests for SSHC_TRANS_sendDisconnectMesg */
/*------------------------------------------------------------------*/

static void test_SSHC_TRANS_sendDisconnectMesg_valid_errors(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Set invalid socket to prevent actual network I/O */
    SOCKET(pContext) = -1;

    /* Test various disconnect error codes */
    SSHC_TRANS_sendDisconnectMesg(pContext, SSH_DISCONNECT_PROTOCOL_ERROR);
    SSHC_TRANS_sendDisconnectMesg(pContext, SSH_DISCONNECT_KEY_EXCHANGE_FAILED);
    SSHC_TRANS_sendDisconnectMesg(pContext, SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT);

    /* Cleanup */
    destroyTestContext(&pContext);
}

/*------------------------------------------------------------------*/
/* Tests for SSHC_TRANS_sendClientAlgorithms */
/*------------------------------------------------------------------*/

static void test_SSHC_TRANS_sendClientAlgorithms_success(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Set invalid socket to prevent actual network I/O */
    SOCKET(pContext) = -1;

    /* Test successful algorithm sending (will fail at TCP_WRITE but should build payload) */
    status = SSHC_TRANS_sendClientAlgorithms(pContext);
    assert_int_equal(ERR_TCP_WRITE_ERROR, status);

    /* Verify that client KEX init payload was saved */
    assert_non_null(CLIENT_KEX_INIT_PAYLOAD(pContext));
    assert_true(CLIENT_KEX_INIT_PAYLOAD_LEN(pContext) > 0);

    /* Verify payload starts with SSH_MSG_KEXINIT */
    assert_int_equal(SSH_MSG_KEXINIT, CLIENT_KEX_INIT_PAYLOAD(pContext)[0]);

    /* Cleanup */
    destroyTestContext(&pContext);
}

/*------------------------------------------------------------------*/
/* Tests for SSHC_TRANS_sendAlgorithms */
/*------------------------------------------------------------------*/

static void test_SSHC_TRANS_sendAlgorithms_success(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Set invalid socket to prevent actual network I/O */
    SOCKET(pContext) = -1;

    /* Test successful algorithm sending */
    status = SSHC_TRANS_sendAlgorithms(pContext);
    assert_int_equal(ERR_TCP_WRITE_ERROR, status);

    /* Verify client KEX init payload was saved */
    assert_non_null(CLIENT_KEX_INIT_PAYLOAD(pContext));
    assert_true(CLIENT_KEX_INIT_PAYLOAD_LEN(pContext) > 0);

    /* Cleanup */
    destroyTestContext(&pContext);
}

/*------------------------------------------------------------------*/
/* Test Setup and Teardown */
/*------------------------------------------------------------------*/

static int testSetup(void **ppState)
{
    MOC_UNUSED(ppState);
    MSTATUS status;

    status = SSHC_STR_HOUSE_initStringBuffers();
    if (OK != status)
        goto exit;

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

    status = SSHC_STR_HOUSE_freeStringBuffers();
    if (OK != status)
        goto exit;

    status = DIGICERT_freeDigicert();

exit:
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
        /* Algorithm verification tests */
        cmocka_unit_test(test_SSHC_TRANS_cipherVerify_null_params),
        cmocka_unit_test(test_SSHC_TRANS_cipherVerify_known_ciphers),
        cmocka_unit_test(test_SSHC_TRANS_hmacVerify_null_params),
        cmocka_unit_test(test_SSHC_TRANS_hmacVerify_known_hmacs),

        /* Protocol function tests */
        cmocka_unit_test(test_SSHC_TRANS_sendHello_invalid_socket),
        cmocka_unit_test(test_SSHC_TRANS_setMessageTimer_null_context),
        cmocka_unit_test(test_SSHC_TRANS_setMessageTimer_success),
        cmocka_unit_test(test_SSHC_TRANS_setMessageTimer_zero_timeout),
        cmocka_unit_test(test_SSHC_TRANS_versionExchange_success),

        /* Message handling tests */
        cmocka_unit_test(test_SSHC_TRANS_doProtocol_ignore_message),
        cmocka_unit_test(test_SSHC_TRANS_doProtocol_debug_message),
        cmocka_unit_test(test_SSHC_TRANS_doProtocol_disconnect_message),
        cmocka_unit_test(test_SSHC_TRANS_doProtocol_invalid_state),
        cmocka_unit_test(test_SSHC_TRANS_sendDisconnectMesg_valid_errors),

        /* Client algorithm sending tests */
        cmocka_unit_test(test_SSHC_TRANS_sendClientAlgorithms_success),

        /* General algorithm sending tests */
        cmocka_unit_test(test_SSHC_TRANS_sendAlgorithms_success)
    };

    return cmocka_run_group_tests(tests, testSetup, testTeardown);
#else
    return 0;
#endif
}

#endif /* __ENABLE_DIGICERT_SSH_CLIENT__ */