/**
 * test_sshc_session.c
 *
 * SSH Client Session Handler Unit Tests
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
#include "../../common/random.h"
#include "../../common/vlong.h"
#include "../../common/mem_pool.h"
#include "../../crypto/hw_accel.h"
#include "../../crypto/pubcrypto.h"
#include "../../common/circ_buf.h"
#include "../../ssh/ssh_defs.h"
#include "../../ssh/ssh_str.h"
#include "../../ssh/client/sshc.h"
#include "../../ssh/client/sshc_context.h"
#include "../../ssh/client/sshc_str_house.h"
#include "../../ssh/client/sshc_client.h"
#include "../../ssh/client/sshc_session.h"
#include "../../ssh/client/sshc_in_mesg.h"
#include "../../ssh/client/sshc_out_mesg.h"
#include "../../ssh/client/sshc_trans.h"
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

    /* Initialize session state */
    pContext->sessionState.isChannelActive = FALSE;
    pContext->sessionState.isShellActive = FALSE;
    pContext->sessionState.channelState = SESSION_CLOSED;
    pContext->sessionState.clientChannel = 1;
    pContext->sessionState.recipientChannel = 2;
    pContext->sessionState.windowSize = MAX_SESSION_WINDOW_SIZE;
    pContext->sessionState.maxPacketSize = MAX_SESSION_WINDOW_SIZE;
    pContext->sessionState.isEof = FALSE;
    pContext->sessionState.rxdClosed = FALSE;
    pContext->sessionState.unAckRecvdData = 0;

    return pContext;
}

static void destroyTestContext(sshClientContext** ppContext)
{
    if (ppContext && *ppContext)
    {
        SSHC_CONTEXT_deallocStructures(ppContext);
    }
}

static sshcConnectDescr* createTestConnectDescr(void)
{
    sshcConnectDescr* pDescr = MALLOC(sizeof(sshcConnectDescr));
    if (NULL == pDescr)
        return NULL;

    DIGI_MEMSET((ubyte *)pDescr, 0, sizeof(sshcConnectDescr));
    pDescr->pContextSSH = createTestContext();
    if (NULL == pDescr->pContextSSH)
    {
        FREE(pDescr);
        return NULL;
    }

    return pDescr;
}

static void destroyTestConnectDescr(sshcConnectDescr** ppDescr)
{
    if (ppDescr && *ppDescr)
    {
        if ((*ppDescr)->pContextSSH)
            destroyTestContext(&((*ppDescr)->pContextSSH));
        FREE(*ppDescr);
        *ppDescr = NULL;
    }
}

/*------------------------------------------------------------------*/
/* Tests for SSHC_SESSION_sendMessage */
/*------------------------------------------------------------------*/

static void test_SSHC_SESSION_sendMessage_zero_length(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    ubyte testData[] = "test message";
    ubyte4 bytesSent = 0;
    MSTATUS status;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Set session active */
    pContext->sessionState.isShellActive = TRUE;
    pContext->sessionState.channelState = SESSION_OPEN;

    /* Test with zero length */
    status = SSHC_SESSION_sendMessage(pContext, testData, 0, &bytesSent);
    assert_int_equal(OK, status);
    assert_int_equal(0, bytesSent);

    /* Cleanup */
    destroyTestContext(&pContext);
}

static void test_SSHC_SESSION_sendMessage_session_not_open(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    ubyte testData[] = "test message";
    ubyte4 bytesSent = 0;
    MSTATUS status;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Keep session inactive */
    pContext->sessionState.isShellActive = FALSE;
    pContext->sessionState.channelState = SESSION_CLOSED;

    /* Test with inactive session */
    status = SSHC_SESSION_sendMessage(pContext, testData, sizeof(testData) - 1, &bytesSent);
    assert_int_equal(ERR_SESSION_NOT_OPEN, status);
    assert_int_equal(0, bytesSent);

    /* Cleanup */
    destroyTestContext(&pContext);
}

static void test_SSHC_SESSION_sendMessage_rekey_occurring(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    ubyte testData[] = "test message";
    ubyte4 bytesSent = 0;
    MSTATUS status;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Set session active but rekey occurring */
    pContext->sessionState.isShellActive = TRUE;
    pContext->sessionState.channelState = SESSION_OPEN;
    pContext->isReKeyOccuring = TRUE;

    /* Test with rekey occurring */
    status = SSHC_SESSION_sendMessage(pContext, testData, sizeof(testData) - 1, &bytesSent);
    assert_int_equal(OK, status);
    assert_int_equal(0, bytesSent);

    /* Cleanup */
    destroyTestContext(&pContext);
}

/*------------------------------------------------------------------*/
/* Tests for SSHC_SESSION_sendWindowAdjust */
/*------------------------------------------------------------------*/

static void test_SSHC_SESSION_sendWindowAdjust_invalid_socket(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Set invalid socket */
    SOCKET(pContext) = -1;

    /* Test window adjust with invalid socket */
    status = SSHC_SESSION_sendWindowAdjust(pContext, SSH_SESSION_DATA, 1024);
    assert_int_equal(ERR_TCP_WRITE_ERROR, status);

    /* Cleanup */
    destroyTestContext(&pContext);
}

/*------------------------------------------------------------------*/
/* Tests for SSHC_SESSION_receiveMessage */
/*------------------------------------------------------------------*/

static void test_SSHC_SESSION_receiveMessage_auth_message_ignored(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    ubyte authMessage[] = {60, 0x00, 0x00, 0x00, 0x01}; /* 60 is in auth range */
    MSTATUS status;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Test auth message is ignored */
    status = SSHC_SESSION_receiveMessage(pContext, authMessage, sizeof(authMessage));
    assert_int_equal(OK, status);

    /* Cleanup */
    destroyTestContext(&pContext);
}

static void test_SSHC_SESSION_receiveMessage_channel_open_confirmation(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    ubyte openConfirmMessage[] = {
        SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
        0x00, 0x00, 0x00, 0x01, /* client channel = 1 */
        0x00, 0x00, 0x00, 0x02, /* server channel = 2 */
        0x00, 0x00, 0x10, 0x00, /* window size = 4096 */
        0x00, 0x00, 0x08, 0x00  /* max packet size = 2048 */
    };
    MSTATUS status;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    assert_int_equal(pContext->sessionState.channelState, SESSION_CLOSED);
    assert_false(pContext->sessionState.isChannelActive);

    /* Test channel open confirmation */
    status = SSHC_SESSION_receiveMessage(pContext, openConfirmMessage, sizeof(openConfirmMessage));
    assert_int_equal(OK, status);

    /* Verify session state was updated */
    assert_true(pContext->sessionState.isChannelActive);
    assert_int_equal(SESSION_OPEN, pContext->sessionState.channelState);
    assert_int_equal(2, pContext->sessionState.recipientChannel);
    assert_int_equal(0x1000, pContext->sessionState.windowSize);

    /* Cleanup */
    destroyTestContext(&pContext);
}

static void test_SSHC_SESSION_receiveMessage_window_adjust(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    ubyte windowAdjustMessage[] = {
        SSH_MSG_CHANNEL_WINDOW_ADJUST,
        0x00, 0x00, 0x00, 0x01, /* channel = 1 */
        0x00, 0x00, 0x10, 0x00  /* bytes to add = 4096 */
    };
    MSTATUS status;
    ubyte4 initialWindowSize;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    initialWindowSize = pContext->sessionState.windowSize;
    pContext->sessionState.channelState = SESSION_OPEN;

    /* Test window adjust */
    status = SSHC_SESSION_receiveMessage(pContext, windowAdjustMessage, sizeof(windowAdjustMessage));
    assert_int_equal(OK, status);

    /* Verify window size was increased */
    assert_int_equal(initialWindowSize + 0x1000, pContext->sessionState.windowSize);

    /* Cleanup */
    destroyTestContext(&pContext);
}

static void test_SSHC_SESSION_receiveMessage_channel_close(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    ubyte channelCloseMessage[] = {
        SSH_MSG_CHANNEL_CLOSE,
        0x00, 0x00, 0x00, 0x01  /* channel = 1 */
    };
    MSTATUS status;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Set channel active */
    pContext->sessionState.isChannelActive = TRUE;

    /* Test channel close */
    status = SSHC_SESSION_receiveMessage(pContext, channelCloseMessage, sizeof(channelCloseMessage));
    assert_int_equal(OK, status);

    /* Verify session was closed */
    assert_false(pContext->sessionState.isChannelActive);
    assert_int_equal(SESSION_CLOSED, pContext->sessionState.channelState);
    assert_true(pContext->sessionState.rxdClosed);

    /* Cleanup */
    destroyTestContext(&pContext);
}

static void test_SSHC_SESSION_receiveMessage_channel_eof(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    ubyte channelEofMessage[] = {
        SSH_MSG_CHANNEL_EOF,
        0x00, 0x00, 0x00, 0x01  /* channel = 1 */
    };
    MSTATUS status;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Set channel active */
    pContext->sessionState.isChannelActive = TRUE;

    /* Test channel EOF */
    status = SSHC_SESSION_receiveMessage(pContext, channelEofMessage, sizeof(channelEofMessage));
    assert_int_equal(OK, status);

    /* Verify EOF was set */
    assert_true(pContext->sessionState.isEof);

    /* Cleanup */
    destroyTestContext(&pContext);
}

static void test_SSHC_SESSION_receiveMessage_unimplemented_default(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    ubyte unknownMessage[] = {255, 0x00, 0x00, 0x00, 0x01}; /* Unknown message type */
    MSTATUS status;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Set invalid socket to prevent actual network I/O */
    SOCKET(pContext) = -1;

    /* Test unknown message handling - should send SSH_MSG_UNIMPLEMENTED */
    status = SSHC_SESSION_receiveMessage(pContext, unknownMessage, sizeof(unknownMessage));
    assert_int_equal(ERR_TCP_WRITE_ERROR, status);

    /* Cleanup */
    destroyTestContext(&pContext);
}

static void test_SSHC_SESSION_receiveMessage_channel_data(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    ubyte channelDataMessage[] = {
        SSH_MSG_CHANNEL_DATA,
        0x00, 0x00, 0x00, 0x01, /* channel = 1 */
        0x00, 0x00, 0x00, 0x04, /* data length = 4 */
        't', 'e', 's', 't'      /* data */
    };
    MSTATUS status;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Set channel active and shell active */
    pContext->sessionState.isChannelActive = TRUE;
    pContext->sessionState.isShellActive = TRUE;

    /* Test channel data */
    status = SSHC_SESSION_receiveMessage(pContext, channelDataMessage, sizeof(channelDataMessage));
    assert_int_equal(OK, status);

    /* Verify unacknowledged data counter was updated */
    assert_int_equal(4, pContext->sessionState.unAckRecvdData);

    /* Cleanup */
    destroyTestContext(&pContext);
}

/*------------------------------------------------------------------*/
/* Tests for SSHC_SESSION_Close */
/*------------------------------------------------------------------*/

static void test_SSHC_SESSION_Close_valid_descr(void **ppState)
{
    MOC_UNUSED(ppState);

    sshcConnectDescr* pDescr = NULL;

    /* Create test descriptor */
    pDescr = createTestConnectDescr();
    assert_non_null(pDescr);

    /* Set session open */
    pDescr->pContextSSH->sessionState.channelState = SESSION_OPEN;

    /* Set invalid socket */
    SOCKET(pDescr->pContextSSH) = -1;

    /* Test close */
    SSHC_SESSION_Close(pDescr);

    /* Verify state is set to closed */
    assert_int_equal(SESSION_CLOSED, pDescr->pContextSSH->sessionState.channelState);

    /* Cleanup */
    destroyTestConnectDescr(&pDescr);
}

/*------------------------------------------------------------------*/
/* Tests for Channel Request Functions */
/*------------------------------------------------------------------*/

static void test_SSHC_SESSION_SendSubsystemSFTPChannelRequest_invalid_connection(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;

    /* Test with invalid connection instance */
    status = SSHC_SESSION_SendSubsystemSFTPChannelRequest(-1);
    assert_int_equal(ERR_SSH_BAD_ID, status);
}

static void test_SSHC_SESSION_sendPtyOpenRequest_invalid_connection(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;

    /* Test with invalid connection instance */
    status = SSHC_SESSION_sendPtyOpenRequest(-1);
    assert_int_equal(ERR_SSH_BAD_ID, status);
}

static void test_SSHC_SESSION_sendShellOpenRequest_invalid_connection(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;

    /* Test with invalid connection instance */
    status = SSHC_SESSION_sendShellOpenRequest(-1);
    assert_int_equal(ERR_SSH_BAD_ID, status);
}

/*------------------------------------------------------------------*/
/* Tests for Session Management Functions */
/*------------------------------------------------------------------*/

static void test_SSHC_SESSION_OpenSessionChannel_invalid_connection(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;

    /* Test with invalid connection instance */
    status = SSHC_SESSION_OpenSessionChannel(-1);
    assert_int_equal(ERR_SSH_BAD_ID, status);
}

static void test_SSHC_SESSION_CloseSessionChannel_invalid_connection(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;

    /* Test with invalid connection instance */
    status = SSHC_SESSION_CloseSessionChannel(-1);
    assert_int_equal(ERR_SSH_BAD_ID, status);
}

/*------------------------------------------------------------------*/
/* Integration Tests */
/*------------------------------------------------------------------*/

static void test_session_lifecycle_simulation(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    ubyte openConfirmMessage[] = {
        SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
        0x00, 0x00, 0x00, 0x01, /* client channel = 1 */
        0x00, 0x00, 0x00, 0x02, /* server channel = 2 */
        0x00, 0x00, 0x10, 0x00, /* window size = 4096 */
        0x00, 0x00, 0x08, 0x00  /* max packet size = 2048 */
    };
    ubyte channelCloseMessage[] = {
        SSH_MSG_CHANNEL_CLOSE,
        0x00, 0x00, 0x00, 0x01  /* channel = 1 */
    };
    MSTATUS status;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* 1. Simulate channel open confirmation */
    status = SSHC_SESSION_receiveMessage(pContext, openConfirmMessage, sizeof(openConfirmMessage));
    assert_int_equal(OK, status);
    assert_true(pContext->sessionState.isChannelActive);
    assert_int_equal(SESSION_OPEN, pContext->sessionState.channelState);

    /* 2. Simulate channel close */
    status = SSHC_SESSION_receiveMessage(pContext, channelCloseMessage, sizeof(channelCloseMessage));
    assert_int_equal(OK, status);
    assert_false(pContext->sessionState.isChannelActive);
    assert_int_equal(SESSION_CLOSED, pContext->sessionState.channelState);

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
        /* SSHC_SESSION_sendMessage tests */
        cmocka_unit_test(test_SSHC_SESSION_sendMessage_zero_length),
        cmocka_unit_test(test_SSHC_SESSION_sendMessage_session_not_open),
        cmocka_unit_test(test_SSHC_SESSION_sendMessage_rekey_occurring),

        /* SSHC_SESSION_sendWindowAdjust tests */
        cmocka_unit_test(test_SSHC_SESSION_sendWindowAdjust_invalid_socket),

        /* SSHC_SESSION_receiveMessage tests */
        cmocka_unit_test(test_SSHC_SESSION_receiveMessage_auth_message_ignored),
        cmocka_unit_test(test_SSHC_SESSION_receiveMessage_channel_open_confirmation),
        cmocka_unit_test(test_SSHC_SESSION_receiveMessage_window_adjust),
        cmocka_unit_test(test_SSHC_SESSION_receiveMessage_channel_close),
        cmocka_unit_test(test_SSHC_SESSION_receiveMessage_channel_eof),
        cmocka_unit_test(test_SSHC_SESSION_receiveMessage_unimplemented_default),
        cmocka_unit_test(test_SSHC_SESSION_receiveMessage_channel_data),

        /* SSHC_SESSION_Close tests */
        cmocka_unit_test(test_SSHC_SESSION_Close_valid_descr),

        /* Channel request function tests */
        cmocka_unit_test(test_SSHC_SESSION_SendSubsystemSFTPChannelRequest_invalid_connection),
        cmocka_unit_test(test_SSHC_SESSION_sendPtyOpenRequest_invalid_connection),
        cmocka_unit_test(test_SSHC_SESSION_sendShellOpenRequest_invalid_connection),

        /* Session management function tests */
        cmocka_unit_test(test_SSHC_SESSION_OpenSessionChannel_invalid_connection),
        cmocka_unit_test(test_SSHC_SESSION_CloseSessionChannel_invalid_connection),

        /* Integration tests */
        cmocka_unit_test(test_session_lifecycle_simulation),
    };

    return cmocka_run_group_tests(tests, testSetup, testTeardown);
#else
    return 0;
#endif
}

#endif /* __ENABLE_DIGICERT_SSH_CLIENT__ */