/**
 * sshc_out_mesg_test.c
 *
 * SSH Client Outbound Message Handler Unit Tests
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

#define __ENABLE_OUTBOUND_SSH_DEFINITIONS__

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
#include "../../ssh/ssh_defs.h"
#include "../../ssh/ssh_str.h"
#include "../../ssh/client/sshc.h"
#include "../../ssh/client/sshc_context.h"
#include "../../ssh/client/sshc_str_house.h"
#include "../../ssh/client/sshc_out_mesg.h"

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
/* Tests for SSHC_OUT_MESG_allocStructures */
/*------------------------------------------------------------------*/

static void test_SSHC_OUT_MESG_allocStructures_null_context(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;

    /* Test with NULL context */
    status = SSHC_OUT_MESG_allocStructures(NULL);
    assert_int_equal(ERR_NULL_POINTER, status);
}

static void test_SSHC_OUT_MESG_allocStructures_success(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;

    /* Create basic context */
    status = SSHC_CONTEXT_allocStructures(&pContext);
    assert_int_equal(OK, status);
    assert_non_null(pContext);

    /* Verify outbound buffer was allocated */
    assert_non_null(OUTBOUND_BUFFER(pContext));

    /* Cleanup */
    SSHC_CONTEXT_deallocStructures(&pContext);
}

/*------------------------------------------------------------------*/
/* Tests for SSHC_OUT_MESG_deallocStructures */
/*------------------------------------------------------------------*/

static void test_SSHC_OUT_MESG_deallocStructures_null_context(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;

    /* Test with NULL context */
    status = SSHC_OUT_MESG_deallocStructures(NULL);
    assert_int_equal(ERR_NULL_POINTER, status);
}

static void test_SSHC_OUT_MESG_deallocStructures_success(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;

    /* Create and allocate structures */
    pContext = createTestContext();
    assert_non_null(pContext);
    assert_non_null(OUTBOUND_BUFFER(pContext));

    /* Test successful deallocation */
    status = SSHC_OUT_MESG_deallocStructures(pContext);
    assert_int_equal(OK, status);

    /* Verify buffer was freed and set to NULL */
    assert_null(OUTBOUND_BUFFER(pContext));

    /* Cleanup context */
    SSHC_CONTEXT_deallocStructures(&pContext);
}

/*------------------------------------------------------------------*/
/* Tests for SSHC_OUT_MESG_sendMessageSize */
/*------------------------------------------------------------------*/

static void test_SSHC_OUT_MESG_sendMessageSize_null_params(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;
    ubyte4 retPayloadMax = 0;
    sshClientContext* pContext = NULL;

    /* Test with NULL context */
    status = SSHC_OUT_MESG_sendMessageSize(NULL, 100, &retPayloadMax);
    assert_int_equal(ERR_NULL_POINTER, status);

    pContext = createTestContext();
    assert_non_null(pContext);

    /* Test with NULL return pointer */
    status = SSHC_OUT_MESG_sendMessageSize(pContext, 100, NULL);
    assert_int_equal(ERR_NULL_POINTER, status);

    /* Cleanup */
    destroyTestContext(&pContext);

}

static void test_SSHC_OUT_MESG_sendMessageSize_zero_payload(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;
    ubyte4 retPayloadMax = 0;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Test with zero payload length */
    status = SSHC_OUT_MESG_sendMessageSize(pContext, 0, &retPayloadMax);
    assert_int_equal(ERR_PAYLOAD_EMPTY, status);

    /* Cleanup */
    destroyTestContext(&pContext);
}

static void test_SSHC_OUT_MESG_sendMessageSize_success(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;
    ubyte4 payloadLength = 100;
    ubyte4 retPayloadMax = 0;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Set up MAC algorithm to test MAC size calculation */
    OUTBOUND_MAC_ALGORITHM(pContext) = (void*)0x12345678; /* Non-NULL value */

    /* Test successful calculation */
    status = SSHC_OUT_MESG_sendMessageSize(pContext, payloadLength, &retPayloadMax);
    assert_int_equal(OK, status);

    /* Verify that payload max was calculated */
    assert_true(retPayloadMax > 0);
    assert_true(retPayloadMax <= payloadLength);

    /* Cleanup */
    destroyTestContext(&pContext);
}

static void test_SSHC_OUT_MESG_sendMessageSize_large_payload(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;
    ubyte4 payloadLength = SSHC_MAX_BUFFER_SIZE; /* Very large payload */
    ubyte4 retPayloadMax = 0;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Set smaller max message size to test size limiting */
    OUTBOUND_MAX_MESSAGE_SIZE(pContext) = 1024;
    OUTBOUND_MAC_ALGORITHM(pContext) = (void*)0x12345678; /* Non-NULL value */

    /* Test with payload larger than max message size */
    status = SSHC_OUT_MESG_sendMessageSize(pContext, payloadLength, &retPayloadMax);
    assert_int_equal(OK, status);

    /* Verify payload was reduced to fit within limits */
    assert_true(retPayloadMax < OUTBOUND_MAX_MESSAGE_SIZE(pContext));

    /* Cleanup */
    destroyTestContext(&pContext);
}

/*------------------------------------------------------------------*/
/* Tests for SSHC_OUT_MESG_sendMessage */
/*------------------------------------------------------------------*/

static void test_SSHC_OUT_MESG_sendMessage_null_params(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;
    ubyte testPayload[] = "test payload";
    ubyte4 retPayloadTransferred = 0;
    sshClientContext* pContext = NULL;

    /* Test with NULL context */
    status = SSHC_OUT_MESG_sendMessage(NULL, testPayload, sizeof(testPayload) - 1, &retPayloadTransferred);
    assert_int_equal(ERR_NULL_POINTER, status);

    /* Create test context for remaining tests */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Test with NULL payload */
    status = SSHC_OUT_MESG_sendMessage(pContext, NULL, 100, &retPayloadTransferred);
    assert_int_equal(ERR_NULL_POINTER, status);

    /* Test with NULL return pointer */
    status = SSHC_OUT_MESG_sendMessage(pContext, testPayload, sizeof(testPayload) - 1, NULL);
    assert_int_equal(ERR_NULL_POINTER, status);

    /* Cleanup test context */
    destroyTestContext(&pContext);
}

static void test_SSHC_OUT_MESG_sendMessage_zero_payload(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;
    ubyte testPayload[] = "test payload";
    ubyte4 retPayloadTransferred = 0;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Test with zero payload length */
    status = SSHC_OUT_MESG_sendMessage(pContext, testPayload, 0, &retPayloadTransferred);
    assert_int_equal(ERR_PAYLOAD_EMPTY, status);

    /* Cleanup */
    destroyTestContext(&pContext);
}

static void test_SSHC_OUT_MESG_sendMessage_packet_format(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;
    ubyte testPayload[] = "test";
    ubyte4 retPayloadTransferred = 0;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Set up context for packet formatting test */
    OUTBOUND_MAC_ALGORITHM(pContext) = NULL; /* No MAC for simpler testing */
    OUTBOUND_CIPHER_ALGORITHM(pContext) = NULL; /* No encryption for testing */
    SOCKET(pContext) = -1; /* Invalid socket to prevent actual network I/O */

    /* Test packet formatting without network send */
    /* This will fail at TCP_WRITE but packet should be formatted correctly */
    status = SSHC_OUT_MESG_sendMessage(pContext, testPayload, sizeof(testPayload) - 1, &retPayloadTransferred);

    /* Should fail at TCP_WRITE but packet formatting should be done */
    assert_int_equal(ERR_TCP_WRITE_ERROR, status);
    assert_int_equal(sizeof(testPayload) - 1, retPayloadTransferred);

    /* Verify packet length field was written (big-endian format) */
    ubyte* buffer = OUTBOUND_BUFFER(pContext);
    assert_non_null(buffer);

    /* Check that packet length field exists and is non-zero */
    ubyte4 packetLen = (buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];
    assert_true(packetLen > 0);

    /* Verify padding length field exists */
    ubyte paddingLen = buffer[4];
    assert_true(paddingLen >= 4); /* Minimum padding length */

    /* Cleanup */
    destroyTestContext(&pContext);
}

/*------------------------------------------------------------------*/
/* Tests for Sequence Number Management */
/*------------------------------------------------------------------*/

static void test_sequence_number_increment(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;
    ubyte testPayload[] = "test";
    ubyte4 retPayloadTransferred = 0;
    ubyte4 initialSeqNum;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Set up for sequence number test */
    initialSeqNum = 0;
    OUTBOUND_MAC_ALGORITHM(pContext) = NULL;
    OUTBOUND_CIPHER_ALGORITHM(pContext) = NULL;
    SOCKET(pContext) = -1; /* Invalid socket to prevent network I/O */

    /* Attempt to send message (will fail at network layer) */
    status = SSHC_OUT_MESG_sendMessage(pContext, testPayload, sizeof(testPayload) - 1, &retPayloadTransferred);

    /* Verify sequence number was incremented */
    assert_int_equal(initialSeqNum + 1, OUTBOUND_SEQUENCE_NUM(pContext));

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
        /* Basic allocation/deallocation tests */
        cmocka_unit_test(test_SSHC_OUT_MESG_allocStructures_null_context),
        cmocka_unit_test(test_SSHC_OUT_MESG_allocStructures_success),
        cmocka_unit_test(test_SSHC_OUT_MESG_deallocStructures_null_context),
        cmocka_unit_test(test_SSHC_OUT_MESG_deallocStructures_success),

        /* Message size calculation tests */
        cmocka_unit_test(test_SSHC_OUT_MESG_sendMessageSize_null_params),
        cmocka_unit_test(test_SSHC_OUT_MESG_sendMessageSize_zero_payload),
        cmocka_unit_test(test_SSHC_OUT_MESG_sendMessageSize_success),
        cmocka_unit_test(test_SSHC_OUT_MESG_sendMessageSize_large_payload),

        /* Message sending parameter validation tests */
        cmocka_unit_test(test_SSHC_OUT_MESG_sendMessage_null_params),
        cmocka_unit_test(test_SSHC_OUT_MESG_sendMessage_zero_payload),
        cmocka_unit_test(test_SSHC_OUT_MESG_sendMessage_packet_format),

        /* Sequence number tests */
        cmocka_unit_test(test_sequence_number_increment)
    };

    return cmocka_run_group_tests(tests, testSetup, testTeardown);
#else
    return 0;
#endif
}

#endif /* __ENABLE_DIGICERT_SSH_CLIENT__ */