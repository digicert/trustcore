/**
 * sshc_in_mesg_test.c
 *
 * SSH Client Inbound Message Handler Unit Tests
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
#define __ENABLE_INBOUND_SSH_DEFINITIONS__

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
#include "../../ssh/client/sshc_in_mesg.h"

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
/* Tests for SSHC_IN_MESG_allocStructures */
/*------------------------------------------------------------------*/

static void test_SSHC_IN_MESG_allocStructures_null_context(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;

    /* Test with NULL context */
    status = SSHC_IN_MESG_allocStructures(NULL);
    assert_int_equal(ERR_NULL_POINTER, status);
}

static void test_SSHC_IN_MESG_allocStructures_success(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;

    /* Create basic context */
    status = SSHC_CONTEXT_allocStructures(&pContext);
    assert_int_equal(OK, status);
    assert_non_null(pContext);

    /* Verify inbound buffer was allocated */
    assert_non_null(INBOUND_BUFFER(pContext));

    /* Verify initial state */
    assert_int_equal(kReceiveInitHelloListen, INBOUND_STATE(pContext));

    /* Cleanup */
    SSHC_CONTEXT_deallocStructures(&pContext);
}

/*------------------------------------------------------------------*/
/* Tests for SSHC_IN_MESG_deallocStructures */
/*------------------------------------------------------------------*/

static void test_SSHC_IN_MESG_deallocStructures_null_context(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;

    /* Test with NULL context */
    status = SSHC_IN_MESG_deallocStructures(NULL);
    assert_int_equal(ERR_NULL_POINTER, status);
}

static void test_SSHC_IN_MESG_deallocStructures_success(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;

    /* Create and allocate structures */
    pContext = createTestContext();
    assert_non_null(pContext);
    assert_non_null(INBOUND_BUFFER(pContext));

    /* Test successful deallocation */
    status = SSHC_IN_MESG_deallocStructures(pContext);
    assert_int_equal(OK, status);

    /* Verify buffer was freed and set to NULL */
    assert_null(INBOUND_BUFFER(pContext));

    /* Cleanup context */
    SSHC_CONTEXT_deallocStructures(&pContext);
}

/*------------------------------------------------------------------*/
/* Tests for SSHC_IN_MESG_processMessage */
/*------------------------------------------------------------------*/

static void test_SSHC_IN_MESG_processMessage_null_context(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;
    ubyte* pPayload = (ubyte*)"test";
    ubyte4 payloadLength = 4;

    /* Test with NULL context */
    status = SSHC_IN_MESG_processMessage(NULL, &pPayload, &payloadLength);
    assert_int_equal(ERR_NULL_POINTER, status);
}

static void test_SSHC_IN_MESG_processMessage_null_payload_pointer(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;
    ubyte4 payloadLength = 4;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Test with NULL payload pointer */
    status = SSHC_IN_MESG_processMessage(pContext, NULL, &payloadLength);
    assert_int_equal(ERR_NULL_POINTER, status);

    /* Cleanup */
    destroyTestContext(&pContext);
}

static void test_SSHC_IN_MESG_processMessage_null_payload(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;
    ubyte* pPayload = NULL;
    ubyte4 payloadLength = 4;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Test with NULL payload */
    status = SSHC_IN_MESG_processMessage(pContext, NULL, &payloadLength);
    assert_int_equal(ERR_NULL_POINTER, status);

    /* Cleanup */
    destroyTestContext(&pContext);
}

static void test_SSHC_IN_MESG_processMessage_null_length(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;
    ubyte* pPayload = (ubyte*)"test";

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Test with NULL length pointer */
    status = SSHC_IN_MESG_processMessage(pContext, &pPayload, NULL);
    assert_int_equal(ERR_NULL_POINTER, status);

    /* Cleanup */
    destroyTestContext(&pContext);
}

static void test_SSHC_IN_MESG_processMessage_zero_length(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;
    ubyte* pPayload = (ubyte*)"test";
    ubyte4 payloadLength = 0;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Test with zero length - should succeed but do nothing */
    status = SSHC_IN_MESG_processMessage(pContext, &pPayload, &payloadLength);
    assert_int_equal(OK, status);

    /* Cleanup */
    destroyTestContext(&pContext);
}

static void test_SSHC_IN_MESG_processMessage_invalid_state(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;
    ubyte testData[] = "SSH-2.0-TestServer\r\n";
    ubyte* pPayload = testData;
    ubyte4 payloadLength = sizeof(testData) - 1;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Set an invalid state */
    INBOUND_STATE(pContext) = 999; /* Invalid state */

    /* Test processing with invalid state */
    status = SSHC_IN_MESG_processMessage(pContext, &pPayload, &payloadLength);
    assert_int_equal(ERR_SSH_BAD_RECEIVE_STATE, status);

    /* Cleanup */
    destroyTestContext(&pContext);
}

/*------------------------------------------------------------------*/
/* Tests for Version String Processing */
/*------------------------------------------------------------------*/


static void test_version_string_processing_invalid_version(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;
    ubyte testData[] = "SSH-1.0-TestServer\r\n";
    ubyte* pPayload = testData;
    ubyte4 payloadLength = sizeof(testData) - 1;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Ensure we're in the correct state for version string processing */
    INBOUND_STATE(pContext) = kReceiveHelloListen;

    /* Test processing invalid SSH version string */
    status = SSHC_IN_MESG_processMessage(pContext, &pPayload, &payloadLength);
    assert_int_equal(ERR_SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED, status);

    /* Cleanup */
    destroyTestContext(&pContext);
}
/*------------------------------------------------------------------*/
/* Tests for Edge Cases */
/*------------------------------------------------------------------*/

static void test_empty_packet_length(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Set up for first block decrypt with zero packet length */
    INBOUND_STATE(pContext) = kDecryptFirstBlock;
    INBOUND_CIPHER_ALGORITHM(pContext) = NULL; /* No decryption */

    /* Mock packet with zero length */
    ubyte mockPacket[16] = {0x00, 0x00, 0x00, 0x00}; /* length = 0 */
    DIGI_MEMCPY(INBOUND_BUFFER(pContext), mockPacket, 16);

    /* Process message */
    ubyte* dummyPayload = mockPacket;
    ubyte4 dummyLength = 0;
    MSTATUS status = SSHC_IN_MESG_processMessage(pContext, &dummyPayload, &dummyLength);

    assert_int_equal(OK, status);

    /* Cleanup */
    destroyTestContext(&pContext);
}

static void test_oversized_packet_length(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Set up for first block decrypt */
    INBOUND_STATE(pContext) = kDecryptFirstBlock;
    INBOUND_CIPHER_ALGORITHM(pContext) = NULL; /* No decryption */

    /* Set maximum message size to something small for testing */
    INBOUND_MAX_MESSAGE_SIZE(pContext) = 1024;

    /* Mock packet with oversized length */
    ubyte mockPacket[16] = {0x00, 0x00, 0x08, 0x00, /* length = 2048 (larger than max) */
                            0x04, /* padding length = 4 */
                            0x01, 0x02, 0x03,
                            0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00};
    DIGI_MEMCPY(INBOUND_BUFFER(pContext), mockPacket, 16);

    /* Process message */
    ubyte* dummyPayload = mockPacket;
    ubyte4 dummyLength = 2048;
    MSTATUS status = SSHC_IN_MESG_processMessage(pContext, &dummyPayload, &dummyLength);

    /* Should return error for oversized payload */
    assert_int_equal(ERR_PAYLOAD_TOO_LARGE, status);

    /* Cleanup */
    destroyTestContext(&pContext);
}

static void test_invalid_padding_length(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Set up for first block decrypt */
    INBOUND_STATE(pContext) = kDecryptFirstBlock;
    INBOUND_CIPHER_ALGORITHM(pContext) = NULL; /* No decryption */

    /* Mock packet with invalid padding length (larger than packet length - 1) */
    ubyte mockPacket[16] = {0x00, 0x00, 0x00, 0x10, /* length = 16 */
                            0xFF, /* padding length = 255 (invalid) */
                            0x01, 0x02, 0x03,
                            0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00};
    DIGI_MEMCPY(INBOUND_BUFFER(pContext), mockPacket, 16);

    /* Process message */
    ubyte* dummyPayload = mockPacket;
    ubyte4 dummyLength = 16;
    MSTATUS status = SSHC_IN_MESG_processMessage(pContext, &dummyPayload, &dummyLength);

    /* Should return error for invalid payload structure */
    assert_int_equal(ERR_PAYLOAD_EMPTY, status);

    /* Cleanup */
    destroyTestContext(&pContext);
}

/*------------------------------------------------------------------*/
/* Tests for State Transitions */
/*------------------------------------------------------------------*/

static void test_state_transition_init_to_hello_listen(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext* pContext = NULL;
    MSTATUS status;
    ubyte* dummyPayload = (ubyte*)"dummy";
    ubyte4 dummyLength = 5;

    /* Create test context */
    pContext = createTestContext();
    assert_non_null(pContext);

    /* Start in kReceiveInitHelloListen state (default after allocation) */
    assert_int_equal(kReceiveInitHelloListen, INBOUND_STATE(pContext));

    /* Process message should transition to kReceiveClientHelloListen */
    status = SSHC_IN_MESG_processMessage(pContext, &dummyPayload, &dummyLength);

    /* Verify state changed */
    assert_int_equal(kReceiveClientHelloListen, INBOUND_STATE(pContext));

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
        cmocka_unit_test(test_SSHC_IN_MESG_allocStructures_null_context),
        cmocka_unit_test(test_SSHC_IN_MESG_allocStructures_success),
        cmocka_unit_test(test_SSHC_IN_MESG_deallocStructures_null_context),
        cmocka_unit_test(test_SSHC_IN_MESG_deallocStructures_success),

        /* Message processing parameter validation tests */
        cmocka_unit_test(test_SSHC_IN_MESG_processMessage_null_context),
        cmocka_unit_test(test_SSHC_IN_MESG_processMessage_null_payload_pointer),
        cmocka_unit_test(test_SSHC_IN_MESG_processMessage_null_payload),
        cmocka_unit_test(test_SSHC_IN_MESG_processMessage_null_length),
        cmocka_unit_test(test_SSHC_IN_MESG_processMessage_zero_length),
        cmocka_unit_test(test_SSHC_IN_MESG_processMessage_invalid_state),

        /* Version string processing tests */
        cmocka_unit_test(test_version_string_processing_invalid_version),

        /* Edge case tests */
        cmocka_unit_test(test_empty_packet_length),
        cmocka_unit_test(test_oversized_packet_length),
        cmocka_unit_test(test_invalid_padding_length),

        /* State transition tests */
        cmocka_unit_test(test_state_transition_init_to_hello_listen),
    };

    return cmocka_run_group_tests(tests, testSetup, testTeardown);
#else
    return 0;
#endif
}

#endif /* __ENABLE_DIGICERT_SSH_CLIENT__ */