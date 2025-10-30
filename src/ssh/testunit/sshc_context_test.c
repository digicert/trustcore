/**
 * sshc_context_test.c
 *
 * SSH Client Context Unit Tests
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

#ifdef __ENABLE_MOCANA_SSH_CLIENT__

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
#include "../../crypto/pubcrypto.h"
#include "../../crypto/cert_store.h"
#include "../../ssh/ssh_defs.h"
#include "../../ssh/ssh_str.h"
#include "../../ssh/client/sshc.h"
#include "../../ssh/client/sshc_context.h"
#include "../../ssh/client/sshc_in_mesg.h"
#include "../../ssh/client/sshc_out_mesg.h"
#include "../../ssh/client/sshc_str_house.h"
#include "../../harness/harness.h"

/*------------------------------------------------------------------*/
/* Tests for SSHC_CONTEXT_allocStructures */
/*------------------------------------------------------------------*/

static void test_SSHC_CONTEXT_allocStructures_null_pointer(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;

    /* Test with NULL pointer */
    status = SSHC_CONTEXT_allocStructures(NULL);
    assert_int_equal(ERR_NULL_POINTER, status);
}

static void test_SSHC_CONTEXT_allocStructures_success(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext *pContext = NULL;
    MSTATUS status;

    /* Test successful allocation */
    status = SSHC_CONTEXT_allocStructures(&pContext);
    assert_int_equal(OK, status);
    assert_non_null(pContext);

    /* Verify context was initialized to zero */
    assert_int_equal(0, CONNECTION_INSTANCE(pContext));
    assert_int_equal(0, INBOUND_SEQUENCE_NUM(pContext));
    assert_int_equal(0, OUTBOUND_SEQUENCE_NUM(pContext));

    /* Verify buffer sizes were set */
    assert_int_equal(SSHC_MAX_BUFFER_SIZE, OUTBOUND_BUFFER_SIZE(pContext));
    assert_int_equal(SSHC_MAX_BUFFER_SIZE, OUTBOUND_MAX_MESSAGE_SIZE(pContext));
    assert_int_equal(SSHC_MAX_BUFFER_SIZE, INBOUND_BUFFER_SIZE(pContext));
    assert_int_equal(SSHC_MAX_BUFFER_SIZE, INBOUND_MAX_MESSAGE_SIZE(pContext));

    /* Verify cipher suites were set to null */
    assert_non_null(OUTBOUND_CIPHER_SUITE_INFO(pContext));
    assert_non_null(OUTBOUND_MAC_INFO(pContext));
    assert_non_null(INBOUND_CIPHER_SUITE_INFO(pContext));
    assert_non_null(INBOUND_MAC_INFO(pContext));

    /* Verify cipher types set to IGNORE */
    assert_int_equal(IGNORE, INBOUND_CIPHER_TYPE(pContext));
    assert_int_equal(IGNORE, OUTBOUND_CIPHER_TYPE(pContext));

    /* Verify terminal was allocated */
    assert_non_null(pContext->pTerminal);

    /* Verify IVs were allocated */
    assert_non_null(pContext->encryptIV);
    assert_non_null(pContext->decryptIV);

    /* Cleanup */
    SSHC_CONTEXT_deallocStructures(&pContext);
}

/*------------------------------------------------------------------*/
/* Tests for SSHC_CONTEXT_deallocStructures */
/*------------------------------------------------------------------*/

static void test_SSHC_CONTEXT_deallocStructures_null_pointer(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;

    /* Test with NULL pointer */
    status = SSHC_CONTEXT_deallocStructures(NULL);
    assert_int_equal(ERR_NULL_POINTER, status);
}

static void test_SSHC_CONTEXT_deallocStructures_success(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext *pContext = NULL;
    MSTATUS status;

    /* First allocate a context */
    status = SSHC_CONTEXT_allocStructures(&pContext);
    assert_int_equal(OK, status);
    assert_non_null(pContext);

    /* Test successful deallocation */
    status = SSHC_CONTEXT_deallocStructures(&pContext);
    assert_int_equal(OK, status);
    assert_null(pContext);
}

static void test_SSHC_CONTEXT_deallocStructures_with_allocated_fields(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext *pContext = NULL;
    MSTATUS status;
    ubyte *testBuffer = NULL;

    /* Allocate a context */
    status = SSHC_CONTEXT_allocStructures(&pContext);
    assert_int_equal(OK, status);
    assert_non_null(pContext);

    /* Simulate allocated fields that need cleanup */
    status = CRYPTO_ALLOC(pContext->hwAccelCookie, 100, TRUE, &testBuffer);
    assert_int_equal(OK, status);
    CLIENT_KEX_INIT_PAYLOAD(pContext) = testBuffer;
    CLIENT_KEX_INIT_PAYLOAD_LEN(pContext) = 100;

    /* Test deallocation cleans up allocated fields */
    status = SSHC_CONTEXT_deallocStructures(&pContext);
    assert_int_equal(OK, status);
    assert_null(pContext);
}

/*------------------------------------------------------------------*/
/* Tests for Memory Management */
/*------------------------------------------------------------------*/

static void test_context_memory_initialization(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext *pContext = NULL;
    MSTATUS status;

    /* Allocate context */
    status = SSHC_CONTEXT_allocStructures(&pContext);
    assert_int_equal(OK, status);
    assert_non_null(pContext);

    /* Verify critical pointers are NULL initially */
    assert_null(CLIENT_KEX_INIT_PAYLOAD(pContext));
    assert_null(SERVER_KEX_INIT_PAYLOAD(pContext));
    assert_null(CLIENT_HELLO_COMMENT(pContext));
    assert_null(SERVER_HELLO_COMMENT(pContext));
    assert_null(SSH_SESSION_ID(pContext));

    /* Verify lengths are zero */
    assert_int_equal(0, CLIENT_KEX_INIT_PAYLOAD_LEN(pContext));
    assert_int_equal(0, SERVER_KEX_INIT_PAYLOAD_LEN(pContext));
    assert_int_equal(0, CLIENT_HELLO_COMMENT_LEN(pContext));
    assert_int_equal(0, SERVER_HELLO_COMMENT_LEN(pContext));

    /* Cleanup */
    SSHC_CONTEXT_deallocStructures(&pContext);
}

static void test_context_algorithm_methods_initialization(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext *pContext = NULL;
    MSTATUS status;
    int i;

    /* Allocate context */
    status = SSHC_CONTEXT_allocStructures(&pContext);
    assert_int_equal(OK, status);
    assert_non_null(pContext);

    /* Verify algorithm methods array is initialized to NULL/zero */
    for (i = 0; i < 10; i++)
    {
        assert_null(pContext->sshc_algorithmMethods[i].pString);
        assert_int_equal(0, pContext->sshc_algorithmMethods[i].stringLen);
    }

    /* Cleanup */
    SSHC_CONTEXT_deallocStructures(&pContext);
}

/*------------------------------------------------------------------*/
/* Tests for Context Field Access */
/*------------------------------------------------------------------*/

static void test_context_field_access_macros(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext *pContext = NULL;
    MSTATUS status;

    /* Allocate context */
    status = SSHC_CONTEXT_allocStructures(&pContext);
    assert_int_equal(OK, status);
    assert_non_null(pContext);

    /* Test setting and getting basic fields */
    SOCKET(pContext) = 42;
    assert_int_equal(42, SOCKET(pContext));

    CONNECTION_INSTANCE(pContext) = 123;
    assert_int_equal(123, CONNECTION_INSTANCE(pContext));

    SSH_TIMER_MS_EXPIRE(pContext) = 5000;
    assert_int_equal(5000, SSH_TIMER_MS_EXPIRE(pContext));

    /* Cleanup */
    SSHC_CONTEXT_deallocStructures(&pContext);
}

/*------------------------------------------------------------------*/
/* Tests for Key Exchange Context */
/*------------------------------------------------------------------*/

static void test_context_key_exchange_initialization(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext *pContext = NULL;
    MSTATUS status;

    /* Allocate context */
    status = SSHC_CONTEXT_allocStructures(&pContext);
    assert_int_equal(OK, status);
    assert_non_null(pContext);

    /* Verify key exchange context is initialized */
    assert_null(SSH_DH_CTX(pContext));
    assert_null(SSH_HASH_H(pContext));
    assert_null(SSH_K(pContext));

    /* Cleanup */
    SSHC_CONTEXT_deallocStructures(&pContext);
}


/*------------------------------------------------------------------*/
/* Integration Tests */
/*------------------------------------------------------------------*/

static void test_context_full_lifecycle(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext *pContext = NULL;
    MSTATUS status;
    ubyte *testPayload = NULL;

    /* Allocate context */
    status = SSHC_CONTEXT_allocStructures(&pContext);
    assert_int_equal(OK, status);
    assert_non_null(pContext);

    /* Simulate normal usage - setting various fields */
    SOCKET(pContext) = 100;
    CONNECTION_INSTANCE(pContext) = 1;

    /* Allocate some test data */
    status = CRYPTO_ALLOC(pContext->hwAccelCookie, 256, TRUE, &testPayload);
    assert_int_equal(OK, status);
    CLIENT_KEX_INIT_PAYLOAD(pContext) = testPayload;
    CLIENT_KEX_INIT_PAYLOAD_LEN(pContext) = 256;

    /* Verify fields are set correctly */
    assert_int_equal(100, SOCKET(pContext));
    assert_int_equal(1, CONNECTION_INSTANCE(pContext));
    assert_non_null(CLIENT_KEX_INIT_PAYLOAD(pContext));
    assert_int_equal(256, CLIENT_KEX_INIT_PAYLOAD_LEN(pContext));

    /* Cleanup should handle everything */
    status = SSHC_CONTEXT_deallocStructures(&pContext);
    assert_int_equal(OK, status);
    assert_null(pContext);
}

static void test_multiple_context_allocation(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext *pContext1 = NULL;
    sshClientContext *pContext2 = NULL;
    MSTATUS status;

    /* Allocate first context */
    status = SSHC_CONTEXT_allocStructures(&pContext1);
    assert_int_equal(OK, status);
    assert_non_null(pContext1);

    /* Allocate second context */
    status = SSHC_CONTEXT_allocStructures(&pContext2);
    assert_int_equal(OK, status);
    assert_non_null(pContext2);

    /* Verify contexts are different */
    assert_ptr_not_equal(pContext1, pContext2);

    /* Set different values in each */
    CONNECTION_INSTANCE(pContext1) = 1;
    CONNECTION_INSTANCE(pContext2) = 2;

    assert_int_equal(1, CONNECTION_INSTANCE(pContext1));
    assert_int_equal(2, CONNECTION_INSTANCE(pContext2));

    /* Cleanup both contexts */
    status = SSHC_CONTEXT_deallocStructures(&pContext1);
    assert_int_equal(OK, status);
    assert_null(pContext1);

    status = SSHC_CONTEXT_deallocStructures(&pContext2);
    assert_int_equal(OK, status);
    assert_null(pContext2);
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

    status = MOCANA_initMocana();
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

    status = MOCANA_freeMocana();

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

#ifdef __ENABLE_MOCANA_SSH_CLIENT__
    const struct CMUnitTest tests[] = {
        /* Basic allocation/deallocation tests */
        cmocka_unit_test(test_SSHC_CONTEXT_allocStructures_null_pointer),
        cmocka_unit_test(test_SSHC_CONTEXT_allocStructures_success),
        cmocka_unit_test(test_SSHC_CONTEXT_deallocStructures_null_pointer),
        cmocka_unit_test(test_SSHC_CONTEXT_deallocStructures_success),
        cmocka_unit_test(test_SSHC_CONTEXT_deallocStructures_with_allocated_fields),

        /* Memory management tests */
        cmocka_unit_test(test_context_memory_initialization),
        cmocka_unit_test(test_context_algorithm_methods_initialization),

        /* Field access tests */
        cmocka_unit_test(test_context_field_access_macros),
        cmocka_unit_test(test_context_key_exchange_initialization),

        /* Integration tests */
        cmocka_unit_test(test_context_full_lifecycle),
        cmocka_unit_test(test_multiple_context_allocation),
    };

    return cmocka_run_group_tests(tests, testSetup, testTeardown);
#else
    return 0;
#endif
}

#endif /* __ENABLE_MOCANA_SSH_CLIENT__ */