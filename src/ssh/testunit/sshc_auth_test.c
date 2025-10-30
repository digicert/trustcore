/**
 * sshc_auth_test.c
 *
 * SSH Client Authentication Unit Tests
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
#include "../../ssh/client/sshc_str_house.h"
#include "../../ssh/client/sshc_auth.h"

/*------------------------------------------------------------------*/
/* Tests for SSHC_AUTH_allocStructures */
/*------------------------------------------------------------------*/

static void test_SSHC_AUTH_allocStructures_null_context(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;

    /* Test with NULL context */
    status = SSHC_AUTH_allocStructures(NULL);
    assert_int_equal(ERR_NULL_POINTER, status);
}

static void test_SSHC_AUTH_allocStructures_success(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext context;
    MSTATUS status;

    /* Initialize context */
    MOC_MEMSET((ubyte *)&context, 0, sizeof(sshClientContext));

    /* Test successful allocation */
    status = SSHC_AUTH_allocStructures(&context);
    assert_int_equal(OK, status);

    /* Verify AUTH_FAILURE_BUFFER was allocated and initialized */
    assert_non_null(AUTH_FAILURE_BUFFER(&context));
    assert_int_equal(SSH_MSG_USERAUTH_FAILURE, AUTH_FAILURE_BUFFER(&context)[0]);

    /* Verify AUTH_KEYINT_CONTEXT was initialized */
    assert_null(AUTH_KEYINT_CONTEXT(&context).user);
    assert_null(AUTH_KEYINT_CONTEXT(&context).pInfoRequest);

    /* Cleanup */
    SSHC_AUTH_deallocStructures(&context);
}

/*------------------------------------------------------------------*/
/* Tests for SSHC_AUTH_deallocStructures */
/*------------------------------------------------------------------*/

static void test_SSHC_AUTH_deallocStructures_null_context(void **ppState)
{
    MOC_UNUSED(ppState);

    MSTATUS status;

    /* Test with NULL context */
    status = SSHC_AUTH_deallocStructures(NULL);
    assert_int_equal(ERR_NULL_POINTER, status);
}

static void test_SSHC_AUTH_deallocStructures_null_buffer(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext context;
    MSTATUS status;

    /* Initialize context with NULL buffer */
    MOC_MEMSET((ubyte *)&context, 0, sizeof(sshClientContext));
    AUTH_FAILURE_BUFFER(&context) = NULL;

    /* Test with NULL failure buffer */
    status = SSHC_AUTH_deallocStructures(&context);
    assert_int_equal(ERR_NULL_POINTER, status);
}

static void test_SSHC_AUTH_deallocStructures_success(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext context;
    MSTATUS status;

    /* Initialize and allocate structures */
    MOC_MEMSET((ubyte *)&context, 0, sizeof(sshClientContext));
    status = SSHC_AUTH_allocStructures(&context);
    assert_int_equal(OK, status);

    /* Test successful deallocation */
    status = SSHC_AUTH_deallocStructures(&context);
    assert_int_equal(OK, status);

    /* Verify buffer was freed and set to NULL */
    assert_null(AUTH_FAILURE_BUFFER(&context));
}

/*------------------------------------------------------------------*/
/* Tests for SSHC_AUTH_doProtocol */
/*------------------------------------------------------------------*/

static void test_SSHC_AUTH_doProtocol_null_message(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext *context = NULL;
    MSTATUS status;

    status = MOC_MALLOC((void **)&context, sizeof(sshClientContext));
    assert_int_equal(OK, status);
    assert_non_null(context);

    /* Initialize context */
    MOC_MEMSET((ubyte *)context, 0, sizeof(sshClientContext));

    /* Test with NULL message */
    status = SSHC_AUTH_doProtocol(context, NULL, 0);
    assert_int_equal(ERR_SSH_BAD_AUTH_RECEIVE_STATE, status);
    MOC_FREE((void **)&context);
}

/*------------------------------------------------------------------*/
/* Tests for Authentication Message Processing */
/*------------------------------------------------------------------*/

static void test_auth_message_success(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext context;
    MSTATUS status;
    ubyte message[] = {SSH_MSG_USERAUTH_SUCCESS};

    /* Initialize context */
    MOC_MEMSET((ubyte *)&context, 0, sizeof(sshClientContext));
    SSH_UPPER_STATE(&context) = kAuthReceiveMessage;

    /* Test processing success message */
    status = SSHC_AUTH_doProtocol(&context, message, sizeof(message));
    assert_int_equal(OK, status);
    assert_int_equal(kOpenState, SSH_UPPER_STATE(&context));
}

static void test_auth_message_failure(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext context;
    MSTATUS status;
    ubyte message[] = {
        SSH_MSG_USERAUTH_FAILURE,
        0x00, 0x00, 0x00, 0x08,  /* length = 8 */
        'p', 'a', 's', 's', 'w', 'o', 'r', 'd',  /* "password" */
        0x00  /* partial success = false */
    };

    /* Initialize context */
    MOC_MEMSET((ubyte *)&context, 0, sizeof(sshClientContext));
    SSH_UPPER_STATE(&context) = kAuthReceiveMessage;

    SSHC_sshClientSettings()->sshMaxAuthAttempts = 3;

    /* Test processing failure message */
    status = SSHC_AUTH_doProtocol(&context, message, sizeof(message));

    assert_int_not_equal(OK, status);
    assert_int_equal(1, context.authContext.authNumAttempts);
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
        cmocka_unit_test(test_SSHC_AUTH_allocStructures_null_context),
        cmocka_unit_test(test_SSHC_AUTH_allocStructures_success),
        cmocka_unit_test(test_SSHC_AUTH_deallocStructures_null_context),
        cmocka_unit_test(test_SSHC_AUTH_deallocStructures_null_buffer),
        cmocka_unit_test(test_SSHC_AUTH_deallocStructures_success),
        cmocka_unit_test(test_SSHC_AUTH_doProtocol_null_message),
        cmocka_unit_test(test_auth_message_success),
        cmocka_unit_test(test_auth_message_failure)
    };
    return cmocka_run_group_tests(tests, testSetup, testTeardown);
#else
    return 0;
#endif
}

#endif /* __ENABLE_MOCANA_SSH_CLIENT__ */