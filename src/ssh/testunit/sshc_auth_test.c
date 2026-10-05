/**
 * sshc_auth_test.c
 *
 * SSH Client Authentication Unit Tests
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 *
 */

#include "../../common/moptions.h"

#ifdef __ENABLE_DIGICERT_SSH_CLIENT__

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include "cmocka.h"

#include "../../common/mtypes.h"
#include "../../common/mlimits.h"
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
    DIGI_MEMSET((ubyte *)&context, 0, sizeof(sshClientContext));

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
    DIGI_MEMSET((ubyte *)&context, 0, sizeof(sshClientContext));
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
    DIGI_MEMSET((ubyte *)&context, 0, sizeof(sshClientContext));
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

    status = DIGI_MALLOC((void **)&context, sizeof(sshClientContext));
    assert_int_equal(OK, status);
    assert_non_null(context);

    /* Initialize context */
    DIGI_MEMSET((ubyte *)context, 0, sizeof(sshClientContext));

    /* Test with NULL message */
    status = SSHC_AUTH_doProtocol(context, NULL, 0);
    assert_int_equal(ERR_SSH_BAD_AUTH_RECEIVE_STATE, status);
    DIGI_FREE((void **)&context);
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
    DIGI_MEMSET((ubyte *)&context, 0, sizeof(sshClientContext));
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
    DIGI_MEMSET((ubyte *)&context, 0, sizeof(sshClientContext));
    SSH_UPPER_STATE(&context) = kAuthReceiveMessage;

    SSHC_sshClientSettings()->sshMaxAuthAttempts = 3;

    /* Test processing failure message */
    status = SSHC_AUTH_doProtocol(&context, message, sizeof(message));

    assert_int_not_equal(OK, status);
    assert_int_equal(1, context.authContext.authNumAttempts);
}

/*------------------------------------------------------------------*/
/* Keyboard-Interactive Security Tests */
/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_SSH_AUTH_KEYBOARD_INTERACTIVE__

/* SSH_MSG_USERAUTH_INFO_REQUEST packet format (RFC 4256 Section 3.1):
   [1 byte]     Message Type: SSH_MSG_USERAUTH_INFO_REQUEST (60)
   [4 bytes]    Name Length (uint32)
   [N bytes]    Name (ISO-10646 UTF-8 string)
   [4 bytes]    Instruction Length (uint32)
   [N bytes]    Instruction (ISO-10646 UTF-8 string)
   [4 bytes]    Language Tag Length (uint32)
   [N bytes]    Language Tag (RFC 3066 format, often empty)
   [4 bytes]    Number of Prompts (uint32)
   [Variable]   For each prompt (num-prompts times):
                  [4 bytes]  Prompt String Length (uint32)
                  [N bytes]  Prompt String (ISO-10646 UTF-8)
                  [1 byte]   Echo Flag (boolean: 0=no echo, 1=echo)
*/
static ubyte* build_info_request(ubyte4 *pLen, ubyte4 numPrompts)
{
    ubyte *pPayload = NULL;
    ubyte4 index = 0;
    ubyte4 allocLen = 1 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + (numPrompts * 20);

    if (OK != DIGI_MALLOC((void**)&pPayload, allocLen))
        return NULL;

    pPayload[index++] = SSH_MSG_USERAUTH_INFO_REQUEST;

    pPayload[index++] = 0x00; pPayload[index++] = 0x00;
    pPayload[index++] = 0x00; pPayload[index++] = 0x04;
    DIGI_MEMCPY(pPayload + index, "test", 4); index += 4;

    pPayload[index++] = 0x00; pPayload[index++] = 0x00;
    pPayload[index++] = 0x00; pPayload[index++] = 0x06;
    DIGI_MEMCPY(pPayload + index, "prompt", 6); index += 6;

    pPayload[index++] = 0x00; pPayload[index++] = 0x00;
    pPayload[index++] = 0x00; pPayload[index++] = 0x00;

    pPayload[index++] = 0x00; pPayload[index++] = 0x00;
    pPayload[index++] = 0x00; pPayload[index++] = (ubyte)numPrompts;

    for (ubyte4 i = 0; i < numPrompts; i++) {
        pPayload[index++] = 0x00; pPayload[index++] = 0x00;
        pPayload[index++] = 0x00; pPayload[index++] = 0x04;
        DIGI_MEMCPY(pPayload + index, "pass", 4); index += 4;
        pPayload[index++] = 0x00;
    }

    *pLen = index;
    return pPayload;
}

static void test_keyboard_interactive_zero_length_packet(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext context;
    MSTATUS status;
    ubyte payload[1];
    ubyte4 index = 0;

    DIGI_MEMSET((ubyte *)&context, 0, sizeof(sshClientContext));
    SSH_UPPER_STATE(&context) = kAuthReceiveMessage;
    context.authType = MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE;
    DIGI_MEMSET(payload, 0, sizeof(payload));

    payload[index++] = SSH_MSG_USERAUTH_INFO_REQUEST;

    status = SSHC_AUTH_doProtocol(&context, payload, index);

    assert_int_equal(ERR_PAYLOAD_EMPTY, status);
}

static void test_keyboard_interactive_invalid_msg_type(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext context;
    MSTATUS status;
    ubyte payload[5];
    ubyte4 index = 0;

    DIGI_MEMSET((ubyte *)&context, 0, sizeof(sshClientContext));
    SSH_UPPER_STATE(&context) = kAuthReceiveMessage;
    context.authType = MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE;
    DIGI_MEMSET(payload, 0, sizeof(payload));

    payload[index++] = SSH_MSG_USERAUTH_INFO_REQUEST;
    payload[index++] = 0x00; payload[index++] = 0x00;
    payload[index++] = 0x00; payload[index++] = 0x01;

    status = SSHC_AUTH_doProtocol(&context, payload, index);

    assert_int_equal(ERR_PAYLOAD_EMPTY, status);
}

static void test_keyboard_interactive_oversized_prompt_count(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext context;
    MSTATUS status;
    ubyte payload[50];
    ubyte4 index = 0;

    DIGI_MEMSET((ubyte *)&context, 0, sizeof(sshClientContext));
    SSH_UPPER_STATE(&context) = kAuthReceiveMessage;
    context.authType = MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE;
    DIGI_MEMSET(payload, 0, sizeof(payload));

    payload[index++] = SSH_MSG_USERAUTH_INFO_REQUEST;

    payload[index++] = 0x00; payload[index++] = 0x00;
    payload[index++] = 0x00; payload[index++] = 0x04;
    DIGI_MEMCPY(payload + index, "test", 4); index += 4;

    payload[index++] = 0x00; payload[index++] = 0x00;
    payload[index++] = 0x00; payload[index++] = 0x06;
    DIGI_MEMCPY(payload + index, "prompt", 6); index += 6;

    payload[index++] = 0x00; payload[index++] = 0x00;
    payload[index++] = 0x00; payload[index++] = 0x00;

    payload[index++] = 0xFF; payload[index++] = 0xFF;
    payload[index++] = 0xFF; payload[index++] = 0xFF;

    status = SSHC_AUTH_doProtocol(&context, payload, index);

    assert_int_equal(ERR_AUTH_MISCONFIGURED_PROMPTS, status);
}

static void test_keyboard_interactive_language_tag_overflow(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext context;
    MSTATUS status;
    ubyte payload[100];
    ubyte4 index = 0;

    DIGI_MEMSET((ubyte *)&context, 0, sizeof(sshClientContext));
    SSH_UPPER_STATE(&context) = kAuthReceiveMessage;
    context.authType = MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE;
    DIGI_MEMSET(payload, 0, sizeof(payload));

    payload[index++] = SSH_MSG_USERAUTH_INFO_REQUEST;

    payload[index++] = 0x00; payload[index++] = 0x00;
    payload[index++] = 0x00; payload[index++] = 0x00;

    payload[index++] = 0x00; payload[index++] = 0x00;
    payload[index++] = 0x00; payload[index++] = 0x00;

    payload[index++] = 0xFF; payload[index++] = 0xFF;
    payload[index++] = 0xFF; payload[index++] = 0xFF;

    status = SSHC_AUTH_doProtocol(&context, payload, index);

    assert_int_equal(ERR_SSH_UNEXPECTED_END_MESSAGE, status);

}

static void test_keyboard_interactive_prompt_length_overflow(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext context;
    MSTATUS status;
    ubyte4 payloadLen;
    ubyte *pPayload;

    DIGI_MEMSET((ubyte *)&context, 0, sizeof(sshClientContext));
    SSH_UPPER_STATE(&context) = kAuthReceiveMessage;
    context.authType = MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE;

    pPayload = build_info_request(&payloadLen, 1);
    assert_non_null(pPayload);

    ubyte4 firstPromptOffset = 1 + 4 + 4 + 4 + 4 + 4 + 4 + 4;
    pPayload[firstPromptOffset] = 0xFF;
    pPayload[firstPromptOffset + 1] = 0xFF;
    pPayload[firstPromptOffset + 2] = 0xFF;
    pPayload[firstPromptOffset + 3] = 0xFF;

    status = SSHC_AUTH_doProtocol(&context, pPayload, payloadLen);

    assert_int_equal(ERR_SSH_UNEXPECTED_END_MESSAGE, status);

    DIGI_FREE((void**)&pPayload);
}

static void test_keyboard_interactive_echo_byte_out_of_bounds(void **ppState)
{
    MOC_UNUSED(ppState);

    sshClientContext context;
    MSTATUS status;
    ubyte payload[60];
    ubyte4 index = 0;

    DIGI_MEMSET((ubyte *)&context, 0, sizeof(sshClientContext));
    SSH_UPPER_STATE(&context) = kAuthReceiveMessage;
    context.authType = MOCANA_SSH_AUTH_KEYBOARD_INTERACTIVE;
    DIGI_MEMSET(payload, 0, sizeof(payload));

    payload[index++] = SSH_MSG_USERAUTH_INFO_REQUEST;

    payload[index++] = 0x00; payload[index++] = 0x00;
    payload[index++] = 0x00; payload[index++] = 0x00;

    payload[index++] = 0x00; payload[index++] = 0x00;
    payload[index++] = 0x00; payload[index++] = 0x00;

    payload[index++] = 0x00; payload[index++] = 0x00;
    payload[index++] = 0x00; payload[index++] = 0x00;

    payload[index++] = 0x00; payload[index++] = 0x00;
    payload[index++] = 0x00; payload[index++] = 0x01;

    payload[index++] = 0x00; payload[index++] = 0x00;
    payload[index++] = 0x00; payload[index++] = 0x04;

    DIGI_MEMCPY(payload + index, "pass", 4); index += 4;

    status = SSHC_AUTH_doProtocol(&context, payload, index);

    assert_int_not_equal(OK, status);
}

#endif /* __ENABLE_DIGICERT_SSH_AUTH_KEYBOARD_INTERACTIVE__ */

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
        cmocka_unit_test(test_SSHC_AUTH_allocStructures_null_context),
        cmocka_unit_test(test_SSHC_AUTH_allocStructures_success),
        cmocka_unit_test(test_SSHC_AUTH_deallocStructures_null_context),
        cmocka_unit_test(test_SSHC_AUTH_deallocStructures_null_buffer),
        cmocka_unit_test(test_SSHC_AUTH_deallocStructures_success),
        cmocka_unit_test(test_SSHC_AUTH_doProtocol_null_message),
        cmocka_unit_test(test_auth_message_success),
        cmocka_unit_test(test_auth_message_failure),

#ifdef __ENABLE_DIGICERT_SSH_AUTH_KEYBOARD_INTERACTIVE__
        cmocka_unit_test(test_keyboard_interactive_zero_length_packet),
        cmocka_unit_test(test_keyboard_interactive_invalid_msg_type),
        cmocka_unit_test(test_keyboard_interactive_oversized_prompt_count),
        cmocka_unit_test(test_keyboard_interactive_language_tag_overflow),
        cmocka_unit_test(test_keyboard_interactive_prompt_length_overflow),
        cmocka_unit_test(test_keyboard_interactive_echo_byte_out_of_bounds),
#endif
    };
    return cmocka_run_group_tests(tests, testSetup, testTeardown);
#else
    return 0;
#endif
}

#endif /* __ENABLE_DIGICERT_SSH_CLIENT__ */