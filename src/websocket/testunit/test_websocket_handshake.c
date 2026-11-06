#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "websocket/websocket.h"
#include "websocket/websocket_handshake.h"
#include "test_mocks.h"

static int setup(void **state)
{
    (void)state;
    ws_test_mocks_reset();
    return 0;
}

static void test_rfc_accept_vector(void **state)
{
    sbyte accept[29] = { 0 };

    (void)state;
    assert_int_equal(WS_computeAccept((const sbyte *)"dGhlIHNhbXBsZSBub25jZQ==", accept), OK);
    assert_string_equal((const char *)accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

static void test_upgrade_request_and_input_validation(void **state)
{
    static const char expected[] =
        "GET /mqtt HTTP/1.1\r\n"
        "Host: example.test:8080\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: mqtt\r\n"
        "\r\n";
    sbyte request[512];
    ubyte4 written = 0;

    (void)state;
    assert_int_equal(WS_buildUpgradeRequest(
        (const sbyte *)"example.test", 8080, (const sbyte *)"/mqtt",
        (const sbyte *)"mqtt", (const sbyte *)"dGhlIHNhbXBsZSBub25jZQ==",
        request, sizeof(request), &written), OK);
    assert_int_equal(written, strlen(expected));
    assert_memory_equal(request, expected, written);

    /* A host header containing CRLF injection should be rejected. */
    assert_int_equal(WS_buildUpgradeRequest(
        (const sbyte *)"example.test\r\nX-Injected: yes", 80,
        (const sbyte *)"/", NULL, (const sbyte *)"key",
        request, sizeof(request), &written), ERR_WS_HANDSHAKE_FAILED);

    /* A request path containing a newline should be rejected. */
    assert_int_equal(WS_buildUpgradeRequest(
        (const sbyte *)"example.test", 80, (const sbyte *)"/bad\npath",
        NULL, (const sbyte *)"key", request, sizeof(request), &written),
        ERR_WS_HANDSHAKE_FAILED);

    /* A subprotocol containing a CRLF should be rejected. */
    assert_int_equal(WS_buildUpgradeRequest(
        (const sbyte *)"example.test", 0, (const sbyte *)"/",
        (const sbyte *)"mqtt\r\nx", (const sbyte *)"key",
        request, sizeof(request), &written), ERR_WS_HANDSHAKE_FAILED);

    /* A request buffer that is too small should be rejected. */
    assert_int_equal(WS_buildUpgradeRequest(
        (const sbyte *)"example.test", 0, (const sbyte *)"/", NULL,
        (const sbyte *)"key", request, 4, &written), ERR_WS_HANDSHAKE_FAILED);

    /* A NULL host should be rejected. */
    assert_int_equal(WS_buildUpgradeRequest(
        NULL, 0, (const sbyte *)"/", NULL, (const sbyte *)"key",
        request, sizeof(request), &written), ERR_WS_HANDSHAKE_FAILED);
}

static void test_response_validation(void **state)
{
    static const sbyte valid[] =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "uPgRaDe: WebSocket \t\r\n"
        "Connection: keep-alive, Upgrade\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        "Sec-WebSocket-Protocol: mqtt\r\n\r\n";
    static const sbyte badAccept[] =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: invalid\r\n\r\n";
    static const sbyte notFound[] = "HTTP/1.1 404 Not Found\r\n\r\n";
    static const sbyte forbidden[] = "HTTP/1.1 403 Forbidden\r\n\r\n";
    static const sbyte malformed[] = "HTTP/1.1 101 Switching Protocols\r\nNoColon\r\n\r\n";
    static const sbyte noUpgrade[] =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    static const sbyte noConnection[] =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    static const sbyte extension[] =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        "Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n";

    (void)state;
    assert_int_equal(WS_parseUpgradeResponse(valid, sizeof(valid) - 1,
        (const sbyte *)"mqtt", (const sbyte *)"dGhlIHNhbXBsZSBub25jZQ=="), OK);
    assert_int_equal(WS_parseUpgradeResponse(badAccept, sizeof(badAccept) - 1,
        NULL, (const sbyte *)"dGhlIHNhbXBsZSBub25jZQ=="), ERR_WS_HANDSHAKE_FAILED);
    assert_int_equal(WS_parseUpgradeResponse(notFound, sizeof(notFound) - 1,
        NULL, (const sbyte *)"dGhlIHNhbXBsZSBub25jZQ=="), ERR_WS_HANDSHAKE_FAILED);
    assert_int_equal(WS_parseUpgradeResponse(forbidden, sizeof(forbidden) - 1,
        NULL, (const sbyte *)"dGhlIHNhbXBsZSBub25jZQ=="), ERR_HTTP_RESPONSE);
    assert_int_equal(WS_parseUpgradeResponse(malformed, sizeof(malformed) - 1,
        NULL, (const sbyte *)"dGhlIHNhbXBsZSBub25jZQ=="), ERR_WS_HANDSHAKE_FAILED);
    assert_int_equal(WS_parseUpgradeResponse(valid, sizeof(valid) - 1,
        (const sbyte *)"other", (const sbyte *)"dGhlIHNhbXBsZSBub25jZQ=="),
        ERR_WS_SUBPROTOCOL_MISMATCH);
    assert_int_equal(WS_parseUpgradeResponse(noUpgrade, sizeof(noUpgrade) - 1,
        NULL, (const sbyte *)"dGhlIHNhbXBsZSBub25jZQ=="), ERR_WS_HANDSHAKE_FAILED);
    assert_int_equal(WS_parseUpgradeResponse(noConnection, sizeof(noConnection) - 1,
        NULL, (const sbyte *)"dGhlIHNhbXBsZSBub25jZQ=="), ERR_WS_HANDSHAKE_FAILED);
    assert_int_equal(WS_parseUpgradeResponse(extension, sizeof(extension) - 1,
        NULL, (const sbyte *)"dGhlIHNhbXBsZSBub25jZQ=="), ERR_WS_HANDSHAKE_FAILED);
}

static void test_response_rejects_bad_headers_after_accept(void **state)
{
    static const sbyte badUpgrade[] =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        "Upgrade: foo\r\nConnection: Upgrade\r\n\r\n";
    static const sbyte badConnection[] =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        "Upgrade: websocket\r\nConnection: close\r\n\r\n";
    static const sbyte extension[] =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        "Sec-WebSocket-Extensions: permessage-deflate\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
    static const sbyte acceptOnly[] =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    static const sbyte truncated[] =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
        "Upgrade: websocket";
    const sbyte *pKey = (const sbyte *)"dGhlIHNhbXBsZSBub25jZQ==";

    (void)state;
    assert_int_equal(WS_parseUpgradeResponse(badUpgrade, sizeof(badUpgrade) - 1,
        NULL, pKey), ERR_WS_HANDSHAKE_FAILED);
    assert_int_equal(WS_parseUpgradeResponse(badConnection, sizeof(badConnection) - 1,
        NULL, pKey), ERR_WS_HANDSHAKE_FAILED);
    assert_int_equal(WS_parseUpgradeResponse(extension, sizeof(extension) - 1,
        NULL, pKey), ERR_WS_HANDSHAKE_FAILED);
    assert_int_equal(WS_parseUpgradeResponse(acceptOnly, sizeof(acceptOnly) - 1,
        NULL, pKey), ERR_WS_HANDSHAKE_FAILED);
    assert_int_equal(WS_parseUpgradeResponse(truncated, sizeof(truncated) - 1,
        NULL, pKey), ERR_WS_HANDSHAKE_FAILED);
}

static void test_response_rejects_wrong_accept_digest(void **state)
{
    /* Correct 28-byte length, wrong value: only the digest comparison can reject it. */
    static const sbyte response[] =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n";

    (void)state;
    assert_int_equal(WS_parseUpgradeResponse(response, sizeof(response) - 1,
        NULL, (const sbyte *)"dGhlIHNhbXBsZSBub25jZQ=="), ERR_WS_HANDSHAKE_FAILED);
}

static void test_handshake_rejects_oversized_response(void **state)
{
    WsContext *pCtx = NULL;
    ubyte junk[WS_RAW_BUF_SIZE];

    (void)state;
    memset(junk, 'A', sizeof(junk));
    assert_int_equal(WS_createContext(&pCtx, 128), OK);
    /* One read fills the whole response buffer with no header terminator. */
    assert_true(ws_test_queue_read(OK, junk, sizeof(junk)));
    assert_int_equal(WS_connect(pCtx, 7, (const sbyte *)"example.test", 0,
        NULL, (const sbyte *)"/"), ERR_WS_HANDSHAKE_FAILED);
    assert_int_equal(pCtx->state, WS_STATE_CLOSED);
    WS_freeContext(&pCtx);
}

static void test_response_rejects_short_accept_at_buffer_end(void **state)
{
    static const sbyte response[] =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: s3p\r\n";
    sbyte *pExact = NULL;

    (void)state;
    /* Exact-size heap copy so a memory checker (valgrind) flags any read past the value */
    pExact = (sbyte *)test_malloc(sizeof(response) - 1);
    assert_non_null(pExact);
    memcpy(pExact, response, sizeof(response) - 1);
    assert_int_equal(WS_parseUpgradeResponse(pExact, sizeof(response) - 1,
        NULL, (const sbyte *)"dGhlIHNhbXBsZSBub25jZQ=="), ERR_WS_HANDSHAKE_FAILED);
    test_free(pExact);
}

static void test_full_tcp_handshake_split_response(void **state)
{
    WsContext *pCtx = NULL;
    const ubyte nonce[] = "the sample nonce";
    const ubyte response1[] =
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Up";
    const ubyte response2[] =
        "grade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    const ubyte *pWritten;

    (void)state;
    assert_int_equal(WS_createContext(&pCtx, 128), OK);
    ws_test_set_random(nonce, sizeof(nonce) - 1, OK);
    assert_true(ws_test_queue_read(OK, response1, sizeof(response1) - 1));
    assert_true(ws_test_queue_read(OK, response2, sizeof(response2) - 1));
    assert_int_equal(WS_connect(pCtx, 7, (const sbyte *)"example.test", 0,
        NULL, (const sbyte *)"/"), OK);
    assert_int_equal(pCtx->transportType, WS_TRANSPORT_TCP);
    assert_int_equal(pCtx->socket, 7);
    assert_int_equal(pCtx->state, WS_STATE_OPEN);
    assert_int_equal(ws_test_write_calls(), 1);
    pWritten = ws_test_written_data();
    assert_non_null(strstr((const char *)pWritten, "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="));
    WS_freeContext(&pCtx);
    assert_null(pCtx);
}

static void test_key_rng_error(void **state)
{
    ubyte rawKey[WS_KEY_NONCE_LEN];
    sbyte base64[WS_KEY_BASE64_LEN + 1];

    (void)state;
    ws_test_set_random(NULL, 0, WS_TEST_RNG_FAILURE);
    assert_int_equal(WS_generateKey(rawKey, base64), WS_TEST_RNG_FAILURE);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_rfc_accept_vector, setup),
        cmocka_unit_test_setup(test_upgrade_request_and_input_validation, setup),
        cmocka_unit_test_setup(test_response_validation, setup),
        cmocka_unit_test_setup(test_response_rejects_bad_headers_after_accept, setup),
        cmocka_unit_test_setup(test_response_rejects_wrong_accept_digest, setup),
        cmocka_unit_test_setup(test_response_rejects_short_accept_at_buffer_end, setup),
        cmocka_unit_test_setup(test_handshake_rejects_oversized_response, setup),
        cmocka_unit_test_setup(test_full_tcp_handshake_split_response, setup),
        cmocka_unit_test_setup(test_key_rng_error, setup)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
