#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "websocket/websocket.h"
#include "test_mocks.h"

static int setup(void **state)
{
    WsContext *pCtx = NULL;

    ws_test_mocks_reset();
    /* Each test gets its own context with a 256-byte decoded-payload ring. */
    if (OK != WS_createContext(&pCtx, 256))
    {
        return -1;
    }
    *state = pCtx;
    return 0;
}

static int teardown(void **state)
{
    WsContext *pCtx = (WsContext *)*state;
    WS_freeContext(&pCtx);
    *state = NULL;
    return 0;
}

static void open_tcp(WsContext *pCtx)
{
    /* Skip the HTTP upgrade; 7 is a dummy socket ignored by the TCP mocks. */
    pCtx->state = WS_STATE_OPEN;
    pCtx->transportType = WS_TRANSPORT_TCP;
    pCtx->socket = 7;
}

static void test_context_lifecycle(void **state)
{
    WsContext *pCtx = (WsContext *)*state;
    WsContext *pNullCtx = NULL;

    /* Creation allocates the requested ring but does not open a connection. */
    assert_int_equal(pCtx->state, WS_STATE_CLOSED);
    assert_non_null(pCtx->pPayloadBuf);
    assert_int_equal(pCtx->payloadBufSize, 256);
    /* A zero-capacity ring is invalid; freeing a null context is safe. */
    assert_int_equal(WS_createContext(&pNullCtx, 0), ERR_BAD_LENGTH);
    WS_freeContext(&pNullCtx);
    assert_null(pNullCtx);
}

static void test_binary_send_and_short_write(void **state)
{
    WsContext *pCtx = (WsContext *)*state;
    /* Fixed test-only mask: makes each outgoing payload byte predictable. */
    const ubyte mask[4] = { 0x37, 0xFA, 0x21, 0x3D };
    const ubyte expected[] = {
        0x82,                   /* [0]: FIN (0x80) + binary opcode (0x02). */
        0x83,                   /* [1]: MASK (0x80) + 3-byte payload length. */
        0x37, 0xFA, 0x21, 0x3D, /* [2..5]: four masking-key bytes, in order. */
        0x7F,                   /* [6]: 'H' (0x48) XOR mask[0] (0x37). */
        0x93,                   /* [7]: 'i' (0x69) XOR mask[1] (0xFA). */
        0x00                    /* [8]: '!' (0x21) XOR mask[2] (0x21). */
    };

    open_tcp(pCtx);
    ws_test_set_random(mask, sizeof(mask), OK);
    /* Verify the entire wire frame, including header, mask, and payload. */
    assert_int_equal(WS_mqttTransportSend(0, pCtx, (sbyte *)"Hi!", 3), OK);
    assert_int_equal(ws_test_written_len(), sizeof(expected));
    assert_memory_equal(ws_test_written_data(), expected, sizeof(expected));

    ws_test_mocks_reset();
    ws_test_set_random(mask, sizeof(mask), OK);
    /* Accept only 2 of the 9 frame bytes: a short write must not report success. */
    ws_test_set_write_result(OK, 2);
    assert_int_equal(WS_mqttTransportSend(0, pCtx, (sbyte *)"Hi!", 3), ERR_WS);
    assert_int_equal(ws_test_write_calls(), 1);
}

static void test_send_requires_open_context(void **state)
{
    WsContext *pCtx = (WsContext *)*state;

    /* A closed context must reject the send before calling the transport. */
    assert_int_equal(WS_mqttTransportSend(0, pCtx, (sbyte *)"x", 1), ERR_WS_NOT_OPEN);
    assert_int_equal(ws_test_write_calls(), 0);
}

static void test_receive_data_and_timeout(void **state)
{
    WsContext *pCtx = (WsContext *)*state;
    const ubyte frame[] = {
        0x82,          /* [0]: FIN + binary opcode. */
        0x03,          /* [1]: unmasked server frame, 3 payload bytes. */
        'M', 'Q', 'T'  /* [2..4]: application payload "MQT". */
    };
    /* Room for the payload; 100 below is the mock read timeout in milliseconds. */
    sbyte out[8] = { 0 };
    ubyte4 received = 0;
    byteBoolean timeout = TRUE;

    open_tcp(pCtx);
    assert_true(ws_test_queue_read(OK, frame, sizeof(frame)));
    /* Receive must strip the frame header and return only "MQT", without timeout. */
    assert_int_equal(WS_mqttTransportRecv(0, pCtx, out, sizeof(out), &received, 100,
        &timeout), OK);
    assert_int_equal(received, 3);
    assert_memory_equal(out, "MQT", 3);
    assert_false(timeout);

    ws_test_mocks_reset();
    timeout = FALSE;
    /* A transport timeout is returned as OK, zero bytes, and timeout = TRUE. */
    assert_true(ws_test_queue_read(ERR_TCP_READ_TIMEOUT, NULL, 0));
    assert_int_equal(WS_mqttTransportRecv(0, pCtx, out, sizeof(out), &received, 100,
        &timeout), OK);
    assert_int_equal(received, 0);
    assert_true(timeout);
}

static void test_ping_then_binary_and_close_echo(void **state)
{
    WsContext *pCtx = (WsContext *)*state;
    /* Deterministic test-only mask used for outgoing Pong and Close frames. */
    const ubyte mask[4] = { 0x01, 0x02, 0x03, 0x04 };
    const ubyte frames[] = {
        0x89, 0x02, 'o', 'k', /* [0]: FIN + Ping; [1]: unmasked length 2;
                                [2..3]: Ping payload "ok", echoed by the Pong. */
        0x82, 0x02, 'M', 'Q'  /* [4]: FIN + binary; [5]: unmasked length 2;
                                [6..7]: application payload "MQ". */
    };
    const ubyte closeFrame[] = {
        0x88,       /* [0]: FIN + Close opcode. */
        0x02,       /* [1]: unmasked, 2-byte close-code payload. */
        0x03, 0xE8  /* [2..3]: big-endian 0x03E8 = 1000 (normal closure). */
    };
    sbyte out[8] = { 0 };
    ubyte4 received = 0;
    byteBoolean timeout = FALSE;

    open_tcp(pCtx);
    ws_test_set_random(mask, sizeof(mask), OK);
    assert_true(ws_test_queue_read(OK, frames, sizeof(frames)));
    /* Control data is handled internally; only the binary payload reaches MQTT. */
    assert_int_equal(WS_mqttTransportRecv(0, pCtx, out, sizeof(out), &received, 100,
        &timeout), OK);
    assert_int_equal(received, 2);
    assert_memory_equal(out, "MQ", 2);
    assert_int_equal(ws_test_write_calls(), 1);
    /* First byte of the reply: FIN (0x80) + Pong opcode (0x0A). */
    assert_int_equal(ws_test_written_data()[0], 0x8A);

    ws_test_mocks_reset();
    ws_test_set_random(mask, sizeof(mask), OK);
    assert_true(ws_test_queue_read(OK, closeFrame, sizeof(closeFrame)));
    /* The server Close triggers a Close echo and the closing state. */
    assert_int_equal(WS_mqttTransportRecv(0, pCtx, out, sizeof(out), &received, 100,
        &timeout), ERR_WS_CLOSE_RECEIVED);
    assert_int_equal(pCtx->state, WS_STATE_CLOSING);
    assert_int_equal(ws_test_write_calls(), 1);
    /* FIN (0x80) + Close opcode (0x08), not an application-data frame. */
    assert_int_equal(ws_test_written_data()[0], 0x88);
}

static void test_receive_ring_wrap_and_closing_state(void **state)
{
    WsContext *pCtx = (WsContext *)*state;
    sbyte out[4] = { 0 };
    ubyte4 received = 0;
    byteBoolean timeout = TRUE;

    /* "abcd" straddles the end of the 256-byte ring: 254, 255, 0, 1. */
    pCtx->pPayloadBuf[254] = 'a';
    pCtx->pPayloadBuf[255] = 'b';
    pCtx->pPayloadBuf[0] = 'c';
    pCtx->pPayloadBuf[1] = 'd';
    pCtx->payloadBufRead = 254; /* Index of the next unread byte ('a'). */
    pCtx->payloadBufWrite = 2;  /* Index where the next decoded byte would go. */
    pCtx->payloadBufFill = 4;   /* Count of unread bytes, not a pointer or index. */
    pCtx->transportType = WS_TRANSPORT_TCP;
    pCtx->state = WS_STATE_CLOSING;

    /* Buffered bytes remain readable while closing; request 3 to leave 'd'. */
    assert_int_equal(WS_mqttTransportRecv(0, pCtx, out, 3, &received, 100,
        &timeout), OK);
    assert_int_equal(received, 3);
    assert_memory_equal(out, "abc", 3);
    assert_int_equal(pCtx->payloadBufFill, 1);
    /* The next call drains the remaining byte; only then is Close reported. */
    assert_int_equal(WS_mqttTransportRecv(0, pCtx, out, sizeof(out), &received,
        100, &timeout), OK);
    assert_int_equal(received, 1);
    assert_int_equal(out[0], 'd');
    assert_int_equal(WS_mqttTransportRecv(0, pCtx, out, sizeof(out), &received,
        100, &timeout), ERR_WS_CLOSE_RECEIVED);

    pCtx->state = WS_STATE_CLOSED;
    /* A fully closed context reports not-open, not a read timeout. */
    assert_int_equal(WS_mqttTransportRecv(0, pCtx, out, sizeof(out), &received,
        100, &timeout), ERR_WS_NOT_OPEN);
    assert_int_equal(received, 0);
    assert_false(timeout);
}

static void test_receive_control_burst_and_protocol_error(void **state)
{
    WsContext *pCtx = (WsContext *)*state;
    const ubyte pong[] = {
        0x8A, /* [0]: FIN + Pong opcode. */
        0     /* [1]: unmasked server frame, zero payload bytes. */
    };
    const ubyte text[] = {
        0x81, /* [0]: FIN + Text opcode, unsupported by this binary transport. */
        1,    /* [1]: unmasked server frame, one payload byte. */
        'x'   /* [2]: text payload; must not be delivered as MQTT data. */
    };
    /* Test-only zero mask: XOR leaves outgoing close-code bytes unchanged. */
    const ubyte mask[4] = { 0, 0, 0, 0 };
    sbyte out[8] = { 0 };
    ubyte4 received = 0;
    byteBoolean timeout = FALSE;
    ubyte4 i;

    open_tcp(pCtx);
    /* The guard uses >, so one beyond the limit exercises its early return. */
    for (i = 0; i < WS_MAX_PING_BURST + 1; i++)
    {
        assert_true(ws_test_queue_read(OK, pong, sizeof(pong)));
    }
    assert_int_equal(WS_mqttTransportRecv(0, pCtx, out, sizeof(out), &received,
        100, &timeout), OK);
    /* Control-only reads yield no MQTT data: timeout flag, not a timeout error.
       This burst guard returns immediately; no real timer expires. */
    assert_true(timeout);
    assert_int_equal(received, 0);

    ws_test_mocks_reset();
    open_tcp(pCtx);
    ws_test_set_random(mask, sizeof(mask), OK);
    assert_true(ws_test_queue_read(OK, text, sizeof(text)));
    /* Reject Text frames and initiate a protocol-error Close (code 1002). */
    assert_int_equal(WS_mqttTransportRecv(0, pCtx, out, sizeof(out), &received,
        100, &timeout), ERR_WS_PROTOCOL_ERROR);
    assert_int_equal(pCtx->state, WS_STATE_CLOSING);
    /* [0]: FIN + Close; [1]: MASK + length 2; [2..5]: zero masking key.
       Payload starts at [6]; 0x03EA is big-endian 1002 (protocol error). */
    assert_int_equal(ws_test_written_data()[0], 0x88);
    assert_int_equal(ws_test_written_data()[6], 0x03);
    assert_int_equal(ws_test_written_data()[7], 0xEA);
}

static void test_graceful_close_timeout_and_interleaved_ping(void **state)
{
    WsContext *pCtx = (WsContext *)*state;
    /* Test-only mask; close payload uses its first two bytes (1 and 2). */
    const ubyte mask[4] = { 1, 2, 3, 4 };
    const ubyte pingAndClose[] = {
        0x89, 0x02, 'o', 'k', /* [0]: FIN + Ping; [1]: unmasked length 2;
                                [2..3]: "ok" must be echoed in the Pong. */
        0x88, 0              /* [4]: FIN + Close; [5]: unmasked, empty payload. */
    };

    open_tcp(pCtx);
    ws_test_set_random(mask, sizeof(mask), OK);
    /* No queued read: mock immediately times out waiting for the peer Close. */
    assert_int_equal(WS_close(pCtx, WS_CLOSE_NORMAL), OK);
    assert_int_equal(pCtx->state, WS_STATE_CLOSED);
    /* 2 header bytes + 4 mask bytes + 2 close-code bytes = 8 wire bytes. */
    assert_int_equal(ws_test_written_len(), 8);
    /* [0]: FIN + Close; [6]: 0x03 XOR 1 = 0x02;
       [7]: 0xE8 XOR 2 = 0xEA (masked normal-close code 1000, not 1002). */
    assert_int_equal(ws_test_written_data()[0], 0x88);
    assert_int_equal(ws_test_written_data()[6], 0x02);
    assert_int_equal(ws_test_written_data()[7], 0xEA);

    ws_test_mocks_reset();
    open_tcp(pCtx);
    assert_true(ws_test_queue_read(OK, pingAndClose, sizeof(pingAndClose)));
    ws_test_set_random(mask, sizeof(mask), OK);
    /* Closing still answers an interleaved Ping before consuming the peer Close. */
    assert_int_equal(WS_close(pCtx, WS_CLOSE_NORMAL), OK);
    assert_int_equal(pCtx->state, WS_STATE_CLOSED);
    assert_int_equal(ws_test_write_calls(), 2);
    /* First Close starts at [0]; the following Pong starts after its 8 bytes. */
    assert_int_equal(ws_test_written_data()[0], 0x88);
    assert_int_equal(ws_test_written_data()[8], 0x8A);
}

static void test_tcp_connect_errors(void **state)
{
    WsContext *pCtx = (WsContext *)*state;
    /* RFC 6455's 16-byte sample nonce; exclude the C string's trailing NUL. */
    const ubyte nonce[] = "the sample nonce";

    ws_test_set_random(nonce, sizeof(nonce) - 1, OK);
    ws_test_set_write_result(ERR_TCP_WRITE_ERROR, 0);
    /* Dummy socket 7, HTTP port 80, no subprotocol, and request path /mqtt.
       A failed request write propagates its error and leaves the context closed. */
    assert_int_equal(WS_connect(pCtx, 7, (const sbyte *)"example.test", 80,
        NULL, (const sbyte *)"/mqtt"), ERR_TCP_WRITE_ERROR);
    assert_int_equal(pCtx->transportType, WS_TRANSPORT_TCP);
    assert_int_equal(pCtx->socket, 7);
    assert_int_equal(pCtx->state, WS_STATE_CLOSED);
    assert_int_equal(ws_test_write_calls(), 1);

    ws_test_mocks_reset();
    ws_test_set_random(nonce, sizeof(nonce) - 1, OK);
    ws_test_set_write_result(OK, 1);
    /* Only one request byte is accepted; the short write fails the handshake. */
    assert_int_equal(WS_connect(pCtx, 7, (const sbyte *)"example.test", 80,
        NULL, (const sbyte *)"/mqtt"), ERR_WS_HANDSHAKE_FAILED);
    assert_int_equal(pCtx->state, WS_STATE_CLOSED);
    assert_int_equal(ws_test_write_calls(), 1);
    assert_int_equal(ws_test_written_len(), 1);

    ws_test_mocks_reset();
    assert_true(ws_test_queue_read(ERR_TCP_READ_TIMEOUT, NULL, 0));
    /* No response before timeout: unlike receive, connect fails the handshake. */
    assert_int_equal(WS_connect(pCtx, 7, (const sbyte *)"example.test", 80,
        NULL, (const sbyte *)"/mqtt"), ERR_WS_HANDSHAKE_FAILED);
    assert_int_equal(pCtx->state, WS_STATE_CLOSED);
    assert_int_equal(ws_test_write_calls(), 1);

    ws_test_mocks_reset();
    assert_true(ws_test_queue_read(OK, NULL, 0));
    /* A successful read with zero bytes represents a peer transport closure. */
    assert_int_equal(WS_connect(pCtx, 7, (const sbyte *)"example.test", 80,
        NULL, (const sbyte *)"/mqtt"), ERR_WS_HANDSHAKE_FAILED);
    assert_int_equal(pCtx->state, WS_STATE_CLOSED);

    ws_test_mocks_reset();
    ws_test_set_random(NULL, 0, WS_TEST_RNG_FAILURE);
    /* Nonce generation failure must prevent any HTTP request from being sent. */
    assert_int_equal(WS_connect(pCtx, 7, (const sbyte *)"example.test", 80,
        NULL, (const sbyte *)"/mqtt"), WS_TEST_RNG_FAILURE);
    assert_int_equal(pCtx->state, WS_STATE_CLOSED);
    assert_int_equal(ws_test_write_calls(), 0);
}

static void test_ssl_handshake_paths(void **state)
{
    WsContext *pCtx = (WsContext *)*state;
    /* RFC sample nonce and its matching Sec-WebSocket-Accept value. */
    const ubyte nonce[] = "the sample nonce";
    const ubyte response[] =
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";

    ws_test_set_random(nonce, sizeof(nonce) - 1, OK);
    assert_true(ws_test_queue_read(OK, response, sizeof(response) - 1));
    /* Dummy TLS instance 19; port 0 omits the port from the HTTP Host header.
       SSL I/O is mocked: verify WebSocket upgrade, not real TLS negotiation. */
    assert_int_equal(WS_connectSSL(pCtx, 19, (const sbyte *)"example.test", 0,
        NULL, (const sbyte *)"/"), OK);
    assert_int_equal(pCtx->state, WS_STATE_OPEN);
    assert_int_equal(ws_test_write_calls(), 1);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_context_lifecycle, setup, teardown),
        cmocka_unit_test_setup_teardown(test_binary_send_and_short_write, setup, teardown),
        cmocka_unit_test_setup_teardown(test_send_requires_open_context, setup, teardown),
        cmocka_unit_test_setup_teardown(test_receive_data_and_timeout, setup, teardown),
        cmocka_unit_test_setup_teardown(test_ping_then_binary_and_close_echo, setup, teardown),
        cmocka_unit_test_setup_teardown(test_receive_ring_wrap_and_closing_state, setup, teardown),
        cmocka_unit_test_setup_teardown(test_receive_control_burst_and_protocol_error, setup, teardown),
        cmocka_unit_test_setup_teardown(test_graceful_close_timeout_and_interleaved_ping, setup, teardown),
        cmocka_unit_test_setup_teardown(test_tcp_connect_errors, setup, teardown),
        cmocka_unit_test_setup_teardown(test_ssl_handshake_paths, setup, teardown)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
