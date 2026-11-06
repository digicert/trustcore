#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "websocket/websocket_frame.h"
#include "test_mocks.h"

static int setup(void **state)
{
    (void)state;
    ws_test_mocks_reset();
    return 0;
}

static void init_context(WsContext *pCtx, ubyte *pBuffer, ubyte4 bufferSize)
{
    memset(pCtx, 0, sizeof(*pCtx));
    pCtx->pPayloadBuf = pBuffer;
    pCtx->payloadBufSize = bufferSize;
    pCtx->parseState = WS_PARSE_HEADER_BYTE1;
    pCtx->state = WS_STATE_OPEN;
}

static void test_mask_vector_and_offset(void **state)
{
    const ubyte key[4] = { 0x37, 0xFA, 0x21, 0x3D };
    ubyte data[9] = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    /* Each output byte is input[i] XOR key[i modulo 4]. */
    const ubyte expected[9] = { 0x36, 0xF8, 0x22, 0x39, 0x32, 0xFC, 0x26, 0x35, 0x3E };
    const ubyte splitExpected[5] = { 0xFF, 0x27, 0x3A, 0x3F, 0xF3 };
    ubyte split[5] = { 5, 6, 7, 8, 9 };

    (void)state;
    WS_applyMask(data, sizeof(data), key, 0);
    assert_memory_equal(data, expected, sizeof(expected));
    /* Offset 1 proves the offset is honoured: key rotation starts at key[1]. */
    WS_applyMask(split, sizeof(split), key, 1);
    assert_memory_equal(split, splitExpected, sizeof(splitExpected));
}

static void test_encoded_bytes_and_boundaries(void **state)
{
    const ubyte key[4] = { 0x37, 0xFA, 0x21, 0x3D };
    const ubyte payload[] = { 'H', 'i' };
    /* FIN+binary, masked length 2, key, then 'H' XOR key[0] and 'i' XOR key[1]. */
    const ubyte expected[] = { 0x82, 0x82, 0x37, 0xFA, 0x21, 0x3D, 0x7F, 0x93 };
    /* 65536 encoded as the low 8 bytes of the protocol's 64-bit length field. */
    const ubyte extendedLength64[] = { 0, 0, 0, 0, 0, 1, 0, 0 };
    /* Probe both sides of the short/16-bit/64-bit payload-length boundaries. */
    const ubyte4 lengths[] = { 0, 1, 125, 126, 65535, 65536 };
    ubyte testPayload[65536];
    ubyte *pFrame = NULL;
    ubyte4 frameLen = 0;
    ubyte4 i;

    (void)state;
    memset(testPayload, 0x5A, sizeof(testPayload));
    assert_int_equal(WS_frameEncode(payload, sizeof(payload), WS_OP_BINARY, key, &pFrame, &frameLen), OK);
    /* Encoding succeeded and produced exactly the expected frame bytes. */
    assert_int_equal(frameLen, sizeof(expected));
    assert_memory_equal(pFrame, expected, sizeof(expected));
    assert_int_equal(DIGI_FREE((void **)&pFrame), OK);

    for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++)
    {
        ubyte4 len = lengths[i];
        /* Client frames include a 2/4/10-byte header plus the 4-byte mask key. */
        ubyte4 headerLen = (len <= 125) ? 6 : ((len <= 65535) ? 8 : 14);
        assert_int_equal(WS_frameEncode(testPayload, len, WS_OP_BINARY, key, &pFrame, &frameLen), OK);
        /* Check total frame size and the FIN+binary opcode. */
        assert_int_equal(frameLen, headerLen + len);
        assert_int_equal(pFrame[0], 0x82);
        /* The mask key immediately precedes the payload (also when payload is empty). */
        assert_int_equal(pFrame[headerLen - 4], key[0]);
        if (len <= 125)
        {
            assert_int_equal(pFrame[1], (ubyte)(0x80 | len));
        }
        else if (len <= 65535)
        {
            assert_int_equal(pFrame[1], 0xFE);
            assert_int_equal(pFrame[2], (ubyte)(len >> 8));
            assert_int_equal(pFrame[3], (ubyte)len);
        }
        else
        {
            assert_int_equal(pFrame[1], 0xFF);
            assert_memory_equal(pFrame + 2, extendedLength64, sizeof(extendedLength64));
        }
        assert_int_equal(DIGI_FREE((void **)&pFrame), OK);
    }
}

static void test_incremental_decode_and_coalesced_frames(void **state)
{
    WsContext ctx;
    ubyte payload[8] = { 0 };
    /* Two unmasked server binary frames: "MQT", followed by "TT". */
    const ubyte raw[] = { 0x82, 0x03, 'M', 'Q', 'T', 0x82, 0x02, 'T', 'T' };
    ubyte4 consumed = 0;
    ubyte4 i;

    (void)state;
    init_context(&ctx, payload, sizeof(payload));
    for (i = 0; i < 5; i++)
    {
        assert_int_equal(WS_frameDecode(&ctx, raw + i, 1, &consumed), OK);
        /* Each call is given one raw byte, so it must consume exactly that byte. */
        assert_int_equal(consumed, 1);
    }
    /* First frame decoded into the payload ring buffer. */
    assert_int_equal(ctx.payloadBufFill, 3);
    assert_memory_equal(payload, "MQT", 3);
    assert_int_equal(WS_frameDecode(&ctx, raw + 5, sizeof(raw) - 5, &consumed), OK);
    /* The decoder consumes the entire remaining input, including the second frame. */
    assert_int_equal(consumed, sizeof(raw) - 5);
    assert_int_equal(ctx.payloadBufFill, 5);
    assert_memory_equal(payload, "MQTTT", 5);
}

static void test_decoder_rejects_invalid_headers(void **state)
{
    WsContext ctx;
    ubyte payload[8] = { 0 };
    ubyte4 consumed = 0;
    const ubyte masked[] = { 0x82, 0x80 }; /* Server frame illegally sets the client-mask bit. */
    const ubyte reserved[] = { 0xC2 }; /* Binary opcode with a reserved RSV bit set. */
    const ubyte noncanonical16[] = { 0x82, 126, 0, 125 }; /* Length 125 must use the short form. */
    const ubyte noncanonical64[] = { 0x82, 127, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF }; /* 65535 fits the 16-bit form. */
    const ubyte huge64[] = { 0x82, 127, 0, 0, 0, 1, 0, 0, 0, 0 }; /* 2^32-byte payload exceeds supported size. */
    const ubyte highBit64[] = { 0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0 }; /* Top bit of 64-bit length is forbidden. */
    const struct
    {
        const ubyte *data;
        ubyte4 len;
        MSTATUS expected;
    } cases[] = {
        /* The masked/reserved/noncanonical/high-bit cases are protocol errors. */
        { masked, sizeof(masked), ERR_WS_PROTOCOL_ERROR },
        { reserved, sizeof(reserved), ERR_WS_PROTOCOL_ERROR },
        { noncanonical16, sizeof(noncanonical16), ERR_WS_PROTOCOL_ERROR },
        { noncanonical64, sizeof(noncanonical64), ERR_WS_PROTOCOL_ERROR },
        { huge64, sizeof(huge64), ERR_WS_PAYLOAD_TOO_LARGE },
        { highBit64, sizeof(highBit64), ERR_WS_PROTOCOL_ERROR }
    };
    ubyte4 i;

    (void)state;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        init_context(&ctx, payload, sizeof(payload));
        assert_int_equal(WS_frameDecode(&ctx, cases[i].data, cases[i].len, &consumed), cases[i].expected);
        /* Even on rejection, the decoder must report consuming input so callers can progress. */
        assert_true(consumed > 0);
    }
}

static void test_ping_close_and_ring_capacity(void **state)
{
    WsContext ctx;
    ubyte payload[4] = { 0 };
    ubyte4 consumed = 0;
    const ubyte ping[] = { 0x89, 0x02, 'o', 'k' }; /* Final Ping frame with a 2-byte payload. */
    const ubyte close[] = { 0x88, 0x02, 0x03, 0xE8 }; /* Close frame carrying status 1000 (normal close). */
    const ubyte full[] = { 0x82, 0x05, 'h', 'e', 'l', 'l', 'o' }; /* 5-byte data frame for a 4-byte ring. */

    (void)state;
    init_context(&ctx, payload, sizeof(payload));
    assert_int_equal(WS_frameDecode(&ctx, ping, sizeof(ping), &consumed), WS_NEED_PONG);
    assert_int_equal(consumed, sizeof(ping));
    assert_int_equal(ctx.pingPayloadLen, 2);
    assert_memory_equal(ctx.pingPayload, "ok", 2);

    assert_int_equal(WS_frameDecode(&ctx, close, sizeof(close), &consumed), ERR_WS_CLOSE_RECEIVED);
    /* Close payload is saved so the transport can echo the peer's close status. */
    assert_int_equal(consumed, sizeof(close));
    assert_true(ctx.closeEchoPayloadValid);
    assert_int_equal(ctx.closeEchoPayload[0], 0x03);
    assert_int_equal(ctx.closeEchoPayload[1], 0xE8);
    assert_int_equal(ctx.state, WS_STATE_CLOSING);

    init_context(&ctx, payload, sizeof(payload));
    assert_int_equal(WS_frameDecode(&ctx, full, sizeof(full), &consumed), ERR_WS_BUFFER_FULL);
    /* Decoder consumes the 2-byte header, sees 5 bytes cannot fit, and rejects before payload copy. */
    assert_int_equal(consumed, 2);
}

static void test_control_frame_limits_and_close_codes(void **state)
{
    WsContext ctx;
    ubyte payload[8] = { 0 };
    ubyte4 consumed = 0;
    ubyte closeFrame[4] = { 0x88, 0x02, 0, 0 };
    /* Control length > 125 would overflow pingPayload[125]; reject at the header. */
    const ubyte pingTooLong[] = { 0x89, 126, 0, 126 };
    const ubyte pingFragmented[] = { 0x09, 0x00 };
    const ubyte closeOneByte[] = { 0x88, 0x01, 0x03 };
    const ubyte4 badCodes[] = { 999, 1004, 1005, 1006, 1015, 5000 };
    const ubyte4 goodCodes[] = { 1000, 1011, 3000 };
    ubyte4 i;

    (void)state;
    init_context(&ctx, payload, sizeof(payload));
    assert_int_equal(WS_frameDecode(&ctx, pingTooLong, sizeof(pingTooLong), &consumed), ERR_WS_PROTOCOL_ERROR);
    assert_int_equal(consumed, 2);

    init_context(&ctx, payload, sizeof(payload));
    assert_int_equal(WS_frameDecode(&ctx, pingFragmented, sizeof(pingFragmented), &consumed), ERR_WS_PROTOCOL_ERROR);
    assert_int_equal(consumed, 2);

    init_context(&ctx, payload, sizeof(payload));
    assert_int_equal(WS_frameDecode(&ctx, closeOneByte, sizeof(closeOneByte), &consumed), ERR_WS_PROTOCOL_ERROR);
    assert_int_equal(consumed, 2);

    for (i = 0; i < sizeof(badCodes) / sizeof(badCodes[0]); i++)
    {
        init_context(&ctx, payload, sizeof(payload));
        closeFrame[2] = (ubyte)(badCodes[i] >> 8);
        closeFrame[3] = (ubyte)badCodes[i];
        assert_int_equal(WS_frameDecode(&ctx, closeFrame, sizeof(closeFrame), &consumed), ERR_WS_PROTOCOL_ERROR);
    }

    for (i = 0; i < sizeof(goodCodes) / sizeof(goodCodes[0]); i++)
    {
        init_context(&ctx, payload, sizeof(payload));
        closeFrame[2] = (ubyte)(goodCodes[i] >> 8);
        closeFrame[3] = (ubyte)goodCodes[i];
        assert_int_equal(WS_frameDecode(&ctx, closeFrame, sizeof(closeFrame), &consumed), ERR_WS_CLOSE_RECEIVED);
    }
}

static void test_mask_rng_result_and_error(void **state)
{
    ubyte key[4] = { 0 };
    /* Deterministic test key; not suitable for production cryptography. */
    const ubyte fixture[4] = { 9, 8, 7, 6 };

    (void)state;
    ws_test_set_random(fixture, sizeof(fixture), OK);
    assert_int_equal(WS_generateMaskKey(key), OK);
    /* Generated key should exactly match the bytes supplied by the RNG mock. */
    assert_memory_equal(key, fixture, sizeof(fixture));
    ws_test_set_random(fixture, sizeof(fixture), WS_TEST_RNG_FAILURE);
    assert_int_equal(WS_generateMaskKey(key), WS_TEST_RNG_FAILURE);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_mask_vector_and_offset, setup),
        cmocka_unit_test_setup(test_encoded_bytes_and_boundaries, setup),
        cmocka_unit_test_setup(test_incremental_decode_and_coalesced_frames, setup),
        cmocka_unit_test_setup(test_decoder_rejects_invalid_headers, setup),
        cmocka_unit_test_setup(test_ping_close_and_ring_capacity, setup),
        cmocka_unit_test_setup(test_control_frame_limits_and_close_codes, setup),
        cmocka_unit_test_setup(test_mask_rng_result_and_error, setup)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
