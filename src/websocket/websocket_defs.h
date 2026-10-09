/*
 * websocket_defs.h
 *
 * WebSocket Client — Types, Constants, and Context Structure
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
 */

/*------------------------------------------------------------------*/

#ifndef __WEBSOCKET_DEFS_HEADER__
#define __WEBSOCKET_DEFS_HEADER__

#include "../common/moptions.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mtcp.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ENABLE_DIGICERT_WEBSOCKET_CLIENT__)

/*------------------------------------------------------------------*/

typedef enum
{
    WS_STATE_CLOSED,
    WS_STATE_CONNECTING,
    WS_STATE_OPEN,
    WS_STATE_CLOSING
} WsState;

typedef enum
{
    WS_TRANSPORT_TCP,
    WS_TRANSPORT_SSL
} WsTransportType;

typedef enum
{
    WS_OP_CONTINUATION = 0x0,
    WS_OP_TEXT         = 0x1,
    WS_OP_BINARY       = 0x2,
    WS_OP_CLOSE        = 0x8,
    WS_OP_PING         = 0x9,
    WS_OP_PONG         = 0xA
} WsOpcode;

typedef enum
{
    WS_CLOSE_NORMAL               = 1000,
    WS_CLOSE_GOING_AWAY           = 1001,
    WS_CLOSE_PROTOCOL_ERROR       = 1002,
    WS_CLOSE_UNSUPPORTED_DATA     = 1003,
    WS_CLOSE_INVALID_PAYLOAD      = 1007,
    WS_CLOSE_POLICY_VIOLATION     = 1008,
    WS_CLOSE_MESSAGE_TOO_BIG      = 1009,
    WS_CLOSE_MESSAGE_NO_EXTENSION = 1010,
    WS_CLOSE_INTERNAL_ERROR       = 1011
} WsCloseCode;

typedef enum
{
    WS_PARSE_HEADER_BYTE1,
    WS_PARSE_HEADER_BYTE2,
    WS_PARSE_EXT_LEN,
    WS_PARSE_PAYLOAD
} WsFrameParseState;

/*------------------------------------------------------------------*/

#ifndef WS_PAYLOAD_BUF_SIZE
#define WS_PAYLOAD_BUF_SIZE        16384
#endif

#ifndef WS_MAX_PING_BURST
#define WS_MAX_PING_BURST          16
#endif

#ifndef WS_RAW_BUF_SIZE
#define WS_RAW_BUF_SIZE   2048
#endif

#ifndef WS_HANDSHAKE_TIMEOUT_MS
#define WS_HANDSHAKE_TIMEOUT_MS    5000
#endif

#define WS_GUID                    "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define WS_KEY_NONCE_LEN           16
#define WS_KEY_BASE64_LEN          24

/* Signals caller to send a Pong immediately */
#define WS_NEED_PONG            1

/*------------------------------------------------------------------*/

typedef struct WsContext
{
    WsState         state;
    WsTransportType transportType;

    TCP_SOCKET  socket;
    sbyte4      sslConnInst;

    WsFrameParseState parseState;
    ubyte             curOpcode;
    byteBoolean       fin;
    ubyte4            extLenBytesExpected;
    ubyte4            extLenBytesRead;
    ubyte             extLenBuf[8];
    ubyte4            payloadLen;
    ubyte4            payloadBytesRead;

    ubyte  pingPayload[125];
    ubyte4 pingPayloadLen;

    /* Status code from server close frame echoed in the close response */
    ubyte       closeEchoPayload[2];
    byteBoolean closeEchoPayloadValid;

    /* Decoded payload raw MQTT bytes placed in ring buffer */
    ubyte *pPayloadBuf;
    ubyte4 payloadBufSize;
    ubyte4 payloadBufRead;
    ubyte4 payloadBufWrite;
    ubyte4 payloadBufFill;
} WsContext;

#endif /* __ENABLE_DIGICERT_WEBSOCKET_CLIENT__ */

#ifdef __cplusplus
}
#endif

#endif /* __WEBSOCKET_DEFS_HEADER__ */
