/*
 * websocket.h
 *
 * WebSocket Client — Public API
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

#ifndef __WEBSOCKET_HEADER__
#define __WEBSOCKET_HEADER__

#include "websocket_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ENABLE_DIGICERT_WEBSOCKET_CLIENT__)

/*------------------------------------------------------------------*/

/*
 * Allocate and zero-initialise a WsContext.
 * Sets state to WS_STATE_CLOSED.
 * Allocates a payload ring buffer of payloadBufSize bytes.
 */
MOC_EXTERN MSTATUS WS_createContext(WsContext **ppCtx, ubyte4 payloadBufSize);

/*
 * Free a WsContext allocated by WS_createContext.
 * Doesn't close the underlying socket or SSL session.
 * Sets *ppCtx = NULL on return.
 */
MOC_EXTERN void WS_freeContext(WsContext **ppCtx);

/*
 * Perform HTTP/1.1 webSocket upgrade over an already open TCP socket.
 * port == 0 uses default (80) and omits port from Host header.
 * On success: pCtx->state is set to WS_STATE_OPEN.
 */
MOC_EXTERN MSTATUS WS_connect(
    WsContext   *pCtx,
    TCP_SOCKET  socket,
    const sbyte *pHost,
    ubyte2      port,
    const sbyte *pSubProtocol,
    const sbyte *pPath);

/*
 * Perform HTTP/1.1 WebSocket upgrade over an already completed TLS session.
 * port == 0 uses default (443) and omits port from Host header.
 * On success: pCtx->state is set to WS_STATE_OPEN.
 */
MOC_EXTERN MSTATUS WS_connectSSL(
    WsContext   *pCtx,
    sbyte4      sslConnInst,
    const sbyte *pHost,
    ubyte2      port,
    const sbyte *pSubProtocol,
    const sbyte *pPath);

/*
 * Initiate a graceful webSocket close.
 * Sends a masked close frame, drains until the server's close is received
 * or a read timeout happens, then sets pCtx->state to WS_STATE_CLOSED.
 * Doesn't close the underlying TCP or SSL connection.
 */
MOC_EXTERN MSTATUS WS_close(WsContext *pCtx, WsCloseCode closeCode);

/*
 * MQTT transport send callback.
 * Wraps pBuffer in a masked WebSocket binary frame and writes it
 * to the underlying transport (websocket).
 */
MOC_EXTERN MSTATUS WS_mqttTransportSend(
    sbyte4 connectionInstance,
    void   *pTransportCtx,
    sbyte  *pBuffer,
    ubyte4 bufferLen);

/*
 * MQTT transport recv callback.
 * Reads inbound webSocket frames, strips framing and returns raw MQTT bytes.
 * Handles ping frames transparently (sends pong and continues).
 */
MOC_EXTERN MSTATUS WS_mqttTransportRecv(
    sbyte4      connectionInstance,
    void        *pTransportCtx,
    sbyte       *pBuffer,
    ubyte4      bufferLen,
    ubyte4      *pNumBytesReceived,
    ubyte4      timeoutMS,
    byteBoolean *pTimeout);

#endif /* __ENABLE_DIGICERT_WEBSOCKET_CLIENT__ */

#ifdef __cplusplus
}
#endif

#endif /* __WEBSOCKET_HEADER__ */
