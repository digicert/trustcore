/*
 * websocket_frame.h
 *
 * WebSocket Frame Encode/Decode Interface (RFC 6455 §5)
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

#ifndef __WEBSOCKET_FRAME_HEADER__
#define __WEBSOCKET_FRAME_HEADER__

#include "websocket_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ENABLE_DIGICERT_WEBSOCKET_CLIENT__)

/*------------------------------------------------------------------*/

/*
 * Encode pPayload into a masked webSocket frame (client -> server).
 * Allocates *ppFrame internally, caller must free it.
 * pMaskKey must be 4 bytes from WS_generateMaskKey.
 * pPayload may be NULL when payloadLen == 0 (empty control frames).
 */
MOC_EXTERN MSTATUS WS_frameEncode(
    const ubyte *pPayload,
    ubyte4      payloadLen,
    WsOpcode    opcode,
    const ubyte *pMaskKey,
    ubyte       **ppFrame,
    ubyte4      *pFrameLen);

/*
 * Feed raw inbound bytes into the incremental frame parser/decoder.
 * Decoded payload bytes are appended to pCtx->pPayloadBuf (ring buffer).
 * *pConsumed is set to the number of bytes from pRawBytes consumed.
 * Forward-progress invariant: when rawLen > 0, *pConsumed >= 1 on every return path.
 * Return values:
 *  OK (0) on success.
 *  WS_NEED_PONG (1) when a Ping was received and a Pong should be sent.
 *  Negative in case of error.
 */
MOC_EXTERN MSTATUS WS_frameDecode(
    WsContext   *pCtx,
    const ubyte *pRawBytes,
    ubyte4      rawLen,
    ubyte4      *pConsumed);

/* Generate 4 random bytes for use as a frame masking key. */
MOC_EXTERN MSTATUS WS_generateMaskKey(ubyte *pMaskKey);

/*
 * XOR pData in-place with the 4-byte masking key.
 * offset is the byte position of pData[0] within the overall payload
 * so the key rotation is correct when called on a buffer slice.
 */
MOC_EXTERN void WS_applyMask(
    ubyte       *pData,
    ubyte4      len,
    const ubyte *pMaskKey,
    ubyte4      offset);

#endif /* __ENABLE_DIGICERT_WEBSOCKET_CLIENT__ */

#ifdef __cplusplus
}
#endif

#endif /* __WEBSOCKET_FRAME_HEADER__ */
