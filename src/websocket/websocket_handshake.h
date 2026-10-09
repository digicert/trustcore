/*
 * websocket_handshake.h
 *
 * WebSocket HTTP/1.1 Upgrade Handshake Interface (RFC 6455 §4)
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

#ifndef __WEBSOCKET_HANDSHAKE_HEADER__
#define __WEBSOCKET_HANDSHAKE_HEADER__

#include "websocket_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ENABLE_DIGICERT_WEBSOCKET_CLIENT__)

/*------------------------------------------------------------------*/

/*
 * Generate the Sec-WebSocket-Key value.
 * Fills pRawKey16 (16 bytes) with random data and base64-encodes it
 * into pBase64Key. Caller must provide WS_KEY_BASE64_LEN+1 bytes.
 */
MOC_EXTERN MSTATUS WS_generateKey(ubyte *pRawKey16, sbyte *pBase64Key);

/*
 * Compute the expected Sec-WebSocket-Accept header value:
 *   base64( SHA1( pBase64Key + WS_GUID ) )
 * pAcceptOut must be at least 29 bytes (28 base64 chars + NUL).
 */
MOC_EXTERN MSTATUS WS_computeAccept(const sbyte *pBase64Key, sbyte *pAcceptOut);

/*
 * Format the HTTP GET upgrade request into pBuf.
 * port == 0 omits the port from the Host header (use scheme default).
 * Sets *pWritten to bytes written.
 */
MOC_EXTERN MSTATUS WS_buildUpgradeRequest(
    const sbyte *pHost,
    ubyte2      port,
    const sbyte *pPath,
    const sbyte *pSubProtocol,
    const sbyte *pBase64Key,
    sbyte       *pBuf,
    ubyte4      bufLen,
    ubyte4      *pWritten);

/*
 * Parse the server's HTTP 101 response in pResponse.
 * Verifies status line, Upgrade, Connection, Sec-WebSocket-Accept,
 * and rejects unsolicited extensions.
 */
MOC_EXTERN MSTATUS WS_parseUpgradeResponse(
    const sbyte *pResponse,
    ubyte4      responseLen,
    const sbyte *pSubProtocol,
    const sbyte *pBase64Key);

/*
 * Perform the full HTTP/1.1 webSocket upgrade handshake over the
 * transport already stored in pCtx.
 * port == 0 uses the scheme default and omits port from Host header.
 * On success: pCtx->state is set to WS_STATE_OPEN.
 */
MOC_EXTERN MSTATUS WS_performHandshake(
    WsContext   *pCtx,
    const sbyte *pHost,
    ubyte2      port,
    const sbyte *pSubProtocol,
    const sbyte *pPath);

#endif /* __ENABLE_DIGICERT_WEBSOCKET_CLIENT__ */

#ifdef __cplusplus
}
#endif

#endif /* __WEBSOCKET_HANDSHAKE_HEADER__ */
