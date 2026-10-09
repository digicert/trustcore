/*
 * websocket_frame.c
 *
 * WebSocket Frame Encode/Decode (RFC 6455 §5)
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

#if defined(__ENABLE_DIGICERT_WEBSOCKET_CLIENT__)

#include "websocket_defs.h"
#include "websocket_frame.h"
#include "../common/random.h"

/*----------------------------------------------------------------------------*/

static void WS_resetParseFields(WsContext *pCtx)
{
    pCtx->parseState          = WS_PARSE_HEADER_BYTE1;
    pCtx->extLenBytesExpected = 0;
    pCtx->extLenBytesRead     = 0;
    pCtx->payloadBytesRead    = 0;
    DIGI_MEMSET(pCtx->extLenBuf, 0x00, sizeof(pCtx->extLenBuf));
}

/*----------------------------------------------------------------------------*/

extern MSTATUS WS_generateMaskKey(ubyte *pMaskKey)
{
    return RANDOM_numberGenerator(g_pRandomContext, pMaskKey, 4);
}

/*----------------------------------------------------------------------------*/

extern void WS_applyMask(ubyte *pData, ubyte4 len, const ubyte *pMaskKey, ubyte4 offset)
{
    ubyte4 i;
    for (i = 0; i < len; i++)
    {
        pData[i] ^= pMaskKey[(offset + i) & 3];
    }
}

/*----------------------------------------------------------------------------*/

/* reserved codes that can't appear on the wire */
static byteBoolean WS_isValidCloseCode(ubyte2 code)
{
    if (code < 1000  || code > 4999 ||
        1004 == code ||
        1005 == code ||
        1006 == code ||
        1015 == code)
    {
        return FALSE;
    }

    return TRUE;
}

/*----------------------------------------------------------------------------*/

/*
+---------------------------------------------------------------+
 0                   1                   2                   3  |
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1|
+-+-+-+-+-------+-+-------------+-------------------------------+
|F|R|R|R| opcode|M| Payload len |    Extended payload length    |
|I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
|N|V|V|V|       |S|             |   (if payload len==126/127)   |
| |1|2|3|       |K|             |                               |
+-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
|     Extended payload length continued, if payload len == 127  |
+ - - - - - - - - - - - - - - - +-------------------------------+
|                               | Masking-key, if MASK set to 1 |
+-------------------------------+-------------------------------+
| Masking-key (continued)       |          Payload Data         |
+-------------------------------- - - - - - - - - - - - - - - - +
:                     Payload Data continued ...                :
+ - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
|                     Payload Data continued ...                |
+---------------------------------------------------------------+
*/

extern MSTATUS WS_frameEncode(
    const ubyte *pPayload,
    ubyte4      payloadLen,
    WsOpcode    opcode,
    const ubyte *pMaskKey,
    ubyte       **ppFrame,
    ubyte4      *pFrameLen)
{
    MSTATUS status   = OK;
    ubyte  *pFrame   = NULL;
    ubyte4 headerLen = 0;
    ubyte4 frameLen  = 0;
    ubyte4 hIdx      = 0;

    /* 2 initial bytes + 4 bytes Masking-key are fixed */
    if (payloadLen <= 125)
    {
        headerLen = 2 + 4;
    }
    else if (payloadLen <= 0xFFFF)
    {
        headerLen = 2 + 2 + 4;
    }
    else
    {
        headerLen = 2 + 8 + 4;
    }

    if (payloadLen > 0xFFFFFFFFu - headerLen)
    {
        status = ERR_WS_PAYLOAD_TOO_LARGE;
        goto exit;
    }

    frameLen = headerLen + payloadLen;

    status = DIGI_MALLOC((void **)&pFrame, frameLen);
    if (OK != status)
    {
        goto exit;
    }

    /* Byte 0: FIN=1, RSV=0, opcode
     * Fragmentation is disabled since FIN=1 always
     */
    pFrame[hIdx++] = (ubyte)(0x80 | (ubyte)opcode);

    /* Byte 1 + extended length, MASK=1 always (client -> server) */
    if (payloadLen <= 125)
    {
        pFrame[hIdx++] = (ubyte)(0x80 | payloadLen);
    }
    else if (payloadLen <= 0xFFFF)
    {
        pFrame[hIdx++] = (ubyte)(0x80 | 126);
        pFrame[hIdx++] = (ubyte)(payloadLen >> 8);
        pFrame[hIdx++] = (ubyte)payloadLen;
    }
    else
    {
        pFrame[hIdx++] = (ubyte)(0x80 | 127);
        /* This implementation uses 32-bits out of 64-bits for extended len bytes
         * since payloadLen is ubyte4 so high bits are all set to 0.
         * Thus it support maximum ~4GB length frames.
         */

        pFrame[hIdx++] = 0;
        pFrame[hIdx++] = 0;
        pFrame[hIdx++] = 0;
        pFrame[hIdx++] = 0;
        pFrame[hIdx++] = (ubyte)(payloadLen >> 24);
        pFrame[hIdx++] = (ubyte)(payloadLen >> 16);
        pFrame[hIdx++] = (ubyte)(payloadLen >>  8);
        pFrame[hIdx++] = (ubyte)payloadLen;
    }

    pFrame[hIdx++] = pMaskKey[0];
    pFrame[hIdx++] = pMaskKey[1];
    pFrame[hIdx++] = pMaskKey[2];
    pFrame[hIdx++] = pMaskKey[3];

    if (payloadLen > 0 && NULL == pPayload)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Close frames can have an empty payload. */
    if (payloadLen > 0)
    {
        status = DIGI_MEMCPY(pFrame + hIdx, pPayload, payloadLen);
        if (OK != status)
        {
            goto exit;
        }

        WS_applyMask(pFrame + hIdx, payloadLen, pMaskKey, 0);
    }

    *ppFrame   = pFrame;
    *pFrameLen = frameLen;
    pFrame     = NULL;

exit:
    if (NULL != pFrame)
    {
        DIGI_FREE((void **)&pFrame);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS WS_frameDecode(
    WsContext   *pCtx,
    const ubyte *pRawBytes,
    ubyte4      rawLen,
    ubyte4      *pConsumed)
{
    MSTATUS status = OK;
    ubyte4 offset = 0;
    ubyte4 toRead = 0;
    ubyte4 avail  = 0;
    ubyte4 chunk  = 0;
    ubyte4 spaceAtEnd = 0;
    ubyte lenField, b = 0;
    byteBoolean frameComplete;

    if (0 == rawLen)
    {
        *pConsumed = 0;
        goto exit;
    }

    while (offset < rawLen)
    {
        frameComplete = FALSE;

        switch (pCtx->parseState)
        {
            case WS_PARSE_HEADER_BYTE1:
                b = pRawBytes[offset++];

                /* RSV1-RSV3 must be 0 if no extensions negotiated */
                if (b & 0x70)
                {
                    *pConsumed = offset;
                    status = ERR_WS_PROTOCOL_ERROR;
                    goto exit;
                }

                pCtx->fin = (b & 0x80) ? TRUE : FALSE;
                pCtx->curOpcode = b & 0x0F;

                switch (pCtx->curOpcode)
                {
                    case WS_OP_BINARY:
                    case WS_OP_CLOSE:
                    case WS_OP_PING:
                    case WS_OP_PONG:
                        break;

                    default:
                        /* Continuation, text and all reserved opcodes */
                        *pConsumed = offset;
                        status = ERR_WS_PROTOCOL_ERROR;
                        goto exit;
                }

                pCtx->parseState = WS_PARSE_HEADER_BYTE2;
                break;

            case WS_PARSE_HEADER_BYTE2:
                b = pRawBytes[offset++];

                /* server -> client frames must never be masked */
                if (b & 0x80)
                {
                    *pConsumed = offset;
                    status = ERR_WS_PROTOCOL_ERROR;
                    goto exit;
                }

                lenField = b & 0x7F;

                /* control frames must not be fragmented and payload should be <= 125 */
                if (pCtx->curOpcode >= WS_OP_CLOSE && (FALSE == pCtx->fin || lenField > 125))
                {
                    *pConsumed = offset;
                    status = ERR_WS_PROTOCOL_ERROR;
                    goto exit;
                }

                /* For binary frames fragmentation is not supported */
                if (WS_OP_BINARY == pCtx->curOpcode && FALSE == pCtx->fin)
                {
                    *pConsumed = offset;
                    status = ERR_WS_PROTOCOL_ERROR;
                    goto exit;
                }

                if (lenField <= 125)
                {
                    pCtx->payloadLen = (ubyte4)lenField;
                    pCtx->extLenBytesExpected = 0;

                    if (WS_OP_BINARY == pCtx->curOpcode &&
                        pCtx->payloadLen > pCtx->payloadBufSize - pCtx->payloadBufFill)
                    {
                        *pConsumed = offset;
                        status = ERR_WS_BUFFER_FULL;
                        goto exit;
                    }

                    pCtx->parseState = WS_PARSE_PAYLOAD;
                }
                else if (126 == lenField)
                {
                    pCtx->extLenBytesRead = 0;
                    pCtx->extLenBytesExpected = 2;
                    pCtx->parseState = WS_PARSE_EXT_LEN;
                }
                else /* 127 */
                {
                    pCtx->extLenBytesRead = 0;
                    pCtx->extLenBytesExpected = 8;
                    pCtx->parseState = WS_PARSE_EXT_LEN;
                }

                break;

            case WS_PARSE_EXT_LEN:
                toRead = pCtx->extLenBytesExpected - pCtx->extLenBytesRead;
                avail = rawLen - offset;
                chunk = (avail < toRead) ? avail : toRead;

                status = DIGI_MEMCPY(pCtx->extLenBuf + pCtx->extLenBytesRead, pRawBytes + offset, chunk);
                if (OK != status)
                {
                    *pConsumed = offset;
                    goto exit;

                }

                pCtx->extLenBytesRead += chunk;
                offset += chunk;

                if (pCtx->extLenBytesRead < pCtx->extLenBytesExpected)
                {
                    /* need more bytes, outer while will exit */
                    break;
                }

                if (2 == pCtx->extLenBytesExpected)
                {
                    pCtx->payloadLen = ((ubyte4)pCtx->extLenBuf[0] << 8)
                                    |  (ubyte4)pCtx->extLenBuf[1];

                    /* 2 byte length must be used only for values 126..65535 */
                    if (pCtx->payloadLen < 126)
                    {
                        *pConsumed = offset;
                        status = ERR_WS_PROTOCOL_ERROR;
                        goto exit;
                    }
                }
                else /* 8-byte extended length */
                {
                    /* MSB must be 0 */
                    if (pCtx->extLenBuf[0] & 0x80)
                    {
                        *pConsumed = offset;
                        status = ERR_WS_PROTOCOL_ERROR;
                        goto exit;
                    }

                    /* High 32 bits must be 0 to fit in ubyte4 */
                    if (pCtx->extLenBuf[0] || pCtx->extLenBuf[1] ||
                        pCtx->extLenBuf[2] || pCtx->extLenBuf[3])
                    {
                        *pConsumed = offset;
                        status = ERR_WS_PAYLOAD_TOO_LARGE;
                        goto exit;
                    }

                    pCtx->payloadLen = ((ubyte4)pCtx->extLenBuf[4] << 24)
                                    | ((ubyte4)pCtx->extLenBuf[5] << 16)
                                    | ((ubyte4)pCtx->extLenBuf[6] <<  8)
                                    |  (ubyte4)pCtx->extLenBuf[7];

                    /* 8 byte length must be used only for values > 65535 */
                    if (pCtx->payloadLen <= 0xFFFF)
                    {
                        *pConsumed = offset;
                        status = ERR_WS_PROTOCOL_ERROR;
                        goto exit;
                    }
                }

                if (WS_OP_BINARY == pCtx->curOpcode &&
                    pCtx->payloadLen > pCtx->payloadBufSize - pCtx->payloadBufFill)
                {
                    *pConsumed = offset;
                    status = ERR_WS_BUFFER_FULL;
                    goto exit;
                }

                pCtx->parseState = WS_PARSE_PAYLOAD;
                break;

            case WS_PARSE_PAYLOAD:
                /* check to handle zero payload control frames */
                if (pCtx->payloadBytesRead < pCtx->payloadLen)
                {
                    avail = rawLen - offset;
                    chunk = pCtx->payloadLen - pCtx->payloadBytesRead;
                    if (avail < chunk)
                    {
                        chunk = avail;
                    }

                    switch (pCtx->curOpcode)
                    {
                        case WS_OP_BINARY:
                            spaceAtEnd = pCtx->payloadBufSize - pCtx->payloadBufWrite;
                            if (chunk <= spaceAtEnd)
                            {
                                status = DIGI_MEMCPY(pCtx->pPayloadBuf + pCtx->payloadBufWrite, pRawBytes + offset, chunk);
                                if (OK != status)
                                {
                                    *pConsumed = offset;
                                    goto exit;
                                }

                                pCtx->payloadBufWrite += chunk;
                                if (pCtx->payloadBufWrite == pCtx->payloadBufSize)
                                {
                                    pCtx->payloadBufWrite = 0;
                                }
                            }
                            else
                            {
                                status = DIGI_MEMCPY(pCtx->pPayloadBuf + pCtx->payloadBufWrite, pRawBytes + offset, spaceAtEnd);
                                if (OK != status)
                                {
                                    *pConsumed = offset;
                                    goto exit;
                                }

                                status = DIGI_MEMCPY(pCtx->pPayloadBuf, pRawBytes + offset + spaceAtEnd, chunk - spaceAtEnd);
                                if (OK != status)
                                {
                                    *pConsumed = offset;
                                    goto exit;
                                }

                                pCtx->payloadBufWrite = chunk - spaceAtEnd;
                            }

                            pCtx->payloadBufFill += chunk;
                            break;

                        case WS_OP_PING:
                            status = DIGI_MEMCPY(pCtx->pingPayload + pCtx->payloadBytesRead, pRawBytes + offset, chunk);
                            if (OK != status)
                            {
                                *pConsumed = offset;
                                goto exit;
                            }
                            break;

                        case WS_OP_CLOSE:
                            if (1 == pCtx->payloadLen)
                            {
                                *pConsumed = offset;
                                status = ERR_WS_PROTOCOL_ERROR;
                                goto exit;
                            }

                            /* Capture up to 2 status code bytes for echoing */
                            if (pCtx->payloadLen >= 2)
                            {
                                ubyte4 i;
                                for (i = 0; i < chunk; i++)
                                {
                                    if (pCtx->payloadBytesRead + i < 2)
                                    {
                                        pCtx->closeEchoPayload[pCtx->payloadBytesRead + i] = pRawBytes[offset + i];
                                    }
                                }

                                if (pCtx->payloadBytesRead < 2 && pCtx->payloadBytesRead + chunk >= 2)
                                {
                                    ubyte2 closeCode = ((ubyte2)pCtx->closeEchoPayload[0] << 8)
                                                     |  (ubyte2)pCtx->closeEchoPayload[1];

                                    if (!WS_isValidCloseCode(closeCode))
                                    {
                                        *pConsumed = offset;
                                        status = ERR_WS_PROTOCOL_ERROR;
                                        goto exit;
                                    }

                                    pCtx->closeEchoPayloadValid = TRUE;
                                }
                            }
                            break;

                        default: /* discard WS_OP_PONG */
                            break;
                    }

                    pCtx->payloadBytesRead += chunk;
                    offset += chunk;
                }

                if (pCtx->payloadBytesRead == pCtx->payloadLen)
                {
                    frameComplete = TRUE;
                }

                if (TRUE == frameComplete)
                {
                    switch (pCtx->curOpcode)
                    {
                        case WS_OP_PING:
                            pCtx->pingPayloadLen = pCtx->payloadLen;
                            WS_resetParseFields(pCtx);
                            *pConsumed = offset;
                            status = WS_NEED_PONG;
                            goto exit;

                        case WS_OP_CLOSE:
                            pCtx->state = WS_STATE_CLOSING;
                            WS_resetParseFields(pCtx);
                            *pConsumed = offset;
                            status = ERR_WS_CLOSE_RECEIVED;
                            goto exit;

                        default: /* WS_OP_BINARY, WS_OP_PONG */
                            WS_resetParseFields(pCtx);
                            break;
                    }
                }
                break;
        }
    }

    *pConsumed = offset;

exit:
    return status;
}

#endif /* __ENABLE_DIGICERT_WEBSOCKET_CLIENT__ */
