/*
 * websocket.c
 *
 * WebSocket Client — Public API and MQTT Transport Callbacks
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

#include "websocket.h"
#include "websocket_frame.h"
#include "websocket_handshake.h"

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
#include "../ssl/ssl.h"
#endif

/*----------------------------------------------------------------------------*/

/* Write frameLen bytes to the transport in pCtx */
static MSTATUS WS_transportWrite(WsContext *pCtx, sbyte *pFrame, ubyte4 frameLen)
{
    MSTATUS status = OK;

    /* one shot tcp/ssl write */
    if (WS_TRANSPORT_TCP == pCtx->transportType)
    {
        ubyte4 written = 0;
        status = TCP_WRITE(pCtx->socket, pFrame, frameLen, &written);
        if (OK != status)
        {
            goto exit;
        }

        if (written != frameLen)
        {
            status = ERR_WS;
            goto exit;
        }
    }
    else
    {
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
        sbyte4 sent = SSL_send(pCtx->sslConnInst, pFrame, (sbyte4)frameLen);
        if (sent < 0)
        {
            status = sent;
            goto exit;
        }

        if ((ubyte4)sent != frameLen)
        {
            status = ERR_WS;
            goto exit;
        }
#else
        status = ERR_WS;
        goto exit;
#endif
    }

exit:
    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS WS_createContext(WsContext **ppCtx, ubyte4 payloadBufSize)
{
    MSTATUS   status = OK;
    WsContext *pCtx  = NULL;

    if (0 == payloadBufSize)
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    status = DIGI_MALLOC((void **)&pCtx, sizeof(WsContext));
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_MEMSET((ubyte *)pCtx, 0x00, sizeof(WsContext));
    if (OK != status)
    {
        goto exit;
    }

    pCtx->state = WS_STATE_CLOSED;
    pCtx->payloadBufSize = payloadBufSize;

    status = DIGI_MALLOC((void **)&pCtx->pPayloadBuf, pCtx->payloadBufSize);
    if (OK != status)
    {
        goto exit;
    }

    *ppCtx = pCtx;
    pCtx   = NULL;

exit:
    if (NULL != pCtx)
    {
        DIGI_FREE((void **)&pCtx);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern void WS_freeContext(WsContext **ppCtx)
{
    if (NULL != *ppCtx)
    {
        if (NULL != (*ppCtx)->pPayloadBuf)
        {
            DIGI_FREE((void **)&(*ppCtx)->pPayloadBuf);
        }

        DIGI_FREE((void **)ppCtx);
    }
}

/*----------------------------------------------------------------------------*/

extern MSTATUS WS_connect(
    WsContext   *pCtx,
    TCP_SOCKET  socket,
    const sbyte *pHost,
    ubyte2      port,
    const sbyte *pSubProtocol,
    const sbyte *pPath)
{
    pCtx->transportType = WS_TRANSPORT_TCP;
    pCtx->socket        = socket;
    return WS_performHandshake(pCtx, pHost, port, pSubProtocol, pPath);
}

/*----------------------------------------------------------------------------*/

extern MSTATUS WS_connectSSL(
    WsContext   *pCtx,
    sbyte4      sslConnInst,
    const sbyte *pHost,
    ubyte2      port,
    const sbyte *pSubProtocol,
    const sbyte *pPath)
{
    pCtx->transportType = WS_TRANSPORT_SSL;
    pCtx->sslConnInst   = sslConnInst;
    return WS_performHandshake(pCtx, pHost, port, pSubProtocol, pPath);
}

/*----------------------------------------------------------------------------*/

extern MSTATUS WS_close(WsContext *pCtx, WsCloseCode closeCode)
{
    MSTATUS status = OK;
    ubyte   closePayload[2];
    ubyte   maskKey[4];
    ubyte   *pFrame  = NULL;
    ubyte4  frameLen = 0;
    sbyte   *pDrainBuf = NULL;
    ubyte4  drainLen = 0;
    ubyte4  drainOff = 0;
    ubyte4  consumed = 0;
    MSTATUS decodeStatus = OK;

    if (WS_STATE_OPEN != pCtx->state)
    {
        goto exit;
    }

    closePayload[0] = (ubyte)((ubyte4)closeCode >> 8);
    closePayload[1] = (ubyte)((ubyte4)closeCode & 0xFF);

    status = WS_generateMaskKey(maskKey);
    if (OK != status)
    {
        goto exit;
    }

    status = WS_frameEncode(closePayload, 2, WS_OP_CLOSE, maskKey, &pFrame, &frameLen);
    if (OK != status)
    {
        goto exit;
    }

    status = WS_transportWrite(pCtx, (sbyte *)pFrame, frameLen);
    if (OK != status)
    {
        goto close_done;
    }

    pCtx->state = WS_STATE_CLOSING;

    status = DIGI_MALLOC((void **)&pDrainBuf, WS_RAW_BUF_SIZE);
    if (OK != status)
    {
        goto exit;
    }

    /* Drain until server close is received or a read times out */
    while (TRUE)
    {
        drainLen = 0;

        if (WS_TRANSPORT_TCP == pCtx->transportType)
        {
            status = TCP_READ_AVL_EX(pCtx->socket, pDrainBuf,
                                        WS_RAW_BUF_SIZE,
                                        &drainLen, 2000);
        }
        else
        {
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
            sbyte4 nRecv = 0;
            status = (MSTATUS)SSL_recv(pCtx->sslConnInst, pDrainBuf,
                                        WS_RAW_BUF_SIZE,
                                        &nRecv, 2000);
            drainLen = (nRecv > 0) ? (ubyte4)nRecv : 0;
#else
            status = ERR_WS;
            break;
#endif
        }

        if (OK != status)
        {
            /* timeout or I/O error */
            break;
        }

        drainOff = 0;
        while (drainOff < drainLen)
        {
            decodeStatus = WS_frameDecode(pCtx, (const ubyte *)pDrainBuf + drainOff,
                                          drainLen - drainOff, &consumed);
            drainOff += consumed;

            /* best effort as we're already closing the connection */
            if (WS_NEED_PONG == decodeStatus)
            {
                ubyte   pongKey[4];
                ubyte   *pPong = NULL;
                ubyte4  pongLen = 0;
                MSTATUS pongStatus;

                pongStatus = WS_generateMaskKey(pongKey);
                if (OK == pongStatus)
                {
                    pongStatus = WS_frameEncode(pCtx->pingPayload,
                                                pCtx->pingPayloadLen,
                                                WS_OP_PONG, pongKey,
                                                &pPong, &pongLen);
                }

                if (OK == pongStatus)
                {
                    WS_transportWrite(pCtx, (sbyte *)pPong, pongLen);
                }

                if (NULL != pPong)
                {
                    DIGI_FREE((void **)&pPong);
                }

                continue;
            }

            if (ERR_WS_CLOSE_RECEIVED == decodeStatus || OK != decodeStatus)
            {
                goto close_done;
            }
        }
    }

close_done:
    pCtx->state = WS_STATE_CLOSED;
    status = OK;

exit:
    if (NULL != pFrame)
    {
        DIGI_FREE((void **)&pFrame);
    }

    if (NULL != pDrainBuf)
    {
        DIGI_FREE((void **)&pDrainBuf);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS WS_mqttTransportSend(
    sbyte4 connectionInstance,
    void   *pTransportCtx,
    sbyte  *pBuffer,
    ubyte4 bufferLen)
{
    MSTATUS status;
    ubyte maskKey[4];
    ubyte  *pFrame  = NULL;
    ubyte4 frameLen = 0;
    WsContext *pCtx = (WsContext *)pTransportCtx;

    MOC_UNUSED(connectionInstance);

    if (WS_STATE_OPEN != pCtx->state)
    {
        status = ERR_WS_NOT_OPEN;
        goto exit;
    }

    status = WS_generateMaskKey(maskKey);
    if (OK != status)
    {
        goto exit;
    }

    status = WS_frameEncode((const ubyte *)pBuffer, bufferLen,
                             WS_OP_BINARY, maskKey, &pFrame, &frameLen);
    if (OK != status)
    {
        goto exit;
    }

    status = WS_transportWrite(pCtx, (sbyte *)pFrame, frameLen);

exit:
    if (NULL != pFrame)
    {
        DIGI_FREE((void **)&pFrame);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS WS_mqttTransportRecv(
    sbyte4      connectionInstance,
    void        *pTransportCtx,
    sbyte       *pBuffer,
    ubyte4      bufferLen,
    ubyte4      *pNumBytesReceived,
    ubyte4      timeoutMS,
    byteBoolean *pTimeout)
{
    MSTATUS status;
    sbyte   *pRawBuf  = NULL;
    ubyte4  bytesRead = 0;
    ubyte4  offset    = 0;
    ubyte4  consumed  = 0;
    ubyte4  controlOnlyReads = 0;
    MSTATUS decodeStatus = OK;
    WsContext *pCtx = (WsContext *)pTransportCtx;

    MOC_UNUSED(connectionInstance);

    *pNumBytesReceived = 0;
    *pTimeout = FALSE;

    if (WS_STATE_CLOSING == pCtx->state)
    {
        if (pCtx->payloadBufFill > 0)
        {
            goto drain_ring_buffer;
        }

        status = ERR_WS_CLOSE_RECEIVED;
        goto exit;
    }

    if (WS_STATE_OPEN != pCtx->state)
    {
        status = ERR_WS_NOT_OPEN;
        goto exit;
    }

    while (TRUE)
    {
drain_ring_buffer:
        if (pCtx->payloadBufFill > 0)
        {
            ubyte4 toCopy = pCtx->payloadBufFill;
            ubyte4 chunk1, chunk2;

            if (toCopy > bufferLen)
            {
                toCopy = bufferLen;
            }

            chunk1 = pCtx->payloadBufSize - pCtx->payloadBufRead;
            if (chunk1 > toCopy)
            {
                chunk1 = toCopy;
            }

            DIGI_MEMCPY((ubyte *)pBuffer, pCtx->pPayloadBuf + pCtx->payloadBufRead, chunk1);

            chunk2 = toCopy - chunk1;
            if (chunk2 > 0)
            {
                DIGI_MEMCPY((ubyte *)pBuffer + chunk1, pCtx->pPayloadBuf, chunk2);
            }

            pCtx->payloadBufRead = (pCtx->payloadBufRead + toCopy) % pCtx->payloadBufSize;
            pCtx->payloadBufFill -= toCopy;
            *pNumBytesReceived = toCopy;
            status = OK;
            goto exit;
        }

        /* Read a chunk of raw bytes from the transport */
        bytesRead = 0;

        status = DIGI_MALLOC((void **)&pRawBuf, WS_RAW_BUF_SIZE);
        if (OK != status)
        {
            goto exit;
        }

        if (WS_TRANSPORT_TCP == pCtx->transportType)
        {
            status = TCP_READ_AVL_EX(pCtx->socket, pRawBuf, WS_RAW_BUF_SIZE,
                                     &bytesRead, timeoutMS);
            if (ERR_TCP_READ_TIMEOUT == status)
            {
                *pTimeout = TRUE;
                status = OK;
                goto exit;
            }

            if (OK != status)
            {
                goto exit;
            }
        }
        else
        {
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
            sbyte4 nRecv = 0;
            status = (MSTATUS)SSL_recv(pCtx->sslConnInst, pRawBuf, WS_RAW_BUF_SIZE,
                                       &nRecv, timeoutMS);
            if (ERR_TCP_READ_TIMEOUT == status)
            {
                *pTimeout = TRUE;
                status = OK;
                goto exit;
            }

            if (OK != status)
            {
                goto exit;
            }

            bytesRead = (ubyte4)nRecv;
#else
            status = ERR_WS;
            goto exit;
#endif
        }

        /* Unannounced TCP/TLS close without a preceding webSocket close frame */
        if (0 == bytesRead)
        {
            status = ERR_WS;
            goto exit;
        }

        /* Feed raw bytes through the frame decoder */
        offset = 0;
        while (offset < bytesRead)
        {
            decodeStatus = WS_frameDecode(pCtx, (const ubyte *)pRawBuf + offset,
                                          bytesRead - offset, &consumed);
            offset += consumed;

            /* we received a ping, send pong immediately */
            if (WS_NEED_PONG == decodeStatus)
            {
                ubyte pongKey[4];
                ubyte *pPong = NULL;
                ubyte4 pongLen = 0;

                status = WS_generateMaskKey(pongKey);
                if (OK != status)
                {
                    goto exit;
                }

                status = WS_frameEncode(pCtx->pingPayload, pCtx->pingPayloadLen,
                                        WS_OP_PONG, pongKey, &pPong, &pongLen);
                if (OK != status)
                {
                    goto exit;
                }

                status = WS_transportWrite(pCtx, (sbyte *)pPong, pongLen);
                DIGI_FREE((void **)&pPong);
                if (OK != status)
                {
                    goto exit;
                }

                continue;
            }

            if (ERR_WS_CLOSE_RECEIVED == decodeStatus)
            {
                ubyte closeKey[4];
                ubyte *pCloseFrame = NULL;
                ubyte4 closeFrameLen = 0;

                status = WS_generateMaskKey(closeKey);
                if (OK != status)
                {
                    goto exit;
                }

                if (TRUE == pCtx->closeEchoPayloadValid)
                {
                    status = WS_frameEncode(pCtx->closeEchoPayload, 2,
                                            WS_OP_CLOSE, closeKey,
                                            &pCloseFrame, &closeFrameLen);
                }
                else
                {
                    status = WS_frameEncode(NULL, 0,
                                            WS_OP_CLOSE, closeKey,
                                            &pCloseFrame, &closeFrameLen);
                }

                if (OK != status)
                {
                    goto exit;
                }

                /* best effort close echo (connection is closing) */
                WS_transportWrite(pCtx, (sbyte *)pCloseFrame, closeFrameLen);
                DIGI_FREE((void **)&pCloseFrame);

                /* Deliver any binary bytes decoded before the close in this segment */
                if (pCtx->payloadBufFill > 0)
                {
                    goto drain_ring_buffer;
                }

                status = ERR_WS_CLOSE_RECEIVED;
                goto exit;
            }

            if (ERR_WS_BUFFER_FULL == decodeStatus ||
                ERR_WS_PROTOCOL_ERROR == decodeStatus ||
                ERR_WS_PAYLOAD_TOO_LARGE == decodeStatus)
            {
                ubyte  errCloseKey[4];
                ubyte  *pErrCloseFrame = NULL;
                ubyte4 errCloseFrameLen = 0;
                ubyte  errClosePayload[2];
                WsCloseCode errCloseCode = (ERR_WS_PROTOCOL_ERROR == decodeStatus)
                                          ? WS_CLOSE_PROTOCOL_ERROR
                                          : WS_CLOSE_MESSAGE_TOO_BIG;

                pCtx->state = WS_STATE_CLOSING;

                errClosePayload[0] = (ubyte)((ubyte4)errCloseCode >> 8);
                errClosePayload[1] = (ubyte)((ubyte4)errCloseCode & 0xFF);

                if (OK == WS_generateMaskKey(errCloseKey) &&
                    (OK == WS_frameEncode(errClosePayload, 2, WS_OP_CLOSE, errCloseKey,
                        &pErrCloseFrame, &errCloseFrameLen)))
                {
                    WS_transportWrite(pCtx, (sbyte *)pErrCloseFrame, errCloseFrameLen);
                    DIGI_FREE((void **)&pErrCloseFrame);
                }

                status = decodeStatus;
                goto exit;
            }

            if (OK != decodeStatus)
            {
                status = decodeStatus;
                goto exit;
            }
        }

        if (pCtx->payloadBufFill > 0)
        {
            goto drain_ring_buffer;
        }

        /* read contained only control frames */
        controlOnlyReads++;
        if (controlOnlyReads > WS_MAX_PING_BURST)
        {
            *pTimeout = TRUE;
            status = OK;
            goto exit;
        }
    }

exit:
    if (NULL != pRawBuf)
    {
        DIGI_FREE((void**)&pRawBuf);
    }

    return status;
}

#endif /* __ENABLE_DIGICERT_WEBSOCKET_CLIENT__ */
