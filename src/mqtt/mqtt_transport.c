/*
 * mqtt_transport.c
 *
 * MQTT transport handling internals
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 *
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt
 *   or https://www.digicert.com/master-services-agreement/
 *
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../common/moptions.h"

#ifdef __ENABLE_MQTT_CLIENT__

#include "mqtt_client.h"
#include "mqtt_client_priv.h"
#include "mqtt_util.h"
#include "mqtt_core.h"
#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)
#if defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__)
/* TODO: Temporary fix
 *
 * Issue: The header file mqtt_client.h includes merrors.h and redefines OK to
 * MOC_OK for ESP32 builds. The ssl.h header below includes a ESP32 toolchain
 * header file which also defines OK which then gets redefined to MOC_OK causing
 * compilation errors.
 *
 * Fix: Undefine OK before including ssl.h, then redefine it back to MOC_OK
 */
#undef OK
#endif
#include "../ssl/ssl.h"
#if defined(__RTOS_FREERTOS__) && defined(__RTOS_FREERTOS_ESP32__)
/* TODO: Temporary fix - see comment above */
#define OK MOC_OK
#endif
#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */


static MSTATUS MQTT_transportTCPSend(
    sbyte4 connectionInstance,
    void *pTransportCtx,
    sbyte *pBuffer,
    ubyte4 bufferLen)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;
    ubyte4 numBytesWritten;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

    status = TCP_WRITE(
        pCtx->transportSocket, pBuffer, bufferLen, &numBytesWritten);

exit:

    return status;
}

static MSTATUS MQTT_transportTCPRecv(
    sbyte4 connectionInstance,
    void *pTransportCtx,
    sbyte *pBuffer,
    ubyte4 bufferLen,
    ubyte4 *pNumBytesReceived,
    ubyte4 timeout,
    byteBoolean *pTimeout)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

    status = TCP_READ_AVL_EX(
        pCtx->transportSocket, pBuffer, bufferLen, pNumBytesReceived, timeout);
    if (ERR_TCP_READ_TIMEOUT == status)
    {
        status = OK;
        *pTimeout = TRUE;
    }

exit:

    return status;
}

extern MSTATUS MQTT_setTransportTCPInternal(
    MqttCtx *pCtx,
    TCP_SOCKET socket)
{
    pCtx->transportSocket = socket;
    pCtx->transportSend = MQTT_transportTCPSend;
    pCtx->transportRecv = MQTT_transportTCPRecv;

    return OK;
}

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)

static MSTATUS MQTT_transportSSLSend(
    sbyte4 connectionInstance,
    void *pTransportCtx,
    sbyte *pBuffer,
    ubyte4 bufferLen)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

    status = SSL_send(
        pCtx->transportConnectionInstance, pBuffer, bufferLen);
    if (OK < status)
    {
        status = OK;
    }

exit:

    return status;
}

static MSTATUS MQTT_transportSSLRecv(
    sbyte4 connectionInstance,
    void *pTransportCtx,
    sbyte *pBuffer,
    ubyte4 bufferLen,
    ubyte4 *pNumBytesReceived,
    ubyte4 timeout,
    byteBoolean *pTimeout)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

    status = SSL_recv(
        pCtx->transportConnectionInstance, pBuffer, bufferLen,
        pNumBytesReceived, timeout);
    if (ERR_TCP_READ_TIMEOUT == status)
    {
        status = OK;
        *pTimeout = TRUE;
    }

exit:

    return status;
}

extern MSTATUS MQTT_setTransportSSLInternal(
    MqttCtx *pCtx,
    sbyte4 sslConnInst)
{
    pCtx->transportConnectionInstance = sslConnInst;
    pCtx->transportSend = MQTT_transportSSLSend;
    pCtx->transportRecv = MQTT_transportSSLRecv;

    return OK;
}

#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */

extern MSTATUS MQTT_setTransportInternal(
    MqttCtx *pCtx,
    void *pTransportCtx,
    funcPtrMqttTransportSend send,
    funcPtrMqttTransportRecv recv)
{
    MSTATUS status;

    if ( (NULL == send) || (NULL == recv) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pCtx->pTransportCtx = pTransportCtx;
    pCtx->transportSend = send;
    pCtx->transportRecv = recv;
    status = OK;

exit:

    return status;
}


#endif /* __ENABLE_MQTT_CLIENT__ */
