/*
 * mqtt_client.c
 *
 * Client MQTT Implementation
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
#include "mqtt_core.h"
#include "mqtt_msg.h"
#include "mqtt_transport.h"
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

#ifndef MQTT_RECV_TIMEOUT
#define MQTT_RECV_TIMEOUT   (15000)
#endif

/*----------------------------------------------------------------------------*/

extern MSTATUS MQTT_init(sbyte4 mqttMaxClientConnections)
{
    return MQTT_initCore(mqttMaxClientConnections);
}

/*----------------------------------------------------------------------------*/

extern MSTATUS MQTT_shutdownStack(void)
{
    return MQTT_uninitCore();
}

/*----------------------------------------------------------------------------*/

static sbyte4 MQTT_connectCommon(
    MqttVersion version,
    ubyte *pClientId,
    ubyte2 clientIdLen,
    ubyte4 internalFlags)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;
    sbyte4 connInst = -1;

    status = MQTT_createConnectInstanceFromId(
        version, pClientId, clientIdLen, &connInst, internalFlags);
    if (OK != status)
        goto exit;

    status = MQTT_getCtxFromConnInst(connInst, &pCtx);

exit:

    if (OK != status)
        connInst = status;

    return connInst;
}

/*----------------------------------------------------------------------------*/

extern sbyte4 MQTT_connect(
    MqttVersion version,
    ubyte *pClientId,
    ubyte2 clientIdLen)
{
    return MQTT_connectCommon(
        version, pClientId, clientIdLen, MQTT_INT_FLAG_SYNC_MODE);
}

/*----------------------------------------------------------------------------*/

extern MSTATUS MQTT_getConnackReasonString(
    sbyte4 connInst,
    ubyte reasonCode,
    sbyte **ppReasonStr)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;
    ubyte4 Mqttv3ErrorsSize;
    ubyte4 Mqttv5ErrorsSize;

    status = MQTT_getCtxFromConnInst(connInst, &pCtx);
    if (OK != status)
        goto exit;

    static const sbyte* Mqttv3Errors[] = {
        [MQTT_CONNECT_UNACCEPTABLE_PROTOCOL_VERSION_V3] = "Connection Refused, unacceptable protocol version",
        [MQTT_CONNECT_IDENTIFIER_REJECTED_V3]           = "Connection Refused, identifier rejected",
        [MQTT_CONNECT_SERVER_UNAVAILABLE_V3]            = "Connection Refused, Server unavailable",
        [MQTT_CONNECT_BAD_USERNAME_PASSWORD_V3]         = "Connection Refused, bad user name or password",
        [MQTT_CONNECT_NOT_AUTHORIZED_V3]                = "Connection Refused, not authorized"
    };

    static const sbyte* Mqttv5Errors[] = {
        [MQTT_CONNECT_UNSPECIFIED_V5]                    = "Unspecified error",
        [MQTT_CONNECT_MALFORMED_PACKET_V5]               = "Malformed Packet",
        [MQTT_CONNECT_PROTOCOL_ERROR_V5]                 = "Protocol Error",
        [MQTT_CONNECT_IMPLEMENTATION_SPECIFIC_ERROR_V5]  = "Implementation specific error",
        [MQTT_CONNECT_UNSUPPORTED_PROTOCOL_VERSION_V5]   = "Unsupported Protocol Version",
        [MQTT_CONNECT_INVALID_CLIENT_IDENTIFIER_V5]      = "Client Identifier not valid",
        [MQTT_CONNECT_BAD_USERNAME_PASSWORD_V5]          = "Bad User Name or Password",
        [MQTT_CONNECT_NOT_AUTHORIZED_V5]                 = "Not authorized",
        [MQTT_CONNECT_SERVER_UNAVAILABLE_V5]             = "Server unavailable",
        [MQTT_CONNECT_BUSY_V5]                           = "Server busy",
        [MQTT_CONNECT_BANNED_V5]                         = "Banned",
        [MQTT_CONNECT_BAD_AUTHENTICATION_METHOD_V5]      = "Bad authentication method",
        [MQTT_CONNECT_INVALID_TOPIC_V5]                  = "Topic Name invalid",
        [MQTT_CONNECT_PACKET_TOO_LARGE_V5]               = "Packet too large",
        [MQTT_CONNECT_QUOTA_EXCEEDED_V5]                 = "Quota exceeded",
        [MQTT_CONNECT_INVALID_PAYLOAD_FORMAT_V5]         = "Payload format invalid",
        [MQTT_CONNECT_RETAIN_NOT_SUPPORTED_V5]           = "Retain not supported",
        [MQTT_CONNECT_QOS_NOT_SUPPORTED_V5]              = "QoS not supported",
        [MQTT_CONNECT_USE_ANOTHER_SERVER_V5]             = "Use another server",
        [MQTT_CONNECT_SERVER_MOVED_V5]                   = "Server moved",
        [MQTT_CONNECT_RATE_EXCEEDED_V5]                  = "Connection rate exceeded"
    };

    Mqttv3ErrorsSize = COUNTOF(Mqttv3Errors);
    Mqttv5ErrorsSize = COUNTOF(Mqttv5Errors);

    if (MQTT_V3_1_1 == pCtx->version)
    {
        if (reasonCode < Mqttv3ErrorsSize && NULL != Mqttv3Errors[reasonCode])
        {
            *ppReasonStr = (sbyte *)Mqttv3Errors[reasonCode];
        }
        else
        {
            *ppReasonStr = "Unknown reason code";
        }
    }

    else if (MQTT_V5 == pCtx->version)
    {
        if (reasonCode < Mqttv5ErrorsSize && NULL != Mqttv5Errors[reasonCode])
        {
            *ppReasonStr = (sbyte *)Mqttv5Errors[reasonCode];
        }
        else
        {
            *ppReasonStr = "Unknown reason code";
        }
    }

exit:
    return status;
}


/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)

extern sbyte4 MQTT_asyncConnect(
    MqttVersion version,
    ubyte *pClientId,
    ubyte2 clientIdLen)
{
    return MQTT_connectCommon(
        version, pClientId, clientIdLen, MQTT_INT_FLAG_ASYNC_MODE);
}

#endif /* __ENABLE_MQTT_ASYNC_CLIENT__ */

/*----------------------------------------------------------------------------*/

extern MSTATUS MQTT_closeConnection(sbyte4 connectionInstance)
{
    return MQTT_closeConnectionInternal(connectionInstance);
}

/*----------------------------------------------------------------------------*/

extern MSTATUS MQTT_disconnect(
    sbyte4 connectionInstance,
    MqttDisconnectOptions *pOptions)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;
    MqttMessage *pMsg = NULL;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

    if (CONNECT_OPEN != pCtx->connectionState && CONNECT_NEGOTIATE != pCtx->connectionState)
    {
        status = ERR_MQTT_INVALID_CONNECTION_STATE;
        goto exit;
    }

    if (TRUE == pCtx->keepAliveThreadActive)
    {
        pCtx->keepAliveThreadActive = FALSE;

        status = RTOS_semSignal(pCtx->keepAliveSem);
        if (OK != status)
            goto exit;

        status = RTOS_joinThread(pCtx->keepAliveTID, NULL);
        if (OK != status)
            goto exit;

        status = RTOS_mutexFree(&pCtx->keepAliveMutex);
        if (OK != status)
            goto exit;

        status = RTOS_semFree(&pCtx->keepAliveSem);
        if (OK != status)
            goto exit;
    }

    status = MQTT_buildDisconnectMsg(pCtx, pOptions, &pMsg);
    if (OK != status)
        goto exit;

    status = MQTT_processPacket(
        connectionInstance, pCtx, &pMsg, pCtx->keepAliveThreadActive);

exit:

    if (NULL != pMsg)
    {
        MQTT_freeMsg(&pMsg);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS MQTT_setTransportTCP(
    sbyte4 connectionInstance,
    TCP_SOCKET socket)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;

    if (!TCP_IS_SOCKET_VALID(socket))
    {
        status = ERR_MQTT_INVALID_TCP_SOCKET;
        goto exit;
    }

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    if (MQTT_IS_ASYNC(pCtx))
    {
        status = ERR_MQTT_ASYNC_CONN_INST;
        goto exit;
    }
#endif

    status = MQTT_setTransportTCPInternal(pCtx, socket);

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

#ifdef __MQTT_ENABLE_FILE_PERSIST__

extern MSTATUS MQTT_setPersistMode(
    sbyte4 connectionInstance,
    FilePersistArgs *pArgs)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;

    if ( (NULL == pArgs) || (NULL == pArgs->pDir) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (MQTT_PERSIST_MODE_FILE != pArgs->mode)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

    pCtx->persistMode = MQTT_PERSIST_MODE_FILE;
    status = DIGI_MALLOC_MEMCPY((void **)(&(pCtx->pDir)), DIGI_STRLEN(pArgs->pDir) + 1, pArgs->pDir, DIGI_STRLEN(pArgs->pDir));
    if (OK != status)
        goto exit;

    pCtx->pDir[DIGI_STRLEN(pArgs->pDir)] = '\0';

exit:

    return status;
}

#endif /* ifdef __MQTT_ENABLE_FILE_PERSIST__ */

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_SSL_CLIENT__)

extern MSTATUS MQTT_setTransportSSL(
    sbyte4 connectionInstance,
    sbyte4 sslConnInst)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;

    status = SSL_isSessionSSL(sslConnInst);
    if (1 != status)
    {
        status = ERR_MQTT_INVALID_SSL_CONN_INST;
        goto exit;
    }

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    if (MQTT_IS_ASYNC(pCtx))
    {
        status = ERR_MQTT_ASYNC_CONN_INST;
        goto exit;
    }
#endif

    status = MQTT_setTransportSSLInternal(pCtx, sslConnInst);

exit:

    return status;
}

#endif /* __ENABLE_DIGICERT_SSL_CLIENT__ */

/*----------------------------------------------------------------------------*/

extern MSTATUS MQTT_setTransport(
    sbyte4 connectionInstance,
    void *pTransportCtx,
    funcPtrMqttTransportSend send,
    funcPtrMqttTransportRecv recv)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    if (MQTT_IS_ASYNC(pCtx))
    {
        status = ERR_MQTT_ASYNC_CONN_INST;
        goto exit;
    }
#endif

    status = MQTT_setTransportInternal(
        pCtx, pTransportCtx, send, recv);

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS MQTT_negotiateConnection(
    sbyte4 connectionInstance,
    MqttConnectOptions *pOptions)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;
    MqttMessage *pMsg = NULL;
    ubyte4 numBytesRecv;
    byteBoolean timeout;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

    if (CONNECT_NEGOTIATE != pCtx->connectionState)
    {
        status = ERR_MQTT_INVALID_CONNECTION_STATE;
        goto exit;
    }

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    if (MQTT_IS_SYNC(pCtx))
#endif
    {
        if (NULL == pCtx->pSyncBuffer)
        {
            status = DIGI_MALLOC(
                (void **) &pCtx->pSyncBuffer, pCtx->syncBufferSize);
            if (OK != status)
                goto exit;
        }
    }

    status = MQTT_buildConnectMsg(pCtx, pOptions, &pMsg);
    if (OK != status)
        goto exit;

    status = RTOS_mutexWait(pCtx->pMutex);
    if (OK != status)
        goto exit;

    pCtx->pollingInterval = pOptions->pollingInterval;
    pCtx->sessionExpiryInterval = pOptions->sessionExpiryIntervalSeconds;
    pCtx->maxPacketSize = 0xFFFFFFFF;

    if (MQTT_V5 <= pCtx->version)
    {
        if (pOptions->maxPacketSize != 0)
        {
            pCtx->maxPacketSize = pOptions->maxPacketSize;
        }
    }

    if (pOptions->receiveMax > 0)
    {
        pCtx->recvMax = pOptions->receiveMax;
    }
    else
    {
        pCtx->recvMax = MQTT_RECV_MAX_DEFLT;
    }

    /* MQTT v5 spec 4.9:
     * The send quota and Receive Maximum value are not 
     * preserved across Network Connections, and are re-initialized with each 
     * new Network Connection */
    pCtx->clientSendQuota = pCtx->recvMax;

    RTOS_mutexRelease(pCtx->pMutex);

    status = MQTT_processPacket(
        connectionInstance, pCtx, &pMsg, pCtx->keepAliveThreadActive);
    if (OK != status)
        goto exit;

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    if (MQTT_IS_SYNC(pCtx))
#endif
    {
        do
        {
            /* TODO: What is a good default timeout value for the negotiate
             * stage? Allow user to override timeout value
             */
            timeout = FALSE;
            numBytesRecv = 0;
            status = pCtx->transportRecv(
                connectionInstance, pCtx->pTransportCtx,
                pCtx->pSyncBuffer, pCtx->syncBufferSize, &numBytesRecv,
                MQTT_RECV_TIMEOUT, &timeout);
            if (OK == status && TRUE == timeout)
                status = ERR_MQTT_CONNECT_TIMEOUT;

            if (0 < numBytesRecv)
            {
                status = MQTT_parsePacket(
                    connectionInstance, pCtx, pCtx->pSyncBuffer, numBytesRecv);
                if (OK != status)
                    goto exit;
            }

        } while (OK == status && CONNECT_NEGOTIATE == pCtx->connectionState);
    }

exit:

    if (NULL != pMsg)
    {
        MQTT_freeMsg(&pMsg);
    }
    if (OK != status)
    {
        if (NULL != pCtx)
            pCtx->connectionState = CONNECT_NEGOTIATE;
    }

    return status;
}

/*----------------------------------------------------------------------------*/

MSTATUS MQTT_subscribe(
    sbyte4 connectionInstance,
    MqttSubscribeTopic *pTopics,
    ubyte4 topicCount,
    MqttSubscribeOptions *pOptions)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;
    MqttMessage *pMsg = NULL;
    ubyte2 packetId = 0;

    if ( (NULL == pTopics) || (0 == topicCount) )
    {
        status = ERR_MQTT_NO_TOPIC_PROVIDED;
        goto exit;
    }

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

    if (CONNECT_OPEN != pCtx->connectionState)
    {
        status = ERR_MQTT_INVALID_CONNECTION_STATE;
        goto exit;
    }

    status = MQTT_buildSubscribeMsg(pCtx, pTopics, topicCount, pOptions, &packetId, &pMsg);
    if (OK != status)
        goto exit;

    status = MQTT_addPacketId(pCtx, pMsg, packetId);
    if (OK != status)
        goto exit;

    status = MQTT_processPacket(
        connectionInstance, pCtx, &pMsg, pCtx->keepAliveThreadActive);

exit:

    if (NULL != pMsg)
    {
        MQTT_freeMsg(&pMsg);
    }
    if (OK != status)
    {
        if (NULL != pCtx)
            pCtx->connectionState = CONNECT_NEGOTIATE;
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS MQTT_unsubscribe(
    sbyte4 connectionInstance,
    MqttUnsubscribeTopic *pTopics,
    ubyte4 topicCount,
    MqttUnsubscribeOptions *pOptions)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;
    MqttMessage *pMsg = NULL;
    ubyte2 packetId = 0;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

    if (CONNECT_OPEN != pCtx->connectionState)
    {
        status = ERR_MQTT_INVALID_CONNECTION_STATE;
        goto exit;
    }

    status = MQTT_buildUnsubscribeMsg(
        pCtx, pTopics, topicCount, pOptions, &packetId, &pMsg);
    if (OK != status)
        goto exit;

    status = MQTT_addPacketId(pCtx, pMsg, packetId);
    if (OK != status)
        goto exit;

    status = MQTT_processPacket(
        connectionInstance, pCtx, &pMsg, pCtx->keepAliveThreadActive);

exit:

    if (NULL != pMsg)
    {
        MQTT_freeMsg(&pMsg);
    }
    if (OK != status)
    {
        if (NULL != pCtx)
            pCtx->connectionState = CONNECT_NEGOTIATE;
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS MQTT_recvExt(
    sbyte4 connectionInstance,
    byteBoolean useTimeout,
    ubyte4 timeoutVal)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;
    ubyte4 numBytesRecv = 0;
    ubyte4 adjustedTimeout = 0;
    byteBoolean timeout = FALSE;
    byteBoolean keepAliveWillExpire = FALSE;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    if (MQTT_IS_ASYNC(pCtx))
    {
        status = ERR_MQTT_ASYNC_CONN_INST;
        goto exit;
    }
#endif

    if (CONNECT_OPEN != pCtx->connectionState)
    {
        status = ERR_MQTT_INVALID_CONNECTION_STATE;
        goto exit;
    }

    if (NULL == pCtx->transportRecv)
    {
        status = ERR_MQTT_NO_TRANSPORT_SET;
        goto exit;
    }

    if (FALSE == pCtx->keepAliveThreadActive)
    {
        if (0 != pCtx->keepAliveMS)
        {
            /* Determine the timeout based on keep alive. If it has already expired
             * then send ping request message, otherwise adjust the timeout until
             * keep alive expires */
            adjustedTimeout = RTOS_deltaMS(&pCtx->lastMessageSent, NULL);
            if (adjustedTimeout >= pCtx->keepAliveMS)
            {
                /* Past or equal to keep alive time, send ping request */
                status = MQTT_pingRequest(connectionInstance);
                if (OK != status)
                    goto exit;

                adjustedTimeout = pCtx->keepAliveMS;
            }
            else
            {
                adjustedTimeout = pCtx->keepAliveMS - adjustedTimeout;
            }
        }

        timeout = FALSE;

        if (TRUE == useTimeout)
        {
            /* Determine if keep alive will expire based on user provided timeout */
            if (timeoutVal >= adjustedTimeout)
            {
                keepAliveWillExpire = TRUE;
            }
            adjustedTimeout = timeoutVal;
        }
        else
        {
            /* User did not provide timeout, the calculated adjustedTimeout will
             * cause the keep alive to expire */
            keepAliveWillExpire = TRUE;
        }
    }
    else
    {
        adjustedTimeout = pCtx->pollingInterval;
    }

    do
    {
        if (NULL != pCtx->pRecieveTimeoutHandler)
        {
            /* Call the user provided timeout handler */
            status = pCtx->pRecieveTimeoutHandler(
                connectionInstance, &adjustedTimeout);
            if (OK != status)
                goto exit;

            if (0 == adjustedTimeout)
            {
                goto exit;
            }
        }

        numBytesRecv = 0;
        timeout = FALSE;
        status = pCtx->transportRecv(
            connectionInstance, pCtx->pTransportCtx,
            pCtx->pSyncBuffer, pCtx->syncBufferSize, &numBytesRecv,
            adjustedTimeout, &timeout);
        if (OK != status)
            goto exit;

        if (FALSE == pCtx->keepAliveThreadActive)
        {
            if ( (0 != pCtx->keepAliveMS) && (TRUE == timeout) &&
                (TRUE == keepAliveWillExpire) )
            {
                /* Keep alive expired, send ping request */
                status = MQTT_pingRequest(connectionInstance);
                if (OK != status)
                    goto exit;
            }
        }

        if (numBytesRecv > 0)
        {
            status = MQTT_parsePacket(
                connectionInstance, pCtx, pCtx->pSyncBuffer, numBytesRecv);
            if (OK != status)
                goto exit;
        }

    } while (NULL != pCtx->pRecieveTimeoutHandler);

exit:

    if (OK != status)
    {
        if (NULL != pCtx)
            pCtx->connectionState = CONNECT_NEGOTIATE;
    }

    return status;
}

extern MSTATUS MQTT_recv(
    sbyte4 connectionInstance)
{
    return MQTT_recvExt(connectionInstance, FALSE, 0);
}

extern MSTATUS MQTT_recvEx(
    sbyte4 connectionInstance,
    ubyte4 timeoutVal)
{
    return MQTT_recvExt(connectionInstance, TRUE, timeoutVal);
}

/*----------------------------------------------------------------------------*/

MSTATUS MQTT_setControlPacketHandlers(
    sbyte4 connectionInstance,
    MqttPacketHandlers *pHandlers)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;

    if (NULL == pHandlers)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

    if (NULL != pHandlers->alertHandler)
    {
        pCtx->handlers.alertHandler = pHandlers->alertHandler;
    }

    if (NULL != pHandlers->connAckHandler)
    {
        pCtx->handlers.connAckHandler = pHandlers->connAckHandler;
    }

    if (NULL != pHandlers->subAckHandler)
    {
        pCtx->handlers.subAckHandler = pHandlers->subAckHandler;
    }

    if (NULL != pHandlers->unsubAckHandler)
    {
        pCtx->handlers.unsubAckHandler = pHandlers->unsubAckHandler;
    }

    if (NULL != pHandlers->publishHandler)
    {
        pCtx->handlers.publishHandler = pHandlers->publishHandler;
    }

    if (NULL != pHandlers->pubAckHandler)
    {
        pCtx->handlers.pubAckHandler = pHandlers->pubAckHandler;
    }

    if (NULL != pHandlers->pubRecHandler)
    {
        pCtx->handlers.pubRecHandler = pHandlers->pubRecHandler;
    }

    if (NULL != pHandlers->pubRelHandler)
    {
        pCtx->handlers.pubRelHandler = pHandlers->pubRelHandler;
    }

    if (NULL != pHandlers->pubCompHandler)
    {
        pCtx->handlers.pubCompHandler = pHandlers->pubCompHandler;
    }

    if (NULL != pHandlers->authHandler)
    {
        pCtx->handlers.authHandler = pHandlers->authHandler;
    }

    if (NULL != pHandlers->disconnectHandler)
    {
        pCtx->handlers.disconnectHandler = pHandlers->disconnectHandler;
    }

exit:
    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS MQTT_publish(
    sbyte4 connectionInstance,
    MqttPublishOptions *pOptions,
    ubyte *pTopic,
    ubyte4 topicLen,
    ubyte *pData,
    ubyte4 dataLen)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;
    MqttMessage *pMsg = NULL;
    ubyte2 packetId = 0;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

    status = MQTT_buildPublishMsg(
        pCtx, pOptions, pTopic, topicLen, pData, dataLen, &packetId, &pMsg);
    if (OK != status)
        goto exit;

    if (IS_QOS_1(pMsg) || IS_QOS_2(pMsg))
    {
        /* Timeout any publishes that have been unacked for too long before we attempt
         * to store another */
        MQTT_timeoutStoredPublishes(pCtx);

        /* MQTT v5 spec 4.9:
         * Each time the Client or Server sends a PUBLISH packet at QoS > 0, it decrements 
         * the send quota. If the send quota reaches zero, the Client or Server MUST NOT send 
         * any more PUBLISH packets with QoS > 0 */
        status = RTOS_mutexWait(pCtx->pMutex);
        if (OK != status)
            goto exit;

        if (pCtx->sendQuota == 0)
        {
            status = ERR_MQTT_SEND_QUOTA;
            RTOS_mutexRelease(pCtx->pMutex);
            goto exit;
        }

        pCtx->sendQuota--;

        RTOS_mutexRelease(pCtx->pMutex);

        status = MQTT_storePublishMsg(pCtx, pMsg, packetId);
        if (OK != status)
            goto exit;
    }

    status = MQTT_processPacket(
        connectionInstance, pCtx, &pMsg, pCtx->keepAliveThreadActive);

exit:

    if (NULL != pMsg)
    {
        MQTT_freeMsg(&pMsg);
    }
    if ( (OK != status) && (ERR_MQTT_SEND_QUOTA != status) )
    {
        if (NULL != pCtx)
            pCtx->connectionState = CONNECT_NEGOTIATE;
    }

    return status;
}

/*----------------------------------------------------------------------------*/

MSTATUS MQTT_sendPubResp(
    sbyte4 connectionInstance,
    MqttPubRespOptions *pOptions)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;
    MqttMessage *pMsg = NULL;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

    status = MQTT_buildPubRespMsg(
        pCtx, pOptions, &pMsg);
    if (OK != status)
        goto exit;

    /* For QOS2, store any PUBRELs to be sent */
    if (MQTT_PUBREL == pOptions->packetType)
    {
        status = MQTT_storePubRelMsg(pCtx, pMsg, pOptions->packetId);
        if (OK != status)
            goto exit;
    }

    status = MQTT_processPacket(
        connectionInstance, pCtx, &pMsg, pCtx->keepAliveThreadActive);

exit:

    if (NULL != pMsg)
    {
        MQTT_freeMsg(&pMsg);
    }
    if (OK != status)
    {
        if (NULL != pCtx)
            pCtx->connectionState = CONNECT_NEGOTIATE;
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS MQTT_pingRequestInternal(
    sbyte4 connectionInstance,
    byteBoolean checkKeepAliveThread)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;
    MqttMessage *pMsg = NULL;
    byteBoolean acquireMutex = FALSE;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

    status = MQTT_buildPingReqMsg(pCtx, &pMsg);
    if (OK != status)
        goto exit;

    if (TRUE == checkKeepAliveThread)
    {
        acquireMutex = pCtx->keepAliveThreadActive;
    }

    status = MQTT_processPacket(
        connectionInstance, pCtx, &pMsg, acquireMutex);
    if (OK != status)
        goto exit;

    pCtx->pingCounter++;

exit:

    if (NULL != pMsg)
    {
        MQTT_freeMsg(&pMsg);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS MQTT_pingRequest(
    sbyte4 connectionInstance)
{
    return MQTT_pingRequestInternal(connectionInstance, TRUE);
}

/*----------------------------------------------------------------------------*/

extern MSTATUS MQTT_sendAuth(
    sbyte4 connectionInstance,
    MqttAuthOptions *pOptions)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;
    MqttMessage *pMsg = NULL;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

    if (MQTT_V3_1_1 >= pCtx->version)
    {
        status = ERR_MQTT_VERSION_UNSUPPORTED;
        goto exit;
    }

    status = MQTT_buildAuthMsg(pCtx, pOptions, &pMsg);
    if (OK != status)
        goto exit;

    status = MQTT_processPacket(
        connectionInstance, pCtx, &pMsg, pCtx->keepAliveThreadActive);

exit:

    if (NULL != pMsg)
    {
        MQTT_freeMsg(&pMsg);
    }
    if (OK != status)
    {
        if (NULL != pCtx)
            pCtx->connectionState = CONNECT_NEGOTIATE;
    }
    
    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS MQTT_setCookie(
    sbyte4 connectionInstance,
    void *pCookie)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

    pCtx->pCookie = pCookie;

exit:
    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS MQTT_getCookie(
    sbyte4 connectionInstance,
    void **ppCookie)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;

    if (NULL == ppCookie)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

    *ppCookie = pCtx->pCookie;

exit:
    return status;
}

/*----------------------------------------------------------------------------*/

extern sbyte4 MQTT_isConnectionEstablished(
    sbyte4 connectionInstance)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

    if (CONNECT_NEGOTIATE == pCtx->connectionState)
    {
        status = 0;
    }
    else if (CONNECT_OPEN == pCtx->connectionState)
    {
        status = 1;
    }
    else
    {
        status = ERR_MQTT_INVALID_CONNECTION_STATE;
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

extern sbyte4 MQTT_resetConnectionState(
    sbyte4 connectionInstance)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

    pCtx->connectionState = CONNECT_NEGOTIATE;

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

MSTATUS MQTT_getClientIdFromConnInst(
    sbyte4 connectionInstance, 
    ubyte **ppClientId, 
    ubyte4 *pClientIdLen)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;

    if ( (NULL == ppClientId) || (NULL == pClientIdLen) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

    *ppClientId = pCtx->pClientId;
    *pClientIdLen = pCtx->clientIdLen;

exit:
    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS MQTT_setPublishTimeout(
    sbyte4 connectionInstance,
    ubyte4 publishTimeoutSeconds)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;

    /* Internally we end up comparing on milliseconds, dont allow a number large
     * enough a conversion to milliseconds will blow out our int */
    if (publishTimeoutSeconds > 0xFFFFFFFF / 1000)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

    pCtx->publishTimeoutSeconds = publishTimeoutSeconds;

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
static sbyte4 MQTT_transactionPendingEx(
    MqttCtx *pCtx);
#endif

extern sbyte4 MQTT_transactionPending(
    sbyte4 connectionInstance)
{
    MSTATUS status;
    sbyte res = 0;
    MqttCtx *pCtx = NULL;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    res = MQTT_transactionPendingEx(pCtx);
#endif

    /* If we have already constructed packets, or unacked packets then
     * we are still pending */
    return res | MQTT_hasUnackedPackets(pCtx);

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)

extern MSTATUS MQTT_getSendBuffer(
    sbyte4 connectionInstance,
    ubyte *pData,
    ubyte4 *pDataLength)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;
    MqttMessageList *pNode;
    ubyte4 remainingLen;
    ubyte4 copyLen;

    if (NULL == pDataLength)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    remainingLen = *pDataLength;
    *pDataLength = 0;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

    if (MQTT_IS_SYNC(pCtx))
    {
        status = ERR_MQTT_ASYNC_CONN_INST;
        goto exit;
    }

    if (CONNECT_CLOSED == pCtx->connectionState)
    {
        status = ERR_MQTT_INVALID_CONNECTION_STATE;
        goto exit;
    }

    if (NULL == pData)
    {
        *pDataLength = pCtx->numBytesToSend;
    }
    else
    {
        pNode = pCtx->pMsgListHead;

        while (NULL != pNode)
        {
            copyLen = pNode->pMsg->dataLen - pCtx->dataProcessed;
            if (copyLen > remainingLen)
                copyLen = remainingLen;

            DIGI_MEMCPY(pData, pNode->pMsg->pData + pCtx->dataProcessed, copyLen);
            pCtx->dataProcessed += copyLen;
            remainingLen -= copyLen;
            pData += copyLen;
            *pDataLength += copyLen;

            if (pCtx->dataProcessed == pNode->pMsg->dataLen)
            {
                pCtx->dataProcessed = 0;
                pNode = pNode->pNext;
                MQTT_freeMsgNode(&pCtx->pMsgListHead);
                pCtx->pMsgListHead = pNode;
            }

            if (remainingLen == 0)
                break;
        }

        if (NULL == pNode)
        {
            pCtx->pMsgListTail = NULL;
        }
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

extern MSTATUS MQTT_recvMessage(
    sbyte4 connectionInstance,
    ubyte *pData,
    ubyte4 dataLength)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;

    if (NULL == pData)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

    if (MQTT_IS_SYNC(pCtx))
    {
        status = ERR_MQTT_ASYNC_CONN_INST;
        goto exit;
    }

    if (CONNECT_CLOSED == pCtx->connectionState)
    {
        status = ERR_MQTT_INVALID_CONNECTION_STATE;
        goto exit;
    }

    if (FALSE == pCtx->keepAliveThreadActive)
    {
        if (0 != pCtx->keepAliveMS)
        {
            /* Determine the timeout based on keep alive. If it has already expired
             * then send ping request message. */
            if (RTOS_deltaMS(&pCtx->lastMessageSent, NULL) > pCtx->keepAliveMS)
            {
                /* Past keep alive time, queue ping request */
                status = MQTT_pingRequest(connectionInstance);
                if (OK != status)
                    goto exit;
            }
        }
    }

    if (0 < dataLength)
    {
        status = MQTT_parsePacket(
            connectionInstance, pCtx, pData, dataLength);
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static sbyte4 MQTT_transactionPendingEx(
    MqttCtx *pCtx)
{
    sbyte res = 0;

    /* Check if we already have constructed packets to be sent */
    if (NULL == pCtx->pMsgListHead)
    {
        res = 0;
    }
    else
    {
        res = 1;
    }

    /* If we have already constructed packets we are still pending */
    return res;
}

#endif /* __ENABLE_MQTT_ASYNC_CLIENT__ */

/*----------------------------------------------------------------------------*/

extern MSTATUS MQTT_readTimeout(
    sbyte4 connectionInstance,
    ubyte4 *pReadTimeoutMS)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;

    if (NULL == pReadTimeoutMS)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pReadTimeoutMS = 0;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

    /* Keep alive only applies to after the connection has been negotiated */
    if (CONNECT_OPEN != pCtx->connectionState)
    {
        status = ERR_MQTT_INVALID_CONNECTION_STATE;
        goto exit;
    }

    if (0 != pCtx->keepAliveMS)
    {
        *pReadTimeoutMS = RTOS_deltaMS(&pCtx->lastMessageSent, NULL);
        if (*pReadTimeoutMS > pCtx->keepAliveMS)
        {
            *pReadTimeoutMS = pCtx->keepAliveMS;
        }
        else
        {
            *pReadTimeoutMS = pCtx->keepAliveMS - *pReadTimeoutMS;
        }
    }

exit:

    return status;
}

extern MSTATUS MQTT_setProtocolBufferSize(
    sbyte4 connectionInstance,
    ubyte4 size)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    if (!MQTT_IS_SYNC(pCtx))
    {
        status = ERR_MQTT_ASYNC_CONN_INST;
        goto exit;
    }
#endif

    pCtx->syncBufferSize = size;

exit:

    return status;
}

static MSTATUS MQTT_computeKeepAliveTimeout(
    MqttCtx *pCtx,
    ubyte4 *pTimeoutMS)
{
    ubyte4 adjustedTimeout = 0;

    *pTimeoutMS = 0;

    if (0 != pCtx->keepAliveMS)
    {
        adjustedTimeout = RTOS_deltaMS(&pCtx->lastMessageSent, NULL);
        if (adjustedTimeout >= pCtx->keepAliveMS)
        {
            *pTimeoutMS = 0;
        }
        else
        {
            *pTimeoutMS = pCtx->keepAliveMS - adjustedTimeout;
        }
    }

    return OK;
}

static void MQTT_keepAliveThread(
    void *pThreadArg)
{
    MSTATUS status;
    sbyte4 connInst = (uintptr) pThreadArg;
    byteBoolean releaseMutex = FALSE;
    MqttCtx *pCtx = NULL;
    ubyte4 timeoutMS = 0;
    RTOS_MUTEX dummyMutex = NULL;
    byteBoolean timeout = TRUE;

    status = MQTT_getCtxFromConnInst(connInst, &pCtx);
    if (OK != status)
        goto exit;

    status = RTOS_mutexCreate(&dummyMutex, MQTT_MUTEX, 0);
    if (OK != status)
        goto exit;

    while (TRUE == pCtx->keepAliveThreadActive && TRUE == timeout)
    {
        status = RTOS_mutexWait(pCtx->keepAliveMutex);
        if (OK != status)
            goto exit;

        releaseMutex = TRUE;

        status = MQTT_computeKeepAliveTimeout(pCtx, &timeoutMS);
        if (OK != status)
            goto exit;

        if (0 == timeoutMS)
        {
            status = MQTT_pingRequestInternal(connInst, FALSE);
            if (OK != status)
                goto exit;

            status = MQTT_computeKeepAliveTimeout(pCtx, &timeoutMS);
            if (OK != status)
                goto exit;
        }

        RTOS_mutexRelease(pCtx->keepAliveMutex);
        releaseMutex = FALSE;

        status = RTOS_mutexWait(dummyMutex);
        if (OK != status)
            goto exit;

        if (TRUE != pCtx->keepAliveThreadActive)
            break;

        status = RTOS_semTimedWait(pCtx->keepAliveSem, timeoutMS, &timeout);
        if (OK != status)
            goto exit;

        RTOS_mutexRelease(dummyMutex);
    }

exit:

    if (TRUE == releaseMutex)
    {
        RTOS_mutexRelease(pCtx->keepAliveMutex);
    }

    if (NULL != dummyMutex)
    {
        RTOS_mutexFree(&dummyMutex);
    }

    RTOS_exitThread(NULL);

    return;
}

extern MSTATUS MQTT_startKeepAliveThread(
    sbyte4 connectionInstance)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    if (!MQTT_IS_SYNC(pCtx))
    {
        status = ERR_MQTT_ASYNC_CONN_INST;
        goto exit;
    }
#endif

    if (0 != pCtx->keepAliveMS)
    {
        status = RTOS_semCreate(&pCtx->keepAliveSem, 0);
        if (OK != status)
            goto exit;

        status = RTOS_mutexCreate(&pCtx->keepAliveMutex, MQTT_MUTEX, 0);
        if (OK != status)
            goto exit;

        pCtx->keepAliveThreadActive = TRUE;

        status = RTOS_createThread(
            MQTT_keepAliveThread, (void *) (uintptr) connectionInstance,
            MQTT_SESSION, &pCtx->keepAliveTID);
        if (OK != status)
            goto exit;
    }

exit:

    return status;
}

extern MSTATUS MQTT_setRecieveTimeoutHandler(
    sbyte4 connectionInstance,
    funcPtrReceiveTimeoutHandler pHandler)
{
    MSTATUS status;
    MqttCtx *pCtx = NULL;

    status = MQTT_getCtxFromConnInst(connectionInstance, &pCtx);
    if (OK != status)
        goto exit;

    pCtx->pRecieveTimeoutHandler = pHandler;

exit:

    return status;
}

#endif /* __ENABLE_MQTT_CLIENT__ */