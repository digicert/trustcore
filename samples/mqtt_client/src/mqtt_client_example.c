/*
 * mqtt_client_example.c
 *
 * Example MQTT client implementation
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

#include <stdio.h>
#include <stdarg.h>
#include <signal.h>

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mocana.h"
#include "../common/mstdlib.h"
#include "../common/mtcp.h"
#include "../common/mtcp_async.h"
#if defined(__ENABLE_MOCANA_HTTP_PROXY__)
#include "../http/http_context.h"
#include "../http/http_common.h"
#include "../http/http.h"
#endif
#include "../mqtt/mqtt_client.h"
#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
#include "../crypto/cert_store.h"
#include "../ssl/ssl.h"
#endif /* __ENABLE_MOCANA_SSL_CLIENT__ */
#ifdef __ENABLE_DIGICERT_SCRAM_CLIENT__
#include "../crypto/scram_client.h"
#include "../crypto/crypto.h"
#endif
#if defined(__ENABLE_MOCANA_MQTT_SAMPLE_LIBRARY__)
#include "../crypto/pubcrypto.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/pkcs10.h"
#include "../trustedge/utils/trustedge_utils.h"
#endif
 
/*----------------------------------------------------------------------------*/

#define MAX_MQTT_CLIENT_CONNECTIONS     (10)

#define MQTT_TCP_TRANSPORT              "TCP"
#define MQTT_SSL_TRANSPORT              "SSL"

#define MQTT_ASYNC_SEND_BUFFER_SIZE     (1024)
#define MQTT_ASYNC_RECV_BUFFER_SIZE     (1024)

/*----------------------------------------------------------------------------*/

typedef enum
{
    MQTT_TCP,
    MQTT_SSL
} MqttExampleTransport;

/*----------------------------------------------------------------------------*/

typedef struct
{
    ubyte *pTopic;
    ubyte4 topicLen;
    ubyte *pData;
    ubyte4 dataLen;
    MqttQoS qos;
    byteBoolean retain;
    MqttPublishOptions pubOptions;
} MqttClientExampleMsg;

/*----------------------------------------------------------------------------*/

typedef struct
{
    MqttVersion mqttVersion;
    TCP_SOCKET socket;
#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
    sbyte4 sslConnInst;
    certStorePtr pStore;
    sbyte *pKeyFile;
    sbyte *pCertFile;
#endif
    sbyte *pMqttServer;
    sbyte pMqttServerIp[40];
    sbyte *pMqttClientId;
    ubyte4 mqttClientIdLen;
    ubyte2 mqttPortNo;
    sbyte *pProxy;
    MqttExampleTransport transport;
    MqttConnectOptions mqttConnectOptions;
    MqttPacketHandlers mqttExampleHandlers;
    byteBoolean exit;
    MqttSubscribeTopic *pTopics;
    ubyte4 topicCount;
    MqttSubscribeOptions mqttSubscribeOptions;
    byteBoolean subTopicSingle;
    MqttUnsubscribeTopic *pUnsubTopics;
    ubyte4 unsubTopicCount;
    MqttUnsubscribeOptions mqttUnsubscribeOptions;
    byteBoolean unsubTopicSingle;
    MqttClientExampleMsg *pMsgs;
    ubyte4 msgCount;
    MqttDisconnectOptions mqttDisconnectOptions;
    byteBoolean sslAllowUntrusted;
    byteBoolean alertHandlerCalled;
    byteBoolean hexBytes;
#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    byteBoolean async;
    ubyte *pSendBuffer;
    ubyte4 sendBufferLen;
    ubyte *pRecvBuffer;
    ubyte4 recvBufferLen;
    ubyte4 bytesReceived;
#endif
#ifdef __ENABLE_DIGICERT_SCRAM_CLIENT__
    ScramCtx *pScramCtx;
    ubyte *pScramUser;
    ubyte4 scramUserLen;
    ubyte *pScramPass;
    ubyte4 scramPassLen;
    ubyte scramHashType;
#endif
#if defined(__ENABLE_MOCANA_MQTT_SAMPLE_LIBRARY__)
    TrustEdgeConfig *pConfig;
#endif
} MqttClientExampleCtx;

#ifdef __ENABLE_DIGICERT_SCRAM_CLIENT__

static char *pScramMethodSha256 = SCRAM_SHA256_METHOD_STRING;
static char *pScramMethodSha512 = SCRAM_SHA512_METHOD_STRING;

#endif

/*----------------------------------------------------------------------------*/

static MSTATUS MQTT_EXAMPLE_connAckHandler(
    sbyte4 connectionInstance,
    MqttMessage *pMsg,
    MqttConnAckInfo *pInfo)
{
    MSTATUS status = OK;
    MqttClientExampleCtx *pCtx = NULL;
    ubyte4 i;
    sbyte *pReasonStr = NULL;

    if (0 == pInfo->reasonCode)
    {
        printf("Connection Success!\n");
        if (TRUE == pInfo->sessionPresent)
        {
            printf("Session resumed\n");
        }

        if (NULL != pInfo->pAssignedClientId)
        {
            printf("Assigned Client ID: %.*s\n", pInfo->assignedClientIdLen, pInfo->pAssignedClientId);
        }

        status = MQTT_getCookie(connectionInstance, (void **) &pCtx);
        if (OK != status)
        {
            printf("MQTT_getCookie failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }

        if (NULL != pCtx->pTopics)
        {
            if (FALSE == pCtx->subTopicSingle)
            {
                status = MQTT_subscribe(
                    connectionInstance, pCtx->pTopics, pCtx->topicCount,
                    &pCtx->mqttSubscribeOptions);
                if (OK != status)
                {
                    printf("MQTT_subscribe failed with status = %d on line %d\n", status, __LINE__);
                    goto exit;
                }
            }
            else
            {
                for (i = 0; i < pCtx->topicCount; i++)
                {
                    status = MQTT_subscribe(
                        connectionInstance, pCtx->pTopics + i, 1,
                        &pCtx->mqttSubscribeOptions);
                    if (OK != status)
                    {
                        printf("MQTT_subscribe failed with status = %d on line %d\n", status, __LINE__);
                        goto exit;
                    }
                }
            }
        }
        else if (TRUE != pInfo->sessionPresent)
        {
            /* Only exit if we are not subscribing to any topics and this is not
             * a resumed session */
            pCtx->exit = TRUE;
        }

        if (NULL != pCtx->pUnsubTopics)
        {
            if (FALSE == pCtx->unsubTopicSingle)
            {
                status = MQTT_unsubscribe(
                    connectionInstance, pCtx->pUnsubTopics,
                    pCtx->unsubTopicCount, &pCtx->mqttUnsubscribeOptions);
                if (OK != status)
                {
                    printf("MQTT_unsubscribe failed with status = %d on line %d\n", status, __LINE__);
                    goto exit;
                }
            }
            else
            {
                for (i = 0; i < pCtx->unsubTopicCount; i++)
                {
                    status = MQTT_unsubscribe(
                        connectionInstance, pCtx->pUnsubTopics + i, 1,
                        &pCtx->mqttUnsubscribeOptions);
                    if (OK != status)
                    {
                        printf("MQTT_unsubscribe failed with status = %d on line %d\n", status, __LINE__);
                        goto exit;
                    }
                }
            }
        }
    }
    else
    {
        printf("Connection attempt failed, reason code: %d\n", pInfo->reasonCode);

        if (NULL != pInfo->pReasonStr)
        {
            printf("Connection failure reason string: %.*s\n", pInfo->reasonStrLen, pInfo->pReasonStr);
        }
        else
        {
            status = MQTT_getConnackReasonString(connectionInstance,pInfo->reasonCode, &pReasonStr);
            printf("Connection failure reason string: %s\n", pReasonStr);
        }

    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS MQTT_EXAMPLE_subAckHandler(
    sbyte4 connectionInstance,
    MqttMessage *pMsg,
    MqttSubAckInfo *pInfo)
{
    MSTATUS status = OK;
    ubyte4 i;

    printf("Subscribe acknowledgement for message ID: %d\n", pInfo->msgId);
    for (i = 0; i < pInfo->QoSCount; i++)
    {
        printf("Granted QoS: %d\n", pInfo->pQoS[i]);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS MQTT_EXAMPLE_unsubAckHandler(
    sbyte4 connectionInstance,
    MqttMessage *pMsg,
    MqttUnsubAckInfo *pInfo)
{
    MSTATUS status = OK;
    ubyte4 i;

    printf("Unsubscribe acknowledgement for message ID: %d\n", pInfo->msgId);
    for (i = 0; i < pInfo->reasonCodeCount; i++)
    {
        printf("Reason Code: %d\n", pInfo->pReasonCodes[i]);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS MQTT_EXAMPLE_publishHandler(
    sbyte4 connectionInstance,
    MqttMessage *pMsg,
    MqttPublishInfo *pInfo)
{
    MSTATUS status = OK;
    ubyte4 i;
    MqttClientExampleCtx *pCtx = NULL;

    printf("Topic: %.*s\n", pInfo->topicLen, pInfo->pTopic);
    printf("Payload: ");

    status = MQTT_getCookie(connectionInstance, (void **) &pCtx);
    if (OK != status)
    {
        printf("MQTT_getCookie failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

    if (TRUE == pCtx->hexBytes)
    {
        for (i = 0; i < pInfo->payloadLen; i++)
        {
            printf("%02X", pInfo->pPayload[i]);
        }
        printf("\n");
    }
    else
    {
        printf("%.*s\n", pInfo->payloadLen, pInfo->pPayload);
    }

    if (1 == pInfo->payloadLen && 'q' == *pInfo->pPayload)
    {
        pCtx->exit = TRUE;
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS MQTT_EXAMPLE_disconnectHandler(
    sbyte4 connectionInstance,
    MqttMessage *pMsg,
    MqttDisconnectInfo *pInfo)
{
    MSTATUS status = OK;
    ubyte4 i;

    printf("Disconnect reason code: %d\n", pInfo->reasonCode);

    if (NULL != pInfo->pReasonStr)
    {
        printf("Disconnect reason string:\n");
        for (i = 0; i < pInfo->reasonStrLen; i++)
        {
            printf("%c", pInfo->pReasonStr[i]);
        }
        printf("\n");
    }

    if (pInfo->reasonCode >= MQTT_DISCONNECT_UNSPECIFIED)
    {
        status = ERR_MQTT_DISCONNECT;
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS MQTT_EXAMPLE_alertHandler(
    sbyte4 connectionInstance,
    sbyte4 statusCode)
{
    MSTATUS status = OK;
    MqttClientExampleCtx *pCtx = NULL;

    printf("Alert code: %d\n", statusCode);

    status = MQTT_getCookie(connectionInstance, (void **) &pCtx);
    if (OK != status)
        goto exit;

    pCtx->alertHandlerCalled = TRUE;

exit:
    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS MQTT_EXAMPLE_authHandler(
    sbyte4 connectionInstance,
    MqttMessage *pMsg,
    MqttAuthInfo *pInfo)
{
    MSTATUS status = OK;
    MqttAuthOptions options = {0};
#ifdef __ENABLE_DIGICERT_SCRAM_CLIENT__
    MqttClientExampleCtx *pCtx = NULL;
    sbyte4 cmp = -1;
#endif

    printf("Authentication message reason code: %d\n", pInfo->reasonCode);

#ifdef __ENABLE_DIGICERT_SCRAM_CLIENT__
    if (MQTT_CONTINUE_AUTHENTICATION == pInfo->reasonCode)
    {
        status = MQTT_getCookie(connectionInstance, (void **) &pCtx);
        if (OK != status)
        {
            printf("MQTT_getCookie failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }

        switch(pCtx->scramHashType)
        {
            case ht_sha256:
                options.pAuthMethod = pScramMethodSha256;
                options.authMethodLen = MOC_STRLEN(pScramMethodSha256);
                break;

            case ht_sha512:
                options.pAuthMethod = pScramMethodSha512;
                options.authMethodLen = MOC_STRLEN(pScramMethodSha512);
                break;

            default:
                status = ERR_INVALID_INPUT;
                goto exit;
        }

        /* Validate that the auth method sent by the server is the same as what we initially sent*/
        if (options.authMethodLen != pInfo->authMethodLen)
        {
            status = ERR_MQTT_AUTH_METHOD_MISMATCH;
            goto exit;
        }

        status = MOC_MEMCMP(options.pAuthMethod, pInfo->pAuthMethod, options.authMethodLen, &cmp);
        if (OK != status)
            goto exit;

        if (0 != cmp)
        {
            status = ERR_MQTT_AUTH_METHOD_MISMATCH;
            goto exit;
        }

        status = SCRAM_buildClientFinal (
            pCtx->pScramCtx, pInfo->pAuthData, pInfo->authDataLen, pCtx->pScramPass,
            pCtx->scramPassLen, pCtx->scramHashType, &(options.pAuthData), &(options.authDataLen));
        if (OK != status)
            goto exit;

        status = MQTT_sendAuth(connectionInstance, &options);
    }

exit:
#endif

    if (NULL != options.pAuthData)
    {
        MOC_FREE((void **)&options.pAuthData);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS MQTT_EXAMPLE_contextCreate(
    MqttClientExampleCtx **ppCtx)
{
    MSTATUS status;

    status = MOC_CALLOC((void **) ppCtx, 1, sizeof(MqttClientExampleCtx));
    if (OK != status)
    {
        goto exit;
    }

    (*ppCtx)->mqttVersion = MQTT_V5;

    (*ppCtx)->socket = -1;
#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
    (*ppCtx)->sslConnInst = -1;
#endif
    (*ppCtx)->transport = MQTT_TCP;

    /* Will Info Defaults */
    (*ppCtx)->mqttConnectOptions.willInfo.qos = MQTT_QOS_0;
    (*ppCtx)->mqttConnectOptions.willInfo.retain = FALSE;
    (*ppCtx)->mqttConnectOptions.willInfo.pWill = NULL;
    (*ppCtx)->mqttConnectOptions.willInfo.willLen = 0;
    (*ppCtx)->mqttConnectOptions.willInfo.pWillTopic = NULL;
    (*ppCtx)->mqttConnectOptions.willInfo.willTopicLen = 0;
    (*ppCtx)->mqttConnectOptions.willInfo.willDelayInterval = 0;
    (*ppCtx)->mqttConnectOptions.willInfo.setPayloadFormat = FALSE;
    (*ppCtx)->mqttConnectOptions.willInfo.payloadFormat = 0;
    (*ppCtx)->mqttConnectOptions.willInfo.msgExpiryInterval = 0;
    (*ppCtx)->mqttConnectOptions.willInfo.pContentType = NULL;
    (*ppCtx)->mqttConnectOptions.willInfo.contentTypeLen = 0;
    (*ppCtx)->mqttConnectOptions.willInfo.pResponseTopic = NULL;
    (*ppCtx)->mqttConnectOptions.willInfo.responseTopicLen = 0;
    (*ppCtx)->mqttConnectOptions.willInfo.pCorrelationData = NULL;
    (*ppCtx)->mqttConnectOptions.willInfo.correlationDataLen = 0;
    (*ppCtx)->mqttConnectOptions.willInfo.pProps = NULL;
    (*ppCtx)->mqttConnectOptions.willInfo.propCount = 0;

    /* Connect Defaults */
    (*ppCtx)->mqttConnectOptions.pExtCtx = NULL;
    (*ppCtx)->mqttConnectOptions.cleanStart = FALSE;
    (*ppCtx)->mqttConnectOptions.keepAliveInterval = 0;
    (*ppCtx)->mqttConnectOptions.pUsername = NULL;
    (*ppCtx)->mqttConnectOptions.usernameLen = 0;
    (*ppCtx)->mqttConnectOptions.pPassword = NULL;
    (*ppCtx)->mqttConnectOptions.passwordLen = 0;
    (*ppCtx)->mqttConnectOptions.sessionExpiryIntervalSeconds = 0;
    (*ppCtx)->mqttConnectOptions.receiveMax = 0;
    (*ppCtx)->mqttConnectOptions.topicAliasMax = 0;
    (*ppCtx)->mqttConnectOptions.requestResponseInfo = FALSE;
    (*ppCtx)->mqttConnectOptions.requestProblemInfo = FALSE;
    (*ppCtx)->mqttConnectOptions.pAuthMethod = NULL;
    (*ppCtx)->mqttConnectOptions.authMethodLen = 0;
    (*ppCtx)->mqttConnectOptions.pAuthData = NULL;
    (*ppCtx)->mqttConnectOptions.authDataLen = 0;
    (*ppCtx)->mqttConnectOptions.pProps = NULL;
    (*ppCtx)->mqttConnectOptions.propCount = 0;

    /* Subscribe Defaults */
    (*ppCtx)->mqttSubscribeOptions.subId = 0;
    (*ppCtx)->mqttSubscribeOptions.pProps = NULL;
    (*ppCtx)->mqttSubscribeOptions.propCount = 0;

    /* Packet Handlers */
    (*ppCtx)->mqttExampleHandlers.connAckHandler = MQTT_EXAMPLE_connAckHandler;
    (*ppCtx)->mqttExampleHandlers.subAckHandler = MQTT_EXAMPLE_subAckHandler;
    (*ppCtx)->mqttExampleHandlers.unsubAckHandler = MQTT_EXAMPLE_unsubAckHandler;
    (*ppCtx)->mqttExampleHandlers.publishHandler = MQTT_EXAMPLE_publishHandler;
    (*ppCtx)->mqttExampleHandlers.disconnectHandler = MQTT_EXAMPLE_disconnectHandler;
    (*ppCtx)->mqttExampleHandlers.alertHandler = MQTT_EXAMPLE_alertHandler;
    (*ppCtx)->mqttExampleHandlers.authHandler = MQTT_EXAMPLE_authHandler;

#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
    status = CERT_STORE_createStore(&((*ppCtx)->pStore));
    if (OK != status)
        goto exit;
#endif

exit:

    return status;
}

static MSTATUS MQTT_EXAMPLE_contextDelete(
    MqttClientExampleCtx **ppCtx)
{
    MSTATUS status = OK;
    ubyte4 i;

    if ( (NULL != ppCtx) && (NULL != *ppCtx) )
    {
        for (i = 0; i < (*ppCtx)->topicCount; i++)
        {
            MOC_FREE((void **) &((*ppCtx)->pTopics + i)->pTopic);
        }
        MOC_FREE((void **) &((*ppCtx)->pTopics));

        for (i = 0; i < (*ppCtx)->unsubTopicCount; i++)
        {
            MOC_FREE((void **) &((*ppCtx)->pUnsubTopics + i)->pTopic);
        }
        MOC_FREE((void **) &((*ppCtx)->pUnsubTopics));

        for (i = 0; i < (*ppCtx)->msgCount; i++)
        {
            MOC_FREE((void **) &((*ppCtx)->pMsgs + i)->pTopic);
            MOC_FREE((void **) &((*ppCtx)->pMsgs + i)->pData);
            
            for (int j = 0; (ubyte4)j < (*ppCtx)->pMsgs->pubOptions.propCount; j++)
            {
                MOC_FREE((void **) &(((*ppCtx)->pMsgs + i)->pubOptions.pProps + j)->data.pair.name.pData);
                MOC_FREE((void **) &(((*ppCtx)->pMsgs + i)->pubOptions.pProps + j)->data.pair.value.pData);
            }
            MOC_FREE((void **) &((*ppCtx)->pMsgs + i)->pubOptions.pProps);
            MOC_FREE((void **) &((*ppCtx)->pMsgs + i)->pubOptions.pContentType);
            MOC_FREE((void **) &((*ppCtx)->pMsgs + i)->pubOptions.pCorrelationData);
            MOC_FREE((void **) &((*ppCtx)->pMsgs + i)->pubOptions.pResponseTopic);
        }
        MOC_FREE((void **) &((*ppCtx)->pMsgs));

        for (i = 0; i < (*ppCtx)->mqttConnectOptions.propCount; i++)
        {
            MOC_FREE((void **) &((*ppCtx)->mqttConnectOptions.pProps + i)->data.pair.name.pData);
            MOC_FREE((void **) &((*ppCtx)->mqttConnectOptions.pProps + i)->data.pair.value.pData);
        }
        MOC_FREE((void **) &((*ppCtx)->mqttConnectOptions.pProps));

        for (i = 0; i < (*ppCtx)->mqttConnectOptions.willInfo.propCount; i++)
        {
            MOC_FREE((void **) &((*ppCtx)->mqttConnectOptions.willInfo.pProps + i)->data.pair.name.pData);
            MOC_FREE((void **) &((*ppCtx)->mqttConnectOptions.willInfo.pProps + i)->data.pair.value.pData);
        }
        MOC_FREE((void **) &((*ppCtx)->mqttConnectOptions.willInfo.pProps));
        MOC_FREE((void **) &((*ppCtx)->mqttConnectOptions.willInfo.pWillTopic));
        MOC_FREE((void **) &((*ppCtx)->mqttConnectOptions.willInfo.pWill));
        MOC_FREE((void **) &((*ppCtx)->mqttConnectOptions.willInfo.pContentType));
        MOC_FREE((void **) &((*ppCtx)->mqttConnectOptions.willInfo.pResponseTopic));
        MOC_FREE((void **) &((*ppCtx)->mqttConnectOptions.willInfo.pCorrelationData));

        MOC_FREE((void **) &((*ppCtx)->mqttConnectOptions.pAuthMethod));
        MOC_FREE((void **) &((*ppCtx)->mqttConnectOptions.pUsername));
        MOC_FREE((void **) &((*ppCtx)->mqttConnectOptions.pPassword));

        for (i = 0; i < (*ppCtx)->mqttSubscribeOptions.propCount; i++)
        {
            MOC_FREE((void **) &((*ppCtx)->mqttSubscribeOptions.pProps + i)->data.pair.name.pData);
            MOC_FREE((void **) &((*ppCtx)->mqttSubscribeOptions.pProps + i)->data.pair.value.pData);
        }
        MOC_FREE((void **) &((*ppCtx)->mqttSubscribeOptions.pProps));

        for (i = 0; i < (*ppCtx)->mqttUnsubscribeOptions.propCount; i++)
        {
            MOC_FREE((void **) &((*ppCtx)->mqttUnsubscribeOptions.pProps + i)->data.pair.name.pData);
            MOC_FREE((void **) &((*ppCtx)->mqttUnsubscribeOptions.pProps + i)->data.pair.value.pData);
        }
        MOC_FREE((void **) &((*ppCtx)->mqttUnsubscribeOptions.pProps));

        for (i = 0; i < (*ppCtx)->mqttDisconnectOptions.propCount; i++)
        {
            MOC_FREE((void **) &((*ppCtx)->mqttDisconnectOptions.pProps + i)->data.pair.name.pData);
            MOC_FREE((void **) &((*ppCtx)->mqttDisconnectOptions.pProps + i)->data.pair.value.pData);
        }
        MOC_FREE((void **) &((*ppCtx)->mqttDisconnectOptions.pProps));

#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
        if (NULL != (*ppCtx)->pStore)
        {
            CERT_STORE_releaseStore(&((*ppCtx)->pStore));
        }

        if (NULL != (*ppCtx)->pKeyFile)
        {
            MOC_FREE((void **) &((*ppCtx)->pKeyFile));
        }

        if (NULL != (*ppCtx)->pCertFile)
        {
            MOC_FREE((void **) &((*ppCtx)->pCertFile));
        }
#endif

        if (NULL != (*ppCtx)->pProxy)
        {
            MOC_FREE((void **) &((*ppCtx)->pProxy));
        }
        if (NULL != (*ppCtx)->pMqttClientId)
        {
            MOC_FREE((void **) &((*ppCtx)->pMqttClientId));
        }
        if (NULL != (*ppCtx)->pMqttServer)
        {
            MOC_FREE((void **) &((*ppCtx)->pMqttServer));
        }
#ifdef __ENABLE_DIGICERT_SCRAM_CLIENT__
        if (NULL != (*ppCtx)->pScramUser)
        {
            MOC_FREE((void **) &((*ppCtx)->pScramUser));
        }
        if (NULL != (*ppCtx)->pScramPass)
        {
            MOC_FREE((void **) &((*ppCtx)->pScramPass));
        }
        if (NULL != (*ppCtx)->pScramCtx)
        {
            SCRAM_freeCtx(&((*ppCtx)->pScramCtx));
        }
#endif
#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
        if (NULL != (*ppCtx)->pSendBuffer)
        {
            MOC_FREE((void **) &((*ppCtx)->pSendBuffer));
        }
        if (NULL != (*ppCtx)->pRecvBuffer)
        {
            MOC_FREE((void **) &((*ppCtx)->pRecvBuffer));
        }
#endif

        MOC_FREE((void **) ppCtx);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS MQTT_EXAMPLE_displayHelp(
    sbyte *pProg,
    sbyte *pErrStringFormat,
    ...)
{
    char pBuffer[1024];
    printf("  Usage: %s [Options]\n", pProg);
    printf("  Options:\n");
    printf("    --help                                              Display this help menu\n");
    printf("    --mqtt_servername <servername>                      MQTT broker to connect to\n");
    printf("    --mqtt_port <port>                                  Network port used for connection\n");
    printf("    --mqtt_client_id <id>                               Client ID used for MQTT connection\n");
    printf("    --mqtt_version <version>                            Version of MQTT to negotiate\n");
    printf("                                                            5 (default)\n");
    printf("                                                            3.1.1\n");
#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    printf("    --mqtt_async                                        Use asynchronous methods\n");
    printf("    --mqtt_async_send_buffer_size <size>                Size of send buffer\n");
    printf("    --mqtt_async_recv_buffer_size <size>                Size of receive buffer\n");
#endif
    printf("    --print_hex_bytes                                   Display payload in hex bytes\n");
    printf("    --mqtt_sub_topic <topic>                            Subscribe to topic. Can be specified multiple times\n");
    printf("    --mqtt_sub_topic_no_local_option                    Pass this in to not receive messages published by this client.\n");
    printf("                                                        Applies to the most recently passed in --mqtt_sub_topic\n");
    printf("    --mqtt_sub_topic_retain_as_published                Messages on this subscription keep the retain flag they were published with.\n");
    printf("                                                        Applies to the most recently passed in --mqtt_sub_topic\n");
    printf("    --mqtt_sub_topic_retain_handling <0|1|2>            Control retained message behaviour on connection establishment.\n");
    printf("                                                        Applies to the most recently passed in --mqtt_sub_topic\n");
    printf("                                                            0: Receive retained messages on subscribe (default)\n");
    printf("                                                            1: Receive retained messages only if the subscription does not exist\n");
    printf("                                                            2: Do not receive retained messages\n");
    printf("    --mqtt_sub_topic_single                             Send separate subscribe messages per topic\n");
    printf("    --mqtt_unsub_topic <topic>                          Unsubscribe to a topic. Can be specified multiple times\n");
    printf("    --mqtt_unsub_topic_single                           Send separate unsubscribe messages per topic\n");
    printf("    --mqtt_pub_topic <topic>                            Publish topic. Can be specified multiple times\n");
    printf("    --mqtt_pub_message <message>                        Publish message, applies to most recently passed in --mqtt_pub_topic.\n");
    printf("                                                        Can be specified multiple times\n");
    printf("    --mqtt_pub_file <file>                              Publish file contents, applies to most recently passed in --mqtt_pub_topic.\n");
    printf("                                                        Can be specified multiple times\n");
    printf("    --mqtt_pub_qos <0|1|2>                              Set the QoS level for the most recently specified message.\n");
    printf("                                                        Applies to most recently passed in --mqtt_pub_message/--mqtt_pub_file.\n");
    printf("                                                            0: At most once  - No acknowledgement, messages may be lost. (default)\n");
    printf("                                                            1: At least once - Acknowledged delivery, possible duplicates.\n");
    printf("                                                            2: Exactly once  - Acknowledged delivery, no duplicates.\n");
    printf("    --mqtt_pub_retain                                   Set the retain flag when publishing a message.\n");
    printf("                                                        Applies to most recently passed in --mqtt_pub_message/--mqtt_pub_file.\n");
    printf("    --mqtt_clean_start                                  Set clean start to disable resuming from a session\n");
    printf("    --mqtt_session_expiry_interval <seconds>            Set the session expiry interval in seconds. Determines how long the\n");
    printf("                                                        session is persisted after the connection is closed.\n");
    printf("                                                            0: Session ends once network connection is closed (default)\n");
    printf("                                                            1 - 4294967294: Session is persisted for this many seconds\n");
    printf("                                                            4294967295: Session does not expire\n");
    printf("                                                        session is persisted after the connection is closed.\n");
    printf("    --mqtt_keep_alive <seconds>                         Keep alive time in seconds\n");
    printf("    --mqtt_username <username>                          Optional username sent in the connect\n");
    printf("    --mqtt_password <password>                          Optional password sent in the connect\n");
    printf("    --mqtt_will_topic <topic>                           Set the will topic\n");
    printf("    --mqtt_will_message <message>                       Set the will message\n");
    printf("    --mqtt_will_qos <0|1|2>                             Set the will QoS level\n");
    printf("    --mqtt_will_retain                                  Set the will retain flag\n");
#ifdef __ENABLE_DIGICERT_SCRAM_CLIENT__
    printf("    --mqtt_scram_hash_alg  <algorithm>                  SCRAM hash algorithm to use (for enhanced authentication)\n");
    printf("                                                            Options: SHA256, SHA512\n");
    printf("    --mqtt_scram_username <username>                    SCRAM username\n");
    printf("    --mqtt_scram_password <password>                    SCRAM password\n");
#endif
    printf("    --mqtt_connect_properties <property> <value>        Set MQTT Connect Properties\n");
    printf("     Supported Connect Properties:\n");
    printf("        session_expiry_interval <seconds>               Session expiry interval in seconds.\n");
    printf("        receive_maximum <value>                         The number of QoS 1 and QoS 2 messages the client can process concurrently.\n");
    printf("        max_packet_size <bytes>                         Maximum packet size the client is willing to receive in bytes\n");
    printf("        topic_alias_max <value>                         Highest value the client is willing to accept as topic alias\n");
    printf("        request_response_info                           Set request_response_info to request response information in the CONNACK packet\n");
    printf("        request_problem_info                            Set request_problem_info to indicate whether reason strings or user properties should be sent in case of failures\n");
    printf("        user_property <key> <value>                     Set connect user property with the specified key and value\n");
    printf("                                                        Can be specified multiple times\n");
    printf("    --mqtt_publish_properties <property> <value>        Set MQTT Publish Properties\n");
    printf("     Supported Publish Properties:\n");
    printf("        payload_format_indicator <0|1>                  Set the payload format indicator\n");
    printf("                                                            0: Unspecified Bytes\n");
    printf("                                                            1: UTF-8 Encoded Character Data\n");
    printf("        message_expiry_interval <seconds>               Set the message expiry interval in seconds\n");
    printf("        topic_alias <value>                             Set the topic alias value\n");
    printf("        response_topic <topic>                          Set the response topic\n");
    printf("        correlation_data <data>                         Set the correlation data\n");
    printf("        content_type <type>                             Set the content type\n");
    printf("        user_property <key> <value>                     Set publish user property with the specified key and value\n");
    printf("                                                        Can be specified multiple times\n");
    printf("    --mqtt_subscribe_properties <property> <value>      Set MQTT Subscribe Properties\n");
    printf("     Supported Subscribe Properties:\n");
    printf("        user_property <key> <value>                         Set subscribe user property with the specified key and value\n");
    printf("                                                        Can be specified multiple times\n");
    printf("    --mqtt_unsubscribe_properties <property> <value>    Set MQTT Unsubscribe Properties\n");
    printf("     Supported Unsubscribe Properties:\n");
    printf("        user_property <key> <value>                     Set unsubscribe user property with the specified key and value\n");
    printf("                                                        Can be specified multiple times\n");
    printf("    --mqtt_disconnect_properties <property> <value>     Set MQTT Disconnect Properties\n");
    printf("     Supported Disconnect Properties:\n");
    printf("        session_expiry_interval <seconds>               Session expiry interval in seconds.\n");
    printf("        user_property <key> <value>                     Set disconnect user property with the specified key and value\n");
    printf("                                                        Can be specified multiple times\n");
    printf("    --mqtt_will_properties <property> <value>           Set MQTT Will Properties\n");
    printf("     Supported Will Properties:\n");
    printf("        message_expiry_interval <seconds>               Set the message expiry interval in seconds\n");
    printf("        content_type                                    Set the content type\n");
    printf("        response_topic                                  Set the response topic\n");
    printf("        correlation_data                                Set the correlation data\n");
    printf("        payload_format_indicator <0|1>                  Set the payload format indicator\n");
    printf("                                                            0: Unspecified Bytes\n");
    printf("                                                            1: UTF-8 Encoded Character Data\n");
    printf("        will_delay_interval <seconds>                   Set the will delay interval in seconds\n");
    printf("        user_property <key> <value>                     Set will user property with the specified key and value\n");
    printf("                                                        Can be specified multiple times\n");
    

#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
    printf("    --mqtt_transport <transport>                        Choose the transport used for MQTT connection\n");
    printf("                                                            TCP (default)\n");
    printf("                                                            SSL\n");
    printf("    --ssl_ca_file <file>                                Only applies if transport is SSL. SSL CA certificate file\n");
    printf("    --ssl_allow_untrusted                               Only applies if transport is SSL. Allow untrusted certificates for SSL\n");
    printf("    --ssl_key_file <file>                               Only applies if transport is SSL. SSL key file for client authentication\n");
    printf("    --ssl_cert_file <file>                              Only applies if transport is SSL. SSL certificate file for client authentication\n");
#if defined(__ENABLE_MOCANA_HTTP_PROXY__)
    printf("    --proxy <proxy>                                     Connect using proxy. Following formats allowed\n");
    printf("                                                            http://[username:password@]hostname:port\n");
    printf("                                                            https://[username:password@]hostname:port\n");
#endif /* __ENABLE_MOCANA_HTTP_PROXY__ */
#endif /* __ENABLE_MOCANA_SSL_CLIENT__ */
#if defined(__ENABLE_MOCANA_MQTT_SAMPLE_LIBRARY__)
#if defined(__ENABLE_MOCANA_PQC__)
    printf("    --require-pqc                                       Enforce usage of PQC algorithms\n");
#endif /* __ENABLE_MOCANA_PQC__ */
#endif /* __ENABLE_MOCANA_MQTT_SAMPLE_LIBRARY__ */
    printf("\n");
    printf("     Note: MQTT v3.1.1 does not support properties\n");
    printf("\n");
    if (NULL != pErrStringFormat)
    {
        va_list args;
        va_start(args, pErrStringFormat);
        vsnprintf(pBuffer, sizeof(pBuffer), pErrStringFormat, args);
        va_end(args);
        printf("ERROR: %s\n", pBuffer);
        return ERR_INVALID_ARG;
    }
    return OK;
}

/*----------------------------------------------------------------------------*/

static void setStringParameter(
    char** param,
    char* value)
{
    *param = MALLOC((MOC_STRLEN((const sbyte *)value))+1);
    if (NULL == *param)
        return;
    (void) MOC_MEMCPY(*param, value, MOC_STRLEN((const sbyte *)value));
    (*param)[MOC_STRLEN((const sbyte *)value)] = '\0';
}

/*----------------------------------------------------------------------------*/

static MSTATUS MQTT_EXAMPLE_addSubTopic(
    MqttClientExampleCtx *pCtx,
    char *pTopic)
{
    MSTATUS status;
    MqttSubscribeTopic *pTopics = NULL;
    sbyte4 topicLen;

    topicLen = MOC_STRLEN(pTopic);

    if (NULL == pCtx->pTopics)
    {
        status = MOC_CALLOC(
            (void **) &pCtx->pTopics, 1, sizeof(MqttSubscribeTopic));
        if (OK != status)
            goto exit;

        status = MOC_MALLOC_MEMCPY(
            (void **) &pCtx->pTopics->pTopic, topicLen,
            pTopic, topicLen);
        if (OK != status)
            goto exit;

        pCtx->pTopics->topicLen = topicLen;
        pCtx->pTopics->qos = MQTT_QOS_2;
        pCtx->topicCount = 1;
    }
    else
    {
        status = MOC_CALLOC(
            (void **) &pTopics, pCtx->topicCount + 1,
            sizeof(MqttSubscribeTopic));
        if (OK != status)
            goto exit;

        MOC_MEMCPY(
            pTopics, pCtx->pTopics,
            sizeof(MqttSubscribeTopic) * pCtx->topicCount);

        status = MOC_MALLOC_MEMCPY(
            (void **) &((pTopics + pCtx->topicCount)->pTopic), topicLen,
            pTopic, topicLen);
        if (OK != status)
            goto exit;

        (pTopics + pCtx->topicCount)->topicLen = topicLen;
        (pTopics + pCtx->topicCount)->qos = MQTT_QOS_2;
        MOC_FREE((void **) &pCtx->pTopics);
        pCtx->pTopics = pTopics;
        pCtx->topicCount++;
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS MQTT_EXAMPLE_addUnsubTopic(
    MqttClientExampleCtx *pCtx,
    char *pTopic)
{
    MSTATUS status;
    MqttUnsubscribeTopic *pUnsubTopics = NULL;
    sbyte4 topicLen;

    topicLen = MOC_STRLEN(pTopic);

    if (NULL == pCtx->pUnsubTopics)
    {
        status = MOC_CALLOC(
            (void **) &pCtx->pUnsubTopics, 1, sizeof(MqttSubscribeTopic));
        if (OK != status)
            goto exit;

        status = MOC_MALLOC_MEMCPY(
            (void **) &pCtx->pUnsubTopics->pTopic, topicLen,
            pTopic, topicLen);
        if (OK != status)
            goto exit;

        pCtx->pUnsubTopics->topicLen = topicLen;
        pCtx->unsubTopicCount = 1;
    }
    else
    {
        status = MOC_CALLOC(
            (void **) &pUnsubTopics, pCtx->unsubTopicCount + 1,
            sizeof(MqttSubscribeTopic));
        if (OK != status)
            goto exit;

        MOC_MEMCPY(
            pUnsubTopics, pCtx->pUnsubTopics,
            sizeof(MqttSubscribeTopic) * pCtx->unsubTopicCount);

        status = MOC_MALLOC_MEMCPY(
            (void **) &((pUnsubTopics + pCtx->unsubTopicCount)->pTopic),
            topicLen, pTopic, topicLen);
        if (OK != status)
            goto exit;

        (pUnsubTopics + pCtx->unsubTopicCount)->topicLen = topicLen;
        MOC_FREE((void **) &pCtx->pUnsubTopics);
        pCtx->pUnsubTopics = pUnsubTopics;
        pCtx->unsubTopicCount++;
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS MQTT_EXAMPLE_addUserProperty(
    MqttClientExampleCtx *pCtx,
    MqttProperty **ppProps,
    ubyte4 *propCount,
    ubyte *pKey,
    ubyte4 keyLen,
    ubyte *pValue,
    ubyte4 valueLen)
{
    MSTATUS status;
    MqttProperty *pProps = NULL;

    if (NULL == *ppProps)
    {
        status = MOC_CALLOC(
            (void **) ppProps, 1, sizeof(MqttProperty));
        if (OK != status)
            goto exit;

        status = MOC_MALLOC_MEMCPY(
            (void **) &(*ppProps)->data.pair.name.pData, keyLen, pKey, keyLen);
        if (OK != status)
            goto exit;

        (*ppProps)->data.pair.name.dataLen = keyLen;

        status = MOC_MALLOC_MEMCPY(
            (void **) &(*ppProps)->data.pair.value.pData, valueLen, pValue, valueLen);
        if (OK != status)
            goto exit;

        (*ppProps)->data.pair.value.dataLen = valueLen;
        (*propCount) = 1;
    }
    else
    {
        status = MOC_CALLOC(
            (void **) &pProps, (*propCount) + 1,
            sizeof(MqttProperty));
        if (OK != status)
            goto exit;

        MOC_MEMCPY(
            pProps, *ppProps,
            sizeof(MqttProperty) * (*propCount));

        status = MOC_MALLOC_MEMCPY(
            (void **) &((pProps + *propCount)->data.pair.name.pData), keyLen,
            pKey, keyLen);
        if (OK != status)
            goto exit;

        (pProps + *propCount)->data.pair.name.dataLen = keyLen;

        status = MOC_MALLOC_MEMCPY(
            (void **) &((pProps + *propCount)->data.pair.value.pData), valueLen,
            pValue, valueLen);
        if (OK != status)
            goto exit;

        (pProps + *propCount)->data.pair.value.dataLen = valueLen;
        MOC_FREE((void **) ppProps);
        *ppProps = pProps;
        (*propCount)++;
    }

exit:

    return status;
}
/*----------------------------------------------------------------------------*/

static MSTATUS MQTT_EXAMPLE_addMessage(
    MqttClientExampleCtx *pCtx,
    ubyte *pTopic,
    ubyte4 topicLen,
    ubyte *pData,
    ubyte4 dataLen,
    MqttQoS qos,
    byteBoolean retain)
{
    MSTATUS status;
    MqttClientExampleMsg *pMsgs = NULL;

    if (NULL == pCtx->pMsgs)
    {
        status = MOC_CALLOC(
            (void **) &pCtx->pMsgs, 1, sizeof(MqttClientExampleMsg));
        if (OK != status)
            goto exit;

        status = MOC_MALLOC_MEMCPY(
            (void **) &pCtx->pMsgs->pTopic, topicLen,
            pTopic, topicLen);
        if (OK != status)
            goto exit;

        pCtx->pMsgs->topicLen = topicLen;

        if (0 < dataLen)
        {
           status = MOC_MALLOC_MEMCPY(
            (void **) &pCtx->pMsgs->pData, dataLen,
            pData, dataLen);
            if (OK != status)
                goto exit;
        }

        pCtx->pMsgs->dataLen = dataLen;
        pCtx->pMsgs->qos = qos; /* MQTT_QOS_0; */
        pCtx->pMsgs->retain = retain; /* FALSE; */
        pCtx->msgCount = 1;
    }
    else
    {
        status = MOC_CALLOC(
            (void **) &pMsgs, pCtx->msgCount + 1,
            sizeof(MqttClientExampleMsg));
        if (OK != status)
            goto exit;

        MOC_MEMCPY(
            pMsgs, pCtx->pMsgs,
            sizeof(MqttClientExampleMsg) * pCtx->msgCount);

        status = MOC_MALLOC_MEMCPY(
            (void **) &((pMsgs + pCtx->msgCount)->pTopic), topicLen,
            pTopic, topicLen);
        if (OK != status)
            goto exit;

        (pMsgs + pCtx->msgCount)->topicLen = topicLen;

        if (0 < dataLen)
        {
            status = MOC_MALLOC_MEMCPY(
                (void **) &((pMsgs + pCtx->msgCount)->pData), dataLen,
                pData, dataLen);
            if (OK != status)
                goto exit;
        }

        (pMsgs + pCtx->msgCount)->dataLen = dataLen;
        (pMsgs + pCtx->msgCount)->qos = qos; /* MQTT_QOS_0; */
        (pMsgs + pCtx->msgCount)->retain = retain; /* FALSE; */
        MOC_FREE((void **) &pCtx->pMsgs);
        pCtx->pMsgs = pMsgs;
        pCtx->msgCount++;
    }

exit:

    return status;
}

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_MOCANA_SSL_CLIENT__)

static MSTATUS MQTT_EXAMPLE_addTrustPointFile(
    certStorePtr pStore,
    sbyte *pFile)
{
    MSTATUS status;
    ubyte *pData = NULL, *pTemp = NULL;
    ubyte4 dataLen = 0, tempLen = 0;

    status = MOCANA_readFile(pFile, &pData, &dataLen);
    if (OK != status)
        goto exit;

    status = CA_MGMT_decodeCertificate(pData, dataLen, &pTemp, &tempLen);
    if (OK == status)
    {
        MOC_FREE((void **) &pData);
        pData = pTemp;
        dataLen = tempLen;
    }

    status = CERT_STORE_addTrustPoint(pStore, pData, dataLen);

exit:

    if (NULL != pData)
    {
        MOC_FREE((void **) &pData);
    }

    return status;
}

#endif /* __ENABLE_MOCANA_SSL_CLIENT__ */

/*----------------------------------------------------------------------------*/

static MSTATUS MQTT_EXAMPLE_parseArgs(
    int argc,
    char **ppArgv,
    MqttClientExampleCtx *pCtx)
{
    MSTATUS status = ERR_INVALID_ARG;
    int i, j;
    sbyte *pStop = NULL;
    sbyte4 portNo = -1;
    sbyte4 numVal = -1;
    sbyte4 retainHandling;
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;
    sbyte *pCurPubTopic = NULL;
    ubyte4 curPubTopicLen = 0;
    MqttQoS qos = MQTT_QOS_0;
    sbyte *pKey = NULL;
    sbyte *pValue = NULL;
    byteBoolean propertySet = FALSE;

    i = 1;
    while (i < argc)
    {
        if (0 == MOC_STRCMP(ppArgv[i], "--help"))
        {
            status = MQTT_EXAMPLE_displayHelp(ppArgv[0], NULL);
            if (argc == 2)
            {
                pCtx->exit = TRUE;
                goto exit;
            }
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--print_hex_bytes"))
        {
            pCtx->hexBytes = TRUE;
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_servername"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_servername argument");
                goto exit;
            }
            setStringParameter((char **) &pCtx->pMqttServer, ppArgv[i]);
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_port"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_port argument");
                goto exit;
            }
            portNo = MOC_ATOL(ppArgv[i], (const sbyte **) &pStop);
            if ('\0' != *pStop)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for --mqtt_port is not valid number or too large");
                goto exit;
            }
            if (0 > portNo || 65535 < portNo)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for --mqtt_port is out of valid port range");
                goto exit;
            }
            pCtx->mqttPortNo = portNo;
        }
#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_transport"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_transport argument");
                goto exit;
            }
            if (0 == MOC_STRCMP(ppArgv[i], MQTT_TCP_TRANSPORT))
            {
                pCtx->transport = MQTT_TCP;
            }
            else if (0 == MOC_STRCMP(ppArgv[i], MQTT_SSL_TRANSPORT))
            {
                pCtx->transport = MQTT_SSL;
            }
            else
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Unrecognized transport %s argument", ppArgv[i]);
                goto exit;
            }
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--ssl_ca_file"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_transport argument");
                goto exit;
            }
            status = MQTT_EXAMPLE_addTrustPointFile(pCtx->pStore, ppArgv[i]);
            if (OK != status)
            {
                printf("MQTT_EXAMPLE_addTrustPointFile failed with status = %d on line %d\n", status, __LINE__);
                goto exit;
            }
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--ssl_allow_untrusted"))
        {
            pCtx->sslAllowUntrusted = TRUE;
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--ssl_key_file"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --ssl_key_file argument");
                goto exit;
            }
            setStringParameter((char **) &pCtx->pKeyFile, ppArgv[i]);
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--ssl_cert_file"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --ssl_cert_file argument");
                goto exit;
            }
            setStringParameter((char **) &pCtx->pCertFile, ppArgv[i]);
        }
#if defined(__ENABLE_MOCANA_HTTP_PROXY__)
        else if (0 == MOC_STRCMP(ppArgv[i], "--proxy"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --proxy argument");
                goto exit;
            }
            setStringParameter((char **) &pCtx->pProxy, ppArgv[i]);
        }
#endif /* __ENABLE_MOCANA_HTTP_PROXY__ */
#endif /* __ENABLE_MOCANA_SSL_CLIENT__ */
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_client_id"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_client_id argument");
                goto exit;
            }
            setStringParameter((char **) &pCtx->pMqttClientId, ppArgv[i]);
            pCtx->mqttClientIdLen = MOC_STRLEN(pCtx->pMqttClientId);
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_version"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_version argument");
                goto exit;
            }
            if (0 == MOC_STRCMP(ppArgv[i], "5"))
            {
                pCtx->mqttVersion = MQTT_V5;
            }
            else if (0 == MOC_STRCMP(ppArgv[i], "3.1.1"))
            {
                pCtx->mqttVersion = MQTT_V3_1_1;
            }
            else
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for --mqtt_version %s is not valid", ppArgv[i]);
                goto exit;
            }
        }
#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_async"))
        {
            pCtx->async = TRUE;
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_async_send_buffer_size"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_async_send_buffer_size argument");
                goto exit;
            }
            numVal = MOC_ATOL(ppArgv[i], (const sbyte **) &pStop);
            if ('\0' != *pStop)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for --mqtt_async_send_buffer_size is not valid number or too large");
                goto exit;
            }
            if (0 >= numVal)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for --mqtt_async_send_buffer_size is not valid size");
                goto exit;
            }
            pCtx->sendBufferLen = numVal;
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_async_recv_buffer_size"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_async_recv_buffer_size argument");
                goto exit;
            }
            numVal = MOC_ATOL(ppArgv[i], (const sbyte **) &pStop);
            if ('\0' != *pStop)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for --mqtt_async_recv_buffer_size is not valid number or too large");
                goto exit;
            }
            if (0 >= numVal)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for --mqtt_async_recv_buffer_size is not valid size");
                goto exit;
            }
            pCtx->recvBufferLen = numVal;
        }
#endif
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_sub_topic"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_sub_topic argument");
                goto exit;
            }
            status = MQTT_EXAMPLE_addSubTopic(pCtx, ppArgv[i]);
            if (OK != status)
                goto exit;
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_sub_topic_no_local_option"))
        {
            if (0 == pCtx->topicCount)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "No topic to apply option too, specify topic using --mqtt_sub_topic");
                goto exit;
            }
            (pCtx->pTopics + pCtx->topicCount - 1)->noLocalOption = TRUE;
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_sub_topic_retain_as_published"))
        {
            if (0 == pCtx->topicCount)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "No topic to apply option too, specify topic using --mqtt_sub_topic");
                goto exit;
            }
            (pCtx->pTopics + pCtx->topicCount - 1)->retainAsPublished = TRUE;
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_sub_topic_retain_handling"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_sub_topic_retain_handling argument");
                goto exit;
            }
            if (0 == pCtx->topicCount)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "No topic to apply option too, specify topic using --mqtt_sub_topic");
                goto exit;
            }
            retainHandling = MOC_ATOL(ppArgv[i], (const sbyte **) &pStop);
            if ('\0' != *pStop)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for --mqtt_sub_topic_retain_handling is not valid number or too large");
                goto exit;
            }
            (pCtx->pTopics + pCtx->topicCount - 1)->retainHandling = retainHandling;
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_sub_topic_single"))
        {
            pCtx->subTopicSingle = TRUE;
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_unsub_topic"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_unsub_topic argument");
                goto exit;
            }
            status = MQTT_EXAMPLE_addUnsubTopic(pCtx, ppArgv[i]);
            if (OK != status)
                goto exit;
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_unsub_topic_single"))
        {
            pCtx->unsubTopicSingle = TRUE;
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_pub_qos"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_pub_qos argument");
                goto exit;
            }

            qos = (MqttQoS)MOC_ATOL(ppArgv[i], (const sbyte **) &pStop);
            if ('\0' != *pStop)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for --mqtt_pub_qos is not valid number or too large");
                goto exit;
            }

            switch(qos)
            {
                case MQTT_QOS_0:
                case MQTT_QOS_1:
                case MQTT_QOS_2:
                    break;

                default:
                {
                    status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for --mqtt_pub_qos is not valid number or too large");
                    goto exit;
                }
            }

            if (pCtx->msgCount == 0)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Must provide --mqtt_pub_message/--mqtt_pub_file before --mqtt_pub_qos argument");
                goto exit;
            }

            pCtx->pMsgs[pCtx->msgCount - 1].qos = qos;
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_pub_retain"))
        {
            if (0 == pCtx->msgCount)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Must provide --mqtt_pub_message/--mqtt_pub_file before --mqtt_pub_retain argument");
                goto exit;
            }
            
            pCtx->pMsgs[pCtx->msgCount - 1].retain = TRUE;

        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_pub_topic"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_pub_topic argument");
                goto exit;
            }
            MOC_FREE((void **) &pCurPubTopic);
            setStringParameter((char **) &pCurPubTopic, ppArgv[i]);
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_pub_message"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_pub_message argument");
                goto exit;
            }

            if (NULL == pCurPubTopic)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "No publish topic specified");
                goto exit;
            }

            status = MQTT_EXAMPLE_addMessage(
                pCtx, pCurPubTopic, MOC_STRLEN(pCurPubTopic),
                ppArgv[i], MOC_STRLEN(ppArgv[i]), MQTT_QOS_0, FALSE);
            if (OK != status)
                goto exit;

            pCtx->pMsgs[pCtx->msgCount - 1].pubOptions.setPayloadFormat = FALSE;
            pCtx->pMsgs[pCtx->msgCount - 1].pubOptions.msgExpiryIntervalSet = FALSE;

            
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_pub_file"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_pub_file argument");
                goto exit;
            }

            if (NULL == pCurPubTopic)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "No publish topic specified");
                goto exit;
            }

            status = MOCANA_readFile(ppArgv[i], &pData, &dataLen);
            if (OK != status)
                goto exit;

            status = MQTT_EXAMPLE_addMessage(
                pCtx, pCurPubTopic, MOC_STRLEN(pCurPubTopic), pData, dataLen, MQTT_QOS_0, FALSE);
            MOC_FREE((void **) &pData);
            if (OK != status)
                goto exit;
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_clean_start"))
        {
            pCtx->mqttConnectOptions.cleanStart = TRUE;
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_session_expiry_interval"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_session_expiry_interval argument");
                goto exit;
            }
            numVal = MOC_ATOL(ppArgv[i], (const sbyte **) &pStop);
            if ('\0' != *pStop)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for --mqtt_session_expiry_interval is not valid number or too large");
                goto exit;
            }

            pCtx->mqttConnectOptions.sessionExpiryIntervalSet = TRUE;
            pCtx->mqttConnectOptions.sessionExpiryIntervalSeconds = (ubyte4) numVal;
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_keep_alive"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_keep_alive argument");
                goto exit;
            }
            numVal = MOC_ATOL(ppArgv[i], (const sbyte **) &pStop);
            if ('\0' != *pStop)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for --mqtt_keep_alive is not valid number or too large");
                goto exit;
            }
            pCtx->mqttConnectOptions.keepAliveInterval = numVal;
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_username"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_username argument");
                goto exit;
            }
            setStringParameter((char **) &(pCtx->mqttConnectOptions.pUsername), ppArgv[i]);
            pCtx->mqttConnectOptions.usernameLen = MOC_STRLEN(ppArgv[i]);
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_password"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_password argument");
                goto exit;
            }
            setStringParameter((char **) &(pCtx->mqttConnectOptions.pPassword), ppArgv[i]);
            pCtx->mqttConnectOptions.passwordLen = MOC_STRLEN(ppArgv[i]);
        }
#ifdef __ENABLE_DIGICERT_SCRAM_CLIENT__
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_scram_username"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_scram_username argument");
                goto exit;
            }
            setStringParameter((char **) &(pCtx->pScramUser), ppArgv[i]);
            pCtx->scramUserLen = MOC_STRLEN(ppArgv[i]);
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_scram_password"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_scram_password argument");
                goto exit;
            }
            setStringParameter((char **) &(pCtx->pScramPass), ppArgv[i]);
            pCtx->scramPassLen = MOC_STRLEN(ppArgv[i]);
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_scram_hash_alg"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_scram_hash_alg argument");
                goto exit;
            }

            if (0 == MOC_STRCMP(ppArgv[i], "SHA256"))
            {
                pCtx->scramHashType = ht_sha256;

                if (NULL != pCtx->mqttConnectOptions.pAuthMethod)
                {
                    status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Cannot set both mqtt_scram_* and mqtt_auth_method");
                    goto exit;
                }
                setStringParameter((char **) &(pCtx->mqttConnectOptions.pAuthMethod), pScramMethodSha256);
                pCtx->mqttConnectOptions.authMethodLen = MOC_STRLEN(pScramMethodSha256);
            }
            else if(0 == MOC_STRCMP(ppArgv[i], "SHA512"))
            {
                pCtx->scramHashType = ht_sha512;

                if (NULL != pCtx->mqttConnectOptions.pAuthMethod)
                {
                    status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Cannot set both mqtt_scram_* and mqtt_auth_method");
                    goto exit;
                }
                setStringParameter((char **) &(pCtx->mqttConnectOptions.pAuthMethod), pScramMethodSha512);
                pCtx->mqttConnectOptions.authMethodLen = MOC_STRLEN(pScramMethodSha512);
            }
            else
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing valid --mqtt_scram_hash_alg argument");
                goto exit;
            }
        }
#endif
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_will_topic"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_will_topic argument");
                goto exit;
            }
            setStringParameter((char **) &(pCtx->mqttConnectOptions.willInfo.pWillTopic), ppArgv[i]);
            pCtx->mqttConnectOptions.willInfo.willTopicLen = MOC_STRLEN(ppArgv[i]);
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_will_message"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_will_message argument");
                goto exit;
            }

            if (NULL == pCtx->mqttConnectOptions.willInfo.pWillTopic)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "No will topic specified");
                goto exit;
            }
            setStringParameter((char **) &(pCtx->mqttConnectOptions.willInfo.pWill), ppArgv[i]);
            pCtx->mqttConnectOptions.willInfo.willLen = MOC_STRLEN(ppArgv[i]);
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_will_qos"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_will_qos argument");
                goto exit;
            }
            if (NULL == pCtx->mqttConnectOptions.willInfo.pWillTopic)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "No will topic specified");
                goto exit;
            }

            qos = (MqttQoS)MOC_ATOL(ppArgv[i], (const sbyte **) &pStop);
            if ('\0' != *pStop)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for --mqtt_will_qos is not valid number or too large");
                goto exit;
            }

            switch(qos)
            {
                case MQTT_QOS_0:
                case MQTT_QOS_1:
                case MQTT_QOS_2:
                    break;

                default:
                {
                    status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for --mqtt_will_qos is not valid number or too large");
                    goto exit;
                }
            }

            pCtx->mqttConnectOptions.willInfo.qos = qos;
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_will_retain"))
        {
            if (NULL == pCtx->mqttConnectOptions.willInfo.pWillTopic)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Must provide --mqtt_will_topic before --mqtt_will_retain argument");
                goto exit;
            }

            pCtx->mqttConnectOptions.willInfo.retain = TRUE;

        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_connect_properties"))
        {
            propertySet = TRUE;
            i++;
            while (i < argc && ppArgv[i][0] != '-')
            {
                if (i >= argc)
                {
                    status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_connect_properties argument");
                    goto exit;
                }
                if (0 == MOC_STRCMP(ppArgv[i], "session_expiry_interval"))
                {
                    i++;
                    if (i >= argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing session_expiry_interval value");
                        goto exit;
                    }
                    numVal = MOC_ATOL(ppArgv[i], (const sbyte **) &pStop);
                    if ('\0' != *pStop)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for session_expiry_interval is not valid number or too large");
                        goto exit;
                    }

                    if (TRUE == pCtx->mqttConnectOptions.sessionExpiryIntervalSet)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Duplicate property value for session_expiry_interval");
                        goto exit;
                    }
                    pCtx->mqttConnectOptions.sessionExpiryIntervalSet = TRUE;
                    pCtx->mqttConnectOptions.sessionExpiryIntervalSeconds = (ubyte4) numVal;

                }
                else if (0 == MOC_STRCMP(ppArgv[i], "receive_maximum"))
                {
                    i++;
                    if (i >= argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing receive_maximum value");
                        goto exit;
                    }
                    numVal = MOC_ATOL(ppArgv[i], (const sbyte **) &pStop);
                    if ('\0' != *pStop)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for receive_maximum is not valid number or too large");
                        goto exit;
                    }
                    if (TRUE == pCtx->mqttConnectOptions.receiveMaxSet)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Duplicate property value for receive_maximum");
                        goto exit;
                    }
                    pCtx->mqttConnectOptions.receiveMaxSet = TRUE;
                    pCtx->mqttConnectOptions.receiveMax = (ubyte2) numVal;
                }
                else if (0 == MOC_STRCMP(ppArgv[i], "max_packet_size"))
                {
                    i++;
                    if (i >= argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing max_packet_size argument");
                        goto exit;
                    }
                    numVal = MOC_ATOL(ppArgv[i], (const sbyte **) &pStop);
                    if ('\0' != *pStop)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for max_packet_size is not valid number or too large");
                        goto exit;
                    }
                    if (TRUE == pCtx->mqttConnectOptions.maxPacketSizeSet)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Duplicate property value for max_packet_size");
                        goto exit;
                    }
                    pCtx->mqttConnectOptions.maxPacketSizeSet = TRUE;
                    pCtx->mqttConnectOptions.maxPacketSize = (ubyte4) numVal;
                }
                else if (0 == MOC_STRCMP(ppArgv[i], "topic_alias_max"))
                {
                    i++;
                    if (i >= argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing topic_alias_max argument");
                        goto exit;
                    }
                    numVal = MOC_ATOL(ppArgv[i], (const sbyte **) &pStop);
                    if ('\0' != *pStop)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for topic_alias_max is not valid number or too large");
                        goto exit;
                    }
                    if (TRUE == pCtx->mqttConnectOptions.topicAliasMaxSet)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Duplicate property value for topic_alias_max");
                        goto exit;
                    }
                    pCtx->mqttConnectOptions.topicAliasMaxSet = TRUE;
                    pCtx->mqttConnectOptions.topicAliasMax = (ubyte2) numVal;
                }
                else if (0 == MOC_STRCMP(ppArgv[i], "request_response_info"))
                {
                    pCtx->mqttConnectOptions.requestResponseInfo = TRUE;
                }
                else if (0 == MOC_STRCMP(ppArgv[i], "request_problem_info"))
                {
                    pCtx->mqttConnectOptions.requestProblemInfo = TRUE;
                }
                else if (0 == MOC_STRCMP(ppArgv[i], "auth_method"))
                {
                    i++;
                    if (i >= argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing auth_method argument");
                        goto exit;
                    }
                    setStringParameter((char **) &(pCtx->mqttConnectOptions.pAuthMethod), ppArgv[i]);
                    pCtx->mqttConnectOptions.authMethodLen = MOC_STRLEN(ppArgv[i]);
                }
                else if (0 == MOC_STRCMP(ppArgv[i], "auth_data"))
                {
                    i++;
                    if (i >= argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing auth_data argument");
                        goto exit;
                    }
                    setStringParameter((char **) &(pCtx->mqttConnectOptions.pAuthData), ppArgv[i]);
                    pCtx->mqttConnectOptions.authDataLen = MOC_STRLEN(ppArgv[i]);
                }
                else if (0 == MOC_STRCMP(ppArgv[i], "user_property"))
                {
                    i++;
                    if (i > argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing key argument");
                        goto exit;
                    }
                    MOC_FREE((void **) &pKey);
                    setStringParameter((char **) &pKey, ppArgv[i]);

                    i++;
                    if (i > argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing value argument");
                        goto exit;
                    }
                    MOC_FREE((void **) &pValue);
                    setStringParameter((char **) &pValue, ppArgv[i]);

                    status = MQTT_EXAMPLE_addUserProperty(pCtx, &pCtx->mqttConnectOptions.pProps, &pCtx->mqttConnectOptions.propCount, pKey, MOC_STRLEN(pKey), pValue, MOC_STRLEN(pValue));
                    if (OK != status)
                        goto exit;
                }
                else
                {
                    status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument %s not recognized", ppArgv[i]);
                    goto exit;
                }
                i++;
           }
           i--;
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_publish_properties"))
        {
            propertySet = TRUE;
            if (pCtx->msgCount == 0)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Must provide --mqtt_pub_message/--mqtt_pub_file before --mqtt_publish_properties argument");
                goto exit;
            }
            i++;
            while (i < argc && ppArgv[i][0] != '-')
            {
                if (i >= argc)
                {
                    status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_publish_properties argument");
                    goto exit;
                }
                if (0 == MOC_STRCMP(ppArgv[i], "payload_format_indicator"))
                {
                    i++;
                    if (i >= argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing payload_format_indicator value");
                        goto exit;
                    }
                    numVal = MOC_ATOL(ppArgv[i], (const sbyte **) &pStop);
                    if ('\0' != *pStop)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for payload_format_indicator is not valid number or too large");
                        goto exit;
                    }

                    if (TRUE == pCtx->pMsgs[pCtx->msgCount - 1].pubOptions.setPayloadFormat)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Duplicate property value for payload_format_indicator");
                        goto exit;
                    }

                    pCtx->pMsgs[pCtx->msgCount - 1].pubOptions.payloadFormat = (ubyte) numVal;
                    pCtx->pMsgs[pCtx->msgCount - 1].pubOptions.setPayloadFormat = TRUE;

                }
                else if (0 == MOC_STRCMP(ppArgv[i], "message_expiry_interval"))
                {
                    i++;
                    if (i >= argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing message_expiry_interval value");
                        goto exit;
                    }
                    numVal = MOC_ATOL(ppArgv[i], (const sbyte **) &pStop);
                    if ('\0' != *pStop)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for message_expiry_interval is not valid number or too large");
                        goto exit;
                    }
                    if (TRUE == pCtx->pMsgs[pCtx->msgCount - 1].pubOptions.msgExpiryIntervalSet)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Duplicate property value for message_expiry_interval");
                        goto exit;
                    }
                    pCtx->pMsgs[pCtx->msgCount - 1].pubOptions.msgExpiryIntervalSet = TRUE;
                    pCtx->pMsgs[pCtx->msgCount - 1].pubOptions.msgExpiryInterval= (ubyte4) numVal;
                }
                else if (0 == MOC_STRCMP(ppArgv[i], "topic_alias"))
                {
                    i++;
                    if (i >= argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing topic_alias argument");
                        goto exit;
                    }
                    numVal = MOC_ATOL(ppArgv[i], (const sbyte **) &pStop);
                    if ('\0' != *pStop)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for topic_alias is not valid number or too large");
                        goto exit;
                    }
                    curPubTopicLen = MOC_STRLEN(pCurPubTopic);
                    for (j = 0; (ubyte4)j < pCtx->msgCount - 1; j++)
                    {
                        if (curPubTopicLen != pCtx->pMsgs[j].topicLen)
                        {
                            if ((pCtx->pMsgs[j].pubOptions.topicAlias == (ubyte2) numVal))
                            {
                                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Duplicate property value for topic_alias");
                                goto exit;
                            }
                        }
                        else
                        {
                            if (((0 != (MOC_STRNCMP(pCurPubTopic, pCtx->pMsgs[j].pTopic, pCtx->pMsgs[j].topicLen))) && (pCtx->pMsgs[j].pubOptions.topicAlias == (ubyte2) numVal)) ||
                                ((0 == (MOC_STRNCMP(pCurPubTopic, pCtx->pMsgs[j].pTopic, pCtx->pMsgs[j].topicLen))) && (pCtx->pMsgs[j].pubOptions.topicAlias != (ubyte2) numVal)))
                            {
                                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Duplicate property value for topic_alias");
                                goto exit;
                            }
                        }
                    }

                    pCtx->pMsgs[pCtx->msgCount - 1].pubOptions.topicAliasSet = TRUE;
                    pCtx->pMsgs[pCtx->msgCount - 1].pubOptions.topicAlias = (ubyte2) numVal;
                }
                else if (0 == MOC_STRCMP(ppArgv[i], "response_topic"))
                {
                    i++;
                    if (i >= argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing response_topic argument");
                        goto exit;
                    }
                    setStringParameter((char **) &(pCtx->pMsgs[pCtx->msgCount - 1].pubOptions.pResponseTopic), ppArgv[i]);
                    pCtx->pMsgs[pCtx->msgCount - 1].pubOptions.responseTopicLen = MOC_STRLEN(ppArgv[i]);
                }
                else if (0 == MOC_STRCMP(ppArgv[i], "correlation_data"))
                {
                    i++;
                    if (i >= argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing correlation_data argument");
                        goto exit;
                    }
                    setStringParameter((char **) &(pCtx->pMsgs[pCtx->msgCount - 1].pubOptions.pCorrelationData), ppArgv[i]);
                    pCtx->pMsgs[pCtx->msgCount - 1].pubOptions.correlationDataLen = MOC_STRLEN(ppArgv[i]);
                }
                else if (0 == MOC_STRCMP(ppArgv[i], "content_type"))
                {
                    i++;
                    if (i >= argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing content_type argument");
                        goto exit;
                    }
                    setStringParameter((char **) &(pCtx->pMsgs[pCtx->msgCount - 1].pubOptions.pContentType), ppArgv[i]);
                    pCtx->pMsgs[pCtx->msgCount - 1].pubOptions.contentTypeLen = MOC_STRLEN(ppArgv[i]);
                }
                else if (0 == MOC_STRCMP(ppArgv[i], "user_property"))
                {
                    i++;
                    if (i > argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing key argument");
                        goto exit;
                    }
                    MOC_FREE((void **) &pKey);
                    setStringParameter((char **) &pKey, ppArgv[i]);

                    i++;
                    if (i > argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing value argument");
                        goto exit;
                    }
                    MOC_FREE((void **) &pValue);
                    setStringParameter((char **) &pValue, ppArgv[i]);

                    status = MQTT_EXAMPLE_addUserProperty(pCtx, &pCtx->pMsgs[pCtx->msgCount - 1].pubOptions.pProps, &pCtx->pMsgs[pCtx->msgCount - 1].pubOptions.propCount, pKey, MOC_STRLEN(pKey), pValue, MOC_STRLEN(pValue));
                    if (OK != status)
                        goto exit;
                }
                else
                {
                    status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument %s not recognized", ppArgv[i]);
                    goto exit;
                }
                i++;
           }
           i--;
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_subscribe_properties"))
        {
            propertySet = TRUE;
            i++;
            while (i < argc && ppArgv[i][0] != '-')
            {
                if (i >= argc)
                {
                    status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_subscribe_properties argument");
                    goto exit;
                }
                if (0 == MOC_STRCMP(ppArgv[i], "user_property"))
                {
                    if (pCtx->topicCount == 0)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Must provide --mqtt_sub_topic before --mqtt_subscribe_properties argument");
                        goto exit;
                    }
                    i++;
                    if (i > argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing key argument");
                        goto exit;
                    }
                    MOC_FREE((void **) &pKey);
                    setStringParameter((char **) &pKey, ppArgv[i]);

                    i++;
                    if (i > argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing value argument");
                        goto exit;
                    }
                    MOC_FREE((void **) &pValue);
                    setStringParameter((char **) &pValue, ppArgv[i]);

                    status = MQTT_EXAMPLE_addUserProperty(pCtx, &pCtx->mqttSubscribeOptions.pProps, &pCtx->mqttSubscribeOptions.propCount, pKey, MOC_STRLEN(pKey), pValue, MOC_STRLEN(pValue));
                    if (OK != status)
                        goto exit;
                }
                else
                {
                    status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument %s not recognized", ppArgv[i]);
                    goto exit;
                }
                i++;
           }
           i--;
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_unsubscribe_properties"))
        {
            propertySet = TRUE;
            i++;
            while (i < argc && ppArgv[i][0] != '-')
            {
                if (i >= argc)
                {
                    status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_unsubscribe_properties argument");
                    goto exit;
                }
                if (0 == MOC_STRCMP(ppArgv[i], "user_property"))
                {
                    if (pCtx->unsubTopicCount == 0)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Must provide --mqtt_unsub_topic before --mqtt_unsubscribe_properties argument");
                        goto exit;
                    }
                    i++;
                    if (i > argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing key argument");
                        goto exit;
                    }
                    MOC_FREE((void **) &pKey);
                    setStringParameter((char **) &pKey, ppArgv[i]);

                    i++;
                    if (i > argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing value argument");
                        goto exit;
                    }
                    MOC_FREE((void **) &pValue);
                    setStringParameter((char **) &pValue, ppArgv[i]);

                    status = MQTT_EXAMPLE_addUserProperty(pCtx, &pCtx->mqttUnsubscribeOptions.pProps, &pCtx->mqttUnsubscribeOptions.propCount, pKey, MOC_STRLEN(pKey), pValue, MOC_STRLEN(pValue));
                    if (OK != status)
                        goto exit;
                }
                else
                {
                    status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument %s not recognized", ppArgv[i]);
                    goto exit;
                }
                i++;
           }
           i--;
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_will_properties"))
        {
            propertySet = TRUE;
            i++;
            while (i < argc && ppArgv[i][0] != '-')
            {
                if (i >= argc)
                {
                    status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_will_properties argument");
                    goto exit;
                }
                if (0 == MOC_STRCMP(ppArgv[i], "message_expiry_interval"))
                {
                    i++;
                    if (i >= argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing message_expiry_interval value");
                        goto exit;
                    }
                    numVal = MOC_ATOL(ppArgv[i], (const sbyte **) &pStop);
                    if ('\0' != *pStop)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for message_expiry_interval is not valid number or too large");
                        goto exit;
                    }

                    if (TRUE == pCtx->mqttConnectOptions.willInfo.msgExpiryIntervalSet)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Duplicate property value for message_expiry_interval");
                        goto exit;
                    }

                    pCtx->mqttConnectOptions.willInfo.msgExpiryIntervalSet = TRUE;
                    pCtx->mqttConnectOptions.willInfo.msgExpiryInterval = (ubyte4) numVal;

                }
                else if (0 == MOC_STRCMP(ppArgv[i], "content_type"))
                {
                    i++;
                    if (i >= argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing content_type argument");
                        goto exit;
                    }
                    setStringParameter((char **) &(pCtx->mqttConnectOptions.willInfo.pContentType), ppArgv[i]);
                    pCtx->mqttConnectOptions.willInfo.contentTypeLen = MOC_STRLEN(ppArgv[i]);
                }
                else if (0 == MOC_STRCMP(ppArgv[i], "response_topic"))
                {
                    i++;
                    if (i >= argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing response_topic argument");
                        goto exit;
                    }
                    setStringParameter((char **) &(pCtx->mqttConnectOptions.willInfo.pResponseTopic), ppArgv[i]);
                    pCtx->mqttConnectOptions.willInfo.responseTopicLen = MOC_STRLEN(ppArgv[i]);
                }
                else if (0 == MOC_STRCMP(ppArgv[i], "correlation_data"))
                {
                    i++;
                    if (i >= argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing correlation_data argument");
                        goto exit;
                    }
                    setStringParameter((char **) &(pCtx->mqttConnectOptions.willInfo.pCorrelationData), ppArgv[i]);
                    pCtx->mqttConnectOptions.willInfo.correlationDataLen = MOC_STRLEN(ppArgv[i]);
                }
                else if (0 == MOC_STRCMP(ppArgv[i], "payload_format_indicator"))
                {
                    i++;
                    if (i >= argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing payload_format_indicator value");
                        goto exit;
                    }
                    numVal = MOC_ATOL(ppArgv[i], (const sbyte **) &pStop);
                    if ('\0' != *pStop)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for payload_format_indicator is not valid number or too large");
                        goto exit;
                    }

                    if (TRUE == pCtx->mqttConnectOptions.willInfo.setPayloadFormat)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Duplicate property value for payload_format_indicator");
                        goto exit;
                    }

                    pCtx->mqttConnectOptions.willInfo.setPayloadFormat = TRUE;
                    pCtx->mqttConnectOptions.willInfo.payloadFormat = (ubyte) numVal;

                }
                else if (0 == MOC_STRCMP(ppArgv[i], "will_delay_interval"))
                {
                    i++;
                    if (i >= argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing will_delay_interval value");
                        goto exit;
                    }
                    numVal = MOC_ATOL(ppArgv[i], (const sbyte **) &pStop);
                    if ('\0' != *pStop)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for will_delay_interval is not valid number or too large");
                        goto exit;
                    }

                    if (TRUE == pCtx->mqttConnectOptions.willInfo.willDelayIntervalSet)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Duplicate property value for will_delay_interval");
                        goto exit;
                    }

                    pCtx->mqttConnectOptions.willInfo.willDelayIntervalSet = TRUE;
                    pCtx->mqttConnectOptions.willInfo.willDelayInterval = (ubyte4) numVal;

                }
                else if (0 == MOC_STRCMP(ppArgv[i], "user_property"))
                {
                    i++;
                    if (i > argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing key argument");
                        goto exit;
                    }
                    MOC_FREE((void **) &pKey);
                    setStringParameter((char **) &pKey, ppArgv[i]);

                    i++;
                    if (i > argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing value argument");
                        goto exit;
                    }
                    MOC_FREE((void **) &pValue);
                    setStringParameter((char **) &pValue, ppArgv[i]);

                    status = MQTT_EXAMPLE_addUserProperty(pCtx, &pCtx->mqttConnectOptions.willInfo.pProps, &pCtx->mqttConnectOptions.willInfo.propCount, pKey, MOC_STRLEN(pKey), pValue, MOC_STRLEN(pValue));
                    if (OK != status)
                        goto exit;
                }
                else
                {
                    status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument %s not recognized", ppArgv[i]);
                    goto exit;
                }
                i++;
           }
           i--;
        }

        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_disconnect_properties"))
        {
            propertySet = TRUE;
            i++;
            while (i < argc && ppArgv[i][0] != '-')
            {
                if (i >= argc)
                {
                    status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --mqtt_disconnect_properties argument");
                    goto exit;
                }
                if (0 == MOC_STRCMP(ppArgv[i], "session_expiry_interval"))
                {
                    i++;
                    if (i >= argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing session_expiry_interval value");
                        goto exit;
                    }
                    numVal = MOC_ATOL(ppArgv[i], (const sbyte **) &pStop);
                    if ('\0' != *pStop)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument for session_expiry_interval is not valid number or too large");
                        goto exit;
                    }

                    pCtx->mqttDisconnectOptions.sessionExpiryInterval = (ubyte4) numVal;
                    pCtx->mqttDisconnectOptions.sendSessionExpiry = TRUE;

                }
                else if (0 == MOC_STRCMP(ppArgv[i], "user_property"))
                {
                    i++;
                    if (i > argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing key argument");
                        goto exit;
                    }
                    MOC_FREE((void **) &pKey);
                    setStringParameter((char **) &pKey, ppArgv[i]);

                    i++;
                    if (i > argc)
                    {
                        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing value argument");
                        goto exit;
                    }
                    MOC_FREE((void **) &pValue);
                    setStringParameter((char **) &pValue, ppArgv[i]);

                    status = MQTT_EXAMPLE_addUserProperty(pCtx, &pCtx->mqttDisconnectOptions.pProps, &pCtx->mqttDisconnectOptions.propCount, pKey, MOC_STRLEN(pKey), pValue, MOC_STRLEN(pValue));
                    if (OK != status)
                        goto exit;
                }
                else
                {
                    status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument %s not recognized", ppArgv[i]);
                    goto exit;
                }
                i++;
           }
           i--; 
        }
#if defined(__ENABLE_MOCANA_PQC__)
        else if (0 == MOC_STRCMP(ppArgv[i], "--require-pqc"))
        {
            /* Do nothing */
        }
#endif
        else
        {
            status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Argument %s not recognized", ppArgv[i]);
            goto exit;
        }
        i++;
    }

    if (NULL == pCtx->pMqttServer)
    {
        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "--mqtt_servername required");
        goto exit;
    }

    if (-1 == portNo)
    {
        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "--mqtt_port required");
        goto exit;
    }

    if ((FALSE == pCtx->mqttConnectOptions.cleanStart) && (0 == pCtx->mqttClientIdLen))
    {
        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "--mqtt_client_id required to resume a session");
        goto exit;
    }

    /* MQTT 3.1.1: If password is included, username is also required */
    if ((pCtx->mqttVersion == MQTT_V3_1_1) && (pCtx->mqttConnectOptions.passwordLen != 0) && (pCtx->mqttConnectOptions.usernameLen == 0))
    {
        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "--mqtt_username is required");
        goto exit;
    }

    if ((pCtx->mqttConnectOptions.sessionExpiryIntervalSeconds == 0) && (pCtx->mqttDisconnectOptions.sessionExpiryInterval != 0))
    {
        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Cannot set session expiry interval in disconnect properties if session expiry interval is not set in connect\n");
        goto exit;
    }

    if ((pCtx->mqttVersion == MQTT_V3_1_1) && propertySet)
    {
        status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Properties are not supported in MQTT v3.1.1\n");
        goto exit;
    }

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    if (TRUE == pCtx->async)
    {
        if (0 == pCtx->sendBufferLen)
            pCtx->sendBufferLen = MQTT_ASYNC_SEND_BUFFER_SIZE;

        status = MOC_MALLOC(
            (void **) &pCtx->pSendBuffer, pCtx->sendBufferLen);
        if (OK != status)
        {
            printf("MOC_MALLOC failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }

        if (0 == pCtx->recvBufferLen)
            pCtx->recvBufferLen = MQTT_ASYNC_RECV_BUFFER_SIZE;

        status = MOC_MALLOC(
            (void **) &pCtx->pRecvBuffer, pCtx->recvBufferLen);
        if (OK != status)
        {
            printf("MOC_MALLOC failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }
    }
#endif

    status = OK;

exit:

    MOC_FREE((void **) &pCurPubTopic);
    MOC_FREE((void **) &pKey);
    MOC_FREE((void **) &pValue);
    return status;
}

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_MOCANA_SSL_CLIENT__)

static MSTATUS MQTT_EXAMPLE_sslCertStatusCb(
    sbyte4 sslConnectionInstance,
    struct certChain *pCertChain,
    MSTATUS validationStatus)
{
    MSTATUS status = OK;
    MqttClientExampleCtx *pCtx = NULL;

    if (OK == validationStatus)
    {
        printf("SSL Certificate is trusted\n");
    }
    else
    {
        status = SSL_getCookie(sslConnectionInstance, (void **) &pCtx);
        if (OK != status)
        {
            printf("SSL_getCookie failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }

        if (TRUE == pCtx->sslAllowUntrusted)
        {
            printf("Allowing untrusted certificate\n");
            status = OK;
        }
        else
        {
            printf("SSL Certificate is not trusted\n");
            status = validationStatus;
        }
    }

exit:

    return status;
}

#endif

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)

static MSTATUS MQTT_EXAMPLE_sendPendingData(
    sbyte4 connInst)
{
    MSTATUS status;
    MqttClientExampleCtx *pCtx = NULL;
    ubyte4 sendNumBytes;
    ubyte4 bytesWritten;

    status = MQTT_getCookie(connInst, (void **) &pCtx);
    if (OK != status)
    {
        printf("MQTT_getCookie failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

    do
    {
        sendNumBytes = pCtx->sendBufferLen;
        status = MQTT_getSendBuffer(connInst, pCtx->pSendBuffer, &sendNumBytes);
        if (OK != status)
        {
            printf("MQTT_getSendBuffer failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }

        if (0 < sendNumBytes)
        {
#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
            if (MQTT_SSL == pCtx->transport)
            {
                status = SSL_send(
                    pCtx->sslConnInst, pCtx->pSendBuffer, sendNumBytes);
                if (OK > status)
                {
                    printf("SSL_send failed with status = %d on line %d\n", status, __LINE__);
                    goto exit;
                }
            }
            else
#endif
            {
                status = TCP_WRITE(
                    pCtx->socket, pCtx->pSendBuffer, sendNumBytes, &bytesWritten);
                if (OK != status)
                {
                    printf("TCP_WRITE failed with status = %d on line %d\n", status, __LINE__);
                    goto exit;
                }
            }
        }

    } while (0 != sendNumBytes);

exit:

    return status;
}

#endif

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_MOCANA_SSL_CLIENT__)

static MSTATUS MQTT_EXAMPLE_getClientCertCallback(
    sbyte4 connInst,
    SizedBuffer **ppRetCert,
    ubyte4 *pRetNumCerts,
    ubyte **ppRetKeyBlob,
    ubyte4 *pRetKeyBlobLen,
    ubyte **ppRetCACert,
    ubyte4 *pRetNumCACerts)
{
    MSTATUS status;
    MqttClientExampleCtx *pCtx = NULL;
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;
    ubyte *pTmp = NULL;
    ubyte4 tmpLen = 0;
    AsymmetricKey asymKey = { 0 };

    CRYPTO_initAsymmetricKey(&asymKey);

    status = SSL_getCookie(connInst, (void **) &pCtx);
    if (OK != status)
    {
        printf("SSL_getCookie failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

    if (NULL != pCtx->pKeyFile && NULL != pCtx->pCertFile)
    {
        status = MOCANA_readFile(pCtx->pCertFile, &pData, &dataLen);
        if (OK != status)
        {
            printf("MOCANA_readFile failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }

        status = CA_MGMT_decodeCertificate(pData, dataLen, &pTmp, &tmpLen);
        if (OK == status)
        {
            MOC_FREE((void **) &pData);
            pData = pTmp;
            dataLen = tmpLen;
        }

        (*ppRetCert)->data = pData;
        (*ppRetCert)->length = dataLen;
        *pRetNumCerts = 1;

        status = MOCANA_readFile(pCtx->pKeyFile, &pData, &dataLen);
        if (OK != status)
        {
            printf("MOCANA_readFile failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }

        status = CRYPTO_deserializeAsymKey(pData, dataLen, NULL, &asymKey);
        if (OK != status)
        {
            printf("CRYPTO_deserializeAsymKey failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }

        status = KEYBLOB_makeKeyBlobEx(&asymKey, ppRetKeyBlob, pRetKeyBlobLen);
        if (OK != status)
        {
            printf("KEYBLOB_makeKeyBlobEx failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }
    }

exit:

    if (NULL != pData)
    {
        MOC_FREE((void **) &pData);
    }

    CRYPTO_uninitAsymmetricKey(&asymKey, NULL);

    return status;
}

#endif

/*----------------------------------------------------------------------------*/

static int published = 0;

/*----------------------------------------------------------------------------*/
static volatile sig_atomic_t shutdownClient;

void MQTT_signalHandler(int dummy)
{
    shutdownClient = 1;
}

MSTATUS MQTT_setupSignalHandler(int signal)
{
    MSTATUS status = OK;
    struct sigaction sa;
    sa.sa_handler = MQTT_signalHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    /* Register the signal handler */
    if (sigaction(signal, &sa, NULL) == -1) {
        status = ERR_MQTT;
    }

    return status;
}

/*----------------------------------------------------------------------------*/


#if defined(__ENABLE_MOCANA_MQTT_SAMPLE_LIBRARY__)
int MQTT_EXAMPLE_main(int argc, char *ppArgv[], TrustEdgeConfig **ppConfig)
#else
int main(int argc, char *ppArgv[])
#endif
{
    MSTATUS status;
    MqttClientExampleCtx *pCtx = NULL;
    sbyte4 connInst = -1;
#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    ubyte4 timeoutMS;
#endif
#if defined(__ENABLE_MOCANA_SSL_CLIENT__) && defined(__ENABLE_MOCANA_HTTP_PROXY__)
    sbyte *pServerAndPort = NULL;
    TCP_SOCKET socketProxy = -1;
    int ret;
    sbyte4 transportProxy = -1;
#endif
    ubyte4 i;
    MqttClientExampleMsg *pCurMsg;
#if defined(__ENABLE_MOCANA_MQTT_SAMPLE_LIBRARY__)
    TrustEdgeConfig *pConfig = NULL;

    if (NULL != ppConfig)
    {
        pConfig = *ppConfig;
        *ppConfig = NULL;
    }
#endif


#if !defined(__ENABLE_MOCANA_MQTT_SAMPLE_LIBRARY__)
    status = MOCANA_initMocana();
    if (OK != status)
    {
        printf("MOCANA_initMocana failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }
#endif /* __ENABLE_MOCANA_MQTT_SAMPLE_LIBRARY__ */

    status = MQTT_EXAMPLE_contextCreate(&pCtx);
    if (OK != status)
    {
        printf("MQTT_EXAMPLE_contextCreate failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

    status = MQTT_EXAMPLE_parseArgs(argc, ppArgv, pCtx);
    if (OK != status)
    {
        printf("MQTT_EXAMPLE_parseArgs failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

    if (TRUE == pCtx->exit && argc == 2)
    {
        goto exit;
    }

#if !defined(__ENABLE_MOCANA_MQTT_SAMPLE_LIBRARY__)
    status = MQTT_init(MAX_MQTT_CLIENT_CONNECTIONS);
    if (OK != status)
    {
        printf("MQTT_init failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
    status = SSL_init(0, MAX_MQTT_CLIENT_CONNECTIONS);
    if (OK > status)
    {
        printf("SSL_init failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }
#endif /* __ENABLE_MOCANA_SSL_CLIENT__ */
#endif /* __ENABLE_MOCANA_MQTT_SAMPLE_LIBRARY__ */

#if defined(__ENABLE_MOCANA_SSL_CLIENT__) && defined(__ENABLE_MOCANA_HTTP_PROXY__)
    if (NULL == pCtx->pProxy)
#endif
    {
        status = TCP_GETHOSTBYNAME(pCtx->pMqttServer, pCtx->pMqttServerIp);
        if (OK != status)
        {
            printf("TCP_GETHOSTBYNAME failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }
    }

    status = MQTT_setupSignalHandler(SIGINT);
    if (OK != status)
    {
        printf("MQTT_setupSignalHandler failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

#if defined(__ENABLE_MOCANA_SSL_CLIENT__) && defined(__ENABLE_MOCANA_HTTP_PROXY__)
    if (NULL != pCtx->pProxy)
    {
        printf("Using proxy: %s\n", pCtx->pProxy);

        status = HTTP_PROXY_setProxyUrlAndPort(pCtx->pProxy);
        if (OK != status)
        {
            printf("HTTP_PROXY_setProxyUrlAndPort failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }

        ret = snprintf(NULL, 0, "%s:%d", pCtx->pMqttServer, pCtx->mqttPortNo);
        status = MOC_MALLOC((void **) &pServerAndPort, ret + 1);
        if (OK != status)
        {
            printf("MOC_MALLOC failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }
        snprintf(pServerAndPort, ret + 1, "%s:%d", pCtx->pMqttServer, pCtx->mqttPortNo);

        status = HTTP_PROXY_connect(
            pServerAndPort, &pCtx->socket, &socketProxy, &transportProxy,
            pCtx->pStore);
        if (OK != status)
        {
            printf("HTTP_PROXY_connect failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }
    }
    else
#endif /* __ENABLE_MOCANA_HTTP_PROXY__ */
    {
        status = TCP_CONNECT(
            &pCtx->socket, pCtx->pMqttServerIp, pCtx->mqttPortNo);
        if (OK != status)
        {
            printf("TCP_CONNECT failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }
    }

#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
    if (MQTT_SSL == pCtx->transport)
    {
#if defined(__ENABLE_MOCANA_HTTP_PROXY__)
        if (0 <= SSL_isSessionSSL(transportProxy))
        {
            pCtx->sslConnInst = SSL_PROXY_connect(
                socketProxy, transportProxy, SSL_PROXY_send, SSL_PROXY_recv,
                pCtx->socket, 0, NULL, NULL, pCtx->pMqttServer, pCtx->pStore);
            if (OK > pCtx->sslConnInst)
            {
                status = pCtx->sslConnInst;
                printf("SSL_PROXY_connect failed with status = %d on line %d\n", status, __LINE__);
                goto exit;
            }
        }
        else
#endif /* __ENABLE_MOCANA_HTTP_PROXY__ */
        {
            pCtx->sslConnInst = SSL_connect(
                pCtx->socket, 0, NULL, NULL, pCtx->pMqttServer, pCtx->pStore);
            if (OK > pCtx->sslConnInst)
            {
                status = pCtx->sslConnInst;
                printf("SSL_connect failed with status = %d on line %d\n", status, __LINE__);
                goto exit;
            }
        }

        status = SSL_setCookie(pCtx->sslConnInst, pCtx);
        if (OK != status)
        {
            printf("SSL_setCookie failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }

        status = SSL_setCertAndStatusCallback(
            pCtx->sslConnInst, MQTT_EXAMPLE_sslCertStatusCb);
        if (OK != status)
        {
            printf("SSL_setCertAndStatusCallback failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }

        status = SSL_setClientCertCallback(
            pCtx->sslConnInst, MQTT_EXAMPLE_getClientCertCallback);
        if (OK != status)
        {
            printf("SSL_setClientCertCallback failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }

        status = SSL_setServerNameIndication(
            pCtx->sslConnInst, pCtx->pMqttServer);
        if (OK != status)
        {
            printf("SSL_setServerNameIndication failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }

#if defined(__ENABLE_MOCANA_MQTT_SAMPLE_LIBRARY__)
#if defined(__ENABLE_MOCANA_PQC__)
        if (NULL != pConfig && TRUE == pConfig->requirePQC)
        {
            status = SSL_enforcePQCAlgorithm(pCtx->sslConnInst);
            if (OK > status)
            {
                printf("SSL_enforcePQCAlgorithm failed with status = %d on line %d\n", status, __LINE__);
                goto exit;
            }
        }
#endif
#endif

        status = SSL_negotiateConnection(pCtx->sslConnInst);
        if (OK > status)
        {
            printf("SSL_negotiateConnection failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }
    }
#endif /* __ENABLE_MOCANA_SSL_CLIENT__ */

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    if (TRUE == pCtx->async)
    {
        connInst = MQTT_asyncConnect(
            pCtx->mqttVersion, pCtx->pMqttClientId, pCtx->mqttClientIdLen);
        if (0 > connInst)
        {
            status = connInst;
            printf("MQTT_asyncConnect failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }
    }
    else
#endif
    {
        connInst = MQTT_connect(
            pCtx->mqttVersion, pCtx->pMqttClientId, pCtx->mqttClientIdLen);
        if (0 > connInst)
        {
            status = connInst;
            printf("MQTT_connect failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }
    }

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    if (TRUE != pCtx->async)
#endif
    {
#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
        if (MQTT_SSL == pCtx->transport)
        {
            status = MQTT_setTransportSSL(connInst, pCtx->sslConnInst);
            if (OK != status)
            {
                printf("MQTT_setTransportSSL failed with status = %d on line %d\n", status, __LINE__);
                goto exit;
            }
        }
        else
#endif /* __ENABLE_MOCANA_SSL_CLIENT__ */
        {
#if defined(__ENABLE_MOCANA_SSL_CLIENT__) && defined(__ENABLE_MOCANA_HTTP_PROXY__)
            if (0 <= SSL_isSessionSSL(transportProxy))
            {
                status = MQTT_setTransportSSL(connInst, transportProxy);
                if (OK != status)
                {
                    printf("MQTT_setTransportSSL failed with status = %d on line %d\n", status, __LINE__);
                    goto exit;
                }
            }
            else
#endif
            {
                status = MQTT_setTransportTCP(connInst, pCtx->socket);
                if (OK != status)
                {
                    printf("MQTT_setTransportTCP failed with status = %d on line %d\n", status, __LINE__);
                    goto exit;
                }
            }
        }
    }

    status = MQTT_setControlPacketHandlers(
        connInst, &(pCtx->mqttExampleHandlers));
    if (OK != status)
    {
        printf("MQTT_setControlPacketHandlers failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

#ifdef __ENABLE_DIGICERT_SCRAM_CLIENT__
    if (NULL != pCtx->pScramUser)
    {
        status = SCRAM_newCtx(&(pCtx->pScramCtx));
        if (OK != status)
            goto exit;

        status = SCRAM_buildClientFirstData(
            pCtx->pScramCtx, pCtx->pScramUser, NULL, 24,
            &(pCtx->mqttConnectOptions.pAuthData),
            &(pCtx->mqttConnectOptions.authDataLen));
        if (OK != status)
            goto exit;
    }
#endif

    status = MQTT_setCookie(connInst, pCtx);
    if (OK != status)
    {
        printf("MQTT_setCookie failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

    status = MQTT_negotiateConnection(connInst, &(pCtx->mqttConnectOptions));
    if (OK != status)
    {
        printf("MQTT_negotiateConnection failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    if (TRUE == pCtx->async)
    {
        while (1)
        {
            status = MQTT_EXAMPLE_sendPendingData(connInst);
            if (OK != status)
            {
                printf("MQTT_EXAMPLE_sendPendingData failed with status = %d on line %d\n", status, __LINE__);
                goto exit;
            }

            pCtx->bytesReceived = 0;
#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
            if (MQTT_SSL == pCtx->transport)
            {
                status = SSL_recv(
                    pCtx->sslConnInst, pCtx->pRecvBuffer, pCtx->recvBufferLen,
                    &pCtx->bytesReceived, 3000);
                if (OK > status)
                {
                    if (0 == shutdownClient)
                    {
                        printf("SSL_recv failed with status = %d on line %d\n", status, __LINE__);
                    }
                    else
                    {
                        status = OK;
                    }
                    goto exit;
                }
            }
            else
#endif
            {
                status = TCP_READ_AVL(
                    pCtx->socket, pCtx->pRecvBuffer, pCtx->recvBufferLen,
                    &pCtx->bytesReceived, 3000);
                if (OK != status)
                {
                    if (0 == shutdownClient)
                    {
                        printf("TCP_READ_AVL failed with status = %d on line %d\n", status, __LINE__);
                    }
                    else
                    {
                        status = OK;
                    }
                    goto exit;
                }
            }

            status = MQTT_recvMessage(
                connInst, pCtx->pRecvBuffer, pCtx->bytesReceived);
            if (OK != status)
            {
                printf("MQTT_recvMessage failed with status = %d on line %d\n", status, __LINE__);
                goto exit;
            }

            status = MQTT_isConnectionEstablished(connInst);
            if (OK > status)
            {
                printf("MQTT_isConnectionEstablished failed with status = %d on line %d\n", status, __LINE__);
                goto exit;
            }

            if (1 == status)
                break;
        }
    }
#endif

    if (0 == published)
    {
        for (i = 0; i < pCtx->msgCount; i++)
        {
            pCurMsg = pCtx->pMsgs + i;
            pCurMsg->pubOptions.qos = pCurMsg->qos;
            pCurMsg->pubOptions.retain = pCurMsg->retain;
            printf("Calling MQTT_publish \n");
            status = MQTT_publish(
                connInst, &pCurMsg->pubOptions, pCurMsg->pTopic, pCurMsg->topicLen,
                pCurMsg->pData, pCurMsg->dataLen);
            if (OK != status)
            {
                printf("MQTT_publish failed with status = %d on line %d\n", status, __LINE__);
                goto exit;
            }
        }

        published = 1;
    }

    /* Flush out any pending data */
#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    if (TRUE == pCtx->async)
    {
        while (1)
        {
            status = MQTT_EXAMPLE_sendPendingData(connInst);
            if (OK != status)
            {
                printf("MQTT_EXAMPLE_sendPendingData failed with status = %d on line %d\n", status, __LINE__);
                goto exit;
            }

            status = MQTT_transactionPending(connInst);
            if (OK > status)
            {
                printf("MQTT_transactionPending failed with status = %d on line %d\n", status, __LINE__);
                goto exit;
            }

            if (0 == status)
                break;

            status = MQTT_readTimeout(connInst, &timeoutMS);
            if (OK != status)
            {
                printf("MQTT_readTimeout failed with status = %d on line %d\n", status, __LINE__);
                goto exit;
            }

            pCtx->bytesReceived = 0;
#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
            if (MQTT_SSL == pCtx->transport)
            {
                status = SSL_recv(
                    pCtx->sslConnInst, pCtx->pRecvBuffer, pCtx->recvBufferLen,
                    &pCtx->bytesReceived, timeoutMS);
                if (ERR_TCP_READ_TIMEOUT == status)
                    status = OK;
                if (OK > status)
                {
                    if (0 == shutdownClient)
                    {
                        printf("SSL_recv failed with status = %d on line %d\n", status, __LINE__);
                    }
                    else
                    {
                        status = OK;
                    }
                    goto exit;
                }
            }
            else
#endif
            {
                status = TCP_READ_AVL(
                    pCtx->socket, pCtx->pRecvBuffer, pCtx->recvBufferLen,
                    &pCtx->bytesReceived, timeoutMS);
                if (ERR_TCP_READ_TIMEOUT == status)
                    status = OK;
                if (OK != status)
                {
                    if (0 == shutdownClient)
                    {
                        printf("TCP_READ_AVL failed with status = %d on line %d\n", status, __LINE__);
                    }
                    else
                    {
                        status = OK;
                    }
                    goto exit;
                }
            }

            status = MQTT_recvMessage(
                connInst, pCtx->pRecvBuffer, pCtx->bytesReceived);
            if (OK != status)
            {
                printf("MQTT_recvMessage failed with status = %d on line %d\n", status, __LINE__);
                goto exit;
            }
        }
    }
#endif

    while (1)
    {
#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
        if (TRUE == pCtx->async)
        {
            status = MQTT_EXAMPLE_sendPendingData(connInst);
            if (OK != status)
            {
                printf("MQTT_EXAMPLE_sendPendingData failed with status = %d on line %d\n", status, __LINE__);
                goto exit;
            }

            status = MQTT_readTimeout(connInst, &timeoutMS);
            if (OK != status)
            {
                printf("MQTT_readTimeout failed with status = %d on line %d\n", status, __LINE__);
                goto exit;
            }

            pCtx->bytesReceived = 0;
#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
            if (MQTT_SSL == pCtx->transport)
            {
                status = SSL_recv(
                    pCtx->sslConnInst, pCtx->pRecvBuffer, pCtx->recvBufferLen,
                    &pCtx->bytesReceived, timeoutMS);
                if (ERR_TCP_READ_TIMEOUT == status)
                    status = OK;
                if (OK > status)
                {
                    if (0 == shutdownClient)
                    {
                        printf("SSL_recv failed with status = %d on line %d\n", status, __LINE__);
                    }
                    else
                    {
                        status = OK;
                    }
                    goto exit;
                }
            }
            else
#endif
            {
                status = TCP_READ_AVL(
                    pCtx->socket, pCtx->pRecvBuffer, pCtx->recvBufferLen,
                    &pCtx->bytesReceived, timeoutMS);
                if (ERR_TCP_READ_TIMEOUT == status)
                    status = OK;
                if (OK != status)
                {
                    if (0 == shutdownClient)
                    {
                        printf("TCP_READ_AVL failed with status = %d on line %d\n", status, __LINE__);
                    }
                    else
                    {
                        status = OK;
                    }
                    goto exit;
                }
            }

            status = MQTT_recvMessage(
                connInst, pCtx->pRecvBuffer, pCtx->bytesReceived);
            if (OK != status)
            {
                printf("MQTT_recvMessage failed with status = %d on line %d\n", status, __LINE__);
                goto exit;
            }
        }
        else
#endif
        {
            if (pCtx->exit && 0 >= MQTT_transactionPending(connInst))
            {
                printf("Exit flag set... \n");
                goto exit;
            }

            status = MQTT_recv(connInst);
            if (0 > status)
            {
                if (0 == shutdownClient)
                {
                    printf("MQTT_recv failed with status = %d on line %d\n", status, __LINE__);
                }
                else
                {
                    status = OK;
                }
                goto exit;
            }
        }
    }

exit:

    if (TRUE == pCtx->exit && argc == 2)
    {
        goto close;
    }
    if (ERR_MQTT_CONNACK == status || ERR_MQTT_DISCONNECT == status)
    {
        goto close;
    }
    else if (ERR_MQTT_INVALID_MAX_CLIENT_CONN == status)
    {
        pCtx->mqttDisconnectOptions.reasonCode = MQTT_DISCONNECT_QUOTA_EXCEEDED;
    }
    else if (OK == status)
    {
       pCtx->mqttDisconnectOptions.reasonCode = MQTT_DISCONNECT_NORMAL;
    }
    else
    {
       pCtx->mqttDisconnectOptions.reasonCode = MQTT_DISCONNECT_UNSPECIFIED;
    }

    if (-1 < connInst)
    {
        if(pCtx->alertHandlerCalled == FALSE)
            MQTT_disconnect(connInst, &pCtx->mqttDisconnectOptions);
        else
            goto close;
#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
        /* Flush out pending data */
        if (TRUE == pCtx->async)
            MQTT_EXAMPLE_sendPendingData(connInst);
#endif
close:
        MQTT_closeConnection(connInst);
    }

#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
    if (NULL != pCtx && -1 < pCtx->sslConnInst)
        SSL_closeConnection(pCtx->sslConnInst);
#endif /* __ENABLE_MOCANA_SSL_CLIENT__ */

    if (NULL != pCtx)
        TCP_CLOSE_SOCKET(pCtx->socket);

    MQTT_EXAMPLE_contextDelete(&pCtx);

#if defined(__ENABLE_MOCANA_SSL_CLIENT__) && defined(__ENABLE_MOCANA_HTTP_PROXY__)
    if (-1 < transportProxy)
    {
        (void) SSL_closeConnection(transportProxy);
        (void) TCP_CLOSE_SOCKET(socketProxy);
    }

    (void) HTTP_PROXY_freeProxyUrl();

    if (NULL != pServerAndPort)
        MOC_FREE((void **) &pServerAndPort);
#endif

#if defined(__ENABLE_MOCANA_MQTT_SAMPLE_LIBRARY__)
    if (NULL != pConfig)
    {
        TRUSTEDGE_utilsDeleteConfig(&pConfig);
    }
#endif

#if !defined(__ENABLE_MOCANA_MQTT_SAMPLE_LIBRARY__)
#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
    SSL_shutdownStack();
#endif /* __ENABLE_MOCANA_SSL_CLIENT__ */

    MQTT_shutdownStack();

    MOCANA_freeMocana();
#endif

    return (OK > status) ? -1 : 0;
}
