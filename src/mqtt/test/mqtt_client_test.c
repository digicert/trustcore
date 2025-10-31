/*
 * mqtt_client_test.c
 *
 * MQTT Client Test
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

#include "../../common/moptions.h"
#include "../../common/mtypes.h"
#include "../../common/merrors.h"
#include "../../common/mrtos.h"
#include "../../common/mocana.h"
#include "../../common/mstdlib.h"
#include "../../common/mtcp.h"
#include "../../common/mtcp_async.h"
#include "../../common/hash_table.h"
#include "../../common/hash_value.h"
#include "../../common/mjson.h"
#include "../../common/mfmgmt.h"
#include "../../http/http_context.h"
#include "../../http/http_common.h"
#include "../../http/http.h"
#include "../../mqtt/mqtt_client.h"
#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
#include "../../ssl/ssl.h"
#endif /* ../__ENABLE_MOCANA_SSL_CLIENT__ */

/*----------------------------------------------------------------------------*/

/* Special prototype decls for test-build only internal verification functions.
 * Intentionally not declared in any header. */

typedef struct
{
    ubyte2 packetId;
    ubyte packetType;
} ExpectOutboundElem;

MSTATUS MQTT_verifyOutboundEmpty(sbyte4 connectionInstance);
MSTATUS MQTT_verifyInboundEmpty(sbyte4 connectionInstance);
MSTATUS MQTT_expectOutbound(sbyte4 connectionInstance, ExpectOutboundElem *pElems, ubyte4 numElems);

/*----------------------------------------------------------------------------*/

#define MAX_MQTT_CLIENT_CONNECTIONS     (10)

#define MQTT_TCP_TRANSPORT              "TCP"
#define MQTT_SSL_TRANSPORT              "SSL"

#define MQTT_ASYNC_DEFAULT_SEND_BUFFER_SIZE     (1024)
#define MQTT_ASYNC_DEFAULT_RECV_BUFFER_SIZE     (1024)

#ifndef MQTT_TEST_DEFAULT_RESP_TIMEOUT_MS
#define MQTT_TEST_DEFAULT_RESP_TIMEOUT_MS 2000
#endif

#define MQTT_TEST_DEFLT_SLEEP_MS 1000

/*----------------------------------------------------------------------------*/

#define MQTT_OP_JSTR                     "operation"
#define MQTT_OPTYPE_JSTR                 "optype"

/* Operations */
#define MQTT_OP_CREATE_JSTR              "create"
#define MQTT_OP_CONNECT_JSTR             "connect"
#define MQTT_OP_PUBLISH_JSTR             "publish"
#define MQTT_OP_SUBSCRIBE_JSTR           "subscribe"
#define MQTT_OP_RECV_JSTR                "recv"
#define MQTT_OP_EXPECT_JSTR              "expect"
#define MQTT_OP_DISCONNECT_JSTR          "disconnect"
#define MQTT_OP_DESTROY_JSTR             "destroy"
#define MQTT_OP_RESET_NETWORK_JSTR       "resetnetwork"
#define MQTT_OP_SYNC_EXPECTS_JSTR        "syncexpects"
#define MQTT_OP_SLEEP_JSTR               "sleep"
#define MQTT_OP_SET_PUB_TIMEOUT_JSTR     "setpublishtimeout"
#define MQTT_OP_VERIFY_OUT_EMPTY         "verifyOutEmpty"
#define MQTT_OP_VERIFY_IN_EMPTY          "verifyInEmpty"
#define MQTT_OP_EXPECT_OUTBOUND          "expectOutbound"

/* General */
#define MQTT_CLIENTID_JSTR               "clientid"
#define MQTT_TEST_MODE_JSTR              "mode"
#define MQTT_EXTENDED_MODE_JSTR          "extended"
#define MQTT_TIMEOUT_JSTR                "timeout"
#define MQTT_BLOCKING_JSTR               "blocking"
#define MQTT_EXPECTED_STATUS_JSTR        "expectedStatus"

/* Server Info */
#define MQTT_SERVER_SET_JSTR             "serverSettings"
#define MQTT_SERVER_ADDR_JSTR            "serverAddress"
#define MQTT_SERVER_PORT_JSTR            "serverPort"

/* Create */
#define MQTT_VERSION_JSTR                "version"
#define MQTT_PERSIST_DIR_JSTR            "persistdir"
#define MQTT_ASYNC_JSTR                  "async"
#define MQTT_ASYNC_SEND_BUF_SIZE         "sendBufferSize"
#define MQTT_ASYNC_RECV_BUF_SIZE         "recvBufferSize"

/* Connect */
#define MQTT_CLEAN_START_JSTR            "cleanStart"
#define MQTT_SESSION_EXPIRY_JSTR         "sessionExpiry"
#define MQTT_USERNAME_JSTR               "username"
#define MQTT_PASSWORD_JSTR               "password"
#define MQTT_KEEPALIVE_JSTR              "keepAlive"
#define MQTT_RECV_MAX_JSTR               "recvMax"
#define MQTT_WILL_QOS_JSTR               "willQos"
#define MQTT_WILL_TOPIC_JSTR             "willTopic"
#define MQTT_WILL_RETAIN_JSTR            "willRetain"
#define MQTT_WILL_DELAY_INTERVAL_JSTR    "willDelayInterval"
#define MQTT_WILL_MSG_EXPIRY_INT_JSTR    "willMsgExpiryInterval"
#define MQTT_WILL_RESPONSE_TOPIC_JSTR    "willResponseTopic"
#define MQTT_WILL_CORRELATION_DATA_JSTR  "willCorrelationData"
#define MQTT_WILL_CONTENT_TYPE_JSTR      "willContentType"
#define MQTT_WILL_PAYLOAD_FORMAT_JSTR    "willPayloadFormat"
#define MQTT_WILL_PAYLOAD_JSTR           "willPayload"

/* Publish */
#define MQTT_PUB_TOPIC_JSTR              "topic"
#define MQTT_PUB_DATA_JSTR               "publishData"
#define MQTT_PUB_FILE_JSTR               "publishFile"
#define MQTT_QOS_JSTR                    "qos"
#define MQTT_RETAIN_JSTR                 "retain"
#define MQTT_MSG_EXPIRY_JSTR             "messageExpiry"
#define MQTT_PAYLOAD_FORMAT_JSTR         "payloadFormat"
#define MQTT_TOPIC_ALIAS_JSTR            "topicAlias"
#define MQTT_RESPONSE_TOPIC_JSTR         "responseTopic"
#define MQTT_CORRELATION_DATA_JSTR       "correlationData"
#define MQTT_CONTENT_TYPE_JSTR           "contentType"

/* Subscribe */
#define MQTT_SUB_TOPICS_JSTR             "topics"
#define MQTT_SUB_MAX_QOS_JSTR            "maxQos"

/* Recv */
#define MQTT_LOOPMS_JSTR                 "loopms"

/* Disconnect */
#define MQTT_DISCONN_REASON_CODE_JSTR    "reasonCode"

/* Expect */
#define MQTT_EXPECTS_JSTR                "expects"
#define MQTT_EXPECT_TOPIC_JSTR           "expectedTopic"
#define MQTT_EXPECT_VALUE_JSTR           "expectedValue"
#define MQTT_EXPECT_FILE_JSTR            "expectedFile"
#define MQTT_EXPECT_QOS_JSTR             "expectedQos"
#define MQTT_EXPECT_PAYLOAD_FRMT_JSTR    "expectedPayloadFormat"
#define MQTT_EXPECT_MSG_EXPIRY_JSTR      "expectedMessageExpiry"
#define MQTT_EXPECT_CORR_DATA_JSTR       "expectedCorrelationData"
#define MQTT_EXPECT_CONTENT_TYPE_JSTR    "expectedContentType"
#define MQTT_EXPECT_RESPONSE_TOPIC_JSTR  "expectedResponseTopic"

/* Sleep */
#define MQTT_SLEEPMS_JSTR                 "sleepms"

/* Set publish timeout */
#define MQTT_PUB_TIMEOUT_SECS_JSTR        "storedPublishTimeoutSeconds"

/* Expect outbound */
#define MQTT_EXPECT_OUT_JSTR              "expectOut"
#define MQTT_PACKET_ID_JSTR               "packetId"
#define MQTT_PACKET_TYPE_JSTR             "packetType"
#define MQTT_PUBLISH_TYPE_JSTR            "publish"
#define MQTT_PUBREL_TYPE_JSTR             "pubrel"

/* SSL Settings */
#define MQTT_SSL_SETTINGS_JSTR            "sslSettings"
#define MQTT_SSL_CA_FILE_JSTR             "caFile"
#define MQTT_SSL_ALLOW_UNTRUST_JSTR       "allowUntrusted"

/*----------------------------------------------------------------------------*/

#define MQTT_TEST_STATE_UNDEFINED   0
#define MQTT_TEST_STATE_NOT_STARTED 1
#define MQTT_TEST_STATE_RUNNING     2
#define MQTT_TEST_STATE_DONE        3

typedef struct
{
    JSON_ContextType *pJsonCtx;
    ubyte4 startingIndex;
    ubyte state;
    ubyte result;
} MqttTestNonBlockingElem;

#define MQTT_TEST_MAX_NONBLOCKING_ELEMS 100

static MqttTestNonBlockingElem *g_pNonBlockingElems[MQTT_TEST_MAX_NONBLOCKING_ELEMS];

/*----------------------------------------------------------------------------*/

typedef enum
{
    MQTT_TCP,
    MQTT_SSL
} MqttExampleTransport;

/*----------------------------------------------------------------------------*/

typedef struct
{
    MqttVersion mqttVersion;
    sbyte *pMqttServer;
    sbyte pMqttServerIp[40];
    ubyte2 mqttPortNo;
    MqttExampleTransport transport;
    MqttPacketHandlers mqttExampleHandlers;
    ubyte allowUntrusted;
} MqttClientExampleCtx;

static char *gpConfig = NULL;
MqttClientExampleCtx *gpCtx = NULL;
#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
certStorePtr gpStore = NULL;
#endif
static ubyte gExtended = FALSE;
static ubyte gAllowUntrusted = FALSE;
static hashTableOfPtrs* gpMqttTestClientTable = NULL;
static ubyte gSsl = FALSE;

typedef struct
{
    sbyte *pTopic;
    ubyte *pData;
    ubyte4 dataLen;
    ubyte qosSet;
    ubyte qos;
    byteBoolean payloadFormatSet;
    ubyte payloadFormat;
    byteBoolean messageExpirySet;
    ubyte4 messageExpiry;
    /* Response Topic is valid UTF8 */
    ubyte *pResponseTopic;
    ubyte2 responseTopicLen;
    ubyte *pCorrelationData;
    ubyte4 correlationDataLen;
    /* Content type must be valid UTF8 */
    ubyte *pContentType;
    ubyte4 contentTypeLen;
    ubyte found;
} ExpectElem;

typedef struct
{
    sbyte4 connInst;
    TCP_SOCKET socket;
    ExpectElem *pExpects;
    ubyte4 numExpects;
    ubyte allFound;
    sbyte4 sslConnInst;
    byteBoolean async;
    ubyte *pSendBuffer;
    ubyte4 sendBufferLen;
    ubyte *pRecvBuffer;
    ubyte4 recvBufferLen;
    ubyte4 bytesReceived;
    MqttExampleTransport transport;
} MqttTestClient;

static MSTATUS MQTT_TEST_publishHandler(
    sbyte4 connectionInstance,
    MqttMessage *pMsg,
    MqttPublishInfo *pInfo);

MSTATUS MQTT_TEST_initConnection(MqttClientExampleCtx *pCtx, TCP_SOCKET *pSocket);
MSTATUS MQTT_TEST_expectWrapper(void *pArg);
MSTATUS MQTT_TEST_getSocketFromClientId(sbyte *pClientId, TCP_SOCKET *pSocket);
MSTATUS MQTT_TEST_getSslConnFromClientId(sbyte *pClientId, sbyte4 *pSslConn);


/*----------------------------------------------------------------------------*/

static MSTATUS MQTT_TEST_disconnectHandler(
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

    return status;
}

static MSTATUS MQTT_EXAMPLE_connAckHandler(
    sbyte4 connectionInstance,
    MqttMessage *pMsg,
    MqttConnAckInfo *pInfo)
{
    MSTATUS status = OK;
    ubyte4 i;

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

    }
    else
    {
        printf("ERROR Connack reason code: %d\n", pInfo->reasonCode);
    }

    if (NULL != pInfo->pReasonStr)
    {
        printf("CONNACK reason str: ");
        for (i = 0; i < pInfo->reasonStrLen; i++)
        {
            printf("%c", pInfo->pReasonStr[i]);
        }
        printf("\n");
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
    (*ppCtx)->transport = MQTT_TCP;


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
        if (NULL != (*ppCtx)->pMqttServer)
        {
            MOC_FREE((void **) &((*ppCtx)->pMqttServer));
        }

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
    printf("    --help                                      Display this help menu\n");
    printf("    --mqtt_config <filename>                    MQTT test configuration to execute\n");
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

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)

static MSTATUS MQTT_EXAMPLE_sendPendingData(
    sbyte4 connInst)
{
    MSTATUS status;
    MqttTestClient *pCtx = NULL;
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

        if (TRUE == pCtx->allowUntrusted)
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

MSTATUS MQTT_TEST_initSslConnection(MqttClientExampleCtx *pCtx, TCP_SOCKET socket, sbyte4 *pSslConnInst)
{
    MSTATUS status;
    sbyte4 connInst;

    connInst = SSL_connect(
        socket, 0, NULL, NULL, pCtx->pMqttServer, gpStore);
    if (OK > connInst)
    {
        status = connInst;
        printf("SSL_connect failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

    pCtx->allowUntrusted = gAllowUntrusted;

    status = SSL_setCookie(connInst, pCtx);
    if (OK != status)
    {
        printf("SSL_setCookie failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

    status = SSL_setCertAndStatusCallback(
        connInst, MQTT_EXAMPLE_sslCertStatusCb);
    if (OK != status)
    {
        printf("SSL_setCertAndStatusCallback failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

    status = SSL_negotiateConnection(connInst);
    if (OK > status)
    {
        printf("SSL_negotiateConnection failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

    *pSslConnInst = connInst;

exit:
    return status;
}

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
#endif



static MSTATUS allocHashPtrElement(
    void *pHashCookie,
    hashTablePtrElement **ppRetNewHashElement)
{
    MSTATUS status = OK;

    if (NULL == (*ppRetNewHashElement = (hashTablePtrElement*) MALLOC(sizeof(hashTablePtrElement))))
        status = ERR_MEM_ALLOC_FAIL;

    return status;
}

static MSTATUS freeHashPtrElement(
    void *pHashCookie,
    hashTablePtrElement *pFreeHashElement)
{
    if (NULL == pFreeHashElement)
        return ERR_NULL_POINTER;

    FREE(pFreeHashElement);

    return OK;
}

MSTATUS MQTT_TEST_init()
{
    MSTATUS status;

    ubyte4 count = 0;
    ubyte4 remain = 20;
    while (remain > 0)
    {
        remain = remain >> 1;
        count++;
    }

    status = HASH_TABLE_createPtrsTable(
        &gpMqttTestClientTable, (1 << count) - 1, NULL,
        allocHashPtrElement, freeHashPtrElement);
    if (OK != status)
        goto exit;

#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
    status = SSL_init(0, MAX_MQTT_CLIENT_CONNECTIONS);
    if (OK != status)
    {
        printf("SSL_init failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

    status = CERT_STORE_createStore(&gpStore);
    if (OK != status)
        goto exit;

    
#endif

exit:
    return status;
}

void MQTT_TEST_uninit()
{
    void *p = NULL;
    HASH_TABLE_removePtrsTable(gpMqttTestClientTable, NULL);

#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
    CERT_STORE_releaseStore(&gpStore);
#endif
}


MSTATUS MQTT_TEST_addClient(sbyte *pClientId, sbyte4 connInst, TCP_SOCKET socket, sbyte4 sslConnInst)
{
    MSTATUS status;
    ubyte4 hashVal = 0;
    MqttTestClient *pClient = NULL;
    ubyte4 clientIdLen = MOC_STRLEN(pClientId);

    HASH_VALUE_hashGen(pClientId, clientIdLen, 0, &hashVal);

    status = MOC_CALLOC((void **)&pClient, 1, sizeof(MqttTestClient));
    if (OK != status)
        goto exit;

    pClient->connInst = connInst;
    pClient->socket = socket;
    pClient->sslConnInst = sslConnInst;

    status = HASH_TABLE_addPtr(gpMqttTestClientTable, hashVal, (void *)pClient);
    if (OK != status)
        goto exit;

exit:
    return status;
}

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
MSTATUS MQTT_TEST_addAsyncClient(sbyte *pClientId, sbyte4 connInst, TCP_SOCKET socket, sbyte4 sslConnInst, ubyte4 sendBufSize, ubyte4 recvBufSize)
{
    MSTATUS status;
    ubyte4 hashVal = 0;
    MqttTestClient *pClient = NULL;
    ubyte4 clientIdLen = MOC_STRLEN(pClientId);

    HASH_VALUE_hashGen(pClientId, clientIdLen, 0, &hashVal);

    status = MOC_CALLOC((void **)&pClient, 1, sizeof(MqttTestClient));
    if (OK != status)
        goto exit;

    status = MOC_CALLOC((void **)&(pClient->pSendBuffer), 1, sendBufSize);
    if (OK != status)
        goto exit;

    status = MOC_CALLOC((void **)&(pClient->pRecvBuffer), 1, recvBufSize);
    if (OK != status)
        goto exit;

    pClient->connInst = connInst;
    pClient->socket = socket;
    pClient->sslConnInst = sslConnInst;
    pClient->sendBufferLen = sendBufSize;
    pClient->recvBufferLen = recvBufSize;
    pClient->async = TRUE;
    pClient->transport = MQTT_TCP;

    if (TRUE == gSsl)
    {
        pClient->transport = MQTT_SSL;
    }

    status = MQTT_setCookie(connInst, pClient);
    if (OK != status)
    {
        printf("MQTT_setCookie failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

    status = HASH_TABLE_addPtr(gpMqttTestClientTable, hashVal, (void *)pClient);
    if (OK != status)
        goto exit;

exit:
    return status;
}
#endif

MSTATUS MQTT_TEST_removeClient(sbyte *pClientId, sbyte4 connInst)
{
    MSTATUS status;
    ubyte4 i = 0;
    ubyte4 hashVal = 0;
    ubyte4 clientIdLen = MOC_STRLEN(pClientId);
    void *pValue = NULL;
    MqttTestClient *pClient = NULL;
    intBoolean found = FALSE;
    TCP_SOCKET socket = 0;
#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
    sbyte4 sslConnInst = 0;
#endif

    status = MQTT_TEST_getSocketFromClientId(pClientId, &socket);
    if (OK != status)
        goto exit;

#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
    if (TRUE == gSsl)
    {
        status = MQTT_TEST_getSslConnFromClientId(pClientId, &sslConnInst);
        if (OK != status)
            goto exit;

        SSL_closeConnection(sslConnInst);
    }
#endif

    TCP_CLOSE_SOCKET(socket);

    HASH_VALUE_hashGen(pClientId, clientIdLen, 0, &hashVal);
    status = HASH_TABLE_deletePtr(gpMqttTestClientTable, hashVal, NULL, NULL, &pValue, &found);
    if (OK != status)
        goto exit;

    if (TRUE == found)
    {
        pClient = (MqttTestClient *)pValue;
        if (NULL != pClient->pExpects)
        {
            for (i = 0; i < pClient->numExpects; i++)
            {
                if (NULL != pClient->pExpects[i].pData)
                {
                    MOC_FREE((void **)&pClient->pExpects[i].pData);
                }
                if (NULL != pClient->pExpects[i].pTopic)
                {
                    MOC_FREE((void **)&pClient->pExpects[i].pTopic);
                }
                if (NULL != pClient->pExpects[i].pResponseTopic)
                {
                    MOC_FREE((void **)&pClient->pExpects[i].pResponseTopic);
                }
                if (NULL != pClient->pExpects[i].pCorrelationData)
                {
                    MOC_FREE((void **)&pClient->pExpects[i].pCorrelationData);
                }
                if (NULL != pClient->pExpects[i].pContentType)
                {
                    MOC_FREE((void **)&pClient->pExpects[i].pContentType);
                }

            }
            MOC_FREE((void **)&pClient->pExpects);
        }

#ifdef __ENABLE_MQTT_ASYNC_CLIENT__
        if (TRUE == pClient->async)
        {
            if (NULL != pClient->pSendBuffer)
            {
                MOC_FREE((void **)&pClient->pSendBuffer);
            }
            if (NULL != pClient->pRecvBuffer)
            {
                MOC_FREE((void **)&pClient->pRecvBuffer);
            }
        }
#endif

        MOC_FREE((void **)&pClient);
    }

exit:
    return status;
}

MSTATUS MQTT_TEST_getClient(sbyte *pClientId, MqttTestClient **ppClient)
{
    MSTATUS status;
    ubyte *pValue = NULL;
    ubyte4 hashVal = 0;
    intBoolean found = FALSE;
    MqttTestClient *pClient = NULL;
    ubyte4 clientIdLen = MOC_STRLEN(pClientId);

    HASH_VALUE_hashGen(pClientId, clientIdLen, 0, &hashVal);
    status = HASH_TABLE_findPtr (
        gpMqttTestClientTable, hashVal, NULL, NULL, (void **)&pValue, &found);
    if (OK != status)
        goto exit;

    if (TRUE == found)
    {
        pClient = (MqttTestClient *)pValue;
        *ppClient = pClient;
    }
    else
    {
        status = ERR_INTERNAL_ERROR;
    }

exit:
    return status;
}

MSTATUS MQTT_TEST_getConnInstFromClientId(sbyte *pClientId, sbyte4 *pConnInst)
{
    MSTATUS status;
    ubyte *pValue = NULL;
    ubyte4 hashVal = 0;
    intBoolean found = FALSE;
    MqttTestClient *pClient = NULL;
    ubyte4 clientIdLen = MOC_STRLEN(pClientId);

    HASH_VALUE_hashGen(pClientId, clientIdLen, 0, &hashVal);
    status = HASH_TABLE_findPtr (
        gpMqttTestClientTable, hashVal, NULL, NULL, (void **)&pValue, &found);
    if (OK != status)
        goto exit;

    if (TRUE == found)
    {
        pClient = (MqttTestClient *)pValue;
        *pConnInst = (sbyte4)(pClient->connInst);
    }
    else
    {
        status = ERR_INTERNAL_ERROR;
    }

exit:
    return status;
}

MSTATUS MQTT_TEST_getSocketFromClientId(sbyte *pClientId, TCP_SOCKET *pSocket)
{
    MSTATUS status;
    ubyte *pValue = NULL;
    ubyte4 hashVal = 0;
    intBoolean found = FALSE;
    MqttTestClient *pClient = NULL;
    ubyte4 clientIdLen = MOC_STRLEN(pClientId);

    HASH_VALUE_hashGen(pClientId, clientIdLen, 0, &hashVal);
    status = HASH_TABLE_findPtr (
        gpMqttTestClientTable, hashVal, NULL, NULL, (void **)&pValue, &found);
    if (OK != status)
        goto exit;

    if (TRUE == found)
    {
        pClient = (MqttTestClient *)pValue;
        *pSocket = pClient->socket;
    }
    else
    {
        status = ERR_INTERNAL_ERROR;
    }

exit:
    return status;
}

#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
MSTATUS MQTT_TEST_getSslConnFromClientId(sbyte *pClientId, sbyte4 *pSslConn)
{
    MSTATUS status;
    ubyte *pValue = NULL;
    ubyte4 hashVal = 0;
    intBoolean found = FALSE;
    MqttTestClient *pClient = NULL;
    ubyte4 clientIdLen = MOC_STRLEN(pClientId);

    HASH_VALUE_hashGen(pClientId, clientIdLen, 0, &hashVal);
    status = HASH_TABLE_findPtr (
        gpMqttTestClientTable, hashVal, NULL, NULL, (void **)&pValue, &found);
    if (OK != status)
        goto exit;

    if (TRUE == found)
    {
        pClient = (MqttTestClient *)pValue;
        *pSslConn = pClient->sslConnInst;
    }
    else
    {
        status = ERR_INTERNAL_ERROR;
    }

exit:
    return status;
}
#endif

ubyte MQTT_TEST_isClientAsync(sbyte *pClientId)
{
    MqttTestClient *pClient = NULL;

    if (0 != MQTT_TEST_getClient(pClientId, &pClient))
    {
        return 0;
    }

    return pClient->async;
}

MSTATUS MQTT_TEST_addNonBlockingElem(MqttTestNonBlockingElem *pElem)
{
    MSTATUS status;
    ubyte found = FALSE;
    ubyte4 i;
    static int once = 0;

    if (NULL == pElem)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == once)
    {
        for (i = 0; i < MQTT_TEST_MAX_NONBLOCKING_ELEMS; i++)
        {
            g_pNonBlockingElems[i] = NULL;
        }
        once++;
    }

    for (i = 0; i < MQTT_TEST_MAX_NONBLOCKING_ELEMS; i++)
    {
        if (NULL == g_pNonBlockingElems[i])
        {
            g_pNonBlockingElems[i] = pElem;
            found = TRUE;
            break;
        }
    }

    if (FALSE == found)
    {
        status = ERR_NOT_FOUND;
    }

    status = OK;

exit:
    return status;
}

void MQTT_TEST_removeAllNonBlockingElems()
{
    ubyte4 i;

    for (i = 0; i < MQTT_TEST_MAX_NONBLOCKING_ELEMS; i++)
    {
        if (NULL != g_pNonBlockingElems[i])
        {
            MOC_FREE((void **)&g_pNonBlockingElems[i]);
        }
    }
}

byteBoolean MQTT_TEST_expecting()
{
    MSTATUS status;
    ubyte4 i;

    for (i = 0; i < MQTT_TEST_MAX_NONBLOCKING_ELEMS; i++)
    {
        if (NULL != g_pNonBlockingElems[i])
        {
            if (MQTT_TEST_STATE_DONE != g_pNonBlockingElems[i]->state)
            {
                return TRUE;
            }
        }
    }

    return FALSE;
}

MSTATUS MQTT_TEST_getExpectStatus()
{
    ubyte4 i;
    for (i = 0; i < MQTT_TEST_MAX_NONBLOCKING_ELEMS; i++)
    {
        if (NULL != g_pNonBlockingElems[i])
        {
            if (0 != g_pNonBlockingElems[i]->result)
            {
                return ERR_CMP;
            }
        }
    }

    return 0;
}

/*---------------------------------------------------------------------------*/

MSTATUS MQTT_TEST_parseandExecVerifyOutEmpty(JSON_ContextType *pJsonCtx, ubyte4 startingIndex)
{
    MSTATUS status;
    sbyte *pClientId = NULL;
    sbyte4 connInst = 0;

    status = JSON_utilReadJsonString (
        pJsonCtx, startingIndex, NULL, MQTT_CLIENTID_JSTR, &pClientId, TRUE);
    if (OK != status)
        goto exit;

    status = MQTT_TEST_getConnInstFromClientId(pClientId, &connInst);
    if (OK != status)
        goto exit;

    status = MQTT_verifyOutboundEmpty(connInst);

exit:
    if (NULL != pClientId)
    {
        MOC_FREE((void **)&pClientId);
    }
    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS MQTT_TEST_parseandExecVerifyInEmpty(JSON_ContextType *pJsonCtx, ubyte4 startingIndex)
{
    MSTATUS status;
    sbyte *pClientId = NULL;
    sbyte4 connInst = 0;

    status = JSON_utilReadJsonString (
        pJsonCtx, startingIndex, NULL, MQTT_CLIENTID_JSTR, &pClientId, TRUE);
    if (OK != status)
        goto exit;

    status = MQTT_TEST_getConnInstFromClientId(pClientId, &connInst);
    if (OK != status)
        goto exit;

    status = MQTT_verifyInboundEmpty(connInst);

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS MQTT_TEST_parseandExecExpectOut(JSON_ContextType *pJsonCtx, ubyte4 startingIndex)
{
    MSTATUS status;
    sbyte *pClientId = NULL;
    ubyte4 i = 0;
    sbyte4 connInst = 0;
    ubyte4 index = 0;
    ubyte4 currIndex = 0;
    JSON_TokenType token = {0};
    ubyte4 numExpects = 0;
    ExpectOutboundElem *pElements = NULL;
    sbyte *pPacketType = NULL;
    ubyte4 packetId = 0;

    status = JSON_utilReadJsonString (
        pJsonCtx, startingIndex, NULL, MQTT_CLIENTID_JSTR, &pClientId, TRUE);
    if (OK != status)
        goto exit;

    status = MQTT_TEST_getConnInstFromClientId(pClientId, &connInst);
    if (OK != status)
        goto exit;

    status = JSON_getObjectIndex (
        pJsonCtx, (sbyte *)MQTT_EXPECT_OUT_JSTR, startingIndex + 1, &index, TRUE);
    if (OK != status)
        goto exit;

    /* Get the array of topics */
    index++;
    status = JSON_getToken(pJsonCtx, index, &token);
    if (OK != status)
        goto exit;
    
    numExpects = token.elemCnt;
    status = MOC_CALLOC((void **)&pElements, numExpects, sizeof(ExpectOutboundElem));
    if (OK != status)
        goto exit;

    currIndex = index + 1;
    for (i = 0; i < numExpects; i++)
    {
        packetId = 0;
        status = JSON_utilReadJsonInt (
            pJsonCtx, currIndex-1, NULL, MQTT_PACKET_ID_JSTR, &packetId, TRUE);
        if (OK != status)
            goto exit;

        pElements[i].packetId = (ubyte2)packetId;

        status = JSON_utilReadJsonString (
            pJsonCtx, currIndex-1, NULL, MQTT_PACKET_TYPE_JSTR, 
            &pPacketType, TRUE);
        if (OK != status)
            goto exit;

        if (0 == MOC_STRCMP(pPacketType, MQTT_PUBLISH_TYPE_JSTR))
        {
            pElements[i].packetType = MQTT_PUBLISH;
        }
        else if (0 == MOC_STRCMP(pPacketType, MQTT_PUBREL_TYPE_JSTR))
        {
            pElements[i].packetType = MQTT_PUBREL;
        }
        else
        {
            printf("ERROR, must specify packet type of publish or pubrel\n");
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        if (NULL != pPacketType)
        {
            MOC_FREE((void **)&pPacketType);
        }

        status = JSON_getToken(pJsonCtx, currIndex, &token);
        if (OK != status)
            goto exit;

        currIndex += 1 + (token.elemCnt * 2);
    }

    status = MQTT_expectOutbound(connInst, pElements, numExpects);

exit:
    if (NULL != pClientId)
    {
        MOC_FREE((void **)&pClientId);
    }
    if (NULL != pElements)
    {
        MOC_FREE((void **)&pElements);
    }

    return status;
}


/*---------------------------------------------------------------------------*/


MSTATUS MQTT_TEST_parseServerSettings(JSON_ContextType *pJsonCtx, ubyte4 startingIndex)
{
    MSTATUS status;
    ubyte4 port = 0;
    sbyte *pModeValue = NULL;

    if (NULL != gpCtx->pMqttServer)
    {
        MOC_FREE((void **)&(gpCtx->pMqttServer));
    }

    status = JSON_utilReadJsonString (
        pJsonCtx, startingIndex, NULL, MQTT_SERVER_ADDR_JSTR, &(gpCtx->pMqttServer), TRUE);
    if (OK != status)
        goto exit;

    status = JSON_utilReadJsonInt (
        pJsonCtx, startingIndex, NULL, MQTT_SERVER_PORT_JSTR, &port, TRUE);
    if (OK != status)
        goto exit;

    status = JSON_utilReadJsonString (
        pJsonCtx, startingIndex, NULL, MQTT_TEST_MODE_JSTR, &pModeValue, FALSE);
    if (OK == status)
    {
        if (0 == MOC_STRCMP(pModeValue, MQTT_EXTENDED_MODE_JSTR))
        {
            gExtended = TRUE;
        }
    }

    if (ERR_NOT_FOUND == status)
        status = OK;

    gpCtx->mqttPortNo = (ubyte2)port;

exit:

    if (NULL != pModeValue)
    {
        MOC_FREE((void **)&pModeValue);
    }

    return status;
}

MSTATUS MQTT_TEST_resetNetwork(JSON_ContextType *pJsonCtx, ubyte4 startingIndex)
{
    MSTATUS status;
    TCP_SOCKET socket = 0;
    sbyte *pClientId = NULL;
    sbyte4 connInst = 0;
#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
    sbyte4 sslConnInst = 0;
    MqttTestClient *pClient = NULL;
#endif

    status = JSON_utilReadJsonString (
        pJsonCtx, startingIndex, NULL, MQTT_CLIENTID_JSTR, &pClientId, TRUE);
    if (OK != status)
        goto exit;

    status = MQTT_TEST_getSocketFromClientId(pClientId, &socket);
    if (OK != status)
        goto exit;

#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
    if (TRUE == gSsl)
    {
        status = MQTT_TEST_getSslConnFromClientId(pClientId, &sslConnInst);
        if (OK != status)
            goto exit;

        SSL_closeConnection(sslConnInst);
    }
#endif 

    printf("Resetting socket: %d for clientid: %s\n", socket, pClientId);

    TCP_CLOSE_SOCKET(socket);

    status = TCP_CONNECT(
        &socket, gpCtx->pMqttServerIp, gpCtx->mqttPortNo);
    if (OK != status)
    {
        printf("TCP_CONNECT failed with status = %d on line %d\n", status, __LINE__);
    }

#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
    if (TRUE == gSsl)
    {
        status = MQTT_TEST_getClient(pClientId, &pClient);
        if (OK != status)
            goto exit;

        sslConnInst = SSL_connect(pClient->socket, 0, NULL, NULL, gpCtx->pMqttServer, gpStore);
        if (OK > sslConnInst)
        {
            status = sslConnInst;
            printf("SSL_connect failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }

        status = SSL_setCookie(sslConnInst, gpCtx);
        if (OK != status)
        {
            printf("SSL_setCookie failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }

        status = SSL_setCertAndStatusCallback(
            sslConnInst, MQTT_EXAMPLE_sslCertStatusCb);
        if (OK != status)
        {
            printf("SSL_setCertAndStatusCallback failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }

        status = SSL_negotiateConnection(sslConnInst);
        if (OK > status)
        {
            printf("SSL_negotiateConnection failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }

        pClient->sslConnInst = sslConnInst;

        if (FALSE == pClient->async)
        {
            status = MQTT_setTransportSSL(connInst, sslConnInst);
            if (OK != status)
            {
                printf("MQTT_setTransportSSL failed with status = %d on line %d\n", status, __LINE__);
                goto exit;
            }
        }
    }
#endif


exit:

    if (NULL != pClientId)
    {
        MOC_FREE((void **)&pClientId);
    }

    return status;
}

MSTATUS MQTT_TEST_parseAndExecSleep(JSON_ContextType *pJsonCtx, ubyte4 startingIndex)
{
    MSTATUS status;
    ubyte4 sleepms = 0;

    status = JSON_utilReadJsonInt (
        pJsonCtx, startingIndex, NULL, MQTT_SLEEPMS_JSTR, &sleepms, TRUE);
    if (OK != status)
        goto exit;

    printf("Sleeping for %d milliseconds\n", sleepms);
    RTOS_sleepMS(sleepms);

exit:
    return status;
}

MSTATUS MQTT_TEST_parseAndExecSetPubTimeout(JSON_ContextType *pJsonCtx, ubyte4 startingIndex)
{
    MSTATUS status;
    sbyte *pClientId = NULL;
    sbyte4 connInst = 0;
    ubyte4 timeout = 0;

    status = JSON_utilReadJsonString (
        pJsonCtx, startingIndex, NULL, MQTT_CLIENTID_JSTR, &pClientId, TRUE);
    if (OK != status)
        goto exit;

    status = JSON_utilReadJsonInt (
        pJsonCtx, startingIndex, NULL, MQTT_PUB_TIMEOUT_SECS_JSTR, &timeout, TRUE);
    if (OK != status)
        goto exit;

    status = MQTT_TEST_getConnInstFromClientId(pClientId, &connInst);
    if (OK != status)
        goto exit;

    status = MQTT_setPublishTimeout(connInst, timeout);

exit:

    if (NULL != pClientId)
    {
        MOC_FREE((void **)&pClientId);
    }

    return status;
}

MSTATUS MQTT_TEST_parseAndExecDestroy(JSON_ContextType *pJsonCtx, ubyte4 startingIndex)
{
    MSTATUS status;
    ubyte4 index = 0;
    sbyte *pClientId = NULL;
    sbyte4 connInst = 0;
    ubyte4 reasonCode = 0;
    MqttDisconnectOptions options = {0};

    status = JSON_utilReadJsonString (
        pJsonCtx, startingIndex, NULL, MQTT_CLIENTID_JSTR, &pClientId, TRUE);
    if (OK != status)
        goto exit;

    status = MQTT_TEST_getConnInstFromClientId(pClientId, &connInst);
    if (OK != status)
        goto exit;

    MQTT_TEST_removeClient(pClientId, connInst);
    status = MQTT_closeConnection(connInst);

exit:

    if (NULL != pClientId)
    {
        MOC_FREE((void **)&pClientId);
    }

    return status;
}

MSTATUS MQTT_TEST_parseAndExecDisconn(JSON_ContextType *pJsonCtx, ubyte4 startingIndex)
{
    MSTATUS status;
    ubyte4 index = 0;
    sbyte *pClientId = NULL;
    sbyte4 connInst = 0;
    ubyte4 reasonCode = 0;
    MqttDisconnectOptions options = {0};

    status = JSON_utilReadJsonString (
        pJsonCtx, startingIndex, NULL, MQTT_CLIENTID_JSTR, &pClientId, TRUE);
    if (OK != status)
        goto exit;

    status = MQTT_TEST_getConnInstFromClientId(pClientId, &connInst);
    if (OK != status)
        goto exit;

    status = JSON_utilReadJsonInt (
        pJsonCtx, startingIndex, NULL, MQTT_DISCONN_REASON_CODE_JSTR, &reasonCode, TRUE);
    if ( (OK != status) && (ERR_NOT_FOUND != status) )
        goto exit;

    options.reasonCode = (ubyte)reasonCode;

    status = MQTT_disconnect(connInst, &options);

exit:

    if (NULL != pClientId)
    {
        MOC_FREE((void **)&pClientId);
    }

    return status;
}

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
static MSTATUS MQTT_TEST_asyncExpect(MqttTestClient *pCtx, ubyte4 loopms)
{
    MSTATUS status;
    ubyte4 timeout = 0;
    moctime_t start = {0};
    moctime_t current = {0};

    do
    {
        status = MQTT_EXAMPLE_sendPendingData(pCtx->connInst);
        if (OK != status)
        {
            printf("MQTT_EXAMPLE_sendPendingData failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }

        RTOS_deltaMS(NULL, &start);
        timeout = loopms;

        pCtx->bytesReceived = 0;
#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
        if (MQTT_SSL == pCtx->transport)
        {
            status = SSL_recv(
                pCtx->sslConnInst, pCtx->pRecvBuffer, pCtx->recvBufferLen,
                &pCtx->bytesReceived, timeout);
            if (ERR_TCP_READ_TIMEOUT == status)
                status = OK;
            if (OK > status)
            {
                printf("SSL_recv failed with status = %d on line %d\n", status, __LINE__);
                goto exit;
            }
        }
        else
#endif
        {
            status = TCP_READ_AVL_EX(
                pCtx->socket, pCtx->pRecvBuffer, pCtx->recvBufferLen,
                &pCtx->bytesReceived, timeout);
            if (ERR_TCP_READ_TIMEOUT == status)
                status = OK;
            if (OK != status)
            {
                printf("TCP_READ_AVL_EX failed with status = %d on line %d\n", status, __LINE__);
                goto exit;
            }
        }

        status = MQTT_recvMessage(
            pCtx->connInst, pCtx->pRecvBuffer, pCtx->bytesReceived);
        if (OK != status)
        {
            printf("MQTT_recvMessage failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }

        if (TRUE == pCtx->allFound)
        {
            break;
        }

        timeout = RTOS_deltaMS(&start, &current);
        if (timeout < loopms)
        {
            loopms = loopms - timeout;
        }
        else
        {
            loopms = 0;
        }

    } while (loopms > 0);

    /* loop for a bit more to ensure all pub* packets finalize */
    loopms = 100;
    do
    {
        status = MQTT_EXAMPLE_sendPendingData(pCtx->connInst);
        if (OK != status)
        {
            printf("MQTT_EXAMPLE_sendPendingData failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }

        RTOS_deltaMS(NULL, &start);
        timeout = loopms;

        pCtx->bytesReceived = 0;
#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
        if (MQTT_SSL == pCtx->transport)
        {
            status = SSL_recv(
                pCtx->sslConnInst, pCtx->pRecvBuffer, pCtx->recvBufferLen,
                &pCtx->bytesReceived, timeout);
            if (ERR_TCP_READ_TIMEOUT == status)
                status = OK;
            if (OK > status)
            {
                printf("SSL_recv failed with status = %d on line %d\n", status, __LINE__);
                goto exit;
            }
        }
        else
#endif
        {
            status = TCP_READ_AVL_EX(
                pCtx->socket, pCtx->pRecvBuffer, pCtx->recvBufferLen,
                &pCtx->bytesReceived, timeout);
            if (ERR_TCP_READ_TIMEOUT == status)
                status = OK;
            if (OK != status)
            {
                printf("TCP_READ_AVL_EX failed with status = %d on line %d\n", status, __LINE__);
                goto exit;
            }
        }

        status = MQTT_recvMessage(
            pCtx->connInst, pCtx->pRecvBuffer, pCtx->bytesReceived);
        if (OK != status)
        {
            printf("MQTT_recvMessage failed with status = %d on line %d\n", status, __LINE__);
            goto exit;
        }

        if (TRUE == pCtx->allFound)
        {
            break;
        }

        timeout = RTOS_deltaMS(&start, &current);
        if (timeout < loopms)
        {
            loopms = loopms - timeout;
        }
        else
        {
            loopms = 0;
        }

    } while (loopms > 0);

exit:
    return status;
}
#endif

MSTATUS MQTT_TEST_parseAndExecExpect(JSON_ContextType *pJsonCtx, ubyte4 startingIndex, MqttTestNonBlockingElem *pElem)
{
    MSTATUS status;
    ubyte4 i = 0;
    sbyte4 connInst = 0;
    sbyte *pClientId = NULL;
    ubyte4 timeout = 0;
    ubyte4 loopms = 0;
    ubyte4 index = 0;
    ubyte4 currIndex = 0;
    ubyte numExpects = 0;
    ubyte4 qosInt = 0;
    ubyte4 payloadFormat = 0;
    ubyte4 msgExpiry = 0;
    JSON_TokenType token = {0};
    ExpectElem *pExpects = NULL;
    MqttTestClient *pClient = NULL;
    sbyte *pFilename = NULL;
    moctime_t start = {0};
    moctime_t current = {0};
    ubyte4 blocking = TRUE;
    MqttTestNonBlockingElem *pLocalElem = NULL;
    RTOS_THREAD threadId = 0;

    status = JSON_utilReadJsonInt (
        pJsonCtx, startingIndex, NULL, MQTT_BLOCKING_JSTR, &blocking, TRUE);
    if ( (OK != status) && (ERR_NOT_FOUND != status) )
        goto exit;

    /* For non-blocking expects, launch a thread here (if we are not already in the launched thread) */
    if ( (FALSE == blocking) && (NULL == pElem) )
    {
        status = MOC_CALLOC((void **)&pLocalElem, 1, sizeof(MqttTestNonBlockingElem));
        if (OK != status)
            goto exit;

        pLocalElem->pJsonCtx = pJsonCtx;
        pLocalElem->startingIndex = startingIndex;
        pLocalElem->state = MQTT_TEST_STATE_NOT_STARTED;
        pLocalElem->result = 1;

        status = MQTT_TEST_addNonBlockingElem(pLocalElem);
        if (OK != status)
            goto exit;

        status = RTOS_createThread((void (*)(void *))(MQTT_TEST_expectWrapper), (void *)pLocalElem, DEBUG_THREAD, &threadId);
        if (OK == status)
        {
            RTOS_destroyThread(threadId);
        }
        pLocalElem = NULL;
        goto exit;
    }

    status = JSON_utilReadJsonString (
        pJsonCtx, startingIndex, NULL, MQTT_CLIENTID_JSTR, &pClientId, TRUE);
    if (OK != status)
        goto exit;

    status = JSON_utilReadJsonInt (
        pJsonCtx, startingIndex, NULL, MQTT_TIMEOUT_JSTR, &loopms, TRUE);
    if (OK != status)
        goto exit;

    status = JSON_getObjectIndex (
        pJsonCtx, (sbyte *)MQTT_EXPECTS_JSTR, startingIndex + 1, &index, TRUE);
    if (OK != status)
        goto exit;

    /* Get the array of expects */
    index++;
    status = JSON_getToken(pJsonCtx, index, &token);
    if (OK != status)
        goto exit;

    numExpects = token.elemCnt;
    status = MOC_CALLOC((void **)&pExpects, numExpects, sizeof(ExpectElem));
    if (OK != status)
        goto exit;

    currIndex = index + 1;
    for (i = 0; i < numExpects; i++)
    {
        status = JSON_utilReadJsonString (
            pJsonCtx, currIndex-1, NULL, MQTT_EXPECT_TOPIC_JSTR, 
            (sbyte **)&(pExpects[i].pTopic), TRUE);
        if (OK != status)
            goto exit;

        status = JSON_utilReadJsonString (
            pJsonCtx, currIndex-1, NULL, MQTT_EXPECT_VALUE_JSTR, 
            (sbyte **)&(pExpects[i].pData), TRUE);
        if ( (OK != status) && (ERR_NOT_FOUND != status) )
            goto exit;

        /* Look for filename if string value not specified */
        if (ERR_NOT_FOUND == status)
        {
            status = JSON_utilReadJsonString (
                pJsonCtx, currIndex-1, NULL, MQTT_EXPECT_FILE_JSTR, 
                &pFilename, TRUE);
            if (OK != status)
                goto exit;

            status = MOCANA_readFile(pFilename, &(pExpects[i].pData), &(pExpects[i].dataLen));
            if (OK != status)
                goto exit;

            MOC_FREE((void **)&pFilename);
        }
        else
        {
            pExpects[i].dataLen = MOC_STRLEN(pExpects[i].pData);
        }

        status = JSON_utilReadJsonInt (
            pJsonCtx, currIndex-1, NULL, MQTT_EXPECT_QOS_JSTR, 
            &qosInt, TRUE);
        if ( (OK != status) && (ERR_NOT_FOUND != status) )
            goto exit;

        if (OK == status)
        {
            pExpects[i].qosSet = TRUE;
            pExpects[i].qos = (ubyte)qosInt;
        }

        status = JSON_utilReadJsonInt (
            pJsonCtx, currIndex-1, NULL, MQTT_EXPECT_PAYLOAD_FRMT_JSTR, 
            &payloadFormat, TRUE);
        if ( (OK != status) && (ERR_NOT_FOUND != status) )
            goto exit;

        if (OK == status)
        {
            pExpects[i].payloadFormatSet = TRUE;
            pExpects[i].payloadFormat = (ubyte)payloadFormat;
        }

        status = JSON_utilReadJsonInt (
            pJsonCtx, currIndex-1, NULL, MQTT_EXPECT_MSG_EXPIRY_JSTR, 
            &msgExpiry, TRUE);
        if ( (OK != status) && (ERR_NOT_FOUND != status) )
            goto exit;

        if (OK == status)
        {
            pExpects[i].messageExpirySet = TRUE;
            pExpects[i].messageExpiry = msgExpiry;
        }

        status = JSON_utilReadJsonString (
            pJsonCtx, currIndex-1, NULL, MQTT_EXPECT_CORR_DATA_JSTR, 
            (sbyte **)&(pExpects[i].pCorrelationData), TRUE);
        if ( (OK != status) && (ERR_NOT_FOUND != status) )
            goto exit;

        if (OK == status)
        {
            pExpects[i].correlationDataLen = MOC_STRLEN(pExpects[i].pCorrelationData);
        }

        status = JSON_utilReadJsonString (
            pJsonCtx, currIndex-1, NULL, MQTT_EXPECT_CONTENT_TYPE_JSTR, 
            (sbyte **)&(pExpects[i].pContentType), TRUE);
        if ( (OK != status) && (ERR_NOT_FOUND != status) )
            goto exit;

        if (OK == status)
        {
            pExpects[i].contentTypeLen = MOC_STRLEN(pExpects[i].pContentType);
        }

        status = JSON_utilReadJsonString (
            pJsonCtx, currIndex-1, NULL, MQTT_EXPECT_RESPONSE_TOPIC_JSTR, 
            (sbyte **)&(pExpects[i].pResponseTopic), TRUE);
        if ( (OK != status) && (ERR_NOT_FOUND != status) )
            goto exit;

        if (OK == status)
        {
            pExpects[i].responseTopicLen = MOC_STRLEN(pExpects[i].pResponseTopic);
        }

        status = JSON_getToken(pJsonCtx, currIndex, &token);
        if (OK != status)
            goto exit;

        currIndex += 1 + (token.elemCnt * 2);
    }

    status = MQTT_TEST_getClient(pClientId, &pClient);
    if (OK != status)
        goto exit;

    pClient->pExpects = pExpects;
    pClient->numExpects = numExpects;

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    if (TRUE == pClient->async)
    {
        status = MQTT_TEST_asyncExpect(pClient, loopms);
        goto exit;
    }
#endif

    do
    {
        RTOS_deltaMS(NULL, &start);
        timeout = loopms;

        status = MQTT_recvEx(connInst, timeout);
        if (OK != status)
            goto exit;

        if (TRUE == pClient->allFound)
        {
            break;
        }

        timeout = RTOS_deltaMS(&start, &current);
        if (timeout < loopms)
        {
            loopms = loopms - timeout;
        }
        else
        {
            loopms = 0;
        }
    } while(loopms > 0);

    /* loop for a bit more to ensure all pub* packets finalize */
    loopms = 100;
    do
    {
        RTOS_deltaMS(NULL, &start);
        timeout = loopms;

        status = MQTT_recvEx(connInst, timeout);
        if (OK != status)
            goto exit;

        if (TRUE == pClient->allFound)
        {
            break;
        }

        timeout = RTOS_deltaMS(&start, &current);
        if (timeout < loopms)
        {
            loopms = loopms - timeout;
        }
        else
        {
            loopms = 0;
        }
    } while(loopms > 0);


exit:

    if (NULL != pElem)
    {
        pElem->result = 1;
    }

    if (NULL != pClient)
    {
        if (TRUE == pClient->allFound)
        {
            if (NULL != pElem)
            {
                pElem->result = 0;
            }
        }
        else
        {
            printf("ERROR Timed out before receiving all expected values\n");
            status = ERR_PAYLOAD;
        }
    }

    if (NULL != pElem)
    {
        pElem->state = MQTT_TEST_STATE_DONE;
    }

    if (NULL != pFilename)
    {
        MOC_FREE((void **)&pFilename);
    }
    if (NULL != pClientId)
    {
        MOC_FREE((void **)&pClientId);
    }

    return status;
}

MSTATUS MQTT_TEST_expectWrapper(void *pArg)
{
    MSTATUS status;
    MqttTestNonBlockingElem *pElem = NULL;

    if (NULL == pArg)
    {
        return ERR_NULL_POINTER;
    }

    pElem = (MqttTestNonBlockingElem *)pArg;
    pElem->state = MQTT_TEST_STATE_RUNNING;

    status = MQTT_TEST_parseAndExecExpect(pElem->pJsonCtx, pElem->startingIndex, pElem);
    return status;
}

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
static MSTATUS MQTT_TEST_asyncRecv(sbyte *pClientId, sbyte4 connInst, ubyte4 timeoutMS, ubyte4 loopms, ubyte flush)
{
    MSTATUS status;
    moctime_t start = {0};
    moctime_t current = {0};
    ubyte4 timeout = 0;
    MqttTestClient *pCtx = NULL;

    if (loopms > 0)
    {
        do
        {
            if (TRUE == flush)
            {
                status = MQTT_EXAMPLE_sendPendingData(connInst);
                if (OK != status)
                {
                    printf("MQTT_EXAMPLE_sendPendingData failed with status = %d on line %d\n", status, __LINE__);
                    goto exit;
                }
            }

            status = MQTT_TEST_getClient(pClientId, &pCtx);
            if (OK != status)
                goto exit;

            RTOS_deltaMS(NULL, &start);
            timeout = loopms;

            pCtx->bytesReceived = 0;
#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
            if (MQTT_SSL == pCtx->transport)
            {
                status = SSL_recv(
                    pCtx->sslConnInst, pCtx->pRecvBuffer, pCtx->recvBufferLen,
                    &pCtx->bytesReceived, timeout);
                if (ERR_TCP_READ_TIMEOUT == status)
                    status = OK;
                if (OK > status)
                {
                    printf("SSL_recv failed with status = %d on line %d\n", status, __LINE__);
                    goto exit;
                }
            }
            else
#endif
            {
                status = TCP_READ_AVL_EX(
                    pCtx->socket, pCtx->pRecvBuffer, pCtx->recvBufferLen,
                    &pCtx->bytesReceived, timeout);
                if (ERR_TCP_READ_TIMEOUT == status)
                    status = OK;
                if (OK != status)
                {
                    printf("TCP_READ_AVL_EX failed with status = %d on line %d\n", status, __LINE__);
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

            timeout = RTOS_deltaMS(&start, &current);
            if (timeout < loopms)
            {
                loopms = loopms - timeout;
            }
            else
            {
                loopms = 0;
            }

        } while (loopms > 0);
    }
    else
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
                &pCtx->bytesReceived, timeoutMS);
            if (ERR_TCP_READ_TIMEOUT == status)
                status = OK;
            if (OK > status)
            {
                printf("SSL_recv failed with status = %d on line %d\n", status, __LINE__);
                goto exit;
            }
        }
        else
#endif
        {
            status = TCP_READ_AVL_EX(
                pCtx->socket, pCtx->pRecvBuffer, pCtx->recvBufferLen,
                &pCtx->bytesReceived, timeoutMS);
            if (ERR_TCP_READ_TIMEOUT == status)
                status = OK;
            if (OK != status)
            {
                printf("TCP_READ_AVL_EX failed with status = %d on line %d\n", status, __LINE__);
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

exit:
    return status;
}
#endif

MSTATUS MQTT_TEST_parseAndExecRecv(JSON_ContextType *pJsonCtx, ubyte4 startingIndex)
{
    MSTATUS status;
    ubyte4 index = 0;
    sbyte *pClientId = NULL;
    sbyte4 connInst = 0;
    ubyte4 timeout = 0;
    ubyte4 loopms = 0;
    moctime_t start = {0};
    moctime_t current = {0};
    
    status = JSON_utilReadJsonString (
        pJsonCtx, startingIndex, NULL, MQTT_CLIENTID_JSTR, &pClientId, TRUE);
    if (OK != status)
        goto exit;

    status = MQTT_TEST_getConnInstFromClientId(pClientId, &connInst);
    if (OK != status)
        goto exit;

    status = JSON_utilReadJsonInt (
        pJsonCtx, startingIndex, NULL, MQTT_TIMEOUT_JSTR, &timeout, TRUE);
    if ( (OK != status) && (ERR_NOT_FOUND != status) )
        goto exit;

    status = JSON_utilReadJsonInt (
        pJsonCtx, startingIndex, NULL, MQTT_LOOPMS_JSTR, &loopms, TRUE);
    if ( (OK != status) && (ERR_NOT_FOUND != status) )
        goto exit;

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    if (MQTT_TEST_isClientAsync(pClientId))
    {
        return MQTT_TEST_asyncRecv(pClientId, connInst, timeout, loopms, FALSE);
    }
#endif

    if (loopms > 0)
    {
        do
        {
            RTOS_deltaMS(NULL, &start);
            timeout = loopms;

            status = MQTT_recvEx(connInst, timeout);
            if (OK != status)
                goto exit;

            timeout = RTOS_deltaMS(&start, &current);
            if (timeout < loopms)
            {
                loopms = loopms - timeout;
            }
            else
            {
                loopms = 0;
            }
        } while(loopms > 0);
    }
    else
    {
        if (timeout > 0)
            status = MQTT_recvEx(connInst, timeout);
        else
            status = MQTT_recv(connInst);
    }


exit:

    if (NULL != pClientId)
    {
        MOC_FREE((void **)&pClientId);
    }

    return status;
}

MSTATUS MQTT_TEST_parseAndExecSubscribe(JSON_ContextType *pJsonCtx, ubyte4 startingIndex, sbyte4 *pConnInst)
{
    MSTATUS status;
    sbyte *pClientId = NULL;
    sbyte4 connInst = 0;
    ubyte4 index = 0;
    ubyte4 currIndex = 0;
    ubyte4 numTopics = 0;
    ubyte4 i = 0;
    ubyte4 maxQos = 0;
    JSON_TokenType token = {0};
    MqttSubscribeTopic *pTopics = NULL;

    status = JSON_utilReadJsonString (
        pJsonCtx, startingIndex, NULL, MQTT_CLIENTID_JSTR, &pClientId, TRUE);
    if (OK != status)
        goto exit;

    status = MQTT_TEST_getConnInstFromClientId(pClientId, &connInst);
    if (OK != status)
        goto exit;

    *pConnInst = connInst;

    status = JSON_getObjectIndex (
        pJsonCtx, (sbyte *)MQTT_SUB_TOPICS_JSTR, startingIndex + 1, &index, TRUE);
    if (OK != status)
        goto exit;

    /* Get the array of topics */
    index++;
    status = JSON_getToken(pJsonCtx, index, &token);
    if (OK != status)
        goto exit;
    
    numTopics = token.elemCnt;
    status = MOC_CALLOC((void **)&pTopics, numTopics, sizeof(MqttSubscribeTopic));
    if (OK != status)
        goto exit;

    currIndex = index + 1;
    for (i = 0; i < numTopics; i++)
    {
        maxQos = 0;
        status = JSON_utilReadJsonString (
            pJsonCtx, currIndex-1, NULL, MQTT_PUB_TOPIC_JSTR, 
            (sbyte **)&(pTopics[i].pTopic), TRUE);
        if (OK != status)
            goto exit;

        pTopics[i].topicLen = MOC_STRLEN(pTopics[i].pTopic);

        status = JSON_utilReadJsonInt (
            pJsonCtx, currIndex-1, NULL, MQTT_SUB_MAX_QOS_JSTR, &maxQos, TRUE);
        if ( (OK != status) && (ERR_NOT_FOUND != status) )
            goto exit;

        pTopics[i].qos = maxQos;

        status = JSON_getToken(pJsonCtx, currIndex, &token);
        if (OK != status)
            goto exit;

        currIndex += 1 + (token.elemCnt * 2);
    }

    status = MQTT_subscribe(connInst, pTopics, numTopics, NULL);

exit:

    if (OK != status)
    {
        printf("ERROR MQTT_TEST_parseAndExecSubscribe\n");
    }

    if (NULL != pClientId)
    {
        MOC_FREE((void **)&pClientId);
    }
    if (NULL != pTopics)
    {
        for (i = 0; i < numTopics; i++)
        {
            if (NULL != pTopics[i].pTopic)
            {
                MOC_FREE((void **)&(pTopics[i].pTopic));
            }
        }
        MOC_FREE((void **)&pTopics);
    }

    return status;
}


MSTATUS MQTT_TEST_parseAndExecPublish(JSON_ContextType *pJsonCtx, ubyte4 startingIndex, sbyte4 *pConnInst)
{
    MSTATUS status;
    MSTATUS expectedStatus = 0;
    sbyte *pClientId = NULL;
    sbyte4 connInst = 0;
    ubyte *pTopic = NULL;
    sbyte *pFilename = NULL;
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;
    MqttPublishOptions pubOptions = {0};
    ubyte4 qos = 0;
    ubyte4 retain = 0;
    ubyte4 payloadFormat = 0;
    ubyte4 msgExpiry = 0;

    status = JSON_utilReadJsonString (
        pJsonCtx, startingIndex, NULL, MQTT_CLIENTID_JSTR, &pClientId, TRUE);
    if (OK != status)
        goto exit;

    status = MQTT_TEST_getConnInstFromClientId(pClientId, &connInst);
    if (OK != status)
        goto exit;

    *pConnInst = connInst;

    status = JSON_utilReadJsonString (
        pJsonCtx, startingIndex, NULL, MQTT_PUB_TOPIC_JSTR, 
        (sbyte **)&pTopic, TRUE);
    if (OK != status)
        goto exit;

    status = JSON_utilReadJsonString (
        pJsonCtx, startingIndex, NULL, MQTT_PUB_DATA_JSTR, 
        (sbyte **)&pData, TRUE);
    if ( (OK != status) && (ERR_NOT_FOUND != status) )
        goto exit;

    if (ERR_NOT_FOUND == status)
    {
        status = JSON_utilReadJsonString (
            pJsonCtx, startingIndex, NULL, MQTT_PUB_FILE_JSTR, 
            (sbyte **)&pFilename, TRUE);
        if (OK != status)
            goto exit;

        status = MOCANA_readFile(pFilename, &pData, &dataLen);
    }
    else
    {
        dataLen = MOC_STRLEN(pData);
    }

    status = JSON_utilReadJsonInt (
        pJsonCtx, startingIndex, NULL, MQTT_QOS_JSTR, &qos, TRUE);
    if ( (OK != status) && (ERR_NOT_FOUND != status) )
        goto exit;

    pubOptions.qos = (MqttQoS)qos;

    status = JSON_utilReadJsonBoolean (
        pJsonCtx, startingIndex, NULL, MQTT_RETAIN_JSTR, &retain, TRUE);
    if ( (OK != status) && (ERR_NOT_FOUND != status) )
        goto exit;
    
    pubOptions.retain = (byteBoolean)retain;

    status = JSON_utilReadJsonInt (
        pJsonCtx, startingIndex, NULL, MQTT_MSG_EXPIRY_JSTR, &msgExpiry, TRUE);
    if ( (OK != status) && (ERR_NOT_FOUND != status) )
        goto exit;

    if (OK == status)
    {
        pubOptions.msgExpiryInterval = msgExpiry;
    }

    status = JSON_utilReadJsonInt (
        pJsonCtx, startingIndex, NULL, MQTT_EXPECTED_STATUS_JSTR, &expectedStatus, TRUE);
    if ( (OK != status) && (ERR_NOT_FOUND != status) )
        goto exit;

    status = JSON_utilReadJsonInt (
        pJsonCtx, startingIndex, NULL, MQTT_PAYLOAD_FORMAT_JSTR, &payloadFormat, TRUE);
    if ( (OK != status) && (ERR_NOT_FOUND != status) )
        goto exit;

    if (OK == status)
    {
        pubOptions.setPayloadFormat = TRUE;
        pubOptions.payloadFormat = (ubyte)payloadFormat;
    }

    status = JSON_utilReadJsonString (
        pJsonCtx, startingIndex, NULL, MQTT_CORRELATION_DATA_JSTR, 
        (sbyte **)&pubOptions.pCorrelationData, TRUE);
    if ( (OK != status) && (ERR_NOT_FOUND != status) )
        goto exit;

    if (OK == status)
    {
        pubOptions.correlationDataLen = MOC_STRLEN(pubOptions.pCorrelationData);
    }

    status = JSON_utilReadJsonString (
        pJsonCtx, startingIndex, NULL, MQTT_CONTENT_TYPE_JSTR, 
        (sbyte **)&pubOptions.pContentType, TRUE);
    if ( (OK != status) && (ERR_NOT_FOUND != status) )
        goto exit;

    if (OK == status)
    {
        pubOptions.contentTypeLen = MOC_STRLEN(pubOptions.pContentType);
    }

    status = JSON_utilReadJsonString (
        pJsonCtx, startingIndex, NULL, MQTT_RESPONSE_TOPIC_JSTR, 
        (sbyte **)&pubOptions.pResponseTopic, TRUE);
    if ( (OK != status) && (ERR_NOT_FOUND != status) )
        goto exit;

    if (OK == status)
    {
        pubOptions.responseTopicLen = MOC_STRLEN(pubOptions.pResponseTopic);
    }

    status = MQTT_publish (
        connInst, &pubOptions, pTopic, MOC_STRLEN(pTopic), pData, dataLen);
    if (expectedStatus != 0)
    {
        if (status == expectedStatus)
        {
            status = OK;
        }
        else
        {
            status = ERR_GENERAL;
            goto exit;
        }
    }
    else if (OK != status)
    {
        printf("MQTT_publish failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

exit:

    if (OK != status)
    {
        printf("ERROR MQTT_TEST_parseAndExecPublish\n");
    }

    if (NULL != pClientId)
    {
        MOC_FREE((void **)&pClientId);
    }
    if (NULL != pData)
    {
        MOC_FREE((void **)&pData);
    }
    if (NULL != pTopic)
    {
        MOC_FREE((void **)&pTopic);
    }
    if (NULL != pubOptions.pCorrelationData)
    {
        MOC_FREE((void **)&pubOptions.pCorrelationData);
    }
    if (NULL != pubOptions.pContentType)
    {
        MOC_FREE((void **)&pubOptions.pContentType);
    }
    if (NULL != pubOptions.pResponseTopic)
    {
        MOC_FREE((void **)&pubOptions.pResponseTopic);
    }


    return status;
}

MSTATUS MQTT_TEST_parseAndExecConnect(JSON_ContextType *pJsonCtx, ubyte4 startingIndex, sbyte4 *pConnInst)
{
    MSTATUS status;
    sbyte *pClientId = NULL;
    sbyte4 connInst = 0;
    MqttConnectOptions mqttConnectOptions = {0};
    ubyte4 cleanStart = 0;
    ubyte4 keepAlive = 0;
    ubyte4 payloadFormat = 0;
    ubyte4 willQos = 0;
    ubyte4 willRetain = 0;
    ubyte4 recvMax = 0;
    MqttWillInfo willInfo = {0};
    MqttTestClient *pCtx = NULL;

    status = JSON_utilReadJsonString (
        pJsonCtx, startingIndex, NULL, MQTT_CLIENTID_JSTR, &pClientId, TRUE);
    if (OK != status)
        goto exit;

    status = MQTT_TEST_getConnInstFromClientId(pClientId, &connInst);
    if (OK != status)
        goto exit;

    *pConnInst = connInst;

    status = JSON_utilReadJsonBoolean (
        pJsonCtx, startingIndex, NULL, MQTT_CLEAN_START_JSTR, &cleanStart, TRUE);
    if ( (OK != status) && (ERR_NOT_FOUND != status) )
        goto exit;
    
    mqttConnectOptions.cleanStart = (ubyte2)cleanStart;

    status = JSON_utilReadJsonInt (
        pJsonCtx, startingIndex, NULL, MQTT_SESSION_EXPIRY_JSTR, 
        &mqttConnectOptions.sessionExpiryIntervalSeconds, TRUE);
    if ( (OK != status) && (ERR_NOT_FOUND != status) )
        goto exit;

    status = JSON_utilReadJsonInt (
        pJsonCtx, startingIndex, NULL, MQTT_RECV_MAX_JSTR, 
        &recvMax, TRUE);
    if ( (OK != status) && (ERR_NOT_FOUND != status) )
        goto exit;

    if (OK == status)
    {
        mqttConnectOptions.receiveMax = recvMax;
    }

    status = JSON_utilReadJsonInt (
        pJsonCtx, startingIndex, NULL, MQTT_KEEPALIVE_JSTR, 
        &keepAlive, TRUE);
    if ( (OK != status) && (ERR_NOT_FOUND != status) )
        goto exit;

    mqttConnectOptions.keepAliveInterval = (ubyte2)keepAlive;

    status = JSON_utilReadJsonString (
        pJsonCtx, startingIndex, NULL, MQTT_USERNAME_JSTR, 
        (sbyte **)&mqttConnectOptions.pUsername, TRUE);
    if ( (OK != status) && (ERR_NOT_FOUND != status) )
        goto exit;

    mqttConnectOptions.usernameLen = MOC_STRLEN(mqttConnectOptions.pUsername);

    status = JSON_utilReadJsonString (
        pJsonCtx, startingIndex, NULL, MQTT_PASSWORD_JSTR, 
        (sbyte **)&mqttConnectOptions.pPassword, TRUE);
    if ( (OK != status) && (ERR_NOT_FOUND != status) )
        goto exit;

    mqttConnectOptions.passwordLen = MOC_STRLEN(mqttConnectOptions.pPassword);

    status = JSON_utilReadJsonInt(
        pJsonCtx, startingIndex, NULL, MQTT_WILL_QOS_JSTR, &willQos, TRUE);
    if ((OK != status) && (ERR_NOT_FOUND != status))
        goto exit;

    if (OK == status)
    {
        mqttConnectOptions.willInfo.qos = (MqttQoS)willQos;
    }

    status = JSON_utilReadJsonString(
        pJsonCtx, startingIndex, NULL, MQTT_WILL_TOPIC_JSTR, (sbyte **)&mqttConnectOptions.willInfo.pWillTopic, TRUE);
    if ((OK != status)  && (ERR_NOT_FOUND != status))
        goto exit;

    if (OK == status)
    {
        mqttConnectOptions.willInfo.willTopicLen = (ubyte2)MOC_STRLEN(mqttConnectOptions.willInfo.pWillTopic);
    }
    
    status = JSON_utilReadJsonString(
        pJsonCtx, startingIndex, NULL, MQTT_WILL_PAYLOAD_JSTR,
        (sbyte **)&mqttConnectOptions.willInfo.pWill, TRUE);
    if ((OK != status) && (ERR_NOT_FOUND != status))
        goto exit;

    if (OK == status)
    {
        mqttConnectOptions.willInfo.willLen = (ubyte4)MOC_STRLEN(mqttConnectOptions.willInfo.pWill);
    }

    status = JSON_utilReadJsonBoolean(
        pJsonCtx, startingIndex, NULL, MQTT_WILL_RETAIN_JSTR, &willRetain, TRUE);
    if ((OK != status) && (ERR_NOT_FOUND != status))
        goto exit;

    if (OK == status)
    {
        mqttConnectOptions.willInfo.retain = (byteBoolean)willRetain;
    }

    status = JSON_utilReadJsonInt(
        pJsonCtx, startingIndex, NULL, MQTT_WILL_DELAY_INTERVAL_JSTR,
        &mqttConnectOptions.willInfo.willDelayInterval, TRUE);
    if ((OK != status) && (ERR_NOT_FOUND != status))
        goto exit;

    status = JSON_utilReadJsonInt(
        pJsonCtx, startingIndex, NULL, MQTT_WILL_MSG_EXPIRY_INT_JSTR,
        &mqttConnectOptions.willInfo.msgExpiryInterval, TRUE);
    if ((OK != status) && (ERR_NOT_FOUND != status))
        goto exit;

    status = JSON_utilReadJsonString(
        pJsonCtx, startingIndex, NULL, MQTT_WILL_RESPONSE_TOPIC_JSTR,
        (sbyte **)&mqttConnectOptions.willInfo.pResponseTopic, TRUE);
    if ((OK != status) && (ERR_NOT_FOUND != status))
        goto exit;

    if (OK == status)
    {
        mqttConnectOptions.willInfo.responseTopicLen = MOC_STRLEN(mqttConnectOptions.willInfo.pResponseTopic);
    }

    status = JSON_utilReadJsonString(
        pJsonCtx, startingIndex, NULL, MQTT_WILL_CORRELATION_DATA_JSTR,
        (sbyte **)&mqttConnectOptions.willInfo.pCorrelationData, TRUE);
    if ((OK != status) && (ERR_NOT_FOUND != status))
        goto exit;

    if (OK == status)
    {
        mqttConnectOptions.willInfo.correlationDataLen = MOC_STRLEN(mqttConnectOptions.willInfo.pCorrelationData);
    }

    status = JSON_utilReadJsonString(
        pJsonCtx, startingIndex, NULL, MQTT_WILL_CONTENT_TYPE_JSTR,
        (sbyte **)&mqttConnectOptions.willInfo.pContentType, TRUE);
    if ((OK != status) && (ERR_NOT_FOUND != status))
        goto exit;

    if (OK == status)
    {
        mqttConnectOptions.willInfo.contentTypeLen = MOC_STRLEN(mqttConnectOptions.willInfo.pContentType);
    }

    status = JSON_utilReadJsonInt(
        pJsonCtx, startingIndex, NULL, MQTT_WILL_PAYLOAD_FORMAT_JSTR, &payloadFormat, TRUE);
    if ((OK != status) && (ERR_NOT_FOUND != status))
        goto exit;

    if (OK == status)
    {
        mqttConnectOptions.willInfo.setPayloadFormat = TRUE;
        mqttConnectOptions.willInfo.payloadFormat = (ubyte)payloadFormat;
    }

    MQTT_resetConnectionState(connInst);

    status = MQTT_negotiateConnection(connInst, &mqttConnectOptions);
    if (OK != status)
    {
        printf("MQTT_negotiateConnection failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    /* For async, ensure connack handling is done */
    if (MQTT_TEST_isClientAsync(pClientId))
    {
        status = MQTT_TEST_getClient(pClientId, &pCtx);
        if (OK != status)
            goto exit;

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
                    printf("SSL_recv failed with status = %d on line %d\n", status, __LINE__);
                    goto exit;
                }
            }
            else
#endif
            {
                status = TCP_READ_AVL_EX(
                    pCtx->socket, pCtx->pRecvBuffer, pCtx->recvBufferLen,
                    &pCtx->bytesReceived, 3000);
                if (OK != status)
                {
                    printf("TCP_READ_AVL_EX failed with status = %d on line %d\n", status, __LINE__);
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

    status = OK;
#endif

exit:

    if (OK != status)
    {
        printf("ERROR MQTT_TEST_parseAndExecConnect\n");
    }
    if (NULL != pClientId)
    {
        MOC_FREE((void **)&pClientId);
    }
    if (NULL != mqttConnectOptions.pUsername)
    {
        MOC_FREE((void **)&mqttConnectOptions.pUsername);
    }
    if (NULL != mqttConnectOptions.pPassword)
    {
        MOC_FREE((void **)&mqttConnectOptions.pPassword);
    }
    if (NULL != mqttConnectOptions.willInfo.pWillTopic)
    {
        MOC_FREE((void **)&mqttConnectOptions.willInfo.pWillTopic);
    }
    if (NULL != mqttConnectOptions.willInfo.pWill)
    {
        MOC_FREE((void **)&mqttConnectOptions.willInfo.pWill);
    }
    if (NULL != mqttConnectOptions.willInfo.pResponseTopic)
    {
        MOC_FREE((void **)&mqttConnectOptions.willInfo.pResponseTopic);
    }
    if (NULL != mqttConnectOptions.willInfo.pCorrelationData)
    {
        MOC_FREE((void **)&mqttConnectOptions.willInfo.pCorrelationData);
    }
    if (NULL != mqttConnectOptions.willInfo.pContentType)
    {
        MOC_FREE((void **)&mqttConnectOptions.willInfo.pContentType);
    }

    return status;
}

MSTATUS MQTT_TEST_parseAndExecCreate(JSON_ContextType *pJsonCtx, ubyte4 startingIndex)
{
    MSTATUS status;
    sbyte *pClientId = NULL;
    sbyte4 connInst = 0;
    TCP_SOCKET socket = 0;
    sbyte4 versionInt = 5;
    MqttVersion version = MQTT_V5;
    MqttPacketHandlers handlers = {0};
#ifdef __MQTT_ENABLE_FILE_PERSIST__
    FilePersistArgs args;
    sbyte *pPersistDir = NULL;
#endif
    sbyte4 sslConnInst = -1;
    ubyte4 async = FALSE;
#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    ubyte4 sendBufSize = MQTT_ASYNC_DEFAULT_SEND_BUFFER_SIZE;
    ubyte4 recvBufSize = MQTT_ASYNC_DEFAULT_RECV_BUFFER_SIZE;
#endif

    /* Given parsed JSON tokens:
     * [0] {
     * [1] "operation":
     * [2] {
     * [3] "optype": 
     * [4] "connect"
     * [5] "clientid":
     * [6] "someclientid"
     * 
     * startingIndex coming into this function is 1. Utility functions use the
     * input index + 1 for obtaining the value, and the start index for bounded 
     * searches must be an object.
     */

    status = JSON_utilReadJsonString (
        pJsonCtx, startingIndex, NULL, MQTT_CLIENTID_JSTR, &pClientId, TRUE);
    if (OK != status)
        goto exit;

    status = JSON_utilReadJsonInt (
        pJsonCtx, startingIndex, NULL, MQTT_VERSION_JSTR, &versionInt, TRUE);
    if ( (OK != status) && (ERR_NOT_FOUND != status) )
        goto exit;

    if (3 == versionInt)
        version = MQTT_V3_1_1;

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    status = JSON_utilReadJsonInt (
        pJsonCtx, startingIndex, NULL, MQTT_ASYNC_JSTR, &async, TRUE);
    if ( (OK != status) && (ERR_NOT_FOUND != status) )
        goto exit;

    if (TRUE == async)
    {
        connInst = MQTT_asyncConnect(version, (ubyte *)pClientId, (ubyte2)MOC_STRLEN(pClientId));
        if (0 > connInst)
        {
            status = ERR_MQTT;
            goto exit;
        }
    }
    else
#endif
    {
        connInst = MQTT_connect(version, (ubyte *)pClientId, (ubyte2)MOC_STRLEN(pClientId));
        if (0 > connInst)
        {
            status = ERR_MQTT;
            goto exit;
        }
    }
    
    handlers.publishHandler = MQTT_TEST_publishHandler;
    handlers.disconnectHandler = MQTT_TEST_disconnectHandler;
    handlers.connAckHandler = MQTT_EXAMPLE_connAckHandler;
    status = MQTT_setControlPacketHandlers(
        connInst, &handlers);
    if (OK != status)
    {
        printf("MQTT_setControlPacketHandlers failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

#ifdef __MQTT_ENABLE_FILE_PERSIST__
    status = JSON_utilReadJsonString (
        pJsonCtx, startingIndex, NULL, MQTT_PERSIST_DIR_JSTR, &pPersistDir, TRUE);
    if ( (OK != status) && (ERR_NOT_FOUND != status) )
        goto exit;
    
    if (NULL != pPersistDir)
    {
        args.mode = MQTT_PERSIST_MODE_FILE;
        args.pDir = pPersistDir;

        if (FALSE == FMGMT_pathExists(pPersistDir, NULL))
        {
            status = FMGMT_mkdir(pPersistDir, 0777);
            if (OK != status)
                goto exit;
        }

        status = MQTT_setPersistMode(connInst, &args);
        if (OK != status)
            goto exit;
    }
#endif

    status = MQTT_TEST_initConnection(gpCtx, &socket);
    if (OK != status)
        goto exit;

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    if (TRUE == async)
    {
        status = JSON_utilReadJsonInt (
            pJsonCtx, startingIndex, NULL, MQTT_ASYNC_SEND_BUF_SIZE, &sendBufSize, TRUE);
        if ( (OK != status) && (ERR_NOT_FOUND != status) )
            goto exit;

        status = JSON_utilReadJsonInt (
            pJsonCtx, startingIndex, NULL, MQTT_ASYNC_RECV_BUF_SIZE, &recvBufSize, TRUE);
        if ( (OK != status) && (ERR_NOT_FOUND != status) )
            goto exit;

#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
        if (TRUE == gSsl)
        {
            status = MQTT_TEST_initSslConnection(gpCtx, socket, &sslConnInst);
            if (OK != status)
                goto exit;
        }
#endif

        status = MQTT_TEST_addAsyncClient(pClientId, connInst, socket, sslConnInst, sendBufSize, recvBufSize);
    }
    else
#endif
    {

#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
        if (TRUE == gSsl)
        {
            status = MQTT_TEST_initSslConnection(gpCtx, socket, &sslConnInst);
            if (OK != status)
                goto exit;

            status = MQTT_setTransportSSL(connInst, sslConnInst);
            if (OK != status)
            {
                printf("MQTT_setTransportSSL failed with status = %d on line %d\n", status, __LINE__);
                goto exit;
            }
        }
        else
#endif
        {
            status = MQTT_setTransportTCP(connInst, socket);
            if (OK != status)
            {
                printf("MQTT_setTransportTCP failed with status = %d on line %d\n", status, __LINE__);
                goto exit;
            }
        }

        status = MQTT_TEST_addClient(pClientId, connInst, socket, sslConnInst);
    }

exit:

    if (OK != status)
    {
        printf("ERROR MQTT_TEST_parseAndExecCreate\n");
    }
    if (NULL != pClientId)
    {
        MOC_FREE((void **)&pClientId);
    }

#ifdef __MQTT_ENABLE_FILE_PERSIST__
    if (NULL != pPersistDir)
    {
        MOC_FREE((void **)&pPersistDir);
    }
#endif

    if (OK != status)
    {
        if (0 <= connInst)
        {
            MQTT_TEST_removeClient(pClientId, connInst);
            status = MQTT_closeConnection(connInst);
        }
    }

    return status;
}

static sbyte pOpBuf[32];

MSTATUS MQTT_TEST_parseAndExecConfig(char *pFilename)
{
    MSTATUS status;
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;
    JSON_ContextType *pJsonCtx = NULL;
    JSON_TokenType token = {0};
    ubyte4 index = 0;
    ubyte4 startingIndex = 0;
    ubyte4 currentIndex = 0;
    ubyte4 numTokens = 0;
    sbyte *pOpType = NULL;
    ubyte process = FALSE;
    sbyte4 connInst = 0;
    ubyte4 timeout = 0;
    ubyte4 loopms = 0;
    moctime_t start = {0};
    moctime_t current = {0};
#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
    sbyte *pCaFile = NULL;
    intBoolean allow = FALSE;
#endif
#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    sbyte *pClientId = NULL;
    ubyte4 clientIdLen = 0;
#endif

    status = MOCANA_readFile(pFilename, &pData, &dataLen);
    if (OK != status)
        goto exit;

    status = JSON_acquireContext(&pJsonCtx);
    if (OK != status)
        goto exit;

    status = JSON_parse(pJsonCtx, pData, dataLen, &numTokens);
    if (OK != status)
        goto exit;

    status = JSON_getObjectIndex(pJsonCtx, (sbyte *)MQTT_SERVER_SET_JSTR, startingIndex, &currentIndex, FALSE);
    if (OK != status)
        goto exit;

    status = MQTT_TEST_parseServerSettings(pJsonCtx, currentIndex);
    if (OK != status)
        goto exit;

#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
    /* Check for "sslSettings" */
    status = JSON_getObjectIndex(pJsonCtx, (sbyte *)MQTT_SSL_SETTINGS_JSTR, startingIndex, &currentIndex, FALSE);
    if ( (OK != status) && (ERR_NOT_FOUND != status) )
        goto exit;

    if (OK == status)
    {
        gSsl = TRUE;

        status = JSON_utilReadJsonString (
            pJsonCtx, currentIndex, NULL, MQTT_SSL_CA_FILE_JSTR, &pCaFile, FALSE);
        if ( (OK != status) && (ERR_NOT_FOUND != status) )
            goto exit;
        
        if (OK == status)
        {
            status = MQTT_EXAMPLE_addTrustPointFile(gpStore, pCaFile);
            if (OK != status)
                goto exit;
        }

        status = JSON_utilReadJsonBoolean (
            pJsonCtx, currentIndex, NULL, MQTT_SSL_ALLOW_UNTRUST_JSTR, &allow, FALSE);
        if ( (OK != status) && (ERR_NOT_FOUND != status) )
            goto exit;

        if (OK == status)
        {
            gAllowUntrusted = allow;
        }
    }
#endif

    do
    {
        process = FALSE;

        /* Find the next "operation" key */
        status = JSON_getObjectIndex(pJsonCtx, (sbyte *)MQTT_OP_JSTR, startingIndex, &currentIndex, FALSE);
        if ( (OK != status) && (ERR_NOT_FOUND != status) )
            goto exit;

        /* If we didnt find any more we are done */
        if (ERR_NOT_FOUND == status)
        {
            status = OK;
            break;
        }

        /* Keep a starting index 1 beyond the current, for the next unbounded search
         * for "operation" */
        startingIndex = currentIndex + 1;

        status = JSON_getToken(pJsonCtx, currentIndex + 3, &token);
        if( OK != status)
        {
            goto exit;
        }

        /* No value given for the given token */
        if (token.len == 0)
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        MOC_MEMCPY(pOpBuf, (const char *)token.pStart,  token.len);
        pOpBuf[token.len] = '\0';

        printf("Found optype: %s\n", pOpBuf);

        if (0 == MOC_STRCMP(MQTT_OP_CREATE_JSTR, pOpBuf))
        {
            status = MQTT_TEST_parseAndExecCreate(pJsonCtx, currentIndex);
        }
        else if (0 == MOC_STRCMP(MQTT_OP_CONNECT_JSTR, pOpBuf))
        {
            status = MQTT_TEST_parseAndExecConnect(pJsonCtx, currentIndex, &connInst);
            process = TRUE;
        }
        else if (0 == MOC_STRCMP(MQTT_OP_PUBLISH_JSTR, pOpBuf))
        {
            status = MQTT_TEST_parseAndExecPublish(pJsonCtx, currentIndex, &connInst);
            process = TRUE;
        }
        else if (0 == MOC_STRCMP(MQTT_OP_SUBSCRIBE_JSTR, pOpBuf))
        {
            status = MQTT_TEST_parseAndExecSubscribe(pJsonCtx, currentIndex, &connInst);
            process = TRUE;
        }
        else if (0 == MOC_STRCMP(MQTT_OP_RECV_JSTR, pOpBuf))
        {
            status = MQTT_TEST_parseAndExecRecv(pJsonCtx, currentIndex);
        }
        else if (0 == MOC_STRCMP(MQTT_OP_EXPECT_JSTR, pOpBuf))
        {
            status = MQTT_TEST_parseAndExecExpect(pJsonCtx, currentIndex, NULL);
        }
        else if (0 == MOC_STRCMP(MQTT_OP_DISCONNECT_JSTR, pOpBuf))
        {
            status = MQTT_TEST_parseAndExecDisconn(pJsonCtx, currentIndex);
        }
        else if (0 == MOC_STRCMP(MQTT_OP_DESTROY_JSTR, pOpBuf))
        {
            status = MQTT_TEST_parseAndExecDestroy(pJsonCtx, currentIndex);
        }
        else if (0 == MOC_STRCMP(MQTT_OP_RESET_NETWORK_JSTR, pOpBuf))
        {
            status = MQTT_TEST_resetNetwork(pJsonCtx, currentIndex);
        }
        else if (0 == MOC_STRCMP(MQTT_OP_SYNC_EXPECTS_JSTR, pOpBuf))
        {
            /* If there are non-blocking expects still running, loop until they complete or timeout */
            while(MQTT_TEST_expecting())
            {
                RTOS_sleepMS(MQTT_TEST_DEFLT_SLEEP_MS);
            }
        }
        else if (0 == MOC_STRCMP(MQTT_OP_SLEEP_JSTR, pOpBuf))
        {
            status = MQTT_TEST_parseAndExecSleep(pJsonCtx, currentIndex);
        }
        else if (0 == MOC_STRCMP(MQTT_OP_SET_PUB_TIMEOUT_JSTR, pOpBuf))
        {
            status = MQTT_TEST_parseAndExecSetPubTimeout(pJsonCtx, currentIndex);
        }
        else if (0 == MOC_STRCMP(MQTT_OP_VERIFY_OUT_EMPTY, pOpBuf))
        {
            status = MQTT_TEST_parseandExecVerifyOutEmpty(pJsonCtx, currentIndex);
        }
        else if (0 == MOC_STRCMP(MQTT_OP_VERIFY_IN_EMPTY, pOpBuf))
        {
            status = MQTT_TEST_parseandExecVerifyInEmpty(pJsonCtx, currentIndex);
        }
        else if (0 == MOC_STRCMP(MQTT_OP_EXPECT_OUTBOUND, pOpBuf))
        {
            status = MQTT_TEST_parseandExecExpectOut(pJsonCtx, currentIndex);
        }
        else
        {
            printf("ERROR invalid config file\n");
            status = ERR_INVALID_INPUT;
            goto exit;
        }

        if (OK == status)
        {
#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
            if (TRUE == process)
            {
                status = MQTT_getClientIdFromConnInst(connInst, (ubyte **)&pClientId, &clientIdLen);
                if (OK != status)
                    goto exit;
                pClientId[clientIdLen] = '\0';
            }

            if ( (TRUE == process) && (MQTT_TEST_isClientAsync(pClientId)) )
            {
                    status = MQTT_TEST_asyncRecv(pClientId, connInst, 0, MQTT_TEST_DEFAULT_RESP_TIMEOUT_MS, TRUE);
                    if (OK != status)
                        goto exit;
            }
            else
#endif
            if ( (FALSE == gExtended) && (TRUE == process) )
            {
                loopms = MQTT_TEST_DEFAULT_RESP_TIMEOUT_MS;
                do
                {
                    RTOS_deltaMS(NULL, &start);
                    timeout = loopms;

                    status = MQTT_recvEx(connInst, timeout);
                    if (OK != status)
                    {
                        printf("ERROR MQTT_recvEx status: %d\n", status);
                        goto exit;
                    }

                    timeout = RTOS_deltaMS(&start, &current);
                    if (timeout < loopms)
                    {
                        loopms = loopms - timeout;
                    }
                    else
                    {
                        loopms = 0;
                    }
                } while(loopms > 0);
            }
        }

    } while(OK == status);

    /* Check to see if there were non-blocking expect results */
    if (OK == status)
    {
        status = MQTT_TEST_getExpectStatus();
    }

exit:

    /* If we hit an error in the main thread, wait for the expects to time out anyways. 
     * This is easier than trying to maintain and kill all expect threads on error. */
    /* If there are non-blocking expects still running, loop until they complete or timeout */
    while(MQTT_TEST_expecting())
    {
        RTOS_sleepMS(MQTT_TEST_DEFLT_SLEEP_MS);
    }

#if defined(__ENABLE_MOCANA_SSL_CLIENT__)
    if (NULL != pCaFile)
    {
        MOC_FREE((void **)&pCaFile);
    }
#endif
    if (NULL != pData)
    {
        MOC_FREE((void **)&pData);
    }
    if (NULL != pJsonCtx)
    {
        JSON_releaseContext(&pJsonCtx);
    }
    MQTT_TEST_removeAllNonBlockingElems();

    if (OK == status)
    {
        printf("SUCCESS all operations executed successfully\n");
    }
    else
    {
        printf("MQTT_TEST_parseAndExecConfig FAIL status: %d\n", status);
    }

    return status;
}

/*----------------------------------------------------------------------------*/

static MSTATUS MQTT_TEST_publishHandler(
    sbyte4 connectionInstance,
    MqttMessage *pMsg,
    MqttPublishInfo *pInfo)
{
    MSTATUS status = OK;
    MqttTestClient *pClient = NULL;
    sbyte *pClientId = NULL;
    ubyte4 clientIdLen = 0;
    sbyte4 cmp = 1;
    ubyte allFound = FALSE;
    ubyte4 i;

    status = MQTT_getClientIdFromConnInst(connectionInstance, (ubyte **)&pClientId, &clientIdLen);
    if (OK != status)
        goto exit;

    status = MQTT_TEST_getClient(pClientId, &pClient);
    if (OK != status)
        goto exit;

    for (i = 0; i < pClient->numExpects; i++)
    {
        if (TRUE == pClient->pExpects[i].found)
        {
            continue;
        }

        if (pInfo->payloadLen != pClient->pExpects[i].dataLen)
        {
            continue;
        }

        if (MOC_STRLEN(pClient->pExpects[i].pTopic) != pInfo->topicLen)
        {
            continue;
        }

        status = MOC_MEMCMP(pInfo->pTopic, pClient->pExpects[i].pTopic, pInfo->topicLen, &cmp);
        if (OK != status)
            goto exit;

        if (0 != cmp)
        {
            continue;
        }

        status = MOC_MEMCMP(pInfo->pPayload, pClient->pExpects[i].pData, pInfo->payloadLen, &cmp);
        if (OK != status)
            goto exit;

        if (0 != cmp)
        {
            continue;
        }

        if (TRUE == pClient->pExpects[i].payloadFormatSet)
        {
            if (TRUE != pClient->pExpects[i].payloadFormatSet)
            {
                continue;
            }

            if (pClient->pExpects[i].payloadFormat != pInfo->payloadFormat)
            {
                continue;
            }
        }

        if (TRUE == pClient->pExpects[i].messageExpirySet)
        {
            if (TRUE != pClient->pExpects[i].messageExpirySet)
            {
                continue;
            }

            if (pClient->pExpects[i].messageExpiry != pInfo->messageExpiry)
            {
                continue;
            }
        }

        if (NULL != pClient->pExpects[i].pCorrelationData)
        {
            if (pClient->pExpects[i].correlationDataLen != pInfo->correlationDataLen)
            {
                continue;
            }

            status = MOC_MEMCMP (
                pInfo->pCorrelationData, pClient->pExpects[i].pCorrelationData, pInfo->correlationDataLen, &cmp);
            if (OK != status)
                goto exit;

            if (0 != cmp)
            {
                continue;
            }
        }

        if (NULL != pClient->pExpects[i].pContentType)
        {
            if (pClient->pExpects[i].contentTypeLen != pInfo->contentTypeLen)
            {
                continue;
            }

            status = MOC_MEMCMP (
                pInfo->pContentType, pClient->pExpects[i].pContentType, pInfo->contentTypeLen, &cmp);
            if (OK != status)
                goto exit;

            if (0 != cmp)
            {
                continue;
            }
        }

        if (TRUE == pClient->pExpects[i].qosSet)
        {
            if (pInfo->qos == pClient->pExpects[i].qos)
            {
                printf("Found expected value: %.*s\n", pInfo->payloadLen, pInfo->pPayload);
                pClient->pExpects[i].found = TRUE;
            }
        }
        else
        {
            printf("Found expected value: %.*s\n", pInfo->payloadLen, pInfo->pPayload);
            pClient->pExpects[i].found = TRUE;
        }
    }

    allFound = TRUE;
    for (i = 0; i < pClient->numExpects; i++)
    {
        if (FALSE == pClient->pExpects[i].found)
        {
            allFound = FALSE;
            break;
        }
    }

    if (TRUE == allFound)
    {
        printf("Found all expected values for conninst: %d\n", connectionInstance);
        pClient->allFound = TRUE;
    }

    printf("Recv PUBLISH for conninst: %d\n", connectionInstance);
    printf("Topic: %.*s\n", pInfo->topicLen, pInfo->pTopic);
    printf("Qos: %d\n", pInfo->qos);
    printf("Payload: %.*s\n", pInfo->payloadLen, pInfo->pPayload);

    printf("topic alias: %d\n", pInfo->topicAlias);
    if (0 != pInfo->payloadFormatSet)
    {
        printf("payloadformat: %d\n", pInfo->payloadFormat);
    }

    if (TRUE == pInfo->messageExpirySet)
    {
        printf("msgExpiryInterval: %d\n", pInfo->messageExpiry);
    }
    
    if (NULL != pInfo->pCorrelationData)
    {
        printf("Correlation data len: %d\n", pInfo->correlationDataLen);
        printf("Correlation data: ");
        for (i = 0; i < pInfo->correlationDataLen; i++)
        {
            printf("%c", pInfo->pCorrelationData[i]);
        }
        printf("\n");
    }

    if (NULL != pInfo->pContentType)
    {
        printf("Content type len: %d\n", pInfo->contentTypeLen);
        printf("Content type: ");
        for (i = 0; i < pInfo->contentTypeLen; i++)
        {
            printf("%c", pInfo->pContentType[i]);
        }
        printf("\n");
    }

    if (NULL != pInfo->pResponseTopic)
    {
        printf("Response Topic len: %d\n", pInfo->responseTopicLen);
        printf("Response Topic: ");
        for (i = 0; i < pInfo->responseTopicLen; i++)
        {
            printf("%c", pInfo->pResponseTopic[i]);
        }
        printf("\n");
    }
    


exit:

    return status;
}

static MSTATUS MQTT_EXAMPLE_parseArgs(
    int argc,
    char **ppArgv,
    MqttClientExampleCtx *pCtx)
{
    MSTATUS status = ERR_INVALID_ARG;
    int i;

    for (i = 1; i < argc; i++)
    {
        if (0 == MOC_STRCMP(ppArgv[i], "--help"))
        {
            status = MQTT_EXAMPLE_displayHelp(ppArgv[0], NULL);
            goto exit;
        }
        else if (0 == MOC_STRCMP(ppArgv[i], "--mqtt_config"))
        {
            i++;
            if (i >= argc)
            {
                status = MQTT_EXAMPLE_displayHelp(ppArgv[0], "Missing --config argument");
                goto exit;
            }
            setStringParameter((char **) &gpConfig, ppArgv[i]);
        }
    }

    status = OK;

exit:

    return status;
}


/*----------------------------------------------------------------------------*/

MSTATUS MQTT_TEST_initConnection(MqttClientExampleCtx *pCtx, TCP_SOCKET *pSocket)
{
    MSTATUS status;
    TCP_SOCKET socket = 0;

    status = TCP_GETHOSTBYNAME(pCtx->pMqttServer, pCtx->pMqttServerIp);
    if (OK != status)
    {
        printf("TCP_GETHOSTBYNAME failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

    status = TCP_CONNECT(
        &socket, pCtx->pMqttServerIp, pCtx->mqttPortNo);
    if (OK != status)
    {
        printf("TCP_CONNECT failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

    *pSocket = socket;

exit:
    return status;
}


int main(int argc, char *ppArgv[])
{
    MSTATUS status;
    MqttClientExampleCtx *pCtx = NULL;
    ubyte4 i;

    status = MOCANA_initMocana();
    if (OK != status)
    {
        printf("MOCANA_initMocana failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

    status = MQTT_TEST_init();
    if (OK != status)
    {
        printf("MQTT_TEST_init failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

    status = MQTT_EXAMPLE_contextCreate(&pCtx);
    if (OK != status)
    {
        printf("MQTT_EXAMPLE_contextCreate failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

    gpCtx = pCtx;

    status = MQTT_EXAMPLE_parseArgs(argc, ppArgv, pCtx);
    if (OK != status)
    {
        printf("MQTT_EXAMPLE_parseArgs failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

    status = MQTT_init(MAX_MQTT_CLIENT_CONNECTIONS);
    if (OK != status)
    {
        printf("MQTT_init failed with status = %d on line %d\n", status, __LINE__);
        goto exit;
    }

    status = MQTT_TEST_parseAndExecConfig(gpConfig);


exit:

    MQTT_EXAMPLE_contextDelete(&pCtx);
    MQTT_TEST_uninit();

    if (NULL != gpConfig)
    {
        MOC_FREE((void **)&gpConfig);
    }

    MQTT_shutdownStack();

    MOCANA_freeMocana();

    return (OK > status) ? -1 : 0;
}
