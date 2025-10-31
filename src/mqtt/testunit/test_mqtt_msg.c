/*
 * test_mqtt_msg.c
 *
 * MQTT Message Unit Test
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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>

#include "cmocka.h"

#include "common/moptions.h"
#include "common/mtypes.h"
#include "common/merrors.h"
#include "common/mdefs.h"
#include "common/mstdlib.h"
#include "common/mocana.h"
#include "../../mqtt/mqtt_client.h" 
#include "mqtt/mqtt_client_priv.h"
#include "mqtt/mqtt_msg.h"


static void mqtt_test_MQTT_buildConnectMsg(void **ppState)
{
    MqttCtx *pCtx = NULL;
    MqttConnectOptions options = {0};
    MqttMessage *pMsg = NULL;
    MSTATUS status;

    MOC_MALLOC((void **)&pCtx, sizeof(MqttCtx));
    assert_non_null(pCtx);

/*version 5 test*/
    pCtx->version = 5;
    pCtx->pClientId = "testClient";
    pCtx->clientIdLen = 10;
    pCtx->keepAliveMS = 60000;

    options.keepAliveInterval = 60;
    options.cleanStart = 1;
    options.maxPacketSize = 1024;
    options.sessionExpiryIntervalSeconds = 60;
    options.sessionExpiryIntervalSet = 1;
    options.maxPacketSizeSet = 1;
    options.pPassword = "password";
    options.passwordLen = 8;
    options.pUsername = "username";
    options.usernameLen = 8; 
    options.willInfo.pWillTopic = "willTopic";
    options.willInfo.willTopicLen = 9;
    options.willInfo.pWill = "willMessage";
    options.willInfo.willLen = 10;  

    status = MQTT_buildConnectMsg(pCtx, &options, &pMsg);
    assert_int_equal(OK, status);
    assert_non_null(pMsg);
    assert_int_equal(1, pMsg->type);

/* version 3.1.1 returns ERR_MQTT_CLEAN_SESSION_REQUIRED when zero len client id is sent without clean start*/
    pCtx->version = 4;
    pCtx->pClientId = NULL;
    pCtx->clientIdLen = 0;
    pCtx->assignedClientId = 1;
    options.cleanStart = 0;

    status = MQTT_buildConnectMsg(pCtx, &options, &pMsg);
    assert_int_equal(ERR_MQTT_CLEAN_SESSION_REQUIRED, status);

    MOC_FREE((void **)&pCtx);
    status = MQTT_freeMsg(&pMsg);
    assert_int_equal(OK, status);
}

static void mqtt_test_MQTT_buildSubscribeMsg(void **ppState)
{
    MqttCtx *pCtx = NULL;
    MqttSubscribeTopic topics[1] = {0};
    MqttSubscribeOptions options = {0};
    MqttMessage *pMsg = NULL;
    MqttProperty *pProps = NULL;
    ubyte2 packetId = 0;
    MSTATUS status;

    MQTT_init(1);

    MOC_MALLOC((void **)&pCtx, sizeof(MqttCtx));
    assert_non_null(pCtx);

    MOC_MALLOC_MEMCPY((void **)&pCtx->pClientId, 10, "testClient", 10);
    assert_non_null(pCtx->pClientId);
    pCtx->clientIdLen = 10;

    pCtx->version = 5;

    topics[0].pTopic = "testTopic";
    topics[0].topicLen = 9;
    topics[0].qos = 1;

    options.subId = 1;
    
    status = MQTT_buildSubscribeMsg(pCtx, topics, 1, &options, &packetId, &pMsg);
    assert_int_equal(OK, status);
    assert_non_null(pMsg);
    assert_int_equal(8, pMsg->type);

    status = MQTT_freeMsg(&pMsg);
    assert_int_equal(OK, status);
   
    options.propCount = 2;
    MOC_MALLOC((void **)&options.pProps, sizeof(MqttProperty) * 2);
    options.pProps[0].data.pair.name.pData = "testName";
    options.pProps[0].data.pair.name.dataLen = 8;
    options.pProps[0].data.pair.value.pData = "testValue";
    options.pProps[0].data.pair.value.dataLen = 9;
    options.pProps[1].data.pair.name.pData = "testName2";
    options.pProps[1].data.pair.name.dataLen = 9;
    options.pProps[1].data.pair.value.pData = "testValue2";
    options.pProps[1].data.pair.value.dataLen = 10;

    status = MQTT_buildSubscribeMsg(pCtx, topics, 1, &options, &packetId, &pMsg);
    assert_int_equal(OK, status);
    assert_non_null(pMsg);
    assert_int_equal(8, pMsg->type);

    status = MQTT_freeMsg(&pMsg);
    assert_int_equal(OK, status);

    MOC_FREE((void **)&pCtx->pClientId);
    MOC_FREE((void **)&pCtx);
    MOC_FREE((void **)&options.pProps);
    MQTT_shutdownStack();
     
}

static void mqtt_test_MQTT_buildUnsubscribeMsg(void **ppState)
{
    MqttCtx *pCtx = NULL;
    MqttUnsubscribeTopic topics[1] = {0};
    MqttMessage *pMsg = NULL;
    MqttProperty *pProps = NULL;
    MqttUnsubscribeOptions options = {0};
    ubyte2 packetId = 0;
    MSTATUS status;

    MQTT_init(1);

    MOC_MALLOC((void **)&pCtx, sizeof(MqttCtx));
    assert_non_null(pCtx);

    MOC_MALLOC_MEMCPY((void **)&pCtx->pClientId, 10, "testClient", 10);
    assert_non_null(pCtx->pClientId);
    pCtx->clientIdLen = 10;

    pCtx->version = 5;

    topics[0].pTopic = "testTopic";
    topics[0].topicLen = 9;

    status = MQTT_buildUnsubscribeMsg(pCtx, topics, 1, &options, &packetId, &pMsg);
    assert_int_equal(OK, status);
    assert_non_null(pMsg);
    assert_int_equal(10, pMsg->type);

    status = MQTT_freeMsg(&pMsg);
    assert_int_equal(OK, status);

    options.propCount = 2;
    MOC_MALLOC((void **)&options.pProps, sizeof(MqttProperty) * 2);
    options.pProps[0].data.pair.name.pData = "testName";
    options.pProps[0].data.pair.name.dataLen = 8;
    options.pProps[0].data.pair.value.pData = "testValue";
    options.pProps[0].data.pair.value.dataLen = 9;
    options.pProps[1].data.pair.name.pData = "testName2";
    options.pProps[1].data.pair.name.dataLen = 9;
    options.pProps[1].data.pair.value.pData = "testValue2";
    options.pProps[1].data.pair.value.dataLen = 10;

    status = MQTT_buildUnsubscribeMsg(pCtx, topics, 1, &options, &packetId, &pMsg);
    assert_int_equal(OK, status);
    assert_non_null(pMsg);
    assert_int_equal(10, pMsg->type);

    status = MQTT_freeMsg(&pMsg);
    assert_int_equal(OK, status);

    MOC_FREE((void **)&pCtx->pClientId);
    MOC_FREE((void **)&pCtx);
    MOC_FREE((void **)&options.pProps);
    MQTT_shutdownStack();
}

static void mqtt_test_MQTT_buildPublishMsg(void **ppState)
{
    MqttCtx *pCtx = NULL;
    MqttPublishOptions options = {0};
    MqttMessage *pMsg = NULL;
    MSTATUS status;

    MOC_MALLOC((void **)&pCtx, sizeof(MqttCtx));
    assert_non_null(pCtx);

    pCtx->version = 5;
    pCtx->pClientId = "testClient";
    pCtx->clientIdLen = 10;
    pCtx->pktId = 1;

    options.qos = 0;
    options.retain = 1;
    options.payloadFormat = 1;
    options.msgExpiryInterval = 60;
    options.msgExpiryIntervalSet = 1;
    options.topicAlias = 1;
    options.topicAliasSet = 1;
    options.pProps = NULL;
    options.propCount = 0;

    status = MQTT_buildPublishMsg(pCtx, &options, "testTopic", 9, "testData", 8, &pCtx->pktId, &pMsg);
    assert_int_equal(OK, status);
    assert_non_null(pMsg);
    assert_int_equal(3, pMsg->type);

    status = MQTT_freeMsg(&pMsg);
    assert_int_equal(OK, status);
    assert_null(pMsg);

    MOC_MEMSET((ubyte *)pCtx, 0, sizeof(MqttCtx));
    pCtx->version = 5;  

    status = MQTT_buildPublishMsg(pCtx, &options, "testTopic", 9, "testData", 8, &pCtx->pktId, &pMsg);
    assert_int_equal(OK, status);
    assert_non_null(pMsg);
    assert_int_equal(3, pMsg->type);

    status = MQTT_freeMsg(&pMsg);
    assert_int_equal(OK, status);
    assert_null(pMsg);

    pCtx->version = 4;
    status = MQTT_buildPublishMsg(pCtx, &options, "testTopic", 9, "testData", 8, &pCtx->pktId, &pMsg);
    assert_int_equal(OK, status);
    assert_non_null(pMsg);
    assert_int_equal(3, pMsg->type);

    status = MQTT_freeMsg(&pMsg);
    assert_int_equal(OK, status);
    assert_null(pMsg);

    /* test user properties */
    pCtx->version = 5;
    options.propCount = 1;
    MOC_MALLOC((void **)&options.pProps, sizeof(MqttProperty));
    options.pProps[0].data.pair.name.pData = "testName";
    options.pProps[0].data.pair.name.dataLen = 8;
    options.pProps[0].data.pair.value.pData = "testValue";
    options.pProps[0].data.pair.value.dataLen = 9;

    status = MQTT_buildPublishMsg(pCtx, &options, "testTopic", 9, "testData", 8, &pCtx->pktId, &pMsg);
    assert_int_equal(OK, status);
    assert_non_null(pMsg);
    assert_int_equal(3, pMsg->type);

    status = MQTT_freeMsg(&pMsg);
    assert_int_equal(OK, status);
    assert_null(pMsg);
    MOC_FREE((void **)&pCtx);
    MOC_FREE((void **)&options.pProps);

}

static void mqtt_test_MQTT_buildPubRespMsg(void **ppState)
{
    MqttCtx *pCtx = NULL;
    MqttPubRespOptions options = {0};
    MqttMessage *pMsg = NULL;
    MSTATUS status;

    MOC_MALLOC((void **)&pCtx, sizeof(MqttCtx));
    assert_non_null(pCtx);

    pCtx->version = 5;
    pCtx->pClientId = "testClient";
    pCtx->clientIdLen = 10;
    pCtx->pktId = 1;

    options.reasonCode = 0;
    options.pProps = NULL;
    options.propCount = 0;
    options.packetType = 6;

    status = MQTT_buildPubRespMsg(pCtx, &options, &pMsg);
    assert_int_equal(OK, status);
    assert_non_null(pMsg);
    assert_int_equal(6, pMsg->type);

    status = MQTT_freeMsg(&pMsg);
    assert_int_equal(OK, status);

    options.packetType  = 4;
    status = MQTT_buildPubRespMsg(pCtx, &options, &pMsg);
    assert_int_equal(OK, status);
    assert_non_null(pMsg);
    assert_int_equal(4, pMsg->type);

    status = MQTT_freeMsg(&pMsg);
    assert_int_equal(OK, status);

    options.packetType = 5;
    status = MQTT_buildPubRespMsg(pCtx, &options, &pMsg);
    assert_int_equal(OK, status);
    assert_non_null(pMsg);
    assert_int_equal(5, pMsg->type);

    status = MQTT_freeMsg(&pMsg);
    assert_int_equal(OK, status);

    options.packetType = 7;
    status = MQTT_buildPubRespMsg(pCtx, &options, &pMsg);
    assert_int_equal(OK, status);   
    assert_non_null(pMsg);
    assert_int_equal(7, pMsg->type);


    MOC_FREE((void **)&pCtx);
    status = MQTT_freeMsg(&pMsg);
    assert_int_equal(OK, status);
}

static void mqtt_test_MQTT_buildPingReqMsg(void **ppState)
{
    MqttCtx *pCtx = NULL;
    MqttMessage *pMsg = NULL;
    MSTATUS status;

    MOC_MALLOC((void **)&pCtx, sizeof(MqttCtx));
    assert_non_null(pCtx);

    pCtx->version = 5;
    pCtx->pClientId = "testClient";
    pCtx->clientIdLen = 10;

    status = MQTT_buildPingReqMsg(pCtx, &pMsg);
    assert_int_equal(OK, status);
    assert_non_null(pMsg);
    assert_int_equal(12, pMsg->type);

    status = MQTT_freeMsg(&pMsg);
    assert_int_equal(OK, status);

    pCtx->version = 4;
    status = MQTT_buildPingReqMsg(pCtx, &pMsg);
    assert_int_equal(OK, status);
    assert_non_null(pMsg);
    assert_int_equal(12, pMsg->type);

    status = MQTT_freeMsg(&pMsg);
    assert_int_equal(OK, status);

    MOC_FREE((void **)&pCtx);
}

static void mqtt_test_MQTT_buildDisconnectMsg(void **ppState)
{
    MqttCtx *pCtx = NULL;
    MqttDisconnectOptions options = {0};
    MqttMessage *pMsg = NULL;
    MSTATUS status;

    MOC_MALLOC((void **)&pCtx, sizeof(MqttCtx));
    assert_non_null(pCtx);

    pCtx->version = 5;
    pCtx->pClientId = "testClient";
    pCtx->clientIdLen = 10;
    pCtx->sessionExpiryInterval = 0;

    options.reasonCode = 0;
    options.pProps = NULL;
    options.propCount = 0;

    status = MQTT_buildDisconnectMsg(pCtx, &options, &pMsg);
    assert_int_equal(OK, status);
    assert_non_null(pMsg);
    assert_int_equal(14, pMsg->type);

    status = MQTT_freeMsg(&pMsg);
    assert_int_equal(OK, status);

    options.sessionExpiryInterval = 50;
    status = MQTT_buildDisconnectMsg(pCtx, &options, &pMsg);
    assert_int_equal(ERR_MQTT_DISCONN_SESSION_EXPIRY_MISMATCH, status);
    assert_null(pMsg);

    status = MQTT_freeMsg(&pMsg);
    assert_int_equal(OK, status);

    /* user properties */
    options.sessionExpiryInterval = 0;
    options.propCount = 2;
    MOC_MALLOC((void **)&options.pProps, sizeof(MqttProperty) * 2);
    options.pProps[0].data.pair.name.pData = "testName";
    options.pProps[0].data.pair.name.dataLen = 8;
    options.pProps[0].data.pair.value.pData = "testValue";
    options.pProps[0].data.pair.value.dataLen = 9;

    options.pProps[1].data.pair.name.pData = "testName2";
    options.pProps[1].data.pair.name.dataLen = 9;
    options.pProps[1].data.pair.value.pData = "testValue2";
    options.pProps[1].data.pair.value.dataLen = 10;

    status = MQTT_buildDisconnectMsg(pCtx, &options, &pMsg);
    assert_int_equal(OK, status);
    assert_non_null(pMsg);
    assert_int_equal(14, pMsg->type);

    status = MQTT_freeMsg(&pMsg);
    assert_int_equal(OK, status);
    MOC_FREE((void **)&options.pProps);
    
    pCtx->version = 4;
    status = MQTT_buildDisconnectMsg(pCtx, &options, &pMsg);
    assert_int_equal(OK, status);
    assert_non_null(pMsg);
    assert_int_equal(14, pMsg->type);

    status = MQTT_freeMsg(&pMsg);
    assert_int_equal(OK, status);  

    MOC_FREE((void **)&pCtx);
}

static void mqtt_test_MQTT_freeMsg(void **ppState)
{
    MqttMessage *pMsg = NULL;
    MSTATUS status;

    status = MQTT_freeMsg(&pMsg);
    assert_int_equal(OK, status);
    assert_null(pMsg);

    MOC_MALLOC((void **)&pMsg, sizeof(MqttMessage));
    assert_non_null(pMsg);

    MOC_MEMSET((ubyte *)pMsg, 0x00, sizeof(MqttMessage));
    status = MQTT_freeMsg(&pMsg);
    assert_int_equal(OK, status);
    assert_null(pMsg);

    MOC_MALLOC((void **)&pMsg, sizeof(MqttMessage));
    assert_non_null(pMsg);

    MOC_MALLOC_MEMCPY((void **)&pMsg->pData, 8, "testData", 8);
    pMsg->dataLen = 8;
    pMsg->type = 3;

    status = MQTT_freeMsg(&pMsg);
    assert_int_equal(OK, status);
    assert_null(pMsg);
}

static void mqtt_test_MQTT_buildAuthMsg(void **ppState)
{
    MqttCtx *pCtx = NULL;
    MqttAuthOptions options = {0};
    MqttMessage *pMsg = NULL;
    MSTATUS status;

    MOC_MALLOC((void **)&pCtx, sizeof(MqttCtx));
    assert_non_null(pCtx);

    pCtx->version = 5;
    pCtx->pClientId = "testClient";
    pCtx->clientIdLen = 10;
    pCtx->pktId = 1;

    options.pProps = NULL;
    options.propCount = 0;
    options.pAuthMethod = "testMethod";
    options.authMethodLen = 10;
    options.pAuthData = "testData"; 
    options.authDataLen = 8;
    options.reAuthenticate = 0;

    status = MQTT_buildAuthMsg(pCtx, &options, &pMsg);
    assert_int_equal(OK, status);
    assert_non_null(pMsg);
    assert_int_equal(15, pMsg->type);

    status = MQTT_freeMsg(&pMsg);
    assert_int_equal(OK, status);

    options.reAuthenticate = 1;
    status = MQTT_buildAuthMsg(pCtx, &options, &pMsg);
    assert_int_equal(OK, status);
    assert_non_null(pMsg);
    assert_int_equal(15, pMsg->type);

    status = MQTT_freeMsg(&pMsg);
    assert_int_equal(OK, status);

    MOC_FREE((void **)&pCtx);
    
}

static void mqtt_test_MQTT_parsePacket(void **ppState)
{
    MqttCtx *pCtx = NULL;
    MqttMessage *pMsg = NULL;
    MSTATUS status;

    MQTT_init(1);

    MOC_MALLOC((void **)&pCtx, sizeof(MqttCtx));
    assert_non_null(pCtx);
    MOC_MEMSET((ubyte *)pCtx, 0, sizeof(MqttCtx));

    pCtx->maxPacketSize = 1024;
    pCtx->version = 5;
    pCtx->pClientId = "testClient";
    pCtx->clientIdLen = 10;
    pCtx->connectionState = CONNECT_NEGOTIATE;

/* Packet type : CONNACK*/
    ubyte *pBuffer = NULL;
    ubyte buffer[11] = {0x20, 0x09, 0x00, 0x00, 0x06, 0x22, 0x00, 0x0a, 0x21, 0x00, 0x0a};
    pBuffer = buffer;
    status = MQTT_parsePacket(1, pCtx, pBuffer, 11);
    assert_int_equal(OK, status);
    assert_int_equal(2, (*(pCtx->pRecvBuffer) >> 4));
    MOC_FREE((void **)&pCtx->pRecvBuffer);

    MOC_MEMSET((ubyte *)pCtx, 0, sizeof(MqttCtx));
    pCtx->maxPacketSize = 5;
    pCtx->version = 5;
    pCtx->pClientId = "testClient";
    pCtx->clientIdLen = 10;
    pCtx->connectionState = CONNECT_NEGOTIATE;
    status = MQTT_parsePacket(1, pCtx, pBuffer, 11);
    assert_int_equal(ERR_MQTT_PACKET_TOO_LARGE, status);

    MOC_MEMSET((ubyte *)pCtx, 0, sizeof(MqttCtx));
    pCtx->version = 5;
    pCtx->pClientId = "testClient";
    pCtx->clientIdLen = 10;
    pCtx->maxPacketSize = 1024;
    pCtx->connectionState = CONNECT_NEGOTIATE;
    ubyte buffer1[5] = {0x20, 0x09, 0x00, 0x00, 0x06};
    pBuffer = buffer1;
    status = MQTT_parsePacket(1, pCtx, pBuffer, 5);
    assert_int_equal(OK, status);

    ubyte buffer2[6] = {0x22, 0x00, 0x0a, 0x21, 0x00, 0x0a};
    pBuffer = buffer2;
    status = MQTT_parsePacket(1, pCtx, pBuffer, 6); 
    assert_int_equal(OK, status);
    assert_int_equal(2, (*(pCtx->pRecvBuffer) >> 4));

    MOC_FREE((void **)&pCtx->pRecvBuffer);

    /* reason code : 128*/
    MOC_MEMSET((ubyte *)pCtx, 0, sizeof(MqttCtx));
    pCtx->version = 5;
    pCtx->pClientId = "testClient";
    pCtx->clientIdLen = 10;
    pCtx->maxPacketSize = 1024;
    pCtx->connectionState = CONNECT_NEGOTIATE;
    ubyte buffer3[11] = {0x20, 0x09, 0x00, 0x80, 0x06, 0x22, 0x00, 0x0a, 0x21, 0x00, 0x80};
    pBuffer = buffer3;
    status = MQTT_parsePacket(1, pCtx, pBuffer, 11);
    assert_int_equal(ERR_MQTT_CONNECTION_REFUSED, status);
    MOC_FREE((void **)&pCtx->pRecvBuffer);

    MOC_MEMSET((ubyte *)pCtx, 0, sizeof(MqttCtx));
    pCtx->version = 5;
    pCtx->pClientId = "testClient";
    pCtx->clientIdLen = 10;
    pCtx->maxPacketSize = 1024;
    pCtx->connectionState = CONNECT_NEGOTIATE;
    ubyte buffer4[24] = {0x20, 0x16, 0x00, 0x00, 0x13, 0x22, 0x00, 0x0a, 0x21, 0x00, 0x0a, 0x26, 0x00, 0x03, 0x6b, 0x65, 0x79, 0x00, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65};
    pBuffer = buffer4;
    status = MQTT_parsePacket(1, pCtx, pBuffer, 24);
    assert_int_equal(OK, status);
    assert_int_equal(2, (*(pCtx->pRecvBuffer) >> 4));
    MOC_FREE((void **)&pCtx->pRecvBuffer);

/* packet type: SUBACK */
    MOC_MEMSET((ubyte *)pCtx, 0, sizeof(MqttCtx));

    MOC_MALLOC_MEMCPY((void **)&pCtx->pClientId, 10, "testClient", 10);
    assert_non_null(pCtx->pClientId);

    pCtx->clientIdLen = 10;
    pCtx->version = 5;
    pCtx->maxPacketSize = 1024;
    ubyte buffer5[6] = {0x90, 0x04, 0x00, 0x01, 0x00, 0x02};
    pBuffer = buffer5;
    status = MQTT_parsePacket(1, pCtx, pBuffer, 6);
    assert_int_equal(OK, status);
    assert_int_equal(9, (*(pCtx->pRecvBuffer) >> 4));
    MOC_FREE((void **)&pCtx->pRecvBuffer);
    MOC_FREE((void **)&pCtx->pClientId);

    /* properties */
    MOC_MEMSET((ubyte *)pCtx, 0, sizeof(MqttCtx));

    MOC_MALLOC_MEMCPY((void **)&pCtx->pClientId, 10, "testClient", 10);
    assert_non_null(pCtx->pClientId);

    pCtx->clientIdLen = 10;
    pCtx->version = 5;
    pCtx->maxPacketSize = 1024;
    ubyte buffer6[19] = {0x90, 0x11, 0x00, 0x01, 0x0d, 0x26, 0x00, 0x03, 0x6b, 0x65, 0x79, 0x00, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65};
    pBuffer = buffer6;
    status = MQTT_parsePacket(1, pCtx, pBuffer, 19);
    assert_int_equal(OK, status);
    assert_int_equal(9, (*(pCtx->pRecvBuffer) >> 4));
    MOC_FREE((void **)&pCtx->pRecvBuffer);
    MOC_FREE((void **)&pCtx->pClientId);

/* packet type: Unsuback*/
    MOC_MEMSET((ubyte *)pCtx, 0, sizeof(MqttCtx));
    MOC_MALLOC_MEMCPY((void **)&pCtx->pClientId, 10, "testClient", 10);
    assert_non_null(pCtx->pClientId);

    pCtx->clientIdLen = 10;
    pCtx->version = 5;
    pCtx->maxPacketSize = 1024;
    ubyte buffer7[6] = {0xb0, 0x04, 0x00, 0x01, 0x00, 0x02};
    pBuffer = buffer7;
    status = MQTT_parsePacket(1, pCtx, pBuffer, 6);
    assert_int_equal(OK, status);
    assert_int_equal(11, (*(pCtx->pRecvBuffer) >> 4));
    MOC_FREE((void **)&pCtx->pRecvBuffer);
    MOC_FREE((void **)&pCtx->pClientId);

    /* properties */
    MOC_MEMSET((ubyte *)pCtx, 0, sizeof(MqttCtx));
    MOC_MALLOC_MEMCPY((void **)&pCtx->pClientId, 10, "testClient", 10);
    assert_non_null(pCtx->pClientId);

    pCtx->clientIdLen = 10;
    pCtx->version = 5;
    pCtx->maxPacketSize = 1024;
    ubyte buffer8[19] = {0xb0, 0x10, 0x00, 0x01, 0x0d, 0x26, 0x00, 0x03, 0x6b, 0x65, 0x79, 0x00, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65};
    pBuffer = buffer8;
    status = MQTT_parsePacket(1, pCtx, pBuffer, 19);
    assert_int_equal(OK, status);
    assert_int_equal(11, (*(pCtx->pRecvBuffer) >> 4));
    MOC_FREE((void **)&pCtx->pRecvBuffer);
    MOC_FREE((void **)&pCtx->pClientId);

/* packet type: Publish*/

    MOC_MEMSET((ubyte *)pCtx, 0, sizeof(MqttCtx));
    pCtx->version = 5;

    pCtx->pClientId = "testClient";
    pCtx->clientIdLen = 10;
    pCtx->maxPacketSize = 1024;

    ubyte buffer9[16] = {0x30, 0x0e, 0x00, 0x05, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x00, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67};
    pBuffer = buffer9;
    status = MQTT_parsePacket(1, pCtx, pBuffer, 16);
    assert_int_equal(OK, status);
    assert_int_equal(3, (*(pCtx->pRecvBuffer) >> 4));
    MOC_FREE((void **)&pCtx->pRecvBuffer);

    /* properties */
    

    MOC_MEMSET((ubyte *)pCtx, 0, sizeof(MqttCtx));
    pCtx->version = 5;
    pCtx->pClientId = "testClient"; 
    pCtx->clientIdLen = 10;
    pCtx->maxPacketSize = 1024;
    pCtx->topicAliasMax = 10;

    ubyte buffer10[61] = {0x30, 0x3b, 0x00, 0x05, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x2c, 0x01, 0x01, 
                          0x02, 0x00, 0x00, 0x00, 0x0a, 0x23, 0x00, 0x01, 0x08, 0x00, 0x04, 0x72, 
                          0x65, 0x73, 0x70, 0x09, 0x00, 0x04, 0x64, 0x61, 0x74, 0x61, 0x26, 0x00, 
                          0x03, 0x6b, 0x65, 0x79, 0x00, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x03, 
                          0x00, 0x04, 0x74, 0x79, 0x70, 0x65, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65};
    pBuffer = buffer10;
    status = MQTT_parsePacket(1, pCtx, pBuffer, 61);
    assert_int_equal(OK, status);
    assert_int_equal(3, (*(pCtx->pRecvBuffer) >> 4));
    MOC_FREE((void **)&pCtx->pRecvBuffer);

    MOC_MEMSET((ubyte *)pCtx, 0, sizeof(MqttCtx));
    pCtx->version = 5;
    pCtx->pClientId = "testClient";
    pCtx->clientIdLen = 10;
    pCtx->maxPacketSize = 1024;
    pCtx->topicAliasMax = 10;

    ubyte buffer10a[1015] = {0x30, 0xf4, 0x07, 0x00, 0x05, 0x74, 0x6f, 0x70, 0x69, 0x63, 0x17, 0x01, 0x01, 0x02, 0x00, 0x00,
                          0x00, 0x64, 0x23, 0x00, 0x01, 0x26, 0x00, 0x03, 0x6b, 0x65, 0x79, 0x00, 0x05, 0x76, 0x61, 0x6c,
                          0x75, 0x65, 0x4c, 0x69, 0x67, 0x68, 0x74, 0x77, 0x65, 0x69, 0x67, 0x68, 0x74, 0x20, 0x61, 0x6e,
                          0x64, 0x20, 0x45, 0x66, 0x66, 0x69, 0x63, 0x69, 0x65, 0x6e, 0x74, 0x0a, 0x4d, 0x51, 0x54, 0x54,
                          0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x73, 0x20, 0x61, 0x72, 0x65, 0x20, 0x76, 0x65, 0x72,
                          0x79, 0x20, 0x73, 0x6d, 0x61, 0x6c, 0x6c, 0x2c, 0x20, 0x72, 0x65, 0x71, 0x75, 0x69, 0x72, 0x65,
                          0x20, 0x6d, 0x69, 0x6e, 0x69, 0x6d, 0x61, 0x6c, 0x20, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63,
                          0x65, 0x73, 0x20, 0x73, 0x6f, 0x20, 0x63, 0x61, 0x6e, 0x20, 0x62, 0x65, 0x20, 0x75, 0x73, 0x65,
                          0x64, 0x20, 0x6f, 0x6e, 0x20, 0x73, 0x6d, 0x61, 0x6c, 0x6c, 0x20, 0x6d, 0x69, 0x63, 0x72, 0x6f,
                          0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x6c, 0x65, 0x72, 0x73, 0x2e, 0x20, 0x4d, 0x51, 0x54,
                          0x54, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
                          0x73, 0x20, 0x61, 0x72, 0x65, 0x20, 0x73, 0x6d, 0x61, 0x6c, 0x6c, 0x20, 0x74, 0x6f, 0x20, 0x6f,
                          0x70, 0x74, 0x69, 0x6d, 0x69, 0x7a, 0x65, 0x20, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x20,
                          0x62, 0x61, 0x6e, 0x64, 0x77, 0x69, 0x64, 0x74, 0x68, 0x2e, 0x0a, 0x0a, 0x42, 0x69, 0x2d, 0x64,
                          0x69, 0x72, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x20, 0x43, 0x6f, 0x6d, 0x6d, 0x75,
                          0x6e, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x0a, 0x4d, 0x51, 0x54, 0x54, 0x20, 0x61,
                          0x6c, 0x6c, 0x6f, 0x77, 0x73, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67,
                          0x69, 0x6e, 0x67, 0x20, 0x62, 0x65, 0x74, 0x77, 0x65, 0x65, 0x6e, 0x20, 0x64, 0x65, 0x76, 0x69,
                          0x63, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x20, 0x61, 0x6e, 0x64, 0x20,
                          0x63, 0x6c, 0x6f, 0x75, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x2e,
                          0x20, 0x54, 0x68, 0x69, 0x73, 0x20, 0x6d, 0x61, 0x6b, 0x65, 0x73, 0x20, 0x66, 0x6f, 0x72, 0x20,
                          0x65, 0x61, 0x73, 0x79, 0x20, 0x62, 0x72, 0x6f, 0x61, 0x64, 0x63, 0x61, 0x73, 0x74, 0x69, 0x6e,
                          0x67, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73, 0x20, 0x74, 0x6f, 0x20, 0x67, 0x72,
                          0x6f, 0x75, 0x70, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x73, 0x2e, 0x0a,
                          0x0a, 0x53, 0x63, 0x61, 0x6c, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x4d, 0x69, 0x6c, 0x6c, 0x69, 0x6f,
                          0x6e, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x54, 0x68, 0x69, 0x6e, 0x67, 0x73, 0x0a, 0x4d, 0x51, 0x54,
                          0x54, 0x20, 0x63, 0x61, 0x6e, 0x20, 0x73, 0x63, 0x61, 0x6c, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x63,
                          0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x6d, 0x69, 0x6c, 0x6c,
                          0x69, 0x6f, 0x6e, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x49, 0x6f, 0x54, 0x20, 0x64, 0x65, 0x76, 0x69,
                          0x63, 0x65, 0x73, 0x2e, 0x0a, 0x0a, 0x52, 0x65, 0x6c, 0x69, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x4d,
                          0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x44, 0x65, 0x6c, 0x69, 0x76, 0x65, 0x72, 0x79, 0x0a,
                          0x52, 0x65, 0x6c, 0x69, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x79, 0x20, 0x6f, 0x66, 0x20, 0x6d,
                          0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x64, 0x65, 0x6c, 0x69, 0x76, 0x65, 0x72, 0x79, 0x20,
                          0x69, 0x73, 0x20, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x61, 0x6e, 0x74, 0x20, 0x66, 0x6f, 0x72,
                          0x20, 0x6d, 0x61, 0x6e, 0x79, 0x20, 0x49, 0x6f, 0x54, 0x20, 0x75, 0x73, 0x65, 0x20, 0x63, 0x61,
                          0x73, 0x65, 0x73, 0x2e, 0x20, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x77, 0x68, 0x79,
                          0x20, 0x4d, 0x51, 0x54, 0x54, 0x20, 0x68, 0x61, 0x73, 0x20, 0x33, 0x20, 0x64, 0x65, 0x66, 0x69,
                          0x6e, 0x65, 0x64, 0x20, 0x71, 0x75, 0x61, 0x6c, 0x69, 0x74, 0x79, 0x20, 0x6f, 0x66, 0x20, 0x73,
                          0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x20, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x73, 0x3a, 0x20, 0x30,
                          0x20, 0x2d, 0x20, 0x61, 0x74, 0x20, 0x6d, 0x6f, 0x73, 0x74, 0x20, 0x6f, 0x6e, 0x63, 0x65, 0x2c,
                          0x20, 0x31, 0x2d, 0x20, 0x61, 0x74, 0x20, 0x6c, 0x65, 0x61, 0x73, 0x74, 0x20, 0x6f, 0x6e, 0x63,
                          0x65, 0x2c, 0x20, 0x32, 0x20, 0x2d, 0x20, 0x65, 0x78, 0x61, 0x63, 0x74, 0x6c, 0x79, 0x20, 0x6f,
                          0x6e, 0x63, 0x65, 0x0a, 0x0a, 0x53, 0x75, 0x70, 0x70, 0x6f, 0x72, 0x74, 0x20, 0x66, 0x6f, 0x72,
                          0x20, 0x55, 0x6e, 0x72, 0x65, 0x6c, 0x69, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x4e, 0x65, 0x74, 0x77,
                          0x6f, 0x72, 0x6b, 0x73, 0x0a, 0x4d, 0x61, 0x6e, 0x79, 0x20, 0x49, 0x6f, 0x54, 0x20, 0x64, 0x65,
                          0x76, 0x69, 0x63, 0x65, 0x73, 0x20, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x20, 0x6f, 0x76,
                          0x65, 0x72, 0x20, 0x75, 0x6e, 0x72, 0x65, 0x6c, 0x69, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x63, 0x65,
                          0x6c, 0x6c, 0x75, 0x6c, 0x61, 0x72, 0x20, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x73, 0x2e,
                          0x20, 0x4d, 0x51, 0x54, 0x54, 0xe2, 0x80, 0x99, 0x73, 0x20, 0x73, 0x75, 0x70, 0x70, 0x6f, 0x72,
                          0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x70, 0x65, 0x72, 0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x74,
                          0x20, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x20, 0x72, 0x65, 0x64, 0x75, 0x63, 0x65,
                          0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x72, 0x65,
                          0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69, 0x65,
                          0x6e, 0x74, 0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x74, 0x68, 0x65, 0x20, 0x62, 0x72, 0x6f, 0x6b,
                          0x65, 0x72, 0x2e, 0x0a, 0x0a, 0x53, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x20, 0x45, 0x6e,
                          0x61, 0x62, 0x6c, 0x65, 0x64, 0x0a, 0x20, 0x0a, 0x4d, 0x51, 0x54, 0x54, 0x20, 0x6d, 0x61, 0x6b,
                          0x65, 0x73, 0x20, 0x69, 0x74, 0x20, 0x65, 0x61, 0x73, 0x79, 0x20, 0x74, 0x6f, 0x20, 0x65, 0x6e,
                          0x63, 0x72, 0x79, 0x70, 0x74, 0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73, 0x20, 0x75,
                          0x73, 0x69, 0x6e, 0x67, 0x20, 0x54, 0x4c, 0x53, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x61, 0x75, 0x74,
                          0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74,
                          0x73, 0x20, 0x75, 0x73, 0x69, 0x6e, 0x67, 0x20, 0x6d, 0x6f, 0x64, 0x65, 0x72, 0x6e, 0x20, 0x61,
                          0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x70, 0x72,
                          0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x73, 0x2c, 0x20, 0x73, 0x75, 0x63, 0x68, 0x20, 0x61, 0x73,
                          0x20, 0x4f, 0x41, 0x75, 0x74, 0x68, 0x2e};
    pBuffer = buffer10a;
    status = MQTT_parsePacket(1, pCtx, pBuffer, 1015);
    assert_int_equal(OK, status);
    assert_int_equal(3, (*(pCtx->pRecvBuffer) >> 4));
    MOC_FREE((void **)&pCtx->pRecvBuffer);
    
/* packet type: ping response*/

    MOC_MEMSET((ubyte *)pCtx, 0, sizeof(MqttCtx));
    pCtx->version = 5;
    pCtx->pClientId = "testClient";
    pCtx->clientIdLen = 10;
    pCtx->maxPacketSize = 1024;
    pCtx->pingCounter = 1;
    ubyte buffer11[2] = {0xd0, 0x00};
    pBuffer = buffer11;
    status = MQTT_parsePacket(1, pCtx, pBuffer, 2);
    assert_int_equal(OK, status);
    assert_int_equal(13, (*(pCtx->pRecvBuffer) >> 4));
    MOC_FREE((void **)&pCtx->pRecvBuffer);

/*packet type: disconnect*/
    MOC_MEMSET((ubyte *)pCtx, 0, sizeof(MqttCtx));
    pCtx->version = 5;
    pCtx->pClientId = "testClient";
    pCtx->clientIdLen = 10;
    pCtx->maxPacketSize = 1024;
    ubyte buffer12[4] = {0xe0, 0x02, 0x00, 0x00};
    pBuffer = buffer12;
    status = MQTT_parsePacket(1, pCtx, pBuffer, 4);
    assert_int_equal(OK, status);
    assert_int_equal(14, (*(pCtx->pRecvBuffer) >> 4));
    MOC_FREE((void **)&pCtx->pRecvBuffer);

    /* properties */
    MOC_MEMSET((ubyte *)pCtx, 0, sizeof(MqttCtx));
    pCtx->version = 5;
    pCtx->pClientId = "testClient";
    pCtx->clientIdLen = 10;
    pCtx->maxPacketSize = 1024;

    MOC_FREE((void **)&pCtx);
    MQTT_shutdownStack();

}

#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)

static void mqtt_test_MQTT_freeMsgNode(void **ppState)
{
    MqttMessageList *pMsgList = NULL;
    MSTATUS status;

    status = MQTT_freeMsgNode(&pMsgList);
    assert_int_equal(OK, status);
    assert_null(pMsgList);

    MOC_MALLOC((void **)&pMsgList, sizeof(MqttMessageList));
    assert_non_null(pMsgList);

    MOC_MALLOC((void **)&pMsgList->pMsg, sizeof(MqttMessage));
    assert_non_null(pMsgList->pMsg);

    MOC_MALLOC_MEMCPY((void **)&pMsgList->pMsg->pData, 8, "testData", 8);   
    pMsgList->pMsg->dataLen = 8;

    status = MQTT_freeMsgNode(&pMsgList);
    assert_int_equal(OK, status);
    assert_null(pMsgList);
}

static void mqtt_test_MQTT_freeMsgList(void **ppState)
{
    MqttMessageList *pMsgList = NULL;
    MSTATUS status;

    status = MQTT_freeMsgList(&pMsgList);
    assert_int_equal(OK, status);

    MOC_MALLOC((void **)&pMsgList, sizeof(MqttMessageList));
    assert_non_null(pMsgList);

    MOC_MALLOC((void **)&pMsgList->pMsg, sizeof(MqttMessage));
    assert_non_null(pMsgList->pMsg);

    MOC_MALLOC_MEMCPY((void **)&pMsgList->pMsg->pData, 8, "testData", 8);   
    pMsgList->pMsg->dataLen = 8;
    pMsgList->pNext = NULL;
  
    status = MQTT_freeMsgList(&pMsgList);
    assert_int_equal(OK, status);
}
#endif

static int testSetup(void **ppState)
{
    MSTATUS status;
    int ret = -1;

    status = MOCANA_initMocana();
    if (OK == status)
        ret = 0;

    return ret;
}

static int testTeardown(void **ppState)
{
    MSTATUS status;
    int ret = -1;

    status = MOCANA_freeMocana();
    if (OK == status)
        ret = 0;

    return ret;
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(mqtt_test_MQTT_buildConnectMsg),
        cmocka_unit_test(mqtt_test_MQTT_buildSubscribeMsg),
        cmocka_unit_test(mqtt_test_MQTT_buildUnsubscribeMsg),
        cmocka_unit_test(mqtt_test_MQTT_buildPublishMsg),
        cmocka_unit_test(mqtt_test_MQTT_buildPubRespMsg),
        cmocka_unit_test(mqtt_test_MQTT_buildPingReqMsg),
        cmocka_unit_test(mqtt_test_MQTT_buildAuthMsg),
        cmocka_unit_test(mqtt_test_MQTT_buildDisconnectMsg),
        cmocka_unit_test(mqtt_test_MQTT_freeMsg),
        cmocka_unit_test(mqtt_test_MQTT_parsePacket)
#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
        ,cmocka_unit_test(mqtt_test_MQTT_freeMsgNode),
        cmocka_unit_test(mqtt_test_MQTT_freeMsgList)
#endif
    };
    return cmocka_run_group_tests(tests, testSetup, testTeardown);
}