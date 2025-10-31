/*
 * mqtt_msg.h
 * 
 * Internal APIs for client MQTT message handling
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

#ifndef __MQTT_MESSAGE_HEADER__
#define __MQTT_MESSAGE_HEADER__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../mqtt/mqtt_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS MQTT_parsePacket(
    sbyte4 connInst,
    MqttCtx *pCtx,
    ubyte *pBuffer,
    ubyte4 bufferLen);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS MQTT_buildConnectMsg(
    MqttCtx *pCtx,
    MqttConnectOptions *pOptions,
    MqttMessage **ppMsg);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS MQTT_buildSubscribeMsg(
    MqttCtx *pCtx,
    MqttSubscribeTopic *pTopics,
    ubyte4 topicCount,
    MqttSubscribeOptions *pOptions,
    ubyte2 *pPacketId,
    MqttMessage **ppMsg);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS MQTT_buildUnsubscribeMsg(
    MqttCtx *pCtx,
    MqttUnsubscribeTopic *pTopics,
    ubyte4 topicCount,
    MqttUnsubscribeOptions *pOptions,
    ubyte2 *pPacketId,
    MqttMessage **ppMsg);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS MQTT_buildPublishMsg(
    MqttCtx *pCtx,
    MqttPublishOptions *pOptions,
    ubyte *pTopic,
    ubyte4 topicLen,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte2 *pPacketId,
    MqttMessage **ppMsg);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS MQTT_buildPubRespMsg(
    MqttCtx *pCtx, 
    MqttPubRespOptions *pOptions, 
    MqttMessage **ppMsg);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS MQTT_buildPingReqMsg(
    MqttCtx *pCtx,
    MqttMessage **ppMsg);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS MQTT_buildAuthMsg(
    MqttCtx *pCtx,
    MqttAuthOptions *pOptions,
    MqttMessage **ppMsg);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS MQTT_buildDisconnectMsg(
    MqttCtx *pCtx,
    MqttDisconnectOptions *pOptions,
    MqttMessage **ppMsg);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS MQTT_freeMsg(
    MqttMessage **ppMsg);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS MQTT_processPacket(
    sbyte4 connInst,
    MqttCtx *pCtx,
    MqttMessage **ppMsg,
    byteBoolean acquireMutex);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS MQTT_freeMsgNode(
    MqttMessageList **ppMsgList);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS MQTT_freeMsgList(
    MqttMessageList **ppMsgList);

#ifdef __cplusplus
}
#endif

#endif /* __MQTT_MESSAGE_HEADER__ */
