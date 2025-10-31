/*
 * mqtt_client_priv.h
 *
 * Internal definitions for client MQTT implementation
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

#ifndef __MQTT_CLIENT_PRIV_HEADER__
#define __MQTT_CLIENT_PRIV_HEADER__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../common/mrtos.h"
#include "../common/datetime.h"
#include "../common/debug_console.h"
#include "../common/utf8.h"
#include "../mqtt/mqtt_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

/*----------------------------------------------------------------------------*/

/* MQTT Internal Flags */
#define MQTT_INT_FLAG_SYNC_MODE          (0x00000001)
#define MQTT_INT_FLAG_ASYNC_MODE         (0x00000002)

#define MQTT_IS_SYNC(_pCtx)             (_pCtx->internalFlags & MQTT_INT_FLAG_SYNC_MODE)
#define MQTT_IS_ASYNC(_pCtx)            (_pCtx->internalFlags & MQTT_INT_FLAG_ASYNC_MODE)

#ifndef MQTT_SYNC_BUFFER_SIZE
#define MQTT_SYNC_BUFFER_SIZE    (2048)
#endif /* MQTT_SYNC_BUFFER_SIZE */

#if defined(__RTOS_WIN32__)
#define MQTT_DIR_SLASH     '\\'
#else
#define MQTT_DIR_SLASH     '/'
#endif

#define MAX_NUM_USER_PROPS 10

/*----------------------------------------------------------------------------*/

typedef enum
{
    CONNECT_DISABLED        = 0,
    CONNECT_CLOSED          = 1,
    CONNECT_NEGOTIATE       = 2,
    CONNECT_OPEN            = 3
} MqttConnectionState;

/*----------------------------------------------------------------------------*/

typedef struct MqttMessageList
{
    MqttMessage *pMsg;
    struct MqttMessageList *pNext;
} MqttMessageList;

typedef struct MqttPacketList
{
    ubyte2 packetId;
    struct MqttPacketList *pNext;
} MqttPacketList;

/*----------------------------------------------------------------------------*/

typedef struct MqttCtx MqttCtx;

/*----------------------------------------------------------------------------*/

typedef MSTATUS (*funcPtrPacketHandler)(sbyte4 connInst, MqttCtx *pCtx, ubyte **ppData, ubyte4 *pDataLen, byteBoolean *pIsDone);

/*----------------------------------------------------------------------------*/

#if defined(__ENABLE_MQTT_STREAMING__)

typedef enum
{
   MQTT_PUBLISH_TYPE_STATE,
   MQTT_PUBLISH_REM_LEN_STATE,
   MQTT_PUBLISH_TOPIC_LEN_STATE,
   MQTT_PUBLISH_TOPIC_STATE,
   MQTT_PUBLISH_PACKET_ID_STATE,
   MQTT_PUBLISH_PROPS_LEN_STATE,
   MQTT_PUBLISH_PROPS_STATE,
   MQTT_PUBLISH_PAYLOAD_STATE,
   MQTT_PUBLISH_DONE_STATE
} MqttPublishState;

typedef struct
{
    ubyte pRemLen[4];
    ubyte4 remLenCount;
    ubyte4 remLen;
    ubyte pTopicLen[2];
    ubyte4 topicLenCount;
    ubyte *pTopic;
    ubyte4 topicLen;
    ubyte pPktId[2];
    ubyte4 pktIdCount;
    ubyte pPropLen[4];
    ubyte4 propLenCount;
    ubyte *pProps;
    ubyte4 propsLen;
    ubyte4 processedPropsLen;
    ubyte *pUserPropsIters[MAX_NUM_USER_PROPS];
} MqttPublishData;

#endif /* __ENABLE_MQTT_STREAMING__ */

/*----------------------------------------------------------------------------*/

typedef struct MqttCtx
{
    MqttVersion version;
    ubyte *pClientId;
    ubyte2 clientIdLen;
    byteBoolean assignedClientId;
    MqttConnectionState connectionState;
    ubyte *pUsername;
    ubyte2 usernameLen;
    ubyte4 keepAliveMS;
    moctime_t lastMessageSent;
    TCP_SOCKET transportSocket;
    sbyte4 transportConnectionInstance;
    void *pTransportCtx;
    funcPtrMqttTransportSend transportSend;
    funcPtrMqttTransportRecv transportRecv;
    ubyte *pRecvBuffer;
    ubyte4 recvBufferSize;
    ubyte4 recvMsgSize;
    ubyte4 recvMsgOffset;
    MqttPacketHandlers handlers;
    ubyte *pSyncBuffer;
    ubyte4 syncBufferSize;
    void *pCookie;
    ubyte2 pktId;
    ubyte4 sessionExpiryInterval;
    ubyte4 maxPacketSize;
    ubyte4 topicAliasMax;
    ubyte4 internalFlags;
    ubyte4 connInst;
    void *pPacketIdList;
    RTOS_MUTEX pMutex;
    ubyte2 recvMax;
    ubyte2 sendQuota;
    ubyte2 clientSendQuota;
    sbyte2 pingCounter;
#if defined(__ENABLE_MQTT_ASYNC_CLIENT__)
    MqttMessageList *pMsgListHead;
    MqttMessageList *pMsgListTail;
    ubyte dataProcessed;
    ubyte4 numBytesToSend;
#endif
    ubyte persistMode;
    sbyte *pDir;
    ubyte outDirCreated;
    ubyte inDirCreated;
    sbyte *pFilename;
    ubyte4 filePrefixLen;
    ubyte4 publishTimeoutSeconds;
    ubyte4 pollingInterval;
#if defined(__ENABLE_MQTT_STREAMING__)
    byteBoolean streamingCurPkt;
    funcPtrPacketHandler pktHandler;
    MqttPublishState publishState;
    MqttPublishData publishData;
    MqttPublishInfo publishInfo;
#endif
    RTOS_MUTEX keepAliveMutex;
    RTOS_SEM keepAliveSem;
    RTOS_MUTEX keepAliveCondMutex;
    RTOS_THREAD keepAliveTID;
    byteBoolean keepAliveThreadActive;
    funcPtrReceiveTimeoutHandler pRecieveTimeoutHandler;
} MqttCtx;

MSTATUS MQTT_sendPubResp(
    sbyte4 connectionInstance,
    MqttPubRespOptions *pOptions);

/*----------------------------------------------------------------------------*/

#ifdef __cplusplus
}
#endif

#endif /* __MQTT_CLIENT_PRIV_HEADER__ */