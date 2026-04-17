/*
 * mqtt_core.h
 *
 * Internal APIs for managing data in global structures
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
 *
 */

#ifndef __MQTT_CORE_HEADER__
#define __MQTT_CORE_HEADER__

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
MOC_EXTERN MSTATUS MQTT_initCore(
    sbyte4 mqttMaxClientConnections);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS MQTT_uninitCore(void);

/**
 * @dont_show
 * @internal
 */
MSTATUS MQTT_closeConnectionInternal(sbyte4 connectionInstance);

/**
 * @dont_show
 * @internal
 */
MSTATUS MQTT_getCtxFromConnInst(sbyte4 connectionInstance, MqttCtx **ppCtx);

/**
 * @dont_show
 * @internal
 */
MSTATUS MQTT_createConnectInstanceFromId(
    MqttVersion version,
    ubyte *pClientId,
    ubyte2 clientIdLen,
    sbyte4 *pConnectInstance,
    ubyte4 internalFlags);

/**
 * @dont_show
 * @internal
 */
MSTATUS MQTT_releaseClientCtx(MqttCtx **ppClientCtx);

/**
 * @dont_show
 * @internal
 */
byteBoolean MQTT_hasUnackedPackets(MqttCtx *pCtx);

/**
 * @dont_show
 * @internal
 */
MSTATUS MQTT_resendUnackedPackets(MqttCtx *pCtx);

/**
 * @dont_show
 * @internal
 */
MSTATUS MQTT_markInboundPubrel(MqttCtx *pCtx, ubyte2 packetId);

/**
 * @dont_show
 * @internal
 */
MSTATUS MQTT_checkPublishDeliveryAllowed(MqttCtx *pCtx, ubyte2 packetId, byteBoolean *pAllowed);

/**
 * @dont_show
 * @internal
 */
MSTATUS MQTT_markAcked(MqttCtx *pCtx, ubyte2 packetId);

/**
 * @dont_show
 * @internal
 */
MSTATUS MQTT_storePubRelMsg(MqttCtx *pCtx, MqttMessage *pMsg, ubyte2 packetId);

/**
 * @dont_show
 * @internal
 */
MSTATUS MQTT_storePublishMsg(MqttCtx *pCtx, MqttMessage *pMsg, ubyte2 packetId);

/**
 * @dont_show
 * @internal
 */
MSTATUS MQTT_removePacketIdFromList(MqttCtx *pCtx, ubyte2 packetId);

/**
 * @dont_show
 * @internal
 */
MSTATUS MQTT_addPacketIdToList(MqttCtx *pCtx, ubyte2 packetId);

/**
 * @dont_show
 * @internal
 */
byteBoolean MQTT_packetIdExists(MqttCtx *pCtx, ubyte2 packetId);

/**
 * @dont_show
 * @internal
 */
MSTATUS MQTT_addPacketId(MqttCtx *pCtx, MqttMessage *pMsg, ubyte2 packetId);

/**
 * @dont_show
 * @internal
 */
MSTATUS MQTT_checkAndMarkAcked(MqttCtx *pCtx, ubyte2 packetId, intBoolean *found);

/**
 * @dont_show
 * @internal
 */
void MQTT_freePacketIdList(MqttCtx *pCtx);

/**
 * @dont_show
 * @internal
 */
MSTATUS MQTT_timeoutStoredPublishes(MqttCtx *pCtx);


#ifdef __cplusplus
}
#endif

#endif /* __MQTT_CORE_HEADER__ */