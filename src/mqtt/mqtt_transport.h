/*
 * mqtt_transport.h
 * 
 * APIs for client MQTT transport implementation
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

#ifndef __MQTT_TRANSPORT_HEADER__
#define __MQTT_TRANSPORT_HEADER__

#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/merrors.h"
#include "../common/mstdlib.h"
#include "../mqtt/mqtt_defs.h"
#include "../mqtt/mqtt_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS MQTT_setTransportTCPInternal(
    MqttCtx *pCtx,
    TCP_SOCKET socket);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS MQTT_setTransportSSLInternal(
    MqttCtx *pCtx,
    sbyte4 sslConnInst);

/**
 * @dont_show
 * @internal
 */
MOC_EXTERN MSTATUS MQTT_setTransportInternal(
    MqttCtx *pCtx,
    void *pTransportCtx,
    funcPtrMqttTransportSend send,
    funcPtrMqttTransportRecv recv);

#ifdef __cplusplus
}
#endif

#endif /* __MQTT_TRANSPORT_HEADER__ */