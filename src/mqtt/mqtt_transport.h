/*
 * mqtt_transport.h
 * 
 * APIs for client MQTT transport implementation
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