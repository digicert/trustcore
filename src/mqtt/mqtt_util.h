/*
 * mqtt_util.h
 * 
 * Utility functions for MQTT
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

#ifndef __MQTT_UTILS_HEADER__
#define __MQTT_UTILS_HEADER__

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
MSTATUS MQTT_encodeVariableByteInt(
    ubyte4 val,
    ubyte pRes[4],
    ubyte *pBytesUsed);

/**
 * @dont_show
 * @internal
 */
MSTATUS MQTT_decodeVariableByteInt(
    ubyte *pBuf,
    ubyte4 bufLen,
    ubyte4 *pVal,
    ubyte *pNumBytesUsed);

/**
 * @dont_show
 * @internal
 */
byteBoolean isValidUtf8(
    ubyte *pData,
    ubyte4 dataLen);

#ifdef __cplusplus
}
#endif

#endif /* __MQTT_UTILS_HEADER__ */