/*
 * mqtt_util.h
 * 
 * Utility functions for MQTT
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