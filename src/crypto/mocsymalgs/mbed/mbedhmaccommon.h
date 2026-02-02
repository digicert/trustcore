/*
 * mbedhmaccommon.h
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * *For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "mbedtls/md.h"

#ifndef __MBED_HMAC_COMMON_H__
#define __MBED_HMAC_COMMON_H__

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS ConvertMocDigestIdToMbedDigestId(
    ubyte mocDigestId,
    mbedtls_md_type_t *pRetMbedDigestId
    );

#ifdef __cplusplus
}
#endif

#endif /* __MBED_HMAC_COMMON_H__ */
