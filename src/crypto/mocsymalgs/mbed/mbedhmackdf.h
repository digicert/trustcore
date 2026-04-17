/*
 * mbedhmackdf.h
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

#include "mbedtls/hkdf.h"

#ifndef __MBED_HMAC_KDF_H__
#define __MBED_HMAC_KDF_H__

#ifdef __cplusplus
extern "C" {
#endif
    
MOC_EXTERN MSTATUS MHmacKdfMbedCreate(
    MocSymCtx pSymCtx,
    ubyte *pDigestFlag
    );
    
MOC_EXTERN MSTATUS MHmacKdfMbedDeriveKey(
    MocSymCtx pSymCtx,
    MHmacKdfOperatorData *pOpData,
    MSymOperatorBuffer *pOutput
    );
    
MOC_EXTERN MSTATUS MHmacKdfMbedFree(
    MocSymCtx pSymCtx
    );
    
#ifdef __cplusplus
}
#endif

#endif /* __MBED_HMAC_KDF_H__ */
