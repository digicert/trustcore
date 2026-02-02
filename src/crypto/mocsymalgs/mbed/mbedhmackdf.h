/*
 * mbedhmackdf.h
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
