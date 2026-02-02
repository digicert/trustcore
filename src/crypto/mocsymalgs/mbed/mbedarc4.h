/*
 * mbedarc4.h
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

#ifndef __MBED_ARC4_H__
#define __MBED_ARC4_H__

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS MArc4MbedCreate(
    MocSymCtx pSymCtx
    );

MOC_EXTERN MSTATUS MArc4MbedLoadKey(
    MocSymCtx pSymCtx,
    MSymOperatorData *pKeyData
    );

MOC_EXTERN MSTATUS MArc4MbedUpdate(
    MocSymCtx pSymCtx,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput
    );

MOC_EXTERN MSTATUS MArc4MbedFree(
    MocSymCtx pSymCtx
    );

MOC_EXTERN MSTATUS MArc4MbedClone(
    MocSymCtx pCtx,
    MocSymCtx pCopyCtx
    );

#ifdef __cplusplus
}
#endif

#endif /* __MBED_ARC4_H__ */
