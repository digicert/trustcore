/*
 * mbedarc4.h
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
