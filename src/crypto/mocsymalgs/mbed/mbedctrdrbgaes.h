/*
 * mbedctrdrbgaes.h
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

#include "mbedtls/ctr_drbg.h"

#ifndef __DIGICERT_MBED_CTR_DRBG_AES_H__
#define __DIGICERT_MBED_CTR_DRBG_AES_H__

#ifdef __cplusplus
extern "C" {
#endif


MOC_EXTERN MSTATUS MCtrDrbgAesMbedSeed (
    MocSymCtx pSymCtx,
    MRandomSeedInfo *pSeedInfo
    );

MOC_EXTERN MSTATUS MCtrDrbgAesMbedReseed (
    MocSymCtx pSymCtx,
    MRandomReseedInfo *pReseedInfo
    );

MOC_EXTERN MSTATUS MCtrDrbgAesMbedGenerate (
    MocSymCtx pSymCtx,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput
    );

MOC_EXTERN MSTATUS MCtrDrbgAesMbedGetState (
    MocSymCtx pSymCtx,
    MSymOperatorData *pState
    );
    
MOC_EXTERN MSTATUS MCtrDrbgAesMbedSetState (
    MocSymCtx pSymCtx,
    MSymOperatorData *pState
    );
    
MOC_EXTERN MSTATUS MCtrDrbgAesMbedFree (
    MocSymCtx pSymCtx
    );

#ifdef __cplusplus
}
#endif

#endif /* __DIGICERT_MBED_CTR_DRBG_AES_H__ */
