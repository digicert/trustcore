/*
 * mbedctrdrbgaes.h
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
