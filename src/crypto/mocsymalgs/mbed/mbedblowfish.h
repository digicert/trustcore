/*
 * mbedblowfish.h
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

#include "mbedtls/blowfish.h"

#ifndef __MBED_BLOWFISH_H__
#define __MBED_BLOWFISH_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    mbedtls_blowfish_context *pBfCtx;
    ubyte pIv[MBEDTLS_BLOWFISH_BLOCKSIZE];
    byteBoolean hasIv;
    
} MBlowfishMbedInfo;


MOC_EXTERN MSTATUS MBlowfishMbedCreate(
    MocSymCtx pSymCtx,
    MBlowfishUpdateData *pInput
    );

MOC_EXTERN MSTATUS MBlowfishMbedUpdateInfo(
    MocSymCtx pSymCtx,
    MBlowfishUpdateData *pInput
    );

MOC_EXTERN MSTATUS MBlowfishMbedLoadKey(
    MocSymCtx pSymCtx,
    MSymOperatorData *pKeyData
    );

MOC_EXTERN MSTATUS MBlowfishMbedUpdate(
    MocSymCtx pSymCtx,
    ubyte4 opFlag,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput
    );

MOC_EXTERN MSTATUS MBlowfishGetOpData(
    MBlowfishMbedInfo *pCtx,
    MSymOperatorData *pOutput
    );

MOC_EXTERN MSTATUS MBlowfishMbedClone(
    MocSymCtx pCtx,
    MocSymCtx pCopyCtx
    );

MOC_EXTERN MSTATUS MBlowfishMbedFree(
    MocSymCtx pSymCtx
    );

#ifdef __cplusplus  
}
#endif

#endif /* __MBED_BLOWFISH_H__ */
