/*
 * mbedaes.h
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

#include "mbedtls/aes.h"

#ifndef __MBED_AES_H__
#define __MBED_AES_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*MbedAesSetKey)(
    mbedtls_aes_context *pCtx,
    const unsigned char *pKey,
    unsigned int keyLenBits
    );

typedef struct
{
    mbedtls_aes_context *pAesCtx;
    ubyte pKey[32];
    ubyte4 keyLen;
    ubyte pIv[16];
    ubyte pWorkingIv[16];
    ubyte ivOffset;
    ubyte pStreamBlock[16];
    ubyte4 ivLen;
    ubyte opFlag;
} MAesMbedInfo;

typedef MSTATUS (*MAesCrypt)(
    MAesMbedInfo *pCtx,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput
    );

MOC_EXTERN MSTATUS MAesMbedCreate(
    MocSymCtx pSymCtx,
    MAesUpdateData *pInput,
    ubyte4 localType,
    MSymOperator pSymOp
    );

MOC_EXTERN MSTATUS MAesMbedUpdateInfo(
    MocSymCtx pSymCtx,
    MAesUpdateData *pInput
    );

MOC_EXTERN MSTATUS MAesMbedLoadKey(
    MocSymCtx pSymCtx,
    MSymOperatorData *pKeyData
    );

MOC_EXTERN MSTATUS MAesMbedInit(
    MocSymCtx pSymCtx,
    MbedAesSetKey pAesSetKey,
    ubyte4 flag
    );

MOC_EXTERN MSTATUS MAesMbedUpdate(
    MocSymCtx pSymCtx,
    ubyte opFlag,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput,
    MAesCrypt pAesCrypt
    );

MOC_EXTERN MSTATUS MAesMbedFree(
    MocSymCtx pSymCtx
    );

MOC_EXTERN MSTATUS MAesGetOpData(
    MAesMbedInfo *pCtx,
    MSymOperatorData *pOutput
    );

MOC_EXTERN MSTATUS MAesMbedClone(
    MocSymCtx pCtx,
    MocSymCtx pCopyCtx
    );

MOC_EXTERN MSTATUS MAesCbcMbedCrypt(
    MAesMbedInfo *pCtx,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput
    );

MOC_EXTERN MSTATUS MAesCfb128MbedCrypt(
    MAesMbedInfo *pCtx,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput
    );

MOC_EXTERN MSTATUS MAesOfbMbedCrypt(
    MAesMbedInfo *pCtx,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput
    );

MOC_EXTERN MSTATUS MAesCtrMbedCrypt(
    MAesMbedInfo *pCtx,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput
    );

MOC_EXTERN MSTATUS MAesCtrMbedGetCounterBlock(
    MAesMbedInfo *pCtx,
    MSymOperatorData *pOutput
    );

MOC_EXTERN MSTATUS MAesCtrMbedUpdateInfo(
    MocSymCtx pSymCtx,
    MAesCtrUpdateData *pInput
    );
#ifdef __cplusplus
}
#endif

#endif /* __MBED_AES_H__ */
