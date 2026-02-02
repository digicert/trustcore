/*
 * mbedaesxts.h
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

#ifndef __MBED_AES_XTS_H__
#define __MBED_AES_XTS_H__

#ifdef __cplusplus
extern "C" {
#endif
    
typedef int (*MbedAesXtsSetKey)(
    mbedtls_aes_xts_context *pCtx,
    const unsigned char *pKey,
    unsigned int keyLenBits
    );

typedef struct
{
    mbedtls_aes_xts_context *pAesXtsCtx;
    ubyte pKey[64]; /* big enough for 2 256 bit keys */
    ubyte4 keyLen;
    ubyte pTweak[16];
    sbyte4 opFlag;
    
} MAesXtsMbedInfo;

MOC_EXTERN MSTATUS MAesXtsMbedCreate(
    MocSymCtx pSymCtx,
    MAesUpdateData *pInput,
    ubyte4 localType,
    MSymOperator pSymOp
    );

MOC_EXTERN MSTATUS MAesXtsMbedUpdateInfo(
    MocSymCtx pSymCtx,
    MAesUpdateData *pInput 
    );

MOC_EXTERN MSTATUS MAesXtsMbedLoadKey(
    MocSymCtx pSymCtx,
    MSymOperatorData *pKeyData
    );

MOC_EXTERN MSTATUS MAesXtsMbedInit(
    MocSymCtx pSymCtx,
    MbedAesXtsSetKey pSetKeyMethod,
    sbyte4 flag
    );

MOC_EXTERN MSTATUS MAesXtsMbedUpdate(
    MocSymCtx pSymCtx,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput
    );

MOC_EXTERN MSTATUS MAesXtsMbedFree(
    MocSymCtx pSymCtx
    );

#ifdef __cplusplus
}
#endif

#endif /* __MBED_AES_XTS_H__ */
