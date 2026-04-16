/*
 * mbedblowfish.h
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
