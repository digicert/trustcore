/*
 * mbedaesgcm.h
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
#include "mbedtls/gcm.h"
#include "mbedtls/cipher_internal.h"

#ifndef MBED_AES_GCM_H
#define MBED_AES_GCM_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    mbedtls_gcm_context *pGcmCtx;
    ubyte pKey[32];
    ubyte4 keyLen;
    ubyte *pNonce;
    ubyte4 nonceLen;
    ubyte *pAad;
    ubyte4 aadLen;
    ubyte4 tagLen;
    ubyte pLeftovers[16];
    ubyte4 leftoverLen;
    ubyte4 cryptFlag;
} MAesGcmMbedInfo;

MOC_EXTERN MSTATUS MAesGcmMbedCreate(
    MocSymCtx pSymCtx,
    MAesGcmUpdateData *pGcmData
    );

MOC_EXTERN MSTATUS MAesGcmMbedUpdateInfo(
    MocSymCtx pSymCtx,
    MAesGcmUpdateData *pGcmData
    );

MOC_EXTERN MSTATUS MAesGcmMbedFree(
    MocSymCtx pSymCtx
    );

MOC_EXTERN MSTATUS MAesGcmMbedGenKey (
    MocSymCtx pCtx,
    MSymKeyGenInfo *pGenInfo,
    MSymOperatorBuffer *pOutput
    );

MOC_EXTERN MSTATUS MAesGcmMbedLoadKey (
    MocSymCtx pCtx,
    MSymOperatorData *pKeyData
    );

MOC_EXTERN MSTATUS MAesGcmMbedInit (
    MocSymCtx pCtx,
    ubyte4 cipherFlag
    );

MOC_EXTERN MSTATUS MAesGcmMbedUpdate (
    MocSymCtx pCtx,
    MSymOperatorData *pInputInfo,
    MSymOperatorBuffer *pOutputInfo
    );

MOC_EXTERN MSTATUS MAesGcmMbedFinal (
    MocSymCtx pCtx,
    MSymOperatorData *pInputInfo,
    MSymOperatorBuffer *pOutputInfo
    );

MOC_EXTERN MSTATUS MAesGcmMbedClone(
    MocSymCtx pCtx,
    MocSymCtx pCopyCtx
    );

#ifdef __cplusplus
}
#endif

#endif /* MBED_AES_GCM_H */
