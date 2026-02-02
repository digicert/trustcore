/*
 * mbedaesecb.c
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

#ifndef MBED_AES_ECB_H
#define MBED_AES_ECB_H

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*MbedAesEcbSetKey)(
    mbedtls_aes_context *pCtx,
    const unsigned char *pKey,
    unsigned int keyLenBits
    );

typedef struct
{
    mbedtls_aes_context *pAesCtx;
    ubyte pKey[32];
    ubyte4 keyLen;
    ubyte opFlag;
} MAesEcbMbedInfo;

MOC_EXTERN MSTATUS MAesEcbMbedCreate(
    MocSymCtx pSymCtx
    );

MOC_EXTERN MSTATUS MAesEcbMbedLoadKey(
    MocSymCtx pSymCtx,
    MSymOperatorData *pKeyData
    );

MOC_EXTERN MSTATUS MAesEcbMbedInit(
    MocSymCtx pSymCtx,
    MbedAesEcbSetKey pAesEcbSetKey
    );

MOC_EXTERN MSTATUS MAesEcbMbedUpdate(
    MocSymCtx pSymCtx,
    ubyte opFlag,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput
    );

MOC_EXTERN MSTATUS MAesEcbMbedFree(
    MocSymCtx pSymCtx
    );

MOC_EXTERN MSTATUS MAesEcbMbedClone(
    MocSymCtx pCtx,
    MocSymCtx pCopyCtx
    );

#ifdef __cplusplus
}
#endif

#endif /* MBED_AES_ECB_H */
