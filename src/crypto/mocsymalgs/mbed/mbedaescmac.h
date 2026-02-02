/*
 * mbedaescmac.h
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

#include "mbedtls/cipher.h"
#include "mbedtls/cmac.h"

#ifndef __MBED_AES_CMAC_H__
#define __MBED_AES_CMAC_H__

#ifdef __cplusplus
extern "C" {
#endif
    
typedef struct
{
    mbedtls_cipher_context_t *pCmacCtx;
    ubyte *pKey;
    ubyte4 keyLen;
    
} MbedAesCmacInfo;

MOC_EXTERN MSTATUS MAesCmacMbedCreate(
    MocSymCtx pSymCtx
    );

MOC_EXTERN MSTATUS MAesCmacMbedLoadKey(
    MocSymCtx pSymCtx,
    MSymOperatorData *pKeyData
    );

MOC_EXTERN MSTATUS MAesCmacMbedInit(
    MocSymCtx pSymCtx
    );
    
MOC_EXTERN MSTATUS MAesCmacMbedUpdate(
    MocSymCtx pSymCtx,
    MSymOperatorData *pInput
    );
    
MOC_EXTERN MSTATUS MAesCmacMbedFinal(
    MocSymCtx pSymCtx,
    MSymOperatorBuffer *pOutput
    );

MOC_EXTERN MSTATUS MAesCmacMbedFree(
    MocSymCtx pSymCtx
    );

MOC_EXTERN MSTATUS MAesCmacMbedClone(
    MocSymCtx pSymCtx,
    MocSymCtx pCopyCtx
    );
    
#ifdef __cplusplus
}
#endif

#endif /* __MBED_AES_CMAC_H__ */
