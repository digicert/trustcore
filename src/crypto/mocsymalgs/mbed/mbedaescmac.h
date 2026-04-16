/*
 * mbedaescmac.h
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
