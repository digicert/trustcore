/* 
 * mbedhmac.h
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

#include "mbedtls/md.h"
#include "mbedtls/md_internal.h"

#ifndef MBED_HMAC_COMMON_H
#define MBED_HMAC_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    mbedtls_md_context_t *pHmacCtx;
    ubyte *pKey;
    ubyte4 keyLen;
    mbedtls_md_type_t digestId;
} MbedHmacInfo;

MOC_EXTERN MSTATUS MHmacMbedCreate(
    MocSymCtx pSymCtx,
    ubyte *pDigestFlag
    );

MOC_EXTERN MSTATUS MHmacMbedLoadKey(
    MocSymCtx pSymCtx,
    MSymOperatorData *pKeyData
    );

MOC_EXTERN MSTATUS MHmacMbedInit(
    MocSymCtx pSymCtx
    );

MOC_EXTERN MSTATUS MHmacMbedUpdate(
    MocSymCtx pSymCtx,
    MSymOperatorData *pInput
    );

MOC_EXTERN MSTATUS MHmacMbedFinal(
    MocSymCtx pSymCtx,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput
    );

MOC_EXTERN MSTATUS MHmacMbedFree(
    MocSymCtx pSymCtx
    );

MOC_EXTERN MSTATUS MHmacMbedClone(
    MocSymCtx pCtx,
    MocSymCtx pCopyCtx
    );


#ifdef __cplusplus
}
#endif

#endif /* MBED_HMAC_COMMON_H */