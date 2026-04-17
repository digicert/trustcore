/*
 * hmackdfmbedop.c
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

#include "../../../crypto/mocsym.h"


#ifdef __ENABLE_DIGICERT_HMAC_KDF_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbedhmackdf.h"

MOC_EXTERN MSTATUS SymOperatorHmacKdf(
    MocSymCtx pMocSymCtx,
    MocCtx pMocCtx,
    symOperation symOp,
    void *pInputInfo,
    void *pOutputInfo
    )
{
    MSTATUS status;

    switch (symOp)
    {
        default:
            status = ERR_NOT_IMPLEMENTED;
            break;

        case MOC_SYM_OP_GET_LOCAL_TYPE:
            status = ERR_NULL_POINTER;
            if (NULL != pOutputInfo)
            {
                *((ubyte4 *) pOutputInfo) = MOC_LOCAL_TYPE_HMAC_KDF_OPERATOR;
                status = OK;
            }
            break;

        case MOC_SYM_OP_CREATE:
            status = MHmacKdfMbedCreate(
                pMocSymCtx, (ubyte *) pInputInfo);
            break;

        case MOC_SYM_OP_DERIVE_KEY:
            status = MHmacKdfMbedDeriveKey(
                pMocSymCtx, (MHmacKdfOperatorData *) pInputInfo, (MSymOperatorBuffer *) pOutputInfo);
            break;

        case MOC_SYM_OP_FREE:
            status = MHmacKdfMbedFree(pMocSymCtx);
            break;
    }

    return status;
}
#endif
