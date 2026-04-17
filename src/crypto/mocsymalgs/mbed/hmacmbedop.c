/*
 * hmacmbedop.c
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


#ifdef __ENABLE_DIGICERT_HMAC_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbedhmac.h"

MOC_EXTERN MSTATUS SymOperatorHmac(
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
                *((ubyte4 *) pOutputInfo) = MOC_LOCAL_TYPE_HMAC_OPERATOR;
                status = OK;
            }
            break;

        case MOC_SYM_OP_CREATE:
            status = MHmacMbedCreate(
                pMocSymCtx, (ubyte *) pInputInfo);
            break;

        case MOC_SYM_OP_LOAD_KEY:
            status = MHmacMbedLoadKey(
                pMocSymCtx, (MSymOperatorData *) pInputInfo);
            break;

        case MOC_SYM_OP_MAC_INIT:
            status = MHmacMbedInit(pMocSymCtx);
            break;

        case MOC_SYM_OP_MAC_UPDATE:
            status = MHmacMbedUpdate(
                pMocSymCtx, (MSymOperatorData *) pInputInfo);
            break;

        case MOC_SYM_OP_MAC_FINAL:
            status = MHmacMbedFinal(
                pMocSymCtx, (MSymOperatorData *) pInputInfo,
                (MSymOperatorBuffer *) pOutputInfo);
            break;

        case MOC_SYM_OP_CLONE:
            status = MHmacMbedClone(
                pMocSymCtx, (MocSymCtx) pOutputInfo);
            break;

        case MOC_SYM_OP_FREE:
            status = MHmacMbedFree(pMocSymCtx);
            break;
    }

    return status;
}
#endif
