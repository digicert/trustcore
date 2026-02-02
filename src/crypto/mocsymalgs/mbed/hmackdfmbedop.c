/*
 * hmackdfmbedop.c
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
