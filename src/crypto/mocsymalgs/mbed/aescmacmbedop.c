/*
 * aescmacmbedop.c
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


#ifdef __ENABLE_DIGICERT_AES_CMAC_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbedaescmac.h"

MOC_EXTERN MSTATUS SymOperatorAesCmac(
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
                *((ubyte4 *) pOutputInfo) = MOC_LOCAL_TYPE_AES_CMAC_OPERATOR;
                status = OK;
            }
            break;
            
        case MOC_SYM_OP_CREATE:
            status = MAesCmacMbedCreate(pMocSymCtx);
            break;
            
        case MOC_SYM_OP_LOAD_KEY:
            status = MAesCmacMbedLoadKey(pMocSymCtx, (MSymOperatorData *) pInputInfo);
            break;
            
        case MOC_SYM_OP_MAC_INIT:
            status = MAesCmacMbedInit(pMocSymCtx);
            break;
            
        case MOC_SYM_OP_MAC_UPDATE:
            status = MAesCmacMbedUpdate(pMocSymCtx, (MSymOperatorData *) pInputInfo);
            break;
            
        case MOC_SYM_OP_MAC_FINAL:
            status = MAesCmacMbedFinal(pMocSymCtx, (MSymOperatorBuffer *) pOutputInfo);
            break;
        
        case MOC_SYM_OP_CLONE:
            status = MAesCmacMbedClone(
                pMocSymCtx, (MocSymCtx) pOutputInfo);
            break;
            
        case MOC_SYM_OP_FREE:
            status = MAesCmacMbedFree(pMocSymCtx);
            break;
    }
    
    return status;
}
#endif /* __ENABLE_DIGICERT_AES_CMAC_MBED__ */
