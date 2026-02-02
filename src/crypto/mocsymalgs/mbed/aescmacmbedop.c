/*
 * aescmacmbedop.c
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
