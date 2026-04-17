/*
 * blowfishmbedop.c
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


#ifdef __ENABLE_DIGICERT_BLOWFISH_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbedblowfish.h"

MOC_EXTERN MSTATUS SymOperatorBlowfish(
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
                *((ubyte4 *) pOutputInfo) = MOC_LOCAL_TYPE_BLOWFISH_CBC_OPERATOR;
                status = OK;
            }
            break;

        case MOC_SYM_OP_CREATE:
            status = MBlowfishMbedCreate(
                pMocSymCtx, (MBlowfishUpdateData *) pInputInfo);
            break;

        case MOC_SYM_OP_UPDATE_OP_DATA:
            status = MBlowfishMbedUpdateInfo(
                pMocSymCtx, (MBlowfishUpdateData *) pInputInfo);
            break;

        case MOC_SYM_OP_LOAD_KEY:
            status = MBlowfishMbedLoadKey(
                pMocSymCtx, (MSymOperatorData *) pInputInfo);
            break;

        case MOC_SYM_OP_ENCRYPT_INIT:
        case MOC_SYM_OP_DECRYPT_INIT:
            status = OK; /* nothing to do */
            break;

        case MOC_SYM_OP_ENCRYPT_UPDATE:
        case MOC_SYM_OP_ENCRYPT_FINAL:
            status = MBlowfishMbedUpdate(pMocSymCtx, MBEDTLS_BLOWFISH_ENCRYPT, (MSymOperatorData *) pInputInfo, (MSymOperatorBuffer *) pOutputInfo);
            break;
            
        case MOC_SYM_OP_DECRYPT_UPDATE:
        case MOC_SYM_OP_DECRYPT_FINAL:
            status = MBlowfishMbedUpdate(
                pMocSymCtx, MBEDTLS_BLOWFISH_DECRYPT, (MSymOperatorData *) pInputInfo, (MSymOperatorBuffer *) pOutputInfo);
            break;
        case MOC_SYM_OP_GET_OP_DATA:

            /* pMocSymCtx will be dereferenced, other params validated later */
            status = ERR_NULL_POINTER;
            if (NULL == pMocSymCtx)
                break;
            status = MBlowfishGetOpData(pMocSymCtx->pLocalData, (MSymOperatorData*) pOutputInfo);

            break;

        case MOC_SYM_OP_CLONE:
            status = MBlowfishMbedClone(
                pMocSymCtx, (MocSymCtx) pOutputInfo);
            break;

        case MOC_SYM_OP_FREE:
            status = MBlowfishMbedFree(pMocSymCtx);
            break;
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_BLOWFISH_MBED__ */
