/*
 * ctrdrbgaesbedop.c
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


#ifdef __ENABLE_DIGICERT_CTR_DRBG_AES_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbedctrdrbgaes.h"

MOC_EXTERN MSTATUS SymOperatorCtrDrbgAes(
    MocSymCtx pMocSymCtx,
    MocCtx pMocCtx,
    symOperation symOp,
    void *pInputInfo,
    void *pOutputInfo
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pMocSymCtx)
        goto exit;

    switch (symOp)
    {
        default:
            status = ERR_NOT_IMPLEMENTED;
            break;

        case MOC_SYM_OP_GET_LOCAL_TYPE:
            status = ERR_NULL_POINTER;
            if (NULL != pOutputInfo)
            {
                *((ubyte4 *) pOutputInfo) = MOC_LOCAL_TYPE_CTR_DRBG_AES_OPERATOR;
                status = OK;
            }
            break;

        case MOC_SYM_OP_RAND_GET_SEED_TYPE:
            status = ERR_NULL_POINTER;
            if (NULL != pOutputInfo)
            {
                *((ubyte4 *)(pOutputInfo)) = MOC_SYM_RAND_SEED_TYPE_CALLBACK;
                status = OK;
            }
            break;

        case MOC_SYM_OP_CREATE:
            pMocSymCtx->localType = MOC_LOCAL_TYPE_CTR_DRBG_AES_OPERATOR;
            pMocSymCtx->SymOperator = SymOperatorCtrDrbgAes;
            status = OK;
            break;

        case MOC_SYM_OP_GET_OP_DATA:
            status = MCtrDrbgAesMbedGetState (
                pMocSymCtx, (MSymOperatorData *) pOutputInfo);
            break;
            
        case MOC_SYM_OP_UPDATE_OP_DATA:
            status = MCtrDrbgAesMbedSetState (
                pMocSymCtx, (MSymOperatorData *) pInputInfo);
            break;
            
        case MOC_SYM_OP_SEED_RANDOM:
            status = MCtrDrbgAesMbedSeed (
                pMocSymCtx, (MRandomSeedInfo *)pInputInfo);
            break;

        case MOC_SYM_OP_RESEED_RANDOM:
            status = MCtrDrbgAesMbedReseed (
                pMocSymCtx, (MRandomReseedInfo *)pInputInfo);
            break;

        case MOC_SYM_OP_GENERATE_RANDOM:
            status = MCtrDrbgAesMbedGenerate(
              pMocSymCtx, (MSymOperatorData *)pInputInfo,
              (MSymOperatorBuffer *)pOutputInfo);
            break;

        case MOC_SYM_OP_FREE:
            status = MCtrDrbgAesMbedFree(pMocSymCtx);
            break;
    }

exit:
    return status;
}
#endif /* __ENABLE_DIGICERT_CTR_DRBG_AES_MBED__ */
