/*
 * dhkeymbed.c
 *
 * Operator for mbed software version of DH MocAsym Key.
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

#include "../../../crypto/mocasym.h"


#ifdef __ENABLE_DIGICERT_DH_MBED__

#include "../../../crypto/mocasymkeys/mbed/mbedcommondh.h"

MOC_EXTERN MSTATUS KeyOperatorDh(
    MocAsymKey pMocAsymKey,
    MocCtx pMocCtx,
    keyOperation keyOp,
    void *pInputInfo,
    void *pOutputInfo,
    struct vlong **ppVlongQueue
    )
{
    MSTATUS status;

    switch (keyOp)
    {
        default:
            status = ERR_NOT_IMPLEMENTED;
            goto exit;

        case MOC_ASYM_OP_GET_LOCAL_TYPE:
            status = ERR_NULL_POINTER;
            if (NULL != pOutputInfo)
            {
                *((ubyte4 *) pOutputInfo) = MOC_LOCAL_KEY_DH_PUB_OPERATOR;
                status = OK;
            }
            break;

        case MOC_ASYM_OP_CREATE:
        case MOC_ASYM_OP_CREATE_PUB:
            pMocAsymKey->KeyOperator = KeyOperatorDh;
            pMocAsymKey->localType = MOC_LOCAL_KEY_DH_PUB_OPERATOR;
            status = OK;
            break;

        case MOC_ASYM_OP_CREATE_PRI:
            pMocAsymKey->KeyOperator = KeyOperatorDh;
            pMocAsymKey->localType = MOC_LOCAL_KEY_DH_PRI_OPERATOR;
            status = OK;
            break;

        case MOC_ASYM_OP_GENERATE:
            status = DhMbedGenerateKeyPair(
                pMocCtx, (MKeyPairGenInfo *) pInputInfo,
                (MKeyPairGenResult *) pOutputInfo);
            break;

        case MOC_ASYM_OP_PUB_FROM_PRI:
            status = DhMbedGetPubFromPri(
                pMocAsymKey, (MocAsymKey *) pOutputInfo);
            break;

        case MOC_ASYM_OP_CLONE:
            status = DhMbedCloneKey(
                pMocAsymKey, (MocAsymKey *) pOutputInfo);
            break;

        case MOC_ASYM_OP_SET_KEY_DATA:
            status = DhMbedSetKeyData(
                pMocAsymKey, (MDhKeyTemplate *) pInputInfo);
            break;

        case MOC_ASYM_OP_GET_KEY_DATA:
            status = DhMbedGetKeyDataAlloc(
                pMocAsymKey, (MDhKeyTemplate *) pOutputInfo, (ubyte *)pInputInfo);
            break;
            
        case MOC_ASYM_OP_GET_PUB_VALUE:
            status = DhMbedReturnPubValAlloc(pMocAsymKey, (MKeyOperatorDataReturn *) pOutputInfo);
            break;
            
        case MOC_ASYM_OP_COMPUTE_SHARED_SECRET:
            status = DhMbedComputeSharedSecret (pMocAsymKey, (MKeyOperatorData *)pInputInfo,
                                                 (MKeyOperatorBuffer *)pOutputInfo);
            break;
            
        case MOC_ASYM_OP_FREE:
            status = DhMbedFreeKey(pMocAsymKey);
            break;
    }

exit:

    return status;
}
#endif
