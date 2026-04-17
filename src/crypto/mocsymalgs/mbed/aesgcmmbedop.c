/*
 * aesgcmmbedop.c
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


#ifdef __ENABLE_DIGICERT_AES_GCM_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbedaesgcm.h"

MOC_EXTERN MSTATUS SymOperatorAesGcm(
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
            goto exit;

        case MOC_SYM_OP_GET_LOCAL_TYPE:
            status = ERR_NULL_POINTER;
            if (NULL != pOutputInfo)
            {
                *((ubyte4 *) pOutputInfo) = MOC_LOCAL_TYPE_AES_GCM_OPERATOR;
                status = OK;
            }
            break;

        case MOC_SYM_OP_CREATE:
            status = MAesGcmMbedCreate(
                pMocSymCtx, (MAesGcmUpdateData *) pInputInfo);
            break;

        case MOC_SYM_OP_UPDATE_OP_DATA:
            status = MAesGcmMbedUpdateInfo(
                pMocSymCtx, (MAesGcmUpdateData *) pInputInfo);
            break;

        case MOC_SYM_OP_FREE:
            status = MAesGcmMbedFree(pMocSymCtx);
            break;

        case MOC_SYM_OP_GENERATE_KEY:
            status = MAesGcmMbedGenKey(
                pMocSymCtx, (MSymKeyGenInfo *) pInputInfo,
                (MSymOperatorBuffer *) pOutputInfo);
            break;

        case MOC_SYM_OP_LOAD_KEY:
            status = MAesGcmMbedLoadKey(
                pMocSymCtx, (MSymOperatorData *) pInputInfo);
            break;

        case MOC_SYM_OP_CLONE:
            status = MAesGcmMbedClone(
                pMocSymCtx, (MocSymCtx) pOutputInfo);
            break;

        case MOC_SYM_OP_DECRYPT_INIT:
            status = MAesGcmMbedInit(pMocSymCtx, MBEDTLS_GCM_DECRYPT);
            break;

        case MOC_SYM_OP_ENCRYPT_INIT:
            status = MAesGcmMbedInit(pMocSymCtx, MBEDTLS_GCM_ENCRYPT);
            break;

        case MOC_SYM_OP_ENCRYPT_UPDATE:
        case MOC_SYM_OP_DECRYPT_UPDATE:
            status = MAesGcmMbedUpdate(
                pMocSymCtx, (MSymOperatorData *) pInputInfo,
                (MSymOperatorBuffer *) pOutputInfo);
            break;

        case MOC_SYM_OP_ENCRYPT_FINAL:
        case MOC_SYM_OP_DECRYPT_FINAL:
            status = MAesGcmMbedFinal(
                pMocSymCtx, (MSymOperatorData *) pInputInfo,
                (MSymOperatorBuffer *) pOutputInfo);
            break;
    }

exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_AES_GCM_MBED__ */
