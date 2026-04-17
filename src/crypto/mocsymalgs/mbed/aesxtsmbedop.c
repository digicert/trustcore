/*
 * aesctrmbedop.c
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


#ifdef __ENABLE_DIGICERT_AES_XTS_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbedaesxts.h"

MOC_EXTERN MSTATUS SymOperatorAesXts(
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
                *((ubyte4 *) pOutputInfo) = MOC_LOCAL_TYPE_AES_XTS_OPERATOR;
                status = OK;
            }
            break;

        case MOC_SYM_OP_CREATE:
            status = MAesXtsMbedCreate(
                pMocSymCtx, (MAesUpdateData *) pInputInfo,
                MOC_LOCAL_TYPE_AES_XTS_OPERATOR, SymOperatorAesXts);
            break;

         case MOC_SYM_OP_UPDATE_OP_DATA:
            status = MAesXtsMbedUpdateInfo(
                pMocSymCtx, (MAesUpdateData *) pInputInfo);
            break;

        case MOC_SYM_OP_LOAD_KEY:
            status = MAesXtsMbedLoadKey(
                pMocSymCtx, (MSymOperatorData *) pInputInfo);
            break;

        case MOC_SYM_OP_ENCRYPT_INIT:
            status = MAesXtsMbedInit(
                pMocSymCtx, mbedtls_aes_xts_setkey_enc, MBEDTLS_AES_ENCRYPT);
            break;

        case MOC_SYM_OP_DECRYPT_INIT:
            status = MAesXtsMbedInit(
                pMocSymCtx, mbedtls_aes_xts_setkey_dec, MBEDTLS_AES_DECRYPT);
            break;

        case MOC_SYM_OP_ENCRYPT_UPDATE:
        case MOC_SYM_OP_ENCRYPT_FINAL:
        case MOC_SYM_OP_DECRYPT_UPDATE:
        case MOC_SYM_OP_DECRYPT_FINAL:
            status = MAesXtsMbedUpdate(
                pMocSymCtx, (MSymOperatorData *) pInputInfo, (MSymOperatorBuffer *) pOutputInfo);
            break;

        case MOC_SYM_OP_FREE:
            status = MAesXtsMbedFree(pMocSymCtx);
            break;
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_AES_XTS_MBED__ */
