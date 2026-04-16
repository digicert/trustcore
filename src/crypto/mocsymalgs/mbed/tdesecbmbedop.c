/*
 * tdesecbmbedop.c
 *
 * Symmetric algorithm definitions and declarations.
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

#ifdef __ENABLE_DIGICERT_TDES_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbeddescommon.h"

MOC_EXTERN MSTATUS SymOperatorTDesEcb (
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
                *((ubyte4 *) pOutputInfo) = MOC_LOCAL_TYPE_TDES_ECB_OPERATOR;
                status = OK;
            }
            break;

        case MOC_SYM_OP_CREATE:
            status = MDesMbedCreate(
                pMocSymCtx, pInputInfo, MOC_LOCAL_TYPE_TDES_ECB_OPERATOR, SymOperatorTDesEcb);
            break;

        case MOC_SYM_OP_GENERATE_KEY:
            status = MDesMbedGenerateKey(
                pMocSymCtx, (MSymKeyGenInfo *) pInputInfo,
                (MSymOperatorBuffer *) pOutputInfo);
            break;

        case MOC_SYM_OP_LOAD_KEY:
            status = MDesMbedLoadKey(
                pMocSymCtx, (MSymOperatorData *) pInputInfo);
            break;

        case MOC_SYM_OP_DECRYPT_INIT:
            status = MDesMbedInit(pMocSymCtx, mbedtls_des3_init_wrap, mbedtls_des3_set3key_dec_wrap);
            break;

        case MOC_SYM_OP_ENCRYPT_INIT:
            status = MDesMbedInit(pMocSymCtx, mbedtls_des3_init_wrap, mbedtls_des3_set3key_enc_wrap);
            break;

        case MOC_SYM_OP_DECRYPT_UPDATE:
        case MOC_SYM_OP_ENCRYPT_UPDATE:
            status = MDesMbedUpdate(
                pMocSymCtx, 0, (MSymOperatorData *) pInputInfo,
                (MSymOperatorBuffer *) pOutputInfo,
                mbedtls_des3_crypt_ecb_wrap);
            break;

        case MOC_SYM_OP_DECRYPT_FINAL:
        case MOC_SYM_OP_ENCRYPT_FINAL:
            status = MDesMbedFinal(
                pMocSymCtx, 0, (MSymOperatorData *) pInputInfo,
                (MSymOperatorBuffer *) pOutputInfo,
                mbedtls_des3_crypt_ecb_wrap);
            break;

        case MOC_SYM_OP_CLONE:
            status = MDesMbedClone(
                pMocSymCtx, (MocSymCtx) pOutputInfo);
            break;

        case MOC_SYM_OP_UPDATE_OP_DATA:
            status = MDesMbedUpdateOperatorData (
                pMocSymCtx, (MDesUpdateData *) pInputInfo);
            break;

        case MOC_SYM_OP_FREE:
            status = MDesMbedFree(pMocSymCtx, mbedtls_des3_free_wrap);
            break;
    }

exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_TDES_MBED__ */
