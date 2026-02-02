/*
 * desecbmbedop.c
 *
 * Symmetric algorithm definitions and declarations.
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


#ifdef __ENABLE_DIGICERT_DES_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbeddescommon.h"

MOC_EXTERN MSTATUS SymOperatorDesEcb (
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
                *((ubyte4 *) pOutputInfo) = MOC_LOCAL_TYPE_DES_ECB_OPERATOR;
                status = OK;
            }
            break;

        case MOC_SYM_OP_CREATE:
            status = MDesMbedCreate(
                pMocSymCtx, pInputInfo, MOC_LOCAL_TYPE_DES_ECB_OPERATOR, SymOperatorDesEcb);
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
            status = MDesMbedInit(pMocSymCtx, mbedtls_des_init_wrap, mbedtls_des_setkey_dec_wrap);
            break;

        case MOC_SYM_OP_ENCRYPT_INIT:
            status = MDesMbedInit(pMocSymCtx, mbedtls_des_init_wrap, mbedtls_des_setkey_enc_wrap);
            break;

        case MOC_SYM_OP_DECRYPT_UPDATE:
        case MOC_SYM_OP_ENCRYPT_UPDATE:
            status = MDesMbedUpdate(
                pMocSymCtx, 0, (MSymOperatorData *) pInputInfo,
                (MSymOperatorBuffer *) pOutputInfo,
                mbedtls_des_crypt_ecb_wrap);
            break;

        case MOC_SYM_OP_DECRYPT_FINAL:
        case MOC_SYM_OP_ENCRYPT_FINAL:
            status = MDesMbedFinal(
                pMocSymCtx, 0, (MSymOperatorData *) pInputInfo,
                (MSymOperatorBuffer *) pOutputInfo,
                mbedtls_des_crypt_ecb_wrap);
            break;

        case MOC_SYM_OP_CLONE:
            status = MDesMbedClone(
                pMocSymCtx, (MocSymCtx) pOutputInfo);
            break;

        case MOC_SYM_OP_UPDATE_OP_DATA:
            status = MDesMbedUpdateOperatorData(
                pMocSymCtx, (MDesUpdateData *) pInputInfo);
            break;

        case MOC_SYM_OP_FREE:
            status = MDesMbedFree(pMocSymCtx, mbedtls_des_free_wrap);
            break;
    }

exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_DES_MBED__ */
