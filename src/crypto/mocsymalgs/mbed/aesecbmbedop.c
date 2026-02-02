/*
 * aesecbmbedop.c
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


#ifdef __ENABLE_DIGICERT_AES_ECB_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbedaesecb.h"

MOC_EXTERN MSTATUS SymOperatorAesEcb(
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
                *((ubyte4 *) pOutputInfo) = MOC_LOCAL_TYPE_AES_ECB_OPERATOR;
                status = OK;
            }
            break;

        case MOC_SYM_OP_CREATE:
            status = MAesEcbMbedCreate(pMocSymCtx);
            break;

        case MOC_SYM_OP_LOAD_KEY:
            status = MAesEcbMbedLoadKey(
                pMocSymCtx, (MSymOperatorData *) pInputInfo);
            break;

        case MOC_SYM_OP_ENCRYPT_INIT:
            status = MAesEcbMbedInit(pMocSymCtx, mbedtls_aes_setkey_enc);
            break;

        case MOC_SYM_OP_DECRYPT_INIT:
            status = MAesEcbMbedInit(pMocSymCtx, mbedtls_aes_setkey_dec);
            break;

        case MOC_SYM_OP_ENCRYPT_UPDATE:
        case MOC_SYM_OP_ENCRYPT_FINAL:
            status = MAesEcbMbedUpdate(pMocSymCtx, MBEDTLS_AES_ENCRYPT,
                (MSymOperatorData *) pInputInfo,
                (MSymOperatorBuffer *) pOutputInfo);
            break;

        case MOC_SYM_OP_DECRYPT_UPDATE:
        case MOC_SYM_OP_DECRYPT_FINAL:
            status = MAesEcbMbedUpdate(pMocSymCtx, MBEDTLS_AES_DECRYPT,
                (MSymOperatorData *) pInputInfo,
                (MSymOperatorBuffer *) pOutputInfo);
            break;

        case MOC_SYM_OP_CLONE:
            status = MAesEcbMbedClone(
                pMocSymCtx, (MocSymCtx) pOutputInfo);
            break;

        case MOC_SYM_OP_FREE:
            status = MAesEcbMbedFree(pMocSymCtx);
            break;
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_AES_ECB_MBED__ */
