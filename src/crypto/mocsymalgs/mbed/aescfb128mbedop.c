/*
 * aescfb128mbedop.c
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


#ifdef __ENABLE_DIGICERT_AES_CFB128_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbedaes.h"

MOC_EXTERN MSTATUS SymOperatorAesCfb128(
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
                *((ubyte4 *) pOutputInfo) = MOC_LOCAL_TYPE_AES_CFB_OPERATOR;
                status = OK;
            }
            break;

        case MOC_SYM_OP_CREATE:
            status = MAesMbedCreate(
                pMocSymCtx, (MAesUpdateData *) pInputInfo,
                MOC_LOCAL_TYPE_AES_CFB_OPERATOR, SymOperatorAesCfb128);
            break;

         case MOC_SYM_OP_UPDATE_OP_DATA:
            status = MAesMbedUpdateInfo(
                pMocSymCtx, (MAesUpdateData *) pInputInfo);
            break;

        case MOC_SYM_OP_LOAD_KEY:
            status = MAesMbedLoadKey(
                pMocSymCtx, (MSymOperatorData *) pInputInfo);
            break;

        case MOC_SYM_OP_ENCRYPT_INIT:
            status = MAesMbedInit(
                pMocSymCtx, mbedtls_aes_setkey_enc, MBEDTLS_AES_ENCRYPT);
            break;

        case MOC_SYM_OP_DECRYPT_INIT:
            status = MAesMbedInit(
                pMocSymCtx, mbedtls_aes_setkey_enc, MBEDTLS_AES_DECRYPT);
            break;

        case MOC_SYM_OP_ENCRYPT_UPDATE:
        case MOC_SYM_OP_ENCRYPT_FINAL:
            status = MAesMbedUpdate(
                pMocSymCtx, MBEDTLS_AES_ENCRYPT,
                (MSymOperatorData *) pInputInfo,
                (MSymOperatorBuffer *) pOutputInfo,
                MAesCfb128MbedCrypt);
            break;

        case MOC_SYM_OP_DECRYPT_UPDATE:
        case MOC_SYM_OP_DECRYPT_FINAL:
            status = MAesMbedUpdate(
                pMocSymCtx, MBEDTLS_AES_DECRYPT,
                (MSymOperatorData *) pInputInfo,
                (MSymOperatorBuffer *) pOutputInfo,
                MAesCfb128MbedCrypt);
            break;

        case MOC_SYM_OP_CLONE:
            status = MAesMbedClone(
                pMocSymCtx, (MocSymCtx) pOutputInfo);
            break;

        case MOC_SYM_OP_FREE:
            status = MAesMbedFree(pMocSymCtx);
            break;
        case MOC_SYM_OP_GET_OP_DATA:

            /* pMocSymCtx will be dereferenced, other params validated later */
            status = ERR_NULL_POINTER;
            if (NULL == pMocSymCtx)
                break;
            status = MAesGetOpData(pMocSymCtx->pLocalData, (MSymOperatorData *) pOutputInfo);

            break;
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_AES_CFB128_MBED__ */
