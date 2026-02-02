/*
 * ecc224keymbed.c
 *
 * Operator for Software version of ECC MocAsym Key.
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

#include "../../../crypto/mocasym.h"


#ifdef __ENABLE_DIGICERT_ECC_P224_MBED__

#include "../../../crypto/mocasymkeys/mbed/mbedcommonecc.h"

MOC_EXTERN MSTATUS KeyOperatorEccNistP224(
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
                status = OK;
                *((ubyte4 *) pOutputInfo) = MOC_LOCAL_KEY_ECC_P224_PUB_OPERATOR;
            }
            break;

        case MOC_ASYM_OP_CREATE:
        case MOC_ASYM_OP_CREATE_PUB:
            pMocAsymKey->KeyOperator = KeyOperatorEccNistP224;
            pMocAsymKey->localType = MOC_LOCAL_KEY_ECC_P224_PUB_OPERATOR;
            status = OK;
            break;

        case MOC_ASYM_OP_CREATE_PRI:
            pMocAsymKey->KeyOperator = KeyOperatorEccNistP224;
            pMocAsymKey->localType = MOC_LOCAL_KEY_ECC_P224_PRI_OPERATOR;
            status = OK;
            break;

        case MOC_ASYM_OP_GENERATE:
            status = EccMbedGenerateKeyPair(
                pMocCtx, KeyOperatorEccNistP224,
                (MKeyPairGenInfo *) pInputInfo, (MKeyPairGenResult *) pOutputInfo,
                MBEDTLS_ECP_DP_SECP224R1);
            break;

        case MOC_ASYM_OP_PUB_FROM_PRI:
            status = EccMbedGetPubFromPri(
                pMocAsymKey, KeyOperatorEccNistP224,
                (MocAsymKey *) pOutputInfo);
            break;

        case MOC_ASYM_OP_GET_PUB_VALUE:
            status = EccMbedReturnPubValAlloc(
                pMocAsymKey, (MKeyOperatorDataReturn *) pOutputInfo);
            break;

        case MOC_ASYM_OP_COMPUTE_SHARED_SECRET:
            status = EccMbedComputeSharedSecret (
                pMocAsymKey, (MKeyOperatorData *)pInputInfo,
                (MKeyOperatorBuffer *)pOutputInfo);
            break;

        case MOC_ASYM_OP_SIGN_DIGEST:
            status = EccMbedSign(
                pMocAsymKey, (MKeyAsymSignInfo *) pInputInfo,
                (MKeyOperatorBuffer *) pOutputInfo);
            break;
            
        case MOC_ASYM_OP_SIGN_MESSAGE:
            status = EccMbedSignMessage(
                pMocAsymKey, (MKeyAsymSignInfo *) pInputInfo,
                (MKeyOperatorBuffer *) pOutputInfo);
            break;

        case MOC_ASYM_OP_SIGN_DIGEST_INFO:
            status = EccMbedSignDigestInfo(
                pMocAsymKey, (MKeyAsymSignInfo *) pInputInfo,
                (MKeyOperatorBuffer *) pOutputInfo);
            break;

        case MOC_ASYM_OP_VERIFY_DIGEST:
            status = EccMbedVerify(
                pMocAsymKey, (MKeyAsymVerifyInfo *) pInputInfo,
                (ubyte4 *) pOutputInfo);
            break;

        case MOC_ASYM_OP_VERIFY_DIGEST_INFO:
            status = EccMbedVerifyDigestInfo(
                pMocAsymKey, (MKeyAsymVerifyInfo *) pInputInfo,
                (ubyte4 *) pOutputInfo);
            break;
            
        case MOC_ASYM_OP_VERIFY_MESSAGE:
            status = EccMbedVerifyMessage(
                pMocAsymKey, (MKeyAsymVerifyInfo *) pInputInfo,
                (ubyte4 *) pOutputInfo);
            break;

        case MOC_ASYM_OP_SET_KEY_DATA:
            status = EccMbedSetKeyData(
                pMocAsymKey, KeyOperatorEccNistP224,
                MOC_LOCAL_KEY_ECC_P224_PUB_OPERATOR, (MEccKeyTemplate *)pInputInfo,
                MBEDTLS_ECP_DP_SECP224R1);
            break;

        case MOC_ASYM_OP_GET_KEY_DATA:
            status = EccMbedGetKeyDataAlloc(
                pMocAsymKey, (MEccKeyTemplate *) pOutputInfo, pInputInfo);
            break;

        case MOC_ASYM_OP_CLONE:
            status = EccMbedCloneKey(
                pMocAsymKey, (MocAsymKey *) pOutputInfo);
            break;

        case MOC_ASYM_OP_VALIDATE_PUB_PRI_MATCH:
            status = EccMbedValidatePubPriMatch(
                pMocAsymKey, (MocAsymKey)pInputInfo,
                (byteBoolean *)pOutputInfo);
            break;

        case MOC_ASYM_OP_VALIDATE_KEY:
            status = EccMbedValidateKey(
                pMocAsymKey, (byteBoolean *)pOutputInfo);
            break;

        case MOC_ASYM_OP_FREE:
            status = EccMbedFreeKey(pMocAsymKey);

    }

exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_ECC_P224_MBED__ */
