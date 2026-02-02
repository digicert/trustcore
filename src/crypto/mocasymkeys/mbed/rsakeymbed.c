/*
 * rsakeymbed.c
 *
 * Operator for Software version of RSA MocAsym Key.
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


#ifdef __ENABLE_DIGICERT_RSA_MBED__

#include "../../../crypto/mocasymkeys/mbed/mbedcommonrsa.h"

MOC_EXTERN MSTATUS KeyOperatorRsa(
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
                *((ubyte4 *) pOutputInfo) = MOC_LOCAL_KEY_RSA_PUB_OPERATOR;
                status = OK;
            }
            break;

        case MOC_ASYM_OP_CREATE:
        case MOC_ASYM_OP_CREATE_PUB:
            pMocAsymKey->KeyOperator = KeyOperatorRsa;
            pMocAsymKey->localType = MOC_LOCAL_KEY_RSA_PUB_OPERATOR;
            status = OK;
            break;

        case MOC_ASYM_OP_CREATE_PRI:
            pMocAsymKey->KeyOperator = KeyOperatorRsa;
            pMocAsymKey->localType = MOC_LOCAL_KEY_RSA_PRI_OPERATOR;
            status = OK;
            break;

        case MOC_ASYM_OP_GET_SECURITY_SIZE:
            status = RsaMbedGetSecuritySize(
                pMocAsymKey, (ubyte4 *) pOutputInfo);
            break;

        case MOC_ASYM_OP_GENERATE:
            status = RsaMbedGenerateKeyPair(
                pMocCtx, (MKeyPairGenInfo *) pInputInfo,
                (MKeyPairGenResult *) pOutputInfo);
            break;

        case MOC_ASYM_OP_SIGN_DIGEST_INFO:
        case MOC_ASYM_OP_SIGN_MESSAGE:
            status = RsaMbedSign(
                pMocAsymKey, (MKeyAsymSignInfo *) pInputInfo,
                (MKeyOperatorBuffer *) pOutputInfo);
            break;

        case MOC_ASYM_OP_VERIFY_DIGEST:
        case MOC_ASYM_OP_VERIFY_DIGEST_INFO:
        case MOC_ASYM_OP_VERIFY_MESSAGE:
            status = RsaMbedVerify(
                pMocAsymKey, (MKeyAsymVerifyInfo *) pInputInfo,
                (ubyte4 *) pOutputInfo);
            break;

        case MOC_ASYM_OP_ENCRYPT:
            status = RsaMbedEncrypt(
                pMocAsymKey, (MKeyAsymEncryptInfo *) pInputInfo,
                (MKeyOperatorBuffer *) pOutputInfo);
            break;

        case MOC_ASYM_OP_DECRYPT:
            status = RsaMbedDecrypt(
                pMocAsymKey, (MKeyAsymEncryptInfo *) pInputInfo,
                (MKeyOperatorBuffer *) pOutputInfo);
            break;

        case MOC_ASYM_OP_PUB_FROM_PRI:
            status = RsaMbedGetPubFromPri(
                pMocAsymKey, (MocAsymKey *) pOutputInfo);
            break;

        case MOC_ASYM_OP_CLONE:
            status = RsaMbedCloneKey(
                pMocAsymKey, (MocAsymKey *) pOutputInfo);
            break;

        case MOC_ASYM_OP_SET_KEY_DATA:
            status = RsaMbedSetKeyData(
                pMocAsymKey, (MRsaKeyTemplate *) pInputInfo);
            break;

        case MOC_ASYM_OP_GET_KEY_DATA:
            status = RsaMbedGetKeyDataAlloc(
                pMocAsymKey, (MRsaKeyTemplate *) pOutputInfo, (ubyte *)pInputInfo);
            break;

        case MOC_ASYM_OP_FREE:
            status = RsaMbedFreeKey(pMocAsymKey);
            break;
    }

exit:

    return status;
}
#endif
