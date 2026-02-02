/*
 * hmactap.c
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

#include "../../../crypto/mocsymalgs/tap/symtap.h"
#include "../../../tap/tap_api.h"

#if defined(__ENABLE_DIGICERT_SYM__) && defined(__ENABLE_DIGICERT_TAP__)

static MSTATUS HmacTapGenerate (
    MocCtx pMocCtx,
    MSymKeyGenInfoEx *pInputInfo,
    MSymKeyGenResult *pOutputInfo
    )
{
    MSTATUS status;
    TAP_Key *pNewTapKey = NULL;
    MTapKeyData *pKeyData = NULL;
    MocSymCtx pNewCtx = NULL;
    MSymTapKeyGenArgs *pKeyGenArgs = NULL;
    TAP_KeyInfo keyInfo = {0};
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrCtx = &errContext;

    status = ERR_NULL_POINTER;
    if ( (NULL == pInputInfo) || (NULL == pOutputInfo) ||
         (NULL == pInputInfo->pOperatorInfo) || (NULL == pOutputInfo->ppNewSymCtx) )
    {
        goto exit;
    }

    pKeyGenArgs = (MSymTapKeyGenArgs *)(pInputInfo->pOperatorInfo);

    status = CRYPTO_createMocSymCtx (MHmacTapOperator, (void *)pKeyGenArgs, pMocCtx, &pNewCtx);
    if (OK != status)
        goto exit;

    pKeyData = (MTapKeyData *)pNewCtx->pLocalData;
    if (NULL == pKeyData)
        goto exit;

    /* Default to SHA256 with no usage defined */
    keyInfo.keyAlgorithm = TAP_KEY_ALGORITHM_HMAC;
    keyInfo.algKeyInfo.hmacInfo.hashAlg = pKeyGenArgs->hashAlg;
    keyInfo.algKeyInfo.hmacInfo.keyLen = pInputInfo->keySizeBits/8;
    keyInfo.keyUsage = TAP_KEY_USAGE_UNDEFINED;

    /* Override mode and usage if specified */
    if (TAP_KEY_USAGE_UNDEFINED != pKeyGenArgs->keyUsage)
    {
        keyInfo.keyUsage = pKeyGenArgs->keyUsage;
    }

    status = TAP_symGenerateKey (
        pKeyGenArgs->pTapCtx, pKeyGenArgs->pEntityCredentials, &keyInfo,
        pKeyGenArgs->pKeyAttributes, pKeyGenArgs->pKeyCredentials, &pNewTapKey, pErrCtx);
    if (OK != status)
        goto exit;

    pKeyData->pKey = pNewTapKey;
    pKeyData->isKeyLoaded = TRUE; /* Key comes loaded out of TAP_symGenerateKey */
    pKeyData->isDeferUnload = FALSE;
    pNewTapKey = NULL;
    *(pOutputInfo->ppNewSymCtx) = pNewCtx;
    pNewCtx = NULL;

exit:

    if (NULL != pNewTapKey)
    {
        (void) TAP_freeKey(&pNewTapKey);
    }
    if (NULL != pNewCtx)
    {
        (void) CRYPTO_freeMocSymCtx (&pNewCtx);
    }

    return status;
}

/* ------------------------------------------------------------------------- */

MOC_EXTERN MSTATUS MHmacTapOperator(
    MocSymCtx pMocSymCtx,
    MocCtx pMocCtx,
    symOperation symOp,
    void *pInputInfo,
    void *pOutputInfo
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    switch (symOp)
    {
        case MOC_SYM_OP_GET_LOCAL_TYPE:
            if (NULL != pOutputInfo)
            {
                *((ubyte4 *) pOutputInfo) = MOC_LOCAL_TYPE_HMAC_TAP;
                status = OK;
            }
            break;

        case MOC_SYM_OP_CREATE:
            status = SymTapCreate(pMocSymCtx, (MSymTapKeyGenArgs *) pInputInfo, MOC_LOCAL_TYPE_HMAC_TAP, MHmacTapOperator);
            break;

        case MOC_SYM_OP_GENERATE_KEY_EX:
            status = HmacTapGenerate (
                pMocCtx, (MSymKeyGenInfoEx *)pInputInfo,
                (MSymKeyGenResult *) pOutputInfo);
            break;
            
        case MOC_SYM_OP_FREE:
            status = SymTapFree(pMocSymCtx);
            break;

        default:
            status = ERR_NOT_IMPLEMENTED;
            break;
    }

    return status;
}

#else

MOC_EXTERN MSTATUS MHmacTapOperator(
    MocSymCtx pMocSymCtx,
    MocCtx pMocCtx,
    symOperation symOp,
    void *pInputInfo,
    void *pOutputInfo
    )
{
    return ERR_NOT_IMPLEMENTED;
}

#endif /* __ENABLE_DIGICERT_SYM__ && __ENABLE_DIGICERT_TAP__ */
