/*
 * crypto_interface_qs_tap.c
 *
 * Cryptographic Interface file containing implementations of QS TAP functions
 * for internal use by the Crypto Interface.
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

#include "../crypto/mocasym.h"
#include "../common/debug_console.h"
#include "../crypto_interface/crypto_interface_priv.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "../tap/tap.h"
#include "../tap/tap_utils.h"
#include "../tap/tap_smp.h"
#include "../crypto/mocasymkeys/tap/qstap.h"
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_qs.h"
#include "../crypto_interface/crypto_interface_qs_tap.h"
#include "../crypto_interface/crypto_interface_qs_tap_priv.h"
#endif

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_PQC_SIG__
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_QS_sign (
    MocAsymKey pSecretKey,
    byteBoolean isDataNotDigest,
    ubyte4 digestId,
    ubyte *pInput,
    ubyte4 inputLen,
    ubyte *pSignature,
    ubyte4 bufferSize,
    ubyte4 *pSignatureLen
    )
{
#if defined(__ENABLE_DIGICERT_TAP__)
    MSTATUS status = OK;
    MSTATUS status2 = OK;

    TAP_Buffer input = {0};
    TAP_ErrorContext errContext;
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_Signature signature = {0};
    TAP_SIG_SCHEME sigScheme = TAP_SIG_SCHEME_NONE;
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_CredentialList *pCombinedKeyCreds = NULL;
    intBoolean freeKeyCreds = FALSE;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_Context *pTapContext = NULL;
    TAP_Key *pTapKey = NULL;
    MQsTapKeyData *pInfo = NULL;
    TAP_Attribute attributes = {
        TAP_ATTR_IS_DATA_NOT_DIGEST, sizeof(isDataNotDigest), &isDataNotDigest
    };
    TAP_AttributeList operAttributes = {1, &attributes};

    if ( (NULL == pInput) || (NULL == pSecretKey) || (NULL == pSignature) || (NULL == pSignatureLen) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#if (defined(__ENABLE_DIGICERT_TAP_EXTERN__))
    if (OK > ( status = CRYPTO_INTERFACE_TAPExternInit()))
        goto exit;
#endif

    /* Future, validation of alg and buffer size for PQC algs */

    input.pBuffer = (ubyte*)pInput;
    input.bufferLen = inputLen;

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status = g_pFuncPtrGetTapContext(&pTapContext,
                                                    &pEntityCredentials,
                                                    &pKeyCredentials,
                                                    (void *)pSecretKey, tap_qs_sign, 1/*get Context*/)))
        {
            goto exit;
        }
    }
    else
    {
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
    }

    pInfo = (MQsTapKeyData *)(pSecretKey->pKeyData);
    if (NULL == pInfo)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pTapKey = (TAP_Key *)pInfo->pKey;

    if (!pInfo->isKeyLoaded)
    {
        pCombinedKeyCreds = pKeyCredentials;
        if (NULL == pKeyCredentials)
        {
            pCombinedKeyCreds = pInfo->pKeyCredentials;
        }

        if ((NULL != pKeyCredentials) && (NULL != pInfo->pKeyCredentials))
        {
            status = TAP_UTILS_joinCredentialList(pKeyCredentials, pInfo->pKeyCredentials, &pCombinedKeyCreds);
            if (OK != status)
                goto exit;

            freeKeyCreds = TRUE;
        }

        status = TAP_loadKey(pTapContext, pEntityCredentials, pTapKey, pCombinedKeyCreds, NULL, pErrContext);
        if (OK != status)
            goto exit;

        pInfo->isKeyLoaded = TRUE;
    }
    
    /* Future, once PQC sig schems are identified via the digestId we'd convert the digestId to a sigScheme,
       For now NanoRoot only uses TAP_SIG_SCHEME_NONE for pqc */
    MOC_UNUSED(digestId);

    sigScheme = pTapKey->keyData.algKeyInfo.pqcInfo.sigScheme;
    status = TAP_asymSign(pTapKey, pEntityCredentials, &operAttributes, sigScheme, isDataNotDigest, &input, &signature, pErrContext);
    if (OK != status)
        goto exit;

    if (signature.signature.pqcSignature.signatureLen > bufferSize)
    {
        status = ERR_BUFFER_TOO_SMALL;
        goto exit;
    }

    status = DIGI_MEMCPY(pSignature, signature.signature.pqcSignature.pSignature, signature.signature.pqcSignature.signatureLen);
    if (OK != status)
        goto exit;

    *pSignatureLen = signature.signature.pqcSignature.signatureLen;

exit:

    (void) TAP_freeSignature(&signature);

    if((NULL != pInfo) && !pInfo->isDeferUnload)
    {
        if (OK > (status2 = TAP_unloadKey(pTapKey, pErrContext)))
        {
            DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"TAP_unloadKey failed with status = ", status2);
        }
        else
        {
            pInfo->isKeyLoaded = FALSE;
        }
    }

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status2 = g_pFuncPtrGetTapContext(&pTapContext,
                                                    &pEntityCredentials,
                                                    &pKeyCredentials,
                                                    (void *)pSecretKey, tap_qs_sign, 0/*release context*/)))
        {
            DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"TAP Context release failed with status = ", status2);
        }
    }

    if (freeKeyCreds && (NULL != pCombinedKeyCreds))
    {
        /* Free any internal structures */
        (void) TAP_UTILS_clearCredentialList(pCombinedKeyCreds);
    
        /* Free outer shell */
        (void) DIGI_FREE((void** ) &pCombinedKeyCreds);
    }

    /* if we failed in the cleanup, record the failure */
    if ((OK == status) && (OK > status2))
        status = status2;

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_QS_verify (
    MocAsymKey pPublicKey,
    byteBoolean isDataNotDigest,
    ubyte4 digestId,
    ubyte *pInput,
    ubyte4 inputLen,
    ubyte *pSignature,
    ubyte4 signatureLen,
    ubyte4 *pVerifyFailures
    )
{
#if defined(__ENABLE_DIGICERT_TAP__)
    MSTATUS status = OK;
    MSTATUS status2 = OK;

    TAP_Buffer input = {0};
    TAP_ErrorContext errContext;
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_Signature signature = {0};
    TAP_SIG_SCHEME sigScheme = TAP_SIG_SCHEME_NONE;
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_CredentialList *pCombinedKeyCreds = NULL;
    intBoolean freeKeyCreds = FALSE;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_Context *pTapContext = NULL;
    TAP_Key *pTapKey = NULL;
    MQsTapKeyData *pInfo = NULL;
    TAP_Attribute attributes = {
        TAP_ATTR_IS_DATA_NOT_DIGEST, sizeof(isDataNotDigest), &isDataNotDigest
    };
    TAP_AttributeList operAttributes = {1, &attributes};
    TAP_OP_EXEC_FLAG opExecFlag = TAP_OP_EXEC_FLAG_HW;
    byteBoolean isSigValid = 0;

    if ( (NULL == pPublicKey) || (NULL == pInput) || (NULL == pSignature) || (NULL == pVerifyFailures) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Set to false by default */
    *pVerifyFailures = 1;

#if (defined(__ENABLE_DIGICERT_TAP_EXTERN__))
    if (OK > ( status = CRYPTO_INTERFACE_TAPExternInit()))
        goto exit;
#endif

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status = g_pFuncPtrGetTapContext(&pTapContext,
                                                    &pEntityCredentials,
                                                    &pKeyCredentials,
                                                    (void *)pPublicKey, tap_qs_verify, 1/*get context*/)))
        {
            goto exit1;
        }
    }
    else
    {
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
    }

    pInfo = (MQsTapKeyData *)(pPublicKey->pKeyData);
    if (NULL == pInfo)
    {
        status = ERR_NULL_POINTER;
        goto exit1;
    }
    pTapKey = (TAP_Key *)pInfo->pKey;

    input.pBuffer = (ubyte*)pInput;
    input.bufferLen = inputLen;

    if (!pInfo->isKeyLoaded)
    {
        pCombinedKeyCreds = pKeyCredentials;
        if (NULL == pKeyCredentials)
        {
            pCombinedKeyCreds = pInfo->pKeyCredentials;
        }

        if ((NULL != pKeyCredentials) && (NULL != pInfo->pKeyCredentials))
        {
            status = TAP_UTILS_joinCredentialList(pKeyCredentials, pInfo->pKeyCredentials, &pCombinedKeyCreds);
            if (OK != status)
                goto exit1;

            freeKeyCreds = TRUE;
        }

        status = TAP_loadKey(pTapContext, pEntityCredentials, pTapKey, pCombinedKeyCreds, NULL, pErrContext);
        if (OK != status)
            goto exit1;

        pInfo->isKeyLoaded = TRUE;
    }

    signature.keyAlgorithm = TAP_KEY_ALGORITHM_MLDSA; /* Only MLDSA right now, but future may need to get it from the TAP_Key or pInfo */
    signature.signature.pqcSignature.pSignature = pSignature;
    signature.signature.pqcSignature.signatureLen = signatureLen;

    /* Future, once PQC sig schems are identified via the digestId we'd convert the digestId to a sigScheme,
       For now NanoRoot only uses TAP_SIG_SCHEME_NONE for pqc */
    MOC_UNUSED(digestId);
    sigScheme = pTapKey->keyData.algKeyInfo.pqcInfo.sigScheme;

    status = TAP_asymVerifySignature(pTapKey, pEntityCredentials, &operAttributes, opExecFlag, sigScheme, &input, &signature, &isSigValid, pErrContext);
    if (OK != status)
        goto exit1;

    if (!isSigValid)
    {
        /* Not valid */
        status = ERR_TAP_SIGN_VERIFY_FAIL;
        DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"TAP QS verify failed with status = ", status);
    }
    else
    {
        /* Valid */
        *pVerifyFailures = 0;
    }

exit1:

    if((NULL != pInfo) && (!pInfo->isDeferUnload))
    {
        if (OK > (status2 = TAP_unloadKey(pTapKey, pErrContext)))
        {
            DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"TAP_unloadKey failed with status = ", status2);
        }
        else
        {
            pInfo->isKeyLoaded = FALSE;
        }
    }

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status2 = g_pFuncPtrGetTapContext(&pTapContext,
                                                    &pEntityCredentials,
                                                    &pKeyCredentials,
                                                    (void *)pPublicKey, tap_qs_verify, 0/* release context*/)))
        {
            DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"TAP Context release failed with status = ", status2);
        }
    }

exit:
    if (freeKeyCreds && (NULL != pCombinedKeyCreds))
    {
        /* Free any internal structures */
        (void) TAP_UTILS_clearCredentialList(pCombinedKeyCreds);
    
        /* Free outer shell */
        (void) DIGI_FREE((void** ) &pCombinedKeyCreds);
    }

    if ((OK == status) && (OK > status2))
        status = status2;

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif /* __ENABLE_DIGICERT_TAP__ */
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_PQC_SIG__ */

/*---------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_PQC_KEM__) || defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_PQC_SIG__)
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_QS_getAlg(
   MocAsymKey pKey,
   ubyte4 *pAlg
)
{
#ifdef __ENABLE_DIGICERT_TAP__
    MQsTapKeyData *pData = NULL;
    TAP_Key *pTapKey = NULL;

    if (NULL == pKey || NULL == pAlg || NULL == pKey->pKeyData)
        return ERR_NULL_POINTER;

    pData = (MQsTapKeyData *) pKey->pKeyData;
    pTapKey = pData->pKey;
    if (NULL == pTapKey)
        return ERR_NULL_POINTER;

    /* Works as long as TAP qsAlg values match ca_mgmt.h values */
    *pAlg = (ubyte4) (pTapKey->keyData.algKeyInfo.pqcInfo.qsAlg);
    return OK;
#else
    return ERR_NOT_IMPLEMENTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_QS_getSwPubFromTap (
    MocAsymKey pPrivateKey,
    QS_CTX **ppNewPub
)
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER;
    MQsTapKeyData *pData = NULL;
    TAP_Key *pTapKey = NULL;
    QS_CTX *pCtx = NULL;

    if (NULL == pPrivateKey || NULL == ppNewPub || NULL == pPrivateKey->pKeyData)
        goto exit;

    pData = (MQsTapKeyData *) pPrivateKey->pKeyData;
    pTapKey = pData->pKey;
    if (NULL == pTapKey)
        goto exit;

    /* Works as long as TAP qsAlg values match ca_mgmt.h values */
    status = CRYPTO_INTERFACE_QS_newCtx(MOC_HASH(0) &pCtx, (ubyte4) pTapKey->keyData.algKeyInfo.pqcInfo.qsAlg);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_setPublicKey(pCtx, pTapKey->keyData.publicKey.publicKey.pqcKey.pPublicKey, pTapKey->keyData.publicKey.publicKey.pqcKey.publicKeyLen);
    if (OK != status)
        goto exit;

    *ppNewPub = pCtx; pCtx = NULL;

exit:
    
    if (NULL != pCtx)
    {
        (void) CRYPTO_INTERFACE_QS_deleteCtx(&pCtx);
    }

    return status;
#else
    return ERR_NOT_IMPLEMENTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_QS_getPublicKey (
    MocAsymKey pKey,
    ubyte *pPublicKey,
    ubyte4 pubLen)
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER;
    MQsTapKeyData *pData = NULL;
    TAP_Key *pTapKey = NULL;

    if (NULL == pKey || NULL == pPublicKey || NULL == pKey->pKeyData)
        goto exit;

    pData = (MQsTapKeyData *) pKey->pKeyData;
    pTapKey = pData->pKey;
    if (NULL == pTapKey)
        goto exit;

    status = ERR_BUFFER_TOO_SMALL;
    if (pubLen < pTapKey->keyData.publicKey.publicKey.pqcKey.publicKeyLen)
        goto exit;

    status = DIGI_MEMCPY(pPublicKey, pTapKey->keyData.publicKey.publicKey.pqcKey.pPublicKey, pTapKey->keyData.publicKey.publicKey.pqcKey.publicKeyLen);

exit:

    return status;
#else
    return ERR_NOT_IMPLEMENTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_QsDeferKeyUnload (
    QS_CTX *pCtx,
    ubyte4 keyType,
    byteBoolean deferredTokenUnload
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != pCtx->enabled)
    {
        status = ERR_TAP_INVALID_KEY_TYPE;
        goto exit;
    }

    if (MOC_ASYM_KEY_TYPE_PRIVATE == keyType)
    {
        status = CRYPTO_INTERFACE_TAP_qsDeferUnloadMocAsym((MocAsymKey) pCtx->pSecretKey, deferredTokenUnload);
    }
    else if (MOC_ASYM_KEY_TYPE_PUBLIC == keyType)
    { 
        status = CRYPTO_INTERFACE_TAP_qsDeferUnloadMocAsym((MocAsymKey) pCtx->pPublicKey, deferredTokenUnload);
    }

exit:

    return status;

#else
    return ERR_TAP_UNSUPPORTED;
#endif
}
#endif /* defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_PQC_KEM__) || defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_PQC_SIG__) */

/*---------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_PQC__)
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_QsGetKeyInfo(
    QS_CTX *pCtx,
    ubyte4 keyType,
    TAP_TokenHandle *pTokenHandle,
    TAP_KeyHandle *pKeyHandle
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != pCtx->enabled)
    {
        status = ERR_TAP_INVALID_KEY_TYPE;
        goto exit;
    }

    if (MOC_ASYM_KEY_TYPE_PRIVATE == keyType)
    {
        status = CRYPTO_INTERFACE_TAP_qsGetKeyInfoMocAsym(pCtx->pSecretKey, pTokenHandle, pKeyHandle);
    }
    else if (MOC_ASYM_KEY_TYPE_PUBLIC == keyType)
    { 
        status = CRYPTO_INTERFACE_TAP_qsGetKeyInfoMocAsym(pCtx->pPublicKey, pTokenHandle, pKeyHandle);
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_QsUnloadKey(
    QS_CTX *pCtx
    )
{
    MSTATUS status = OK;
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;
    MocAsymKey pMocAsymKey = NULL;
    MQsTapKeyData *pData = NULL;
    TAP_Key *pTapKey = NULL;

    /* if nothing to unload return OK */
    if (NULL == pCtx)
        return OK;
    
    pMocAsymKey = pCtx->pSecretKey;
    if (NULL == pMocAsymKey)
        return OK;

    pData = (MQsTapKeyData *)(pMocAsymKey->pKeyData);
    if (NULL == pData)     
        return OK;

    if (pData->isKeyLoaded)
    {
        pTapKey = (TAP_Key *) pData->pKey;
        if (NULL == pTapKey)
        {
            return ERR_NULL_POINTER; /* this is a problem */
        }
        
        status = TAP_unloadKey(pTapKey, pErrContext);
        if (OK == status)
        {
            pData->isKeyLoaded = FALSE;
        }
    }

    return status;
}
#endif /* defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_PQC__) */
