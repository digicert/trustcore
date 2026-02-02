/*
 * crypto_interface_ecc_tap_priv.c
 *
 * Cryptographic Interface file containing implementations of ECC TAP functions
 * for internal use by the Crypto Interface.
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

#include "../crypto/mocasym.h"
#include "../common/debug_console.h"
#include "../crypto/sha512.h"
#include "../crypto_interface/crypto_interface_priv.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "../tap/tap.h"
#include "../tap/tap_utils.h"
#include "../tap/tap_smp.h"
#include "../crypto/mocasymkeys/tap/ecctap.h"
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_ecc_tap_priv.h"
#endif

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_ECC__

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_EccDeferKeyUnload (
    ECCKey *pKey,
    ubyte4 keyType,
    byteBoolean deferredTokenUnload
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pKey)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != pKey->enabled)
    {
        status = ERR_TAP_INVALID_KEY_TYPE;
        goto exit;
    }

    if (MOC_ASYM_KEY_TYPE_PRIVATE == keyType)
    {
        status = CRYPTO_INTERFACE_TAP_eccDeferUnloadMocAsym(pKey->pPrivateKey, deferredTokenUnload);
    }
    else if (MOC_ASYM_KEY_TYPE_PUBLIC == keyType)
    { 
        status = CRYPTO_INTERFACE_TAP_eccDeferUnloadMocAsym(pKey->pPublicKey, deferredTokenUnload);
    }

exit:

    return status;

#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_TAP__
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_EccGetKeyInfo(
    ECCKey *pKey,
    ubyte4 keyType,
    TAP_TokenHandle *pTokenHandle, 
    TAP_KeyHandle *pKeyHandle
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pKey)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != pKey->enabled)
    {
        status = ERR_TAP_INVALID_KEY_TYPE;
        goto exit;
    }

    if (MOC_ASYM_KEY_TYPE_PRIVATE == keyType)
    {
        status = CRYPTO_INTERFACE_TAP_eccGetKeyInfoMocAsym(pKey->pPrivateKey, pTokenHandle, pKeyHandle);
    }
    else if (MOC_ASYM_KEY_TYPE_PUBLIC == keyType)
    { 
        status = CRYPTO_INTERFACE_TAP_eccGetKeyInfoMocAsym(pKey->pPublicKey, pTokenHandle, pKeyHandle);
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_EccUnloadKey(
    ECCKey *pKey
    )
{
    MSTATUS status = OK;
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;
    MocAsymKey pMocAsymKey = NULL;
    MEccTapKeyData *pData = NULL;
    TAP_Key *pTapKey = NULL;

    /* if nothing to unload return OK */
    if (NULL == pKey)
        return OK;
    
    pMocAsymKey = pKey->pPrivateKey;
    if (NULL == pMocAsymKey)
        return OK;

    pData = (MEccTapKeyData *)(pMocAsymKey->pKeyData);
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
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_getECCPublicKeyEx(MocAsymKey pMocAsymKey, void **ppPub)
{
#if defined(__ENABLE_DIGICERT_TAP__)
    MSTATUS status;
    ECCKey *pECCKey = NULL;
    MEccTapKeyData *pData = NULL;
    ubyte *pPublicDataBuffer = NULL;
    ubyte4 curveId, elementLen;

    if ( (NULL == pMocAsymKey) || (NULL == ppPub) )
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    pData = (MEccTapKeyData *)(pMocAsymKey->pKeyData);
    if (NULL == pData)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    /* Get the id for this curve, we need to specify it on the creation call */
    status = CRYPTO_INTERFACE_TAP_EC_getCurveIdFromKey (
        pMocAsymKey, &curveId);
    if (OK != status)
        goto exit;

    /* Create a shell for the new public key */
    status = EC_newKeyEx (curveId, &pECCKey);
    if (OK != status)
        goto exit;

    /* Get the element size, we will need to package up the public key elements */
    status = CRYPTO_INTERFACE_TAP_EC_getElementByteStringLen (
        pMocAsymKey, &elementLen);
    if (OK != status)
        goto exit;

    /* We need to construct an ECC public key, which is a compression
        * byte followed by x and y, zero padded to exactly elementLen */
    status = DIGI_CALLOC((void **)&pPublicDataBuffer, 1, 1 + (2 * elementLen));
    if (OK != status)
        goto exit;

    /* Indicate this is in the uncompressed form */
    pPublicDataBuffer[0] = 0x04;

    /* Copy in the x and y values */
    status = DIGI_MEMCPY (
        pPublicDataBuffer + 1,
        pData->pKey->keyData.publicKey.publicKey.eccKey.pPubX,
        pData->pKey->keyData.publicKey.publicKey.eccKey.pubXLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY (
        pPublicDataBuffer + 1 + elementLen,
        pData->pKey->keyData.publicKey.publicKey.eccKey.pPubY,
        pData->pKey->keyData.publicKey.publicKey.eccKey.pubYLen);
    if (OK != status)
        goto exit;

    /* Set the data into the key */
    status = EC_setKeyParametersEx ( MOC_ECC(0) /* not used in TAP */
        pECCKey, pPublicDataBuffer, 1 + (2 * elementLen), NULL, 0);
    if (OK != status)
        goto exit;

    *ppPub = (void *)pECCKey;
    pECCKey = NULL;

exit:

    if (NULL != pECCKey)
    {
        EC_deleteKeyEx(&pECCKey);
    }
    if (NULL != pPublicDataBuffer)
    {
        DIGI_FREE((void **)&pPublicDataBuffer);
    }

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

/* Produces concatenation of r and s as big endian bytestrings, zero padded
 * if necessary to ensure each bytestring is exactly element length. */
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_TAP_ECDSA_sign (
    MocAsymKey pECCKey,
    byteBoolean isDataNotDigest,
    ubyte hashAlgo,
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
    MocAsymKey pKey = (MocAsymKey)pECCKey;
    MEccTapKeyData *pInfo = NULL;
    ubyte4 elementLen = 0;
    ubyte4 padLen = 0;

    if ( (NULL == pInput) || (NULL == pKey) || (NULL == pSignatureLen) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#if (defined(__ENABLE_DIGICERT_TAP_EXTERN__))
    if (OK > ( status = CRYPTO_INTERFACE_TAPExternInit()))
        goto exit;
#endif

    /* Get the element length to determine if the buffer is large enough */
    status = CRYPTO_INTERFACE_TAP_EC_getElementByteStringLen(pKey, &elementLen);
    if (OK != status)
        goto exit;

    if (NULL == pSignature || bufferSize < (2 * elementLen))
    {
        *pSignatureLen = (2 * elementLen);
        status = ERR_BUFFER_TOO_SMALL;
        goto exit;
    }

    input.pBuffer = (ubyte*)pInput;
    input.bufferLen = inputLen;

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status = g_pFuncPtrGetTapContext(&pTapContext,
                                                    &pEntityCredentials,
                                                    &pKeyCredentials,
                                                    (void *)pKey, tap_ecc_sign, 1/*get Context*/)))
        {
            goto exit;
        }
    }
    else
    {
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
    }

    pInfo = (MEccTapKeyData *)(pKey->pKeyData);
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

    if (isDataNotDigest)
    {
        switch (hashAlgo)
        {
            case ht_sha1:
                sigScheme = TAP_SIG_SCHEME_ECDSA_SHA1;
                break;
            case ht_sha224:
                sigScheme = TAP_SIG_SCHEME_ECDSA_SHA224;
                break;
            case ht_sha256:
                sigScheme = TAP_SIG_SCHEME_ECDSA_SHA256;
                break;
            case ht_sha384:
                sigScheme = TAP_SIG_SCHEME_ECDSA_SHA384;
                break;
            case ht_sha512:
                sigScheme = TAP_SIG_SCHEME_ECDSA_SHA512;
                break;
        }
    }
    else
    {
        sigScheme = pTapKey->keyData.algKeyInfo.eccInfo.sigScheme;
    }

    status = TAP_asymSign(pTapKey, pEntityCredentials, NULL, sigScheme, isDataNotDigest, &input, &signature, pErrContext);
    if (OK != status)
        goto exit;

    /* Copy the data into the signature buffer as (r || s) properly padded */
    padLen = elementLen - signature.signature.eccSignature.rDataLen;  /* Safe to assume rDataLen <= elementLen */
    if (padLen)
    {
        (void) DIGI_MEMSET(pSignature, 0x00, padLen);
    }

    status = DIGI_MEMCPY (
        pSignature + padLen,
        signature.signature.eccSignature.pRData,
        signature.signature.eccSignature.rDataLen);
    if (OK != status)
        goto exit;

    padLen = elementLen - signature.signature.eccSignature.sDataLen;  /* Safe to assume sDataLen <= elementLen */
    if (padLen)
    {
        (void) DIGI_MEMSET(pSignature + elementLen, 0x00, padLen);
    }

    status = DIGI_MEMCPY (
        pSignature + elementLen + padLen,
        signature.signature.eccSignature.pSData,
        signature.signature.eccSignature.sDataLen);

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"ECDSA sign failed with status = ", status);
    else
        *pSignatureLen = 2*elementLen;

    TAP_freeSignature(&signature);

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
                                                    (void *)pKey, tap_ecc_sign, 0/*release context*/)))
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

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_TAP_ECDSA_verify (
    MocAsymKey pPublicKey,
    byteBoolean isDataNotDigest,
    ubyte hashAlgo,
    ubyte *pInput,
    ubyte4 inputLen,
    ubyte *pR,
    ubyte4 rLen,
    ubyte *pS,
    ubyte4 sLen,
    ubyte4 *pVerifyFailures
    )
{
#if defined(__ENABLE_DIGICERT_TAP__)
    MSTATUS status  = OK;
    MSTATUS status2 = OK;

    ubyte inputBuf[SHA512_RESULT_SIZE];
    TAP_Buffer input =
    {
        .pBuffer    = inputBuf,
        .bufferLen  = 0
    };
    TAP_ErrorContext errContext;
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_Signature signature = {0};
    TAP_SIG_SCHEME sigScheme = TAP_SIG_SCHEME_NONE;
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_CredentialList *pCombinedKeyCreds = NULL;
    intBoolean freeKeyCreds = FALSE;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_OP_EXEC_FLAG opExecFlag = TAP_OP_EXEC_FLAG_HW;
    byteBoolean isSigValid = 0;
    TAP_Context *pTapContext = NULL;
    TAP_Key *pTapKey = NULL;
    MocAsymKey pKey = (MocAsymKey)pPublicKey;
    MEccTapKeyData *pInfo = NULL;

    if ( (NULL == pKey) || (NULL == pInput) || (NULL == pR) ||
            (NULL == pS) || (NULL == pVerifyFailures) )
    {
        status = ERR_NULL_POINTER;
        goto exit1;
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
                                                    (void *)pKey, tap_ecc_verify, 1/*get context*/)))
        {
            goto exit1;
        }
    }
    else
    {
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
    }

    pInfo = (MEccTapKeyData *)(pKey->pKeyData);
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
                goto exit;

            freeKeyCreds = TRUE;
        }

        status = TAP_loadKey(pTapContext, pEntityCredentials, pTapKey, pCombinedKeyCreds, NULL, pErrContext);
        if (OK != status)
            goto exit1;

        pInfo->isKeyLoaded = TRUE;
    }

    signature.keyAlgorithm = TAP_KEY_ALGORITHM_ECC;
    signature.signature.eccSignature.pRData = pR;
    signature.signature.eccSignature.pSData = pS;
    signature.signature.eccSignature.rDataLen = rLen;
    signature.signature.eccSignature.sDataLen = sLen;

    if (isDataNotDigest)
    {
        switch (hashAlgo)
        {
            case ht_sha1:
                sigScheme = TAP_SIG_SCHEME_ECDSA_SHA1;
                break;
            case ht_sha224:
                sigScheme = TAP_SIG_SCHEME_ECDSA_SHA224;
                break;
            case ht_sha256:
                sigScheme = TAP_SIG_SCHEME_ECDSA_SHA256;
                break;
            case ht_sha384:
                sigScheme = TAP_SIG_SCHEME_ECDSA_SHA384;
                break;
            case ht_sha512:
                sigScheme = TAP_SIG_SCHEME_ECDSA_SHA512;
                break;
        }
    }
    else
    {
        sigScheme = pTapKey->keyData.algKeyInfo.eccInfo.sigScheme;
    }

    status = TAP_asymVerifySignature(pTapKey, pEntityCredentials, NULL, opExecFlag, sigScheme, &input, &signature, &isSigValid, pErrContext);
    if (OK != status)
        goto exit;

    if (!isSigValid)
    {
        /* Not valid */
        status = ERR_TAP_SIGN_VERIFY_FAIL;
        DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"ECDSA sign failed with status = ", status);
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
                                                    (void *)pKey, tap_ecc_verify, 0/* release context*/)))
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

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_TAP_EC_getCurveIdFromKey (
    MocAsymKey pKey,
    ubyte4 *pCurveId
    )
{
#if defined(__ENABLE_DIGICERT_TAP__)
    MSTATUS status;

    if ( (NULL == pKey) || (NULL == pCurveId) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = OK;

    TAP_ECC_CURVE curve;
    MEccTapKeyData *pData = NULL;
    MocAsymKey pMocAsymKey = (MocAsymKey)pKey;

    pData = (MEccTapKeyData *)(pMocAsymKey->pKeyData);
    curve = pData->pKey->keyData.algKeyInfo.eccInfo.curveId;
    switch(curve)
    {
#ifdef __ENABLE_DIGICERT_ECC_P192__
        case TAP_ECC_CURVE_NIST_P192:
            *pCurveId = cid_EC_P192;
            break;
#endif
        case TAP_ECC_CURVE_NIST_P224:
            *pCurveId = cid_EC_P224;
            break;
        case TAP_ECC_CURVE_NIST_P256:
            *pCurveId = cid_EC_P256;
            break;
        case TAP_ECC_CURVE_NIST_P384:
            *pCurveId = cid_EC_P384;
            break;
        case TAP_ECC_CURVE_NIST_P521:
            *pCurveId = cid_EC_P521;
            break;
        default:
            status = ERR_EC_UNSUPPORTED_CURVE;
            goto exit;
    }

exit:

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif /* __ENABLE_DIGICERT_TAP__ */
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_TAP_EC_getElementByteStringLen (
    MocAsymKey pKey,
    ubyte4 *pLen
    )
{
#if defined(__ENABLE_DIGICERT_TAP__)
    MSTATUS status;

    if ( (NULL == pKey) || (NULL == pLen) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = OK;

    TAP_ECC_CURVE curve;
    MEccTapKeyData *pData = NULL;
    MocAsymKey pMocAsymKey = (MocAsymKey)pKey;

    pData = (MEccTapKeyData *)(pMocAsymKey->pKeyData);
    curve = pData->pKey->keyData.algKeyInfo.eccInfo.curveId;
    switch(curve)
    {
#ifdef __ENABLE_DIGICERT_ECC_P192__
        case TAP_ECC_CURVE_NIST_P192:
            *pLen = 24;
            break;
#endif
        case TAP_ECC_CURVE_NIST_P224:
            *pLen = 28;
            break;
        case TAP_ECC_CURVE_NIST_P256:
            *pLen = 32;
            break;
        case TAP_ECC_CURVE_NIST_P384:
            *pLen = 48;
            break;
        case TAP_ECC_CURVE_NIST_P521:
            *pLen = 66;
            break;
        default:
            status = ERR_EC_UNSUPPORTED_CURVE;
            goto exit;
    }
exit:

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif /* __ENABLE_DIGICERT_TAP__ */
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_EC_writePublicKeyToBuffer (
    MocAsymKey pKey,
    ubyte *pBuffer,
    ubyte4 bufferSize
    )
{
#if defined(__ENABLE_DIGICERT_TAP__)
    MSTATUS status;
    ECCKey *pPubKey = NULL;

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    /* just in case build uses both TAP and hwAccel */
    hwAccelDescr hwAccelCtx = 0;
#endif

    status = CRYPTO_INTERFACE_getECCPublicKeyEx(pKey, (void **)&pPubKey);
    if (OK != status)
        goto exit;

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
        goto exit;
#endif

    status = EC_writePublicKeyToBuffer(MOC_ECC(hwAccelCtx) pPubKey, pBuffer, bufferSize);

exit:

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
#endif

    if (NULL != pPubKey)
    {
        EC_deleteKeyEx(&pPubKey);
    }

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif /* __ENABLE_DIGICERT_TAP__ */
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_EC_cloneKey (
    ECCKey **ppNew,
    MocAsymKey pSrc
    )
{
#if defined(__ENABLE_DIGICERT_TAP__)
    MSTATUS status = OK;

    ECCKey *pNewKey = NULL;
    MEccTapKeyData *pInfo = NULL;
    MocAsymKey pNewMocAsymKey = NULL;
    TAP_Key *pTapKey = NULL;

    status = DIGI_CALLOC((void **)&pNewMocAsymKey, sizeof(MocAsymmetricKey), 1);
    if (OK != status)
    {
        goto exit;
    }

    status = DIGI_CALLOC ((void **)&pNewMocAsymKey->pKeyData, sizeof (MEccTapKeyData), 1);
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte *)"Error allocating RsaTapKeyData", status);
        goto exit;
    }

    pInfo = (MEccTapKeyData *)((MocAsymKey)pSrc)->pKeyData;
    pTapKey = (TAP_Key *)pInfo->pKey;

    pInfo = (MEccTapKeyData *)pNewMocAsymKey->pKeyData;
    if (OK > (status = TAP_copyKey((TAP_Key **)&(pInfo->pKey), pTapKey)))
        goto exit;

    /* Set the operator and local type */
    pNewMocAsymKey->KeyOperator = pSrc->KeyOperator;
    pNewMocAsymKey->pMocCtx = pSrc->pMocCtx;
    pNewMocAsymKey->localType = pSrc->localType;

    status = CRYPTO_INTERFACE_EC_loadKey(&pNewKey, &pNewMocAsymKey);
    if (OK != status)
        goto exit;

    *ppNew = pNewKey;
    pNewKey = NULL;

exit:

    if (NULL != pNewMocAsymKey)
    {
        if (NULL != pNewMocAsymKey->pKeyData)
        {
            pInfo = (MEccTapKeyData *)pNewMocAsymKey->pKeyData;

            if (NULL != pInfo->pKey)
                TAP_freeKey((TAP_Key **)&pInfo->pKey);

            DIGI_FREE((void **)&pNewMocAsymKey->pKeyData);
        }

        DIGI_FREE((void **)&pNewMocAsymKey);
    }
    if (NULL != pNewKey)
    {
        EC_deleteKeyEx(&pNewKey);
    }

    return status;

#else
    return ERR_TAP_UNSUPPORTED;
#endif /* __ENABLE_DIGICERT_TAP__ */
}
#endif /* __ENABLE_DIGICERT_ECC__ */
