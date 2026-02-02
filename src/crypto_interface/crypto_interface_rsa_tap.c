/*
 * crypto_interface_rsa_tap_priv.c
 *
 * Cryptographic Interface file containing implementations of RSA TAP functions
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
#include "../crypto/mocasymkeys/tap/rsatap.h"
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_rsa_tap_priv.h"
#include "../crypto_interface/crypto_interface_sym_tap.h"
#include "../crypto/mocsymalgs/tap/symtap.h"
#endif

/*---------------------------------------------------------------------------*/

#define MOC_RSA_NO_PAD   0
#define MOC_RSA_V15_PAD  1
#define MOC_RSA_OAEP_PAD 2


MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_RsaDeferKeyUnload (
    RSAKey *pKey,
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
        status = CRYPTO_INTERFACE_TAP_rsaDeferUnloadMocAsym(pKey->pPrivateKey, deferredTokenUnload);
    }
    else if (MOC_ASYM_KEY_TYPE_PUBLIC == keyType)
    { 
        status = CRYPTO_INTERFACE_TAP_rsaDeferUnloadMocAsym(pKey->pPublicKey, deferredTokenUnload);
    }

exit:

    return status;

#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_TAP__
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_RsaGetKeyInfo(
    RSAKey *pKey,
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
        status = CRYPTO_INTERFACE_TAP_rsaGetKeyInfoMocAsym(pKey->pPrivateKey, pTokenHandle, pKeyHandle);
    }
    else if (MOC_ASYM_KEY_TYPE_PUBLIC == keyType)
    { 
        status = CRYPTO_INTERFACE_TAP_rsaGetKeyInfoMocAsym(pKey->pPublicKey, pTokenHandle, pKeyHandle);
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_RsaUnloadKey(
    RSAKey *pKey
    )
{
    MSTATUS status = OK;
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;
    MocAsymKey pMocAsymKey = NULL;
    MRsaTapKeyData *pData = NULL;
    TAP_Key *pTapKey = NULL;

    /* if nothing to unload return OK */
    if (NULL == pKey)
        return OK;
    
    pMocAsymKey = pKey->pPrivateKey;
    if (NULL == pMocAsymKey)
        return OK;

    pData = (MRsaTapKeyData *)(pMocAsymKey->pKeyData);
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

#if defined(__ENABLE_DIGICERT_TAP__)

static MSTATUS CRYPTO_INTERFACE_TAP_RSA_getSigScheme (
    ubyte hashAlgo,
    TAP_SIG_SCHEME inScheme,
    TAP_SIG_SCHEME *pOutScheme,
    byteBoolean isPss
    )
{
    MSTATUS status = OK;

    /* internal method, NULL check not necc */

    if (isPss)
    {
        /* no TAP_SIG_SCHEME_PSS_*, set outScheme based on hashAlgo */
        switch (hashAlgo)
        {
            case ht_sha1:
                *pOutScheme = TAP_SIG_SCHEME_PSS_SHA1;
                break;

            case ht_sha256:
                *pOutScheme = TAP_SIG_SCHEME_PSS_SHA256;
                break;

            case ht_sha384:
                *pOutScheme = TAP_SIG_SCHEME_PSS_SHA384;
                break;

            case ht_sha512:
                *pOutScheme = TAP_SIG_SCHEME_PSS_SHA512;
                break;

            default:
                status = ERR_RSA_INVALID_PSS_PARAMETERS;
                goto exit;
        }
    }
    else
    {
        switch(hashAlgo)
        {
            case ht_sha1:
                *pOutScheme = TAP_SIG_SCHEME_PKCS1_5_SHA1;
                break;
            case ht_sha224:
                *pOutScheme = TAP_SIG_SCHEME_PKCS1_5_SHA224;
                break;
            case ht_sha256:
                *pOutScheme = TAP_SIG_SCHEME_PKCS1_5_SHA256;
                break;
            case ht_sha384:
                *pOutScheme = TAP_SIG_SCHEME_PKCS1_5_SHA384;
                break;
            case ht_sha512:
                *pOutScheme = TAP_SIG_SCHEME_PKCS1_5_SHA512;
                break;
            default:
                /* get it from the key or just set to pkcs1.5 */
                if (TAP_SIG_SCHEME_NONE != inScheme)
                {
                    *pOutScheme = inScheme;
                }
                else
                {
                    *pOutScheme = TAP_SIG_SCHEME_PKCS1_5;
                }      
                break;  
        }
    }
      
exit:

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS CRYPTO_INTERFACE_TAP_RSA_getOrValidateEncScheme(
    ubyte hashAlgo,
    TAP_ENC_SCHEME inScheme,
    TAP_ENC_SCHEME *pOutScheme,
    ubyte padding
    )
{
    MSTATUS status = ERR_RSA_INVALID_ENCRYPTION_SCHEME;

    /* TAP_ENC_SCHEME_NONE is the generic encryption mode. When generating a
     * TAP key with this mode, the appropriate TAP_ENC_SCHEME will be determined
     * by the padding algorithm and padding algorithm parameters.
     *
     * Any other encryption mode restricts the key to just that particular
     * algorithm and an error will be returned if the caller attempts to pass
     * in a padding mode which is incompatabile with that encryption mode. */
    switch (padding)
    {
        /* No padding - TAP_ENC_SCHEME_NONE must be returned. */
        case MOC_RSA_NO_PAD:
            *pOutScheme = TAP_ENC_SCHEME_NONE;
            break;

        /* PKCS v1.5 padding - TAP_ENC_SCHEME_PKCS1_5 must be returned. */
        case MOC_RSA_V15_PAD:
            *pOutScheme = TAP_ENC_SCHEME_PKCS1_5;
            break;

        /* OAEP padding - inScheme must be TAP_ENC_SCHEME_OAEP_* otherwise
         * it is derived from hashAlgo. */
        case MOC_RSA_OAEP_PAD:

            /* Derive TAP_ENC_SCHEME from provided hash algorithm */
            switch (hashAlgo)
            {
                case ht_sha1:
                    *pOutScheme = TAP_ENC_SCHEME_OAEP_SHA1;
                    break;

                case ht_sha256:
                    *pOutScheme = TAP_ENC_SCHEME_OAEP_SHA256;
                    break;

                case ht_sha384:
                    *pOutScheme = TAP_ENC_SCHEME_OAEP_SHA384;
                    break;

                case ht_sha512:
                    *pOutScheme = TAP_ENC_SCHEME_OAEP_SHA512;
                    break;

                default:
                    goto exit;
            }

            break;

        default:
            goto exit;
    }

    status = OK;

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

/*
  Internal API for handling both v1.5 and pss padding.
  hashAlgo, mgfHashAlgo, and saltLen, are only used (as passed in) if isPss is true
  For pss the input should be the raw digest. For v1.5 the input MUST
  be a digestInfo. This is to keep consistent with northside APIs that
  typically pass a digestInfo into the RSA sign API */
static MSTATUS CRYPTO_INTERFACE_TAP_RSA_signInternal (
    MocAsymKey pRSAKey,
    ubyte *pInput,
    ubyte4 inputLen,
    byteBoolean isPss,
    ubyte4 saltLen,
    ubyte hashAlgo,
    ubyte mgfHashAlgo,
    ubyte **ppSig,
    ubyte4 *pSigLen
    )
{
    MSTATUS status = OK, status2;
    TAP_Buffer digestOrData = {0};
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_Signature signature = {0};
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_CredentialList *pCombinedKeyCreds = NULL;
    intBoolean freeKeyCreds = FALSE;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_Key *pTapKey = NULL;
    TAP_Context *pTapContext = NULL;
    MocAsymKey pKey = (MocAsymKey)pRSAKey;
    MRsaTapKeyData *pInfo = NULL;
    ubyte *pSig = NULL;
    TAP_AttributeList opAttributes = {0};
    byteBoolean isDataNotDigest = FALSE;
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_TAP_HYBRID_ASYM_SIGN__)
    TAP_SignatureInfo tapSigInfo = { 0 };
#endif
    TAP_SIG_SCHEME sigScheme = TAP_SIG_SCHEME_NONE;
    TAP_SIG_SCHEME *pSigScheme = &sigScheme;

    /* Extract Digest and Algorithm from DigestInfo */
    ubyte4 digestLen, digestAlg, oidLen;
    ubyte *pOid = NULL;
    ubyte *pDigest = NULL;

    if ((NULL == pInput) || (NULL == ppSig) || (NULL == pSigLen) || ( NULL == pKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pSigLen = 0;

#if (defined(__ENABLE_DIGICERT_TAP_EXTERN__))
    if (OK > ( status = CRYPTO_INTERFACE_TAPExternInit()))
        goto exit;
#endif

    if (isPss)  /* For pss our input is the raw digest */
    {
        digestOrData.pBuffer = pInput;
        digestOrData.bufferLen = inputLen;
    }
    else        /* For pkcs v1.5 we need to get the digest from the digestInfo */
    {
        /* Decode the DigestInfo */
        status = ASN1_parseDigestInfo ( (ubyte*)pInput, inputLen,
                                        &pOid, &oidLen, &pDigest, &digestLen, &digestAlg);
        if (OK != status)
            goto exit;

        digestOrData.pBuffer = pDigest;
        digestOrData.bufferLen = digestLen;
        hashAlgo = (ubyte) digestAlg;
    }

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status = g_pFuncPtrGetTapContext(&pTapContext,
                        &pEntityCredentials,
                        &pKeyCredentials,
                        (void *)pKey, tap_rsa_sign, 1/*get context*/)))
        {
            goto exit;
        }
    }
    else
    {
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
    }

    pInfo = (MRsaTapKeyData *)(pKey->pKeyData);
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
            goto exit1;

        pInfo->isKeyLoaded = TRUE;
    }

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_TAP_HYBRID_ASYM_SIGN__)
    if (isPss)
    {
        pSigScheme = &(tapSigInfo.sigScheme);
    }
#endif
    status = CRYPTO_INTERFACE_TAP_RSA_getSigScheme(hashAlgo, pTapKey->keyData.algKeyInfo.rsaInfo.sigScheme, pSigScheme, isPss);
    if (OK != status)
        goto exit1;

    if (isPss)
    {
        isDataNotDigest = TRUE;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_TAP_HYBRID_ASYM_SIGN__)
        /* Override PSS signature scheme and set PSS parameters provided by
         * caller */
        tapSigInfo.sigScheme = TAP_SIG_SCHEME_PSS;
        status = TAP_UTILS_getTapHashAlgFromHashId(
            hashAlgo, &tapSigInfo.sigInfo.rsaPss.hashAlgo);
        if (OK != status)
        {
            goto exit;
        }
        status = TAP_UTILS_getTapHashAlgFromHashId(
            mgfHashAlgo, &tapSigInfo.sigInfo.rsaPss.mgf.mgfInfo.mgf1.hashAlgo);
        if (OK != status)
        {
            goto exit;
        }
        tapSigInfo.sigInfo.rsaPss.saltLen = saltLen;
        tapSigInfo.sigInfo.rsaPss.mgf.mgfScheme = TAP_MGF1;
#else
        status = DIGI_MALLOC((void **) &opAttributes.pAttributeList, sizeof(TAP_Attribute));
        if (OK != status)
            goto exit;

        opAttributes.pAttributeList->type = TAP_ATTR_SALT_LEN;
        opAttributes.pAttributeList->length = sizeof(saltLen);
        opAttributes.pAttributeList->pStructOfType = (void *) &saltLen;
        opAttributes.listLen = 1;
#endif
    }

    /* Even though TAP_asymSignEx can support PKCS1.5 padding, some SMPs might not support raw siging, so still go through
       TAP_asymSign in non-PSS case */
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_TAP_HYBRID_ASYM_SIGN__)
    if (isPss)
    {
        status = TAP_asymSignEx(pTapKey, pEntityCredentials, &opAttributes, &tapSigInfo, &digestOrData, &signature, pErrContext);
    }
    else
#endif
    {
        status = TAP_asymSign(pTapKey, pEntityCredentials, &opAttributes, sigScheme, isDataNotDigest, &digestOrData, &signature, pErrContext);
    }
    if (OK != status)
        goto exit1;

    status = DIGI_MALLOC((void **) &pSig, signature.signature.rsaSignature.signatureLen);
    if (OK != status)
        goto exit1;

    status = DIGI_MEMCPY(pSig, signature.signature.rsaSignature.pSignature, signature.signature.rsaSignature.signatureLen);
    if (OK != status)
        goto exit1;

    *ppSig = pSig; pSig = NULL;
    *pSigLen = (ubyte4) signature.signature.rsaSignature.signatureLen;

exit1:

    /* no cleanup of digestInfo parsing needed, pointers not allocated */

    if (NULL != pSig)
    {
        (void) DIGI_MEMSET_FREE(&pSig, signature.signature.rsaSignature.signatureLen);
    }

    if (NULL != opAttributes.pAttributeList)
    {
        (void) DIGI_FREE((void **) &opAttributes.pAttributeList);
    }

    if (OK > status)
        DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"RSA sign failed with status = ", status);

    TAP_freeSignature(&signature);

    if(!pInfo->isDeferUnload)
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
                        (void *)pKey, tap_rsa_sign, 0/*release context*/)))
        {
            DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"Tap Context release failed with status = ", status2);
        }
    }
    /* Return 'cleanup' error when it does not override a 'real' error */
    if ((OK != status2) && (OK == status))
    {
        status = status2;
    }
exit:
    if (OK == status)
        status = status2;

    if (freeKeyCreds && (NULL != pCombinedKeyCreds))
    {
        /* Free any internal structures */
        (void) TAP_UTILS_clearCredentialList(pCombinedKeyCreds);
    
        /* Free outer shell */
        (void) DIGI_FREE((void** ) &pCombinedKeyCreds);
    }
    return status;
}

/*---------------------------------------------------------------------------*/

/*
  Internal API for handling both v1.5 and pss padding.
  hashAlgo, mgfHashAlgo, and saltLen, are only used (as passed in) if isPss is true
  For pss the input should be the raw digest. For v1.5 the input MUST
  be a digestInfo. This is to keep consistent with northside APIs that
  typically pass a digestInfo into the RSA sign API */
static MSTATUS CRYPTO_INTERFACE_TAP_RSA_verifyInternal (
    MocAsymKey pRSAKey,
    ubyte* pSignature,
    ubyte* pInput,
    ubyte4 inputLen,
    byteBoolean isPss,
    sbyte4 saltLen,
    ubyte hashAlgo,
    ubyte mgfHashAlgo
    )
{
    MSTATUS status  = OK;
    MSTATUS status2 = OK;
    TAP_Buffer digest = {0};
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_Signature signature = {0};
    TAP_SIG_SCHEME sigScheme = TAP_SIG_SCHEME_NONE;
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_CredentialList *pCombinedKeyCreds = NULL;
    intBoolean freeKeyCreds = FALSE;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    sbyte4 keyLen = 0;
    TAP_OP_EXEC_FLAG opExecFlag = TAP_OP_EXEC_FLAG_HW;
    byteBoolean isSigValid = 0;
    TAP_Key *pTapKey = NULL;
    TAP_Context *pTapContext = NULL;
    MocAsymKey pKey = (MocAsymKey)pRSAKey;
    MRsaTapKeyData *pInfo = NULL;
    ubyte *pOid = NULL, *pDigest = NULL;
    ubyte4 oidLen, digestLen, digestAlg;
    TAP_AttributeList opAttributes = {0};

    if ((NULL == pInput) || (NULL == pSignature) || ( NULL == pKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#if (defined(__ENABLE_DIGICERT_TAP_EXTERN__))
    if (OK > ( status = CRYPTO_INTERFACE_TAPExternInit()))
        goto exit;
#endif

    if (isPss)  /* For pss our input is the raw digest */
    {
        digest.pBuffer = pInput;
        digest.bufferLen = inputLen;
    }
    else        /* For pkcs v1.5 we need to get the digest from the digestInfo */
    {
        /* Decode the DigestInfo */
        status = ASN1_parseDigestInfo ( (ubyte*)pInput, inputLen,
                                        &pOid, &oidLen, &pDigest, &digestLen, &digestAlg);
        if (OK != status)
            goto exit;

        digest.pBuffer = pDigest;
        digest.bufferLen = digestLen;
        hashAlgo = (ubyte) digestAlg;
    }

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status = g_pFuncPtrGetTapContext(&pTapContext,
                                                    &pEntityCredentials,
                                                    &pKeyCredentials,
                                                    (void *)pKey, tap_rsa_verify, 1/*get context*/)))
        {
            goto exit;
        }
    }
    else
    {
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
    }

    pInfo = (MRsaTapKeyData *)(pKey->pKeyData);
    pTapKey = (TAP_Key *)pInfo->pKey;

    ubyte keySize = pTapKey->keyData.algKeyInfo.rsaInfo.keySize;
    switch(keySize)
    {
        case TAP_KEY_SIZE_1024:
            keyLen = (1024/8);
            break;
        case TAP_KEY_SIZE_2048:
            keyLen = (2048/8);
            break;
        case TAP_KEY_SIZE_3072:
            keyLen = (3072/8);
            break;
        case TAP_KEY_SIZE_4096:
            keyLen = (4096/8);
            break;
        case TAP_KEY_SIZE_8192:
            keyLen = (8192/8);
            break;
        default:
            status = ERR_TAP_INVALID_KEY_SIZE;
            goto exit;
    }

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

    signature.signature.rsaSignature.pSignature = (ubyte*) pSignature;
    signature.signature.rsaSignature.signatureLen = keyLen;
    signature.isDEREncoded = FALSE;
    signature.keyAlgorithm = TAP_KEY_ALGORITHM_RSA;

    status = CRYPTO_INTERFACE_TAP_RSA_getSigScheme(hashAlgo, pTapKey->keyData.algKeyInfo.rsaInfo.sigScheme, &sigScheme, isPss);
    if (OK != status)
        goto exit;

    if (isPss)
    {
        status = DIGI_MALLOC((void **) &opAttributes.pAttributeList, sizeof(TAP_Attribute));
        if (OK != status)
            goto exit;

        opAttributes.pAttributeList->type = TAP_ATTR_SALT_LEN;
        opAttributes.pAttributeList->length = sizeof(saltLen);
        opAttributes.pAttributeList->pStructOfType = (void *) &saltLen;
        opAttributes.listLen = 1;
    }

    status = TAP_asymVerifySignature(pTapKey, pEntityCredentials, &opAttributes, opExecFlag,
            sigScheme, &digest, &signature, &isSigValid, pErrContext);

    if (!isSigValid)
    {
        status = ERR_TAP_SIGN_VERIFY_FAIL;
        DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"RSA verify signature failed with status = ", status);
    }

    if(!pInfo->isDeferUnload)
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
                                                    (void *)pKey, tap_rsa_verify, 0/*release context*/)))
        {
            DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"TAP Context release failed with status = ", status2);
        }
    }

exit:

    /* no cleanup of digestInfo parsing needed, pointers not allocated */

    if (NULL != opAttributes.pAttributeList)
    {
        (void) DIGI_FREE((void **) &opAttributes.pAttributeList);
    }

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
}

/*---------------------------------------------------------------------------*/

static MSTATUS CRYPTO_INTERFACE_TAP_RSA_encryptInternal (
    MocAsymKey pKey,
    ubyte *pPlainText,
    ubyte4 plainTextLen,
    ubyte **ppCipherText,
    ubyte4 *pCipherLen,
    ubyte padding,
    ubyte hashAlgo,
    ubyte mgfHashAlgo,
    ubyte *pLabel,
    ubyte4 labelLen
    )
{
    MSTATUS status  = OK;
    MSTATUS status2 = OK;
    TAP_ErrorContext *pErrContext = NULL;
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_CredentialList *pCombinedKeyCreds = NULL;
    intBoolean freeKeyCreds = FALSE;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_Buffer inData = { 0 };
    TAP_Buffer encryptedData = { 0 };
    TAP_OP_EXEC_FLAG opExecFlag = TAP_OP_EXEC_FLAG_HW;
    TAP_Key *pTapKey = NULL;
    TAP_Context *pTapContext = NULL;
    MRsaTapKeyData *pInfo = NULL;
    TAP_ENC_SCHEME encScheme = TAP_ENC_SCHEME_NONE;
    TAP_AttributeList opAttributes = {0};
    TAP_Buffer label = {0};

    ubyte *pCipher = NULL;

    if ((NULL == pKey) || (NULL == ppCipherText) || (NULL == pPlainText) || NULL == pCipherLen)
    {
        return ERR_NULL_POINTER;
    }

    inData.pBuffer = pPlainText;
    inData.bufferLen = plainTextLen;

    pInfo = (MRsaTapKeyData *)(pKey->pKeyData);
    if (NULL == pInfo)
    {
        return ERR_NULL_POINTER;
    }

    pTapKey = (TAP_Key *)pInfo->pKey;
    if (NULL == pTapKey)
    {
        return ERR_NULL_POINTER;
    }

    status = CRYPTO_INTERFACE_TAP_RSA_getOrValidateEncScheme(hashAlgo, pTapKey->keyData.algKeyInfo.rsaInfo.encScheme,
                                                            &encScheme, padding);
    if (OK != status)
        goto exit;

#if (defined(__ENABLE_DIGICERT_TAP_EXTERN__))
    if (OK > ( status = CRYPTO_INTERFACE_TAPExternInit()))
        goto exit;
#endif

    pInfo = (MRsaTapKeyData *)(pKey->pKeyData);
    pTapKey = (TAP_Key *)pInfo->pKey;

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status = g_pFuncPtrGetTapContext(&pTapContext,
                                                    &pEntityCredentials,
                                                    &pKeyCredentials,
                                                    (void *)pKey, tap_rsa_encrypt, 1/*get context*/)))
        {
            goto exit1;
        }
    }
    else
    {
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
    }

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

    if (NULL != pLabel && labelLen)
    {
        status = DIGI_MALLOC((void **) &opAttributes.pAttributeList, sizeof(TAP_Attribute));
        if (OK != status)
            goto exit;

        label.pBuffer = pLabel;
        label.bufferLen = labelLen;
        opAttributes.pAttributeList->type = TAP_ATTR_ENC_LABEL;
        opAttributes.pAttributeList->length = sizeof(TAP_Buffer);
        opAttributes.pAttributeList->pStructOfType = &label;
        opAttributes.listLen = 1;
    }

    status = TAP_asymEncrypt(pTapKey, pEntityCredentials, &opAttributes, opExecFlag, encScheme,
            &inData, &encryptedData, pErrContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d TAP_asymEncrypt status=%d", __FUNCTION__, __LINE__, status);
        goto exit1;
    }

    if (OK != (status = DIGI_MALLOC((void **) &pCipher, encryptedData.bufferLen)))
    {
        goto exit1;
    }

    if (OK != (status = DIGI_MEMCPY(pCipher, encryptedData.pBuffer, encryptedData.bufferLen)))
    {
        goto exit1;
    }

    *ppCipherText = pCipher; pCipher = NULL;
    *pCipherLen = (ubyte4) encryptedData.bufferLen;

exit1:

    if (NULL != pCipher)
    {
        (void) DIGI_MEMSET_FREE(&pCipher, encryptedData.bufferLen);
    }

    if (NULL != opAttributes.pAttributeList)
    {
        (void) DIGI_FREE((void **) &opAttributes.pAttributeList);
    }

    if (OK > status)
        DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"RSA encrypt failed with status = ", status);

    if (NULL != encryptedData.pBuffer)
    {
        TAP_UTILS_freeBuffer(&encryptedData);
    }

    if(!pInfo->isDeferUnload)
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
                                                    (void *)pKey, tap_rsa_encrypt, 0/*release context*/)))
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

    if (OK == status)
        status = status2;

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS CRYPTO_INTERFACE_TAP_RSA_decryptInternal (
    MocAsymKey pRSAKey,
    ubyte* pCipherText,
    ubyte** ppPlainText,
    ubyte4 *pPlainTextLen,
    ubyte padding,
    ubyte hashAlgo,
    ubyte mgfHashAlgo,
    ubyte *pLabel,
    ubyte4 labelLen
    )
{
    MSTATUS status  = OK;
    MSTATUS status2 = OK;
    TAP_ErrorContext *pErrContext = NULL;
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_CredentialList *pCombinedKeyCreds = NULL;
    intBoolean freeKeyCreds = FALSE;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_Buffer inData = { 0 };
    TAP_Buffer decryptedData = { 0 };
    ubyte4 cipherTextLen = 0;
    TAP_Key *pTapKey = NULL;
    TAP_Context *pTapContext = NULL;
    MocAsymKey pKey = (MocAsymKey)pRSAKey;
    MRsaTapKeyData *pInfo = NULL;
    TAP_ENC_SCHEME encScheme = TAP_ENC_SCHEME_NONE;
    TAP_AttributeList opAttributes = {0};
    TAP_Buffer label = {0};

    ubyte *pPlain = NULL;

    if ((NULL == pRSAKey) || (NULL == pCipherText) || (NULL == ppPlainText) || (NULL == pPlainTextLen))
    {
        return ERR_NULL_POINTER;
    }

    pInfo = (MRsaTapKeyData *)(pKey->pKeyData);
    if (NULL == pInfo)
    {
        return ERR_NULL_POINTER;
    }

    pTapKey = (TAP_Key *)pInfo->pKey;
    if (NULL == pTapKey)
    {
        return ERR_NULL_POINTER;
    }

    status = CRYPTO_INTERFACE_TAP_RSA_getOrValidateEncScheme(hashAlgo, pTapKey->keyData.algKeyInfo.rsaInfo.encScheme,
                                                            &encScheme, padding);
    if (OK != status)
        goto exit;

#if (defined(__ENABLE_DIGICERT_TAP_EXTERN__))
    if (OK > ( status = CRYPTO_INTERFACE_TAPExternInit()))
        goto exit;
#endif

    pInfo = (MRsaTapKeyData *)(pKey->pKeyData);
    pTapKey = (TAP_Key *)pInfo->pKey;

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status = g_pFuncPtrGetTapContext(&pTapContext,
                                                    &pEntityCredentials,
                                                    &pKeyCredentials,
                                                    (void *)pKey, tap_rsa_decrypt, 1/*get context*/)))
        {
            goto exit1;
        }
    }
    else
    {
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
    }

    ubyte keySize = pTapKey->keyData.algKeyInfo.rsaInfo.keySize;
    switch(keySize)
    {
        case TAP_KEY_SIZE_1024:
            cipherTextLen = (1024/8);
            break;
        case TAP_KEY_SIZE_2048:
            cipherTextLen = (2048/8);
            break;
        case TAP_KEY_SIZE_3072:
            cipherTextLen = (3072/8);
            break;
        case TAP_KEY_SIZE_4096:
            cipherTextLen = (4096/8);
            break;
        case TAP_KEY_SIZE_8192:
            cipherTextLen = (8192/8);
            break;
        default:
            status = ERR_TAP_INVALID_KEY_SIZE;
            goto exit1;
    }

    inData.pBuffer = pCipherText;
    inData.bufferLen = cipherTextLen;

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

        status = TAP_loadKey(pTapContext, pEntityCredentials, pTapKey,pCombinedKeyCreds, NULL, pErrContext);
        if (OK != status)
            goto exit1;

        pInfo->isKeyLoaded = TRUE;
    }

    if (NULL != pLabel && labelLen)
    {
        status = DIGI_MALLOC((void **) &opAttributes.pAttributeList, sizeof(TAP_Attribute));
        if (OK != status)
            goto exit;

        label.pBuffer = pLabel;
        label.bufferLen = labelLen;
        opAttributes.pAttributeList->type = TAP_ATTR_ENC_LABEL;
        opAttributes.pAttributeList->length = sizeof(TAP_Buffer);
        opAttributes.pAttributeList->pStructOfType = &label;
        opAttributes.listLen = 1;
    }

    status = TAP_asymDecrypt(pTapKey, pEntityCredentials, &opAttributes, encScheme,
            &inData, &decryptedData, pErrContext);

    if (OK != status)
        goto exit1;

    if (OK != (status = DIGI_MALLOC((void **) &pPlain, decryptedData.bufferLen)))
    {
        goto exit1;
    }

    if (OK != (status = DIGI_MEMCPY(pPlain, decryptedData.pBuffer, decryptedData.bufferLen)))
    {
        goto exit1;
    }

    *ppPlainText = pPlain; pPlain = NULL;
    *pPlainTextLen = (ubyte4) decryptedData.bufferLen;

exit1:

    if (NULL != pPlain)
    {
        (void) DIGI_MEMSET_FREE(&pPlain, decryptedData.bufferLen);
    }

    if (NULL != opAttributes.pAttributeList)
    {
        (void) DIGI_FREE((void **) &opAttributes.pAttributeList);
    }

    if (OK > status)
        DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"RSA decrypt failed with status = ", status);

    if (NULL != decryptedData.pBuffer)
        shredMemory(&(decryptedData.pBuffer), decryptedData.bufferLen, TRUE);

    if(!pInfo->isDeferUnload)
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
                                                    (void *)pKey, tap_rsa_decrypt, 0/*release context*/)))
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
}
#endif /*  __ENABLE_DIGICERT_TAP__ */

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_RSA_signDigestInfo (
    MocAsymKey pRSAKey,
    ubyte *pDigestInfo,
    ubyte4 digestInfoLen,
    ubyte *pSignature,
    vlong **ppVlongQueue
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = OK;

    ubyte *pSig = NULL;
    ubyte4 sigLen = 0;

    MOC_UNUSED(ppVlongQueue);

    /* input validation done by below call */

    status = CRYPTO_INTERFACE_TAP_RSA_signInternal (pRSAKey, pDigestInfo, digestInfoLen, FALSE,
                                                               0, 0, 0, &pSig, &sigLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pSignature, pSig, sigLen);

exit:

    if (NULL != pSig)
    {
        (void) DIGI_MEMSET_FREE(&pSig, sigLen);
    }

    return status;

#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_PKCS1_rsaPssSignData (
    randomContext *pRandomContext,
    MocAsymKey pKey,
    ubyte hashAlgo,
    ubyte mgfAlgo,
    ubyte mgfHashAlgo,
    ubyte *pDigest,
    ubyte4 digestLen,
    ubyte4 saltLen,
    ubyte **ppSignature,
    ubyte4 *pSignatureLen
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MOC_UNUSED(pRandomContext);
    MOC_UNUSED(mgfAlgo);

    return CRYPTO_INTERFACE_TAP_RSA_signInternal (pKey, pDigest, digestLen, TRUE, saltLen,
                                                  hashAlgo, mgfHashAlgo, ppSignature, pSignatureLen);
#else
    return ERR_TAP_UNSUPPORTED;
#endif /* __ENABLE_DIGICERT_TAP__ */
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_RSA_verifyDigestInfo (
    MocAsymKey pRSAKey,
    ubyte* pSignature,
    ubyte* pDigestInfo,
    ubyte4 digestInfoLen,
    vlong **ppVlongQueue
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MOC_UNUSED(ppVlongQueue);

    return CRYPTO_INTERFACE_TAP_RSA_verifyInternal (pRSAKey, pSignature, pDigestInfo, digestInfoLen,
                                                    FALSE, 0, 0, 0);
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_PKCS1_rsaPssVerifyDigest (
    MocAsymKey pKey,
    ubyte hashAlgo,
    ubyte mgfAlgo,
    ubyte mgfHashAlgo,
    ubyte *pDigest,
    ubyte4 digestLen,
    ubyte *pSignature,
    ubyte4 signatureLen,
    sbyte4 saltLen,
    ubyte4 *pVerify
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = OK;

    MOC_UNUSED(mgfHashAlgo);
    MOC_UNUSED(signatureLen);

    status = CRYPTO_INTERFACE_TAP_RSA_verifyInternal (pKey, pSignature, pDigest, digestLen, TRUE,
                                                      saltLen, hashAlgo, mgfHashAlgo);
    if (OK == status)
    {
        *pVerify = 0;
    }
    else
    {
        *pVerify = 1;
    }

    if (ERR_TAP_SIGN_VERIFY_FAIL == status)
       status = OK;

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_RSA_encrypt (
    MocAsymKey pRSAKey,
    ubyte *pPlainText,
    ubyte4 plainTextLen,
    ubyte *pCipherText,
    RNGFun rngFun,
    void *rngFunArg,
    vlong **ppVlongQueue
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = OK;

    ubyte *pCipher = NULL;
    ubyte4 cipherLen = 0;

    MOC_UNUSED(rngFun);
    MOC_UNUSED(rngFunArg);
    MOC_UNUSED(ppVlongQueue);

    /* rest of params checked for NULL in below call */
    if (NULL == pCipherText)
    {
        return ERR_NULL_POINTER;
    }

    status = CRYPTO_INTERFACE_TAP_RSA_encryptInternal (pRSAKey, pPlainText, plainTextLen, &pCipher, &cipherLen,
                                                        MOC_RSA_V15_PAD, 0, 0, NULL, 0);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pCipherText, pCipher, cipherLen);

exit:

    if (NULL != pCipher)
    {
        (void) DIGI_MEMSET_FREE(&pCipher, cipherLen);
    }

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_PKCS1_rsaOaepEncrypt(
    MocAsymKey pKey,
    ubyte hashAlgo,
    ubyte mgfAlgo,
    ubyte mgfHashAlgo,
    ubyte *pMessage,
    ubyte4 mLen,
    ubyte *pLabel,
    ubyte4 lLen,
    ubyte **ppCipherText,
    ubyte4 *pCipherTextLen
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MOC_UNUSED(mgfAlgo);

    return CRYPTO_INTERFACE_TAP_RSA_encryptInternal (pKey, pMessage, mLen, ppCipherText, pCipherTextLen, MOC_RSA_OAEP_PAD,
                                                      hashAlgo, mgfHashAlgo, pLabel, lLen);
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_RSA_decrypt (
    MocAsymKey pRSAKey,
    ubyte *pCipherText,
    ubyte *pPlainText,
    ubyte4 *pPlainTextLen,
    RNGFun rngFun,
    void *rngFunArg,
    vlong **ppVlongQueue
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = OK;

    ubyte *pPlain = NULL;
    ubyte4 plainLen = 0;

    MOC_UNUSED(ppVlongQueue);
    MOC_UNUSED(rngFun);
    MOC_UNUSED(rngFunArg);

    /* rest of params checked for NULL in below call */
    if (NULL == pPlainText || NULL == pPlainTextLen)
    {
        return ERR_NULL_POINTER;
    }

    status = CRYPTO_INTERFACE_TAP_RSA_decryptInternal(pRSAKey, pCipherText, &pPlain, &plainLen, MOC_RSA_V15_PAD,
                                                       0, 0, NULL, 0);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pPlainText, pPlain, plainLen);
    if (OK != status)
        goto exit;

    *pPlainTextLen = plainLen;

exit:

    if (NULL != pPlain)
    {
        (void) DIGI_MEMSET_FREE(&pPlain, plainLen);
    }

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_PKCS1_rsaOaepDecrypt(
    MocAsymKey pKey,
    ubyte hashAlgo,
    ubyte mgfAlgo,
    ubyte mgfHashAlgo,
    ubyte *pCipherText,
    ubyte4 cLen,
    ubyte *pLabel,
    ubyte4 lLen,
    ubyte **ppPlainText,
    ubyte4 *pPlainTextLen
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MOC_UNUSED(mgfAlgo);

    return CRYPTO_INTERFACE_TAP_RSA_decryptInternal(pKey, pCipherText, ppPlainText, pPlainTextLen, MOC_RSA_OAEP_PAD,
                                                     hashAlgo, mgfHashAlgo, pLabel, lLen);
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_RSA_applyPrivateKey (
    MocAsymKey pRSAKey,
    RNGFun rngFun,
    void *rngFunArg,
    const ubyte *pInput,
    ubyte4 inputLen,
    ubyte *pOutput,
    ubyte4 *pOutputLen,
    vlong **ppVlongQueue
    )
{
#if defined(__ENABLE_DIGICERT_TAP__)
    MSTATUS status = OK;

    ubyte *pOut = NULL;
    ubyte4 outLen = 0;

    MOC_UNUSED(ppVlongQueue);
    MOC_UNUSED(inputLen);
    MOC_UNUSED(rngFun);
    MOC_UNUSED(rngFunArg);

    /* rest of params checked for NULL in below call */
    if (NULL == pOutput || NULL == pOutputLen)
    {
        return ERR_NULL_POINTER;
    }

    status = CRYPTO_INTERFACE_TAP_RSA_decryptInternal(pRSAKey, (ubyte* ) pInput, &pOut, &outLen, MOC_RSA_NO_PAD,
                                                       0, 0, NULL, 0);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pOutput, pOut, outLen);
    if (OK != status)
        goto exit;

    *pOutputLen = outLen;

exit:

    if (NULL != pOut)
    {
        (void) DIGI_MEMSET_FREE(&pOut, outLen);
    }

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_TAP_RSA_applyPublicKey (
    MocAsymKey pRSAKey,
    const ubyte *pInput,
    ubyte4 inputLen,
    ubyte *pOutput,
    vlong **ppVlongQueue
    )
{
#if defined(__ENABLE_DIGICERT_TAP__)
    MSTATUS status = OK;

    ubyte *pOut = NULL;
    ubyte4 outLen = 0;

    MOC_UNUSED(ppVlongQueue);

    /* rest of params checked for NULL in below call */
    if (NULL == pOutput)
    {
        return ERR_NULL_POINTER;
    }

    status = CRYPTO_INTERFACE_TAP_RSA_encryptInternal (pRSAKey, (ubyte *) pInput, inputLen, &pOut, &outLen, MOC_RSA_NO_PAD,
                                                        0, 0, NULL, 0);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pOutput, pOut, outLen);

exit:

    if (NULL != pOut)
    {
        (void) DIGI_MEMSET_FREE(&pOut, outLen);
    }

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

#if defined(__ENABLE_DIGICERT_TAP__)

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_TAP_RSA_wrapSymKey (
    TAP_Context *pTapContext,
    TAP_EntityCredentialList *pUsageCredentials,
    TAP_CredentialList *pKeyCredentials,
    RSAKey *pRSASwPub,
    ubyte *pKeyToBeWrappedId,
    ubyte4 keyToBeWrappedIdLen,
    ubyte useOAEP,
    ubyte hashAlgo,
    ubyte *pLabel,
    ubyte4 labelLen,
    ubyte **ppOutDuplicate,
    ubyte4 *pOutDuplicateLen
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MRsaKeyTemplate keyData;
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_AttributeList createAttributes = {0};
    TAP_AttributeList opAttributes = {0};
    TAP_Key *pPubTapKey = NULL;
    TAP_KeyInfo pubKeyInfo = {0};
    TAP_Buffer pubKeyBlob = {0};
    TAP_Buffer label = {0};
    TAP_Buffer out = {0};
    TAP_Buffer ktbwId = {0};
    TAP_ENC_SCHEME encScheme;
    ubyte *pBlob = NULL;
    ubyte4 blobLen = 0;
    ubyte wrapType = TAP_KEY_WRAP_RSA;
    ubyte4 tokenFalse = 0;
    ubyte4 numAttrs = 2;

    if ( (NULL == pRSASwPub) || (NULL == ppOutDuplicate) || (NULL == pTapContext) ||
         (NULL == pKeyToBeWrappedId) || (0 == keyToBeWrappedIdLen) )
    {
        goto exit;
    }

    ktbwId.pBuffer = pKeyToBeWrappedId;
    ktbwId.bufferLen = keyToBeWrappedIdLen;

    /* Get the raw public key data from the RSA SW key */
    status = CRYPTO_INTERFACE_RSA_getKeyParametersAllocAux(pRSASwPub, &keyData, MOC_GET_PUBLIC_KEY_DATA);
    if (OK != status)
        goto exit;

    /* Construct the key blob the PKCS11 SMP expects. Format is:
     * modLen (4 bytes) || modulus || exponentLen (4 bytes) || exponent */
    blobLen = 8 + keyData.nLen + keyData.eLen;
    status = DIGI_CALLOC((void **)&pBlob, 1, blobLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)pBlob, (void *)&keyData.nLen, sizeof(ubyte4));
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)(pBlob + 4), (void *)keyData.pN, keyData.nLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)(pBlob + 4 + keyData.nLen), (void *)&keyData.eLen, sizeof(ubyte4));
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)(pBlob + 4 + keyData.nLen + 4), (void *)keyData.pE, keyData.eLen);
    if (OK != status)
        goto exit;

    /* Prepare the attributes for creating RSA public key */
    status = DIGI_MALLOC((void **) &createAttributes.pAttributeList, sizeof(TAP_Attribute) * 2);
    if (OK != status)
        goto exit;

    pubKeyBlob.pBuffer = pBlob;
    pubKeyBlob.bufferLen = blobLen;

    createAttributes.pAttributeList[0].type = TAP_ATTR_OBJECT_VALUE;
    createAttributes.pAttributeList[0].length = sizeof(TAP_Buffer);
    createAttributes.pAttributeList[0].pStructOfType = (void *) &pubKeyBlob;

    /* Make as a session object */
    createAttributes.pAttributeList[1].type = TAP_ATTR_TOKEN_OBJECT;
    createAttributes.pAttributeList[1].length = sizeof(ubyte4);
    createAttributes.pAttributeList[1].pStructOfType = (void *) &tokenFalse;
    createAttributes.listLen = 2;

    pubKeyInfo.keyAlgorithm = TAP_KEY_ALGORITHM_RSA;

    status = TAP_asymCreatePubKey (
        pTapContext, pUsageCredentials, &pubKeyInfo, &createAttributes, 
        pKeyCredentials, &pPubTapKey, pErrContext);
    if (OK != status)
        goto exit;

    if (TRUE == useOAEP)
    {
        numAttrs++;
        wrapType = TAP_KEY_WRAP_RSA_OAEP;

        switch (hashAlgo)
        {
            case ht_sha1:
                encScheme = TAP_ENC_SCHEME_OAEP_SHA1;
                break;

            case ht_sha256:
                encScheme = TAP_ENC_SCHEME_OAEP_SHA256;
                break;

            case ht_sha384:
                encScheme = TAP_ENC_SCHEME_OAEP_SHA384;
                break;

            case ht_sha512:
                encScheme = TAP_ENC_SCHEME_OAEP_SHA512;
                break;

            default:
                status = ERR_INVALID_INPUT;
                goto exit;
        }

        if (NULL != pLabel)
            numAttrs++;
    }



    /* Prepare the attributes for RSA key wrap using the newly established public key */
    status = DIGI_MALLOC((void **) &opAttributes.pAttributeList, sizeof(TAP_Attribute) * numAttrs);
    if (OK != status)
        goto exit;

    opAttributes.pAttributeList[0].type = TAP_ATTR_KEY_WRAP_TYPE;
    opAttributes.pAttributeList[0].length = sizeof(ubyte);
    opAttributes.pAttributeList[0].pStructOfType = (void *) &wrapType;
    opAttributes.pAttributeList[1].type = TAP_ATTR_KEY_TO_BE_WRAPPED_ID;
    opAttributes.pAttributeList[1].length = sizeof(TAP_Buffer);
    opAttributes.pAttributeList[1].pStructOfType = (void *) &ktbwId;
    opAttributes.listLen = 2;

    if (TRUE == useOAEP)
    {
        opAttributes.pAttributeList[2].type = TAP_ATTR_ENC_SCHEME;
        opAttributes.pAttributeList[2].length = sizeof(TAP_ENC_SCHEME);
        opAttributes.pAttributeList[2].pStructOfType = (void *) &encScheme;
        opAttributes.listLen++;
    }

    if ( (TRUE == useOAEP) && (NULL != pLabel) )
    {   
        label.pBuffer = pLabel;
        label.bufferLen = labelLen;
        opAttributes.pAttributeList[opAttributes.listLen].type = TAP_ATTR_ENC_LABEL;
        opAttributes.pAttributeList[opAttributes.listLen].length = sizeof(TAP_Buffer);
        opAttributes.pAttributeList[opAttributes.listLen].pStructOfType = &label;
        opAttributes.listLen++;
    }

    status = TAP_exportDuplicateKey(pPubTapKey, pUsageCredentials, &opAttributes, NULL, &out, pErrContext);
    if (OK != status)
        goto exit;

    *ppOutDuplicate = out.pBuffer;
    *pOutDuplicateLen = out.bufferLen;
    out.pBuffer = NULL;

exit:

    CRYPTO_INTERFACE_RSA_freeKeyTemplateAux(pRSASwPub, &keyData);

    if (NULL != pPubTapKey)
    {
        TAP_freeKey(&pPubTapKey);
    }
    if (NULL != opAttributes.pAttributeList)
    {
        (void) DIGI_FREE((void **) &opAttributes.pAttributeList);
    }
    if (NULL != createAttributes.pAttributeList)
    {
        (void) DIGI_FREE((void **) &createAttributes.pAttributeList);
    }
    if (NULL != pBlob)
    {
        (void) DIGI_FREE((void **)&pBlob);
    }

    return status;
}


MSTATUS CRYPTO_INTERFACE_TAP_getKeyTypeFromKeyInfo(TAP_KeyInfo *pKeyInfo, ubyte4 *pKeyType, MSymOperator *ppOperator)
{
    ubyte4 keyType;
    MSymOperator operator;

    if ( (NULL == pKeyInfo) || (NULL == pKeyType) || (NULL == ppOperator) )
    {
        return ERR_NULL_POINTER;
    }

    switch(pKeyInfo->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_AES:
        {
            operator = MAesTapOperator;
            switch(pKeyInfo->algKeyInfo.aesInfo.symMode)
            {
                case TAP_SYM_KEY_MODE_CTR:
                    keyType = MOC_SYM_ALG_AES_CTR;
                    break;

                case TAP_SYM_KEY_MODE_OFB:
                    keyType = MOC_SYM_ALG_AES_OFB;
                    break;

                case TAP_SYM_KEY_MODE_CBC:
                    keyType = MOC_SYM_ALG_AES_CBC;
                    break;

                case TAP_SYM_KEY_MODE_CFB:
                    keyType = MOC_SYM_ALG_AES_CFB;
                    break;

                case TAP_SYM_KEY_MODE_ECB:
                    keyType = MOC_SYM_ALG_AES_ECB;
                    break;

                case TAP_SYM_KEY_MODE_GCM:
                    keyType = MOC_SYM_ALG_AES_GCM;
                    break;

                case TAP_SYM_KEY_MODE_UNDEFINED:
                    keyType = MOC_SYM_ALG_AES;
                    break;

                default:
                    keyType = MOC_SYM_ALG_AES;
                    break;
            }
            break;
        }

        case TAP_KEY_ALGORITHM_DES:
        {
            operator = MDesTapOperator;
            switch(pKeyInfo->algKeyInfo.desInfo.symMode)
            {
                case TAP_SYM_KEY_MODE_CBC:
                    keyType = MOC_SYM_ALG_DES_CBC;
                    break;

                case TAP_SYM_KEY_MODE_ECB:
                    keyType = MOC_SYM_ALG_DES_ECB;
                    break;

                case TAP_SYM_KEY_MODE_UNDEFINED:
                    keyType = MOC_SYM_ALG_DES;
                    break;

                default:
                    keyType = MOC_SYM_ALG_DES;
                    break;
            }

            break;
        }

        case TAP_KEY_ALGORITHM_TDES:
        {
            operator = MTDesTapOperator;
            switch(pKeyInfo->algKeyInfo.tdesInfo.symMode)
            {
                case TAP_SYM_KEY_MODE_CBC:
                    keyType = MOC_SYM_ALG_TDES_CBC;
                    break;

                case TAP_SYM_KEY_MODE_ECB:
                    keyType = MOC_SYM_ALG_TDES_ECB;
                    break;

                case TAP_SYM_KEY_MODE_UNDEFINED:
                    keyType = MOC_SYM_ALG_TDES;
                    break;

                default:
                    keyType = MOC_SYM_ALG_TDES;
                    break;
            }

            break;
        }

        case TAP_KEY_ALGORITHM_HMAC:
        {
            operator = MHmacTapOperator;
            keyType = MOC_SYM_ALG_HMAC;
            break;
        }

        default:
            return ERR_INVALID_INPUT;
    }

    *pKeyType = keyType;
    *ppOperator = operator;
    return OK;
}

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_TAP_RSA_unwrapSymKey (
    TAP_Context *pTapContext,
    TAP_EntityCredentialList *pUsageCredentials,
    TAP_CredentialList *pKeyCredentials,
    TAP_KeyInfo *pKeyInfo,
    ubyte *pWrappingKeyId,
    ubyte4 wrappingKeyIdLen,
    ubyte useOAEP,
    ubyte hashAlgo,
    ubyte *pLabel,
    ubyte4 labelLen,
    ubyte *pDuplicateKey,
    ubyte4 duplicateKeyLen,
    SymmetricKey **ppNewKey
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_Key *pNewTapKey = NULL;
    TAP_AttributeList opAttributes = {0};
    TAP_Buffer tempBuf = {0};
    TAP_Buffer label = {0};
    TAP_Buffer wkId = {0};
    TAP_ENC_SCHEME encScheme;
    MSymTapKeyGenArgs keyGenArgs = {0};
    SymmetricKey *pNewSymKey = NULL;
    MocSymCtx pNewSymCtx = NULL;
    MTapKeyData *pKeyData = NULL;
    ubyte4 keyType = 0;
    MocCtx pMocCtx = NULL;
    MSymOperator operator = NULL;
    ubyte wrapType = TAP_KEY_WRAP_RSA;
    ubyte4 numAttrs = 2;

    if ((NULL == pTapContext) || (NULL == pKeyInfo) || (NULL == pDuplicateKey) || 
        (NULL == ppNewKey) || (NULL == pWrappingKeyId))
    {
        goto exit;
    }

    wkId.pBuffer = pWrappingKeyId;
    wkId.bufferLen = wrappingKeyIdLen;

    if (TRUE == useOAEP)
    {
        numAttrs++;
        wrapType = TAP_KEY_WRAP_RSA_OAEP;

        switch (hashAlgo)
        {
            case ht_sha1:
                encScheme = TAP_ENC_SCHEME_OAEP_SHA1;
                break;

            case ht_sha256:
                encScheme = TAP_ENC_SCHEME_OAEP_SHA256;
                break;

            case ht_sha384:
                encScheme = TAP_ENC_SCHEME_OAEP_SHA384;
                break;

            case ht_sha512:
                encScheme = TAP_ENC_SCHEME_OAEP_SHA512;
                break;

            default:
                status = ERR_INVALID_INPUT;
                goto exit;
        }

        if (NULL != pLabel)
            numAttrs++;
    }

    status = DIGI_MALLOC((void **) &opAttributes.pAttributeList, sizeof(TAP_Attribute) * numAttrs);
    if (OK != status)
        goto exit;

    opAttributes.pAttributeList[0].type = TAP_ATTR_WRAPPING_KEY_ID;
    opAttributes.pAttributeList[0].length = sizeof(TAP_Buffer);
    opAttributes.pAttributeList[0].pStructOfType = (void *) &wkId;
    opAttributes.pAttributeList[1].type = TAP_ATTR_KEY_WRAP_TYPE;
    opAttributes.pAttributeList[1].length = sizeof(ubyte);
    opAttributes.pAttributeList[1].pStructOfType = (void *) &wrapType;
    opAttributes.listLen = 2;

    if (TRUE == useOAEP)
    {
        opAttributes.pAttributeList[2].type = TAP_ATTR_ENC_SCHEME;
        opAttributes.pAttributeList[2].length = sizeof(TAP_ENC_SCHEME);
        opAttributes.pAttributeList[2].pStructOfType = (void *) &encScheme;
        opAttributes.listLen++;
    }

    if ( (TRUE == useOAEP) && (NULL != pLabel) )
    {   
        label.pBuffer = pLabel;
        label.bufferLen = labelLen;
        opAttributes.pAttributeList[opAttributes.listLen].type = TAP_ATTR_ENC_LABEL;
        opAttributes.pAttributeList[opAttributes.listLen].length = sizeof(TAP_Buffer);
        opAttributes.pAttributeList[opAttributes.listLen].pStructOfType = &label;
        opAttributes.listLen++;
    }

    tempBuf.pBuffer = pDuplicateKey;
    tempBuf.bufferLen = duplicateKeyLen;

    status = TAP_importDuplicateKey (
        pTapContext, pUsageCredentials, pKeyInfo, &tempBuf, &opAttributes, 
        pKeyCredentials, &pNewTapKey, pErrContext);
    if (OK != status)
        goto exit;

    keyGenArgs.keyAlgorithm = pKeyInfo->keyAlgorithm;
    keyGenArgs.pTapCtx = pTapContext;
    keyGenArgs.pEntityCredentials = pUsageCredentials;
    keyGenArgs.pKeyCredentials = pKeyCredentials;

    /* Wrap the new TAP key up into a SymmetricKey structure */

    /* Get a reference to the Tap MocCtx within the Crypto Interface Core */
    status = CRYPTO_INTERFACE_getTapMocCtx(&pMocCtx);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_TAP_getKeyTypeFromKeyInfo(pKeyInfo, &keyType, &operator);
    if (OK != status)
        goto exit;

    status = CRYPTO_createMocSymCtx(operator, (void *)&keyGenArgs, pMocCtx, &pNewSymCtx);
    if (OK != status)
        goto exit;

    /* Need to poke inside to set TAP key inside of newly created MocSymCtx */
    pKeyData = (MTapKeyData *)pNewSymCtx->pLocalData;
    if (NULL == pKeyData)
        goto exit;

    pKeyData->pKey = pNewTapKey;
    pKeyData->isKeyLoaded = TRUE;
    pKeyData->isDeferUnload = FALSE;
    pNewTapKey = NULL;

    /* Now wrap up the MocSymCtx inside a SymmetricKey structure */
    status = DIGI_CALLOC((void **)&pNewSymKey, 1, sizeof(SymmetricKey));
    if (OK != status)
        goto exit;

    /* Load the MocSymCtx into the SymmetricKey wrapper */
    pNewSymKey->pKeyData = (void *) pNewSymCtx; pNewSymCtx = NULL;
    pNewSymKey->keyType = keyType;

    *ppNewKey = pNewSymKey;
    pNewSymKey = NULL;

exit:

    if (NULL != opAttributes.pAttributeList)
    {
        (void) DIGI_FREE((void **) &opAttributes.pAttributeList);
    }
    if (NULL != pNewSymKey)
    {
        (void) DIGI_FREE((void **)&pNewSymKey);
    }
    if (NULL != pNewSymCtx)
    {
        (void) CRYPTO_freeMocSymCtx (&pNewSymCtx);
    }
    if (NULL != pNewTapKey)
    {
        (void) TAP_freeKey(&pNewTapKey);
    }

    return status;
}

#endif /* #if defined(__ENABLE_DIGICERT_TAP__) */
