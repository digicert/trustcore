/*
 * crypto_interface_tap.c
 *
 * Cryptographic Interface specification for Generic TAP.
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

#include "../crypto/mocsym.h"
#include "../common/debug_console.h"
#include "../common/base64.h"
#include "../crypto_interface/crypto_interface_tap.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "../tap/tap.h"
#include "../tap/tap_api.h"
#include "../tap/tap_common.h"
#include "../crypto/mocasymkeys/tap/rsatap.h"
#include "../crypto_interface/cryptointerface.h"

#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/mocasymkeys/tap/ecctap.h"
#endif

#ifdef __ENABLE_DIGICERT_PQC__
#include "../crypto_interface/crypto_interface_qs.h"
#include "../crypto/mocasymkeys/tap/qstap.h"
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_getKeyById(ubyte *pId, ubyte4 idLen, AsymmetricKey *pKey)
{
    MSTATUS status = ERR_NULL_POINTER, fstatus = OK;
    TAP_Buffer keyId = {0};
    ubyte4 idInt = 0;
    TAP_Key *pTapKey = NULL;
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;
    byteBoolean releaseContext = FALSE;
    MocAsymmetricKey emptyKey = { 0 };
    TAP_Context *pTapContext = NULL;
    TAP_EntityCredentialList *pUsageCredentials = NULL;
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_KeyInfo keyInfo = {0};
    MocAsymKey pMocAsymKey = NULL;
    TAP_KEY_SIZE keySize = 0;
    ubyte subType = 0;
#ifndef __DISABLE_DIGICERT_RSA__
    RSAKey *pRsaKey = NULL;
#endif
#ifdef __ENABLE_DIGICERT_ECC__
    ECCKey *pEccKey = NULL;
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    QS_CTX *pQsCtx = NULL;
#endif

    if (NULL == pId || NULL == pKey)
        goto exit;

    /* Ids for at least NanoRoot must be 4 bytes */
    status = ERR_INVALID_INPUT;
    if (idLen != 4)
        goto exit;

    /* delete any previously existing key */
    status = CRYPTO_uninitAsymmetricKey(pKey, 0);
    if (OK != status)
        goto exit;

#ifdef __ENABLE_DIGICERT_TAP_EXTERN__
    status = CRYPTO_INTERFACE_TAPExternInit();
    if (OK != status)
        goto exit;
#endif

    if (NULL != g_pFuncPtrGetTapContext)
    {
        status = g_pFuncPtrGetTapContext(
            &pTapContext, &pUsageCredentials,
            &pKeyCredentials, &emptyKey, tap_key_import, 1);
        if (OK != status)
            goto exit;

        releaseContext = TRUE;
    }
    else
    {
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
    }

    keyId.pBuffer = pId;
    keyId.bufferLen = idLen;
    /* TODO should this be big endian? */
    idInt = (((ubyte4) pId[3]) << 24) | (((ubyte4) pId[2]) << 16) | (((ubyte4) pId[1]) << 8) | ((ubyte4) pId[0]);

    status = TAP_parse_algorithm_info(idInt, &keyInfo.keyAlgorithm, &keySize, &subType);
    if (OK != status)
        goto exit;

    /* we need the to set the keyInfo too
       NOTE: The hashes (sigScheme) are automatically set to what NanoRoot requires
       Future project many be to pass the pKeyInfo into this method as its done in CRYPTO_INTERFACE_TAP_serializeKeyById.
       (difficulty in that is that this is called by CRYPTO_deserializeAsymKey which does not know the keyInfo a priori)
    */
    switch (keyInfo.keyAlgorithm)
    {
#ifndef __DISABLE_DIGICERT_RSA__
        case TAP_KEY_ALGORITHM_RSA:
            keyInfo.algKeyInfo.rsaInfo.keySize = keySize;
            if (TAP_KEY_SIZE_4096 == keySize || TAP_KEY_SIZE_8192 == keySize)
                keyInfo.algKeyInfo.rsaInfo.sigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA512;
            else
                keyInfo.algKeyInfo.rsaInfo.sigScheme = TAP_SIG_SCHEME_PKCS1_5_SHA256;

            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC__
        case TAP_KEY_ALGORITHM_ECC:
            keyInfo.algKeyInfo.eccInfo.curveId = subType;
            if (TAP_ECC_CURVE_NIST_P521 == subType)
                keyInfo.algKeyInfo.eccInfo.sigScheme = TAP_SIG_SCHEME_ECDSA_SHA512;
            else
                keyInfo.algKeyInfo.eccInfo.sigScheme = TAP_SIG_SCHEME_ECDSA_SHA256;

            break;
#endif
#ifdef __ENABLE_DIGICERT_PQC__
        case TAP_KEY_ALGORITHM_MLDSA:
             keyInfo.algKeyInfo.pqcInfo.qsAlg = subType;
             break;
#endif
        default:
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
    }

    status = TAP_importKeyFromID(pTapContext, pUsageCredentials, &keyInfo, &keyId, NULL, pKeyCredentials, &pTapKey, pErrContext);
    if (OK != status)
        goto exit;

    status = DIGI_CALLOC((void **)&pMocAsymKey, sizeof(MocAsymmetricKey), 1);
    if (OK != status)
        goto exit;

    switch (keyInfo.keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:

#ifndef __DISABLE_DIGICERT_RSA__
            status = RsaTapCreate(pMocAsymKey, NULL, MOC_ASYM_KEY_TYPE_PRIVATE);
            if (OK != status)
                goto exit;

            status = RsaTapLoadKeyData(&pTapKey, NULL, 0, NULL, pMocAsymKey);
            if (OK != status)
                goto exit;

            status = CRYPTO_INTERFACE_RSA_loadKey(&pRsaKey, &pMocAsymKey);
            if (OK != status)
                goto exit;

            pKey->key.pRSA = pRsaKey; pRsaKey = NULL;
            pKey->type = akt_tap_rsa;
            break;
#else
            status = ERR_RSA_DISABLED;
            goto exit;
#endif

        case TAP_KEY_ALGORITHM_ECC:

#ifdef __ENABLE_DIGICERT_ECC__
            status = EccTapCreate(pMocAsymKey, NULL, MOC_ASYM_KEY_TYPE_PRIVATE);
            if (OK != status)
                goto exit;

            status = EccTapLoadKeyData(&pTapKey, NULL, 0, NULL, NULL, pMocAsymKey);
            if (OK != status)
                goto exit;

            status = CRYPTO_INTERFACE_EC_loadKey(&pEccKey, &pMocAsymKey);
            if (OK != status)
                goto exit;

            pKey->key.pECC = pEccKey; pEccKey = NULL;
            pKey->type = akt_tap_ecc;
            break;
#else
            status = ERR_UNSUPPORTED_OPERATION;
            goto exit;
#endif

        case TAP_KEY_ALGORITHM_MLDSA:

#ifdef __ENABLE_DIGICERT_PQC__
            status = QsTapCreate(pMocAsymKey, NULL, MOC_ASYM_KEY_TYPE_PRIVATE);
            if (OK != status)
                goto exit;

            status = QsTapLoadKeyData(&pTapKey, NULL, 0, NULL, NULL, pMocAsymKey);
            if (OK != status)
                goto exit;

            status = CRYPTO_INTERFACE_QS_loadKey(&pQsCtx, &pMocAsymKey);
            if (OK != status)
                goto exit;

            pKey->pQsCtx = pQsCtx; pQsCtx = NULL;
            pKey->type = akt_tap_qs;
            break;
#else
            status = ERR_UNSUPPORTED_OPERATION;
            goto exit;
#endif

        default:
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
    }

exit:

    if (NULL != pTapKey)
    {
        fstatus = TAP_unloadKey(pTapKey, pErrContext);
        if (OK == status)
            status = fstatus;

        fstatus = TAP_freeKey(&pTapKey);
        if (OK == status)
            status = fstatus;
    }

    if (NULL != pMocAsymKey)
    {
        (void) DIGI_FREE((void **)&pMocAsymKey);
    }

#ifndef __DISABLE_DIGICERT_RSA__
    if (NULL != pRsaKey)
    {
        (void) CRYPTO_INTERFACE_RSA_freeKey((void **) &pRsaKey, NULL, akt_tap_rsa);
    }
#endif
#ifdef __ENABLE_DIGICERT_ECC__
    if (NULL != pEccKey)
    {
        (void) CRYPTO_INTERFACE_EC_deleteKey((void **) &pEccKey, akt_tap_ecc);
    }
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    if (NULL != pQsCtx)
    {
        (void) CRYPTO_INTERFACE_QS_deleteCtx(&pQsCtx);
    }
#endif

    if (TRUE == releaseContext && NULL != g_pFuncPtrGetTapContext)
    {
        fstatus = g_pFuncPtrGetTapContext(
            &pTapContext, &pUsageCredentials, &pKeyCredentials,
            &emptyKey, tap_key_import, 0);
        if (OK == status)
            status = fstatus;
    }

    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_serializeKeyById(
    TAP_Context *pTapContext,
    TAP_EntityCredentialList *pUsageCredentials,
    TAP_CredentialList *pKeyCredentials,
    TAP_KeyInfo *pKeyInfo,
    ubyte *pId,
    ubyte4 idLen,
    ubyte serialFormat,
    ubyte **ppSerializedKey,
    ubyte4 *pSerializedKeyLen)
{
    MSTATUS status = ERR_NULL_POINTER, fstatus = OK;
    TAP_Buffer keyId = {0};
    TAP_Key *pTapKey = NULL;
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;
    ubyte *pTemp = NULL;
    ubyte4 tempLen = 0;
    byteBoolean releaseContext = FALSE;
    MocAsymmetricKey emptyKey = { 0 };

    if (NULL == pId || NULL == pKeyInfo || NULL == ppSerializedKey || NULL == pSerializedKeyLen)
        goto exit;

#ifdef __ENABLE_DIGICERT_TAP_EXTERN__
    status = CRYPTO_INTERFACE_TAPExternInit();
    if (OK != status)
        goto exit;
#endif

    if (NULL == pTapContext)
    {
        if (NULL != g_pFuncPtrGetTapContext)
        {
            status = g_pFuncPtrGetTapContext(
                &pTapContext, &pUsageCredentials,
                &pKeyCredentials, &emptyKey, tap_key_import, 1);
            if (OK != status)
                goto exit;

            releaseContext = TRUE;
        }
        else
        {
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
        }
    }

    keyId.pBuffer = pId;
    keyId.bufferLen = idLen;

    status = TAP_importKeyFromID(pTapContext, pUsageCredentials, pKeyInfo, &keyId, NULL, pKeyCredentials, &pTapKey, pErrContext);
    if (OK != status)
        goto exit;

    switch (pKeyInfo->keyAlgorithm)
    {
#ifndef __DISABLE_DIGICERT_RSA__
        case TAP_KEY_ALGORITHM_RSA:

            status = SerializeRsaTapKeyAlloc (pTapKey, (serializedKeyFormat) serialFormat, &pTemp, &tempLen); 
            if (OK != status)
                goto exit;

            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC__
        case TAP_KEY_ALGORITHM_ECC:

            status = SerializeEccTapKeyAlloc (pTapKey, (serializedKeyFormat) serialFormat, &pTemp, &tempLen);
            if (OK != status)
                goto exit;
                
            break;
#endif
#ifdef __ENABLE_DIGICERT_PQC__
        case TAP_KEY_ALGORITHM_MLDSA:
            status = SerializeQsTapKeyAlloc (pTapKey, (serializedKeyFormat) serialFormat, &pTemp, &tempLen);
            if (OK != status)
                goto exit;

            break;
#endif
        default:
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
    }

    /* The above API actually doesn't handle PEM form. Convert to PEM if necc */
    if (privateKeyPem == (serializedKeyFormat) serialFormat)
    {
        status = BASE64_makePemMessageAlloc (MOC_PEM_TYPE_PRI_TAP_KEY, pTemp, tempLen, ppSerializedKey, pSerializedKeyLen);
    }
    else /* others are converted correctly */
    {
        *ppSerializedKey = pTemp; pTemp = NULL;
        *pSerializedKeyLen = tempLen;
    }

exit:

    if (NULL != pTemp)
    {
        (void) DIGI_MEMSET_FREE(&pTemp, tempLen);
    }

    if (NULL != pTapKey)
    {
        fstatus = TAP_unloadKey(pTapKey, pErrContext);
        if (OK == status)
            status = fstatus;

        fstatus = TAP_freeKey(&pTapKey);
        if (OK == status)
            status = fstatus;
    }

    if (TRUE == releaseContext && NULL != g_pFuncPtrGetTapContext)
    {
        fstatus = g_pFuncPtrGetTapContext(
            &pTapContext, &pUsageCredentials, &pKeyCredentials,
            &emptyKey, tap_key_import, 0);
        if (OK == status)
            status = fstatus;
    }

    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_loadWithCreds(
    MocAsymKey pKey,
    ubyte *pPassword,
    ubyte4 passwordLen,
    void *pLoadCtx)
{
    MSTATUS status = ERR_NULL_POINTER, status2 = OK;
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_CredentialList *pFuncPtrCredList = NULL;
    TAP_CredentialList *pCredList = NULL;
    TAP_Credential *pCred = NULL;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_Context *pTapContext = NULL;
    TAP_Key *pTapKey = NULL;
    byteBoolean freeCredList = FALSE;
#ifdef __ENABLE_DIGICERT_ECC__
    byteBoolean isEcc = FALSE;
    MEccTapKeyData *pEccInfo = NULL;
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    byteBoolean isPqc = FALSE;
    MQsTapKeyData *pQsInfo = NULL;
#endif
    MRsaTapKeyData *pRsaInfo = NULL;

    if (NULL == pKey || (passwordLen && NULL == pPassword))
    {
        goto exit;
    }

#if (defined(__ENABLE_DIGICERT_TAP_EXTERN__))
    if (OK > ( status = CRYPTO_INTERFACE_TAPExternInit()))
        goto exit;
#endif

    if (passwordLen > 0)
    {
        status = DIGI_CALLOC((void **) &pCredList, 1, sizeof(TAP_CredentialList));
        if (OK != status)
            goto exit;

        freeCredList = TRUE;
       
        /* allocate the credential list */
        status = DIGI_CALLOC((void **) &pCredList->pCredentialList, 1, sizeof(TAP_Credential));
        if (OK != status)
            goto exit;

        pCredList->numCredentials = 1;

        pCred = pCredList->pCredentialList;
        
        status = DIGI_MALLOC((void **) &pCred->credentialData.pBuffer, passwordLen);
        if (OK != status)
            goto exit;

        pCred->credentialData.bufferLen = passwordLen;
        
        status = DIGI_MEMCPY(pCred->credentialData.pBuffer, pPassword, passwordLen);
        if (OK != status)
            goto exit;

        pCred->credentialType = TAP_CREDENTIAL_TYPE_PASSWORD;
        pCred->credentialFormat = TAP_CREDENTIAL_FORMAT_PLAINTEXT;
        pCred->credentialContext = TAP_CREDENTIAL_CONTEXT_ENTITY;
    }

    if (MOC_LOCAL_TYPE_RSA == (MOC_LOCAL_TYPE_COM_MASK & pKey->localType))
    {
        pRsaInfo = (MRsaTapKeyData *) (pKey->pKeyData);
        if (NULL == pRsaInfo)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        pTapKey = (TAP_Key *) pRsaInfo->pKey;

        if (pRsaInfo->isKeyLoaded)
        {
            status = TAP_unloadKey(pTapKey, pErrContext);
            if (OK != status)
                goto exit;
            
            pRsaInfo->isKeyLoaded = FALSE;
        }
    }
#ifdef __ENABLE_DIGICERT_ECC__
    else if (MOC_LOCAL_TYPE_ECC == (MOC_LOCAL_TYPE_COM_MASK & pKey->localType))
    {
        pEccInfo = (MEccTapKeyData *) (pKey->pKeyData);
        if (NULL == pEccInfo)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        pTapKey = (TAP_Key *) pEccInfo->pKey;
        
        if (pEccInfo->isKeyLoaded)
        {
            status = TAP_unloadKey(pTapKey, pErrContext);
            if (OK != status)
                goto exit;
            
            pEccInfo->isKeyLoaded = FALSE;
        }

        isEcc = TRUE;
    }
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    else if (MOC_LOCAL_TYPE_QS_SIG == (MOC_LOCAL_TYPE_COM_MASK & pKey->localType)) /* Future, QS_KEM */
    {
        pQsInfo = (MQsTapKeyData *) (pKey->pKeyData);
        if (NULL == pQsInfo)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        pTapKey = (TAP_Key *) pQsInfo->pKey;
        
        if (pQsInfo->isKeyLoaded)
        {
            status = TAP_unloadKey(pTapKey, pErrContext);
            if (OK != status)
                goto exit;
            
            pQsInfo->isKeyLoaded = FALSE;
        }

        isPqc = TRUE;
    }
#endif
    else
    {
        status = ERR_BAD_KEY_TYPE;
        goto exit;
    }

    if (NULL == pLoadCtx)
    {
        if (g_pFuncPtrGetTapContext != NULL)
        {
            if (OK > (status = g_pFuncPtrGetTapContext(&pTapContext,
                                                        &pEntityCredentials,
                                                        &pFuncPtrCredList,
                                                        (void *)pKey, tap_key_load, 1/*get context*/)))
            {
                goto exit1;
            }
        }
        else
        {
            status = ERR_NOT_IMPLEMENTED;
            goto exit;
        }
    }
    else
    {
        pTapContext = (TAP_Context *) pLoadCtx;
    }

    if (NULL == pCredList)
    {
        pCredList = pFuncPtrCredList;
    }
    
    status = TAP_loadKey(pTapContext, pEntityCredentials, pTapKey, pCredList, NULL, pErrContext);
    if (OK != status)
        goto exit1;

#ifdef __ENABLE_DIGICERT_ECC__
    if (isEcc)
    {
        pEccInfo->isKeyLoaded = TRUE;
    } else
#endif
#ifdef __ENABLE_DIGICERT_PQC__
    if (isPqc)
    {
        pQsInfo->isKeyLoaded = TRUE;
    } else
#endif
    {
        pRsaInfo->isKeyLoaded = TRUE;
    }
    
exit1:

    if (NULL == pLoadCtx && NULL != g_pFuncPtrGetTapContext)
    {
        if (OK > (status2 = g_pFuncPtrGetTapContext(&pTapContext,
                                                    &pEntityCredentials,
                                                    &pFuncPtrCredList,
                                                    (void *)pKey, tap_key_load, 0/* release context*/)))
        {
            DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"TAP Context release failed with status = ", status2);
        }
        if (OK == status)
            status = status2;
    }

exit:

    if (freeCredList && NULL != pCredList)
    {
        /* Free any internal structures */
        (void) TAP_UTILS_clearCredentialList(pCredList);
    
        /* Free outer shell */
        (void) DIGI_FREE((void** ) &pCredList);
    }

    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_getKeyTapInfo(
    MocAsymKey pKey,
    ubyte4 *pProvider,
    ubyte4 *pModuleId
)
{
    MSTATUS status = ERR_NULL_POINTER;
    TAP_Key *pTapKey = NULL;

    if (NULL == pKey || NULL == pProvider || NULL == pModuleId)
        goto exit;

    if (MOC_LOCAL_TYPE_RSA == (MOC_LOCAL_TYPE_COM_MASK & pKey->localType))
    {
        MRsaTapKeyData *pInfo = (MRsaTapKeyData *) (pKey->pKeyData);
        if (NULL == pInfo)
            goto exit;

        pTapKey = (TAP_Key *) pInfo->pKey;
    }
#ifdef __ENABLE_DIGICERT_ECC__
    else if (MOC_LOCAL_TYPE_ECC == (MOC_LOCAL_TYPE_COM_MASK & pKey->localType))
    {
        MEccTapKeyData *pInfo = (MEccTapKeyData *) (pKey->pKeyData);
        if (NULL == pInfo)
            goto exit;

        pTapKey = (TAP_Key *) pInfo->pKey;
    }
#endif
    else
    {
        status = ERR_BAD_KEY_TYPE;
        goto exit;
    }

    if (NULL == pTapKey) /* still ERR_NULL_POINTER */
        goto exit;

    *pProvider = (ubyte4) pTapKey->providerObjectData.objectInfo.providerType;
    *pModuleId = (ubyte4) pTapKey->providerObjectData.objectInfo.moduleId;

    status = OK;     

exit:
   
    return status;
}
#endif /* __ENABLE_DIGICERT_TAP__ */
