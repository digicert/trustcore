/*
 * cryptointerface.c
 *
 * @brief Crypto wrapper APIs
 * @details This file contains crypto wrapper APIs for RSA and ECDSA.
 *          These APIs decides whether to call crypto software APIs or TAP APIs.
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

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/vlong.h"
#include "../common/random.h"
#include "../common/prime.h"
#include "../common/debug_console.h"
#include "../common/memory_debug.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/rsa.h"
#include "../crypto/dsa.h"
#include "../crypto/primefld.h"
#include "../asn1/parseasn1.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../crypto/ecc.h"
#endif
#include "../crypto/keyblob.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/md4.h"
#include "../crypto/md5.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/sha3.h"
#include "../crypto/blake2.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "../tap/tap.h"
#include "../tap/tap_utils.h"
#include "../tap/tap_smp.h"
#include "../crypto/mocasymkeys/tap/rsatap.h"
#include "../crypto/mocasymkeys/tap/ecctap.h"
#include "../crypto_interface/crypto_interface_rsa_tap_priv.h"
#include "../crypto_interface/crypto_interface_ecc_tap_priv.h"

#if (defined(__ENABLE_DIGICERT_TAP_EXTERN__))
#include "../crypto_interface/tap_extern.h"
#endif
#endif

#include "cryptointerface.h"
#include "crypto_interface_priv.h"
#include "../crypto_interface/crypto_interface_md4.h"
#include "../crypto_interface/crypto_interface_md5.h"
#include "../crypto_interface/crypto_interface_sha1.h"
#include "../crypto_interface/crypto_interface_sha256.h"
#include "../crypto_interface/crypto_interface_sha512.h"
#include "../crypto_interface/crypto_interface_sha3.h"
#include "../crypto_interface/crypto_interface_blake2.h"

#define MAX_CMD_BUFFER 4096
#define MAX_KEY_BUFFER 1024

#if defined(__ENABLE_DIGICERT_TAP__)

pFuncPtrGetTapContext g_pFuncPtrGetTapContext;

#if (defined(__ENABLE_DIGICERT_TAP_EXTERN__))
MSTATUS
CRYPTO_INTERFACE_TAPExternInit()
{
    MSTATUS status = OK;
    if (g_pFuncPtrGetTapContext == NULL)
    {
        if (OK > ( status = DIGICERT_TAPExternInit((void **)&g_pFuncPtrGetTapContext)))
            goto exit;
    }

exit:
    return status;
}
#endif

MSTATUS CRYPTO_INTERFACE_registerTapCtxCallback(void *pCallback)
{
	g_pFuncPtrGetTapContext = pCallback;
    return OK;
}

/*---------------------------------------------------------------------------*/

#endif /* if defined(__ENABLE_DIGICERT_TAP__) */

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#ifdef __ENABLE_DIGICERT_ECC__
/* This function is deprecated. Use CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux
 * instead.
 */
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_getECurve(void *pKey, PEllipticCurvePtr *ppECurve, ubyte4 keyType)
{
    MSTATUS status = OK;
    if ((NULL == pKey) || (NULL == ppECurve))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (akt_tap_ecc == keyType)
    {
#if defined(__ENABLE_DIGICERT_TAP__)
        TAP_ECC_CURVE curve;
        MEccTapKeyData *pData = NULL;
        MocAsymKey pMocAsymKey = (MocAsymKey)pKey;

        pData = (MEccTapKeyData *)(pMocAsymKey->pKeyData);
        curve = pData->pKey->keyData.algKeyInfo.eccInfo.curveId;
        switch (curve)
        {
#ifdef __ENABLE_DIGICERT_ECC_P192__
            case TAP_ECC_CURVE_NIST_P192:
                *ppECurve = EC_P192;
                break;
#endif
            case TAP_ECC_CURVE_NIST_P224:
                *ppECurve = EC_P224;
                break;
            case TAP_ECC_CURVE_NIST_P256:
                *ppECurve = EC_P256;
                break;
            case TAP_ECC_CURVE_NIST_P384:
                *ppECurve = EC_P384;
                break;
            case TAP_ECC_CURVE_NIST_P521:
                *ppECurve = EC_P521;
                break;
            default:
                status = ERR_EC_UNSUPPORTED_CURVE;
                goto exit;
        }
#else
        status = ERR_TAP_UNSUPPORTED;
#endif
    }
    else
    {
        *ppECurve = ((ECCKey*)pKey)->pCurve;
    }

exit:
    return status;
}
#endif
#endif

#if defined(__ENABLE_DIGICERT_TAP__)

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_retrieveFingerPrintInfo_TAPSeed(
    FingerprintElement **ppElements,
    ubyte4 *pNumElements,
    ubyte **ppInitialSeed,
    ubyte4 *pInitialSeedLen,
    ubyte8  ek_obj_id
    )
{
    MSTATUS status;
    ubyte4 seedLen = SHA256_RESULT_SIZE;
    ubyte *deviceSeed = NULL;
    FingerprintElement *pElements = NULL;
    ubyte4 numElements = 1;
    sbyte *pLabel = (sbyte*)"mcnfngrprnt";
    ubyte4 labelLen = DIGI_STRLEN(pLabel);
    ubyte fpValue[16] = {0x24, 0x67, 0x82, 0x56, 0xfe, 0x03, 0xdb, 0xdb, \
                          0x73, 0xa9, 0x5e, 0xcc, 0x82, 0x91, 0x2f, 0x7c};
    ubyte4 valueLen = 16;
    ubyte4 offset = 0;
    MocAsymmetricKey emptyKey = { 0 };
    ubyte publicKeyBuffer[MAX_KEY_BUFFER];
    TAP_Context              *pTapCtx = NULL;
    TAP_CredentialList       *pKeyCredentials = NULL;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_ErrorContext *pErrContext = NULL;
    TAP_KeyInfo rootKeyInfo = {0};
    TAP_Key *pRootKey = NULL;

    if ( (NULL == ppElements) || (NULL == pNumElements) || (NULL == ppInitialSeed) || (NULL == pInitialSeedLen) )
    {
        return ERR_NULL_POINTER;
    }

    status = DIGI_MALLOC((void **)&deviceSeed, seedLen);
    if (OK != status)
        goto exit;

    if (!ek_obj_id)
    {
        status = ERR_TAP_UNSUPPORTED;
        goto exit;
    }

	/* Set ObjectId */
	rootKeyInfo.objectId = ek_obj_id;

	if (NULL != g_pFuncPtrGetTapContext)
    {
        status = g_pFuncPtrGetTapContext(
                    &(pTapCtx),
                    &(pEntityCredentials),
                    &(pKeyCredentials),
                    (void *)&emptyKey, tap_seed, 1);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
    }

	DIGI_MEMSET(publicKeyBuffer, 0, MAX_KEY_BUFFER);

    status = TAP_getRootOfTrustKey(pTapCtx, &rootKeyInfo, TAP_ROOT_OF_TRUST_TYPE_UNKNOWN,
                                    &pRootKey, pErrContext);

    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"TAP_getRootOfTrustKey status = ", status);
        goto exit;
    }

    /* Serialize Public key */
    offset = 0;
    status = TAP_SERIALIZE_serialize(TAP_SERALIZE_SMP_getPublicKeyShadowStruct(),
                                        TAP_SD_IN, (void *)&pRootKey->keyData.publicKey,
                                        sizeof(pRootKey->keyData.publicKey),
                                        publicKeyBuffer, sizeof(publicKeyBuffer), &offset);
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"Serialize public key status = ", status);
        goto exit;

    }

	status = CRYPTO_INTERFACE_SHA256_completeDigest(MOC_HASH(0) publicKeyBuffer,
             offset,
             deviceSeed);
    if (OK != status)
    {
        DEBUG_ERROR(DEBUG_TAP_MESSAGES, "Failed to generate digest, status = \n",
                 status);
        goto exit;
    }

    (void) TAP_unloadKey(pRootKey, pErrContext);

    (void) TAP_freeKey(&pRootKey);
    pRootKey = NULL;

    status = DIGI_CALLOC((void **)&pElements, 1, sizeof(FingerprintElement));
    if (OK != status)
        goto exit;

    status = DIGI_CALLOC((void **)&(pElements->pLabel), 1, labelLen + 1);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)pElements->pLabel, pLabel, labelLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY((void *)pElements->pValue, fpValue, valueLen);
    if (OK != status)
        goto exit;

    pElements->valueLen = valueLen;

    *ppElements = pElements;
    *pNumElements = numElements;
    *ppInitialSeed = deviceSeed;
    *pInitialSeedLen = seedLen;
    pElements = NULL;
    deviceSeed = NULL;

exit:
    if (NULL != pElements)
    {
        DIGI_FREE((void **)&pElements);
    }
    if (NULL != deviceSeed)
    {
        DIGI_FREE((void **)&deviceSeed);
    }
    if(NULL != pRootKey)
    {
        TAP_unloadKey(pRootKey, pErrContext);

        TAP_freeKey(&pRootKey);
    }
    if ((NULL != g_pFuncPtrGetTapContext)  && pTapCtx)
    {
        g_pFuncPtrGetTapContext(
                    &(pTapCtx),
                    &(pEntityCredentials),
                    &(pKeyCredentials),
                    (void *)&emptyKey, tap_seed, 0);
    }
    return status;

}
#endif /* if defined(__ENABLE_DIGICERT_TAP__) */


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_getKeyUsage(void *pKey, ubyte4 keyType, ubyte *pKeyUsage)
{
    MSTATUS status = OK;
#if defined(__ENABLE_DIGICERT_TAP__)
    MocAsymKey pMocAsymKey = NULL;
#endif

    if ( (NULL == pKey) || (NULL == pKeyUsage) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pKeyUsage = 0;

#if defined(__ENABLE_DIGICERT_TAP__)
    if (keyType == akt_tap_rsa)
    {
        MRsaTapKeyData *pInfo = NULL;
        TAP_Key *pTapKey = NULL;

        pMocAsymKey = ((RSAKey *)(pKey))->pPublicKey;
        if ( (NULL == pMocAsymKey) || (NULL == pMocAsymKey->pKeyData) )
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        pInfo = (MRsaTapKeyData *)(pMocAsymKey->pKeyData);
        pTapKey = (TAP_Key *)pInfo->pKey;
        *pKeyUsage = pTapKey->keyData.keyUsage;
        goto exit;
    }
#ifdef __ENABLE_DIGICERT_ECC__
    if (keyType == akt_tap_ecc)
    {
        MEccTapKeyData *pInfo = NULL;
        TAP_Key *pTapKey = NULL;

        pMocAsymKey = ((ECCKey *)(pKey))->pPublicKey;
        if ( (NULL == pMocAsymKey) || (NULL == pMocAsymKey->pKeyData) )
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        pInfo = (MEccTapKeyData *)(pMocAsymKey->pKeyData);
        pTapKey = (TAP_Key *)pInfo->pKey;
        *pKeyUsage = pTapKey->keyData.keyUsage;
        goto exit;
    }
#endif
#endif
    if ((keyType == akt_rsa) || (keyType == akt_ecc) || (keyType == akt_ecc_ed) ||
             (keyType == akt_hsm_rsa))
    {
        *pKeyUsage = 0;
    }
    else
    {
        status = ERR_TAP_INVALID_KEY_TYPE;
    }

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_getKeyType(void *pKey, ubyte4 *keyType)
{
#if defined(__ENABLE_DIGICERT_TAP__)
    MSTATUS status = OK;
    MocAsymKey pMocAsymKey = NULL;
    MRsaTapKeyData *pInfo = NULL; /* Location of TAP_Key is same for both RSA and ECC struct */
    TAP_Key *pTapKey = NULL;

    if (NULL == pKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* We cast to an RSAKey structure, but the offset for the underlying public key
     * is identical for both RSAKey and ECCKey. The Crypto Interface internals
     * guarantee there will always be a valid public key so we use that instead of
     * the public key */
    pMocAsymKey = ((RSAKey *)(pKey))->pPublicKey;
    if ( (NULL == pMocAsymKey) || (NULL == pMocAsymKey->pKeyData) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Validate that this is a TAP key */
    if (0 == (MOC_LOCAL_TYPE_TAP & pMocAsymKey->localType))
    {
        status = ERR_UNSUPPORTED_OPERATION;
        goto exit;
    }

    pInfo = (MRsaTapKeyData *)(pMocAsymKey->pKeyData);
    pTapKey = (TAP_Key *)pInfo->pKey;

    switch(pTapKey->keyData.keyAlgorithm)
    {
        case 1:
            *keyType = akt_tap_rsa;
            break;

        case 2:
            *keyType = akt_tap_ecc;
            break;

        default:
            *keyType = akt_undefined;
            break;
    }

exit:
    return status;
#else
    *keyType = akt_undefined;
    return OK;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_asymmetricKeyAddCreds(AsymmetricKey *pKey, sbyte *pPassword, sbyte4 passwordLen)
{
#if defined(__ENABLE_DIGICERT_TAP__)
    MSTATUS status = OK;
    MocAsymKey pMocKey = NULL;
    TAP_CredentialList *pCredList = NULL;
    TAP_Credential *pCred = NULL;
    byteBoolean freeCredList = FALSE;

    if ((NULL == pKey) || (NULL == pPassword))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == passwordLen)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    if ((pKey->type != akt_tap_rsa) && (pKey->type != akt_tap_ecc))
    {
        status = ERR_BAD_KEY_TYPE;
        goto exit;
    }

    if (pKey->type == akt_tap_rsa)
    {
        pMocKey = pKey->key.pRSA->pPublicKey;
    }
#ifdef __ENABLE_DIGICERT_ECC__
    else if (pKey->type == akt_tap_ecc)
    {
        pMocKey = pKey->key.pECC->pPublicKey;
    }
#endif

    if ((NULL == pMocKey) || (NULL == pMocKey->pKeyData))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Validate that this is a TAP key */
    if (0 == (MOC_LOCAL_TYPE_TAP & pMocKey->localType))
    {
        status = ERR_UNSUPPORTED_OPERATION;
        goto exit;
    }

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

    if (pKey->type == akt_tap_rsa)
    {
        ((MRsaTapKeyData*)pMocKey->pKeyData)->pKeyCredentials = pCredList;
    }
#ifdef __ENABLE_DIGICERT_ECC__
    else if (pKey->type == akt_tap_ecc)
    {
        ((MEccTapKeyData*)pMocKey->pKeyData)->pKeyCredentials = pCredList;
    }
#endif
    pCredList = NULL;

exit:
    if (freeCredList && NULL != pCredList)
    {
        /* Free any internal structures */
        (void) TAP_UTILS_clearCredentialList(pCredList);
    
        /* Free outer shell */
        (void) DIGI_FREE((void** ) &pCredList);
    }

    return status;
#else
    return ERR_NOT_IMPLEMENTED;
#endif
}

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_asymmetricKeyRemoveCreds(
    AsymmetricKey *pKey)
{
#if defined(__ENABLE_DIGICERT_TAP__)
    MSTATUS status, fstatus;
    MocAsymKey pMocKey = NULL;
    TAP_CredentialList **ppCredList = NULL;

    if (NULL == pKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (akt_tap_rsa == pKey->type)
    {
        pMocKey = pKey->key.pRSA->pPublicKey;
    }
#ifdef __ENABLE_DIGICERT_ECC__
    else if (akt_tap_ecc == pKey->type)
    {
        pMocKey = pKey->key.pECC->pPublicKey;
    }
#endif
    else
    {
        status = OK;
        goto exit;
    }

    if ( (NULL == pMocKey) || (NULL == pMocKey->pKeyData) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Validate that this is a TAP key */
    if (0 == (MOC_LOCAL_TYPE_TAP & pMocKey->localType))
    {
        status = ERR_UNSUPPORTED_OPERATION;
        goto exit;
    }

    status = OK;

    if (akt_tap_rsa == pKey->type)
    {
        ppCredList = &(((MRsaTapKeyData*)pMocKey->pKeyData)->pKeyCredentials);
    }
#ifdef __ENABLE_DIGICERT_ECC__
    else if (akt_tap_ecc == pKey->type)
    {
        ppCredList = &(((MEccTapKeyData*)pMocKey->pKeyData)->pKeyCredentials);
    }
#endif

    if ( (NULL != ppCredList) && (NULL != *ppCredList) )
    {
        status = TAP_UTILS_clearCredentialList(*ppCredList);

        fstatus = DIGI_FREE((void **) ppCredList);
        if (OK == status)
            status = fstatus;
    }

exit:

    return status;
#else
    return ERR_NOT_IMPLEMENTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_copyAsymmetricKey(AsymmetricKey* pNew, const AsymmetricKey* pSrc)
{
    MSTATUS status = OK;
    MocAsymKey pNewMocAsymKey = NULL;
#ifdef __ENABLE_DIGICERT_TAP__
    MocAsymKey pKey = NULL;
    ubyte4 flag = 0;
    RSAKey *pNewRsaKey = NULL;
    TAP_Key *pNewTapKey = NULL;
#ifdef __ENABLE_DIGICERT_ECC__
    ECCKey *pNewEccKey = NULL;
#endif
#endif

    if ((pNew == NULL) || (pSrc == NULL))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    CRYPTO_uninitAsymmetricKey( pNew, 0);

    if ((pSrc->type == akt_tap_rsa) || (pSrc->type == akt_tap_ecc))
    {
#if defined(__ENABLE_DIGICERT_TAP__)
        TAP_Key *pTapKey = NULL;
        MRsaTapKeyData *pRsaInfo = NULL;

        if (NULL == pSrc->key.pRSA)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        if (pSrc->type == akt_tap_rsa)
        {
            pKey = pSrc->key.pRSA->pPublicKey;
        }
#ifdef __ENABLE_DIGICERT_ECC__
        else
        {
            pKey = pSrc->key.pECC->pPublicKey;
        }
#endif

        if ( (NULL == pKey) || (NULL == pKey->pKeyData) )
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        /* Validate that this is a TAP key */
        if (0 == (MOC_LOCAL_TYPE_TAP & pKey->localType))
        {
            status = ERR_UNSUPPORTED_OPERATION;
            goto exit;
        }

        if (OK > (status = DIGI_CALLOC((void **)&pNewMocAsymKey, sizeof(MocAsymmetricKey), 1)))
        {
            goto exit;
        }

        if (NULL != pKey->pMocCtx)
        {
            /* Acquire a reference to the MocCtx. */
            status = AcquireMocCtxRef(pKey->pMocCtx);
            if (OK != status)
                goto exit;
        }

        flag = 1;

        if (pSrc->type == akt_tap_rsa)
        {
#ifndef __DISABLE_DIGICERT_RSA__
            pRsaInfo = (MRsaTapKeyData *)(pKey->pKeyData);
            pTapKey = (TAP_Key *)pRsaInfo->pKey;

            if (OK > (status = TAP_copyKey(&pNewTapKey, pTapKey)))
                goto exit;

            if (OK > (status = RsaTapCreate(pNewMocAsymKey, NULL, MOC_ASYM_KEY_TYPE_PRIVATE)))
                goto exit;

            if (OK > (status = RsaTapLoadKeyData(&pNewTapKey, NULL, 0, NULL, pNewMocAsymKey)))
                goto exit;

            pNewMocAsymKey->pMocCtx = pSrc->key.pRSA->pPublicKey->pMocCtx;

            status = CRYPTO_INTERFACE_RSA_loadKey(&pNewRsaKey, &pNewMocAsymKey);
            if (OK != status)
                goto exit;

            pNew->key.pRSA = pNewRsaKey;
            pNewRsaKey = NULL;
#else
            status = ERR_RSA_DISABLED;
            goto exit;
#endif
        }
        else
        {
#ifdef __ENABLE_DIGICERT_ECC__
            MEccTapKeyData *pEccInfo = (MEccTapKeyData *)(pKey->pKeyData);
            pTapKey = (TAP_Key *)pEccInfo->pKey;

            if (OK > (status = TAP_copyKey(&pNewTapKey, pTapKey)))
                goto exit;

            if (OK > (status = EccTapCreate(pNewMocAsymKey, NULL, MOC_ASYM_KEY_TYPE_PRIVATE)))
                goto exit;

            if (OK > (status = EccTapLoadKeyData(&pNewTapKey, NULL, 0, NULL, NULL, pNewMocAsymKey)))
                goto exit;

            pNewMocAsymKey->pMocCtx = pSrc->key.pECC->pPublicKey->pMocCtx;

            status = CRYPTO_INTERFACE_EC_loadKey(&pNewEccKey, &pNewMocAsymKey);
            if (OK != status)
                goto exit;

            pNew->key.pECC = pNewEccKey;
            pNewEccKey = NULL;
#else
            status = ERR_UNSUPPORTED_OPERATION;
            goto exit;
#endif
        }

        pNew->type = pSrc->type;
        flag = 0;
#else
        status = ERR_TAP_UNSUPPORTED;
#endif
    }
    else
    {
        status = CRYPTO_copyAsymmetricKey(pNew, pSrc);
    }

exit:

    if (NULL != pNewMocAsymKey)
    {
      DIGI_FREE((void **)&pNewMocAsymKey);
    }
#if defined(__ENABLE_DIGICERT_TAP__)
    if (NULL != pNewTapKey)
    {
        TAP_freeKey(&pNewTapKey);
    }
    if (0 != flag)
    {
        ReleaseMocCtxRef (pKey->pMocCtx);
    }
#ifndef __DISABLE_DIGICERT_RSA__
    if (NULL != pNewRsaKey)
    {
        RSA_freeKey(&pNewRsaKey, NULL);
    }
#endif
#ifdef __ENABLE_DIGICERT_ECC__
    if (NULL != pNewEccKey)
    {
        EC_deleteKeyEx(&pNewEccKey);
    }
#endif
#endif

    return status;
}

/*---------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_ECC__))
MSTATUS
CRYPTO_INTERFACE_getECCPublicKey(AsymmetricKey *pKey, ECCKey **ppPub)
{
    MSTATUS status = OK;
    ECCKey *pECCKey = NULL;

    if ((NULL == pKey) || (NULL == ppPub))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (akt_tap_ecc == pKey->type)
    {
#if defined(__ENABLE_DIGICERT_TAP__)

        /* Ensure we dont dereference a NULL pointer */
        if (NULL == pKey->key.pECC)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        /* TAP Key */
        MocAsymKey pMocAsymKey = pKey->key.pECC->pPublicKey;

        status = CRYPTO_INTERFACE_getECCPublicKeyEx(pMocAsymKey, (void **)&pECCKey);
#else
        status = ERR_TAP_UNSUPPORTED;
#endif
    }
    else if((akt_ecc == pKey->type) || (akt_ecc_ed == pKey->type))
    {
        /* SW Key */
        if (NULL == pKey->key.pECC)
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        pECCKey = pKey->key.pECC;
    }
    else
    {
        status = ERR_EC_INVALID_KEY_TYPE;
        goto exit;
    }
    *ppPub = pECCKey;
    pECCKey = NULL;

exit:
    if ((NULL != pKey) && (akt_tap_ecc == pKey->type))
    {
        if (NULL != pECCKey)
            EC_deleteKeyEx(&pECCKey);
    }
    return status;
}

#endif /* if (defined(__ENABLE_DIGICERT_ECC__)) */

/*---------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_getRSACipherTextLength(MOC_RSA(hwAccelDescr hwAccelCtx) void *pKey, sbyte4 *keySize, ubyte4 keyType)
{
    MOC_UNUSED(keyType);
    return RSA_getCipherTextLength(MOC_RSA(hwAccelCtx) (const RSAKey *)pKey, keySize);
}

/*---------------------------------------------------------------------------*/

MSTATUS CRYPTO_INTERFACE_getRsaSwPubFromTapKey(
    RSAKey *pKey,
    RSAKey **ppPub
    )
{
#if defined(__ENABLE_DIGICERT_TAP__)
    MSTATUS status;
    MRsaTapKeyData *pData = NULL;
    TAP_RSAPublicKey *pRsaTapPub = NULL;
    ubyte4 exponent = 0;
    RSAKey *pRsaKey = NULL;

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    /* just in case build uses both TAP and hwAccel */
    hwAccelDescr hwAccelCtx = 0;
#endif

    if ( (NULL == pKey) || (NULL == pKey->pPublicKey) ||
         (NULL == pKey->pPublicKey->pKeyData) || (NULL == ppPub) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Validate that this is a TAP key */
    if (0 == (MOC_LOCAL_TYPE_TAP & pKey->pPublicKey->localType))
    {
        status = ERR_UNSUPPORTED_OPERATION;
        goto exit;
    }

    pData = (MRsaTapKeyData *)(pKey->pPublicKey->pKeyData);
    if (NULL == pData->pKey)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pRsaTapPub = (TAP_RSAPublicKey *)(&(pData->pKey->keyData.publicKey.publicKey.rsaKey));

    /* Exponent length must fit into a 32-bit integer */
    /* exponent is Little Endian */
    switch (pRsaTapPub->exponentLen)
    {
        case 4:  /* fallthrough on each */
            exponent |= (((ubyte4) (pRsaTapPub->pExponent[3])) << 24);
        case 3:
            exponent |= (((ubyte4) (pRsaTapPub->pExponent[2])) << 16);
        case 2:
            exponent |= (((ubyte4) (pRsaTapPub->pExponent[1])) << 8);
        case 1:
            exponent |= ((ubyte4) (pRsaTapPub->pExponent[0]));
            break;
        default:
            status = ERR_BAD_KEY;
            goto exit;
    }
    
    status = RSA_createKey(&pRsaKey);
    if (OK != status)
    {
        goto exit;
    }

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    status = (MSTATUS) HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
    {
        goto exit;
    }
#endif

    status = RSA_setPublicKeyParameters( MOC_RSA(hwAccelCtx)
        pRsaKey, exponent, pRsaTapPub->pModulus, pRsaTapPub->modulusLen, NULL);
    if (OK != status)
    {
        goto exit;
    }

    *ppPub = pRsaKey;
    pRsaKey = NULL;

exit:

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
#endif

    if (NULL != pRsaKey)
    {
        RSA_freeKey(&pRsaKey, NULL);
    }

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif /* __ENABLE_DIGICERT_TAP__ */
}

/*---------------------------------------------------------------------------*/

MSTATUS
CRYPTO_INTERFACE_getRSAPublicKey(AsymmetricKey *pKey, RSAKey **ppPub)
{
    MSTATUS status = OK;
    RSAKey *pRsaKey = NULL;

    if ((NULL == pKey) || (NULL == ppPub) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (akt_tap_rsa == pKey->type)
    {
        status = CRYPTO_INTERFACE_getRsaSwPubFromTapKey(
            pKey->key.pRSA, &pRsaKey);
        if (OK != status)
        {
            goto exit;
        }
    }
    else if (akt_rsa == pKey->type)
    {
        if (NULL == pKey->key.pRSA)
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
        pRsaKey = pKey->key.pRSA;
    }
    else
    {
        status = ERR_CRYPTO_BAD_KEY_TYPE;
        goto exit;
    }
    *ppPub = pRsaKey;
    pRsaKey = NULL;

exit:
    if ((NULL != pKey) && (akt_tap_rsa == pKey->type))
    {
        if (NULL != pRsaKey)
        {
            RSA_freeKey(&pRsaKey, NULL);
        }
    }
    return status;
}
#endif /* __DISABLE_DIGICERT_RSA__ */

/*---------------------------------------------------------------------------*/

#if !defined(__DISABLE_DIGICERT_RSA__) || defined(__ENABLE_DIGICERT_ECC__)

extern MSTATUS CRYPTO_INTERFACE_getPublicKey(
    AsymmetricKey *pKey, AsymmetricKey *pPubKey)
{
    MSTATUS status;

    if ( (NULL == pKey) || (NULL == pPubKey) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    CRYPTO_uninitAsymmetricKey(pPubKey, NULL);

    switch (pKey->type & 0xFF)
    {
#if !defined(__DISABLE_DIGICERT_RSA__)
        case akt_rsa:
        case akt_rsa_pss:
            status = CRYPTO_INTERFACE_getRSAPublicKey(
                pKey, &(pPubKey->key.pRSA));
            if (OK != status)
            {
                goto exit;
            }
            pPubKey->type = (pKey->type) & 0xFF;
            break;
#endif

#if defined(__ENABLE_DIGICERT_ECC__)
        case akt_ecc:
        case akt_ecc_ed:
            status = CRYPTO_INTERFACE_getECCPublicKey(
                pKey, &(pPubKey->key.pECC));
            if (OK != status)
            {
                goto exit;
            }
            pPubKey->type = (pKey->type) & 0xFF;
            break;
#endif

        default:
            status = ERR_CRYPTO_BAD_KEY_TYPE;
            goto exit;
    }

exit:

    return status;
}

#endif

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_TAP__
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_TAP_AsymDeferUnload(AsymmetricKey *pKey, byteBoolean deferredTokenUnload)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pKey)
        return ERR_NULL_POINTER;

    switch (pKey->type)
    {
#ifdef __ENABLE_DIGICERT_ECC__
        case akt_tap_ecc:
            
            if (NULL == pKey->key.pECC)
                goto exit; /* still ERR_NULL_POINTER */

            status = OK;

            /* Only mark keys that are there and TAP */
            if (NULL != pKey->key.pECC->pPrivateKey && 0 != (MOC_LOCAL_TYPE_TAP & pKey->key.pECC->pPrivateKey->localType) )
            {
                status = CRYPTO_INTERFACE_TAP_eccDeferUnloadMocAsym(pKey->key.pECC->pPrivateKey, deferredTokenUnload);
                if (OK != status)
                    goto exit;
            }

            if (NULL != pKey->key.pECC->pPublicKey && 0 != (MOC_LOCAL_TYPE_TAP & pKey->key.pECC->pPublicKey->localType))
            { 
                status = CRYPTO_INTERFACE_TAP_eccDeferUnloadMocAsym(pKey->key.pECC->pPublicKey, deferredTokenUnload);
            }

            break;
#endif
        case akt_tap_rsa:

            if (NULL == pKey->key.pRSA)
                goto exit; /* still ERR_NULL_POINTER */

            status = OK;

            /* Only mark keys that are there and TAP */
            if (NULL != pKey->key.pRSA->pPrivateKey && 0 != (MOC_LOCAL_TYPE_TAP & pKey->key.pRSA->pPrivateKey->localType) )
            {
                status = CRYPTO_INTERFACE_TAP_rsaDeferUnloadMocAsym(pKey->key.pRSA->pPrivateKey, deferredTokenUnload);
                if (OK != status)
                    goto exit;
            }

            if (NULL != pKey->key.pRSA->pPublicKey && 0 != (MOC_LOCAL_TYPE_TAP & pKey->key.pRSA->pPublicKey->localType))
            { 
                status = CRYPTO_INTERFACE_TAP_rsaDeferUnloadMocAsym(pKey->key.pRSA->pPublicKey, deferredTokenUnload);
            }

            break;   

        default:
            status = ERR_TAP_INVALID_KEY_TYPE;
            break;
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_TAP_AsymGetKeyInfo(AsymmetricKey *pKey, ubyte4 keyType, TAP_TokenHandle *pTokenHandle, TAP_KeyHandle *pKeyHandle)
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pKey)
        return ERR_NULL_POINTER;

    switch (pKey->type)
    {
#ifdef __ENABLE_DIGICERT_ECC__
        case akt_tap_ecc:
            
            if (NULL == pKey->key.pECC)
                goto exit; /* still ERR_NULL_POINTER */

            status = ERR_TAP_INVALID_KEY_TYPE;

            if (MOC_ASYM_KEY_TYPE_PRIVATE == keyType && NULL != pKey->key.pECC->pPrivateKey && 
                0 != (MOC_LOCAL_TYPE_TAP & pKey->key.pECC->pPrivateKey->localType) )
            {
                status = CRYPTO_INTERFACE_TAP_eccGetKeyInfoMocAsym(pKey->key.pECC->pPrivateKey, pTokenHandle, pKeyHandle);
            }
            else if (MOC_ASYM_KEY_TYPE_PUBLIC == keyType && NULL != pKey->key.pECC->pPublicKey && 
                     0 != (MOC_LOCAL_TYPE_TAP & pKey->key.pECC->pPublicKey->localType) )
            {
                status = CRYPTO_INTERFACE_TAP_eccGetKeyInfoMocAsym(pKey->key.pECC->pPublicKey, pTokenHandle, pKeyHandle);
            }

            break;
#endif
        case akt_tap_rsa:

            if (NULL == pKey->key.pRSA)
                goto exit; /* still ERR_NULL_POINTER */

            status = ERR_TAP_INVALID_KEY_TYPE;;

            if (MOC_ASYM_KEY_TYPE_PRIVATE == keyType && NULL != pKey->key.pRSA->pPrivateKey && 
                0 != (MOC_LOCAL_TYPE_TAP & pKey->key.pRSA->pPrivateKey->localType) )
            {
                status = CRYPTO_INTERFACE_TAP_rsaGetKeyInfoMocAsym(pKey->key.pRSA->pPrivateKey, pTokenHandle, pKeyHandle);
            }
            else if (MOC_ASYM_KEY_TYPE_PUBLIC == keyType && NULL != pKey->key.pRSA->pPublicKey && 
                     0 != (MOC_LOCAL_TYPE_TAP & pKey->key.pRSA->pPublicKey->localType) )
            {
                status = CRYPTO_INTERFACE_TAP_rsaGetKeyInfoMocAsym(pKey->key.pRSA->pPublicKey, pTokenHandle, pKeyHandle);
            }

            break;   

        default:
            status = ERR_TAP_INVALID_KEY_TYPE;
            break;
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_TAP_rsaDeferUnloadMocAsym(MocAsymKey pKey, byteBoolean deferredTokenUnload)
{
    if (NULL == pKey || NULL == pKey->pKeyData)
        return ERR_NULL_POINTER;

    if (0 == (MOC_LOCAL_TYPE_TAP & pKey->localType) )
        return ERR_TAP_INVALID_KEY_TYPE;

    ((MRsaTapKeyData *) pKey->pKeyData)->isDeferUnload = TRUE;

    if (TRUE == deferredTokenUnload)
    {
        if (NULL == ((MRsaTapKeyData *) pKey->pKeyData)->pKey)
            return ERR_NULL_POINTER;

        ((MEccTapKeyData *) pKey->pKeyData)->pKey->deferredTokenUnload = TRUE;
    }
    
    return OK;
}

#if defined(__ENABLE_DIGICERT_ECC__)

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_TAP_eccDeferUnloadMocAsym(MocAsymKey pKey, byteBoolean deferredTokenUnload)
{
    if (NULL == pKey || NULL == pKey->pKeyData)
        return ERR_NULL_POINTER;

    if (0 == (MOC_LOCAL_TYPE_TAP & pKey->localType) )
        return ERR_TAP_INVALID_KEY_TYPE;

    ((MEccTapKeyData *) pKey->pKeyData)->isDeferUnload = TRUE;

    if (TRUE == deferredTokenUnload)
    {
        if (NULL == ((MEccTapKeyData *) pKey->pKeyData)->pKey)
            return ERR_NULL_POINTER;

        ((MEccTapKeyData *) pKey->pKeyData)->pKey->deferredTokenUnload = TRUE;
    }
    
    return OK;
}
#endif /* __ENABLE_DIGICERT_ECC__ */

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS 
CRYPTO_INTERFACE_TAP_rsaGetKeyInfoMocAsym(MocAsymKey pKey, TAP_TokenHandle *pTokenHandle, TAP_KeyHandle *pKeyHandle)
{
    MSTATUS status = ERR_NULL_POINTER;
    MRsaTapKeyData *pTapData = NULL;
    TAP_Key *pTapKey = NULL;

    if (NULL == pKey || NULL == pTokenHandle || NULL == pKeyHandle || NULL == pKey->pKeyData)
        goto exit;

    status = ERR_TAP_INVALID_KEY_TYPE;
    if ( 0 == (MOC_LOCAL_TYPE_TAP & pKey->localType) )
        goto exit;

    pTapData = (MRsaTapKeyData *) pKey->pKeyData;
    pTapKey = (TAP_Key *) pTapData->pKey;

    if (pTapData->isKeyLoaded)
    {
        *pTokenHandle = pTapKey->tokenHandle;
        *pKeyHandle = pTapKey->keyHandle;

         status = OK;
    }
    else
    {
        *pTokenHandle = 0;
        *pKeyHandle = 0;

        status = ERR_TAP_KEY_NOT_INITIALIZED;
    }

exit:

    return status;
}

#if defined(__ENABLE_DIGICERT_ECC__)

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS 
CRYPTO_INTERFACE_TAP_eccGetKeyInfoMocAsym(MocAsymKey pKey, TAP_TokenHandle *pTokenHandle, TAP_KeyHandle *pKeyHandle)
{
    MSTATUS status = ERR_NULL_POINTER;
    MEccTapKeyData *pTapData = NULL;
    TAP_Key *pTapKey = NULL;

    if (NULL == pKey || NULL == pTokenHandle || NULL == pKeyHandle || NULL == pKey->pKeyData)
        goto exit;

    status = ERR_TAP_INVALID_KEY_TYPE;
    if ( 0 == (MOC_LOCAL_TYPE_TAP & pKey->localType) )
        goto exit;

    pTapData = (MEccTapKeyData *) pKey->pKeyData;
    pTapKey = (TAP_Key *) pTapData->pKey;

    if (pTapData->isKeyLoaded)
    {
        *pTokenHandle = pTapKey->tokenHandle;
        *pKeyHandle = pTapKey->keyHandle;

         status = OK;
    }
    else
    {
        *pTokenHandle = 0;
        *pKeyHandle = 0;

        status = ERR_TAP_KEY_NOT_INITIALIZED;
    }

exit:

    return status;
}

#endif /* __ENABLE_DIGICERT_ECC__ */

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_asymGetTapObjectId(AsymmetricKey *pKey, ubyte **ppId, ubyte4 *pIdLen)
{
    MSTATUS status;
    TAP_Key *pTapKey = NULL;
    TAP_ObjectAttributes *pObjAttributes = NULL;
    ubyte4 i = 0;
    ubyte idFound = FALSE;

    status = ERR_NULL_POINTER;
    if ( (NULL == ppId) || (NULL == pIdLen) )
    {
        goto exit;
    }

    status = CRYPTO_INTERFACE_getTapKey(pKey, &pTapKey);
    if (OK != status)
        goto exit;

    pObjAttributes = &(pTapKey->providerObjectData.objectInfo.objectAttributes);
    if (NULL == pObjAttributes)
    {
        status = ERR_INVALID_INPUT;
        goto exit;
    }

    for (i = 0; i < pObjAttributes->listLen; i++)
    {
        if(TAP_ATTR_OBJECT_ID_BYTESTRING == pObjAttributes->pAttributeList[i].type)
        {
            if (NULL == pObjAttributes->pAttributeList[i].pStructOfType)
            {
                status = ERR_INVALID_INPUT;
                goto exit;
            }

            status = DIGI_MALLOC_MEMCPY (
                (void **)ppId, 
                ((TAP_Buffer *)(pObjAttributes->pAttributeList[i].pStructOfType))->bufferLen,
                ((TAP_Buffer *)(pObjAttributes->pAttributeList[i].pStructOfType))->pBuffer,
                ((TAP_Buffer *)(pObjAttributes->pAttributeList[i].pStructOfType))->bufferLen);
            if (OK != status)
                goto exit;

            *pIdLen = ((TAP_Buffer *)(pObjAttributes->pAttributeList[i].pStructOfType))->bufferLen;
            idFound = TRUE;
            break;
        }
    }

    if (FALSE == idFound)
    {
        status = ERR_NOT_FOUND;
    }

exit:
    return status;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_getTapKey(AsymmetricKey *pKey, TAP_Key **ppTapKey)
{
    MSTATUS status = ERR_NULL_POINTER;

    if ( (NULL == pKey) || (NULL == ppTapKey) )
    {
        goto exit;
    }

    status = ERR_INVALID_ARG;
    switch(pKey->type)
    {
#ifndef __DISABLE_DIGICERT_RSA__
        case akt_tap_rsa:
            status = CRYPTO_INTERFACE_RSA_getTapKey(pKey->key.pRSA, ppTapKey);
            break;
#endif
#ifdef __ENABLE_DIGICERT_ECC__
        case akt_tap_ecc:
            status = CRYPTO_INTERFACE_ECC_getTapKey(pKey->key.pECC, ppTapKey);
            break;
#endif

        default:
            goto exit;
    }

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_unloadTapKey(TAP_Context *pTapCtx, TAP_TokenHandle tokenHandle, TAP_KeyHandle keyHandle)
{
    TAP_CredentialList       *pKeyCredentials = NULL;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    MocAsymmetricKey         emptyKey = { 0 };
    MSTATUS                  status = OK;
    MSTATUS                  status1 = OK;
    intBoolean               releaseContext = FALSE;

	if ((NULL == pTapCtx) && (NULL != g_pFuncPtrGetTapContext))
    {
        status = g_pFuncPtrGetTapContext(&pTapCtx, &(pEntityCredentials),
                                         &(pKeyCredentials), (void *)&emptyKey, tap_key_unload, 1);
        if (OK != status)
            goto exit;

        releaseContext = TRUE;
    }

    if (NULL == pTapCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = TAP_unloadSmpKey(pTapCtx, tokenHandle, keyHandle);

exit:
    if (releaseContext && (NULL != g_pFuncPtrGetTapContext))
    {
        status1 = g_pFuncPtrGetTapContext(&pTapCtx, &(pEntityCredentials),
                                         &(pKeyCredentials), (void *)&emptyKey, tap_key_unload, 0);
        if (status >= OK)
        {
            status = status1;
        }
    }
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_unloadTapToken(TAP_Context *pTapCtx, TAP_TokenHandle tokenHandle)
{
    TAP_CredentialList       *pKeyCredentials = NULL;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    MocAsymmetricKey         emptyKey = { 0 };
    MSTATUS                  status = OK;
    MSTATUS                  status1 = OK;
    intBoolean               releaseContext = FALSE;

	if ((NULL == pTapCtx) && (NULL != g_pFuncPtrGetTapContext))
    {
        status = g_pFuncPtrGetTapContext(&pTapCtx, &(pEntityCredentials),
                                         &(pKeyCredentials), (void *)&emptyKey, tap_token_unload, 1);
        if (OK != status)
            goto exit;

        releaseContext = TRUE;
    }

    if (NULL == pTapCtx)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    status = TAP_uninitToken(pTapCtx, tokenHandle);

exit:
    if (releaseContext && (NULL != g_pFuncPtrGetTapContext))
    {
        status1 = g_pFuncPtrGetTapContext(&pTapCtx, &(pEntityCredentials),
                                         &(pKeyCredentials), (void *)&emptyKey, tap_token_unload, 0);
        if (status >= OK)
        {
            status = status1;
        }
    }
    return status;
}

/*---------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_RSA_getTapKey(RSAKey *pRsaKey, TAP_Key **ppTapKey)
{
    MSTATUS status = ERR_NULL_POINTER;
    MRsaTapKeyData *pData = NULL;

    if ( (NULL == ppTapKey) || (NULL == pRsaKey) || (NULL == pRsaKey->pPublicKey) )
    {
        goto exit;
    }

    /* Ensure this is a TAP key */
    status = ERR_INVALID_ARG;
    if (0 == (MOC_LOCAL_TYPE_TAP & pRsaKey->pPublicKey->localType))
    {
        goto exit;
    }

    pData = (MRsaTapKeyData *)(pRsaKey->pPublicKey->pKeyData);

    status = ERR_NULL_POINTER;
    if (NULL == pData)
    {
        goto exit;
    }

    *ppTapKey = pData->pKey;
    status = OK;

exit:

    return status;
}
#endif /* __DISABLE_DIGICERT_RSA__ */

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_ECC__
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_ECC_getTapKey(ECCKey *pEccKey, TAP_Key **ppTapKey)
{
    MSTATUS status = ERR_NULL_POINTER;
    MEccTapKeyData *pData = NULL;

    if ( (NULL == ppTapKey) || (NULL == pEccKey) || (NULL == pEccKey->pPublicKey) )
    {
        goto exit;
    }

    /* Ensure this is a TAP key */
    status = ERR_INVALID_ARG;
    if (0 == (MOC_LOCAL_TYPE_TAP & pEccKey->pPublicKey->localType))
    {
        goto exit;
    }

    pData = (MEccTapKeyData *)(pEccKey->pPublicKey->pKeyData);

    status = ERR_NULL_POINTER;
    if (NULL == pData)
    {
        goto exit;
    }

    *ppTapKey = pData->pKey;
    status = OK;

exit:

    return status;
}
#endif

#endif /* __ENABLE_DIGICERT_TAP__ */

/*---------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__

/* This function only applies for TAP attestation keys. Use
 * CRYPTO_INTERFACE_RSA_signMessageAux to handle both software and TAP
 * non-attestation keys. This function performs the digest of the plaintext
 * by using the underneath provider. For providers like TPM2, the digest of the
 * plaintext MUST be done by the TPM2 for attestation keys.
 */
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_RSA_signMessageEx(MOC_RSA(hwAccelDescr hwAccelCtx) void *pRSAKey,
        const ubyte* pPlainText, ubyte4 plainTextLen,
        ubyte* cipherText, vlong **ppVlongQueue, ubyte4 keyType)
{
#if defined(__ENABLE_DIGICERT_TAP__)
    MSTATUS status  = OK;
    MSTATUS status2 = OK;

    TAP_Buffer input =
    {
        .pBuffer    = NULL,
        .bufferLen  = 0
    };
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_Signature signature = {0};
    TAP_SIG_SCHEME sigScheme = TAP_SIG_SCHEME_NONE;
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_Key *pTapKey = NULL;
    TAP_Context *pTapContext = NULL;
    MocAsymKey pKey = NULL;
    MRsaTapKeyData *pInfo = NULL;

    if ((NULL == pPlainText) || (NULL == cipherText) || ( NULL == pRSAKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pKey = ((RSAKey *)(pRSAKey))->pPrivateKey;

    if ( (NULL == pKey) || (NULL == pKey->pKeyData) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* Validate that this is a TAP key */
    if (0 == (MOC_LOCAL_TYPE_TAP & pKey->localType))
    {
        status = ERR_UNSUPPORTED_OPERATION;
        goto exit;
    }

#if (defined(__ENABLE_DIGICERT_TAP_EXTERN__))
    if (OK > ( status = CRYPTO_INTERFACE_TAPExternInit()))
        goto exit;
#endif

    input.pBuffer = (ubyte*)pPlainText;
    input.bufferLen = plainTextLen;

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
        status = TAP_loadKey(pTapContext, pEntityCredentials, pTapKey, pKeyCredentials, NULL, pErrContext);
        if (OK != status)
            goto exit1;
        
        pInfo->isKeyLoaded = TRUE;
    }

    sigScheme = pTapKey->keyData.algKeyInfo.rsaInfo.sigScheme;

    status = TAP_asymSign(pTapKey, pEntityCredentials, NULL, sigScheme,
            TRUE, &input, &signature, pErrContext);
    if (OK != status)
        goto exit1;

    if (OK != (status = DIGI_MEMCPY((ubyte*)cipherText,
                    signature.signature.rsaSignature.pSignature,
                    signature.signature.rsaSignature.signatureLen)))
    {
        goto exit1;
    }
exit1:
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

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif /* defined(__ENABLE_DIGICERT_TAP__) */
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_RSA_signMessage(MOC_RSA(hwAccelDescr hwAccelCtx) void *pRSAKey,
        const ubyte* plainText, ubyte4 plainTextLen,
        ubyte* cipherText, vlong **ppVlongQueue, ubyte4 keyType)
{
    MOC_UNUSED(keyType);
    return RSA_signMessage (
        MOC_RSA(hwAccelCtx) (const RSAKey *)pRSAKey, plainText, plainTextLen,
        cipherText, ppVlongQueue);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_RSA_verifySignature(MOC_RSA(hwAccelDescr hwAccelCtx) void *pRSAKey,
    const ubyte* cipherText, ubyte* plainText, ubyte4* plainTextLen, vlong **ppVlongQueue, ubyte4 keyType)
{
    MOC_UNUSED(keyType);
    return RSA_verifySignature (
        MOC_RSA(hwAccelCtx) (const RSAKey *)pRSAKey, cipherText, plainText,
        plainTextLen, ppVlongQueue);
}
#endif /* __DISABLE_DIGICERT_RSA__ */

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#if (defined(__ENABLE_DIGICERT_ECC__))
#if defined(__ENABLE_DIGICERT_TAP__)
/* This is a static function which should be called only when the keyType is akt_tap_ecc
 * The data passed to this function can be plaintext or digestInfo.
 * This is specified by isDataNotDigest flag
 * isDataNotDigest = FALSE for digestInfo
 *                 = TRUE for plaintext
 */
static MSTATUS
CRYPTO_INTERFACE_TAP_ECDSA_signEx(void *pECCKey, RNGFun rngFun, void *rngArg,
                                  const ubyte* data, ubyte4 dataLen,
                                  PFEPtr r, PFEPtr s, byteBoolean isDataNotDigest)
{
    MSTATUS status  = OK;
    MSTATUS status2 = OK;
    TAP_Buffer input = {0};/* This can be plaintext or digestInfo based on the isDataNotDigest flag */
    TAP_ErrorContext errContext;
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_Signature signature = {0};
    TAP_SIG_SCHEME sigScheme = TAP_SIG_SCHEME_NONE;
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_Context *pTapContext = NULL;
    TAP_Key *pTapKey = NULL;
    MocAsymKey pKey = (MocAsymKey)pECCKey;
    PEllipticCurvePtr pECCurve = NULL;
    MEccTapKeyData *pInfo = NULL;

    if ((NULL == data) || (NULL == pKey))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#if (defined(__ENABLE_DIGICERT_TAP_EXTERN__))
    if (OK > ( status = CRYPTO_INTERFACE_TAPExternInit()))
        goto exit;
#endif

    input.pBuffer = (ubyte*)data;
    input.bufferLen = dataLen;

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
        status = TAP_loadKey(pTapContext, pEntityCredentials, pTapKey, pKeyCredentials, NULL, pErrContext);
        if (OK != status)
            goto exit;
        
        pInfo->isKeyLoaded = TRUE;
    }

    sigScheme = pTapKey->keyData.algKeyInfo.eccInfo.sigScheme;

    status = TAP_asymSign(pTapKey, pEntityCredentials, NULL, sigScheme,
                          isDataNotDigest, &input, &signature, pErrContext);
    if (OK != status)
        goto exit;

    switch (pTapKey->keyData.algKeyInfo.eccInfo.curveId)
    {
#ifdef __ENABLE_DIGICERT_ECC_P192__
        case TAP_ECC_CURVE_NIST_P192:
            pECCurve = EC_P192;
            break;
#endif
        case TAP_ECC_CURVE_NIST_P224:
            pECCurve = EC_P224;
            break;
        case TAP_ECC_CURVE_NIST_P256:
            pECCurve = EC_P256;
            break;
        case TAP_ECC_CURVE_NIST_P384:
            pECCurve = EC_P384;
            break;
        case TAP_ECC_CURVE_NIST_P521:
            pECCurve = EC_P521;
            break;
        default:
            status = ERR_EC_UNSUPPORTED_CURVE;
            goto exit;
    }

    if (OK != (status = PRIMEFIELD_setToByteString(pECCurve->pPF, r, signature.signature.eccSignature.pRData,
                               signature.signature.eccSignature.rDataLen)))
    {
        goto exit;
    }

    if (OK != (status = PRIMEFIELD_setToByteString(pECCurve->pPF, s, signature.signature.eccSignature.pSData,
                               signature.signature.eccSignature.sDataLen)))
    {
        goto exit;
    }

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"ECDSA sign failed with status = ", status);

    TAP_freeSignature(&signature);

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
                                                    (void *)pKey, tap_ecc_sign, 0/*release context*/)))
        {
            DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"TAP Context release failed with status = ", status2);
        }
    }

    /* if we failed in the cleanup, record the failure */
    if ((OK == status) && (OK > status2))
        status = status2;

    return status;

}
#endif

/* This function is deprecated. Use CRYPTO_INTERFACE_ECDSA_signDigestAux
 * instead.
 */
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_ECDSA_sign(void *pECCKey, RNGFun rngFun, void *rngArg,
                                     const ubyte* hash, ubyte4 hashLen,
                                     PFEPtr r, PFEPtr s, ubyte4 keyType)
{
    MSTATUS status  = OK;

    if (keyType == akt_tap_ecc)
    {
#if defined(__ENABLE_DIGICERT_TAP__)
        if (OK > (status = CRYPTO_INTERFACE_TAP_ECDSA_signEx(pECCKey, rngFun, rngArg,
                                                             hash, hashLen, r, s, FALSE)))
        {
            DEBUG_ERROR(DEBUG_TAP_MESSAGES, "CRYPTO_INTERFACE_TAP_ECDSA_signEx failed with status = ", status);
        }
#else
        status = ERR_TAP_UNSUPPORTED;
#endif
    }
    else
    {
        ECCKey *pKey = (ECCKey *)pECCKey;

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
        if (OK > ( status = ECDSA_signDigestAux( pKey->pCurve,
                                pKey->k,
                                rngFun, rngArg,
                                hash, hashLen,
                                r, s)))
#else
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif
        {
            DEBUG_ERROR(DEBUG_CRYPTO, "ECDSA_signDigestAux failed with status = ", status);
        }
    }

    return status;
}

/*---------------------------------------------------------------------------*/

/* This function is deprecated. Use CRYPTO_INTERFACE_ECDSA_signDigestAux for
 * software and TAP keys.
 */
extern MSTATUS
CRYPTO_INTERFACE_ECDSA_signEx(void *pECCKey, RNGFun rngFun, void *rngArg,
                                     const ubyte* pPlainText, ubyte4 plainTextLen,
                                     PFEPtr r, PFEPtr s, ubyte4 keyType)
{
    MSTATUS status = OK;

    if ((NULL == pPlainText) || (NULL == pECCKey))
    {
        return ERR_NULL_POINTER;
    }

    if (keyType == akt_tap_ecc)
    {
#if defined(__ENABLE_DIGICERT_TAP__)
        if (OK > (status = CRYPTO_INTERFACE_TAP_ECDSA_signEx(pECCKey, rngFun, rngArg,
                                                             pPlainText, plainTextLen, r, s, TRUE/*isDataNotDigest*/)))
        {
            DEBUG_ERROR(DEBUG_TAP_MESSAGES, "CRYPTO_INTERFACE_TAP_ECDSA_signEx failed with status = ", status);
        }
#else
        status = ERR_TAP_UNSUPPORTED;
#endif
    }
    else
    {
        ECCKey *pKey = (ECCKey *)pECCKey;

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
        if (OK > ( status = ECDSA_signDigestAux( pKey->pCurve,
                                pKey->k,
                                rngFun, rngArg,
                                pPlainText, plainTextLen,
                                r, s)))
#else
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif
        {
            DEBUG_ERROR(DEBUG_CRYPTO, "ECDSA_signDigestAux failed with status = ", status);
        }
    }

    return status;
}

/*---------------------------------------------------------------------------*/

/* This function is deprecated. Use
 * CRYPTO_INTERFACE_ECDSA_verifySignatureDigestAux instead.
 */
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_ECDSA_verifySignature( void *pECCKey, const ubyte* hash, ubyte4 hashLen,
                                           ConstPFEPtr r, ConstPFEPtr s, ubyte4 keyType)
{
    MSTATUS status  = OK;
#if defined(__ENABLE_DIGICERT_TAP__)
    MSTATUS status2 = OK;
#endif

    if ((NULL == hash) || (NULL == pECCKey))
    {
        return ERR_NULL_POINTER;
    }

    if (keyType == akt_tap_ecc)
    {
#if defined(__ENABLE_DIGICERT_TAP__)
        ubyte digestBuf[SHA512_RESULT_SIZE];
        TAP_Buffer digest =
        {
            .pBuffer    = digestBuf,
            .bufferLen  = 0
        };
        TAP_ErrorContext errContext = {0};
        TAP_ErrorContext *pErrContext = &errContext;
        TAP_Signature signature = {0};
        TAP_SIG_SCHEME sigScheme = TAP_SIG_SCHEME_NONE;
        TAP_CredentialList *pKeyCredentials = NULL;
        TAP_EntityCredentialList *pEntityCredentials = NULL;
        TAP_OP_EXEC_FLAG opExecFlag = TAP_OP_EXEC_FLAG_HW;
        byteBoolean isSigValid = 0;
        TAP_Context *pTapContext = NULL;
        TAP_Key *pTapKey = NULL;
        MocAsymKey pKey = (MocAsymKey)pECCKey;
        PEllipticCurvePtr pECCurve;
        ubyte *pR = NULL;
        ubyte *pS = NULL;
        sbyte4 rLen = 0, sLen=0;
        MEccTapKeyData *pInfo = NULL;

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
            goto exit;
        }
        pTapKey = (TAP_Key *)pInfo->pKey;

        digest.pBuffer = (ubyte*)hash;
        digest.bufferLen = hashLen;

        if (!pInfo->isKeyLoaded)
        {
            status = TAP_loadKey(pTapContext, pEntityCredentials, pTapKey, pKeyCredentials, NULL, pErrContext);
            if (OK != status)
                goto exit1;

            pInfo->isKeyLoaded = TRUE;
        }

        switch (pTapKey->keyData.algKeyInfo.eccInfo.curveId)
        {
#ifdef __ENABLE_DIGICERT_ECC_P192__
            case TAP_ECC_CURVE_NIST_P192:
                pECCurve = EC_P192;
                break;
#endif
            case TAP_ECC_CURVE_NIST_P224:
                pECCurve = EC_P224;
                break;
            case TAP_ECC_CURVE_NIST_P256:
                pECCurve = EC_P256;
                break;
            case TAP_ECC_CURVE_NIST_P384:
                pECCurve = EC_P384;
                break;
            case TAP_ECC_CURVE_NIST_P521:
                pECCurve = EC_P521;
                break;
            default:
                status = ERR_EC_UNSUPPORTED_CURVE;
                goto exit1;
        }

        PrimeFieldPtr pPF = EC_getUnderlyingField(pECCurve);

        if (OK != (status = PRIMEFIELD_getAsByteString(pPF, r, &pR, &rLen)))
        {
            goto exit1;
        }
        if (OK != (status = PRIMEFIELD_getAsByteString(pPF, s, &pS, &sLen)))
        {
            goto exit1;
        }
        signature.keyAlgorithm = TAP_KEY_ALGORITHM_ECC;
        signature.signature.eccSignature.pRData = pR;
        signature.signature.eccSignature.pSData = pS;
        signature.signature.eccSignature.rDataLen = rLen;
        signature.signature.eccSignature.sDataLen = sLen;

        sigScheme = pTapKey->keyData.algKeyInfo.eccInfo.sigScheme;

        status = TAP_asymVerifySignature(pTapKey, pEntityCredentials, NULL, opExecFlag,
                sigScheme, &digest, &signature, &isSigValid, pErrContext);

        if (!isSigValid)
        {
            /* Not valid */
            status = ERR_TAP_SIGN_VERIFY_FAIL;
            DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"ECDSA sign failed with status = ", status);
        }

exit1:
        TAP_freeSignature(&signature);

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
#else
        status = ERR_TAP_UNSUPPORTED;
#endif  /* defined(__ENABLE_DIGICERT_TAP__) */
    }
    else
    {
#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__))
        ECCKey *pKey = (ECCKey *)pECCKey;

        if ( OK > (status = ECDSA_verifySignature(pKey->pCurve, pKey->Qx, pKey->Qy, hash, hashLen, r, s)))
        {
            DEBUG_ERROR(DEBUG_CRYPTO, "ECDSA_verifySignature failed with status = ", status);
        }
#else
        status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif
    }

#if defined(__ENABLE_DIGICERT_TAP__)
exit:

    if ((OK == status) && (OK > status2))
        status = status2;
#endif

    return status;
}
#endif /* ifdef __ENABLE_DIGICERT_ECC__ */
#endif

/*---------------------------------------------------------------------------*/

#ifndef __DISABLE_DIGICERT_RSA__
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_RSA_createKey(
    void **ppNewKey,
    ubyte4 keyType,
    void *pKeyAttributes
    )
{
    MSTATUS status;

    if (akt_tap_rsa == keyType)
    {
        status = ERR_TAP_UNSUPPORTED;
    }
    else
    {
        status = RSA_createKey((RSAKey **) ppNewKey);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_RSA_freeKey(
    void **ppKey,
    vlong **ppVlongQueue,
    ubyte4 keyType
    )
{
    MOC_UNUSED(keyType);
    return RSA_freeKey((RSAKey **) ppKey, ppVlongQueue);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_RSA_setPublicKeyParameters(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    void *pKey,
    ubyte4 exponent,
    const ubyte *pModulus,
    ubyte4 modulusLen,
    vlong **ppVlongQueue,
    ubyte4 keyType
    )
{
    MOC_UNUSED(keyType);
    return RSA_setPublicKeyParameters( MOC_RSA(hwAccelCtx)
        pKey, exponent, pModulus, modulusLen, ppVlongQueue);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_RSA_setAllKeyData(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    void *pKey,
    ubyte *pPubExpo,
    ubyte4 pubExpoLen,
    const ubyte *pModulus,
    ubyte4 modulusLen,
    const ubyte *pPrime,
    ubyte4 primeLen,
    const ubyte *pSubprime,
    ubyte4 subprimeLen,
    vlong **ppVlongQueue,
    ubyte4 keyType
    )
{
    MOC_UNUSED(keyType);
    return RSA_setAllKeyData(
        MOC_RSA(hwAccelCtx) pKey, pPubExpo, pubExpoLen, pModulus, modulusLen,
        pPrime, primeLen, pSubprime, subprimeLen, ppVlongQueue);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_RSA_getKeyParametersAlloc(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    void *pKey,
    MRsaKeyTemplate *pTemplate,
    ubyte reqType,
    ubyte4 keyType
    )
{
    MOC_UNUSED(keyType);
    return RSA_getKeyParametersAlloc(MOC_RSA(hwAccelCtx) pKey, pTemplate, reqType);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_RSA_freeKeyTemplate(
    void *pKey,
    MRsaKeyTemplate *pTemplate,
    ubyte4 keyType
    )
{
    MOC_UNUSED(keyType);
    return RSA_freeKeyTemplate(pKey, pTemplate);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_RSA_applyPublicKey(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    void *pKey,
    ubyte *pInput,
    ubyte4 inputLen,
    ubyte **ppOutput,
    vlong **ppVlongQueue,
    ubyte4 keyType
    )
{
    MOC_UNUSED(keyType);
    return RSA_applyPublicKey(MOC_RSA(hwAccelCtx) pKey, pInput, inputLen, ppOutput, ppVlongQueue);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_RSA_applyPrivateKey(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    void *pKey,
    RNGFun rngFun,
    void *pRngFunArg,
    ubyte *pInput,
    ubyte4 inputLen,
    ubyte **ppOutput,
    vlong **ppVlongQueue,
    ubyte4 keyType
    )
{
    MOC_UNUSED(keyType);
    return RSA_applyPrivateKey(MOC_RSA(hwAccelCtx)
        pKey, rngFun, pRngFunArg, pInput, inputLen, ppOutput, ppVlongQueue);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_RSA_encrypt(MOC_RSA(hwAccelDescr hwAccelCtx) void *pRSAKey,
        const ubyte* plainText, ubyte4 plainTextLen, ubyte* cipherText,
        RNGFun rngFun, void* rngFunArg, vlong **ppVlongQueue, ubyte4 keyType)
{
    MOC_UNUSED(keyType);
    return RSA_encrypt(
        MOC_RSA(hwAccelCtx) pRSAKey, plainText, plainTextLen, cipherText,
        rngFun, rngFunArg, ppVlongQueue);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_RSA_decrypt(MOC_RSA(hwAccelDescr hwAccelCtx) void *pRSAKey,
        const ubyte* cipherText, ubyte* plainText, ubyte4* plainTextLen,
        RNGFun rngFun, void* rngFunArg, vlong **ppVlongQueue, ubyte4 keyType)
{
    MOC_UNUSED(keyType);
    return RSA_decrypt(
        MOC_RSA(hwAccelCtx) pRSAKey, cipherText, plainText, plainTextLen, rngFun,
        rngFunArg, ppVlongQueue);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_RSA_generateKeyAlloc (
    MOC_RSA(hwAccelDescr hwAccelCtx)
    randomContext *pRandomContext,
    void **ppNewKey,
    ubyte4 keySize,
    vlong **ppVlongQueue,
    ubyte4 keyType,
    void *pKeyAttributes
    )
{
    MSTATUS status;
    RSAKey *pNewKey = NULL;
#if defined(__ENABLE_DIGICERT_TAP__)
    MocAsymKey pPriKey = NULL, pPubKey = NULL;
    MocAsymmetricKey emptyKey = { 0 };
    MRsaTapKeyGenArgs *pTapKeyArgs = NULL;
    MocCtx pTapMocCtx = NULL;
#endif

    status = ERR_NULL_POINTER;
    if (NULL == ppNewKey)
        goto exit;

    if (akt_tap_rsa == keyType)
    {
#if defined(__ENABLE_DIGICERT_TAP__)

        /* Key attributes must be provided when generating a TAP key.
         */
        if (NULL == pKeyAttributes)
        {
            status = ERR_NULL_POINTER;
            DEBUG_ERROR(
                DEBUG_TAP_MESSAGES, (sbyte *)"ERROR: NULL key attributes", status);
            goto exit;
        }

        pTapKeyArgs = (MRsaTapKeyGenArgs *) pKeyAttributes;

        switch (keySize)
        {
            case 1024:
                pTapKeyArgs->algKeyInfo.rsaInfo.keySize = TAP_KEY_SIZE_1024;
                break;

            case 2048:
                pTapKeyArgs->algKeyInfo.rsaInfo.keySize = TAP_KEY_SIZE_2048;
                break;

            case 3072:
                pTapKeyArgs->algKeyInfo.rsaInfo.keySize = TAP_KEY_SIZE_3072;
                break;

            case 4096:
                pTapKeyArgs->algKeyInfo.rsaInfo.keySize = TAP_KEY_SIZE_4096;
                break;

            case 8192:
                pTapKeyArgs->algKeyInfo.rsaInfo.keySize = TAP_KEY_SIZE_8192;
                break;

            default:
                status = ERR_INVALID_ARG;
                DEBUG_ERROR(
                    DEBUG_TAP_MESSAGES, (sbyte *)"ERROR: Invalid key size",
                    keySize);
                goto exit;
        }

#ifdef __ENABLE_DIGICERT_TAP_EXTERN__
        if (OK > (status = CRYPTO_INTERFACE_TAPExternInit()))
            goto exit;
#endif

        status = CRYPTO_INTERFACE_getTapMocCtx(&pTapMocCtx);
        if (OK != status)
            goto exit;

        if (NULL == pTapKeyArgs->pTapCtx)
        {
            if (NULL != g_pFuncPtrGetTapContext)
            {
                status = g_pFuncPtrGetTapContext(
                    &(pTapKeyArgs->pTapCtx),
                    &(pTapKeyArgs->pEntityCredentials),
                    &(pTapKeyArgs->pKeyCredentials),
                    (void *)&emptyKey, tap_rsa_generate, 1);
                if (OK != status)
                    goto exit;
            }
            else
            {
                status = ERR_NOT_IMPLEMENTED;
                goto exit;
            }
        }

        /* Generate a TAP key. Only a private key will be generated.
         */
        status = CRYPTO_generateKeyPair(
            KeyOperatorRsaTap, (MRsaTapKeyGenArgs *) pKeyAttributes, pTapMocCtx,
            NULL, NULL, &pPubKey, &pPriKey, ppVlongQueue);

        if (OK != status)
        {
            DEBUG_ERROR(
                DEBUG_TAP_MESSAGES,
                (sbyte *)"ERROR: CRYPTO_generateKeyPair failed", status);
        }

        status = CRYPTO_INTERFACE_RSA_loadKeys(&pNewKey, &pPriKey, &pPubKey);
        if (OK != status)
            goto exit;

        *ppNewKey = pNewKey;
        pNewKey = NULL;
#else
        status = ERR_TAP_UNSUPPORTED;
#endif
    }
    else
    {
        status = RSA_createKey(&pNewKey);
        if (OK != status)
            goto exit;

        status = RSA_generateKey (
            MOC_RSA(hwAccelCtx) pRandomContext, pNewKey,
            keySize, ppVlongQueue);
        if (OK != status)
            goto exit;

        *ppNewKey = pNewKey;
        pNewKey = NULL;
    }

exit:
#if defined(__ENABLE_DIGICERT_TAP__)
    if (NULL != pPriKey)
    {
        CRYPTO_freeMocAsymKey(&pPriKey, ppVlongQueue);
    }
    if (NULL != pPubKey)
    {
        CRYPTO_freeMocAsymKey(&pPubKey, ppVlongQueue);
    }
#endif
    if (NULL != pNewKey)
    {
        RSA_freeKey(&pNewKey, ppVlongQueue);
    }

    return status;
}
#endif /* __DISABLE_DIGICERT_RSA__ */

/*---------------------------------------------------------------------------*/

typedef struct GenHashCtx
{
    MocSymCtx pMocSymCtx;
    ubyte4 enabled;
    ubyte4 hashId;

} GenHashCtx;

/*---------------------------------------------------------------------------*/

/* To be supported for a particular hashing context the context must 
   begin with the same structure as genHashCtx */

extern MSTATUS CRYPTO_INTERFACE_cloneHashCtx (
    MOC_HASH(hwAccelDescr hwAccelCtx)
    BulkCtx pSrc,
    BulkCtx pDest,
    ubyte4 size
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    /* size unused but left in as a parameter for legacy purposes */
    MOC_UNUSED(size);

    if ( NULL == pSrc || NULL == pDest )
        goto exit;

    switch ( ((GenHashCtx *) pSrc)->hashId )
    {

#ifdef __ENABLE_DIGICERT_MD4__
        case ht_md4:
            status = CRYPTO_INTERFACE_MD4_cloneCtx(MOC_HASH(hwAccelCtx) (MD4_CTX *) pDest, (MD4_CTX *) pSrc);
            break;
#endif

        case ht_md5:
            status = CRYPTO_INTERFACE_MD5_cloneCtx(MOC_HASH(hwAccelCtx) (MD5_CTX *) pDest, (MD5_CTX *) pSrc);
            break;

        case ht_sha1:
            status = CRYPTO_INTERFACE_SHA1_cloneCtx(MOC_HASH(hwAccelCtx) (SHA1_CTX *) pDest, (SHA1_CTX *) pSrc);
            break;

#ifndef __DISABLE_DIGICERT_SHA224__
        case ht_sha224:
            status = CRYPTO_INTERFACE_SHA224_cloneCtx(MOC_HASH(hwAccelCtx) (SHA224_CTX *) pDest, (SHA224_CTX *) pSrc);
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
        case ht_sha256:
            status = CRYPTO_INTERFACE_SHA256_cloneCtx(MOC_HASH(hwAccelCtx) (SHA256_CTX *) pDest, (SHA256_CTX *) pSrc);
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
        case ht_sha384:
            status = CRYPTO_INTERFACE_SHA384_cloneCtx(MOC_HASH(hwAccelCtx) (SHA384_CTX *) pDest, (SHA384_CTX *) pSrc);
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
        case ht_sha512:
            status = CRYPTO_INTERFACE_SHA512_cloneCtx(MOC_HASH(hwAccelCtx) (SHA512_CTX *) pDest, (SHA512_CTX *) pSrc);
            break;
#endif

#ifdef __ENABLE_DIGICERT_SHA3__
        case ht_sha3_224:
        case ht_sha3_256:
        case ht_sha3_384:
        case ht_sha3_512:
        case ht_shake128:
        case ht_shake256:
            status = CRYPTO_INTERFACE_SHA3_cloneCtx(MOC_HASH(hwAccelCtx) (SHA3_CTX *) pDest, (SHA3_CTX *) pSrc);
            break;
#endif

#ifdef __ENABLE_DIGICERT_BLAKE_2B__
        case ht_blake2b:
            status = CRYPTO_INTERFACE_BLAKE_2B_cloneCtx(MOC_HASH(hwAccelCtx) (BLAKE2B_CTX *) pDest, (BLAKE2B_CTX *) pSrc);
            break;
#endif

#ifdef __ENABLE_DIGICERT_BLAKE_2S__
        case ht_blake2s:
            status = CRYPTO_INTERFACE_BLAKE_2S_cloneCtx(MOC_HASH(hwAccelCtx) (BLAKE2S_CTX *) pDest, (BLAKE2S_CTX *) pSrc);
            break;
#endif

        default:
            status = ERR_INVALID_ARG;
    }

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

/* To be supported for a particular hashing context the context must 
   begin with the same structure as genHashCtx */

extern MSTATUS CRYPTO_INTERFACE_freeCloneHashCtx (
    BulkCtx pCtx
    )
{
    MSTATUS status = OK;
    GenHashCtx *pShaCtx = NULL;

    /* It is not an error to attempt to free a NULL context */
    if (NULL != pCtx)
    {
        pShaCtx = (GenHashCtx *)pCtx;
        if ( (NULL != pShaCtx->pMocSymCtx) &&
             (CRYPTO_INTERFACE_ALGO_ENABLED == pShaCtx->enabled) )
        {
            status = CRYPTO_freeMocSymCtx(&(pShaCtx->pMocSymCtx));
        }
    }

    return status;
}

/*---------------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_ECC__))

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_EC_newKeyEx (
    ubyte4 curveId,
    ECCKey** ppNewKey,
    ubyte4 keyType,
    void *pKeyAttributes
    )
{
    MSTATUS status;

    if (akt_tap_ecc == keyType)
    {
        status = ERR_TAP_UNSUPPORTED;
    }
    else
    {
        status = EC_newKeyEx (
            curveId, (ECCKey **)ppNewKey);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

/* Produces concatenation of r and s as big endian bytestrings, zero padded
 * if necessary to ensure each bytestring is exactly element length. */
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_ECDSA_signDigest (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    void *pECCKey,
    RNGFun rngFun,
    void* rngArg,
    ubyte *pHash,
    ubyte4 hashLen,
    ubyte *pSignature,
    ubyte4 bufferSize,
    ubyte4 *pSignatureLen,
    ubyte4 keyType
    )
{
    MOC_UNUSED(keyType);
    return ECDSA_signDigest ( MOC_ECC(hwAccelCtx)
        (ECCKey *)pECCKey, rngFun, rngArg, pHash, hashLen, pSignature,
        bufferSize, pSignatureLen);
}

/*---------------------------------------------------------------------------*/

/* This function only applies for TAP keys and digests the message based on the
 * TAP parameters used to generate the key. For control over which digest is
 * used, compute the digest and use CRYPTO_INTERFACE_ECDSA_signDigestAux
 * instead, which works for both software and TAP keys. Refer to the existing
 * usage in crypto_interface_ecc_example.c.
 */
MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_ECDSA_signMessage (
    void *pECCKey,
    RNGFun rngFun,
    void* rngArg,
    ubyte *pMessage,
    ubyte4 messageLen,
    ubyte *pSignature,
    ubyte4 bufferSize,
    ubyte4 *pSignatureLen,
    ubyte4 keyType
    )
{
#if defined(__ENABLE_DIGICERT_TAP__)
    MSTATUS status = ERR_UNSUPPORTED_OPERATION;
    MSTATUS status2 = ERR_UNSUPPORTED_OPERATION;

    MocAsymKey pPrivateKey = NULL;
    TAP_Buffer message = {0};
    TAP_ErrorContext errContext = NULL;
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_Signature signature = {0};
    TAP_SIG_SCHEME sigScheme = TAP_SIG_SCHEME_NONE;
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_Context *pTapContext = NULL;
    TAP_Key *pTapKey = NULL;
    MocAsymKey pKey = NULL;
    MEccTapKeyData *pInfo = NULL;
    ubyte4 elementLen = 0;

    if ( (NULL == pMessage) || (NULL == pECCKey) || (NULL == pSignatureLen) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    /* This function is TAP only, there is no software version so this must be
     * a TAP key to work */
    pPrivateKey = ((ECCKey *)(pECCKey))->pPrivateKey;
    if ( (NULL == pPrivateKey) || (NULL == pPrivateKey->pKeyData) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    if (0 == (MOC_LOCAL_TYPE_TAP & pPrivateKey->localType))
    {
        status = ERR_UNSUPPORTED_OPERATION;
        goto exit;
    }

    pKey = pPrivateKey;

#if (defined(__ENABLE_DIGICERT_TAP_EXTERN__))
    if (OK > ( status = CRYPTO_INTERFACE_TAPExternInit()))
        goto exit;
#endif

    /* Get the element length to determine if the buffer is large enough */
    status = CRYPTO_INTERFACE_EC_getElementByteStringLen(pECCKey, &elementLen, akt_tap_ecc);
    if (OK != status)
        goto exit;

    if (bufferSize < (2 * elementLen))
    {
        *pSignatureLen = (2 * elementLen);
        status = ERR_BUFFER_TOO_SMALL;
        goto exit;
    }

    message.pBuffer = (ubyte*)pMessage;
    message.bufferLen = messageLen;

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
        status = TAP_loadKey(pTapContext, pEntityCredentials, pTapKey, pKeyCredentials, NULL, pErrContext);
        if (OK != status)
            goto exit;

        pInfo->isKeyLoaded = TRUE;
    }

    sigScheme = pTapKey->keyData.algKeyInfo.eccInfo.sigScheme;

    status = TAP_asymSign(pTapKey, pEntityCredentials, NULL, sigScheme,
             TRUE, &message, &signature, pErrContext);
    if (OK != status)
        goto exit;

    /* Copy the data into the signature buffer as (r || s) */
    status = DIGI_MEMCPY (
        pSignature,
        signature.signature.eccSignature.pRData,
        signature.signature.eccSignature.rDataLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY (
        pSignature + elementLen,
        signature.signature.eccSignature.pSData,
        signature.signature.eccSignature.sDataLen);

exit:
    if (OK > status)
        DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"ECDSA sign failed with status = ", status);
    else
        *pSignatureLen = signature.signature.eccSignature.rDataLen +
            signature.signature.eccSignature.sDataLen;

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

    if ((OK == status) && (OK > status2))
        status = status2;

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_ECDSA_verifySignatureDigest (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    void *pPublicKey,
    ubyte *pHash,
    ubyte4 hashLen,
    ubyte *pR,
    ubyte4 rLen,
    ubyte *pS,
    ubyte4 sLen,
    ubyte4 *pVerifyFailures,
    ubyte4 keyType
    )
{
    MOC_UNUSED(keyType);
    return ECDSA_verifySignatureDigest ( MOC_ECC(hwAccelCtx)
        (ECCKey *)pPublicKey, pHash, hashLen, pR, rLen, pS, sLen, pVerifyFailures);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_EC_generateKeyPairAlloc (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ubyte4 curveId,
    void **ppNewKey,
    RNGFun rngFun,
    void* rngArg,
    ubyte4 keyType,
    void *pKeyAttributes
    )
{
    MSTATUS status = OK;
#if defined(__ENABLE_DIGICERT_TAP__)
    MocAsymKey pPriKey = NULL, pPubKey = NULL;
    MocAsymmetricKey emptyKey = { 0 };
    MEccTapKeyGenArgs *pTapKeyArgs = NULL;
    MocCtx pTapMocCtx = NULL;
    ECCKey *pNewKey = NULL;
#endif

    if (akt_tap_ecc == keyType)
    {
#if defined(__ENABLE_DIGICERT_TAP__)

        /* Key attributes must be provided when generating a TAP key.
         */
        if (NULL == pKeyAttributes)
        {
            status = ERR_NULL_POINTER;
            DEBUG_ERROR(
                DEBUG_TAP_MESSAGES, (sbyte *)"ERROR: NULL key attributes", status);
            goto exit;
        }

        pTapKeyArgs = (MEccTapKeyGenArgs *) pKeyAttributes;
        switch (curveId)
        {
            case cid_EC_P192:
                pTapKeyArgs->algKeyInfo.eccInfo.curveId = TAP_ECC_CURVE_NIST_P192;
                break;

            case cid_EC_P224:
                pTapKeyArgs->algKeyInfo.eccInfo.curveId = TAP_ECC_CURVE_NIST_P224;
                break;

            case cid_EC_P256:
                pTapKeyArgs->algKeyInfo.eccInfo.curveId = TAP_ECC_CURVE_NIST_P256;
                break;

            case cid_EC_P384:
                pTapKeyArgs->algKeyInfo.eccInfo.curveId = TAP_ECC_CURVE_NIST_P384;
                break;

            case cid_EC_P521:
                pTapKeyArgs->algKeyInfo.eccInfo.curveId = TAP_ECC_CURVE_NIST_P521;
                break;

            default:
                status = ERR_INVALID_ARG;
                DEBUG_ERROR(
                    DEBUG_TAP_MESSAGES, (sbyte *)"ERROR: Invalid curveid %d",
                    curveId);
                goto exit;
        }

#ifdef __ENABLE_DIGICERT_TAP_EXTERN__
        if (OK > ( status = CRYPTO_INTERFACE_TAPExternInit()))
            goto exit;
#endif

        status = CRYPTO_INTERFACE_getTapMocCtx(&pTapMocCtx);
        if (OK != status)
            goto exit;

        if (NULL == pTapKeyArgs->pTapCtx)
        {
            if (NULL != g_pFuncPtrGetTapContext)
            {
                status = g_pFuncPtrGetTapContext(
                    &(pTapKeyArgs->pTapCtx),
                    &(pTapKeyArgs->pEntityCredentials),
                    &(pTapKeyArgs->pKeyCredentials),
                    (void *)&emptyKey, tap_ecc_generate, 1);
                if (OK != status)
                    goto exit;
            }
            else
            {
                status = ERR_NOT_IMPLEMENTED;
                goto exit;
            }
        }

        /* Generate a TAP key. Only a private key will be generated.
         */
        status = CRYPTO_generateKeyPair(
            KeyOperatorEccTap, (MEccTapKeyGenArgs *) pKeyAttributes, pTapMocCtx,
            NULL, NULL, &pPubKey, &pPriKey, NULL);
        if (OK != status)
        {
            DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte *)"ERROR: CRYPTO_generateKeyPair failed", status);
        }

        status = CRYPTO_INTERFACE_EC_loadKeys(&pNewKey, &pPriKey, &pPubKey);
        if (OK != status)
            goto exit;

        *ppNewKey = pNewKey;
        pNewKey = NULL;
#else
        status = ERR_TAP_UNSUPPORTED;
#endif
    }
    else
    {
        status = EC_generateKeyPairAlloc (MOC_ECC(hwAccelCtx)
            curveId, (ECCKey **)ppNewKey, rngFun, rngArg);
    }

#if defined(__ENABLE_DIGICERT_TAP__)
exit:
    if (NULL != pPriKey)
    {
	    CRYPTO_freeMocAsymKey(&pPriKey, NULL);
    }
    if (NULL != pNewKey)
    {
        EC_deleteKeyEx(&pNewKey);
    }
#endif

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_ECDH_generateSharedSecretFromKeys (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    void *pPrivateKey,
    void *pPublicKey,
    ubyte **ppSharedSecret,
    ubyte4 *pSharedSecretLen,
    sbyte4 flag,
    void *pKdfInfo,
    ubyte4 keyType
    )
{
    MOC_UNUSED(keyType);
    return ECDH_generateSharedSecretFromKeys ( MOC_ECC(hwAccelCtx)
        (ECCKey *)pPrivateKey, (ECCKey *)pPublicKey, ppSharedSecret,
        pSharedSecretLen, flag, pKdfInfo);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_ECDH_generateSharedSecretFromPublicByteString (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    void *pPrivateKey,
    ubyte *pPublicPointByteString,
    ubyte4 pointByteStringLen,
    ubyte **ppSharedSecret,
    ubyte4 *pSharedSecretLen,
    sbyte4 flag,
    void *pKdfInfo,
    ubyte4 keyType
    )
{
    MOC_UNUSED(keyType);
    return ECDH_generateSharedSecretFromPublicByteString ( MOC_ECC(hwAccelCtx)
        (ECCKey *)pPrivateKey, pPublicPointByteString, pointByteStringLen,
        ppSharedSecret, pSharedSecretLen, flag, pKdfInfo);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_cloneKey (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    void **ppNew,
    void *pSrc,
    ubyte4 keyType
    )
{
    MOC_UNUSED(keyType);
    return EC_cloneKeyEx(MOC_ECC(hwAccelCtx) (ECCKey **)ppNew, (ECCKey *)pSrc);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_EC_getCurveIdFromKey (
    void *pKey,
    ubyte4 *pCurveId,
    ubyte4 keyType
    )
{
    MOC_UNUSED(keyType);
    return EC_getCurveIdFromKey((ECCKey *)pKey, pCurveId);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_EC_getElementByteStringLen (
    void *pKey,
    ubyte4 *pLen,
    ubyte4 keyType
    )
{
    MOC_UNUSED(keyType);
    return EC_getElementByteStringLen((ECCKey *)pKey, pLen);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_getPointByteStringLenEx (
    void *pKey,
    ubyte4 *pLen,
    ubyte4 keyType
  )
{
    MOC_UNUSED(keyType);
    return EC_getPointByteStringLenEx((ECCKey *)pKey, pLen);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_EC_deleteKey (
    void **ppKey,
    ubyte4 keyType
    )
{
    MOC_UNUSED(keyType);
    return EC_deleteKeyEx((ECCKey **)ppKey);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_EC_writePublicKeyToBuffer (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    void *pKey,
    ubyte *pBuffer,
    ubyte4 bufferSize,
    ubyte4 keyType
    )
{
    MOC_UNUSED(keyType);
    return EC_writePublicKeyToBuffer(MOC_ECC(hwAccelCtx) pKey, pBuffer, bufferSize);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_EC_writePublicKeyToBufferAlloc (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    void *pKey,
    ubyte **ppBuffer,
    ubyte4 *pBufferSize,
    ubyte4 keyType
    )
{
    MSTATUS status;
    ubyte4 elementLen, bufferSize;
    ubyte *pBuffer = NULL;

    status = ERR_NULL_POINTER;
    if ( (NULL == pKey) || (NULL == ppBuffer) || (NULL == pBufferSize) )
        goto exit;

    status = CRYPTO_INTERFACE_EC_getElementByteStringLen (
        pKey, &elementLen, keyType);
    if (OK != status)
        goto exit;

    /* We need enough space for compression byte plus x and y,
     * which are each elementLen */
    bufferSize = 1 + (2 * elementLen);
    status = DIGI_CALLOC((void **)&pBuffer, 1, bufferSize);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_EC_writePublicKeyToBuffer (MOC_ECC(hwAccelCtx)
        pKey, pBuffer, bufferSize, keyType);
    if (OK != status)
        goto exit;

    *ppBuffer = pBuffer;
    *pBufferSize = bufferSize;
    pBuffer = NULL;

exit:

    if (NULL != pBuffer)
    {
        DIGI_FREE((void **)&pBuffer);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_EC_newPublicKeyFromByteString (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ubyte4 curveId,
    void **ppNewKey,
    ubyte *pByteString,
    ubyte4 byteStringLen,
    ubyte4 keyType
    )
{
    MSTATUS status;

    if (akt_tap_ecc == keyType)
    {
        status = ERR_TAP_UNSUPPORTED;
    }
    else
    {
        status = EC_newPublicKeyFromByteString (MOC_ECC(hwAccelCtx)
            curveId, (ECCKey **)ppNewKey, pByteString, byteStringLen);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_EC_setKeyParameters (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    void *pKey,
    const ubyte *pPoint,
    ubyte4 pointLen,
    const ubyte *pScalar,
    ubyte4 scalarLen,
    ubyte4 keyType
    )
{
    MOC_UNUSED(keyType);
    return EC_setKeyParametersEx (MOC_ECC(hwAccelCtx)
        (ECCKey *)pKey, (ubyte *) pPoint, pointLen, (ubyte *) pScalar, scalarLen);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_EC_getKeyParametersAlloc (
    MOC_ECC(hwAccelDescr hwAccelCtx)
    void *pKey,
    MEccKeyTemplate *pTemplate,
    ubyte reqType,
    ubyte4 keyType
    )
{
    MOC_UNUSED(keyType);
    return EC_getKeyParametersAlloc ( MOC_ECC(hwAccelCtx)
        (ECCKey *)pKey, pTemplate, reqType);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_EC_freeKeyTemplate (
    void *pKey,
    MEccKeyTemplate *pTemplate,
    ubyte4 keyType
    )
{
    MOC_UNUSED(keyType);
    return EC_freeKeyTemplate(NULL, pTemplate);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
CRYPTO_INTERFACE_EC_verifyPublicKey(
    MOC_ECC(hwAccelDescr hwAccelCtx)
    void *pKey,
    byteBoolean *pIsValid,
    ubyte4 keyType
    )
{
    MOC_UNUSED(keyType);
    return EC_verifyPublicKeyEx(MOC_ECC(hwAccelCtx) pKey, pIsValid);
}

#endif /* if (defined(__ENABLE_DIGICERT_ECC__)) */
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
