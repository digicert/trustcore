/*
 * smp_nanoroot_api.c
 *
 * SMP NanoROOT API
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

/**
 * @file       smp_nanoroot_api.c
 * @brief      NanoSMP module feature API definitions for NanoROOT.
 * @details    This C file contains function definitions
               implemented by the NanoROOT NanoSMP.
 */

#if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_SMP_NANOROOT__))
#include "smp_nanoroot_api.h"
#include "smp_nanoroot.h"
#include "smp_nanoroot_device_protect.h"

#include "crypto/aes.h"
#include "crypto/sha256.h"
#include "crypto/sha512.h"
#include "crypto_interface/crypto_interface_aes.h"
#include "crypto_interface/crypto_interface_sha256.h"
#include "crypto_interface/crypto_interface_sha512.h"
#include "crypto_interface/crypto_interface_random.h"
#include "crypto_interface/crypto_interface_nist_ctr_drbg.h"
#include "crypto_interface/crypto_interface_rsa.h"
#include "crypto_interface/crypto_interface_ecc.h"
#include "crypto_interface/crypto_interface_qs_sig.h"
#include "tap/tap_utils.h"

/* Global Mutex for protecting nanoroot module */
RTOS_MUTEX gSmpNanoROOTMutex = NULL;

/* Global required to store the nanoroot config details */
NanoROOT_Config* gpNanoROOTConfig = NULL;


static MSTATUS NanoROOT_getCredential(TAP_SealAttributes *pRequestTemplate, ubyte *pCredBuf, ubyte4 *pCredLen)
{
    MSTATUS status = OK;
    ubyte4 count = 0;
    TAP_Attribute *pAttr = NULL;
    TAP_Credential *pCredential = NULL;

    if(NULL == pRequestTemplate || NULL == pCredBuf || NULL == pCredLen)
    {
        return ERR_NULL_POINTER;
    }

    if(NanoROOTMAX_SEED_LEN < *pCredLen)
    {
        return ERR_INTERNAL_ERROR;
    }

    if(((0 < pRequestTemplate->listLen) && (pRequestTemplate->pAttributeList == NULL)) ||
                ((0 == pRequestTemplate->listLen) && (pRequestTemplate->pAttributeList)))
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Error invalid pRequestTemplate. status=%d\n", __FUNCTION__,__LINE__,status);
        goto exit;
    }

    for(count = 0; count < pRequestTemplate->listLen; count++)
    {
        pAttr = &pRequestTemplate->pAttributeList[count];
        if (TAP_ATTR_CREDENTIAL == pAttr->type)
        {
            if(sizeof(TAP_Credential) != pAttr->length)
            {
                status = ERR_INVALID_INPUT;
                DB_PRINT("%s.%d Error invalid pRequestTemplate. status=%d\n", __FUNCTION__,__LINE__,status);
                goto exit;
            }
            if(NULL == pAttr->pStructOfType)
            {
                status = ERR_INVALID_INPUT;
                DB_PRINT("%s.%d Error NULL pStructOfType. status=%d\n", __FUNCTION__,__LINE__,status);
                goto exit;
            }
            pCredential = pAttr->pStructOfType;
            if(pCredential->credentialType == TAP_CREDENTIAL_TYPE_PASSWORD &&
                pCredential->credentialContext == TAP_CREDENTIAL_CONTEXT_USER &&
                pCredential->credentialData.pBuffer &&
                pCredential->credentialData.bufferLen)
            {
                if(pCredential->credentialData.bufferLen > NanoROOTMAX_SEED_LEN)
                {
                    status = ERR_INVALID_INPUT;
                    DB_PRINT("%s.%d Error invalid pRequestTemplate. status=%d\n", __FUNCTION__,__LINE__,status);
                    goto exit;
                }
                *pCredLen = pCredential->credentialData.bufferLen;
                DIGI_MEMCPY(pCredBuf, pCredential->credentialData.pBuffer, pCredential->credentialData.bufferLen);
            }
            else
            {
                status = ERR_INVALID_INPUT;
                DB_PRINT("%s.%d Error invalid pRequestTemplate. status=%d\n", __FUNCTION__,__LINE__,status);
                goto exit;
            }
        }
    }

exit:
    return status;
}


static MSTATUS NanoROOT_genRSAKeyPair(   randomContext *pRandCtx,
                                AsymmetricKey *pPrivKey,
                                ubyte4 ulBitlength
                            )
{
    MSTATUS status = OK;

    DB_PRINT("Create RSA key\n");
    /* Internally invokes CRYPTO_INTERFACE_RSA_createKeyAux() */
    status = CRYPTO_createRSAKey(pPrivKey, NULL);
    if (OK != status)
    {
        DB_PRINT("%s.%d Create RSA Key failed = %d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

    DB_PRINT("Generate RSA key of size : %d\n", ulBitlength);
    status = CRYPTO_INTERFACE_RSA_generateKey (pRandCtx, pPrivKey->key.pRSA, ulBitlength, NULL);
    if (OK != status)
    {
        DB_PRINT("%s.%d Generate RSA Key failed = %d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

exit:
    return status;
}

static MSTATUS NanoROOT_genECCKeyPair(  randomContext *pRandCtx,
                                AsymmetricKey *pPrivKey,
                                ubyte4 curveId
                             )
{
    MSTATUS status = OK;

    DB_PRINT("Create ECC key\n");
    /* Internally invokes CRYPTO_INTERFACE_EC_newKeyAux() */
    status = CRYPTO_createECCKeyEx(pPrivKey, curveId);
    if (OK != status)
    {
        DB_PRINT("%s.%d Create ECC Key failed = %d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

    DB_PRINT("Generate ECC key of CurveId : %d\n", curveId);
    status = CRYPTO_INTERFACE_EC_generateKeyPairAux(pPrivKey->key.pECC, RANDOM_rngFun, (void *) pRandCtx);
    if (OK != status)
    {
        DB_PRINT("%s.%d Generate ECC Key failed = %d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

exit:
    return status;
}

static MSTATUS NanoROOT_setECCSignature(TAP_Signature *pSignature, ubyte *pSignBuf, ubyte4 elementLen)
{
    MSTATUS status = OK;
    ubyte* pRData, *pSData;

    if (NULL == pSignature || NULL == pSignBuf)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Error: NULL pointer\n", __FUNCTION__, __LINE__);
        goto exit;
    }
    if (elementLen == 0)
    {
        status = ERR_INTERNAL_ERROR;
        DB_PRINT("%s.%d Error: Invalid element length %d\n", __FUNCTION__, __LINE__, elementLen);
        goto exit;
    }

    if (NULL != pSignature->signature.eccSignature.pRData || NULL != pSignature->signature.eccSignature.pSData)
    {
        DB_PRINT("%s.%d Error: Signature already set\n", __FUNCTION__, __LINE__);
        status = ERR_INTERNAL_ERROR;
        goto exit;
    }

    /* Allocate memory for R and S data */
    pRData = NULL;
    pSData = NULL;

    status = DIGI_CALLOC((void **)&pRData, 1, elementLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for pRData, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    status = DIGI_CALLOC((void **)&pSData, 1, elementLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for pSData, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    status = DIGI_MEMCPY(pRData, pSignBuf, elementLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy %d bytes of pRData, status = %d\n",
                __FUNCTION__, __LINE__, elementLen, status);
        goto exit;
    }

    status = DIGI_MEMCPY(pSData, pSignBuf + elementLen, elementLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy %d bytes of pSData, status = %d\n",
                __FUNCTION__, __LINE__, elementLen, status);
        goto exit;
    }

    pSignature->keyAlgorithm = TAP_KEY_ALGORITHM_ECC;
    pSignature->signature.eccSignature.rDataLen = elementLen;
    pSignature->signature.eccSignature.pRData = pRData;
    pSignature->signature.eccSignature.sDataLen = elementLen;
    pSignature->signature.eccSignature.pSData = pSData;
    (void) DIGI_FREE((void **) &pSignBuf);

exit:
    if(OK != status)
    {
        (void) DIGI_FREE((void **) &pRData);
        (void) DIGI_FREE((void **) &pSData);
        if (NULL != pSignature)
        {
            pSignature->signature.eccSignature.pRData = NULL;
            pSignature->signature.eccSignature.pSData = NULL;
            pSignature->signature.eccSignature.rDataLen = 0;
            pSignature->signature.eccSignature.sDataLen = 0;
        }
    }
    return status;
}

static MSTATUS NanoROOT_genMLDSAKeyPair(    randomContext *pRandCtx,
                                    AsymmetricKey *pPrivKey,
                                    ubyte4 id
                               )
{
    MSTATUS status = OK;
    QS_CTX *pCtx = NULL;

    status = CRYPTO_INTERFACE_QS_newCtx(&pCtx, id);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_generateKeyPair(pCtx, RANDOM_rngFun, pRandCtx);
    if (OK != status)
        goto exit;

    pPrivKey->pQsCtx = pCtx;
    pPrivKey->type = akt_qs;

exit:
    return status;
}

static MSTATUS NanoROOT_getRSAPublicKey(RSAKey *pRSAKey, TAP_PublicKey *publicKey)
{
    MSTATUS status = OK;
    MRsaKeyTemplate template = {0};
    ubyte *pModulus, *pExponent;

    if(NULL == pRSAKey || NULL == publicKey)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Error: NULL pointer\n", __FUNCTION__, __LINE__);
        goto exit;
    }

    status = CRYPTO_INTERFACE_RSA_getKeyParametersAllocAux(pRSAKey, &template, MOC_GET_PUBLIC_KEY_DATA);
    if (OK != status)
    {
        DB_PRINT("%s.%d CRYPTO_INTERFACE_RSA_getKeyParametersAllocAux() failed. status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    status = DIGI_MALLOC_MEMCPY ((void **)&pModulus, template.nLen, (void *)template.pN, template.nLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for modulus, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    status = DIGI_MALLOC_MEMCPY ((void **)&pExponent, template.eLen, (void *)template.pE, template.eLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for exponent, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    publicKey->publicKey.rsaKey.pModulus = pModulus;
    publicKey->publicKey.rsaKey.pExponent = pExponent;
    publicKey->publicKey.rsaKey.modulusLen = template.nLen;
    publicKey->publicKey.rsaKey.exponentLen = template.eLen;
    publicKey->keyAlgorithm = TAP_KEY_ALGORITHM_RSA;

exit:
    (void) CRYPTO_INTERFACE_RSA_freeKeyTemplateAux(NULL, &template);
    if(OK != status)
    {
        (void) DIGI_FREE((void **) &pModulus);
        (void) DIGI_FREE((void **) &pExponent);
    }
    return status;
}

static MSTATUS NanoROOT_getECCPublicKey(ECCKey *pECCKey, TAP_PublicKey *publicKey)
{
    MSTATUS status = OK;
    ubyte4 elementLen = 0;
    ubyte *pPubBuf = NULL;
    ubyte4 pubBufLen = 0;

    if(NULL == pECCKey || NULL == publicKey)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Error: NULL pointer\n", __FUNCTION__, __LINE__);
        goto exit;
    }

    status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pECCKey, &(publicKey->publicKey.eccKey.curveId));
    if (OK != status)
    {
        DB_PRINT("%s.%d CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux() failed. status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(pECCKey, &elementLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d CRYPTO_INTERFACE_EC_getElementByteStringLenAux() failed. status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    /* Get the public key from the private key */
    status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAllocAux(pECCKey, &pPubBuf, &pubBufLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d CRYPTO_INTERFACE_EC_writePublicKeyToBufferAllocAux() failed. status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    status = DIGI_CALLOC((void **)&(publicKey->publicKey.eccKey.pPubX), 1, elementLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for eccKey.pPubX, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    status = DIGI_CALLOC((void **)&(publicKey->publicKey.eccKey.pPubY), 1, elementLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for eccKey.pPubY, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    status = DIGI_MEMCPY(&(publicKey->publicKey.eccKey.pPubX[0]), &pPubBuf[1], elementLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy %d bytes of pPubX, status = %d\n",
                __FUNCTION__, __LINE__, elementLen, status);
        goto exit;
    }

    status = DIGI_MEMCPY(&(publicKey->publicKey.eccKey.pPubY[0]), &pPubBuf[1+elementLen], elementLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy %d bytes of pPubY, status = %d\n",
                __FUNCTION__, __LINE__, elementLen, status);
        goto exit;
    }

    publicKey->publicKey.eccKey.pubXLen = elementLen;
    publicKey->publicKey.eccKey.pubYLen = elementLen;
    publicKey->keyAlgorithm = TAP_KEY_ALGORITHM_ECC;

exit:
    if(OK != status)
    {
        (void) DIGI_FREE((void **) &(publicKey->publicKey.eccKey.pPubX));
        (void) DIGI_FREE((void **) &(publicKey->publicKey.eccKey.pPubY));
    }
    (void) DIGI_FREE((void **) &pPubBuf);
    return status;
}

static MSTATUS NanoROOT_getMLDSAPublicKey(QS_CTX *pCtx, TAP_PublicKey *publicKey)
{
    MSTATUS status = OK;
    ubyte *pPublicKey = NULL;
    ubyte4 pubLen = 0;
    ubyte4 qsAlg = 0;

    if(NULL == pCtx || NULL == publicKey)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Error: NULL pointer\n", __FUNCTION__, __LINE__);
        goto exit;
    }

    status = CRYPTO_INTERFACE_QS_getAlg(pCtx, &qsAlg);
    if(OK != status)
    {
        DB_PRINT("%s.%d Error : CRYPTO_INTERFACE_QS_getAlg failed.\n", __FUNCTION__,__LINE__);
        goto exit;
    }

    status = CRYPTO_INTERFACE_QS_getPublicKeyAlloc(pCtx, &pPublicKey, &pubLen);
    if(OK != status)
    {
        DB_PRINT("%s.%d Error : CRYPTO_INTERFACE_QS_getPublicKeyAlloc failed.\n", __FUNCTION__,__LINE__);
        goto exit;
    }

    publicKey->publicKey.mldsaKey.publicKeyLen = pubLen;
    publicKey->publicKey.mldsaKey.pPublicKey = pPublicKey;
    publicKey->publicKey.mldsaKey.qsAlg = qsAlg;
    publicKey->keyAlgorithm = TAP_KEY_ALGORITHM_MLDSA;

exit:
    return status;
}

#ifdef __SMP_ENABLE_SMP_CC_GET_MODULE_LIST__
MSTATUS SMP_API(NanoROOT, getModuleList,
    TAP_ModuleCapabilityAttributes *pModuleAttributes,
    TAP_EntityList *pModuleIdList
)
{
    MSTATUS status = OK;
    MOC_UNUSED(pModuleAttributes);

    if (NULL == pModuleIdList)
    {
        status = ERR_TAP_INVALID_INPUT;
        DB_PRINT("%s.%d NULL pointer on input pModuleIdList\n",
                __FUNCTION__, __LINE__);
        goto exit;
    }

    pModuleIdList->entityType = TAP_ENTITY_TYPE_MODULE;

    status = DIGI_CALLOC((void **)&pModuleIdList->entityIdList.pEntityIdList, 1, sizeof(TAP_EntityId));
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for Module list, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    pModuleIdList->entityIdList.numEntities = 1;
    pModuleIdList->entityIdList.pEntityIdList[0] = NanoROOTMODULE_ID;

exit:

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_FREE_MODULE_LIST__
MSTATUS SMP_API(NanoROOT, freeModuleList,
        TAP_EntityList *pModuleList

)
{
    if (NULL != pModuleList)
    {
        if (NULL != pModuleList->entityIdList.pEntityIdList)
        {
            FREE(pModuleList->entityIdList.pEntityIdList);
        }
    }

    return OK;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_MODULE_INFO__
MSTATUS SMP_API(NanoROOT, getModuleInfo,
        TAP_ModuleId moduleId,
        TAP_ModuleCapabilityAttributes *pCapabilitySelectAttributes,
        TAP_ModuleCapabilityAttributes *pModuleCapabilities
)
{
    MSTATUS status = OK;
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_TOKEN_LIST__
MSTATUS SMP_API(NanoROOT, getTokenList,
        TAP_ModuleHandle moduleHandle,
        TAP_TOKEN_TYPE tokenType,
        TAP_TokenCapabilityAttributes  *pTokenAttributes,
        TAP_EntityList *pTokenIdList
)
{
    MSTATUS status = OK;

    MOC_UNUSED(tokenType);
    MOC_UNUSED(pTokenAttributes);

    if ((0 == moduleHandle) || (NULL == pTokenIdList))
    {
        status = ERR_TAP_INVALID_INPUT;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p, pTokenIdList = %p\n",
                __FUNCTION__, __LINE__, moduleHandle, pTokenIdList);
        return status;
    }

    pTokenIdList->entityType = TAP_ENTITY_TYPE_TOKEN;
    pTokenIdList->entityIdList.numEntities = 0;
    status = DIGI_CALLOC((void *)&(pTokenIdList->entityIdList.pEntityIdList), 1, sizeof(TAP_EntityId));
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for Token EntityIdList, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }
    
    /* one token is return as no multiple tokens */
    pTokenIdList->entityIdList.pEntityIdList[pTokenIdList->entityIdList.numEntities] = NanoROOTTOKEN_ID;
    pTokenIdList->entityIdList.numEntities++;

exit:
    if (OK != status)
    {
        if(NULL != pTokenIdList->entityIdList.pEntityIdList)
        {
            DIGI_FREE((void **)&pTokenIdList->entityIdList.pEntityIdList);
        }
    }
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_INIT_MODULE__
MSTATUS SMP_API(NanoROOT, initModule,
        TAP_ModuleId moduleId,
        TAP_ModuleCapabilityAttributes* pModuleAttributes,
        TAP_CredentialList *pCredentials,
        TAP_ModuleHandle *pModuleHandle
)
{
    MSTATUS status = OK;
    byteBoolean isMutexLocked = FALSE;
    NanoROOT_Module* pNanoRootModule = NULL;

    DB_PRINT("Begins %s()..\n", __FUNCTION__);

    MOC_UNUSED(pModuleAttributes);
    MOC_UNUSED(pCredentials);

    if(moduleId != NanoROOTMODULE_ID)
    {
        status = ERR_TAP_MODULE_NOT_FOUND;
        NanoROOT_FillError(NULL, &status, ERR_TAP_MODULE_NOT_FOUND, "ERR_TAP_MODULE_NOT_FOUND");
        DB_PRINT("%s.%d Error initModule. status=%d\n", __FUNCTION__,__LINE__,status);
        goto exit;
    }

    if (NULL == pModuleHandle)
    {
        status = ERR_TAP_INVALID_INPUT;
        NanoROOT_FillError(NULL, &status, ERR_TAP_INVALID_INPUT, "ERR_TAP_INVALID_INPUT");
        DB_PRINT("%s.%d Error initModule. status=%d\n", __FUNCTION__,__LINE__,status);
        goto exit;
    }

    if (OK != (status = RTOS_mutexWait(gSmpNanoROOTMutex)))
        goto exit;

    isMutexLocked = TRUE;

    status = DIGI_CALLOC((void **)&pNanoRootModule, 1, sizeof(NanoROOT_Module));
    if (OK != status)
    {
        status = ERR_MEM_ALLOC_FAIL;
        NanoROOT_FillError(NULL, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
        DB_PRINT("%s.%d Failed to allocate memory. status=%d\n", __FUNCTION__,__LINE__,status);
        goto exit;
    }

    DIGI_MEMSET((ubyte *)&pNanoRootModule->error, 0, sizeof(pNanoRootModule->error));
    status = DIGI_MALLOC((void**) &pNanoRootModule->error.tapErrorString.pBuffer, NanoROOTMAX_ERROR_BUFFER);
    if (OK != status)
    {
        status = ERR_MEM_ALLOC_FAIL;
        NanoROOT_FillError(&pNanoRootModule->error, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
        DB_PRINT("%s.%d Failed to allocate memory. status=%d\n", __FUNCTION__,__LINE__,status);
        goto exit;
    }

    status = NanoROOT_initFingerprintCtx(&pNanoRootModule->pCtx, NanoROOTSINGLE_REUSABLE_KEY, 0);
    if (OK != status)
    {
        status = ERR_TDP_CTX_NOT_READY;
        NanoROOT_FillError(&pNanoRootModule->error, &status, ERR_TDP_CTX_NOT_READY, "ERR_TDP_CTX_NOT_READY");
        DB_PRINT("%s.%d NanoROOT_initFingerprintCtx () failed. status=%d\n", __FUNCTION__,__LINE__,status);
        goto exit;
    }

    status = NanoROOT_FingerprintDevice(pNanoRootModule->pCtx, gpNanoROOTConfig->cred_ctx.kdf,
                gpNanoROOTConfig->cred_ctx.pFPElement, gpNanoROOTConfig->cred_ctx.numOfFPElement,
                gpNanoROOTConfig->cred_ctx.pInitSeed, gpNanoROOTConfig->cred_ctx.initSeedLen, NULL);
    if (OK != status)
    {
        status = ERR_TDP_CTX_NOT_READY;
        NanoROOT_FillError(&pNanoRootModule->error, &status, ERR_TDP_CTX_NOT_READY, "ERR_TDP_CTX_NOT_READY");
        DB_PRINT("%s.%d NanoROOT_FingerprintDevice() failed. status=%d\n", __FUNCTION__,__LINE__,status);
        goto exit;
    }

    pNanoRootModule->mech = gpNanoROOTConfig->cred_ctx.mech;
    pNanoRootModule->moduleId = NanoROOTMODULE_ID;
    *pModuleHandle = (TAP_ModuleHandle)((uintptr)pNanoRootModule);

exit:
    if (OK != status)
    {
        if (NULL != pNanoRootModule)
        {
            if (NULL != pNanoRootModule->error.tapErrorString.pBuffer)
                FREE(pNanoRootModule->error.tapErrorString.pBuffer);

            FREE(pNanoRootModule);
        }
    }

    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gSmpNanoROOTMutex);

    DB_PRINT("End %s() status=%d\n", __FUNCTION__, status);

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNINIT_MODULE__
MSTATUS SMP_API(NanoROOT, uninitModule,
        TAP_ModuleHandle moduleHandle
)
{
    MSTATUS status = OK;
    byteBoolean isMutexLocked = FALSE;
    NanoROOT_Module* pNanoRootModule = (NanoROOT_Module*) ((uintptr)moduleHandle);

    DB_PRINT("Begins %s()..\n", __FUNCTION__);

    if (NULL == pNanoRootModule)
    {
        status = ERR_TAP_INVALID_INPUT;
        NanoROOT_FillError(NULL, &status, ERR_TAP_INVALID_INPUT, "ERR_TAP_INVALID_INPUT");
        DB_PRINT("%s.%d Error : NULL moduleHandle.\n", __FUNCTION__,__LINE__);
        goto exit;
    }

    if(pNanoRootModule->moduleId != NanoROOTMODULE_ID)
    {
        status = ERR_TAP_MODULE_NOT_FOUND;
        NanoROOT_FillError(&pNanoRootModule->error, &status, ERR_TAP_MODULE_NOT_FOUND, "ERR_TAP_MODULE_NOT_FOUND");
        DB_PRINT("%s.%d Error module not found. status=%d\n", __FUNCTION__,__LINE__,status);
        goto exit;
    }


    if (OK != (status = RTOS_mutexWait(gSmpNanoROOTMutex)))
        goto exit;

    isMutexLocked = TRUE;

    if (NULL != pNanoRootModule->error.tapErrorString.pBuffer)
        FREE(pNanoRootModule->error.tapErrorString.pBuffer);

    status = NanoROOT_freeFingerprintCtx(&pNanoRootModule->pCtx);
    if (OK != status)
    {
        NanoROOT_FillError(NULL, &status, ERR_TDP, "ERR_TDP");
        DB_PRINT("%s.%d NanoROOT_freeFingerprintCtx() failed. status=%d\n", __FUNCTION__,__LINE__,status);
        goto exit;
    }

    FREE(pNanoRootModule);

exit:
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gSmpNanoROOTMutex);

    DB_PRINT("End %s() status=%d\n", __FUNCTION__, status);

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_INIT_TOKEN__
MSTATUS SMP_API(NanoROOT, initToken,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenCapabilityAttributes  *pTokenAttributes,
        TAP_TokenId tokenId,
        TAP_EntityCredentialList *pCredentials,
        TAP_TokenHandle *pTokenHandle
)
{
    MSTATUS status = OK;
    byteBoolean isMutexLocked = FALSE;
    NanoROOT_Module* pNanoRootModule = (NanoROOT_Module*) ((uintptr)moduleHandle);
    NanoROOT_Token* pNanoRootToken = NULL;

    DB_PRINT("Begins %s()..\n", __FUNCTION__);

    MOC_UNUSED(pTokenAttributes);
    MOC_UNUSED(pCredentials);

    if (NULL == pNanoRootModule)
    {
        status = ERR_TAP_INVALID_INPUT;
        NanoROOT_FillError(NULL, &status, ERR_TAP_INVALID_INPUT, "ERR_TAP_INVALID_INPUT");
        DB_PRINT("%s.%d Error : NULL moduleHandle.\n", __FUNCTION__,__LINE__);
        goto exit;
    }

    if(tokenId != NanoROOTTOKEN_ID)
    {
        status = ERR_TAP_NO_TOKEN_AVAILABLE;
        NanoROOT_FillError(&pNanoRootModule->error, &status, ERR_TAP_NO_TOKEN_AVAILABLE, "ERR_TAP_NO_TOKEN_AVAILABLE");
        DB_PRINT("%s.%d Error initToken. status=%d\n", __FUNCTION__,__LINE__,status);
        goto exit;
    }

    if (OK != (status = RTOS_mutexWait(gSmpNanoROOTMutex)))
        goto exit;

    isMutexLocked = TRUE;

    pNanoRootToken = &pNanoRootModule->token;
    pNanoRootToken->tokenId = NanoROOTTOKEN_ID;
    *pTokenHandle = (TAP_TokenHandle)((uintptr)pNanoRootToken);

exit:
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gSmpNanoROOTMutex);

    DB_PRINT("End %s() status=%d\n", __FUNCTION__, status);
    return status;

}
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNINIT_TOKEN__
MSTATUS SMP_API(NanoROOT, uninitToken,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle
)
{
    MSTATUS status = OK;
    byteBoolean isMutexLocked = FALSE;
    NanoROOT_Module *pNanoRootModule = (NanoROOT_Module*) ((uintptr)moduleHandle);
    NanoROOT_Token *pNanoRootToken = (NanoROOT_Token*) ((uintptr)tokenHandle);

    DB_PRINT("Begins %s()..\n", __FUNCTION__);

    if (NULL == pNanoRootModule || NULL == pNanoRootToken)
    {
        status = ERR_TAP_INVALID_INPUT;
        NanoROOT_FillError(NULL, &status, ERR_TAP_INVALID_INPUT, "ERR_TAP_INVALID_INPUT");
        DB_PRINT("%s.%d Error : NULL moduleHandle or tokenHandle.\n", __FUNCTION__,__LINE__);
        goto exit;
    }

    if(pNanoRootToken->tokenId != NanoROOTTOKEN_ID)
    {
        status = ERR_TAP_NO_TOKEN_AVAILABLE;
        NanoROOT_FillError(&pNanoRootModule->error, &status, ERR_TAP_NO_TOKEN_AVAILABLE, "ERR_TAP_NO_TOKEN_AVAILABLE");
        DB_PRINT("%s.%d Error initToken. status=%d\n", __FUNCTION__,__LINE__,status);
        goto exit;
    }

    if (OK != (status = RTOS_mutexWait(gSmpNanoROOTMutex)))
        goto exit;

    isMutexLocked = TRUE;

    DIGI_MEMSET((ubyte *)pNanoRootToken, 0, sizeof(*pNanoRootToken));

exit:
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gSmpNanoROOTMutex);

    DB_PRINT("End %s() status=%d\n", __FUNCTION__, status);
    return status;

}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SIGN_DIGEST__
MSTATUS SMP_API(NanoROOT, signDigest,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_Buffer *pDigest,
        TAP_SIG_SCHEME type,
        TAP_SignAttributes *pSignatureAttributes,
        TAP_Signature **ppSignature
)
{
    MSTATUS status = OK;
    NanoROOT_Module *pNanoRootModule = (NanoROOT_Module*) ((uintptr)moduleHandle);
    NanoROOT_Token *pNanoRootToken = (NanoROOT_Token*) ((uintptr)tokenHandle);
    NanoROOT_Object *pNanoRootObject = (NanoROOT_Object*) ((uintptr)objectHandle);
    ubyte *pSignBuf = NULL;
    ubyte4 signLen = 0;
    ubyte *pDigestInfo = NULL;
    ubyte4 digestInfoLen = 0;
    ubyte4 keyType = 0;
    ubyte4 elementLen = 0;

    DB_PRINT("Begins %s()..\n", __FUNCTION__);

    if (NULL == pNanoRootModule || NULL == pNanoRootToken || NULL == pNanoRootObject
            || NULL == pDigest || NULL == ppSignature)
    {
        status = ERR_NULL_POINTER;
        NanoROOT_FillError(NULL, &status, ERR_TAP_INVALID_INPUT, "ERR_TAP_INVALID_INPUT");
        DB_PRINT("%s.%d Error : NULL arguemtns.\n", __FUNCTION__,__LINE__);
        goto exit;
    }

    switch(type)
    {
        case TAP_SIG_SCHEME_PKCS1_5_SHA256:
            {
                if (SHA256_HASH_LENGTH != pDigest->bufferLen)
                {
                    status = ERR_TAP_INVALID_SIZE;
                    DB_PRINT("%s.%d Digest length is invalid  = %d\n",
                             __FUNCTION__, __LINE__, pDigest->bufferLen);
                    goto exit;
                }

                /* Construct the digestInfo to sign */
                status = ASN1_buildDigestInfoAlloc(pDigest->pBuffer, SHA256_RESULT_SIZE, ht_sha256, &pDigestInfo, &digestInfoLen);
                if (OK != status)
                    goto exit;
             }
             break;

        case TAP_SIG_SCHEME_PKCS1_5_SHA512:
            {
                if (SHA512_HASH_LENGTH != pDigest->bufferLen)
                {
                    status = ERR_TAP_INVALID_SIZE;
                    DB_PRINT("%s.%d Digest length is invalid  = %d\n",
                             __FUNCTION__, __LINE__, pDigest->bufferLen);
                    goto exit;
                }

                /* Construct the digestInfo to sign */
                status = ASN1_buildDigestInfoAlloc(pDigest->pBuffer, SHA512_RESULT_SIZE, ht_sha512, &pDigestInfo, &digestInfoLen);
                if (OK != status)
                    goto exit;
             }
             break;

        case TAP_SIG_SCHEME_ECDSA_SHA256:
            {
                if (SHA256_HASH_LENGTH != pDigest->bufferLen)
                {
                    status = ERR_TAP_INVALID_SIZE;
                    DB_PRINT("%s.%d Digest length is invalid  = %d\n",
                             __FUNCTION__, __LINE__, pDigest->bufferLen);
                    goto exit;
                }
             }
            break;

        case TAP_SIG_SCHEME_ECDSA_SHA512:
            {
                if (SHA512_HASH_LENGTH != pDigest->bufferLen)
                {
                    status = ERR_TAP_INVALID_SIZE;
                    DB_PRINT("%s.%d Digest length is invalid  = %d\n",
                             __FUNCTION__, __LINE__, pDigest->bufferLen);
                    goto exit;
                }
             }
            break;

        case TAP_SIG_SCHEME_NONE:
            /* fallthrough */

        default:
            {
                status = ERR_TAP_INVALID_SCHEME;
                DB_PRINT("%s.%d unsupported algorithm status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }
    }

    *ppSignature = NULL;
    keyType = pNanoRootObject->privKey.type;

    switch(keyType)
    {
        case akt_rsa:
            {
                RSAKey *pRSAKey = pNanoRootObject->privKey.key.pRSA;
                status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(pRSAKey, (sbyte4 *)&signLen);
                if(OK != status)
                    goto exit;

                if(signLen >= RSA_4096_SIGN_LENGTH && TAP_SIG_SCHEME_PKCS1_5_SHA512 != type)
                {
                    status = ERR_TAP_INVALID_SCHEME;
                    DB_PRINT("%s.%d unsupported algorithm status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                else if( signLen < RSA_4096_SIGN_LENGTH && TAP_SIG_SCHEME_PKCS1_5_SHA256 != type)
                {
                    status = ERR_TAP_INVALID_SCHEME;
                    DB_PRINT("%s.%d unsupported algorithm status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }

                /* Allocate the signature buffer */
                status = DIGI_CALLOC((void **)&pSignBuf, 1, signLen);
                if (OK != status)
                    goto exit;

                /* Sign the digestInfo of the message */
                status = CRYPTO_INTERFACE_RSA_signMessageAux(pRSAKey, pDigestInfo, digestInfoLen, pSignBuf, NULL);
                if (OK != status)
                {
                    DB_PRINT("%s.%d CRYPTO_INTERFACE_RSA_signMessageAux failed, status = %d\n",
                             __FUNCTION__, __LINE__, status);
                    goto exit;
                }
            }
            break;

        case akt_ecc:
            {
                ubyte4 signatureLen = 0;
                ubyte4 curveId = 0;
                ECCKey *pECCKey = pNanoRootObject->privKey.key.pECC;

                status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pECCKey, &curveId);
                if (OK != status)
                {
                    DB_PRINT("%s.%d CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux() failed. status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                if(cid_EC_P521 == curveId && TAP_SIG_SCHEME_ECDSA_SHA512 != type)
                {
                    status = ERR_TAP_INVALID_SCHEME;
                    DB_PRINT("%s.%d unsupported algorithm status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                else if( (cid_EC_P256 == curveId || cid_EC_P384 == curveId) && TAP_SIG_SCHEME_ECDSA_SHA256 != type)
                {
                    status = ERR_TAP_INVALID_SCHEME;
                    DB_PRINT("%s.%d unsupported algorithm status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }


                /* The signature output will always be 2 * elementLen */
                status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(pECCKey, &elementLen);
                if (OK != status)
                    goto exit;

                signatureLen = 2 * elementLen;

                /* Allocate the signature buffer */
                status = DIGI_CALLOC((void **)&pSignBuf, 1, signatureLen);
                if (OK != status)
                    goto exit;

                /*  Sign the hash of the message with the private key */
                status = CRYPTO_INTERFACE_ECDSA_signDigestAux(pECCKey, RANDOM_rngFun, g_pRandomContext,
                                pDigest->pBuffer, pDigest->bufferLen, pSignBuf, signatureLen, &signLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d CRYPTO_INTERFACE_ECDSA_signDigestAux() failed, status = %d\n",
                             __FUNCTION__, __LINE__, status);
                    goto exit;
                }

                if (NULL == pSignBuf || 0 == signLen)
                {
                    status = ERR_INTERNAL_ERROR;
                    DB_PRINT("%s.%d Error: Signature length is invalid = %d\n",
                             __FUNCTION__, __LINE__, signLen);
                    goto exit;
                }
            }
            break;

        case akt_qs:
            /* fallthrough */

        default:
            {
                status = ERR_TAP_UNSUPPORTED_ALGORITHM;
                DB_PRINT("%s.%d unsupported algorithm status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }
    }


    if (OK != (status = DIGI_CALLOC((void **)ppSignature, 1, sizeof(**ppSignature))))
    {
        DB_PRINT("%s.%d Unable to allocate memory for "
                 "signature structure, status = %d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

    (*ppSignature)->isDEREncoded = FALSE;

    switch(keyType)
    {
        case akt_rsa:
            {
                (*ppSignature)->keyAlgorithm = TAP_KEY_ALGORITHM_RSA;
                (*ppSignature)->signature.rsaSignature.pSignature = pSignBuf;
                (*ppSignature)->signature.rsaSignature.signatureLen = signLen;
                pSignBuf = NULL;
            }
            break;

        case akt_ecc:
            {
                status = NanoROOT_setECCSignature(*ppSignature, pSignBuf, elementLen);
                if(OK != status)
                {
                    DB_PRINT("%s.%d NanoROOT_setECCSignature() failed, status = %d\n",
                             __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                pSignBuf = NULL;
            }
            break;
    }

exit:
    DB_PRINT("End %s() status=%d\n", __FUNCTION__, status);
    if(OK != status)
    {
        if(ppSignature)
        {
            DIGI_FREE((void **)ppSignature);
        }
    }
    if (NULL != pDigestInfo)
    {
        DIGI_FREE((void **)&pDigestInfo);
    }
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SIGN_BUFFER__
MSTATUS SMP_API(NanoROOT, signBuffer,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_Buffer *pData,
        TAP_SIG_SCHEME type,
        TAP_SignAttributes *pSignatureAttributes,
        TAP_Signature **ppSignature
)
{
    MSTATUS status = OK;
    NanoROOT_Module *pNanoRootModule = (NanoROOT_Module*) ((uintptr)moduleHandle);
    NanoROOT_Token *pNanoRootToken = (NanoROOT_Token*) ((uintptr)tokenHandle);
    NanoROOT_Object *pNanoRootObject = (NanoROOT_Object*) ((uintptr)objectHandle);
    ubyte *pSignature = NULL;
    ubyte4 signLen = 0;
    ubyte4 qsSigLen = 0;
    RSAKey *pRSAKey = NULL;
    ubyte4 keyType = 0;
    ubyte4 elementLen = 0;

    DB_PRINT("Begins %s()..\n", __FUNCTION__);

    if (NULL == pNanoRootModule || NULL == pNanoRootToken || NULL == pNanoRootObject
            || NULL == ppSignature || NULL == pData)
    {
        status = ERR_NULL_POINTER;
        NanoROOT_FillError(NULL, &status, ERR_TAP_INVALID_INPUT, "ERR_TAP_INVALID_INPUT");
        DB_PRINT("%s.%d Error : NULL arguemtns.\n", __FUNCTION__,__LINE__);
        goto exit;
    }

    if(NanoROOTMAX_SIGN_DATA_SIZE < pData->bufferLen)
    {
        status = ERR_TAP_SIGN_INPUT_TOO_LARGE;
        NanoROOT_FillError(&pNanoRootModule->error, &status, ERR_TAP_SIGN_INPUT_TOO_LARGE, "ERR_TAP_SIGN_INPUT_TOO_LARGE");
        DB_PRINT("%s.%d Error input data exceeds max limit. status=%d\n", __FUNCTION__,__LINE__,status);
        goto exit;
    }

    *ppSignature = NULL;
    keyType = pNanoRootObject->privKey.type;

    switch(keyType)
    {
        case akt_rsa:
            {
                ubyte4 hashType = 0;

                if (! (TAP_SIG_SCHEME_PKCS1_5_SHA256 == type || TAP_SIG_SCHEME_PKCS1_5_SHA512 == type))
                {
                    status = ERR_TAP_INVALID_SCHEME;
                    DB_PRINT("%s.%d unsupported algorithm status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }

                pRSAKey = pNanoRootObject->privKey.key.pRSA;
                status = CRYPTO_INTERFACE_RSA_getCipherTextLengthAux(pRSAKey, (sbyte4 *)&signLen);
                if(OK != status)
                    goto exit;

                if(signLen >= RSA_4096_SIGN_LENGTH && TAP_SIG_SCHEME_PKCS1_5_SHA512 != type)
                {
                    status = ERR_TAP_INVALID_SCHEME;
                    DB_PRINT("%s.%d unsupported algorithm status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                else if(signLen < RSA_4096_SIGN_LENGTH && TAP_SIG_SCHEME_PKCS1_5_SHA256 != type)
                {
                    status = ERR_TAP_INVALID_SCHEME;
                    DB_PRINT("%s.%d unsupported algorithm status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                hashType = (signLen >= RSA_4096_SIGN_LENGTH) ? ht_sha512 : ht_sha256;

                /* Allocate the signature buffer */
                status = DIGI_CALLOC((void **)&pSignature, 1, signLen);
                if (OK != status)
                    goto exit;

                /* Sign the message */
                status = CRYPTO_INTERFACE_RSA_signData(pRSAKey, pData->pBuffer, pData->bufferLen, hashType, pSignature, NULL);
                if (OK != status)
                {
                    DB_PRINT("%s.%d CRYPTO_INTERFACE_RSA_signData() failed, status = %d\n",
                             __FUNCTION__, __LINE__, status);
                    goto exit;
                }
            }
            break;

        case akt_ecc:
            {
                ubyte4 signatureLen = 0;
                ubyte4 curveId = 0;
                ubyte4 hashType = 0;
                ECCKey *pECCKey = pNanoRootObject->privKey.key.pECC;

                if (! (TAP_SIG_SCHEME_ECDSA_SHA256 == type || TAP_SIG_SCHEME_ECDSA_SHA512 == type))
                {
                    status = ERR_TAP_INVALID_SCHEME;
                    DB_PRINT("%s.%d unsupported algorithm status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }

                status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux(pECCKey, &curveId);
                if (OK != status)
                {
                    DB_PRINT("%s.%d CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux() failed. status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                if(cid_EC_P521 == curveId && TAP_SIG_SCHEME_ECDSA_SHA512 != type)
                {
                    status = ERR_TAP_INVALID_SCHEME;
                    DB_PRINT("%s.%d unsupported algorithm status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                else if( (cid_EC_P256 == curveId || cid_EC_P384 == curveId) && TAP_SIG_SCHEME_ECDSA_SHA256 != type)
                {
                    status = ERR_TAP_INVALID_SCHEME;
                    DB_PRINT("%s.%d unsupported algorithm status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                hashType = (curveId == cid_EC_P521) ? ht_sha512 : ht_sha256;

                /* The signature output will always be 2 * elementLen */
                status = CRYPTO_INTERFACE_EC_getElementByteStringLenAux(pECCKey, &elementLen);
                if (OK != status)
                    goto exit;

                signatureLen = 2 * elementLen;

                /* Allocate the signature buffer */
                status = DIGI_CALLOC((void **)&pSignature, 1, signatureLen);
                if (OK != status)
                    goto exit;

                status = CRYPTO_INTERFACE_ECDSA_signMessageExt (pECCKey, RANDOM_rngFun, g_pRandomContext, hashType,
                        pData->pBuffer, pData->bufferLen, pSignature, signatureLen, &signLen, NULL);
                if (OK != status)
                {
                    DB_PRINT("%s.%d CRYPTO_INTERFACE_ECDSA_signMessageExt() failed, status = %d\n",
                             __FUNCTION__, __LINE__, status);
                    goto exit;
                }

                if (NULL == pSignature || 0 == signLen)
                {
                    status = ERR_INTERNAL_ERROR;
                    DB_PRINT("%s.%d Error: Signature length is invalid = %d\n",
                             __FUNCTION__, __LINE__, signLen);
                    goto exit;
                }
            }
            break;

        case akt_qs:
            {
                if (TAP_SIG_SCHEME_NONE != type)
                {
                    status = ERR_TAP_INVALID_SCHEME;
                    DB_PRINT("%s.%d unsupported algorithm status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }

                /* Sign the data buffer */
                status = CRYPTO_INTERFACE_QS_SIG_signAlloc(pNanoRootObject->privKey.pQsCtx, RANDOM_rngFun,
                                g_pRandomContext, pData->pBuffer, pData->bufferLen, &pSignature, &qsSigLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d CRYPTO_INTERFACE_QS_SIG_signAlloc() failed, status = %d\n",
                             __FUNCTION__, __LINE__, status);
                    goto exit;
                }
            }
            break;

        default:
            {
                status = ERR_TAP_UNSUPPORTED_ALGORITHM;
                DB_PRINT("%s.%d unsupported algorithm status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }
    }

    if (OK != (status = DIGI_CALLOC((void **)ppSignature, 1, sizeof(**ppSignature))))
    {
        DB_PRINT("%s.%d Unable to allocate memory for "
                 "signature structure, status = %d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

    switch(keyType)
    {
        case akt_rsa:
            {
                (*ppSignature)->signature.rsaSignature.pSignature = pSignature;
                (*ppSignature)->signature.rsaSignature.signatureLen = signLen;
                (*ppSignature)->keyAlgorithm = TAP_KEY_ALGORITHM_RSA;
                pSignature = NULL;
            }
            break;

        case akt_ecc:
            {
                status = NanoROOT_setECCSignature(*ppSignature, pSignature, elementLen);
                if(OK != status)
                {
                    DB_PRINT("%s.%d NanoROOT_setECCSignature() failed, status = %d\n",
                             __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                pSignature = NULL;
            }
            break;

        case akt_qs:
            {
                (*ppSignature)->keyAlgorithm = TAP_KEY_ALGORITHM_MLDSA;
                (*ppSignature)->signature.mldsaSignature.pSignature = pSignature;
                (*ppSignature)->signature.mldsaSignature.signatureLen = qsSigLen;
                pSignature = NULL;
            }
            break;
    }
    (*ppSignature)->isDEREncoded = FALSE;

exit:
    DB_PRINT("End %s() status=%d\n", __FUNCTION__, status);
    if(OK != status)
    {
        if(ppSignature)
        {
            DIGI_FREE((void **)ppSignature);
        }
    }
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SEAL_WITH_TRUSTED_DATA__
MOC_EXTERN MSTATUS SMP_API(NanoROOT, sealWithTrustedData,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_SealAttributes *pRequestTemplate,
        TAP_Buffer *pDataToSeal,
        TAP_Buffer *pDataOut
)
{
    MSTATUS status = OK;
    byteBoolean isMutexLocked = FALSE;
    NanoROOT_Module* pNanoRootModule = (NanoROOT_Module*) ((uintptr)moduleHandle);
    NanoROOT_Token* pNanoRootToken = (NanoROOT_Token*) ((uintptr)tokenHandle);
    ubyte pCredBuf[NanoROOTMAX_SEED_LEN] = {0};
    ubyte4 credLen = NanoROOTMAX_SEED_LEN;
    ubyte pHashedCred[SHA256_RESULT_SIZE * 2] = {0};

    DB_PRINT("Begins %s()..\n", __FUNCTION__);

    if (NULL == pNanoRootModule || NULL == pNanoRootToken || NULL == pDataToSeal || NULL == pDataOut)
    {
        status = ERR_TAP_INVALID_INPUT;
        NanoROOT_FillError(NULL, &status, ERR_TAP_INVALID_INPUT, "ERR_TAP_INVALID_INPUT");
        DB_PRINT("%s.%d Error : NULL arguments.\n", __FUNCTION__,__LINE__);
        goto exit;
    }

    if(((NULL == pDataOut->pBuffer) && (0 != pDataOut->bufferLen)) ||
        ((NULL != pDataOut->pBuffer) && (0 == pDataOut->bufferLen)))
    {
        status = ERR_TAP_INVALID_INPUT;
        NanoROOT_FillError(&pNanoRootModule->error, &status, ERR_TAP_INVALID_INPUT, "ERR_TAP_INVALID_INPUT");
        DB_PRINT("%s.%d Error : NULL arguments.\n", __FUNCTION__,__LINE__);
        goto exit;
    }

    if(pNanoRootToken->tokenId != NanoROOTTOKEN_ID)
    {
        status = ERR_TAP_NO_TOKEN_AVAILABLE;
        NanoROOT_FillError(&pNanoRootModule->error, &status, ERR_TAP_NO_TOKEN_AVAILABLE, "ERR_TAP_NO_TOKEN_AVAILABLE");
        DB_PRINT("%s.%d Error invalid tokenHandle. status=%d\n", __FUNCTION__,__LINE__,status);
        goto exit;
    }

    if(NanoROOTMAX_SEAL_DATA_SIZE < pDataToSeal->bufferLen)
    {
        status = ERR_TAP_ENCRYPT_INPUT_TOO_LARGE;
        NanoROOT_FillError(&pNanoRootModule->error, &status, ERR_TAP_ENCRYPT_INPUT_TOO_LARGE, "ERR_TAP_ENCRYPT_INPUT_TOO_LARGE");
        DB_PRINT("%s.%d Error input data exceeds max limit. status=%d\n", __FUNCTION__,__LINE__,status);
        goto exit;
    }

    if (OK != (status = RTOS_mutexWait(gSmpNanoROOTMutex)))
        goto exit;

    isMutexLocked = TRUE;

    if(pRequestTemplate)
    {
        status = NanoROOT_getCredential(pRequestTemplate, pCredBuf, &credLen);
        if (OK != status)
        {
            NanoROOT_FillError(&pNanoRootModule->error, &status, ERR_TAP_INVALID_INPUT, "ERR_TAP_INVALID_INPUT");
            goto exit;
        }
    }

    status = CRYPTO_INTERFACE_SHA256_completeDigest(pCredBuf, credLen, pHashedCred);
    if (OK != status)
    {
        NanoROOT_FillError(&pNanoRootModule->error, &status, ERR_INTERNAL_ERROR, "ERR_INTERNAL_ERROR");
        DB_PRINT("%s.%d Error SHA256 operation. status=%d\n", __FUNCTION__,__LINE__,status);
        goto exit;
    }

    DIGI_MEMCPY(pHashedCred + SHA256_RESULT_SIZE, pHashedCred, SHA256_RESULT_SIZE);
    DB_PRINT("sha256 hash\n");
    DEBUG_HEXDUMP(DEBUG_MEMORY, pHashedCred, SHA256_RESULT_SIZE * 2);

    if(NULL == pDataOut->pBuffer)
    {
        pDataOut->bufferLen = pDataToSeal->bufferLen;

        status = DIGI_CALLOC((void **)&pDataOut->pBuffer, 1, pDataOut->bufferLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Unable to allocate memory for output buffer, status = %d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }
    }

    status = NanoROOT_Encrypt(pNanoRootModule->pCtx, pNanoRootModule->mech, pHashedCred, sizeof(pHashedCred), pDataToSeal->pBuffer,
                pDataToSeal->bufferLen, pDataOut->pBuffer, &pDataOut->bufferLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error NanoROOT_Encrypt(). status=%d\n", __FUNCTION__,__LINE__,status);
        goto exit;
    }

exit:
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gSmpNanoROOTMutex);

    DB_PRINT("End %s() status=%d\n", __FUNCTION__, status);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNSEAL_WITH_TRUSTED_DATA__
MOC_EXTERN MSTATUS SMP_API(NanoROOT, unsealWithTrustedData,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_SealAttributes *pRequestTemplate,
        TAP_Buffer *pDataToUnseal,
        TAP_Buffer *pDataOut
)
{
    MSTATUS status = OK;
    byteBoolean isMutexLocked = FALSE;
    NanoROOT_Module* pNanoRootModule = (NanoROOT_Module*) ((uintptr)moduleHandle);
    NanoROOT_Token* pNanoRootToken = (NanoROOT_Token*) ((uintptr)tokenHandle);
    ubyte pCredBuf[NanoROOTMAX_SEED_LEN] = {0};
    ubyte4 credLen = NanoROOTMAX_SEED_LEN;
    ubyte pHashedCred[SHA256_RESULT_SIZE * 2] = {0};

    DB_PRINT("Begins %s()..\n", __FUNCTION__);

    if (NULL == pNanoRootModule || NULL == pNanoRootToken || NULL == pDataToUnseal || NULL == pDataOut)
    {
        status = ERR_TAP_INVALID_INPUT;
        NanoROOT_FillError(NULL, &status, ERR_TAP_INVALID_INPUT, "ERR_TAP_INVALID_INPUT");
        DB_PRINT("%s.%d Error : NULL arguments.\n", __FUNCTION__,__LINE__);
        goto exit;
    }

    if(((NULL == pDataOut->pBuffer) && (0 != pDataOut->bufferLen)) ||
        ((NULL != pDataOut->pBuffer) && (0 == pDataOut->bufferLen)))
    {
        status = ERR_TAP_INVALID_INPUT;
        NanoROOT_FillError(&pNanoRootModule->error, &status, ERR_TAP_INVALID_INPUT, "ERR_TAP_INVALID_INPUT");
        DB_PRINT("%s.%d Error : NULL arguments.\n", __FUNCTION__,__LINE__);
        goto exit;
    }

    if(pNanoRootToken->tokenId != NanoROOTTOKEN_ID)
    {
        status = ERR_TAP_NO_TOKEN_AVAILABLE;
        NanoROOT_FillError(&pNanoRootModule->error, &status, ERR_TAP_NO_TOKEN_AVAILABLE, "ERR_TAP_NO_TOKEN_AVAILABLE");
        DB_PRINT("%s.%d Error invalid tokenHandle. status=%d\n", __FUNCTION__,__LINE__,status);
        goto exit;
    }

    if(NanoROOTMAX_SEAL_DATA_SIZE < pDataToUnseal->bufferLen)
    {
        status = ERR_TAP_DECRYPT_INPUT_TOO_LARGE;
        NanoROOT_FillError(&pNanoRootModule->error, &status, ERR_TAP_DECRYPT_INPUT_TOO_LARGE, "ERR_TAP_DECRYPT_INPUT_TOO_LARGE");
        DB_PRINT("%s.%d Error input data exceeds max limit. status=%d\n", __FUNCTION__,__LINE__,status);
        goto exit;
    }

    if (OK != (status = RTOS_mutexWait(gSmpNanoROOTMutex)))
        goto exit;

    isMutexLocked = TRUE;

    if(pRequestTemplate)
    {
        status = NanoROOT_getCredential(pRequestTemplate, pCredBuf, &credLen);
        if (OK != status)
        {
            NanoROOT_FillError(&pNanoRootModule->error, &status, ERR_TAP_INVALID_INPUT, "ERR_TAP_INVALID_INPUT");
            goto exit;
        }
    }

    status = CRYPTO_INTERFACE_SHA256_completeDigest(pCredBuf, credLen, pHashedCred);
    if (OK != status)
    {
        NanoROOT_FillError(&pNanoRootModule->error, &status, ERR_INTERNAL_ERROR, "ERR_INTERNAL_ERROR");
        DB_PRINT("%s.%d Error SHA256 operation. status=%d\n", __FUNCTION__,__LINE__,status);
        goto exit;
    }

    DIGI_MEMCPY(pHashedCred + SHA256_RESULT_SIZE, pHashedCred, SHA256_RESULT_SIZE);
    DB_PRINT("sha256 hash\n");
    DEBUG_HEXDUMP(DEBUG_MEMORY, pHashedCred, SHA256_RESULT_SIZE * 2);


    if(NULL == pDataOut->pBuffer)
    {
        pDataOut->bufferLen = pDataToUnseal->bufferLen;

        status = DIGI_CALLOC((void **)&pDataOut->pBuffer, 1, pDataOut->bufferLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Unable to allocate memory for output buffer, status = %d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }
    }

    status = NanoROOT_Decrypt(pNanoRootModule->pCtx, pNanoRootModule->mech, pHashedCred, sizeof(pHashedCred), pDataToUnseal->pBuffer,
                pDataToUnseal->bufferLen, pDataOut->pBuffer, &pDataOut->bufferLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error NanoROOT_Decrypt(). status=%d\n", __FUNCTION__,__LINE__,status);
        goto exit;
    }

exit:
    if (TRUE == isMutexLocked)
        RTOS_mutexRelease(gSmpNanoROOTMutex);

    DB_PRINT("End %s() status=%d\n", __FUNCTION__, status);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_CREATE_OBJECT__
MSTATUS SMP_API(NanoROOT, createObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_KeyAttributes *pKeyAttributeList,
        TAP_ObjectCapabilityAttributes *pKeyObjectAttributes,
        TAP_ObjectId *pObjectIdOut,
        TAP_ObjectHandle *pHandle
)
{
    MSTATUS status = OK;
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_DELETE_OBJECT__
MSTATUS SMP_API(NanoROOT, deleteObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle
)
{
    MSTATUS status = OK;
    NanoROOT_Module *pNanoRootModule = (NanoROOT_Module*) ((uintptr)moduleHandle);
    NanoROOT_Token *pNanoRootToken = (NanoROOT_Token*) ((uintptr)tokenHandle);
    NanoROOT_Object *pObject = &pNanoRootToken->object;

    DB_PRINT("Begins %s()..\n", __FUNCTION__);

    if (NULL == pNanoRootModule || NULL == pNanoRootToken || NULL == pObject)
    {
        status = ERR_NULL_POINTER;
        NanoROOT_FillError(NULL, &status, ERR_TAP_INVALID_INPUT, "ERR_TAP_INVALID_INPUT");
        DB_PRINT("%s.%d Error : NULL arguemtns.\n", __FUNCTION__,__LINE__);
        return status;
    }

    /* Uninit the Asymmetric Key, which will free the underlying RSA key */
    (void) CRYPTO_uninitAsymmetricKey(&pObject->privKey, NULL);

    DB_PRINT("End %s() status=%d\n", __FUNCTION__, status);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_INIT_OBJECT__
MSTATUS SMP_API(NanoROOT, initObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectId objectIdIn,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_EntityCredentialList *pCredentials,
        TAP_ObjectHandle *pObjectHandle,
        TAP_ObjectId *pObjectIdOut,
        TAP_ObjectAttributes *pObjectAttributesOut
)
{
    MSTATUS status = OK;
    NanoROOT_Module *pNanoRootModule = (NanoROOT_Module*) ((uintptr)moduleHandle);
    NanoROOT_Token *pNanoRootToken = (NanoROOT_Token*) ((uintptr)tokenHandle);
    TAP_ObjectCapabilityAttributes *pKeyAttributeList = pObjectAttributes;
    AsymmetricKey *pPrivKey = NULL;
    TAP_KEY_ALGORITHM keyAlgorithm = TAP_KEY_ALGORITHM_UNDEFINED;
    TAP_KEY_USAGE keyUsage = TAP_KEY_USAGE_UNDEFINED;
    TAP_KEY_SIZE keySize = TAP_KEY_SIZE_UNDEFINED;
    TAP_ENC_SCHEME encScheme = TAP_ENC_SCHEME_NONE;
    TAP_SIG_SCHEME sigScheme = TAP_SIG_SCHEME_NONE;
    TAP_ECC_CURVE eccCurve =  TAP_ECC_CURVE_NONE;
    TAP_Attribute *pAttribute = NULL;
    ubyte4 numCreatedKeyAttributes = 0;
    TAP_Attribute *pCreatedKeyAttributes = NULL;
    NanoROOT_Object *pObject = NULL;
    TAP_Buffer objectId = {0};
    ubyte8 keyId = 0;
    ubyte4 count = 0;
    randomContext *pRandCtx = NULL;
    ubyte4 subKeyType = 0;

    MOC_UNUSED(objectIdIn);
    MOC_UNUSED(pObjectIdOut);

    DB_PRINT("Begins %s()..\n", __FUNCTION__);

    if (NULL == pNanoRootModule || NULL == pNanoRootToken)
    {
        status = ERR_TAP_INVALID_INPUT;
        NanoROOT_FillError(NULL, &status, ERR_TAP_INVALID_INPUT, "ERR_TAP_INVALID_INPUT");
        DB_PRINT("%s.%d Error : NULL arguemtns.\n", __FUNCTION__,__LINE__);
        return status;
    }

    pObject = &pNanoRootToken->object;
    if (NULL == pObject || NULL == pObjectHandle)
    {
        status = ERR_TAP_INVALID_INPUT;
        NanoROOT_FillError(NULL, &status, ERR_TAP_INVALID_INPUT, "ERR_TAP_INVALID_INPUT");
        DB_PRINT("%s.%d Error : NULL arguemtns.\n", __FUNCTION__,__LINE__);
        return status;
    }
    pPrivKey = &pObject->privKey;

    if (pKeyAttributeList && pKeyAttributeList->listLen)
    {
        for (count = 0; count < pKeyAttributeList->listLen; count++)
        {
            pAttribute = &pKeyAttributeList->pAttributeList[count];

            switch (pAttribute->type)
            {
                case TAP_ATTR_KEY_USAGE:
                    if (sizeof(TAP_KEY_USAGE) == pAttribute->length)
                        keyUsage = *((TAP_KEY_USAGE *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key usage length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    break;

                case TAP_ATTR_ENC_SCHEME:
                    if (sizeof(TAP_ENC_SCHEME) == pAttribute->length)
                        encScheme = *((TAP_ENC_SCHEME *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key encryption scheme structure length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    break;

                case TAP_ATTR_SIG_SCHEME:
                    if (sizeof(TAP_SIG_SCHEME) == pAttribute->length)
                        sigScheme = *((TAP_SIG_SCHEME *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key signing scheme structure length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    break;

                case TAP_ATTR_CURVE:
                    if (sizeof(TAP_ECC_CURVE) == pAttribute->length)
                        eccCurve = *((TAP_ECC_CURVE *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key curve structure length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    break;

                case TAP_ATTR_OBJECT_ID_BYTESTRING:
                    if ((sizeof(TAP_Buffer) != pAttribute->length) ||
                        (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid byte string ID structure length %d, status = %d\n",
                                    __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    objectId.pBuffer = ((TAP_Buffer *)(pAttribute->pStructOfType))->pBuffer;
                    objectId.bufferLen = ((TAP_Buffer *)(pAttribute->pStructOfType))->bufferLen;
                    break;
            }
        }
    }

    if (NULL == objectId.pBuffer || 0 == objectId.bufferLen)
    {
        DB_PRINT("%s.%d Failed, id not properly provided.\n",
                    __FUNCTION__, __LINE__);
        NanoROOT_FillError(&pNanoRootModule->error, &status, ERR_NOT_FOUND, "ERR_NOT_FOUND");
        goto exit;
    }

    /* Instantiate a new random context implementing a CTR-DRBG*/
    DB_PRINT("Acquiring random context with seed\n");
    status = CRYPTO_INTERFACE_NIST_CTRDRBG_newContext(&pRandCtx, pNanoRootModule->pCtx->pKeyMaterial,
                                                    MOC_MAX_AES_KEY_SIZE, AES_BLOCK_SIZE, NULL, 0);
    if (OK != status)
    {
        DB_PRINT("%s.%d Acquiring random context failed = %d\n",
                 __FUNCTION__, __LINE__, status);
        goto exit;
    }

    keyId = *(ubyte8*) objectId.pBuffer;
    DB_PRINT("Key ID : %llX\n", keyId);

    status = TAP_NanoROOT_parse_algorithm_info(keyId, &keyAlgorithm, &keySize, &subKeyType);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unsupported Algorithm status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    switch(keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
            DB_PRINT("Creating RSA key\n");
            status = NanoROOT_genRSAKeyPair(pRandCtx, pPrivKey, subKeyType);
            if(OK != status)
            {
                DB_PRINT("%s.%d RSA keypair generation failed, status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }
            break;

        case TAP_KEY_ALGORITHM_ECC:
            DB_PRINT("Creating ECC key\n");
            status = NanoROOT_genECCKeyPair(pRandCtx, pPrivKey, subKeyType);
            if(OK != status)
            {
                DB_PRINT("%s.%d ECC keypair generation failed, status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }
            break;

        case TAP_KEY_ALGORITHM_MLDSA:
            DB_PRINT("Creating MLDSA key\n");
            status = NanoROOT_genMLDSAKeyPair(pRandCtx, pPrivKey, subKeyType);
            if(OK != status)
            {
                DB_PRINT("%s.%d MLDSA keypair generation failed, status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }
            break;
    }

    /* Clean up the context when finished */
    if (NULL != pRandCtx)
    {
        CRYPTO_INTERFACE_NIST_CTRDRBG_deleteContext(&pRandCtx);
        pRandCtx = NULL;
    }
    *pObjectHandle = (TAP_ObjectHandle)((uintptr)&pNanoRootToken->object);

    if (pObjectAttributesOut)
    {
        /* Put together TAP Attribute list of the parameters used to create this key */
        if (NULL != pObjectAttributesOut->pAttributeList)
        {
            status = TAP_UTILS_freeAttributeList(pObjectAttributesOut);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to free memory for key attribute list, status = %d\n", __FUNCTION__,__LINE__, status);
                goto exit;
            }
        }

        numCreatedKeyAttributes = 6;
        pObjectAttributesOut->listLen = numCreatedKeyAttributes;

        status = DIGI_CALLOC((void **)&pObjectAttributesOut->pAttributeList, 1,
                sizeof(TAP_Attribute) * numCreatedKeyAttributes);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for created key attribute list"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        count = 0;
        pCreatedKeyAttributes = &pObjectAttributesOut->pAttributeList[count++];

        pCreatedKeyAttributes->type = TAP_ATTR_KEY_USAGE;
        pCreatedKeyAttributes->length = sizeof(keyUsage);
        status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                sizeof(keyUsage));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for keyUsage attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
        status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &keyUsage,
                sizeof(keyUsage));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy keyUsage attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        pCreatedKeyAttributes = &pObjectAttributesOut->pAttributeList[count++];

        pCreatedKeyAttributes->type = TAP_ATTR_KEY_ALGORITHM;
        pCreatedKeyAttributes->length = sizeof(keyAlgorithm);
        status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                sizeof(keyAlgorithm));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for keyAlgorithm attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
        status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &keyAlgorithm,
                sizeof(keyAlgorithm));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy keyAlgorithm attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        pCreatedKeyAttributes = &pObjectAttributesOut->pAttributeList[count++];

        pCreatedKeyAttributes->type = TAP_ATTR_ENC_SCHEME;
        pCreatedKeyAttributes->length = sizeof(encScheme);
        status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                sizeof(encScheme));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for encScheme attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
        status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &encScheme,
                sizeof(encScheme));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy encScheme attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        pCreatedKeyAttributes = &pObjectAttributesOut->pAttributeList[count++];

        pCreatedKeyAttributes->type = TAP_ATTR_SIG_SCHEME;
        pCreatedKeyAttributes->length = sizeof(sigScheme);
        status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                sizeof(sigScheme));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for sigScheme attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
        status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &sigScheme,
                sizeof(sigScheme));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy sigScheme attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        pCreatedKeyAttributes = &pObjectAttributesOut->pAttributeList[count++];

        if (TAP_KEY_ALGORITHM_RSA == keyAlgorithm)
        {
            pCreatedKeyAttributes->type = TAP_ATTR_KEY_SIZE;
            pCreatedKeyAttributes->length = sizeof(keySize);
            status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                    sizeof(keySize));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to allocate memory for keySize attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
            status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &keySize,
                    sizeof(keySize));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy keySize attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
        }
        else if (TAP_KEY_ALGORITHM_ECC == keyAlgorithm)
        {
            pCreatedKeyAttributes->type = TAP_ATTR_CURVE;
            pCreatedKeyAttributes->length = sizeof(eccCurve);
            status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                    sizeof(eccCurve));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to allocate memory for eccCurve attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
            status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &eccCurve,
                    sizeof(eccCurve));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy eccCurve attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
        }
        pCreatedKeyAttributes = &pObjectAttributesOut->pAttributeList[count++];

        /* Last entry */
        pCreatedKeyAttributes->type = TAP_ATTR_NONE;
        pCreatedKeyAttributes->length = 0;
        pCreatedKeyAttributes->pStructOfType = NULL;
    }
exit:
    DB_PRINT("End %s() status=%d\n", __FUNCTION__, status);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNINIT_OBJECT__
MSTATUS SMP_API(NanoROOT, uninitObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle
)
{
    MSTATUS status = OK;
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_OBJECT_LIST__
MSTATUS SMP_API(NanoROOT, getObjectList,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_EntityList *pObjectIdList
)
{
        return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_PRIVATE_KEY__
MSTATUS SMP_API(NanoROOT, getPrivateKeyBlob,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_Blob *pPrivateBlob
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_PUBLIC_KEY__
MSTATUS SMP_API(NanoROOT, getPublicKey,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_PublicKey **ppublicKey
)
{
    MSTATUS status = OK;
    NanoROOT_Module *pNanoRootModule = (NanoROOT_Module*) ((uintptr)moduleHandle);
    NanoROOT_Token *pNanoRootToken = (NanoROOT_Token*) ((uintptr)tokenHandle);
    NanoROOT_Object *pNanoRootObject = (NanoROOT_Object*) ((uintptr)objectHandle);
    ubyte4 keyType = 0;

    DB_PRINT("Begins %s()..\n", __FUNCTION__);

    if (NULL == pNanoRootModule || NULL == pNanoRootToken || NULL == pNanoRootObject || NULL == ppublicKey)
    {
        status = ERR_NULL_POINTER;
        NanoROOT_FillError(NULL, &status, ERR_TAP_INVALID_INPUT, "ERR_TAP_INVALID_INPUT");
        DB_PRINT("%s.%d Error : NULL arguemtns.\n", __FUNCTION__,__LINE__);
        DB_PRINT("End %s() status=%d\n", __FUNCTION__, status);
        return status;
    }
    keyType = pNanoRootObject->privKey.type;

    if (OK != (status = DIGI_CALLOC((void**)ppublicKey, 1, sizeof(**ppublicKey))))
    {
        NanoROOT_FillError(&pNanoRootModule->error, &status, ERR_MEM_ALLOC_FAIL, "ERR_MEM_ALLOC_FAIL");
        DB_PRINT("%s.%d Error : NULL arguemtns.\n", __FUNCTION__,__LINE__);
        goto exit;
    }


    switch(keyType)
    {
        case akt_rsa:
            {
                status = NanoROOT_getRSAPublicKey(pNanoRootObject->privKey.key.pRSA, *ppublicKey);
                if(OK != status)
                {
                    DB_PRINT("%s.%d Failed to retrieve RSA public key.\n", __FUNCTION__,__LINE__);
                    goto exit;
                }
            }
            break;

        case akt_ecc:
            {
                status = NanoROOT_getECCPublicKey(pNanoRootObject->privKey.key.pECC, *ppublicKey);
                if(OK != status)
                {
                    DB_PRINT("%s.%d Failed to retrieve ECC public key.\n", __FUNCTION__,__LINE__);
                    goto exit;
                }
            }
            break;

        case akt_qs:
            {
                status = NanoROOT_getMLDSAPublicKey(pNanoRootObject->privKey.pQsCtx, *ppublicKey);
                if(OK != status)
                {
                    DB_PRINT("%s.%d Failed to retrieve MLDSA public key.\n", __FUNCTION__,__LINE__);
                    goto exit;
                }
            }
            break;

        default:
            {
                status = ERR_TAP_UNSUPPORTED_ALGORITHM;
                DB_PRINT("%s.%d unsupported algorithm status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }
    }

exit:
    if(OK != status)
    {
        if(NULL != *ppublicKey)
        {
            DIGI_FREE((void **)ppublicKey);
        }
    }
    DB_PRINT("End %s() status=%d\n", __FUNCTION__, status);
    return status;
}

MSTATUS SMP_API(NanoROOT, getPublicKeyBlob,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_Blob *pPublicBlob
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#endif /* #if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_SMP_NANOROOT__)) */
