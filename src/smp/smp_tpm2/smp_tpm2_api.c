/*
 * smp_tpm2_api.c
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
 * @file       smp_tpm2_api.c
 * @brief      NanoSMP module feature API definitions for TPM2.
 * @details    This C file contains feature function
               definitions implemented by the TPM2 NanoSMP.
 */

#include "../../common/moptions.h"

#if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_TPM2__))
#include "tpm2_lib/tpm2_types.h"
#include "tpm2_lib/fapi2/fapi2.h"
#include "smp_tpm2_api.h"
#include "../smp_interface.h"
#include "../../common/moc_config.h"
#include "../../common/debug_console.h"
#include "../../common/mocana.h"
#include "../../crypto/hw_accel.h"
#include "../../crypto/sha256.h"
#include "../../crypto/sha512.h"
#ifdef __ENABLE_DIGICERT_ECC__
#include "../../crypto/primefld.h"
#include "../../crypto/primeec.h"
#include "../../crypto/primefld_priv.h"
#include "../../crypto/primeec_priv.h"
#endif
#include "../../crypto/pkcs1.h"
#include "../smp_utils/smp_utils.h"
#include "smp_tpm2_utils.h"
#include "smp_tap_tpm2.h"
#include "smp_tpm2.h"
#include "../../tap/tap_base_serialize.h"
#include "tpm2_lib/sapi2/sapi2_serialize.h"
#include "tpm2_lib/fapi2/fapi2_context_internal.h"
#include "tpm2_lib/fapi2/fapi2_utils_internal.h"
#include "tpm2_lib/fapi2/fapi2_asym_internal.h"
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#include "../../crypto_interface/cryptointerface.h"
#include "../../crypto_interface/crypto_interface_pkcs1.h"
#endif
#ifdef __RTOS_WIN32__
#include "../../smp/smp_tpm2/tpm2_lib/tpm2/tbs_util.h"
#endif

#define APISTATE_MODULE_MUTEX_LOCKED         0x01
#define APISTATE_RSA_KEY_CREATED             0x02
#define APISTATE_RESULT_BUFFER_CREATED       0x04
#define APISTATE_FAPI_CONTEXT_INIT           0x08

extern TPM2_MODULE_CONFIG_SECTION *pgConfig;
extern RTOS_MUTEX tpm2SmpMutex;

static MSTATUS freeAttrList(TAP_AttributeList *pAttrs);

static MSTATUS symSignHmac(
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_SIG_SCHEME signScheme,
        TAP_SignAttributes *pSignatureAttributes,
        TAP_Buffer *pInBuffer,
        TAP_Signature **ppSignature);

MSTATUS TPM2_keyCreated(SMP_Context *pSmpContext, TAP_ObjectId objectId,
        ubyte *pObjectPresent);

int TPM2_storageObject(SMP_Context *pSmpContext, TOKEN_Context *pToken,
        TAP_ObjectId objectId)
{
    /* May need to query TPM2 library */
    return ((SMP_TPM2_CRYPTO_TOKEN_ID == pToken->id) ? 1 : 0);
}

MSTATUS TPM2_getAllProvisionedIds(SMP_Context *pSmpContext,
        TAP_EntityList *pObjectIdList)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    ubyte4 handleCount = 0;
    MgmtCapabilityIn capIn = {0};
    MgmtCapabilityOut capOut = {0};
    MgmtCapabilityOut keyCapOut = {0};
    ubyte4 keyHandleCount = 0;

    /* Internal function, pSmpContext should already be validated
       by the caller */

    {
        /* Get NV Indexes */
        capIn.capability = TPM2_CAP_HANDLES;
        capIn.property = 0x01000000;
        capIn.propertyCount = 64;
        rc = FAPI2_MGMT_getCapability(pSmpContext->pFapiContext,
                &capIn, &capOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d FAPI2_MGMT_getCapability error, rc = 0x%02x\n",
                    __FUNCTION__, __LINE__, rc);
            goto exit;
        }

        /* Map capability data to entityIdList */
        if (capOut.moreData)
        {
            /* Error out for now */
            DB_PRINT("%s.%d FAPI2_MGMT_getCapability nvHandles exceed limit of 64\n",
                    __FUNCTION__, __LINE__);
            status = ERR_TAP_CMD_FAILED;
            goto exit;
        }

        /* Get other persistent handles, SRK, EK and AIKs (if any) */
        capIn.capability = TPM2_CAP_HANDLES;
        capIn.property = 0x81000000;
        capIn.propertyCount = 64;
        rc = FAPI2_MGMT_getCapability(pSmpContext->pFapiContext,
                &capIn, &keyCapOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d FAPI2_MGMT_getCapability error, rc = 0x%02x\n",
                    __FUNCTION__, __LINE__, rc);
            goto exit;
        }

        if (!keyCapOut.moreData)
        {
            pObjectIdList->entityType = TAP_ENTITY_TYPE_OBJECT;

            keyHandleCount = keyCapOut.capabilityData.data.handles.count;

            pObjectIdList->entityIdList.numEntities = capOut.capabilityData.data.handles.count +
                keyHandleCount;
            if (0 < pObjectIdList->entityIdList.numEntities)
            {
                status = DIGI_CALLOC((void **)&pObjectIdList->entityIdList.pEntityIdList,
                        1, sizeof (TAP_EntityId) * pObjectIdList->entityIdList.numEntities);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Unable to allocate memory for Object list, status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }

                /* Update nvram object ids */
                for (handleCount = 0; handleCount < capOut.capabilityData.data.handles.count;
                        handleCount++)
                {
                    pObjectIdList->entityIdList.pEntityIdList[handleCount] =
                        (TAP_EntityId)(capOut.capabilityData.data.handles.handle[handleCount]);
                }

                /* Update persistent handles */
                for (keyHandleCount = 0; keyHandleCount < keyCapOut.capabilityData.data.handles.count;
                        keyHandleCount++)
                {
                    pObjectIdList->entityIdList.pEntityIdList[handleCount + keyHandleCount] =
                        (TAP_EntityId)(keyCapOut.capabilityData.data.handles.handle[keyHandleCount]);
                }
            }
            else
            {
                DB_PRINT("%s.%d FAPI2_MGMT_getCapability: No handle found. ObjectIdList would be empty\n",
                        __FUNCTION__, __LINE__);
            }
        }
        else
        {
            /* Error out for now */
            DB_PRINT("%s.%d FAPI2_MGMT_getCapability key handles exceed limit of 64\n",
                    __FUNCTION__, __LINE__);
            status = ERR_TAP_CMD_FAILED;
            goto exit;
        }
    }

exit:
    if (OK != status)
    {
        if (NULL != pObjectIdList->entityIdList.pEntityIdList)
        {
            if (OK !=
                 DIGI_FREE((void **)&pObjectIdList->entityIdList.pEntityIdList))
            {
                DB_PRINT("%s.%d Failed releasing memory for entitylist=%p"
                       " on failure\n", __FUNCTION__, __LINE__,
                       pObjectIdList->entityIdList.pEntityIdList);
            }
            pObjectIdList->entityIdList.numEntities = 0;
        }
    }
    return status;
}
MSTATUS TPM2_getProvisionedIds(SMP_Context *pSmpContext, TOKEN_Context *pToken,
        TAP_EntityList *pObjectIdList)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    ubyte4 handleCount = 0;
    ubyte4 objectIndex = 0;
    MgmtCapabilityIn capIn = {0};
    MgmtCapabilityOut capOut = {0};
    MgmtCapabilityOut keyCapOut = {0};
    ubyte4 keyHandleCount = 0;

    /* Internal function, pSmpContext and pToken should already be validated
       by the caller */

    if (SMP_TPM2_CRYPTO_TOKEN_ID == pToken->id)
    {
        /* Get NV Indexes */
        capIn.capability = TPM2_CAP_HANDLES;
        capIn.property = 0x01000000;
        capIn.propertyCount = 64;
        rc = FAPI2_MGMT_getCapability(pSmpContext->pFapiContext,
                &capIn, &capOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d FAPI2_MGMT_getCapability error, rc = 0x%02x\n",
                    __FUNCTION__, __LINE__, rc);
            goto exit;
        }

        /* Map capability data to entityIdList */
        if (capOut.moreData)
        {
            /* Error out for now */
            DB_PRINT("%s.%d FAPI2_MGMT_getCapability nvHandles exceed limit of 64\n",
                    __FUNCTION__, __LINE__);
            status = ERR_TAP_CMD_FAILED;
            goto exit;
        }

        /* Get other persistent handles, SRK, EK and AIKs (if any) */
        capIn.capability = TPM2_CAP_HANDLES;
        capIn.property = 0x81000000;
        capIn.propertyCount = 64;
        rc = FAPI2_MGMT_getCapability(pSmpContext->pFapiContext,
                &capIn, &keyCapOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d FAPI2_MGMT_getCapability error, rc = 0x%02x\n",
                    __FUNCTION__, __LINE__, rc);
            goto exit;
        }

        if (!keyCapOut.moreData)
        {
            pObjectIdList->entityType = TAP_ENTITY_TYPE_OBJECT;

            /* Is SRK among them, keep only that */
            for (handleCount = 0; handleCount < keyCapOut.capabilityData.data.handles.count; handleCount++)
            {
                if (FAPI2_RH_SRK == (TAP_EntityId)(keyCapOut.capabilityData.data.handles.handle[handleCount]))
                    break;
            }
            if (handleCount < keyCapOut.capabilityData.data.handles.count)
            {
                keyHandleCount = 1;
            }

            pObjectIdList->entityIdList.numEntities = capOut.capabilityData.data.handles.count +
                keyHandleCount;
            if (0 < pObjectIdList->entityIdList.numEntities)
            {
                status = DIGI_CALLOC((void **)&pObjectIdList->entityIdList.pEntityIdList,
                        1, sizeof (TAP_EntityId) * pObjectIdList->entityIdList.numEntities);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Unable to allocate memory for Object list, status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }

                /* Update nvram indexes */
                for (handleCount = 0; handleCount < capOut.capabilityData.data.handles.count;
                        handleCount++)
                {
                    pObjectIdList->entityIdList.pEntityIdList[handleCount] =
                        (TAP_EntityId)(capOut.capabilityData.data.handles.handle[handleCount]);
                }

                /* Update key handles */
                if (0 < keyHandleCount)
                {
                    /* Add SRK handle if found in keyCapOut */
                    pObjectIdList->entityIdList.pEntityIdList[handleCount] =
                        FAPI2_RH_SRK;
                }
            }
            else
            {
                DB_PRINT("%s.%d FAPI2_MGMT_getCapability: No handle found. ObjectIdList would be empty\n",
                        __FUNCTION__, __LINE__);
            }
        }
        else
        {
            /* Error out for now */
            DB_PRINT("%s.%d FAPI2_MGMT_getCapability key handles exceed limit of 64\n",
                    __FUNCTION__, __LINE__);
            status = ERR_TAP_CMD_FAILED;
            goto exit;
        }
    }
    else
    {
        /* Get other persistent handles, SRK, EK and AIKs (if any) */
        capIn.capability = TPM2_CAP_HANDLES;
        capIn.property = 0x81000000;
        capIn.propertyCount = 64;
        rc = FAPI2_MGMT_getCapability(pSmpContext->pFapiContext,
                &capIn, &keyCapOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d FAPI2_MGMT_getCapability error, rc = 0x%02x\n",
                    __FUNCTION__, __LINE__, rc);
            goto exit;
        }

        if (!keyCapOut.moreData)
        {
            /* Is SRK among them, skip that */
            for (handleCount = 0; handleCount < keyCapOut.capabilityData.data.handles.count; handleCount++)
            {
                if (FAPI2_RH_SRK == (TAP_EntityId)(keyCapOut.capabilityData.data.handles.handle[handleCount]))
                    break;
            }
            if (handleCount < keyCapOut.capabilityData.data.handles.count)
                keyHandleCount = keyCapOut.capabilityData.data.handles.count - 1;
            else
                keyHandleCount = keyCapOut.capabilityData.data.handles.count;

            pObjectIdList->entityType = TAP_ENTITY_TYPE_OBJECT;
            pObjectIdList->entityIdList.numEntities = keyHandleCount;

            if (0 < pObjectIdList->entityIdList.numEntities)
            {
                status = DIGI_CALLOC((void **)&pObjectIdList->entityIdList.pEntityIdList,
                        1, sizeof (TAP_EntityId) * pObjectIdList->entityIdList.numEntities);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Unable to allocate memory for Object list, status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }

                objectIndex = 0;

                /* Update key handles */
                for (handleCount = 0; handleCount < keyCapOut.capabilityData.data.handles.count; handleCount++)
                {
                    if (FAPI2_RH_SRK != keyCapOut.capabilityData.data.handles.handle[handleCount])
                    {
                        pObjectIdList->entityIdList.pEntityIdList[objectIndex++] =
                            (TAP_EntityId)(keyCapOut.capabilityData.data.handles.handle[handleCount]);
                    }
                }
            }
            else
            {
                DB_PRINT("%s.%d FAPI2_MGMT_getCapability: No key handle found. ObjectIdList would be empty\n",
                        __FUNCTION__, __LINE__);
            }
        }
        else
        {
            /* Error out for now */
            DB_PRINT("%s.%d FAPI2_MGMT_getCapability key handles exceed limit of 64\n",
                    __FUNCTION__, __LINE__);
            status = ERR_TAP_CMD_FAILED;
            goto exit;
        }
    }

exit:
    if (OK != status)
    {
        if (NULL != pObjectIdList->entityIdList.pEntityIdList)
        {
            if (OK !=
                 DIGI_FREE((void **)&pObjectIdList->entityIdList.pEntityIdList))
            {
                DB_PRINT("%s.%d Failed releasing memory for entitylist=%p"
                       " on failure\n", __FUNCTION__, __LINE__,
                       pObjectIdList->entityIdList.pEntityIdList);
            }
            pObjectIdList->entityIdList.numEntities = 0;
        }
    }
    return status;
}

static MSTATUS getModuleConnectionInfo(TAP_ModuleId moduleId,
        TPM2_MODULE_CONFIG_SECTION **ppModuleConfigInfo)
{
    MSTATUS status = OK;
    TPM2_MODULE_CONFIG_SECTION *pModuleInfo = NULL;

    if ((0 == moduleId) || (NULL == ppModuleConfigInfo))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleId = %p,"
                "ppModuleConfigInfo = %p\n",
                __FUNCTION__, __LINE__, moduleId,
                ppModuleConfigInfo);
        goto exit;
    }

    pModuleInfo = pgConfig;

    while (pModuleInfo)
    {
        if (pModuleInfo->moduleId == moduleId)
        {
            *ppModuleConfigInfo = pModuleInfo;
            break;
        }

        pModuleInfo = pModuleInfo->pNext;
    }

    if (!pModuleInfo)
    {
        DB_PRINT("%s.%d Failed fetching module configuration for moduleId=%d\n",
                __FUNCTION__, __LINE__, moduleId);
        status = ERR_INVALID_ARG;
    }

exit:
    return status;
}

/*! TPM20_SECURITY_MODULE */
#define TPM20_SECURITY_MODULE       0
/*! TPM20_SECURITY_EMULATOR */
#define TPM20_SECURITY_EMULATOR     1

#ifdef __RTOS_WIN32__
static ubyte4 getTPM2DeviceType(TAP_ModuleId moduleId)
{
    MSTATUS status = OK;
    ubyte4 tpm2DeviceType = TPM20_SECURITY_MODULE;
    TPM2_MODULE_CONFIG_SECTION *pModuleConfigInfo = NULL;

    if (0 == moduleId)
        goto exit;

    status = getModuleConnectionInfo(moduleId, &pModuleConfigInfo);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to locate Device connection information, "
                "status = %d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

    tpm2DeviceType = (0 == pModuleConfigInfo->modulePort) ?
                        TPM20_SECURITY_MODULE : TPM20_SECURITY_EMULATOR;

exit:
    return tpm2DeviceType;
}
#endif

static int TPM2_getAttribute(TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_ATTR_TYPE attrType, TAP_Attribute **ppAttribute)
{
    TAP_Attribute *pAttribute  = NULL;
    ubyte4 attrCount = 0;
    int rc = 0;

    if (pObjectAttributes && pObjectAttributes->listLen)
    {
        pAttribute = pObjectAttributes->pAttributeList;
        attrCount = 0;

        while (attrCount < pObjectAttributes->listLen)
        {
            if (attrType == pAttribute->type)
            {
                *ppAttribute = pAttribute;
                rc = 1;
                break;
            }

            pAttribute++;
            attrCount++;
        }
    }

    return rc;
}

#if (defined __SMP_ENABLE_SMP_CC_INIT_OBJECT__) || \
    (defined __SMP_ENABLE_SMP_CC_CREATE_OBJECT__)

int TPM2_nvProvisionedIndex(SMP_Context *pSmpContext, TOKEN_Context *pToken,
        TAP_ObjectId nvId)
{
    int rc = 0;
    ubyte4 i;
    TAP_EntityList objectIdList = {0};

    if (OK != TPM2_getProvisionedIds(pSmpContext, pToken,
                &objectIdList))
    {
        DB_PRINT("%s.%d Failed retrieving provisioned ids\n",
                __FUNCTION__, __LINE__);
        goto exit;
    }

    for (i = 0; i < objectIdList.entityIdList.numEntities; i++)
    {
        if (nvId == objectIdList.entityIdList.pEntityIdList[i])
        {
            /* Found */
            rc = 1;
            break;
        }
    }

    /* Free object list */
    DIGI_FREE((void **)&objectIdList.entityIdList.pEntityIdList);

exit:

    return rc;
}
#endif

#if (defined __SMP_ENABLE_SMP_CC_FREE_MODULE_LIST__) || (defined __SMP_ENABLE_SMP_CC_GET_MODULE_LIST__)

static MSTATUS getModuleMutex(TAP_ModuleId moduleId,
        SMP_Context *pSmpContext)
{
    MSTATUS status = OK;
    TPM2_MODULE_CONFIG_SECTION *pModuleInfo = NULL;

    if (NULL == pSmpContext)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, pSmpContext = %p\n",
                __FUNCTION__, __LINE__, pSmpContext);
        goto exit;
    }

    pModuleInfo = pgConfig;
    while (pModuleInfo)
    {
        if (pModuleInfo->moduleId == moduleId)
        {
            pSmpContext->moduleMutex = pModuleInfo->moduleMutex;

            break;
        }

        pModuleInfo = pModuleInfo->pNext;
    }

    if (!pModuleInfo)
    {
        status = ERR_INVALID_ARG;
    }

exit:
    return status;
}

#endif

/*------------------------------------------------------------------*/
MOC_EXTERN MSTATUS TPM2_getDeviceModuleIdString(TPM2_MODULE_CONFIG_SECTION *pModuleConfig, ubyte *pDeviceId)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    FAPI2_CONTEXT *pFapiContext = NULL;
    AdminGetPrimaryPublicKeyIn pubKeyIn = {0};
    AdminGetPrimaryPublicKeyOut pubKeyOut = {0};
    sha256Descr shaContext = {0};
    ubyte state = 0x00;
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    hwAccelDescr hwAccelCtx = 0;
#endif
    
    if ((NULL == pModuleConfig) || (NULL == pDeviceId))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input pModuleConfig = %p, pDeviceId = %p\n",
                __FUNCTION__, __LINE__, pModuleConfig, pDeviceId);
        goto exit;
    }
    
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    status = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
        goto exit;
#endif

    /* Init module */
    rc = FAPI2_CONTEXT_init(&pFapiContext,
            pModuleConfig->moduleName.bufferLen,
            pModuleConfig->moduleName.pBuffer,
            pModuleConfig->modulePort,
            4, NULL);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d FAPI2 Context init error, rc = 0x%02x\n",
                __FUNCTION__, __LINE__, rc);
        goto exit;
    }
    state |= APISTATE_FAPI_CONTEXT_INIT;

    /* Get Public key */
    pubKeyIn.persistentHandle = FAPI2_RH_EK;
    rc = FAPI2_ADMIN_getPrimaryPublicKey(pFapiContext,
            &pubKeyIn, &pubKeyOut);
    if (TSS2_RC_SUCCESS != rc)
    {

        DB_PRINT("%s.%d FAPI2 get primary public key error, rc = 0x%02x\n",
                __FUNCTION__, __LINE__, rc);
        goto exit;
    }

    switch (pubKeyOut.keyAlg)
    {
        case TPM2_ALG_RSA:
            status = SHA256_completeDigest(MOC_HASH(hwAccelCtx) pubKeyOut.publicKey.rsaPublic.buffer,
                    pubKeyOut.publicKey.rsaPublic.size,
                    pDeviceId);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to generate digest, status = %d\n",
                        __FUNCTION__, __LINE__, (int)status);
            }

            break;

        case TPM2_ALG_ECC:
            status = SHA256_initDigest(MOC_HASH(hwAccelCtx) &shaContext);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to init SHA256 digest, status = %d\n",
                        __FUNCTION__, __LINE__, (int)status);
            }

            status = SHA256_updateDigest(MOC_HASH(hwAccelCtx) &shaContext,
                    pubKeyOut.publicKey.eccPublic.x.buffer,
                    pubKeyOut.publicKey.eccPublic.x.size);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to update SHA256 digest on x value, status = %d\n",
                        __FUNCTION__, __LINE__, (int)status);
            }

            status = SHA256_updateDigest(MOC_HASH(hwAccelCtx) &shaContext,
                    pubKeyOut.publicKey.eccPublic.y.buffer,
                    pubKeyOut.publicKey.eccPublic.y.size);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to update SHA256 digest on y value, status = %d\n",
                        __FUNCTION__, __LINE__, (int)status);
            }

            status = SHA256_finalDigest(MOC_HASH(hwAccelCtx) &shaContext, pDeviceId);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to finalize SHA256 digest, status = %d\n",
                        __FUNCTION__, __LINE__, (int)status);
            }
            break;

        default:
            DB_PRINT("%s.%d Invalid key algorithm %d\n",
                    __FUNCTION__, __LINE__, (int)pubKeyOut.keyAlg);
            status = ERR_TAP_CMD_FAILED;
            goto exit;
    }

    /* Uninit module */
    rc = FAPI2_CONTEXT_uninit(&pFapiContext);
    state &= ~(APISTATE_FAPI_CONTEXT_INIT);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d FAPI2 Context uninit error, rc = 0x%02x\n",
                __FUNCTION__, __LINE__, rc);
    }

exit:

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_freeCloneHashCtx(&shaContext);
#endif

    if (TSS2_RC_SUCCESS != rc)
        status = ERR_GENERAL;

    /*Uninitialize any latest uninitalized fapi_context*/
    if (state & APISTATE_FAPI_CONTEXT_INIT)
    {
        rc = FAPI2_CONTEXT_uninit(&pFapiContext);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d FAPI2 Context uninit error on exit, rc= 0x%02x\n",
                    __FUNCTION__, __LINE__, rc);
        }
    }
    
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
#endif
    
    return status;
}

#ifdef __SMP_ENABLE_SMP_CC_GET_MODULE_LIST__

/*------------------------------------------------------------------*/
MSTATUS TPM2_validateModuleList(TPM2_MODULE_CONFIG_SECTION *pModuleInfo)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    FAPI2_CONTEXT *pFapiContext = NULL;
    AdminGetPrimaryPublicKeyIn pubKeyIn = {0};
    AdminGetPrimaryPublicKeyOut pubKeyOut = {0};
    TPM2_MODULE_CONFIG_SECTION *pModuleConfig = NULL;
    sbyte4 cmpResult = -1;
    sha256Descr shaContext = {0};
    ubyte4 moduleIndex = 0;
    ubyte4 maxDevices = 0;
    ubyte *pWildcard = NULL;
    ubyte4 wildcardLocation = 0;
    ubyte4 numDigits = 0;
    ubyte4 moduleNameLen = 0;
    ubyte *moduleNamePtr = NULL;
    TAP_Buffer moduleName = {0};
    ubyte state = 0x00;
    ubyte4 i;
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    hwAccelDescr hwAccelCtx = 0;
#endif

    if (NULL == pModuleInfo)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input pModuleInfo = %p\n",
                __FUNCTION__, __LINE__, pModuleInfo);
        goto exit;
    }

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    status = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
        goto exit;
#endif

    pModuleConfig = pModuleInfo;
    while (pModuleConfig)
    {
        if (NULL != (pWildcard = (ubyte *)DIGI_STRCHR(
                        (sbyte *)pModuleConfig->moduleName.pBuffer,
                        WILDCARD, pModuleConfig->moduleName.bufferLen)))
        {
            wildcardLocation = pWildcard - pModuleConfig->moduleName.pBuffer;
            status = DIGI_CALLOC((void **)&moduleName.pBuffer, 1,
                    pModuleConfig->moduleName.bufferLen + WILDCARD_STR_LEN);
            if (OK != status)
            {
                DB_PRINT("%s.%d Error allocating memory for module name, status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }

            status = DIGI_MEMCPY(moduleName.pBuffer, pModuleConfig->moduleName.pBuffer,
                    pModuleConfig->moduleName.bufferLen);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy %d bytes of module name, status = %d\n",
                        __FUNCTION__, __LINE__, pModuleConfig->moduleName.bufferLen,
                        status);
                goto exit;
            }

            moduleNamePtr = moduleName.pBuffer;

            /* Start with index 0, eg /dev/tpm0 */
            status = DIGI_UTOA(moduleIndex, &moduleNamePtr[wildcardLocation],
                        &numDigits);
            if (OK != status)
            {
                DB_PRINT("%s.%d DIGI_UTOA failed to convert %d to string, status = %d\n",
                        __FUNCTION__, __LINE__, moduleIndex, status);
                goto exit;
            }

            moduleNameLen = pModuleConfig->moduleName.bufferLen + numDigits;
            maxDevices = MAX_TPM2_DEVICES;
        }
        else
        {
            maxDevices = 1;
            moduleNamePtr = pModuleConfig->moduleName.pBuffer;
            moduleNameLen = pModuleConfig->moduleName.bufferLen;
        }

        for (moduleIndex = 0; moduleIndex < maxDevices; moduleIndex++)
        {
            if (moduleIndex)
            {
                status = DIGI_UTOA(moduleIndex, &moduleNamePtr[wildcardLocation],
                        &numDigits);
                if (OK != status)
                {
                    DB_PRINT("%s.%d DIGI_UTOA failed to convert %d to string, status = %d\n",
                            __FUNCTION__, __LINE__, moduleIndex, status);
                    goto exit;
                }
                moduleNameLen = pModuleConfig->moduleName.bufferLen + numDigits;
#ifdef TESTING
                if (4 == moduleIndex)
                {
                    DIGI_STRCBCPY((sbyte *)moduleName.pBuffer,
                            10, (const sbyte *)"localhost");
                    moduleName.bufferLen = 10;
                    moduleNameLen = 10;
                }
#endif
            }

            /* Init module */
            rc = FAPI2_CONTEXT_init(&pFapiContext,
                    moduleNameLen,
                    moduleNamePtr,
                    pModuleConfig->modulePort,
                    8, NULL);
            if (TSS2_RC_SUCCESS != rc)
            {
                DB_PRINT("%s.%d FAPI2 Context init error, rc = 0x%02x\n",
                        __FUNCTION__, __LINE__, rc);
                continue;
            }
            state |= APISTATE_FAPI_CONTEXT_INIT;

            /* Get Public key */
            pubKeyIn.persistentHandle = FAPI2_RH_EK;
            rc = FAPI2_ADMIN_getPrimaryPublicKey(pFapiContext,
                    &pubKeyIn, &pubKeyOut);
            if (TSS2_RC_SUCCESS != rc)
            {
                DB_PRINT("%s.%d FAPI2 get primary public key error, rc = 0x%02x\n",
                        __FUNCTION__, __LINE__, rc);
                continue;
            }
            switch (pubKeyOut.keyAlg)
            {
                case TPM2_ALG_RSA:
                    status = SHA256_completeDigest(MOC_HASH(hwAccelCtx) pubKeyOut.publicKey.rsaPublic.buffer,
                            pubKeyOut.publicKey.rsaPublic.size,
                            pModuleConfig->deviceModuleIdStr);
                    if (OK != status)
                    {
                        DB_PRINT("%s.%d Failed to generate digest, status = %d\n",
                                __FUNCTION__, __LINE__, (int)status);
                        continue;
                    }

                    break;

                case TPM2_ALG_ECC:
                    status = SHA256_initDigest(MOC_HASH(hwAccelCtx) &shaContext);
                    if (OK != status)
                    {
                        DB_PRINT("%s.%d Failed to init SHA256 digest, status = %d\n",
                                __FUNCTION__, __LINE__, (int)status);
                        continue;
                    }

                    status = SHA256_updateDigest(MOC_HASH(hwAccelCtx) &shaContext,
                            pubKeyOut.publicKey.eccPublic.x.buffer,
                            pubKeyOut.publicKey.eccPublic.x.size);
                    if (OK != status)
                    {
                        DB_PRINT("%s.%d Failed to update SHA256 digest on x value, status = %d\n",
                                __FUNCTION__, __LINE__, (int)status);
                        continue;
                    }

                    status = SHA256_updateDigest(MOC_HASH(hwAccelCtx) &shaContext,
                            pubKeyOut.publicKey.eccPublic.y.buffer,
                            pubKeyOut.publicKey.eccPublic.y.size);
                    if (OK != status)
                    {
                        DB_PRINT("%s.%d Failed to update SHA256 digest on y value, status = %d\n",
                                __FUNCTION__, __LINE__, (int)status);
                        continue;
                    }

                    status = SHA256_finalDigest(MOC_HASH(hwAccelCtx) &shaContext, pModuleConfig->deviceModuleIdStr);
                    if (OK != status)
                    {
                        DB_PRINT("%s.%d Failed to finalize SHA256 digest, status = %d\n",
                                __FUNCTION__, __LINE__, (int)status);
                        continue;
                    }
                    break;

                default:
                    DB_PRINT("%s.%d Invalid key algorithm %d\n",
                            __FUNCTION__, __LINE__, (int)pubKeyOut.keyAlg);
                    status = ERR_TAP_CMD_FAILED;
                    goto exit;
            }

            /* Verify */
            status = DIGI_MEMCMP(pModuleConfig->deviceModuleIdStr,
                    pModuleConfig->configuredModuleIdStr,
                    sizeof(pModuleConfig->deviceModuleIdStr), &cmpResult);
            if (OK != status)
            {
                DB_PRINT("%s.%d Error comparing ModuleId's, status = %d\n",
                        __FUNCTION__, __LINE__, (int)status);

                goto exit;
            }

            if (0 != cmpResult)
            {
                /* Fail if we are at the last entry */
                if (moduleIndex == (maxDevices - 1))
                {
                    DB_PRINT("%s.%d Module ID string check failed, device module id string "
                            "does not match one in configuration file\n",
                            __FUNCTION__, __LINE__);

                    /* Dump all the moduleid strings found thus far */
                    for (moduleIndex = 0; moduleIndex < maxDevices; moduleIndex++)
                    {
                        DB_PRINT("\nModule Id %d DeviceID string set to => ", pModuleConfig->moduleId);
                        for(i = 0; i < sizeof(pModuleConfig->deviceModuleIdStr); i++)
                        {
                            DB_PRINT("%02x", pModuleConfig->deviceModuleIdStr[i]);
                        }
                        DB_PRINT("\n");
                    }
                    status = ERR_TAP_CMD_FAILED;
                    goto exit;
                }
            }
            else
            {
                /* If multiple moduleNames were scanned,
                   Save this moduleName as the correct device name
                 */
                if (moduleName.pBuffer)
                {
                    if (pModuleConfig->moduleName.pBuffer)
                    {
                        /* Free old buffer */
                        DIGI_FREE((void **)&pModuleConfig->moduleName.pBuffer);
                        pModuleConfig->moduleName.bufferLen = 0;
                    }

                    /* Assign updated buffer */
                    pModuleConfig->moduleName = moduleName;

                    moduleName.pBuffer = NULL;
                    moduleName.bufferLen = 0;
                }
                break;
            }

            /* Uninit module */
            rc = FAPI2_CONTEXT_uninit(&pFapiContext);
            state &= ~(APISTATE_FAPI_CONTEXT_INIT);
            if (TSS2_RC_SUCCESS != rc)
            {
                DB_PRINT("%s.%d FAPI2 Context uninit error, rc = 0x%02x\n",
                        __FUNCTION__, __LINE__, rc);
                continue;
            }
        }

        /* Next module */
        pModuleConfig = pModuleConfig->pNext;
    }
exit:

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_freeCloneHashCtx(&shaContext);
#endif

    if (OK != status)
    {
        if (moduleName.pBuffer)
        {
            DIGI_FREE((void **)&moduleName.pBuffer);
            moduleName.bufferLen = 0;
        }
    }

    /*Uninitialize any latest uninitalized fapi_context*/
    if (state & APISTATE_FAPI_CONTEXT_INIT)
    {
        rc = FAPI2_CONTEXT_uninit(&pFapiContext);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d FAPI2 Context uninit error on exit, rc= 0x%02x\n",
                    __FUNCTION__, __LINE__, rc);
        }
    }

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
#endif

    return status;
}

MSTATUS SMP_API(TPM2, getModuleList,
        TAP_ModuleCapabilityAttributes *pModuleAttributes,
        TAP_EntityList *pModuleIdList
)
{
    MSTATUS status = OK;
    TPM2_MODULE_CONFIG_SECTION *pModuleConfig = NULL;
    ubyte4 entity = 0;

    if (NULL == pModuleIdList)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input pModuleIdList = %p\n",
                __FUNCTION__, __LINE__, pModuleIdList);
        goto exit;
    }

    /* Build the Module list from configuration */
    pModuleConfig = pgConfig;
    while (pModuleConfig)
    {
        entity++;
        pModuleConfig = pModuleConfig->pNext;
    }

    pModuleIdList->entityType = TAP_ENTITY_TYPE_MODULE;
    pModuleIdList->entityIdList.numEntities = entity;
    if (entity)
    {
        status = DIGI_CALLOC((void **)&pModuleIdList->entityIdList.pEntityIdList, 1,
            sizeof(TAP_EntityId) * pModuleIdList->entityIdList.numEntities);
        if (OK != status)
        {
            DB_PRINT("%s.%d Unable to allocate memory for Module list, status = %d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }

        pModuleConfig = pgConfig;
        for (entity = 0; entity < pModuleIdList->entityIdList.numEntities; entity++)
        {
            pModuleIdList->entityIdList.pEntityIdList[entity] = pModuleConfig->moduleId;

            pModuleConfig = pModuleConfig->pNext;
        }
    }

exit:

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_FREE_MODULE_LIST__
/*------------------------------------------------------------------*/

MSTATUS SMP_API(TPM2, freeModuleList,
        TAP_EntityList *pModuleList
)
{
    MSTATUS status = OK;

    if (NULL == pModuleList)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, pModuleList = %p\n",
                __FUNCTION__, __LINE__, pModuleList);
        goto exit;
    }

    if (pModuleList->entityIdList.pEntityIdList)
    {
        if (OK != DIGI_FREE((void **)&pModuleList->entityIdList.pEntityIdList))
        {
            DB_PRINT("%s.%d Failed freeing memory for entity at - %p\n",
                    __FUNCTION__, __LINE__, pModuleList->entityIdList.pEntityIdList);
        }
    }

exit:

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_MODULE_INFO__

MSTATUS getCapabilityWord(FAPI2_CONTEXT *pFapiContext, ubyte4 capProperty,
        ubyte4 *pCapabilityWord)
{
    MSTATUS status = OK;
    MgmtCapabilityIn capIn = {0};
    MgmtCapabilityOut capOut = {0};
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    /* Get Firmware version (MSB) */
    capIn.capability = TPM2_CAP_TPM_PROPERTIES;
    capIn.property = capProperty;
    capIn.propertyCount = 64;
    rc = FAPI2_MGMT_getCapability(pFapiContext,
            &capIn, &capOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d FAPI2_MGMT_getCapability error, rc = %d\n",
                __FUNCTION__, __LINE__, rc);
        goto exit;
    }

    if (capOut.moreData)
    {
        /* Error out for now */
        DB_PRINT("%s.%d FAPI2_MGMT_getCapability vendor string2 exceeds limit of %d\n",
                __FUNCTION__, __LINE__, capIn.propertyCount);
        status = ERR_TAP_CMD_FAILED;
        goto exit;
    }

    *pCapabilityWord = DIGI_NTOHL((ubyte *)&capOut.capabilityData.data.tpmProperties.tpmProperty[0].value);

exit:
    return status;
}

static MSTATUS TPM2_getModuleInfo(TAP_ModuleId moduleId,
        TPM2_MODULE_INFO *pModuleInfo)
{
    MSTATUS status = OK;
    FAPI2_CONTEXT *pFapiContext = NULL;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    ContextIsTpmProvisionedOut isProvisioned = { 0 };
    TPM2_MODULE_CONFIG_SECTION *pModuleConfigInfo = NULL;

    status = getModuleConnectionInfo(moduleId, &pModuleConfigInfo);

    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to locate Device connection information, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    /* Init module */
    rc = FAPI2_CONTEXT_init(&pFapiContext,
            pModuleConfigInfo->moduleName.bufferLen,
            pModuleConfigInfo->moduleName.pBuffer,
            pModuleConfigInfo->modulePort,
            8, NULL);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d FAPI2 Context init error, rc = 0x%02x\n",
                __FUNCTION__, __LINE__, rc);
        goto exit;
    }

    /* Get Module provision status */
    rc = FAPI2_CONTEXT_isTpmProvisioned(pFapiContext, &isProvisioned);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d FAPI2 isTpmProvisioned error, rc = 0x%02x\n",
                __FUNCTION__, __LINE__, rc);
        goto exit;
    }

    *pModuleInfo->pIsTpmConfigured = (isProvisioned.provisioned) ? TRUE : FALSE;

    /* Get Manufacturer info */
    status = getCapabilityWord(pFapiContext, 0x00000105,
            pModuleInfo->pManufacturer);
    if (OK != status)
    {
        DB_PRINT("%s.%d getCapabilityWord returned error, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    /* Get Vendor info */
    status = getCapabilityWord(pFapiContext, 0x00000106,
            pModuleInfo->pVendorString1);
    if (OK != status)
    {
        DB_PRINT("%s.%d getCapabilityWord returned error, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    /* Get Vendor info (String 2) */
    status = getCapabilityWord(pFapiContext, 0x00000107,
            pModuleInfo->pVendorString2);
    if (OK != status)
    {
        DB_PRINT("%s.%d getCapabilityWord returned error, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    /* Get Firmware version (High) */
    status = getCapabilityWord(pFapiContext, 0x0000010b,
            pModuleInfo->pFirmwareVersionHigh);
    if (OK != status)
    {
        DB_PRINT("%s.%d getCapabilityWord returned error, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    /* Get Firmware version (Low) */
    status = getCapabilityWord(pFapiContext, 0x0000010c,
            pModuleInfo->pFirmwareVersionLow);
    if (OK != status)
    {
        DB_PRINT("%s.%d getCapabilityWord returned error, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    /* Firmware version is Little endian */
    *pModuleInfo->pFirmwareVersionHigh = DIGI_NTOHL((const ubyte *)pModuleInfo->pFirmwareVersionHigh);
    *pModuleInfo->pFirmwareVersionLow = DIGI_NTOHL((const ubyte *)pModuleInfo->pFirmwareVersionLow);

exit:
    /* If FAPI CONTEXT initialized then uninitialize it regardless of status */
    if (NULL != pFapiContext)
    {
        rc = FAPI2_CONTEXT_uninit(&pFapiContext);
        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d FAPI2 Context uninit error, rc = 0x%02x\n",
                    __FUNCTION__, __LINE__, rc);
        }
    }

    return status;
}

static MSTATUS TAP_copyCredential(TAP_Credential *pDestCredentials,
        TAP_Credential *pSrcCredentials)
{
    MSTATUS status = OK;

    if(!pDestCredentials || !pSrcCredentials)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    pDestCredentials->credentialType = pSrcCredentials->credentialType;
    pDestCredentials->credentialFormat = pSrcCredentials->credentialFormat;
    pDestCredentials->credentialContext = pSrcCredentials->credentialContext;

    pDestCredentials->credentialData.pBuffer = NULL;

    /* Allocate Auth data buffer, if required */
    pDestCredentials->credentialData.bufferLen =
        pSrcCredentials->credentialData.bufferLen;

    if (pDestCredentials->credentialData.bufferLen)
    {
        status = DIGI_MALLOC(
                (void **)&pDestCredentials->credentialData.pBuffer,
                pDestCredentials->credentialData.bufferLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Error allocating memory for credential auth data, "
                    "status = %d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }

        status = DIGI_MEMCPY(pDestCredentials->credentialData.pBuffer,
                pSrcCredentials->credentialData.pBuffer,
                pDestCredentials->credentialData.bufferLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Error copying credential auth data, "
                    "status = %d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }
    }
exit:
    if (OK != status)
    {
        if (pDestCredentials && pDestCredentials->credentialData.pBuffer)
                DIGI_FREE((void **)&pDestCredentials->credentialData.pBuffer);
    }

    return status;
}

static MSTATUS TAP_copyCredentialList(TAP_CredentialList *pDestCredentialList,
        TAP_CredentialList *pSrcCredentialList)
{
    MSTATUS status = OK;
    TAP_Credential *pSrcCredentials = NULL;
    TAP_Credential *pDestCredentials = NULL;
    ubyte4 j;

    pDestCredentialList->numCredentials =
        pSrcCredentialList->numCredentials;

    if (pDestCredentialList->numCredentials)
    {
        /* Allocate space for Credentials */
        status = DIGI_CALLOC((void **)&pDestCredentialList->pCredentialList,
                1, sizeof(pDestCredentialList->numCredentials) *
                pDestCredentialList->numCredentials);
        if (OK != status)
        {
            DB_PRINT("%s.%d Error allocating memory for credential list, "
                    "status = %d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }

        for (j = 0; j < pDestCredentialList->numCredentials; j++)
        {
            pSrcCredentials = &pSrcCredentialList->pCredentialList[j];
            pDestCredentials = &pDestCredentialList->pCredentialList[j];

            status = TAP_copyCredential(&pDestCredentialList->pCredentialList[j],
                    &pSrcCredentialList->pCredentialList[j]);

            if (OK != status)
            {
                goto exit;
            }
        }
    }

exit:

    return status;
}

static MSTATUS TAP_copyEntityCredentials(TAP_EntityCredential *pDestEntityCredentials,
        TAP_EntityCredential *pSrcEntityCredentials)
{
    MSTATUS status = OK;

    pDestEntityCredentials->parentType = pSrcEntityCredentials->parentType;
    pDestEntityCredentials->parentId = pSrcEntityCredentials->parentId;
    pDestEntityCredentials->entityType = pSrcEntityCredentials->entityType;
    pDestEntityCredentials->entityId = pSrcEntityCredentials->entityId;

    status = TAP_copyCredentialList(&pDestEntityCredentials->credentialList,
            &pSrcEntityCredentials->credentialList);
    if (OK != status)
    {
        goto exit;
    }

exit:

    return status;
}

static MSTATUS TAP_copyEntityCredentialList(TAP_Attribute *pDestAttr,
        TAP_Attribute *pSrcAttr)
{
    MSTATUS status = OK;
    TAP_EntityCredentialList *pSrcEntityCredentialList = NULL;
    TAP_EntityCredentialList *pDestEntityCredentialList = NULL;
    ubyte4 i;

    pSrcEntityCredentialList = (TAP_EntityCredentialList *)pSrcAttr->pStructOfType;
    pDestEntityCredentialList = (TAP_EntityCredentialList *)pDestAttr->pStructOfType;
    pDestEntityCredentialList->numCredentials = pSrcEntityCredentialList->numCredentials;
    if (pDestEntityCredentialList->numCredentials)
    {
        /* Allocate space for Entity Credential */
        status = DIGI_CALLOC((void **)&pDestEntityCredentialList->pEntityCredentials,
                1, pDestEntityCredentialList->numCredentials *
                sizeof(*pDestEntityCredentialList->pEntityCredentials));
        if (OK != status)
        {
            DB_PRINT("%s.%d Error allocating memory for entity credential list, "
                    "status = %d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }

        for (i = 0; i < pDestEntityCredentialList->numCredentials; i++)
        {
            status = TAP_copyEntityCredentials(&pDestEntityCredentialList->pEntityCredentials[i],
                    &pSrcEntityCredentialList->pEntityCredentials[i]);

            if (OK != status)
            {
                goto exit;
            }
        }
    }

exit:

    return status;
}

static MSTATUS TAP_copyPublicKey(TAP_PublicKey *pDestPublicKey,
        TAP_PublicKey *pSrcPublicKey)
{
    MSTATUS status = OK;
    TAP_RSAPublicKey *pDestRsaKey = NULL;
    TAP_RSAPublicKey *pSrcRsaKey = NULL;
    TAP_ECCPublicKey *pDestEccKey = NULL;
    TAP_ECCPublicKey *pSrcEccKey = NULL;
    TAP_DSAPublicKey *pDestDsaKey = NULL;
    TAP_DSAPublicKey *pSrcDsaKey = NULL;

    pDestPublicKey->keyAlgorithm = pSrcPublicKey->keyAlgorithm;

    switch(pDestPublicKey->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
            pDestRsaKey = &pDestPublicKey->publicKey.rsaKey;
            pSrcRsaKey = &pSrcPublicKey->publicKey.rsaKey;

            pDestRsaKey->modulusLen = pSrcRsaKey->modulusLen;
            if (pDestRsaKey->modulusLen)
            {
                status = DIGI_MALLOC((void **)&pDestRsaKey->pModulus,
                        pDestRsaKey->modulusLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error allocating %d bytes for RSA modulus, "
                            "status = %d\n",
                            __FUNCTION__, __LINE__, pDestRsaKey->modulusLen,
                            status);
                    goto exit;
                }

                status = DIGI_MEMCPY(pDestRsaKey->pModulus, pSrcRsaKey->pModulus,
                        pDestRsaKey->modulusLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error allocating %d bytes for RSA moduls, "
                            "status = %d\n",
                            __FUNCTION__, __LINE__, pDestRsaKey->modulusLen,
                            status);
                    goto exit;
                }
            }

            pDestRsaKey->exponentLen = pSrcRsaKey->exponentLen;
            if (pDestRsaKey->exponentLen)
            {
                status = DIGI_MALLOC((void **)&pDestRsaKey->pExponent,
                        pDestRsaKey->exponentLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error allocating %d bytes for RSA exponent, "
                            "status = %d\n",
                            __FUNCTION__, __LINE__, pDestRsaKey->exponentLen,
                            status);
                    goto exit;
                }

                status = DIGI_MEMCPY(pDestRsaKey->pExponent, pSrcRsaKey->pExponent,
                        pDestRsaKey->exponentLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error allocating %d bytes for RSA exponent, "
                            "status = %d\n",
                            __FUNCTION__, __LINE__, pDestRsaKey->exponentLen,
                            status);
                    goto exit;
                }
            }

            pDestRsaKey->encScheme = pSrcRsaKey->encScheme;
            pDestRsaKey->sigScheme = pSrcRsaKey->sigScheme;

            break;

        case TAP_KEY_ALGORITHM_ECC:
            pDestEccKey = &pDestPublicKey->publicKey.eccKey;
            pSrcEccKey = &pSrcPublicKey->publicKey.eccKey;

            pDestEccKey->curveId = pSrcEccKey->curveId;

            pDestEccKey->pubXLen = pSrcEccKey->pubXLen;
            if (pDestEccKey->pubXLen)
            {
                status = DIGI_MALLOC((void **)&pDestEccKey->pPubX,
                        pDestEccKey->pubXLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error allocating %d bytes for ECC pubX, "
                            "status = %d\n",
                            __FUNCTION__, __LINE__, pDestEccKey->pubXLen,
                            status);
                    goto exit;
                }

                status = DIGI_MEMCPY(pDestEccKey->pPubX, pSrcEccKey->pPubX,
                        pDestEccKey->pubXLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error allocating %d bytes for ECC pubX, "
                            "status = %d\n",
                            __FUNCTION__, __LINE__, pDestEccKey->pubXLen,
                            status);
                    goto exit;
                }
            }

            pDestEccKey->pubYLen = pSrcEccKey->pubYLen;
            if (pDestEccKey->pubYLen)
            {
                status = DIGI_MALLOC((void **)&pDestEccKey->pPubY,
                        pDestEccKey->pubYLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error allocating %d bytes for ECC pubY, "
                            "status = %d\n",
                            __FUNCTION__, __LINE__, pDestEccKey->pubYLen,
                            status);
                    goto exit;
                }

                status = DIGI_MEMCPY(pDestEccKey->pPubY, pSrcEccKey->pPubY,
                        pDestEccKey->pubYLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error allocating %d bytes for ECC pubY, "
                            "status = %d\n",
                            __FUNCTION__, __LINE__, pDestEccKey->pubYLen,
                            status);
                    goto exit;
                }
            }

            pDestEccKey->encScheme = pSrcEccKey->encScheme;
            pDestEccKey->sigScheme = pSrcEccKey->sigScheme;
            break;

        case TAP_KEY_ALGORITHM_DSA:
            pDestDsaKey = &pDestPublicKey->publicKey.dsaKey;
            pSrcDsaKey = &pSrcPublicKey->publicKey.dsaKey;

            pDestDsaKey->primeLen = pSrcDsaKey->primeLen;
            if (pDestDsaKey->primeLen)
            {
                status = DIGI_MALLOC((void **)&pDestDsaKey->pPrime,
                        pDestDsaKey->primeLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error allocating %d bytes for DSA prime, "
                            "status = %d\n",
                            __FUNCTION__, __LINE__, pDestDsaKey->primeLen,
                            status);
                    goto exit;
                }

                status = DIGI_MEMCPY(pDestDsaKey->pPrime, pSrcDsaKey->pPrime,
                        pDestDsaKey->primeLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error allocating %d bytes for DSA prime, "
                            "status = %d\n",
                            __FUNCTION__, __LINE__, pDestDsaKey->primeLen,
                            status);
                    goto exit;
                }
            }

            pDestDsaKey->subprimeLen = pSrcDsaKey->subprimeLen;
            if (pDestDsaKey->subprimeLen)
            {
                status = DIGI_MALLOC((void **)&pDestDsaKey->pSubprime,
                        pDestDsaKey->subprimeLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error allocating %d bytes for DSA subprime, "
                            "status = %d\n",
                            __FUNCTION__, __LINE__, pDestDsaKey->subprimeLen,
                            status);
                    goto exit;
                }

                status = DIGI_MEMCPY(pDestDsaKey->pSubprime, pSrcDsaKey->pSubprime,
                        pDestDsaKey->subprimeLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error allocating %d bytes for DSA subprime, "
                            "status = %d\n",
                            __FUNCTION__, __LINE__, pDestDsaKey->subprimeLen,
                            status);
                    goto exit;
                }
            }

            pDestDsaKey->baseLen = pSrcDsaKey->baseLen;
            if (pDestDsaKey->baseLen)
            {
                status = DIGI_MALLOC((void **)&pDestDsaKey->pBase,
                        pDestDsaKey->baseLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error allocating %d bytes for DSA key base, "
                            "status = %d\n",
                            __FUNCTION__, __LINE__, pDestDsaKey->baseLen,
                            status);
                    goto exit;
                }

                status = DIGI_MEMCPY(pDestDsaKey->pBase, pSrcDsaKey->pBase,
                        pDestDsaKey->baseLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error allocating %d bytes for DSA key base, "
                            "status = %d\n",
                            __FUNCTION__, __LINE__, pDestDsaKey->baseLen,
                            status);
                    goto exit;
                }
            }

            pDestDsaKey->pubValLen = pSrcDsaKey->pubValLen;
            if (pDestDsaKey->pubValLen)
            {
                status = DIGI_MALLOC((void **)&pDestDsaKey->pPubVal,
                        pDestDsaKey->pubValLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error allocating %d bytes for DSA public value, "
                            "status = %d\n",
                            __FUNCTION__, __LINE__, pDestDsaKey->pubValLen,
                            status);
                    goto exit;
                }

                status = DIGI_MEMCPY(pDestDsaKey->pPubVal, pSrcDsaKey->pPubVal,
                        pDestDsaKey->pubValLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error allocating %d bytes for DSA public value, "
                            "status = %d\n",
                            __FUNCTION__, __LINE__, pDestDsaKey->pubValLen,
                            status);
                    goto exit;
                }
            }
            break;

        default:
            break;
    }

exit:
    return status;
}

static MSTATUS TPM2_freeAttribute(TAP_Attribute *pAttr)
{
    MSTATUS status = OK;
    TAP_Buffer *pTapBuffer = NULL;

    switch (pAttr->type)
    {
        /* These attributes have TAP_Buffer as the structure buffer, need to allocate that as well */
        case TAP_ATTR_VENDOR_INFO:
        case TAP_ATTR_MODULE_KEY:
        case TAP_ATTR_RNG_SEED:
        case TAP_ATTR_RND_STIR:
        case TAP_ATTR_ENC_LABEL:
        case TAP_ATTR_BUFFER:
        case TAP_ATTR_TRUSTED_DATA_KEY:
        case TAP_ATTR_TRUSTED_DATA_VALUE:
        case TAP_ATTR_TEST_REPORT:
        case TAP_ATTR_TEST_REQUEST_DATA:
        case TAP_ATTR_GET_MODULE_CREDENTIALS:
            pTapBuffer = (TAP_Buffer *)pAttr->pStructOfType;
            if (NULL != pTapBuffer)
                DIGI_FREE((void **)&pAttr->pStructOfType);
            break;

        default:
            break;
    }

    return status;
}

static MSTATUS TPM2_copyAttribute(TAP_Attribute *pDestAttr,
        TAP_Attribute *pSrcAttr)
{
    MSTATUS status = OK;
    TAP_Buffer *pDestTapBuffer = NULL;
    TAP_Buffer *pSrcTapBuffer = NULL;

    status = DIGI_MALLOC((void **)&pDestAttr->pStructOfType,
            pSrcAttr->length);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error allocating %d bytes for returned attribute, "
                "status = %d\n",
                __FUNCTION__, __LINE__, pSrcAttr->length,
                status);
        goto exit;
    }

    status = DIGI_MEMCPY(pDestAttr->pStructOfType,
            pSrcAttr->pStructOfType, pSrcAttr->length);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error copying returned attribute, "
                "status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }
    pDestAttr->type = pSrcAttr->type;
    pDestAttr->length = pSrcAttr->length;
    switch (pSrcAttr->type)
    {
        /* These attributes have TAP_Buffer as the structure buffer, need to allocate that as well */
        case TAP_ATTR_VENDOR_INFO:
        case TAP_ATTR_MODULE_KEY:
        case TAP_ATTR_RNG_SEED:
        case TAP_ATTR_RND_STIR:
        case TAP_ATTR_ENC_LABEL:
        case TAP_ATTR_BUFFER:
        case TAP_ATTR_TRUSTED_DATA_KEY:
        case TAP_ATTR_TRUSTED_DATA_VALUE:
        case TAP_ATTR_TEST_REPORT:
        case TAP_ATTR_TEST_REQUEST_DATA:
        case TAP_ATTR_GET_MODULE_CREDENTIALS:
            pSrcTapBuffer = (TAP_Buffer *)pSrcAttr->pStructOfType;
            pDestTapBuffer = (TAP_Buffer *)pDestAttr->pStructOfType;
            status = DIGI_MALLOC((void **)&pDestTapBuffer->pBuffer, pSrcTapBuffer->bufferLen);
            if (OK != status)
            {
                DB_PRINT("%s.%d Error allocating %d bytes for attribute TAP_Buffer pointer, "
                        "status = %d\n",
                        __FUNCTION__, __LINE__, pSrcTapBuffer->bufferLen,
                        status);
                goto exit;
            }
            status = DIGI_MEMCPY(pDestTapBuffer->pBuffer, pSrcTapBuffer->pBuffer,
                    pSrcTapBuffer->bufferLen);
            if (OK != status)
            {
                DB_PRINT("%s.%d Error copying attribute TAP_Buffer, "
                        "status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }
            pDestTapBuffer->bufferLen = pSrcTapBuffer->bufferLen;
            break;

        case TAP_ATTR_TRUSTED_DATA_INFO:
            /* Needs special handling */
            break;

        case TAP_ATTR_CREDENTIAL_USAGE:
            status = TAP_copyEntityCredentialList(pDestAttr, pSrcAttr);
            break;

        case TAP_ATTR_CREDENTIAL_SET:
            status = TAP_copyCredentialList((TAP_CredentialList *)pDestAttr->pStructOfType,
                    (TAP_CredentialList *)pSrcAttr->pStructOfType);
            break;

        case TAP_ATTR_ENTITY_CREDENTIAL:
            status = TAP_copyEntityCredentials((TAP_EntityCredential *)pDestAttr->pStructOfType,
                        (TAP_EntityCredential *)pSrcAttr->pStructOfType);
            break;

        case TAP_ATTR_PUBLIC_KEY:
            status = TAP_copyPublicKey((TAP_PublicKey *)pDestAttr->pStructOfType,
                    (TAP_PublicKey *)pSrcAttr->pStructOfType);
            break;

        case TAP_ATTR_CREDENTIAL:
            status = TAP_copyCredential((TAP_Credential *)pDestAttr->pStructOfType,
                    (TAP_Credential *)pSrcAttr->pStructOfType);
            break;

        default:
            break;
    }

exit:
    if (OK != status)
    {
        if (pDestAttr->pStructOfType)
            DIGI_FREE((void **)&pDestAttr->pStructOfType);
    }

    return status;
}

MSTATUS SMP_API(TPM2, getModuleInfo,
        TAP_ModuleId moduleId,
        TAP_ModuleCapabilityAttributes *pCapabilitySelectAttributes,
        TAP_ModuleCapabilityAttributes *pModuleCapabilities
)
{
    MSTATUS status = OK;
    TPM2_MODULE_CONFIG_SECTION *pModuleConfig = NULL;
    static TAP_CAPABILITY_CATEGORY rng = TAP_CAPABILITY_RNG;
    static TAP_CAPABILITY_CATEGORY trustedData = TAP_CAPABILITY_TRUSTED_DATA;
    static TAP_CAPABILITY_CATEGORY crypto = TAP_CAPABILITY_CRYPTO_OP;
    static TAP_CAPABILITY_CATEGORY keyStorage = TAP_CAPABILITY_KEY_STORAGE;
    static TAP_MODULE_PROVISION_STATE provisionState = 0;
    static ubyte4 manufacturer = 0;
    static ubyte vendorBuffer[sizeof(ubyte4) * 2];
    static ubyte moduleIdStr[SHA256_RESULT_SIZE];
    static TAP_Version firmwareVersion = {0};
    static TAP_Buffer vendorInfo = {sizeof(vendorBuffer), vendorBuffer};
    static TAP_Buffer credentialFile = {0, NULL};
    static TAP_Attribute tpm2Category[] =
    {
        {TAP_ATTR_CAPABILITY_CATEGORY, sizeof(rng), (void *)&rng},
        {TAP_ATTR_CAPABILITY_CATEGORY, sizeof(trustedData), (void *)&trustedData},
        {TAP_ATTR_CAPABILITY_CATEGORY, sizeof(crypto), (void *)&crypto},
        {TAP_ATTR_CAPABILITY_CATEGORY, sizeof(keyStorage), (void *)&keyStorage},
        {TAP_ATTR_MODULE_PROVISION_STATE, sizeof(provisionState), &provisionState},
        {TAP_ATTR_MODULE_ID_STRING, sizeof(moduleIdStr), moduleIdStr},
        {TAP_ATTR_FIRMWARE_VERSION, sizeof(firmwareVersion), &firmwareVersion},
        {TAP_ATTR_VENDOR_INFO, sizeof(vendorInfo), &vendorInfo},
        {TAP_ATTR_GET_MODULE_CREDENTIALS, sizeof(credentialFile), &credentialFile},
    };
    ubyte4 count, attrCount;
    TPM2_MODULE_INFO moduleInfo = {0};
    TAP_Attribute *pTpm2ReturnCap = NULL;
    ubyte4 outAttrCount = 0;
    ubyte4 attrLen = 0, destLen = 0;;
    byteBoolean moduleLocked = FALSE;
    TPM2_MODULE_CONFIG_SECTION *pModuleConfigInfo = NULL;

    if (NULL == pModuleCapabilities)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input pModuleCapabilities = %p\n",
                __FUNCTION__, __LINE__, pModuleCapabilities);
        goto exit;
    }

    /* Check against configured moduleId's */
    pModuleConfig = pgConfig;
    while (pModuleConfig)
    {
        if (moduleId == pModuleConfig->moduleId)
            break;

        pModuleConfig = pModuleConfig->pNext;
    }
    if (!pModuleConfig)
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Invalid module id %d\n",
                __FUNCTION__, __LINE__, moduleId);
        goto exit;
    }

    status = RTOS_mutexWait(pModuleConfig->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Wait on Mutex failed with error= %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }
    moduleLocked = TRUE;

    moduleInfo.pIsTpmConfigured = &provisionState;
    moduleInfo.pManufacturer = &manufacturer;
    moduleInfo.pVendorString1 = (ubyte4 *)&vendorBuffer[0];
    moduleInfo.pVendorString2 = (ubyte4 *)&vendorBuffer[sizeof(ubyte4)];
    moduleInfo.pFirmwareVersionLow = &firmwareVersion.minor;
    moduleInfo.pFirmwareVersionHigh = &firmwareVersion.major;

    /* Get Module pCapabilities */
    TPM2_getModuleInfo(moduleId, &moduleInfo);

    /* Get Module credentials */
    status = getModuleConnectionInfo(moduleId, &pModuleConfigInfo);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to locate Device connection information, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }
    credentialFile = pModuleConfigInfo->credentialFile;

    status = DIGI_MEMCPY(moduleIdStr,
            pModuleConfig->deviceModuleIdStr, sizeof(moduleIdStr));
    if (OK != status)
    {
        DB_PRINT("%s.%d Error copying module id string, status =  %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    attrLen = sizeof(tpm2Category)/sizeof(TAP_Attribute);

    destLen = pCapabilitySelectAttributes ?
        pCapabilitySelectAttributes->listLen : attrLen;

    /* Allocate max possible attribute list */
    status = DIGI_CALLOC((void **)&pTpm2ReturnCap, 1,
            destLen * sizeof(TAP_Attribute));
    if (OK != status)
    {
        DB_PRINT("%s.%d Error allocating %d bytes for returned attribute "
                "list, status =  %d\n",
                __FUNCTION__, __LINE__,
                sizeof(tpm2Category)/sizeof(TAP_Attribute),
                status);
        goto exit;
    }

    if (pCapabilitySelectAttributes)
    {
        for (attrCount = 0; attrCount < attrLen; attrCount++)
        {
            /* Send only the Capabilities caller is interested in */
            for (count = 0; count < pCapabilitySelectAttributes->listLen; count++)
            {
                if (pCapabilitySelectAttributes->pAttributeList[count].type ==
                        tpm2Category[attrCount].type)
                {
                    /* Include this to the caller list */
                    status = TPM2_copyAttribute(&pTpm2ReturnCap[outAttrCount], &tpm2Category[attrCount]);
                    if (OK != status)
                    {
                        goto exit;
                    }

                    outAttrCount++;
                    break;
                }
            }
        }

        pModuleCapabilities->listLen = outAttrCount;
        pModuleCapabilities->pAttributeList = pTpm2ReturnCap;
        pTpm2ReturnCap = NULL;
    }
    else
    {
        pModuleCapabilities->listLen = attrLen;
        pModuleCapabilities->pAttributeList = pTpm2ReturnCap;
        pTpm2ReturnCap = NULL;
    }

exit:
    if (pTpm2ReturnCap)
    {
        for (attrCount = 0; attrCount < attrLen; attrCount++)
            TPM2_freeAttribute(&pTpm2ReturnCap[attrCount]);

        DIGI_FREE((void **)&pTpm2ReturnCap);
    }

    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pModuleConfig->moduleMutex);

    return status;
}
#endif


/*------------------------------------------------------------------*/

#ifdef __SMP_ENABLE_SMP_CC_GET_MODULE_CAPABILITY__
#define SMP_CAP_PROP_DEFAULT_DESC       (const ubyte*)""
#define SMP_CAP_PROP_DESC_MAX_SIZE      256

/*------------------------------------------------------------------*/

/* getTpmPtFixedPropDescription
 * Internal method. Used to set property decsription corresponding to
 * a property in TPM_PROPERTIES capability in PT_FIXED group
 */
static MSTATUS getTpmPtFixedPropDescription(TPM2_PT property,
                                    ubyte **ppTpmPropDesc /*OUT*/
)
{
    MSTATUS status = OK;
    sbyte4 index = 0;
    ubyte4 descTableLen = 0;
    ubyte4 descriptionLen = 0;
    const ubyte* description = (const ubyte*) SMP_CAP_PROP_DEFAULT_DESC;

    static const ubyte* pt_fixed_description_table[] =
    {
        /*(PT_FIXED + 0)*/ (const ubyte*)"TPM_PT_FAMILY_INDICATOR - a 4-octet character string containing the TPM Family value (TPM_SPEC_FAMILY)",
        /*(PT_FIXED + 1)*/ (const ubyte*)"TPM_PT_LEVEL - the level of the specification",
        /*(PT_FIXED + 2)*/ (const ubyte*)"TPM_PT_REVISION - the specification Revision times 100",
        /*(PT_FIXED + 3)*/ (const ubyte*)"TPM_PT_DAY_OF_YEAR - the specification day of year using TCG calendar",
        /*(PT_FIXED + 4)*/ (const ubyte*)"TPM_PT_YEAR - the specification year using the CE",
        /*(PT_FIXED + 5)*/ (const ubyte*)"TPM_PT_MANUFACTURER - the vendor ID unique to each TPM manufacturer ",
        /*(PT_FIXED + 6)*/ (const ubyte*)"TPM_PT_VENDOR_STRING_1 - the first four characters of the vendor ID string",
        /*(PT_FIXED + 7)*/ (const ubyte*)"TPM_PT_VENDOR_STRING_2 - the second four characters of the vendor ID string ",
        /*(PT_FIXED + 8)*/ (const ubyte*)"TPM_PT_VENDOR_STRING_3 - the third four characters of the vendor ID string ",
        /*(PT_FIXED + 9)*/ (const ubyte*)"TPM_PT_VENDOR_STRING_4 - the fourth four characters of the vendor ID sting ",
        /*(PT_FIXED + 10)*/ (const ubyte*)"TPM_PT_VENDOR_TPM_TYPE - vendor-defined value indicating the TPM model ",
        /*(PT_FIXED + 11)*/ (const ubyte*)"TPM_PT_FIRMWARE_VERSION_1 - the most-significant 32 bits of a TPM vendor-specific value indicating the version number of the firmware",
        /*(PT_FIXED + 12)*/ (const ubyte*)"TPM_PT_FIRMWARE_VERSION_2 - the least-significant 32 bits of a TPM vendor-specific value indicating the version number of the firmware",
        /*(PT_FIXED + 13)*/ (const ubyte*)"TPM_PT_INPUT_BUFFER - the maximum size of a parameter (typically, a TPM2B_MAX_BUFFER)",
        /*(PT_FIXED + 14)*/ (const ubyte*)"TPM_PT_HR_TRANSIENT_MIN - the minimum number of transient objects that can be held in TPM RAM",
        /*(PT_FIXED + 15)*/ (const ubyte*)"TPM_PT_HR_PERSISTENT_MIN - the minimum number of persistent objects that can be held in TPM NV memory",
        /*(PT_FIXED + 16)*/ (const ubyte*)"TPM_PT_HR_LOADED_MIN - the minimum number of authorization sessions that can be held in TPM RAM",
        /*(PT_FIXED + 17)*/ (const ubyte*)"TPM_PT_ACTIVE_SESSIONS_MAX - the number of authorization sessions that may be active at a time",
        /*(PT_FIXED + 18)*/ (const ubyte*)"TPM_PT_PCR_COUNT - the number of PCR implemented",
        /*(PT_FIXED + 19)*/ (const ubyte*)"TPM_PT_PCR_SELECT_MIN - the minimum number of octets in a TPMS_PCR_SELECT.sizeOfSelect",
        /*(PT_FIXED + 20)*/ (const ubyte*)"TPM_PT_CONTEXT_GAP_MAX - the maximum allowed difference (unsigned) between the contextID values of two saved session contexts",
        /*(PT_FIXED + 21 SKIPPED)*/ (const ubyte*)"Skipped",
        /*(PT_FIXED + 22)*/ (const ubyte*)"TPM_PT_NV_COUNTERS_MAX - the maximum number of NV Indexes that are allowed to have the TPMA_NV_COUNTER attribute SET",
        /*(PT_FIXED + 23)*/ (const ubyte*)"TPM_PT_NV_INDEX_MAX - the maximum size of an NV Index data area",
        /*(PT_FIXED + 24)*/ (const ubyte*)"TPM_PT_MEMORY - a TPMA_MEMORY indicating the memory management method for the TPM",
        /*(PT_FIXED + 25)*/ (const ubyte*)"TPM_PT_CLOCK_UPDATE - interval, in milliseconds, between updates to the copy of TPMS_CLOCK_INFO.clock in NV",
        /*(PT_FIXED + 26)*/ (const ubyte*)"TPM_PT_CONTEXT_HASH - the algorithm used for the integrity HMAC on saved contexts and for hashing the fuData of TPM2_FirmwareRead()",
        /*(PT_FIXED + 27)*/ (const ubyte*)"TPM_PT_CONTEXT_SYM - TPM_ALG_ID, the algorithm used for encryption of saved contexts",
        /*(PT_FIXED + 28)*/ (const ubyte*)"TPM_PT_CONTEXT_SYM_SIZE - TPM_KEY_BITS, the size of the key used for encryption of saved contexts",
        /*(PT_FIXED + 29)*/ (const ubyte*)"TPM_PT_ORDERLY_COUNT - the modulus - 1 of the count for NV update of an orderly counter",
        /*(PT_FIXED + 30)*/ (const ubyte*)"TPM_PT_MAX_COMMAND_SIZE - the maximum value for commandSize in a command",
        /*(PT_FIXED + 31)*/ (const ubyte*)"TPM_PT_MAX_RESPONSE_SIZE - the maximum value for responseSize in a response",
        /*(PT_FIXED + 32)*/ (const ubyte*)"TPM_PT_MAX_DIGEST - the maximum size of a digest that can be produced by the TPM",
        /*(PT_FIXED + 33)*/ (const ubyte*)"TPM_PT_MAX_OBJECT_CONTEXT - the maximum size of an object context that will be returned by TPM2_ContextSave",
        /*(PT_FIXED + 34)*/ (const ubyte*)"TPM_PT_MAX_SESSION_CONTEXT - the maximum size of a session context that will be returned by TPM2_ContextSave",
        /*(PT_FIXED + 35)*/ (const ubyte*)"TPM_PT_PS_FAMILY_INDICATOR - platform-specific family (a TPM_PS value)(see Table 24)",
        /*(PT_FIXED + 36)*/ (const ubyte*)"TPM_PT_PS_LEVEL - the level of the platform-specific specification",
        /*(PT_FIXED + 37)*/ (const ubyte*)"TPM_PT_PS_REVISION - the specification Revision times 100 for the platform-specific specification",
        /*(PT_FIXED + 38)*/ (const ubyte*)"TPM_PT_PS_DAY_OF_YEAR - the platform-specific specification day of year using TCG calendar",
        /*(PT_FIXED + 39)*/ (const ubyte*)"TPM_PT_PS_YEAR - the platform-specific specification year using the CE",
        /*(PT_FIXED + 40)*/ (const ubyte*)"TPM_PT_SPLIT_MAX - the number of split signing operations supported by the TPM",
        /*(PT_FIXED + 41)*/ (const ubyte*)"TPM_PT_TOTAL_COMMANDS - total number of commands implemented in the TPM",
        /*(PT_FIXED + 42)*/ (const ubyte*)"TPM_PT_LIBRARY_COMMANDS - number of commands from the TPM library that are implemented",
        /*(PT_FIXED + 43)*/ (const ubyte*)"TPM_PT_VENDOR_COMMANDS - number of vendor commands that are implemented",
        /*(PT_FIXED + 44)*/ (const ubyte*)"TPM_PT_NV_BUFFER_MAX - the maximum data size in one NV write command",
        /*(PT_FIXED + 45)*/ (const ubyte*)"TPM_PT_MODES - a TPMA_MODES value, indicating that the TPM is designed for these modes",
        /*(PT_FIXED + 46)*/ (const ubyte*)"TPM_PT_MAX_CAP_BUFFER - the maximum size of a TPMS_CAPABILITY_DATA structure returned in TPM2_GetCapability",
    };

    if (NULL == ppTpmPropDesc)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    descTableLen = sizeof(pt_fixed_description_table) /
                     sizeof(*pt_fixed_description_table);
    index = property - TPM2_PT_FIXED;

    if (0 <= index && index < (sbyte4) descTableLen)
    {
        description = pt_fixed_description_table[index];
    }

    descriptionLen = DIGI_STRLEN((sbyte*)description);
    status = DIGI_CALLOC((void **)ppTpmPropDesc, descriptionLen+1,
                        sizeof(*description));
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for Property description, "
                "status = %d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

    status = DIGI_MEMCPY(*ppTpmPropDesc, description, descriptionLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to copy property description for property = %d, "
                "status = %d\n", __FUNCTION__, __LINE__, property, status);
        goto exit;
    }

exit:
    if (OK != status)
    {
       if(NULL != ppTpmPropDesc && NULL != *ppTpmPropDesc)
       {
            DIGI_FREE((void **)ppTpmPropDesc);
       }
    }

    return status;
}

/*------------------------------------------------------------------*/

/* getTpmPtVarPropDescription
 * Internal method. Used to set property decsription corresponding to
 * a property in TPM_PROPERTIES capability in PT_VAR group
 */
static MSTATUS getTpmPtVarPropDescription(TPM2_PT property,
                                    ubyte **ppTpmPropDesc /*OUT*/
)
{
    MSTATUS status = OK;
    sbyte4 index = 0;
    ubyte4 descTableLen = 0;
    const ubyte* description = (const ubyte*) SMP_CAP_PROP_DEFAULT_DESC;
    ubyte4 descriptionLen = 0;

    static const ubyte* pt_var_description_table[] =
    {
        /*(PT_VAR + 0)*/ (const ubyte*)"TPMA_PERMANENT - TPMA_PERMANENT ",
        /*(PT_VAR + 1)*/ (const ubyte*)"TPM_PT_STARTUP_CLEAR - TPMA_STARTUP_CLEAR ",
        /*(PT_VAR + 2)*/ (const ubyte*)"TPM_PT_HR_NV_INDEX - the number of NV Indexes currently defined ",
        /*(PT_VAR + 3)*/ (const ubyte*)"TPM_PT_HR_LOADED - the number of authorization sessions currently loaded into TPM RAM",
        /*(PT_VAR + 4)*/ (const ubyte*)"TPM_PT_HR_LOADED_AVAIL - the number of additional authorization sessions, of any type, that could be loaded into TPM RAM",
        /*(PT_VAR + 5)*/ (const ubyte*)"TPM_PT_HR_ACTIVE - the number of active authorization sessions currently being tracked by the TPM",
        /*(PT_VAR + 6)*/ (const ubyte*)"TPM_PT_HR_ACTIVE_AVAIL - the number of additional authorization sessions, of any type, that could be created",
        /*(PT_VAR + 7)*/ (const ubyte*)"TPM_PT_HR_TRANSIENT_AVAIL - estimate of the number of additional transient objects that could be loaded into TPM RAM",
        /*(PT_VAR + 8)*/ (const ubyte*)"TPM_PT_HR_PERSISTENT - the number of persistent objects currently loaded into TPM NV memory",
        /*(PT_VAR + 9)*/ (const ubyte*)"TPM_PT_HR_PERSISTENT_AVAIL - the number of additional persistent objects that could be loaded into NV memory",
        /*(PT_VAR + 10)*/ (const ubyte*)"TPM_PT_NV_COUNTERS - the number of defined NV Indexes that have NV TPMA_NV_COUNTER attribute SET",
        /*(PT_VAR + 11)*/ (const ubyte*)"TPM_PT_NV_COUNTERS_AVAIL - the number of additional NV Indexes that can be defined with their TPMA_NV_COUNTER and TPMA_NV_ORDERLY attribute SET",
        /*(PT_VAR + 12)*/ (const ubyte*)"TPM_PT_ALGORITHM_SET - code that limits the algorithms that may be used with the TPM",
        /*(PT_VAR + 13)*/ (const ubyte*)"TPM_PT_LOADED_CURVES - the number of loaded ECC curves ",
        /*(PT_VAR + 14)*/ (const ubyte*)"TPM_PT_LOCKOUT_COUNTER - the current value of the lockout counter (failedTries) ",
        /*(PT_VAR + 15)*/ (const ubyte*)"TPM_PT_MAX_AUTH_FAIL - the number of authorization failures before DA lockout is invoked",
        /*(PT_VAR + 16)*/ (const ubyte*)"TPM_PT_LOCKOUT_INTERVAL - the number of seconds before the value reported by TPM_PT_LOCKOUT_COUNTER is decremented",
        /*(PT_VAR + 17)*/ (const ubyte*)"TPM_PT_LOCKOUT_RECOVERY - the number of seconds after a lockoutAuth failure before use of lockoutAuth may be attempted again",
        /*(PT_VAR + 18)*/ (const ubyte*)"TPM_PT_NV_WRITE_RECOVERY - number of milliseconds before the TPM will accept another command that will modify NV",
        /*(PT_VAR + 19)*/ (const ubyte*)"TPM_PT_AUDIT_COUNTER_0 - the high-order 32 bits of the command audit counter ",
        /*(PT_VAR + 20)*/ (const ubyte*)"TPM_PT_AUDIT_COUNTER_1 - the low-order 32 bits of the command audit counter",
    };

    if (NULL == ppTpmPropDesc)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    descTableLen = sizeof(pt_var_description_table) /
                        sizeof(*pt_var_description_table);
    index = property - TPM2_PT_VAR;

    if (0 <= index && index < (sbyte4) descTableLen)
    {
        description = pt_var_description_table[index];
    }

    descriptionLen = DIGI_STRLEN((sbyte*)description);
    status = DIGI_CALLOC((void **)ppTpmPropDesc, descriptionLen+1,
                        sizeof(*description));
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for Property description, status = %d\n",
            __FUNCTION__, __LINE__, status);
        goto exit;
    }

    status = DIGI_MEMCPY(*ppTpmPropDesc, description, descriptionLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to copy property description for property = %d, "
                "status = %d\n", __FUNCTION__, __LINE__, property, status);
        goto exit;
    }

exit:
    if (OK != status)
    {
       if(NULL != ppTpmPropDesc && NULL != *ppTpmPropDesc)
        {
            DIGI_FREE((void **)ppTpmPropDesc);
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

/* getTpmPropertyDescription
 * Internal method. Get decription text for properties in capability
 * 'TPM_PROPERTIES'
 */
static MSTATUS getTpmPropertyDescription(TPM2_PT property, ubyte** ppDescription)
{
    MSTATUS status = OK;
    TPM2_PT group = 0;

    group = property / TPM2_PT_GROUP;
    switch (group)
    {
        case 1: /* TPM2_PT_FIXED group */
            status = getTpmPtFixedPropDescription(property, ppDescription);
            break;
        case 2: /* TPM2_PT_VAR group */
            status = getTpmPtVarPropDescription(property, ppDescription);
            break;
        default:
            status = getTpmPtFixedPropDescription(TPM2_MAX_TPM_PROPERTIES,
                                                ppDescription);
            break;
    }

    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to get TPM property description text, "
                "status = %d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

/* getEccCurveName
 * Internal method. Gets Text for corresponding ECC_CURVE ID
 */
MSTATUS getEccCurveName(TPM2_ECC_CURVE curve, ubyte **ppDescription)
{
    MSTATUS status = OK;
    const ubyte *pCurveName = SMP_CAP_PROP_DEFAULT_DESC;
    ubyte4 curveNameLen = 0;

    if (NULL == ppDescription)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch (curve)
    {
        /* TPM2_ECC_NIST_P192 */
    case TPM2_ECC_NIST_P192:
        pCurveName = (const ubyte*)"TPM2_ECC_NIST_P192";
        break;
        /* TPM2_ECC_NIST_P224 */
    case TPM2_ECC_NIST_P224:
        pCurveName = (const ubyte*)"TPM2_ECC_NIST_P224";
        break;
        /* TPM2_ECC_NIST_P256 */
    case TPM2_ECC_NIST_P256:
        pCurveName = (const ubyte*)"TPM2_ECC_NIST_P256";
        break;
        /* TPM2_ECC_NIST_P384 */
    case TPM2_ECC_NIST_P384:
        pCurveName = (const ubyte*)"TPM2_ECC_NIST_P384";
        break;
        /* TPM2_ECC_NIST_P521 */
    case TPM2_ECC_NIST_P521:
        pCurveName = (const ubyte*)"TPM2_ECC_NIST_P521";
        break;
        /* TPM2_ECC_BN_P256 - for ECDAA support */
    case TPM2_ECC_BN_P256:
        pCurveName = (const ubyte*)"TPM2_ECC_BN_P256";
        break;
        /* TPM2_ECC_BN_P638 - for ECDAA support */
    case TPM2_ECC_BN_P638:
        pCurveName = (const ubyte*)"TPM2_ECC_BN_P638";
        break;
        /* TPM2_ECC_SM2_P256 */
    case TPM2_ECC_SM2_P256:
        pCurveName = (const ubyte*)"TPM2_ECC_SM2_P256";
        break;
        /* TPM2_ECC_NONE */
    case TPM2_ECC_NONE:
    default:
        pCurveName = (const ubyte*)"TPM2_ECC_NONE";
        break;
    }

    curveNameLen = DIGI_STRLEN((sbyte*)pCurveName);
    status = DIGI_CALLOC((void **)ppDescription, curveNameLen+1,
                        sizeof(**ppDescription));
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for Property description, "
                "status = %d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

    status = DIGI_MEMCPY((sbyte*) *ppDescription , (sbyte*) pCurveName, curveNameLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to copy ecc curve text for curve-id = %d, "
                "status = %d\n", __FUNCTION__, __LINE__, curve, status);
        goto exit;
    }

exit:
    if (OK != status)
    {
        if (NULL != ppDescription && NULL != *ppDescription)
        {
            DIGI_FREE((void **)ppDescription);
        }
    }

    return status;
}

/*------------------------------------------------------------------*/

/* getEccCurvePropertyDescription
 * Internal Method
 */
MSTATUS getEccCurvePropertyDescription(TPMU_CAPABILITIES *pCapabilities,
                                        sbyte4 propertyIndex,
                                        ubyte** ppDescription)
{
    MSTATUS status = OK;
    TPML_ECC_CURVE *pEccCurves = NULL;

    if ((NULL == pCapabilities) ||  (NULL == ppDescription) )
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pEccCurves = &(pCapabilities->eccCurves);

    if (0 > propertyIndex && (sbyte4) pEccCurves->count < propertyIndex)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    /* Copy algorithm name in description */
    status = getEccCurveName(pEccCurves->eccCurves[propertyIndex],
                            ppDescription);

    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to copy ecc curve name to description, "
                "status = %d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/

/* getAlgName
 * Internal method to get algorithm name text
 */
MSTATUS getAlgName(TPM2_ALG_ID algId, ubyte** ppDescription)
{
    MSTATUS status = OK;
    ubyte4 algNameLen = 0;
    const ubyte* pAlgName = SMP_CAP_PROP_DEFAULT_DESC;

    if (NULL == ppDescription)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch (algId) {
    case  TPM2_ALG_RSA:
        pAlgName = (const ubyte*)"TPM2_ALG_RSA";
        break;
    case  TPM2_ALG_DES:
        pAlgName = (const ubyte*)"TPM2_ALG_DES";
        break;
    case TPM2_ALG_3DES:
        pAlgName = (const ubyte*)"TPM2_ALG_3DES";
        break;
    case TPM2_ALG_SHA1:
        pAlgName = (const ubyte*)"TPM2_ALG_SHA1";
        break;
    case TPM2_ALG_HMAC:
        pAlgName = (const ubyte*)"TPM2_ALG_HMAC";
        break;
    case TPM2_ALG_AES:
        pAlgName = (const ubyte*)"TPM2_ALG_AES";
        break;
    case TPM2_ALG_MGF1:
        pAlgName = (const ubyte*)"TPM2_ALG_MGF1";
        break;
    case TPM2_ALG_KEYEDHASH:
        pAlgName = (const ubyte*)"TPM2_ALG_KEYEDHASH";
        break;
    case  TPM2_ALG_XOR:
        pAlgName = (const ubyte*)"TPM2_ALG_XOR";
        break;
    case  TPM2_ALG_SHA256:
        pAlgName = (const ubyte*)"TPM2_ALG_SHA256";
        break;
    case  TPM2_ALG_SHA384:
        pAlgName = (const ubyte*)"TPM2_ALG_SHA384";
        break;
    case  TPM2_ALG_SHA512:
        pAlgName = (const ubyte*)"TPM2_ALG_SHA512";
        break;
    case  TPM2_ALG_NULL:
        pAlgName = (const ubyte*)"TPM2_ALG_NULL";
        break;
    case  TPM2_ALG_SM3_256:
        pAlgName = (const ubyte*)"TPM2_ALG_SM3_256";
        break;
    case  TPM2_ALG_SM4:
        pAlgName = (const ubyte*)"TPM2_ALG_SM4";
        break;
    case  TPM2_ALG_RSASSA:
        pAlgName = (const ubyte*)"TPM2_ALG_RSASSA";
        break;
    case  TPM2_ALG_RSAES:
        pAlgName = (const ubyte*)"TPM2_ALG_RSAES";
        break;
    case  TPM2_ALG_RSAPSS:
        pAlgName = (const ubyte*)"TPM2_ALG_RSAPSS";
        break;
    case  TPM2_ALG_OAEP:
        pAlgName = (const ubyte*)"TPM2_ALG_OAEP";
        break;
    case  TPM2_ALG_ECDSA:
        pAlgName = (const ubyte*)"TPM2_ALG_ECDSA";
        break;
    case  TPM2_ALG_ECDH:
        pAlgName = (const ubyte*)"TPM2_ALG_ECDH";
        break;
    case  TPM2_ALG_ECDAA:
        pAlgName = (const ubyte*)"TPM2_ALG_ECDAA";
        break;
    case  TPM2_ALG_SM2:
        pAlgName = (const ubyte*)"TPM2_ALG_SM2";
        break;
    case  TPM2_ALG_ECSCHNORR:
        pAlgName = (const ubyte*)"TPM2_ALG_ECSCHNORR";
        break;
    case  TPM2_ALG_ECMQV:
        pAlgName = (const ubyte*)"TPM2_ALG_ECMQV";
        break;
    case  TPM2_ALG_KDF1_SP800_56A:
        pAlgName = (const ubyte*)"TPM2_ALG_KDF1_SP800_56A";
        break;
    case  TPM2_ALG_KDF2:
        pAlgName = (const ubyte*)"TPM2_ALG_KDF2";
        break;
    case  TPM2_ALG_KDF1_SP800_108:
        pAlgName = (const ubyte*)"TPM2_ALG_KDF1_SP800_108";
        break;
    case  TPM2_ALG_ECC:
        pAlgName = (const ubyte*)"TPM2_ALG_ECC";
        break;
    case  TPM2_ALG_SYMCIPHER:
        pAlgName = (const ubyte*)"TPM2_ALG_SYMCIPHER";
        break;
    case  TPM2_ALG_CAMELLIA:
        pAlgName = (const ubyte*)"TPM2_ALG_CAMELLIA";
        break;
    case  TPM2_ALG_CTR:
        pAlgName = (const ubyte*)"TPM2_ALG_CTR";
        break;
    case  TPM2_ALG_OFB:
        pAlgName = (const ubyte*)"TPM2_ALG_OFB";
        break;
    case  TPM2_ALG_CBC:
        pAlgName = (const ubyte*)"TPM2_ALG_CBC";
        break;
    case  TPM2_ALG_CFB:
        pAlgName = (const ubyte*)"TPM2_ALG_CFB";
        break;
    case  TPM2_ALG_ECB:
        pAlgName = (const ubyte*)"TPM2_ALG_ECB";
        break;
    case TPM2_ALG_ERROR:
    default:
        pAlgName = (const ubyte*)"UNKNOWN";
    }

    algNameLen = DIGI_STRLEN((sbyte*)pAlgName);
    status = DIGI_CALLOC((void **)ppDescription, algNameLen+1,
                        sizeof(**ppDescription));
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for algorithm name, "
                "status = %d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

    status = DIGI_MEMCPY((void *)(*ppDescription), (void*)pAlgName, algNameLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to copy algorithm name, status = %d\n",
            __FUNCTION__, __LINE__, status);
        goto exit;
    }
exit:
    if (OK != status)
    {
        if (NULL != ppDescription && NULL != *ppDescription)
        {
            DIGI_FREE((void**)ppDescription);
        }
    }
    return status;
}

/*------------------------------------------------------------------*/
/*
 * setAlgValues
 * Internal method - Used to set algortihm values in description
 */
ubyte4 setAlgValues(ubyte *pDesc, ubyte4 descLen, TPMA_ALGORITHM algValue)
{
    ubyte4 concatLen = 0;
    ubyte4 totalLen = 0;

    if (algValue & TPMA_ALGORITHM_ASYMMETRIC)
    {
        concatLen = DIGI_STRCBCPY((sbyte*)(pDesc), descLen,
                             (const sbyte*) " asymmetric");
        totalLen = totalLen + concatLen;
        descLen = descLen - concatLen;
        pDesc = pDesc + concatLen;
    }
    if (algValue & TPMA_ALGORITHM_SYMMETRIC)
    {
        concatLen = DIGI_STRCBCPY((sbyte*)(pDesc), descLen,
                             (const sbyte*) " symmetric");
        totalLen = totalLen + concatLen;
        descLen = descLen - concatLen;
        pDesc = pDesc + concatLen;
    }
    if (algValue & TPMA_ALGORITHM_HASH)
    {
        concatLen = DIGI_STRCBCPY((sbyte*)(pDesc), descLen,
                             (const sbyte*) " hash");
        totalLen = totalLen + concatLen;
        descLen = descLen - concatLen;
        pDesc = pDesc + concatLen;
    }
    if (algValue & TPMA_ALGORITHM_OBJECT)
    {
        concatLen = DIGI_STRCBCPY((sbyte*)(pDesc), descLen,
                             (const sbyte*) " object");
        totalLen = totalLen + concatLen;
        descLen = descLen - concatLen;
        pDesc = pDesc + concatLen;
    }
    if (algValue & TPMA_ALGORITHM_SIGNING)
    {
        concatLen = DIGI_STRCBCPY((sbyte*)(pDesc), descLen,
                             (const sbyte*) " signing");
        totalLen = totalLen + concatLen;
        descLen = descLen - concatLen;
        pDesc = pDesc + concatLen;
    }
    if (algValue & TPMA_ALGORITHM_ENCRYPTING)
    {
        concatLen = DIGI_STRCBCPY((sbyte*)(pDesc), descLen,
                             (const sbyte*) " encrypting");
        totalLen = totalLen + concatLen;
        descLen = descLen - concatLen;
        pDesc = pDesc + concatLen;
    }
    if (algValue & TPMA_ALGORITHM_METHOD)
    {
        concatLen = DIGI_STRCBCPY((sbyte*)(pDesc), descLen,
                             (const sbyte*) " method");
        totalLen = totalLen + concatLen;
        descLen = descLen - concatLen;
        pDesc = pDesc + concatLen;
    }

    return totalLen;
}

/*------------------------------------------------------------------*/
/* getAlgsPropertyDescription
 * Internal method
 * Returns description text for algorithm property in capability(0) - TPM2_CAP_ALGS.
 * Caller to free memory allocated in ppDescription
*/
MSTATUS getAlgsPropertyDescription( TPM2_ALG_ID algId,
                                    TPMA_ALGORITHM algValue,
                                    ubyte** ppDescription
)
{
    MSTATUS status = OK;
    ubyte* pAlgName = NULL;
    ubyte4 descriptionLen = 0;
    ubyte4 concatLen = 0;
    ubyte *pDesc = NULL;

    descriptionLen = SMP_CAP_PROP_DESC_MAX_SIZE;
    status = DIGI_CALLOC((void**) ppDescription, descriptionLen+1,
                        sizeof(ubyte));
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for Property description, "
                "status = %d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

    status = getAlgName(algId, &pAlgName);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to get algorithm name for algorithm-id = %d, "
                "status = %d\n", __FUNCTION__, __LINE__, algId, status);
        goto exit;
    }

    pDesc = *ppDescription;
    /* Concatenate title 'Algorithm' */
    concatLen = DIGI_STRCBCPY((sbyte*)(pDesc), descriptionLen,
                            (sbyte*)"Algorithm: ");
    descriptionLen = descriptionLen - concatLen;
    if (0 >= descriptionLen)
    {
        DB_PRINT("%s.%d Description text too long, "
                "status = %d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }
    pDesc = pDesc + concatLen;

    /* Concatenate Algorithm value */
    concatLen = DIGI_STRCBCPY((sbyte*)(pDesc), descriptionLen, (sbyte*)pAlgName);
    descriptionLen = descriptionLen - concatLen;
    if (0 >= descriptionLen)
    {
        DB_PRINT("%s.%d Description text too long, "
                "status = %d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }
    pDesc = pDesc + concatLen;

    /* Concatenate Title - Values*/
    concatLen = DIGI_STRCBCPY((sbyte*)(pDesc), descriptionLen,
                            (sbyte*)" Values: ");
    descriptionLen = descriptionLen - concatLen;
    if (0 >= descriptionLen)
    {
        DB_PRINT("%s.%d Description text too long, "
                "status = %d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }
    pDesc = pDesc + concatLen;

    /* Concatenate Values text */
    concatLen = setAlgValues(pDesc, descriptionLen, algValue);
    descriptionLen = descriptionLen - concatLen;
    if (0 >= descriptionLen)
    {
        DB_PRINT("WARNING: %s.%d Description text too long. Text truncated, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }
    pDesc = pDesc + concatLen;

exit:
    if (OK != status && NULL != *ppDescription)
    {
        DIGI_FREE((void**) ppDescription);
    }
    if (NULL != pAlgName)
    {
        DIGI_FREE((void**)&pAlgName);
    }

    return status;
}

/*------------------------------------------------------------------*/
ubyte4 setPcrValues(ubyte *pDesc, ubyte4 descMaxLen,
                    TPMS_PCR_SELECTION *pPcrSelection
)
{
    ubyte4 concatLen = 0;
    ubyte4 i = 0;
    ubyte4 descRemainderLen = descMaxLen;

    /* Concatenate Length text */
    concatLen = DIGI_STRCBCPY((sbyte*)(pDesc), descRemainderLen,
        (sbyte*)" Length: ");
    descRemainderLen = descRemainderLen - concatLen;

    if (0 >= descRemainderLen)
    {
        DB_PRINT("%s.%d Description text too long\n",
                __FUNCTION__, __LINE__);
        goto exit;
    }
    pDesc = pDesc + concatLen;

    /* Concatenate Length Value */
    if (OK != DIGI_UTOA(pPcrSelection->sizeofSelect, pDesc, &concatLen))
    {
        DB_PRINT("%s.%d: Error appending count value of PCRs\n",
            __FUNCTION__, __LINE__);
        goto exit;
    }
    descRemainderLen = descRemainderLen - concatLen;
    if (0 >= descRemainderLen)
    {
        DB_PRINT("%s.%d Description text too long\n",
            __FUNCTION__, __LINE__);
        goto exit;
    }
    pDesc = pDesc + concatLen;

    /* Concatenate Values text */
    concatLen = DIGI_STRCBCPY((sbyte*)(pDesc), descRemainderLen,
        (sbyte*)" Values: ");
    descRemainderLen = descRemainderLen - concatLen;
    if (0 >= descRemainderLen)
    {
        DB_PRINT("%s.%d Description text too long\n",
            __FUNCTION__, __LINE__);
        goto exit;
    }
    pDesc = pDesc + concatLen;

    /* Concatenate value of PCR indices */
    for (i = 0; i < pPcrSelection->sizeofSelect; i++)
    {
        if ( (sizeof(ubyte)*2 + 1) > descRemainderLen)
        {
            DB_PRINT("%s.%d Description text too long to append PCR selection values\n",
                __FUNCTION__, __LINE__);
            goto exit;
        }
        *pDesc++ = ' ';
        *pDesc++ = returnHexDigit(pPcrSelection->pcrSelect[i] >> 4);
        *pDesc++ = returnHexDigit(pPcrSelection->pcrSelect[i]);
        descRemainderLen = descRemainderLen - 3;
    }

exit:
    return (descMaxLen - descRemainderLen);
}


/*------------------------------------------------------------------*/
MSTATUS getPcrsPropertyDescription( TPM2_ALG_ID algId,
                                    TPMU_CAPABILITIES *pCapabilities,
                                    ubyte4 propertyIndex,
                                    ubyte** ppDescription
)
{
    MSTATUS status = OK;
    ubyte *pAlgName = NULL;
    ubyte4 concatLen = 0;
    ubyte *pDesc = NULL;
    ubyte4 descriptionLen = SMP_CAP_PROP_DESC_MAX_SIZE;
    TPMS_PCR_SELECTION *pPcrSelection = NULL;

    status = DIGI_CALLOC((void**) ppDescription, descriptionLen+1,
                        sizeof(ubyte));
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for Property description, "
                "status = %d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

    status = getAlgName(algId, &pAlgName);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to get algorithm name for algorithm-id = %d, "
                "status = %d\n", __FUNCTION__, __LINE__, algId, status);
        goto exit;
    }

    pDesc = *ppDescription;
    /* Concatenate title 'Algorithm' */
    concatLen = DIGI_STRCBCPY((sbyte*)(pDesc), descriptionLen,
                            (sbyte*)"Algorithm: ");
    descriptionLen = descriptionLen - concatLen;
    if (0 >= descriptionLen)
    {
        DB_PRINT("%s.%d Description text too long, "
                "status = %d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }
    pDesc = pDesc + concatLen;

    /* Concatenate Algorithm name */
    concatLen = DIGI_STRCBCPY((sbyte*)(pDesc), descriptionLen, (sbyte*)pAlgName);
    descriptionLen = descriptionLen - concatLen;
    if (0 >= descriptionLen)
    {
        DB_PRINT("%s.%d Description text too long, "
                "status = %d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }
    pDesc = pDesc + concatLen;

    /* Concatenate Algorithm value */
    pPcrSelection = &(pCapabilities->assignedPCR.pcrSelections[propertyIndex]);
    concatLen = setPcrValues(pDesc, descriptionLen, pPcrSelection);
    descriptionLen = descriptionLen - concatLen;
    pDesc = pDesc + concatLen;

exit:
    if (OK != status && NULL != *ppDescription)
    {
        DIGI_FREE((void**)ppDescription);
    }
    return status;
}

/*------------------------------------------------------------------*/
static MSTATUS setCapPropertyDescription(
                TAP_Buffer * pPropertyDescBuffer,
                TPM2_PT property,
                ubyte4 propertyValue,
                TPMU_CAPABILITIES *pCapabilities,
                ubyte4 propertyIndex,
                TAP_MODULE_CAP_CAP_T capability)
{
    MSTATUS status = OK;
    ubyte* pDescriptionText = NULL;
    ubyte4 descTextLen = 0;

    if (NULL == pPropertyDescBuffer)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    switch (capability)
    {
    case TPM2_CAP_TPM_PROPERTIES:
        status = getTpmPropertyDescription(property, &pDescriptionText);
        break;
    case TPM2_CAP_ALGS:
        status = getAlgsPropertyDescription(property, propertyValue, &pDescriptionText);
        break;
    case TPM2_CAP_PCRS:
        status = getPcrsPropertyDescription(property, pCapabilities,
                                propertyIndex, &pDescriptionText);
        break;
    case TPM2_CAP_ECC_CURVES:
        status = getEccCurvePropertyDescription(pCapabilities, propertyIndex,
                            &pDescriptionText);
        break;
    default:
        descTextLen = DIGI_STRLEN((const sbyte*) SMP_CAP_PROP_DEFAULT_DESC);
        status = DIGI_CALLOC((void**) &pDescriptionText, descTextLen + 1,
                            sizeof(*pDescriptionText));
        if (OK == status)
        {
            status = DIGI_MEMCPY(pDescriptionText, SMP_CAP_PROP_DEFAULT_DESC, descTextLen);
        }
        break;
    }
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to get property description, status = %d\n",
            __FUNCTION__, __LINE__, status);
        goto exit;
    }

    descTextLen = DIGI_STRLEN((const sbyte*) pDescriptionText);
    status = DIGI_CALLOC((void **)&(pPropertyDescBuffer->pBuffer),
                descTextLen+1,
                sizeof(*(pPropertyDescBuffer->pBuffer)));
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for Property description, status = %d\n",
            __FUNCTION__, __LINE__, status);
        goto exit;
    }

    status = DIGI_MEMCPY(pPropertyDescBuffer->pBuffer,
                    pDescriptionText, descTextLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to copy Property description, status = %d\n",
            __FUNCTION__, __LINE__, status);
        goto exit;
    }
    pPropertyDescBuffer->bufferLen = descTextLen + 1;

exit:
    if (OK != status)
    {
        if ( NULL != pPropertyDescBuffer &&
             NULL != pPropertyDescBuffer->pBuffer)
        {
            DIGI_FREE((void **)&(pPropertyDescBuffer->pBuffer));
            pPropertyDescBuffer->bufferLen = 0;
        }
    }
    if (NULL != pDescriptionText)
    {
        DIGI_FREE((void**)&pDescriptionText);
    }
    return status;
}

/*------------------------------------------------------------------*/
static MSTATUS copyTpmPropertyListValues(
    TPMU_CAPABILITIES *pCapabilities, /* source */
    TAP_ModuleCapPropertyList *pCapPropertyList, /* destination */
    TAP_MODULE_CAP_CAP_T capability
)
{
    MSTATUS status = OK;
    ubyte4 count = 0;
    ubyte4 i = 0;
    TAP_ModuleCapProperty *propertyIter = NULL;
    ubyte4 propertyValLen = 0;
    ubyte4 propertyValue = 0;
    TPML_TAGGED_TPM_PROPERTY *pTpmProperties = (TPML_TAGGED_TPM_PROPERTY *)pCapabilities;
    count = pTpmProperties->count;
    if (0 == count)
    {
        goto exit;
    }

    status = DIGI_CALLOC((void **)&(pCapPropertyList->pPropertyList),
        count, sizeof(*pCapPropertyList->pPropertyList));
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for Property list, status = %d\n",
            __FUNCTION__, __LINE__, status);
        goto exit;
    }
    pCapPropertyList->numProperties = count;

    for (i = 0; i < count; i++)
    {
        propertyIter = pCapPropertyList->pPropertyList + i;
        /* copy property index */
        propertyIter->propertyId = pTpmProperties->tpmProperty[i].property;

        /* copy property value */
        propertyValLen = sizeof(pTpmProperties->tpmProperty[i].value);
        propertyIter->propertyValue.bufferLen = propertyValLen;
        status = DIGI_CALLOC((void **)&(propertyIter->propertyValue.pBuffer),
            propertyValLen,
            sizeof(*propertyIter->propertyValue.pBuffer));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed copying property value, error = %d\n",
                __FUNCTION__, __LINE__, status);
            goto exit;
        }
        propertyValue = DIGI_NTOHL((ubyte *)&(pTpmProperties->tpmProperty[i].value));
        status = DIGI_MEMCPY(propertyIter->propertyValue.pBuffer,
            &propertyValue,
            propertyValLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed copying property value, error = %d\n",
                __FUNCTION__, __LINE__, status);
            goto exit;
        }

        /* Get and save a description text buffer corresponding to the property */
        status = setCapPropertyDescription(&(propertyIter->propertyDescription),
                                    propertyIter->propertyId, propertyValue,
                                    pCapabilities, i,capability);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed copying property description, error = %d\n",
                __FUNCTION__, __LINE__, status);
            goto exit;
        }
    }
exit:
    return status;
}

/*------------------------------------------------------------------*/
static MSTATUS copyAlgsPropertyListValues(
    TPMU_CAPABILITIES *pCapabilities, /* source */
    TAP_ModuleCapPropertyList *pCapPropertyList, /* destination */
    TAP_MODULE_CAP_CAP_T capability
)
{
    MSTATUS status = OK;
    ubyte4 count = 0;
    ubyte4 i = 0;
    TAP_ModuleCapProperty *propertyIter = NULL;
    ubyte4 propertyValLen = 0;
    ubyte4 propertyValue = 0;
    TPML_ALG_PROPERTY *pAlgProperties = (TPML_ALG_PROPERTY *)pCapabilities;

    count = pAlgProperties->count;
    if (0 == count)
    {
        goto exit;
    }

    status = DIGI_CALLOC((void **)&(pCapPropertyList->pPropertyList),
        count, sizeof(*pCapPropertyList->pPropertyList));
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for Property list, status = %d\n",
            __FUNCTION__, __LINE__, status);
        goto exit;
    }
    pCapPropertyList->numProperties = count;

    for (i = 0; i < count; i++)
    {
        propertyIter = pCapPropertyList->pPropertyList + i;
        /* copy property index */
        propertyIter->propertyId = pAlgProperties->algProperties[i].alg;

        /* copy property value */
        propertyValLen = sizeof(pAlgProperties->algProperties[i].algProperties);
        propertyIter->propertyValue.bufferLen = propertyValLen;
        status = DIGI_CALLOC((void **)&(propertyIter->propertyValue.pBuffer),
            propertyValLen,
            sizeof(*propertyIter->propertyValue.pBuffer));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed copying property value, error = %d\n",
                __FUNCTION__, __LINE__, status);
            goto exit;
        }
        propertyValue = pAlgProperties->algProperties[i].algProperties;
        status = DIGI_MEMCPY(propertyIter->propertyValue.pBuffer,
            &propertyValue,
            propertyValLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed copying property value, error = %d\n",
                __FUNCTION__, __LINE__, status);
            goto exit;
        }

        /* Get and save a description text buffer corresponding to the property */
        status = setCapPropertyDescription(&(propertyIter->propertyDescription),
                            propertyIter->propertyId, propertyValue,
                            pCapabilities, i, capability);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed copying property description, error = %d\n",
                __FUNCTION__, __LINE__, status);
            goto exit;
        }
    }
exit:
    return status;
}

/*------------------------------------------------------------------*/
static MSTATUS copyHandlesPropertyListValues(
                TPMU_CAPABILITIES *pCapabilities, /* source */
                TAP_ModuleCapPropertyList *pCapPropertyList, /* destination */
                TAP_MODULE_CAP_CAP_T capability
)
{
    MSTATUS status = OK;
    ubyte4 count = 0;
    ubyte4 i = 0;
    TAP_ModuleCapProperty *propertyIter = NULL;
    TPML_HANDLE *pHandles = (TPML_HANDLE *)pCapabilities;

    count = pHandles->count;
    if (0 == count)
    {
        goto exit;
    }

    status = DIGI_CALLOC((void **)&(pCapPropertyList->pPropertyList),
        count, sizeof(*pCapPropertyList->pPropertyList));
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for Handles list, status = %d\n",
            __FUNCTION__, __LINE__, status);
        goto exit;
    }
    pCapPropertyList->numProperties = count;

    for (i = 0; i < count; i++)
    {
        propertyIter = pCapPropertyList->pPropertyList + i;
        /* copy handle value to property index */
        propertyIter->propertyId = pHandles->handle[i];

        /* No property value for HANDLES */
        propertyIter->propertyValue.pBuffer = NULL;
        propertyIter->propertyValue.bufferLen = 0;

        /* No property descriptionfor HANDLES */
        propertyIter->propertyDescription.pBuffer = NULL;
        propertyIter->propertyDescription.bufferLen = 0;
    }
exit:
    return status;
}

/*------------------------------------------------------------------*/
static MSTATUS copyEccCurvePropertyListValues(
    TPMU_CAPABILITIES *pCapabilities, /* source */
    TAP_ModuleCapPropertyList *pCapPropertyList, /* destination */
    TAP_MODULE_CAP_CAP_T capability
)
{
    MSTATUS status = OK;
    ubyte4 count = 0;
    ubyte4 i = 0;
    TAP_ModuleCapProperty *propertyIter = NULL;
    ubyte4 propertyValue = 0;
    TPML_ECC_CURVE *pEccCurves = &(pCapabilities->eccCurves);

    count = pEccCurves->count;
    if (0 == count)
    {
        goto exit;
    }

    status = DIGI_CALLOC((void **)&(pCapPropertyList->pPropertyList),
        count, sizeof(*pCapPropertyList->pPropertyList));
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for Handles list, status = %d\n",
            __FUNCTION__, __LINE__, status);
        goto exit;
    }
    pCapPropertyList->numProperties = count;

    for (i = 0; i < count; i++)
    {
        propertyIter = pCapPropertyList->pPropertyList + i;
        /* copy ALG ID to property index */
        propertyIter->propertyId = pEccCurves->eccCurves[i];

        /* No property value for ECC curves */
        propertyIter->propertyValue.pBuffer = NULL;
        propertyIter->propertyValue.bufferLen = 0;

        /* Get description */
        status = setCapPropertyDescription(&(propertyIter->propertyDescription),
				propertyIter->propertyId, propertyValue,
				pCapabilities, i, capability);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed copying property description, error = %d\n",
                __FUNCTION__, __LINE__, status);
            goto exit;
        }
    }
exit:

    return status;
}

/*------------------------------------------------------------------*/
static MSTATUS copyPcrsPropertyListValues(
    TPMU_CAPABILITIES *pCapabilities, /* source */
    TAP_ModuleCapPropertyList *pCapPropertyList, /* destination */
    TAP_MODULE_CAP_CAP_T capability
)
{
    MSTATUS status = OK;
    ubyte4 count = 0;
    ubyte4 i = 0;
    TAP_ModuleCapProperty *propertyIter = NULL;
    TPML_PCR_SELECTION *pAssignedPcrs = (TPML_PCR_SELECTION *)pCapabilities;

    count = pAssignedPcrs->count;
    if (0 == count)
    {
        goto exit;
    }

    status = DIGI_CALLOC((void **)&(pCapPropertyList->pPropertyList),
        count, sizeof(*pCapPropertyList->pPropertyList));
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for Property list, status = %d\n",
            __FUNCTION__, __LINE__, status);
        goto exit;
    }
    pCapPropertyList->numProperties = count;

    for (i = 0; i < count; i++)
    {
        propertyIter = pCapPropertyList->pPropertyList + i;

        /* copy property index */
        propertyIter->propertyId = pAssignedPcrs->pcrSelections[i].hash;

        /* No property value for PCR selection */
        propertyIter->propertyValue.bufferLen = 0;
        propertyIter->propertyValue.pBuffer = NULL;

        /* Get and save a description text buffer corresponding to the property */
        status = setCapPropertyDescription(&(propertyIter->propertyDescription), propertyIter->propertyId, 0, pCapabilities, i, capability);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed copying property description, error = %d\n",
                __FUNCTION__, __LINE__, status);
            goto exit;
        }
    }
exit:
    return status;
}

/*------------------------------------------------------------------*/
static MSTATUS copyPropertyListValues(
        TPMU_CAPABILITIES *pCapabilities, /* source */
        TAP_ModuleCapPropertyList *pCapPropertyList, /* destination */
        TAP_MODULE_CAP_CAP_T capability
    )
{
    MSTATUS status = OK;

    if (NULL == pCapabilities || NULL == pCapPropertyList)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    switch (capability)
    {
    case TPM2_CAP_ALGS:
        status = copyAlgsPropertyListValues(pCapabilities, pCapPropertyList, capability);
        break;
    case TPM2_CAP_HANDLES:
        status = copyHandlesPropertyListValues(pCapabilities, pCapPropertyList, capability);
        break;
    case TPM2_CAP_PCRS:
        status = copyPcrsPropertyListValues(pCapabilities, pCapPropertyList, capability);
        break;
    case TPM2_CAP_ECC_CURVES:
        status = copyEccCurvePropertyListValues(pCapabilities, pCapPropertyList, capability);
        break;
    case TPM2_CAP_TPM_PROPERTIES:
    default:
        status = copyTpmPropertyListValues(pCapabilities,
            pCapPropertyList,
            capability);
        break;
    }
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed reading properties output for capability - %d\n",
            __FUNCTION__, __LINE__, capability);
        goto exit;
    }

exit:

    return status;
}

/*------------------------------------------------------------------*/
ubyte4 getMaxPropertiesCount(TAP_MODULE_CAP_CAP_T capability)
{
    ubyte4 propertyCount = 0;
    switch (capability)
    {
    case TPM2_CAP_ALGS:
        propertyCount = TPM2_MAX_CAP_ALGS;
        break;
    case TPM2_CAP_HANDLES:
        propertyCount = TPM2_MAX_CAP_HANDLES;
        break;
    case TPM2_CAP_COMMANDS:
    case TPM2_CAP_PP_COMMANDS:
    case TPM2_CAP_AUDIT_COMMANDS:
        propertyCount = TPM2_MAX_CAP_CC;
        break;
    case TPM2_CAP_PCRS:
        propertyCount = TPM2_MAX_PCRS;
        break;
    case TPM2_CAP_TPM_PROPERTIES:
        propertyCount = TPM2_MAX_TPM_PROPERTIES;
        break;
    case TPM2_CAP_PCR_PROPERTIES:
        propertyCount = TPM2_MAX_PCR_PROPERTIES;
        break;
    case TPM2_CAP_ECC_CURVES:
        propertyCount = TPM2_MAX_ECC_CURVES;
        break;
    default:
        propertyCount = 64;
        break;
    }
    return propertyCount;
}

/*------------------------------------------------------------------*/
byteBoolean verifyCapabilitySupport(TAP_MODULE_CAP_CAP_T capability)
{
    byteBoolean isSupported = TRUE;

    switch (capability)
    {
    case TPM2_CAP_ALGS:
    case TPM2_CAP_HANDLES:
    case TPM2_CAP_PCRS:
    case TPM2_CAP_TPM_PROPERTIES:
    case TPM2_CAP_ECC_CURVES:
        isSupported = TRUE;
        break;

    case TPM2_CAP_COMMANDS:
    case TPM2_CAP_PP_COMMANDS:
    case TPM2_CAP_AUDIT_COMMANDS:
    case TPM2_CAP_PCR_PROPERTIES:
    default:
        /* TODO - to add support for these capabilities */
        isSupported = FALSE;
        break;
    }

    return isSupported;
}

/*------------------------------------------------------------------*/
MSTATUS SMP_API(TPM2, getCapability,
        TAP_ModuleId moduleId,
        TAP_ModuleCapPropertyAttributes *pCapPropertySelectCriterion,
        TAP_ModuleCapPropertyList *pModuleCapProperties
)
{
    MSTATUS status = OK;
    FAPI2_CONTEXT *pFapiContext = NULL;
    TPM2_MODULE_CONFIG_SECTION *pModuleConfig = NULL;
    byteBoolean moduleLocked = FALSE;
    MgmtCapabilityIn capIn = { 0 };
    MgmtCapabilityOut capOut = { 0 };
    TAP_MODULE_CAP_PROPERTY_TAG property = 0;
    TAP_MODULE_CAP_CAP_T capability = TPM2_CAP_TPM_PROPERTIES;
    ubyte4 propertyCount = 0;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TAP_Attribute *pSelectAttribute = NULL;
    ubyte4 i = 0;

    if (NULL == pModuleCapProperties)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input pModuleCapabilities = %p\n",
            __FUNCTION__, __LINE__, pModuleCapProperties);
        goto exit;
    }

    /* Check against configured moduleId's */
    pModuleConfig = pgConfig;
    while (pModuleConfig)
    {
        if (moduleId == pModuleConfig->moduleId)
            break;

        pModuleConfig = pModuleConfig->pNext;
    }
    if (!pModuleConfig)
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Invalid module id %d\n",
            __FUNCTION__, __LINE__, moduleId);
        goto exit;
    }

    status = RTOS_mutexWait(pModuleConfig->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Wait on Mutex failed with error= %d\n",
            __FUNCTION__, __LINE__, status);
        goto exit;
    }
    moduleLocked = TRUE;

    /* read selection parameter if present, else use default */
    if (NULL != pCapPropertySelectCriterion &&
        NULL != pCapPropertySelectCriterion->pAttributeList)
    {
        for (i = 0; i < pCapPropertySelectCriterion->listLen; i++)
        {
            pSelectAttribute = pCapPropertySelectCriterion->pAttributeList + i;
            switch (pSelectAttribute->type)
            {
                /* Read capability value */
            case TAP_ATTR_GET_CAP_CAPABILITY:
                if ((sizeof(TAP_MODULE_CAP_CAP_T) != pSelectAttribute->length)
                    || (NULL == pSelectAttribute->pStructOfType))
                {
                    status = ERR_INVALID_ARG;
                    DB_PRINT("%s.%d Invalid capability length %d, "
                        "pStructOfType = %p\n",
                        __FUNCTION__, __LINE__, pSelectAttribute->length,
                        pSelectAttribute->pStructOfType);
                    goto exit;
                }
                capability = *((TAP_MODULE_CAP_CAP_T *)pSelectAttribute->pStructOfType);
                if (FALSE == verifyCapabilitySupport(capability))
                {
                    status = ERR_TAP_UNSUPPORTED;
                    DB_PRINT("%s.%d Unsupported capability %d, "
                            "status = %d\n",
                            __FUNCTION__, __LINE__, (int)capability,
                            (int)status);
                    goto exit;
                }
                break;

                /* Read first property tag */
            case TAP_ATTR_GET_CAP_PROPERTY:
                if ((sizeof(TAP_MODULE_CAP_PROPERTY_TAG) != pSelectAttribute->length) ||
                    (NULL == pSelectAttribute->pStructOfType))
                {
                    status = ERR_INVALID_ARG;
                    DB_PRINT("%s.%d Invalid property selection length %d, "
                        "pStructOfType = %p\n",
                        __FUNCTION__, __LINE__, pSelectAttribute->length,
                        pSelectAttribute->pStructOfType);
                    goto exit;
                }
                property = *((TAP_MODULE_CAP_PROPERTY_TAG *)pSelectAttribute->pStructOfType);
                break;

                /* Read property count tag */
            case TAP_ATTR_GET_CAP_PROPERTY_COUNT:
                if ((sizeof(ubyte4) != pSelectAttribute->length) ||
                    (NULL == pSelectAttribute->pStructOfType))
                {
                    status = ERR_INVALID_ARG;
                    DB_PRINT("%s.%d Invalid property count length %d, "
                        "pStructOfType = %p\n",
                        __FUNCTION__, __LINE__, pSelectAttribute->length,
                        pSelectAttribute->pStructOfType);
                    goto exit;
                }
                propertyCount = *((ubyte4 *)pSelectAttribute->pStructOfType);
                break;
            default:
                DB_PRINT("%s.%d Invalid attribute type in property selection",
                    __FUNCTION__, __LINE__);
                goto exit;
            }
        }
    }

    if (0 == propertyCount)
    {
        propertyCount = getMaxPropertiesCount(capability);
        DB_PRINT("%s.%d property count value not specified, Attempting to fetch all.\n",
            __FUNCTION__, __LINE__);
    }

    /* Init module */
    rc = FAPI2_CONTEXT_init(&pFapiContext,
        pModuleConfig->moduleName.bufferLen,
        pModuleConfig->moduleName.pBuffer,
        pModuleConfig->modulePort,
        8, NULL);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d FAPI2 Context init error, rc = 0x%02x\n",
            __FUNCTION__, __LINE__, rc);
        goto exit;
    }

    /* Get Module Capabilities */
    capIn.capability = capability;
    capIn.property = property;
    capIn.propertyCount = propertyCount;
    rc = FAPI2_MGMT_getCapability(pFapiContext,
                &capIn, &capOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d FAPI2_MGMT_getCapability error, rc = %d\n",
                __FUNCTION__, __LINE__, rc);
        goto exit;
    }

    /* TODO - To verify if moreData check is needed. Note we have used the max property values from spec here when property-count is zero*/

    /* Set response properties list */
    status = copyPropertyListValues(&(capOut.capabilityData.data),
                                pModuleCapProperties, capability);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy tpmProperties into response structure, "
                "status = %d", __FUNCTION__, __LINE__, status);
        goto exit;
    }

exit:
    /* If FAPI CONTEXT initialized then uninitialize it regardless of status */
    if (NULL != pFapiContext)
    {
        rc = FAPI2_CONTEXT_uninit(&pFapiContext);
        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d FAPI2 Context uninit error, rc = 0x%02x\n",
                    __FUNCTION__, __LINE__, rc);
        }
    }

    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pModuleConfig->moduleMutex);

    return status;
}

#endif /*#ifdef __SMP_ENABLE_SMP_CC_GET_MODULE_CAPABILITY__*/

#ifdef __SMP_ENABLE_SMP_CC_GET_MODULE_SLOTS__
MSTATUS SMP_API(TPM2, getModuleSlots,
        TAP_ModuleHandle moduleHandle,
        TAP_ModuleSlotList *pModuleSlotList
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif
#ifdef __SMP_ENABLE_SMP_CC_GET_TOKEN_LIST__
MSTATUS SMP_API(TPM2, getTokenList,
        TAP_ModuleHandle moduleHandle,
        TAP_TOKEN_TYPE tokenType,
        TAP_TokenCapabilityAttributes  *pTokenAttributes,
        TAP_EntityList *pTokenIdList
)
{
    MSTATUS status = OK;
    TAP_Attribute *pAttribute = NULL;
    ubyte4 listCount = 0;
    TAP_TokenId selTokenId = 0;

    if ((0 == moduleHandle) || (NULL == pTokenIdList))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "pTokenIdList = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                pTokenIdList);
        goto exit;
    }

    if (pTokenAttributes && pTokenAttributes->listLen)
    {
        pAttribute = pTokenAttributes->pAttributeList;

        while (listCount < pTokenAttributes->listLen)
        {
            /* handle parameters we need */
            switch (pAttribute->type)
            {
                case TAP_ATTR_CAPABILITY_CATEGORY:
                case TAP_ATTR_CAPABILITY_FUNCTIONALITY:
                    if ((sizeof(TAP_CAPABILITY_FUNCTIONALITY) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid capability structure length %d, "
                                "pStructOfType = %p\n",
                                __FUNCTION__, __LINE__, pAttribute->length,
                                pAttribute->pStructOfType);
                        goto exit;
                    }

                    switch (*((TAP_CAPABILITY_FUNCTIONALITY *)pAttribute->pStructOfType))
                    {
                        case TAP_CAPABILITY_REMOTE_ATTESTATION:
                        case TAP_CAPABILITY_ATTESTATION_BASIC:
                            selTokenId = SMP_TPM2_ATTESTATION_TOKEN_ID;
                            break;

                        default:
                            break;
                    }
                    break;

                case TAP_ATTR_KEY_USAGE:
                    if ((sizeof(TAP_KEY_USAGE) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key-usage structure length %d, "
                                "pStructOfType = %p\n",
                                __FUNCTION__, __LINE__, pAttribute->length,
                                pAttribute->pStructOfType);
                        goto exit;
                    }

                    switch (*((TAP_KEY_USAGE *)pAttribute->pStructOfType))
                    {
                        case TAP_KEY_USAGE_SIGNING:
                        case TAP_KEY_USAGE_DECRYPT:
                        case TAP_KEY_USAGE_GENERAL:
                            selTokenId = SMP_TPM2_CRYPTO_TOKEN_ID;
                            break;

                        case TAP_KEY_USAGE_ATTESTATION:
                            selTokenId = SMP_TPM2_ATTESTATION_TOKEN_ID;
                            break;

                        default:
                            break;
                    }
                    break;

                default:
                    break;
            }

            pAttribute++;
            listCount++;
        }
    }

    pTokenIdList->entityType = TAP_ENTITY_TYPE_TOKEN;
    pTokenIdList->entityIdList.numEntities = selTokenId ? 1 : 2;

    status = DIGI_CALLOC((void **)&(pTokenIdList->entityIdList.pEntityIdList),
            1, sizeof(*pTokenIdList->entityIdList.pEntityIdList) *
            pTokenIdList->entityIdList.numEntities);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for Token list, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    if (selTokenId)
    {
        pTokenIdList->entityIdList.pEntityIdList[0] = selTokenId;
    }
    else
    {
        pTokenIdList->entityIdList.pEntityIdList[0] = SMP_TPM2_CRYPTO_TOKEN_ID;
        pTokenIdList->entityIdList.pEntityIdList[1] = SMP_TPM2_ATTESTATION_TOKEN_ID;
    }

exit:
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_TOKEN_INFO__
MSTATUS SMP_API(TPM2, getTokenInfo,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenType tokenType,
        TAP_TokenId tokenId,
        TAP_TokenCapabilityAttributes *pCapabiltySelectAttributes,
        TAP_TokenCapabilityAttributes  *pTokenCapabilities
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif
#ifdef __SMP_ENABLE_SMP_CC_GET_OBJECT_LIST__

MSTATUS SMP_API(TPM2, getObjectList,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_EntityList *pObjectIdList
)
{
    MSTATUS status = OK;
    SMP_Context *pSmpContext = NULL;

    if ((0 == moduleHandle) || (NULL == pObjectIdList))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input, moduleHandle = %p, "
                "pObjectIdList = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                pObjectIdList);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Wait on Mutex handle %p failed with error= %d\n",
                __FUNCTION__, __LINE__, pSmpContext, status);
        goto exit;
    }

    status = TPM2_getAllProvisionedIds(pSmpContext, pObjectIdList);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed retrieving all provisioned ids\n",
                __FUNCTION__, __LINE__);
    }

    RTOS_mutexRelease(pSmpContext->moduleMutex);
exit:

    return status;
}
#endif
#ifdef __SMP_ENABLE_SMP_CC_GET_OBJECT_INFO__
MSTATUS SMP_API(TPM2, getObjectInfo,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectId objectId,
        TAP_ObjectCapabilityAttributes *pCapabiltySelectAttributes,
        TAP_ObjectCapabilityAttributes *pObjectCapabilities
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif
#if (defined __SMP_ENABLE_SMP_CC_PROVISION_MODULE__) || \
    (defined __SMP_ENABLE_SMP_CC_RESET_MODULE__) || \
    (defined __SMP_ENABLE_SMP_CC_INIT_MODULE__)
static int TPM2_parseCredential(TAP_Credential *pObjCredential,
        TPM2B_AUTH *pAuth)
{
    int rc = 0;
    MSTATUS status = OK;

    if (TAP_CREDENTIAL_CONTEXT_ENTITY == pObjCredential->credentialContext)
    {
        if (TAP_CREDENTIAL_FORMAT_PLAINTEXT ==
                pObjCredential->credentialFormat)
        {
            if (pObjCredential->credentialData.bufferLen
                    && (NULL != pObjCredential->credentialData.pBuffer))
            {
                if (sizeof (pAuth->buffer) <
                        pObjCredential->credentialData.bufferLen)
                {
                    DB_PRINT("%s.%d Insufficient buffer size\n",
                        __FUNCTION__, __LINE__);
                    goto exit;
                }

                status = DIGI_MEMCPY(pAuth->buffer,
                        pObjCredential->credentialData.pBuffer,
                        pObjCredential->credentialData.bufferLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed copying auth buffer. status = %d\n",
                        __FUNCTION__, __LINE__, status);
                    goto exit;
                }

                pAuth->size = pObjCredential->credentialData.bufferLen;

                rc = 1;
                goto exit;
            }
        }
        else
        {
            DB_PRINT("%s.%d Unsupported credential format - %d\n",
                    __FUNCTION__, __LINE__, pObjCredential->credentialFormat);
            goto exit;
        }
    }

exit:
    return rc;
}

static int TPM2_parseCredentialList(TAP_CredentialList *pCredentialList,
        TPM2B_AUTH *pAuth)
{
    int rc = 0;
    ubyte4 objCredentialCount = 0;
    TAP_Credential *pObjCredential = NULL;

    objCredentialCount = 0;
    pObjCredential = pCredentialList->pCredentialList;
    while (objCredentialCount < pCredentialList->numCredentials)
    {
        if ((rc = TPM2_parseCredential(pObjCredential, pAuth)))
        {
            goto exit;
        }

        pObjCredential++;
        objCredentialCount++;
    }

exit:
    return rc;
}

static int TPM2_getEntityCredentials(TAP_EntityCredentialList *pCredentials,
        TAP_ENTITY_TYPE entityType, TAP_EntityId entityId, TAP_EntityId parentId,
        TPM2B_AUTH *pAuth)
{
    int rc = 0;
    ubyte4 entityCredentialCount = 0;
    TAP_EntityCredential *pEntityCredentials = NULL;

    if (NULL == pAuth)
    {
        DB_PRINT("%s.%d NULL pointer on input, pAuth= %p\n",
                __FUNCTION__, __LINE__, pAuth);
        goto exit;
    }

    pAuth->size = 0;
    if (pCredentials && pCredentials->numCredentials)
    {
        pEntityCredentials = pCredentials->pEntityCredentials;

        entityCredentialCount = 0;
        while (entityCredentialCount < pCredentials->numCredentials)
        {
            if ((entityType == pEntityCredentials->entityType) &&
                    ((entityId == pEntityCredentials->entityId) ||
                     !entityId))
            {
                if (!parentId || (parentId == pEntityCredentials->parentId))
                {
                    if ((rc = TPM2_parseCredentialList(
                                    &pEntityCredentials->credentialList,
                                    pAuth)))
                        goto exit;
                }
            }

            pEntityCredentials++;
            entityCredentialCount++;
        }
    }

exit:
    return rc;
}

/* Method returns 1 on success, 0 on error */
static int TPM2_getCredentialsList(TAP_CredentialList *pCredentials,
        TAP_CREDENTIAL_TYPE credentialType, TPM2B_AUTH *pAuth)
{
    int rc = 0;
    ubyte4 entityCredentialCount = 0;
    TAP_Credential *pCredential = NULL;

    if (NULL == pAuth)
    {
        DB_PRINT("%s.%d NULL pointer on input, pAuth= %p\n",
                __FUNCTION__, __LINE__, pAuth);
        goto exit;
    }

    pAuth->size = 0;
    if (pCredentials && pCredentials->numCredentials)
    {
        entityCredentialCount = 0;
        while (entityCredentialCount < pCredentials->numCredentials)
        {
            pCredential = pCredentials->pCredentialList + entityCredentialCount;
            if (credentialType == pCredential->credentialType)
            {
                    if ( (rc = TPM2_parseCredential(pCredential,pAuth)) )
                    {
                        goto exit;
                    }
            }

            entityCredentialCount++;
        }
    }
    else /* it is ok to have empty credential list, just means pAuth doesn't get set */
    {
        rc = 1;
    }

exit:
    return rc;
}

static MSTATUS TPM2_getHierarchyAuth(TPM2B_AUTH *pAuth, TAP_ENTITY_TYPE entityType,
        TAP_EntityId entityId, TAP_EntityId parentId,
        TAP_ModuleProvisionAttributes *pModuleProvisionAttributes)
{
    MSTATUS status = OK;
    TAP_Attribute *pAttribute = NULL;
    ubyte4 listCount = 0;
    TAP_EntityCredentialList *pEntityCredentialList = NULL;
    byteBoolean authValueFound = FALSE;

    if (NULL == pAuth)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, pAuth= %p\n",
                __FUNCTION__, __LINE__, pAuth);
        goto exit;
    }

    /* Get the credentials */
    if (pModuleProvisionAttributes &&
        (pModuleProvisionAttributes->listLen))
    {
        pAttribute = pModuleProvisionAttributes->pAttributeList;

        while ((listCount < pModuleProvisionAttributes->listLen) &&
            (FALSE == authValueFound))
        {
            switch (pAttribute->type)
            {
                case TAP_ATTR_CREDENTIAL_USAGE:
                case TAP_ATTR_CREDENTIAL_SET:
                case TAP_ATTR_ENTITY_CREDENTIAL:
                    pEntityCredentialList =
                        (TAP_EntityCredentialList *)pAttribute->pStructOfType;

                    if (TPM2_getEntityCredentials(
                            (TAP_EntityCredentialList *)pAttribute->pStructOfType,
                            entityType, entityId, parentId, pAuth))
                    {
                        authValueFound = TRUE;
                    }
                    break;

                default:
                    break;
            }

            pAttribute++;
            listCount++;
        }
    }

exit:
    return status;
}

#endif

#ifdef __SMP_ENABLE_SMP_CC_PROVISION_MODULE__

MSTATUS SMP_API(TPM2, provisionModule,
        TAP_ModuleHandle moduleHandle,
        TAP_ModuleProvisionAttributes *pModuleProvisionAttributes
)
{
    MSTATUS status = OK;
    SMP_Context *pSmpContext = NULL;
    AdminTakeOwnershipIn takeOwnershipIn = {0};
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    byteBoolean moduleLocked = FALSE;

    if ((0 == moduleHandle) || (NULL == pModuleProvisionAttributes))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "pModuleProvisionAttributes = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                pModuleProvisionAttributes);
        return status;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting on module mutex for module - %p\n",
                __FUNCTION__, __LINE__, moduleHandle);
        goto exit;
    }
    moduleLocked = TRUE;

    /* This must set the lockout hierarchy password */
    status = TPM2_getHierarchyAuth(&pSmpContext->lockoutAuth,
            TAP_ENTITY_TYPE_MODULE, 0, 0,
            pModuleProvisionAttributes);

    if (OK != status)
    {
        DB_PRINT("%s.%d Error, Lockout hierarchy password must be passed in as attribute\n",
                __FUNCTION__, __LINE__);
    }
    else
    {
        if (pSmpContext->lockoutAuth.size)
        {
            /* Set lockout hierarchy password */
            takeOwnershipIn.newLockOutAuth = pSmpContext->lockoutAuth;

            rc = FAPI2_ADMIN_takeOwnership(pSmpContext->pFapiContext,
                    &takeOwnershipIn);
            if (TSS2_RC_SUCCESS != rc)
            {
                status = SMP_TPM2_UTILS_getMocanaError(rc);
                DB_PRINT("%s.%d FAPI2 take ownership error, rc = 0x%02x\n",
                        __FUNCTION__, __LINE__, rc);
            }
        }
        else
        {
            DB_PRINT("%s.%d Error, Lockout hierarchy password must be passed in as attribute\n",
                    __FUNCTION__, __LINE__);
            status = ERR_INVALID_ARG;
        }
    }

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);
    return status;
}
#endif
#ifdef __SMP_ENABLE_SMP_CC_RESET_MODULE__
MSTATUS SMP_API(TPM2, resetModule,
        TAP_ModuleHandle moduleHandle,
        TAP_ModuleProvisionAttributes *pModuleProvisionAttributes
)
{
    MSTATUS status = OK;
    SMP_Context *pSmpContext = NULL;
    ContextSetHierarchyAuthIn hierarchyAuthIn = {0};
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    byteBoolean moduleLocked = FALSE;

    if (0 == moduleHandle)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p, "
                "pModuleProvisionAttributes = %p\n",
                __FUNCTION__, __LINE__, moduleHandle, pModuleProvisionAttributes);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting on module mutex for module - %p\n",
                __FUNCTION__, __LINE__, moduleHandle);
        goto exit;
    }
    moduleLocked = TRUE;

    hierarchyAuthIn.lockoutAuth = pSmpContext->lockoutAuth;
    rc = FAPI2_CONTEXT_setHierarchyAuth(pSmpContext->pFapiContext,
            &hierarchyAuthIn);

    /* This translates to FAPI2_ADMIN_releaseOwnership and
       FAPI2_ADMIN_takeOwnership. The API will use the old lockout password
       from the moduleHandle and set the new password */
    rc = FAPI2_ADMIN_releaseOwnership(pSmpContext->pFapiContext);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d FAPI2 releaseOwnership error, rc = 0x%02x\n",
                __FUNCTION__, __LINE__, rc);
    }

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);
    return status;
}
#endif
#ifdef __SMP_ENABLE_SMP_CC_PROVISION_TOKEN__
MSTATUS SMP_API(TPM2, provisionTokens,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenProvisionAttributes *pTokenProvisionAttributes,
        TAP_EntityList *pTokenIdList
)
{
    MSTATUS status = OK;
    SMP_Context *pSmpContext = NULL;
    AdminTakeOwnershipIn takeOwnershipIn = {0};
    AdminCreateSRKIn srkIn = { 0 };
    AdminCreateEKIn ekIn = { 0 };
    ContextGetPrimaryObjectNameIn objectNameIn = { 0 };
    ContextGetPrimaryObjectNameOut objectName = { 0 };
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2B_AUTH ownerAuth = {0};
    TPM2B_AUTH endorsementAuth = {0};
    TAP_Attribute *pAttribute = NULL;
    ubyte4 listCount = 0;
    TPMI_ALG_PUBLIC keyAlg = TPM2_ALG_RSA;
    byteBoolean moduleLocked = FALSE;

    if ((0 == moduleHandle) || (NULL == pTokenProvisionAttributes))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "pModuleProvisionAttributes = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                pTokenProvisionAttributes);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);

    /* Provision all tokens at the same time for TPM2 */
    status = TPM2_getHierarchyAuth(&ownerAuth, TAP_ENTITY_TYPE_TOKEN,
            TPM2_RH_OWNER_ID, 0,
            pTokenProvisionAttributes);

    if (OK != status)
    {
        DB_PRINT("%s.%d Error, Owner hierarchy password must be passed in as attribute\n",
                __FUNCTION__, __LINE__);
        goto exit;
    }
    /* Provision all tokens at the same time for TPM2 */
    status = TPM2_getHierarchyAuth(&endorsementAuth, TAP_ENTITY_TYPE_TOKEN,
            TPM2_RH_ENDORSEMENT_ID, 0,
            pTokenProvisionAttributes);

    if (OK != status)
    {
        DB_PRINT("%s.%d Error, Endorsement hierarchy password must be passed in as attribute\n",
                __FUNCTION__, __LINE__);
        goto exit;
    }

    /* Get SRK and EK algorithm */
    if (pTokenProvisionAttributes->listLen)
    {
        pAttribute = pTokenProvisionAttributes->pAttributeList;

        while (listCount < pTokenProvisionAttributes->listLen)
        {
            /* handle parameters we need */
            if (TAP_ATTR_KEY_ALGORITHM == pAttribute->type)
            {
                if ((sizeof(TAP_KEY_ALGORITHM) != pAttribute->length) ||
                        (NULL == pAttribute->pStructOfType))
                {
                    status = ERR_INVALID_ARG;
                    DB_PRINT("%s.%d Invalid key algorithm length %d, status = %d\n",
                        __FUNCTION__, __LINE__, pAttribute->length, status);
                    goto exit;
                }
                switch (*((TAP_KEY_ALGORITHM *)(pAttribute->pStructOfType)))
                {
                    case TAP_KEY_ALGORITHM_ECC:
                        keyAlg = TPM2_ALG_ECC;
                        break;

                    case TAP_KEY_ALGORITHM_RSA:
                    default:
                        keyAlg = TPM2_ALG_RSA;
                        break;
                }
            }

            pAttribute++;
            listCount++;
        }
    }
    takeOwnershipIn.newLockOutAuth = pSmpContext->lockoutAuth;
    takeOwnershipIn.newOwnerAuth = ownerAuth;
    takeOwnershipIn.newEndorsementAuth = endorsementAuth;

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting on module mutex for module - %p, status - %d\n",
                __FUNCTION__, __LINE__, moduleHandle, status);
        goto exit;
    }
    moduleLocked = TRUE;

    /* The passwords can be provided for hierarchies as well as
       primary keys(SRK, EK). This API should set the appropriate
       passwords and create the primary keys.
     */
    rc = FAPI2_ADMIN_takeOwnership(pSmpContext->pFapiContext,
            &takeOwnershipIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d FAPI2 take ownership error, rc = 0x%02x\n",
                __FUNCTION__, __LINE__, rc);
        goto exit;
    }

    status = TPM2_getHierarchyAuth(&ownerAuth,
            TAP_ENTITY_TYPE_OBJECT, 0, TPM2_RH_OWNER_ID,
            pTokenProvisionAttributes);

    if (OK != status)
    {
        DB_PRINT("%s.%d Error, SRK key password must be passed in as attribute\n",
                __FUNCTION__, __LINE__);
    }

    /*
     * Create SRK only if it does not already exist.
     */
    objectNameIn.persistentHandle = FAPI2_RH_SRK;
    rc = FAPI2_CONTEXT_getPrimaryObjectName(pSmpContext->pFapiContext,
            &objectNameIn, &objectName);
    if (TSS2_RC_SUCCESS != rc)
    {
        srkIn.SRKAuth = ownerAuth;
        srkIn.keyAlg = keyAlg;
        rc = FAPI2_ADMIN_createSRK(pSmpContext->pFapiContext, &srkIn);
        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d FAPI2 createSRK failed. rc = 0x%02x",
                    __FUNCTION__, __LINE__, (unsigned int)rc);
            goto exit;
        }
    }
    else
    {
        DB_PRINT("%s.%d SRK already created. Skipping SRK Creation\n",
                __FUNCTION__, __LINE__);
    }

    status = TPM2_getHierarchyAuth(&endorsementAuth,
            TAP_ENTITY_TYPE_OBJECT, 0, TPM2_RH_ENDORSEMENT_ID,
            pTokenProvisionAttributes);

    if (OK != status)
    {
        DB_PRINT("%s.%d Error, EK key password must be passed in as attribute\n",
                __FUNCTION__, __LINE__);
    }

    ekIn.isPrivacySensitive = TRUE;
    ekIn.keyAlg = keyAlg; /* Same key algorithm as SRK */
    ekIn.EKAuth = endorsementAuth;

    /*
     * Create EK only if it does not already exist.
     */
    objectNameIn.persistentHandle = FAPI2_RH_EK;
    rc = FAPI2_CONTEXT_getPrimaryObjectName(pSmpContext->pFapiContext,
            &objectNameIn, &objectName);
    if (TSS2_RC_SUCCESS != rc)
    {
        rc = FAPI2_ADMIN_createEK(pSmpContext->pFapiContext, &ekIn);
        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d FAPI2 createEK failed. rc = 0x%02x",
                    __FUNCTION__, __LINE__, (unsigned int)rc);
            goto exit;
        }
    }
    else
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d EK already created. Skipping EK Creation\n",
                __FUNCTION__, __LINE__);
    }

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    return status;
}
#endif

#ifdef __RTOS_WIN32__
#if defined (__SMP_ENABLE_SMP_CC_INIT_MODULE__)

static MSTATUS TPM2_getAuthFromTbs(TPM2B_AUTH *pAuth,
                        TAP_ENTITY_TYPE entityType,
                        TAP_EntityId entityId, TAP_EntityId parentId)
{
    MSTATUS status = OK;
    ubyte *pOwnerSecret = NULL;
    ubyte4 ownerSecretLen = 0;
    TPM2_TBS_OWNERAUTH_TYPE tbsOwnerAuthType = TPM2_TBS_OWNERAUTH_TYPE_OWNER_ADMIN;

    if (NULL == pAuth)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, pAuth= %p\n",
            __FUNCTION__, __LINE__, pAuth);
        goto exit;
    }

    switch(entityId)
    {
        case TPM2_RH_OWNER:
           tbsOwnerAuthType = TPM2_TBS_OWNERAUTH_TYPE_OWNER_ADMIN;
           break;

        case TPM2_RH_ENDORSEMENT:
           tbsOwnerAuthType = TPM2_TBS_OWNERAUTH_TYPE_ENDORSEMENT;
           break;

        case TPM2_RH_LOCKOUT:
           status = ERR_TAP_UNSUPPORTED;
           DB_PRINT("%s.%d Invalid entity-type = %d\n"
               __FUNCTION__, __LINE__, entityId);
           break;

        default:
           status = ERR_INVALID_ARG;
           DB_PRINT("%s.%d Invalid entity-type = %d\n"
               __FUNCTION__, __LINE__, entityId);
           break;
    }

    /* If entity-id is invalid then exit */
    if (OK != status)
    {
        goto exit;
    }

    /* Retrieve Owner authorization for TBS */
    status = TPM2_TBS_UTIL_GetOwnerAuth(tbsOwnerAuthType,
                                 &pOwnerSecret, &ownerSecretLen);
    if (OK != status)
    {
        goto exit;
    }

    pAuth->size = 0;
    if (sizeof (pAuth->buffer) < ownerSecretLen)
    {
        DB_PRINT("%s.%d Insufficient buffer size\n",
            __FUNCTION__, __LINE__);
        goto exit;
    }

    status = DIGI_MEMCPY(pAuth->buffer, pOwnerSecret, ownerSecretLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed copying auth buffer. status = %d\n",
            __FUNCTION__, __LINE__, status);
        goto exit;
    }

    pAuth->size = ownerSecretLen;

exit:
    if (NULL != pOwnerSecret)
        DIGI_FREE((void**)&pOwnerSecret);

    return status;
}

#endif
#endif /* __RTOS_WIN32__ */


#if defined (__SMP_ENABLE_SMP_CC_INIT_MODULE__)

static MSTATUS getOwnerHierarchyAuth(TAP_ModuleId moduleId,
                        TPM2B_AUTH *pAuth,
                        TAP_ModuleProvisionAttributes *pModuleAttribute)
{
    MSTATUS status = OK;
    byteBoolean isOwnerAuthRetrieved = FALSE;

    if (NULL == pAuth)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __RTOS_WIN32__
    /* For windows hardware, retrieve owner auth from TBS ONLY */
    if (TPM20_SECURITY_MODULE == getTPM2DeviceType(moduleId))
    {
        /* Get authorization corresponding to SRK for ownerAuth
         * i.e. TBS_OWNERAUTH_TYPE_STORAGE_20 */
        status = TPM2_getAuthFromTbs(pAuth, TAP_ENTITY_TYPE_TOKEN,
                                    TPM2_RH_OWNER, 0);
        if (OK != status)
        {
            DB_PRINT("%s.%d Info, Could not fetch Owner authorization from TBS, "
                    "status = %d\n", __FUNCTION__, __LINE__, status);
            goto exit;
        }
        isOwnerAuthRetrieved = TRUE;
    }
#endif /* __RTOS_WIN32__ */

    /* This should be true only for non-windows platform and
     * windows-emulator setting only */
    if (FALSE == isOwnerAuthRetrieved)
    {
        status = TPM2_getHierarchyAuth(pAuth, TAP_ENTITY_TYPE_TOKEN,
                                    TPM2_RH_OWNER, 0, pModuleAttribute);

        if (OK != status)
        {
            DB_PRINT("%s.%d Error, Owner hierarchy password must be passed in "
                    " as attribute\n", __FUNCTION__, __LINE__);
            goto exit;
        }
    }

exit:
    return status;
}

static MSTATUS getEndorsementHierarchyAuth(TAP_ModuleId moduleId,
                        TPM2B_AUTH *pAuth,
                        TAP_ModuleProvisionAttributes *pModuleAttribute)
{
    MSTATUS status = OK;
    byteBoolean isEndorsementAuthRetrieved = FALSE;

    if (NULL == pAuth)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __RTOS_WIN32__
    /* For windows hardware, retrieve owner auth from TBS ONLY */
    if (TPM20_SECURITY_MODULE == getTPM2DeviceType(moduleId))
    {
        status = TPM2_getAuthFromTbs(pAuth, TAP_ENTITY_TYPE_TOKEN,
                                            TPM2_RH_ENDORSEMENT, 0);
        if (OK != status)
        {
            DB_PRINT("%s.%d Info, Could not fetch Owner authorization type "
                    "endorsement from TBS, status = %d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }
        isEndorsementAuthRetrieved = TRUE;
    }
#endif /* __RTOS_WIN32__ */

    /* This should be true only for non-windows platform and
     * windows-emulator setting only */
    if (FALSE == isEndorsementAuthRetrieved)
    {
        status = TPM2_getHierarchyAuth(pAuth, TAP_ENTITY_TYPE_TOKEN,
                                    TPM2_RH_ENDORSEMENT, 0, pModuleAttribute);

        if (OK != status)
        {
            DB_PRINT("%s.%d Error, Endorsement hierarchy password must be passed in as attribute\n",
                    __FUNCTION__, __LINE__);
            goto exit;
        }
    }

exit:
    return status;
}

#endif /* defined (__SMP_ENABLE_SMP_CC_INIT_MODULE__) */


#ifdef __SMP_ENABLE_SMP_CC_INIT_MODULE__
MSTATUS SMP_API(TPM2, initModule,
        TAP_ModuleId moduleId,
        TAP_ModuleCapabilityAttributes *pModuleAttribute,
        TAP_CredentialList *pCredentials,
        TAP_ModuleHandle *pModuleHandle
)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    SMP_Context *pSmpContext = NULL;
    ContextSetHierarchyAuthIn setAuthIn = {0};
    TPM2_MODULE_CONFIG_SECTION *pModuleInfo = NULL;
    byteBoolean moduleLocked = FALSE;

    if (NULL == pModuleHandle)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, pModuleHandle = %p\n",
                __FUNCTION__, __LINE__, pModuleHandle);
        goto exit;
    }

    /* Allocate SMP_Context, will be returned as the ModuleHandle */
    status = DIGI_CALLOC((void **)&pSmpContext, 1, sizeof(SMP_Context));

    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for SMP context, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    status = getModuleMutex(moduleId, pSmpContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to get handle to module mutex, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    status = getModuleConnectionInfo(moduleId, &pModuleInfo);

    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to locate Device connection information, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Wait on module mutex failed, status = %d",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    moduleLocked = TRUE;

    /* If have response, set the TAP_Buffer */
    rc = FAPI2_CONTEXT_init(&(pSmpContext->pFapiContext),
            pModuleInfo->moduleName.bufferLen,
            pModuleInfo->moduleName.pBuffer,
            pModuleInfo->modulePort,
            8, NULL);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d FAPI2 Context init error, rc = 0x%02x\n",
                __FUNCTION__, __LINE__, rc);
        goto exit;
    }

    status = TPM2_getHierarchyAuth(&pSmpContext->lockoutAuth,
            TAP_ENTITY_TYPE_MODULE, TPM2_RH_LOCKOUT, 0,
            pModuleAttribute);

    if (OK != status)
    {
        DB_PRINT("%s.%d Error, Lockout hierarchy password must be passed in as attribute\n",
                __FUNCTION__, __LINE__);
        goto exit;
    }
    setAuthIn.lockoutAuth = pSmpContext->lockoutAuth;
    setAuthIn.forceUseLockoutAuth = TRUE;

    status = getOwnerHierarchyAuth(moduleId, &pSmpContext->ownerAuth,
                                 pModuleAttribute);
    if (OK != status)
    {
        goto exit;
    }
    setAuthIn.ownerAuth = pSmpContext->ownerAuth;
    setAuthIn.forceUseOwnerAuth = TRUE;

    status = getEndorsementHierarchyAuth(moduleId,
                        &pSmpContext->endorsementAuth, pModuleAttribute);
    if (OK != status)
    {
        goto exit;
    }
    setAuthIn.endorsementAuth = pSmpContext->endorsementAuth;
    setAuthIn.forceUseEndorsementAuth = TRUE;

    rc = FAPI2_CONTEXT_setHierarchyAuth(pSmpContext->pFapiContext,
            &setAuthIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d FAPI2 SetHierarchyAuth error, rc = 0x%02x\n",
                __FUNCTION__, __LINE__, rc);
    }

    /* Set platform auth if configured */
    if (0 < pModuleInfo->platformAuth.bufferLen)
    {
        if (sizeof(pSmpContext->platformAuth.buffer) < pModuleInfo->platformAuth.bufferLen)
        {
            status = ERR_INVALID_ARG;
            DB_PRINT("%s.%d Insufficient buffer size\n", __FUNCTION__, __LINE__);
            goto exit;
        }
        status = DIGI_MEMCPY(pSmpContext->platformAuth.buffer,
                                pModuleInfo->platformAuth.pBuffer,
                                pModuleInfo->platformAuth.bufferLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed copying platform auth buffer. status = %d\n",
                __FUNCTION__, __LINE__, status);
            goto exit;
        }
        pSmpContext->platformAuth.size = pModuleInfo->platformAuth.bufferLen;
    }

    pSmpContext->moduleId = moduleId;

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    if (OK != status)
    {
        if (NULL != pSmpContext)
        {
            if (NULL != pSmpContext->pFapiContext)
            {
                FAPI2_CONTEXT_uninit(&(pSmpContext->pFapiContext));
            }

            DIGI_FREE((void **)&pSmpContext);
        }
    }
    else
        *pModuleHandle = (TAP_ModuleHandle)((uintptr)pSmpContext);

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNINIT_MODULE__
MSTATUS SMP_API(TPM2, uninitModule,
        TAP_ModuleHandle moduleHandle
)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    SMP_Context *pSmpContext = NULL;

    if ((0 == moduleHandle))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p\n",
                __FUNCTION__, __LINE__, moduleHandle);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Wait on module mutex failed, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    rc = FAPI2_CONTEXT_uninit(&pSmpContext->pFapiContext);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d FAPI2 Context uninit error, rc = 0x%02x\n",
                __FUNCTION__, __LINE__, rc);
    }

    RTOS_mutexRelease(pSmpContext->moduleMutex);

    DIGI_FREE((void **)&pSmpContext);
exit:

    return status;
}
#endif

#if defined(__SMP_ENABLE_SMP_CC_ASSOCIATE_MODULE_CREDENTIALS__)

static MSTATUS getOwnerEntityAuth(TAP_ModuleId moduleId,
                          TPM2B_AUTH *pAuth,
                          TAP_EntityCredentialList *pEntityCredentials)
{
    MSTATUS status = OK;
    byteBoolean isOwnerAuthRetrieved = FALSE;

    if (NULL == pAuth)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __RTOS_WIN32__
    /* For windows hardware, retrieve owner auth from TBS ONLY */
    if (TPM20_SECURITY_MODULE == getTPM2DeviceType(moduleId))
    {
        /* Get owner authorization type administrator
         * i.e. TBS_OWNERAUTH_TYPE_STORAGE_20 */
        status = TPM2_getAuthFromTbs(pAuth, TAP_ENTITY_TYPE_TOKEN,
                                    TPM2_RH_OWNER, 0);
        if (OK != status)
        {
            DB_PRINT("%s.%d Info, Could not fetch Owner authorization from TBS, "
                    "status = %d\n", __FUNCTION__, __LINE__, status);
            goto exit;
        }
        isOwnerAuthRetrieved = TRUE;
    }
#endif /* __RTOS_WIN32__ */

    /* This should be true only for non-windows platform and
     * windows-emulator setting only */
    if (FALSE == isOwnerAuthRetrieved)
    {
        TPM2_getEntityCredentials(pEntityCredentials,
                            TAP_ENTITY_TYPE_TOKEN, TPM2_RH_OWNER, 0,
                            pAuth);
    }

exit:
    return status;
}

static MSTATUS getEndorsementEntityAuth(TAP_ModuleId moduleId,
                            TPM2B_AUTH *pAuth,
                            TAP_EntityCredentialList *pEntityCredentials)
{
    MSTATUS status = OK;
    byteBoolean isEndorsementAuthRetrieved = FALSE;

    if (NULL == pAuth)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

#ifdef __RTOS_WIN32__
    /* For windows hardware, retrieve owner auth from TBS ONLY */
    if (TPM20_SECURITY_MODULE == getTPM2DeviceType(moduleId))
    {
        status = TPM2_getAuthFromTbs(pAuth, TAP_ENTITY_TYPE_TOKEN,
                                        TPM2_RH_ENDORSEMENT, 0);
        if (OK != status)
        {
            DB_PRINT("%s.%d Info, Could not fetch Owner authorization type "
                    "endorsement from TBS, status = %d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }
        isEndorsementAuthRetrieved = TRUE;
    }
#endif /* __RTOS_WIN32__ */

    /* This should be true only for non-windows platform and
     * windows-emulator setting only */
    if (FALSE == isEndorsementAuthRetrieved)
    {
        TPM2_getEntityCredentials(pEntityCredentials,
                                    TAP_ENTITY_TYPE_TOKEN, TPM2_RH_ENDORSEMENT,
                                    0, pAuth);
    }

exit:
    return status;
}

#endif /* defined(__SMP_ENABLE_SMP_CC_ASSOCIATE_MODULE_CREDENTIALS__) */


#ifdef __SMP_ENABLE_SMP_CC_ASSOCIATE_MODULE_CREDENTIALS__
MSTATUS SMP_API(TPM2, associateModuleCredentials,
        TAP_ModuleHandle moduleHandle,
        TAP_EntityCredentialList *pEntityCredentials
)
{
    MSTATUS status = OK;
    SMP_Context *pSmpContext = NULL;
    ContextSetHierarchyAuthIn setAuthIn = {0};
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    byteBoolean moduleLocked = FALSE;

    if (0 == moduleHandle)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p\n",
                __FUNCTION__, __LINE__, moduleHandle);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Wait on module mutex failed, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    moduleLocked = TRUE;

    TPM2_getEntityCredentials(pEntityCredentials,
            TAP_ENTITY_TYPE_MODULE, TPM2_RH_LOCKOUT, 0,
            &pSmpContext->lockoutAuth);

    setAuthIn.lockoutAuth = pSmpContext->lockoutAuth;
    setAuthIn.forceUseLockoutAuth = TRUE;

    getOwnerEntityAuth(pSmpContext->moduleId,
                            &pSmpContext->ownerAuth, pEntityCredentials);

    setAuthIn.ownerAuth = pSmpContext->ownerAuth;
    setAuthIn.forceUseOwnerAuth = TRUE;

    getEndorsementEntityAuth(pSmpContext->moduleId,
                        &pSmpContext->endorsementAuth, pEntityCredentials);

    setAuthIn.endorsementAuth = pSmpContext->endorsementAuth;
    setAuthIn.forceUseEndorsementAuth = TRUE;

    rc = FAPI2_CONTEXT_setHierarchyAuth(pSmpContext->pFapiContext,
            &setAuthIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d FAPI2 SetHierarchyAuth error, rc = 0x%02x\n",
                __FUNCTION__, __LINE__, rc);
    }

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);
    return status;
}
#endif
#ifdef __SMP_ENABLE_SMP_CC_INIT_TOKEN__
MSTATUS SMP_API(TPM2, initToken,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenCapabilityAttributes *pTokenAttributes,
        TAP_TokenId tokenId,
        TAP_EntityCredentialList *pCredentials,
        TAP_TokenHandle *pTokenHandle
)
{
    MSTATUS status = OK;
    TPM2B_AUTH keyAuth = {0};
    ContextGetPrimaryObjectNameIn objIn = {0};
    ContextGetPrimaryObjectNameOut objOut = {0};
    ContextSetObjectAuthIn objAuthIn = {0};
    TOKEN_Context *pToken = NULL;
    SMP_Context *pSmpContext = NULL;
    ContextSetHierarchyAuthIn setAuthIn = {0};
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    byteBoolean moduleLocked = FALSE;

    if ((0 == moduleHandle) || (NULL == pTokenHandle) ||
            (0 == tokenId))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "pTokenHandle = %p, "
                "tokenId = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                pTokenHandle, tokenId);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Wait on module mutex failed, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }
    moduleLocked = TRUE;

    status = DIGI_CALLOC((void **)&pToken, 1, sizeof(*pToken));
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for Token context, "
                "status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    if (!((SMP_TPM2_CRYPTO_TOKEN_ID == tokenId) ||
          (SMP_TPM2_ATTESTATION_TOKEN_ID == tokenId) ||
          (SMP_TPM2_PLATFORM_TOKEN_ID == tokenId)))
    {
        DB_PRINT("%s.%d Invalid token id - %d\n",
                __FUNCTION__, __LINE__, tokenId);
        status = ERR_INVALID_ARG;
        goto exit;
    }

    /* Init token structure */
    pToken->id = tokenId;

    /* Platform token does not require initialization */
    if (SMP_TPM2_PLATFORM_TOKEN_ID != tokenId)
    {
        /* pCredentials, if provided, will correspond to password of
           corresponding primary keys based on the operation expected.
        */

        /* Use the module credentials from credentials passed in initModule
         */
        setAuthIn.lockoutAuth = pSmpContext->lockoutAuth;
        setAuthIn.forceUseLockoutAuth = TRUE;
        setAuthIn.ownerAuth = pSmpContext->ownerAuth;
        setAuthIn.forceUseOwnerAuth = TRUE;
        setAuthIn.endorsementAuth = pSmpContext->endorsementAuth;
        setAuthIn.forceUseEndorsementAuth = TRUE;
        rc = FAPI2_CONTEXT_setHierarchyAuth(pSmpContext->pFapiContext,
                &setAuthIn);
        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d FAPI2 SetHierarchyAuth error, rc = 0x%02x\n",
                    __FUNCTION__, __LINE__, rc);
            goto exit;
        }

        /* User objects are created under EK or SRK object IDs */
        TPM2_getEntityCredentials(pCredentials, TAP_ENTITY_TYPE_OBJECT,
                    (tokenId == SMP_TPM2_CRYPTO_TOKEN_ID) ? TPM2_RH_SRK :
                    TPM2_RH_EK, 0, &keyAuth);

        objIn.persistentHandle = (tokenId == SMP_TPM2_CRYPTO_TOKEN_ID) ?
            FAPI2_RH_SRK : FAPI2_RH_EK;
        rc = FAPI2_CONTEXT_getPrimaryObjectName(pSmpContext->pFapiContext,
                &objIn, &objOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d FAPI2 getPrimaryObjectName error, rc = 0x%02x\n",
                    __FUNCTION__, __LINE__, rc);
            goto exit;
        }

        objAuthIn.objName = objOut.objName;
        objAuthIn.objAuth = keyAuth;
        objAuthIn.forceUseAuthValue = 1;

        rc = FAPI2_CONTEXT_setObjectAuth(pSmpContext->pFapiContext,
                &objAuthIn);
        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d FAPI2 setObjectAuth error, rc = 0x%02x\n",
                    __FUNCTION__, __LINE__, rc);
            goto exit;
        }
    }

    *pTokenHandle = (TAP_TokenHandle)((uintptr)pToken);
exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);
    if (OK != status)
    {
        if (NULL != pToken)
            DIGI_FREE((void **)&pToken);
    }

    return status;
}
#endif

#if (defined __SMP_ENABLE_SMP_CC_DELETE_OBJECT__) || \
    (defined __SMP_ENABLE_SMP_CC_UNINIT_TOKEN__)
MSTATUS TPM2_uninitAllObjects(SMP_Context *pSmpContext,
        TOKEN_Context *pToken)
{
    MSTATUS status = OK;
    TPM2_OBJECT *pSmpObject = NULL;
    TPM2_OBJECT *pNextSmpObject = NULL;

    /* Look for this object in the context */
    pNextSmpObject = pSmpObject = pToken->pTpm2ObjectFirst;
    while (pSmpObject)
    {
        pNextSmpObject = pSmpObject->pNext;

        /* Free memory */
        if (OK != DIGI_FREE((void **)&pSmpObject))
        {
            DB_PRINT("%s.%d Failed to free SMPObject memory at %p\n",
                    __FUNCTION__, __LINE__, pSmpObject);
        }

        pSmpObject = pNextSmpObject;

        /* Unlink */
        pToken->pTpm2ObjectFirst = pSmpObject;
    }

    return status;
}

MSTATUS TPM2_deleteObject_usingAuthContext(SMP_Context *pSmpContext, TAP_TokenHandle tokenHandle,
        TPM2_OBJECT *pTpm2Object, byteBoolean flushObject,
        TAP_AUTH_CONTEXT_PROPERTY authContext)
{
    MSTATUS status = OK;
    TPM2_OBJECT *pSmpObject = NULL;
    TPM2_OBJECT *pPrevSmpObject = NULL;
    NVUndefineIn nvIn = {0};
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    CACHED_KeyInfo *pCachedKeyInfo = NULL;
    TOKEN_Context *pToken = NULL;
    ContextFlushObjectIn flushIn = {0};

    /* Check the object type */
    if (TPM2_OBJECT_TYPE_KEY == pTpm2Object->objectType)
    {
        pCachedKeyInfo = (CACHED_KeyInfo *)pTpm2Object;

        if (TRUE == flushObject)
        {
            flushIn.objName = pCachedKeyInfo->keyName;
            rc = FAPI2_CONTEXT_flushObject(pSmpContext->pFapiContext,
                    &flushIn);
            if (TSS2_RC_SUCCESS != rc)
            {
                status = SMP_TPM2_UTILS_getMocanaError(rc);
                DB_PRINT("%s.%d Failed to flush key object, "
                        "rc 0x%02x\n",
                        __FUNCTION__,__LINE__, rc);
                goto exit;
            }
        }

        /* Free key memory */
        if (OK != DIGI_FREE((void **)&pCachedKeyInfo))
        {
            DB_PRINT("%s.%d Failed to free memory for key object at %p\n",
                    __FUNCTION__, __LINE__, pTpm2Object);
        }
    }
    else
    {
        if (0 == tokenHandle)
        {
            status = ERR_NULL_POINTER;
            DB_PRINT("%s.%d NULL pointer on input, tokenHandle = %p\n",
                    __FUNCTION__, __LINE__, tokenHandle);
            goto exit;
        }

        pToken = (TOKEN_Context *)((uintptr)tokenHandle);

        /* Look for this object in the context */
        pPrevSmpObject = pSmpObject = pToken->pTpm2ObjectFirst;
        while (pSmpObject)
        {
            if (pTpm2Object == pSmpObject)
            {
                /* Found */
                if (TRUE == flushObject)
                {
                    nvIn.nvIndex = pSmpObject->id;
                    nvIn.authHandle = (TAP_AUTH_CONTEXT_PLATFORM == authContext) ?
                                    TPM2_RH_PLATFORM : TPM2_RH_OWNER;
                    if (0 < pSmpContext->platformAuth.size)
                    {
                        nvIn.authHandleAuth = pSmpContext->platformAuth;
                    }
                    rc = FAPI2_NV_undefine(pSmpContext->pFapiContext, &nvIn);
                    if (TSS2_RC_SUCCESS != rc)
                    {
                        status = SMP_TPM2_UTILS_getMocanaError(rc);
                        DB_PRINT("%s.%d Failed to undefine NV Index, "
                                "rc 0x%02x\n",
                                __FUNCTION__,__LINE__, rc);
                        goto exit;
                    }
                }

                /* Unlink */
                if (pPrevSmpObject == pToken->pTpm2ObjectFirst)
                    pToken->pTpm2ObjectFirst = pSmpObject->pNext;
                else
                    pPrevSmpObject->pNext = pSmpObject->pNext;

                /* Free memory */
                if (OK != DIGI_FREE((void **)&pSmpObject))
                    DB_PRINT("%s.%d Failed freeing memory for object\n",
                            __FUNCTION__, __LINE__);

                break;
            }

            pPrevSmpObject = pSmpObject;
            pSmpObject = pSmpObject->pNext;
        }
    }

exit:

    return status;
}

MSTATUS TPM2_deleteObject(SMP_Context *pSmpContext, TAP_TokenHandle tokenHandle,
        TPM2_OBJECT *pTpm2Object, byteBoolean flushObject)
{
    return TPM2_deleteObject_usingAuthContext(pSmpContext, tokenHandle,
                            pTpm2Object, flushObject,
                            0);
}

#endif

#ifdef __SMP_ENABLE_SMP_CC_UNINIT_TOKEN__
MSTATUS SMP_API(TPM2, uninitToken,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle
)
{
    MSTATUS status = OK;
    SMP_Context *pSmpContext = NULL;
    TOKEN_Context *pToken = NULL;
    byteBoolean moduleLocked = FALSE;

    if ((0 == moduleHandle) || (0 == tokenHandle))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "tokenHandle = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                tokenHandle);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pToken = (TOKEN_Context *)((uintptr)tokenHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Wait on module mutex failed, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }
    moduleLocked = TRUE;

    /* Delete all objects under this token */
    status = TPM2_uninitAllObjects(pSmpContext, pToken);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed deleting all TPM Objects, status = %d",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    /* Destroy token */
    if (OK != DIGI_FREE((void **)&pToken))
        DB_PRINT("%s.%d Failed freeing memory for token handle\n",
                __FUNCTION__, __LINE__);

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_ASSOCIATE_TOKEN_CREDENTIALS__
MSTATUS SMP_API(TPM2, associateTokenCredentials,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_EntityCredentialList *pCredentials
)
{
    MSTATUS status = OK;
    ContextSetHierarchyAuthIn hierarchyAuthIn = {0};
    TAP_ObjectId tokenId = 0;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    SMP_Context *pSmpContext = NULL;
    TOKEN_Context *pToken = NULL;
    ContextGetPrimaryObjectNameIn objectNameIn = { 0 };
    ContextGetPrimaryObjectNameOut objectName = { 0 };
    ContextSetObjectAuthIn objAuthIn = {0};
    byteBoolean moduleLocked = FALSE;

    if ((0 == moduleHandle) || (0 == tokenHandle) ||
            (NULL == pCredentials))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input, moduleHandle = %p, tokenHandle = %p, "
                "pCredentials = %p\n",
                __FUNCTION__, __LINE__, moduleHandle, tokenHandle,
                pCredentials);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pToken = (TOKEN_Context *)((uintptr)tokenHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Wait on module mutex failed, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }
    moduleLocked = TRUE;

    tokenId = pToken->id;
    TPM2_getEntityCredentials(pCredentials, TAP_ENTITY_TYPE_OBJECT,
            (SMP_TPM2_CRYPTO_TOKEN_ID == tokenId) ? TPM2_RH_SRK :
            TPM2_RH_EK, 0, &pToken->keyAuth);

    /* We set all the hierarchy auths together */
    hierarchyAuthIn.lockoutAuth = pSmpContext->lockoutAuth;
    hierarchyAuthIn.ownerAuth = pSmpContext->ownerAuth;
    hierarchyAuthIn.endorsementAuth = pSmpContext->endorsementAuth;

    rc = FAPI2_CONTEXT_setHierarchyAuth(pSmpContext->pFapiContext,
            &hierarchyAuthIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d FAPI2 setHierarchyAuth failed. rc = 0x%02x",
                __FUNCTION__, __LINE__, (unsigned int)rc);
        goto exit;
    }

    objectNameIn.persistentHandle = (SMP_TPM2_CRYPTO_TOKEN_ID == tokenId) ?
            FAPI2_RH_SRK : FAPI2_RH_EK;
    rc = FAPI2_CONTEXT_getPrimaryObjectName(pSmpContext->pFapiContext,
            &objectNameIn, &objectName);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d FAPI2 getPrimaryObjectName failed. rc = 0x%02x",
                __FUNCTION__, __LINE__, (unsigned int)rc);
        goto exit;
    }

    objAuthIn.objName = objectName.objName;
    objAuthIn.objAuth = pToken->keyAuth;
    objAuthIn.forceUseAuthValue = 1;

    rc = FAPI2_CONTEXT_setObjectAuth(pSmpContext->pFapiContext,
            &objAuthIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d FAPI2 setObjectAuth failed. rc = 0x%02x",
                __FUNCTION__, __LINE__, (unsigned int)rc);
        goto exit;
    }

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);
    return status;
}
#endif

#if (defined __SMP_ENABLE_SMP_CC_INIT_OBJECT__) || \
    (defined __SMP_ENABLE_SMP_CC_CREATE_OBJECT__)

MSTATUS TPM2_createNVObject(SMP_Context *pSmpContext, TOKEN_Context *pToken,
        TAP_ObjectId nvId, ubyte4 nvSize, TPM2B_AUTH *pAuth,
        TAP_AUTH_CONTEXT_PROPERTY authContext,
        TAP_ObjectHandle *pObjectHandle)
{
    MSTATUS status = OK;
    TPM2_OBJECT *pTpm2Object = NULL;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    NVDefineIn nvIn = {0};

    status = DIGI_CALLOC((void **)&pTpm2Object, 1, sizeof(TPM2_OBJECT));
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for NVRAM object, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    nvIn.nvIndex = nvId;
    nvIn.nvIndexType = TPM2_NT_ORDINARY;
    nvIn.dataSize = nvSize;
    nvIn.nvAuth = *pAuth;
    nvIn.disableDA = TRUE;
    nvIn.authHandle = (TAP_AUTH_CONTEXT_PLATFORM == authContext) ?
                    TPM2_RH_PLATFORM : TPM2_RH_OWNER;
    if (0 < pSmpContext->platformAuth.size)
    {
        nvIn.authHandleAuth = pSmpContext->platformAuth;
    }
    rc = FAPI2_NV_define(pSmpContext->pFapiContext, &nvIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to define NV Index, "
                "rc 0x%02x\n",
                __FUNCTION__,__LINE__, rc);
        goto exit;
    }

    /* Associate credentials */
    pTpm2Object->auth = *pAuth;

    pTpm2Object->objectType = TPM2_OBJECT_TYPE_NV;
    pTpm2Object->id = nvId;
    pTpm2Object->size = nvSize;

    pTpm2Object->pNext = pToken->pTpm2ObjectFirst;
    pToken->pTpm2ObjectFirst = pTpm2Object;

    *pObjectHandle = (TAP_ObjectHandle)((uintptr)pTpm2Object);
    pTpm2Object = NULL;

exit:
    if (pTpm2Object)
        DIGI_FREE((void **)&pTpm2Object);

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_INIT_OBJECT__

MSTATUS SMP_API(TPM2, initObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectId objectIdIn,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_EntityCredentialList *pCredentials,
        TAP_ObjectHandle *pObjectHandle,
        TAP_ObjectId *pObjectIdOut
)
{
    MSTATUS status = OK;
    TPM2_OBJECT *pTpm2Object = NULL;
    SMP_Context *pSmpContext = NULL;
    ubyte objectPresent = 0;
    TPM2B_AUTH auth = {0};
    TOKEN_Context *pToken = NULL;
    CACHED_KeyInfo *pCachedKey = NULL;
    ubyte4 nvSize = 0;
    TAP_Attribute *pAttribute = NULL;
    ContextGetPrimaryObjectNameIn objectNameIn = { 0 };
    ContextGetPrimaryObjectNameOut objectNameOut = { 0 };
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC rc_exit;
    byteBoolean moduleLocked = FALSE;
    ContextGetObjectPublicInfoIn publicInfoIn = {0};
    ContextGetObjectPublicInfoOut publicInfoOut = {0};
    ContextSetObjectAuthIn authIn = {0};
    ubyte4 attrCount;
    FAPI2_OBJECT *pFapiObject = NULL;
    ContextFlushObjectIn flushObjectIn = { 0 };

    if ((0 == moduleHandle) || (NULL == pObjectHandle) ||
            (0 == tokenHandle))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input, moduleHandle = %p, objectIdIn = %p, "
                "pObjectHandle = %p\n",
                __FUNCTION__, __LINE__, moduleHandle, objectIdIn,
                pObjectHandle);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pToken = (TOKEN_Context *)((uintptr)tokenHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Wait on module mutex failed, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }
    moduleLocked = TRUE;

    /* If objectId is 0 then it might be in the attributes instead*/
    if (0x00L == objectIdIn)
    {
        TAP_Buffer *pIdBuf = NULL;
        sbyte4 i = 0;

        /* Get object size */
        if (TPM2_getAttribute(pObjectAttributes, TAP_ATTR_OBJECT_ID_BYTESTRING, &pAttribute))
        {
            if ((sizeof(TAP_Buffer) != pAttribute->length) ||
                    (NULL == pAttribute->pStructOfType))
            {
                status = ERR_INVALID_ARG;
                DB_PRINT("%s.%d Invalid storage structure length %d, "
                        "pStructOfType = %p\n",
                        __FUNCTION__, __LINE__, pAttribute->length,
                        pAttribute->pStructOfType);
                goto exit;
            }

            pIdBuf = (TAP_Buffer *)(pAttribute->pStructOfType);
            if (pIdBuf->bufferLen > 8)
            {
                status = ERR_INVALID_INPUT;
                DB_PRINT("%s.%d Invalid id length %d\n",
                        __FUNCTION__, __LINE__, pIdBuf->bufferLen);
                goto exit;                
            }

            if (NULL == pIdBuf->pBuffer)
            {
                status = ERR_NULL_POINTER;
                DB_PRINT("%s.%d Null id buffer\n",
                        __FUNCTION__, __LINE__);
                goto exit;   
            }

            for (i = 0; i < (sbyte4) pIdBuf->bufferLen; i++)
            {
                /* convert byte array as a big Endian integer */
                objectIdIn |= ( ((TAP_ObjectId) (pIdBuf->pBuffer[i])) << (8 * (pIdBuf->bufferLen - 1 - i)) );
            }
        }

        /* if still 0x00 error */
        if (0x00L == objectIdIn)
        {
                status = ERR_INVALID_INPUT;
                DB_PRINT("%s.%d Invalid id of 0x00\n",
                        __FUNCTION__, __LINE__);
                goto exit;  
        }
    }

    if (pObjectAttributes && pObjectAttributes->listLen)
    {
        attrCount = 0;
        pAttribute = pObjectAttributes->pAttributeList;

        while (attrCount < pObjectAttributes->listLen)
        {
            if (TAP_ATTR_CREDENTIAL_SET == pAttribute->type)
            {
                /* get credential if there, but no  error in case it's not */
                (void) TPM2_getCredentialsList(
                    (TAP_CredentialList *)pAttribute->pStructOfType,
                    TAP_CREDENTIAL_TYPE_PASSWORD, &authIn.objAuth);
            }
            pAttribute++;
            attrCount++;
        }
    }

    /* Collect credentials */
    TPM2_getEntityCredentials(pCredentials, TAP_ENTITY_TYPE_OBJECT, objectIdIn,
            0, &auth);

    if (TPM2_storageObject(pSmpContext, pToken, objectIdIn))
    {
        /* If it is SRK, get the object name and return a key context */
        if ( (FAPI2_RH_SRK == objectIdIn) || (FAPI2_RH_EK == objectIdIn) )
        {
            status = DIGI_CALLOC((void **)&pCachedKey, 1, sizeof(*pCachedKey));

            if (OK != status)
            {
                DB_PRINT("%s.%d Unable to allocate memory for cached key object, status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }

            pCachedKey->objectType = TPM2_OBJECT_TYPE_KEY;

            objectNameIn.persistentHandle = objectIdIn;
            rc = FAPI2_CONTEXT_getPrimaryObjectName(pSmpContext->pFapiContext,
                    &objectNameIn, &objectNameOut);
            if (TSS2_RC_SUCCESS != rc)
            {
                status = SMP_TPM2_UTILS_getMocanaError(rc);
                DB_PRINT("%s.%d FAPI2 getPrimaryObjectName failed. rc = 0x%02x",
                        __FUNCTION__, __LINE__, (unsigned int)rc);
                goto exit;
            }

            pCachedKey->keyName = objectNameOut.objName;
            /* keyblob is not available for persistent keys */

            publicInfoIn.object = pCachedKey->keyName;
            rc = FAPI2_CONTEXT_getObjectPublicInfo(pSmpContext->pFapiContext,
                    &publicInfoIn, &publicInfoOut);
            if (TSS2_RC_SUCCESS != rc)
            {
                status = SMP_TPM2_UTILS_getMocanaError(rc);
                DB_PRINT("%s.%d Failed to get key public info, rc = 0x%02x\n",
                        __FUNCTION__, __LINE__, rc);
                goto exit;
            }

            switch (publicInfoOut.publicInfo.type)
            {
                case TPM2_ALG_RSA:
                    pCachedKey->keyAlgorithm = TAP_KEY_ALGORITHM_RSA;
                    break;

                case TPM2_ALG_ECC:
                    pCachedKey->keyAlgorithm = TAP_KEY_ALGORITHM_ECC;
                    break;

                case TPM2_ALG_AES:
                case TPM2_ALG_AES192:
                case TPM2_ALG_AES256:
                case TPM2_ALG_SYMCIPHER:
                    pCachedKey->keyAlgorithm = TAP_KEY_ALGORITHM_AES;
                    break;

                case TPM2_ALG_HMAC:
                    pCachedKey->keyAlgorithm = TAP_KEY_ALGORITHM_HMAC;
                    break;

                default:
                    DB_PRINT("%s.%d Unsupported algorithm %d in key public info, rc = 0x%02x\n",
                            __FUNCTION__, __LINE__,
                            (int)publicInfoOut.publicInfo.type, rc);
                    status = ERR_TAP_CMD_FAILED;
                    goto exit;
                    break;
            }

            if (pObjectIdOut)
                *pObjectIdOut = objectIdIn;

            *pObjectHandle = (TAP_ObjectHandle)((uintptr)pCachedKey);
            pCachedKey = NULL;

            goto exit;
        }

        /* Get object size */
        if (TPM2_getAttribute(pObjectAttributes, TAP_ATTR_STORAGE_SIZE,
                    &pAttribute))
        {
            if ((sizeof(ubyte4) != pAttribute->length) ||
                    (NULL == pAttribute->pStructOfType))
            {
                status = ERR_INVALID_ARG;
                DB_PRINT("%s.%d Invalid storage structure length %d, "
                        "pStructOfType = %p\n",
                        __FUNCTION__, __LINE__, pAttribute->length,
                        pAttribute->pStructOfType);
                goto exit;
            }
            nvSize = *(ubyte4 *)(pAttribute->pStructOfType);
        }

        /* Verify that the object is already created */
        if (((objectIdIn >> TPM2_HR_SHIFT) & 0xFF) == TPM2_HT_NV_INDEX)
        {
            if (TPM2_nvProvisionedIndex(pSmpContext, pToken, objectIdIn))
            {
                status = DIGI_CALLOC((void **)&pTpm2Object, 1, sizeof(TPM2_OBJECT));
                if (OK != status)
                {
                    DB_PRINT("%s.%d Unable to allocate memory for NVRAM object, status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }

                /* Associate credentials */
                pTpm2Object->auth = auth;

                pTpm2Object->id = objectIdIn;

                pTpm2Object->objectType = TPM2_OBJECT_TYPE_NV;
                pTpm2Object->size = nvSize;
                pTpm2Object->pNext = pToken->pTpm2ObjectFirst;
                pToken->pTpm2ObjectFirst = pTpm2Object;

                if (pObjectIdOut)
                    *pObjectIdOut = objectIdIn;

                *pObjectHandle = (TAP_ObjectHandle)((uintptr)pTpm2Object);
            }
            else
            {
                status = ERR_INVALID_ARG;
                DB_PRINT("%s.%d Object ID 0x%08x not provisioned\n",
                        __FUNCTION__, __LINE__, (int)objectIdIn);
                goto exit;
            }
        }
        else if (((objectIdIn >> TPM2_HR_SHIFT) & 0xFF) == TPM2_HT_PERSISTENT)
        {
            status = TPM2_keyCreated(
                pSmpContext, objectIdIn, &objectPresent);
            if (OK != status)
            {
                DB_PRINT("%s.%d Error finding key by object ID, status %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }

            if (!objectPresent)
            {
                status = ERR_TAP_INVALID_INPUT;
                DB_PRINT("%s.%d Error object does not exist, status %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }

            status = DIGI_CALLOC((void **)&pCachedKey, 1, sizeof(*pCachedKey));

            if (OK != status)
            {
                DB_PRINT("%s.%d Unable to allocate memory for cached key object, status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }

            pCachedKey->objectType = TPM2_OBJECT_TYPE_KEY;

            pCachedKey->id = objectIdIn;
            objectNameIn.persistentHandle = objectIdIn;
            rc = FAPI2_CONTEXT_getPrimaryObjectName(pSmpContext->pFapiContext,
                    &objectNameIn, &objectNameOut);
            if (TSS2_RC_SUCCESS != rc)
            {
                status = SMP_TPM2_UTILS_getMocanaError(rc);
                DB_PRINT("%s.%d FAPI2 getPrimaryObjectName failed. rc = 0x%02x",
                        __FUNCTION__, __LINE__, (unsigned int)rc);
                goto exit;
            }

            pCachedKey->keyName = objectNameOut.objName;

            status = DIGI_MEMCPY(authIn.objName.name, objectNameOut.objName.name,
                                objectNameOut.objName.size);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy keyname to set auth name buffer, "
                         "status = %d\n",
                          __FUNCTION__,__LINE__, status);
                goto exit;
            }
            authIn.objName.size = objectNameOut.objName.size;
            authIn.forceUseAuthValue = 1;

            rc = FAPI2_CONTEXT_setObjectAuth(pSmpContext->pFapiContext,
                &authIn);
            if (TSS2_RC_SUCCESS != rc)
            {
                status = SMP_TPM2_UTILS_getMocanaError(rc);
                    DB_PRINT("%s.%d Failed to set auth value on imported key, rc = 0x%02x\n",
                             __FUNCTION__, __LINE__, rc);
                goto exit;
            }

            publicInfoIn.object = pCachedKey->keyName;
            rc = FAPI2_CONTEXT_getObjectPublicInfo(pSmpContext->pFapiContext,
                    &publicInfoIn, &publicInfoOut);
            if (TSS2_RC_SUCCESS != rc)
            {
                status = SMP_TPM2_UTILS_getMocanaError(rc);
                DB_PRINT("%s.%d Failed to get key public info, rc = 0x%02x\n",
                        __FUNCTION__, __LINE__, rc);
                goto exit;
            }

            switch (publicInfoOut.publicInfo.type)
            {
                case TPM2_ALG_RSA:
                    pCachedKey->keyAlgorithm = TAP_KEY_ALGORITHM_RSA;
                    break;

                case TPM2_ALG_ECC:
                    pCachedKey->keyAlgorithm = TAP_KEY_ALGORITHM_ECC;
                    break;

                case TPM2_ALG_AES:
                case TPM2_ALG_AES192:
                case TPM2_ALG_AES256:
                case TPM2_ALG_SYMCIPHER:
                    pCachedKey->keyAlgorithm = TAP_KEY_ALGORITHM_AES;
                    break;

                case TPM2_ALG_HMAC:
                case TPM2_ALG_KEYEDHASH:
                    pCachedKey->keyAlgorithm = TAP_KEY_ALGORITHM_HMAC;
                    break;

                default:
                    DB_PRINT("%s.%d Unsupported algorithm %d in key public info, rc = 0x%02x\n",
                            __FUNCTION__, __LINE__,
                            (int)publicInfoOut.publicInfo.type, rc);
                    status = ERR_TAP_CMD_FAILED;
                    goto exit;
            }

            /* get the keyblob by getting the FAPI2 Object and serializing */
            rc = FAPI2_CONTEXT_lookupPrimaryObjectByHandle(pSmpContext->pFapiContext,
                (TPM2_HANDLE) objectIdIn, &pFapiObject);
            if (TSS2_RC_SUCCESS != rc)
            {
                status = SMP_TPM2_UTILS_getMocanaError(rc);
                DB_PRINT("%s.%d FAPI2_CONTEXT_lookupPrimaryObjectByHandle, rc = 0x%02x\n",
                        __FUNCTION__, __LINE__, rc);
                goto exit;
            }
            
            rc = FAPI2_UTILS_serialize(&pFapiObject, FALSE, &pCachedKey->key);
            flushObjectIn.objName = pFapiObject->objectName;
            rc_exit = FAPI2_CONTEXT_flushObject(pSmpContext->pFapiContext, &flushObjectIn);
            if (TSS2_RC_SUCCESS != rc)
            {
                status = SMP_TPM2_UTILS_getMocanaError(rc);
                DB_PRINT("%s.%d FAPI2_UTILS_serialize, rc = 0x%02x\n",
                        __FUNCTION__, __LINE__, rc);
                goto exit;
            }
            if (TSS2_RC_SUCCESS != rc_exit)
            {
                status = SMP_TPM2_UTILS_getMocanaError(rc_exit);
                DB_PRINT("%s.%d FAPI2_CONTEXT_flushObject, rc = 0x%02x\n",
                        __FUNCTION__, __LINE__, rc_exit);
                goto exit;
            }

            if (pObjectIdOut)
                *pObjectIdOut = objectIdIn;

            *pObjectHandle = (TAP_ObjectHandle)((uintptr)pCachedKey);
            pCachedKey = NULL;

            goto exit;
        }
        else
        {
            status = ERR_TAP_INVALID_HANDLE;
            DB_PRINT("%s.%d Object ID 0x%08x unsupported range\n",
                    __FUNCTION__, __LINE__, (int)objectIdIn);
            goto exit;
        }
    }
    else
    {
        /* If it is EK, get the object name and return a key context */
        status = DIGI_CALLOC((void **)&pCachedKey, 1, sizeof(*pCachedKey));

        if (OK != status)
        {
            DB_PRINT("%s.%d Unable to allocate memory for cached key object, status = %d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }

        pCachedKey->objectType = TPM2_OBJECT_TYPE_KEY;

        objectNameIn.persistentHandle = objectIdIn;
        rc = FAPI2_CONTEXT_getPrimaryObjectName(pSmpContext->pFapiContext,
                &objectNameIn, &objectNameOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d FAPI2 getPrimaryObjectName failed. rc = 0x%02x",
                    __FUNCTION__, __LINE__, (unsigned int)rc);
            goto exit;
        }

        pCachedKey->keyName = objectNameOut.objName;
        /* keyblob is not available for persistent keys */

        publicInfoIn.object = pCachedKey->keyName;
        rc = FAPI2_CONTEXT_getObjectPublicInfo(pSmpContext->pFapiContext,
                &publicInfoIn, &publicInfoOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d Failed to get key public info, rc = 0x%02x\n",
                    __FUNCTION__, __LINE__, rc);
            goto exit;
        }

        switch (publicInfoOut.publicInfo.type)
        {
            case TPM2_ALG_RSA:
                pCachedKey->keyAlgorithm = TAP_KEY_ALGORITHM_RSA;
                break;

            case TPM2_ALG_ECC:
                pCachedKey->keyAlgorithm = TAP_KEY_ALGORITHM_ECC;
                break;

            case TPM2_ALG_AES:
            case TPM2_ALG_AES192:
            case TPM2_ALG_AES256:
            case TPM2_ALG_SYMCIPHER:
                pCachedKey->keyAlgorithm = TAP_KEY_ALGORITHM_AES;
                break;

            case TPM2_ALG_HMAC:
                pCachedKey->keyAlgorithm = TAP_KEY_ALGORITHM_HMAC;
                break;

            default:
                DB_PRINT("%s.%d Unsupported algorithm %d in key public info, rc = 0x%02x\n",
                        __FUNCTION__, __LINE__,
                        (int)publicInfoOut.publicInfo.type, rc);
                status = ERR_TAP_CMD_FAILED;
                goto exit;
                break;
        }

        if (pObjectIdOut)
            *pObjectIdOut = objectIdIn;

        *pObjectHandle = (TAP_ObjectHandle)((uintptr)pCachedKey);
        pCachedKey = NULL;

        goto exit;
    }

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);
    if (NULL != pCachedKey)
        DIGI_FREE((void**)&pCachedKey);

    return status;
}
#endif
#ifdef __SMP_ENABLE_SMP_CC_IMPORT_OBJECT__
MSTATUS SMP_API(TPM2, importObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_Blob *pObjectBuffer,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_EntityCredentialList *pCredentials,
        TAP_ObjectCapabilityAttributes *pObjectAttributesOut,
        TAP_ObjectHandle *pObjectHandle
)
{
    MSTATUS status = OK;
    SMP_Context *pSmpContext = NULL;
    ContextLoadObjectIn loadObjIn = {0};
    ContextLoadObjectOut loadObjOut = {0};
    TSS2_RC rc = 0;
    CACHED_KeyInfo *pCachedKey = NULL;
    ContextSetObjectAuthIn authIn = {0};
    byteBoolean moduleLocked = FALSE;
    TAP_Attribute *pAttribute = NULL;
    ubyte4 attrCount;

    if ((0 == moduleHandle) || (NULL == pObjectBuffer) ||
            (NULL == pObjectHandle))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input, moduleHandle = %p, pObjectBuffer = %p,"
                "pObjectHandle = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                pObjectBuffer, pObjectHandle);
        goto exit;
    }

    if (TAP_BLOB_FORMAT_MOCANA != pObjectBuffer->format)
    {
        status = ERR_TAP_UNSUPPORTED;
        DB_PRINT("%s.%d Unsupported object format %d, "
                "status = %d\n",
                __FUNCTION__, __LINE__, pObjectBuffer->format,
                (int)status);
        goto exit;
    }

    if (TAP_BLOB_ENCODING_BINARY != pObjectBuffer->encoding)
    {
        status = ERR_TAP_UNSUPPORTED;
        DB_PRINT("%s.%d Unsupported object encoding %d, "
                "status = %d\n",
                __FUNCTION__, __LINE__, pObjectBuffer->encoding,
                (int)status);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Wait on Mutex for module - %p, failed with error= %d\n",
                __FUNCTION__, __LINE__, moduleHandle, status);
        goto exit;
    }
    moduleLocked = TRUE;

    if (pObjectBuffer->blob.bufferLen >
            sizeof(loadObjIn.obj.buffer))
    {
        status = ERR_TAP_CMD_FAILED;
        DB_PRINT("%s.%d Object size of %d exceeds limit of %d "
                "status = %d\n",
                __FUNCTION__, __LINE__, (int)pObjectBuffer->blob.bufferLen,
                (int)sizeof(loadObjIn.obj.buffer),
                (int)status);
        goto exit;
    }

    if (pObjectAttributes && pObjectAttributes->listLen)
    {
        attrCount = 0;
        pAttribute = pObjectAttributes->pAttributeList;

        while (attrCount < pObjectAttributes->listLen)
        {
            if (TAP_ATTR_CREDENTIAL_SET == pAttribute->type)
            {
                if (!TPM2_getCredentialsList(
                    (TAP_CredentialList *)pAttribute->pStructOfType,
                    TAP_CREDENTIAL_TYPE_PASSWORD, &authIn.objAuth))
                {
                    status = ERR_TAP_INVALID_AUTH_FORMAT;
                    DB_PRINT("%s.%d Failed getting entity credential for key\n",
                        __FUNCTION__, __LINE__);
                    goto exit;
                }
            }
            pAttribute++;
            attrCount++;
        }
    }

    loadObjIn.objAuth.size = 0;
    loadObjIn.obj.size = pObjectBuffer->blob.bufferLen;
    status = DIGI_MEMCPY(loadObjIn.obj.buffer, pObjectBuffer->blob.pBuffer,
                loadObjIn.obj.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error copying object into request block, "
                "status = %d\n",
                __FUNCTION__, __LINE__, (int)status);
        goto exit;
    }

    status = DIGI_CALLOC((void **)&pCachedKey, 1, sizeof(*pCachedKey));

    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for cached key object, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    rc = FAPI2_CONTEXT_loadObject(pSmpContext->pFapiContext,
            &loadObjIn, &loadObjOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to load object into secure element, rc = 0x%02x\n",
                __FUNCTION__, __LINE__, rc);
        goto exit;
    }

    authIn.forceUseAuthValue = 1;

    status = DIGI_MEMCPY(authIn.objName.name, loadObjOut.objName.name,
            loadObjOut.objName.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy keyname to set auth name buffer, "
                "status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }
    authIn.objName.size = loadObjOut.objName.size;
    authIn.forceUseAuthValue = 1;

    rc = FAPI2_CONTEXT_setObjectAuth(pSmpContext->pFapiContext,
            &authIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to set auth value on imported key, rc = 0x%02x\n",
                __FUNCTION__, __LINE__, rc);
        goto exit;
    }

    status = DIGI_MEMCPY(pCachedKey->keyName.name, loadObjOut.objName.name,
            loadObjOut.objName.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy keyname, "
                "status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }
    pCachedKey->keyName.size = loadObjOut.objName.size;

    switch (loadObjOut.objectType)
    {
        case TPM2_ALG_RSA:
            pCachedKey->keyAlgorithm = TAP_KEY_ALGORITHM_RSA;
            break;

        case TPM2_ALG_ECC:
            pCachedKey->keyAlgorithm = TAP_KEY_ALGORITHM_ECC;
            break;

        case TPM2_ALG_AES:
        case TPM2_ALG_AES192:
        case TPM2_ALG_AES256:
        case TPM2_ALG_SYMCIPHER:
            pCachedKey->keyAlgorithm = TAP_KEY_ALGORITHM_AES;
            break;

        case TPM2_ALG_HMAC:
        case TPM2_ALG_KEYEDHASH:
            pCachedKey->keyAlgorithm = TAP_KEY_ALGORITHM_HMAC;
            break;

        default:
            status = ERR_TAP_INVALID_ALGORITHM;
            DB_PRINT("%s.%d Invalid key key algorithm %d, status = %d\n",
                    __FUNCTION__,__LINE__, (int)loadObjOut.objectType,
                    status);
            goto exit;
            break;
    }

    status = DIGI_MEMCPY(pCachedKey->key.buffer, pObjectBuffer->blob.pBuffer,
            pObjectBuffer->blob.bufferLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy key blob, "
                "status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    pCachedKey->key.size = pObjectBuffer->blob.bufferLen;

    pCachedKey->objectType = TPM2_OBJECT_TYPE_KEY;
    *pObjectHandle = (TAP_ObjectHandle)((uintptr)pCachedKey);
    pCachedKey = NULL;
exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);
    if (NULL != pCachedKey)
        DIGI_FREE((void**)&pCachedKey);

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNINIT_OBJECT__
MSTATUS SMP_API(TPM2, uninitObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle
)
{
    MSTATUS status = OK;
    SMP_Context *pSmpContext = NULL;
    TPM2_OBJECT *pTpm2Object = NULL;
    byteBoolean moduleLocked = FALSE;

    if ((0 == moduleHandle) || (0 == objectHandle))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "objectHandle = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                objectHandle);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pTpm2Object = (TPM2_OBJECT *)((uintptr)objectHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Wait on Mutex for module - %p, failed with error= %d\n",
                __FUNCTION__, __LINE__, moduleHandle, status);
        goto exit;
    }
    moduleLocked = TRUE;

    status = TPM2_deleteObject(pSmpContext, tokenHandle, pTpm2Object, FALSE);
    if (OK != status)
    {
        DB_PRINT("%s.%d TPM2_deleteObject failed, status = %d\n",
                __FUNCTION__, __LINE__, status);
    }

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);
    return status;
}

#endif

#ifdef __SMP_ENABLE_SMP_CC_EVICT_OBJECT__

MSTATUS TPM2_evictKey(
    SMP_Context *pSmpContext,
    TAP_ObjectId objectId,
    TPMI_RH_PROVISION authHandle)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_FAPI_RC_BAD_VALUE;
    EvictKeyIn evictKeyIn = {0};
    ubyte objectPresent = 0;
    TPM2B_AUTH auth = {0};
    ContextGetPrimaryObjectNameIn objNameIn = {0};
    ContextGetPrimaryObjectNameOut objNameOut = {0};
    ContextSetObjectAuthIn authIn = {0};
    TAP_EntityCredentialList *pCredentials = NULL;

    status = TPM2_keyCreated(pSmpContext, objectId, &objectPresent);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error getting key creation status, status %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    if (!objectPresent)
    {
        status = ERR_TAP_INVALID_HANDLE;
        DB_PRINT("%s.%d Key does not exist for handle %d, status %d\n",
            __FUNCTION__, __LINE__, objectId, status);
        goto exit;
    }

    TPM2_getEntityCredentials(pCredentials, TAP_ENTITY_TYPE_OBJECT, objectId, 0, &auth);

    objNameIn.persistentHandle = objectId;

    rc = FAPI2_CONTEXT_getPrimaryObjectName(pSmpContext->pFapiContext,
            &objNameIn, &objNameOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d FAPI2 getPrimaryObjectName failed. rc = 0x%02x",
                __FUNCTION__, __LINE__, (unsigned int)rc);
        goto exit;
    }

    status = DIGI_MEMCPY(authIn.objName.name, objNameOut.objName.name,
                        objNameOut.objName.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy keyname to set auth name buffer, "
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
        goto exit;
    }
    authIn.objName.size = objNameOut.objName.size;
    authIn.forceUseAuthValue = 1;

    rc = FAPI2_CONTEXT_setObjectAuth(pSmpContext->pFapiContext,
        &authIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d Failed to set auth value on imported key, rc = 0x%02x\n",
                        __FUNCTION__, __LINE__, rc);
        goto exit;
    }

    evictKeyIn.objName = objNameOut.objName;
    evictKeyIn.objectId = (ubyte4)objectId;
    evictKeyIn.authHandle = authHandle;
    if (TPM2_RH_PLATFORM == authHandle)
        evictKeyIn.authHandleAuth = pSmpContext->platformAuth;
    else
        evictKeyIn.authHandleAuth = pSmpContext->pFapiContext->authValues.ownerAuth;
    rc = FAPI2_CONTEXT_evictKey(
        pSmpContext->pFapiContext, &evictKeyIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to evict key , "
                "rc 0x%02x\n",
                __FUNCTION__,__LINE__, rc);
        goto exit;
    }

exit:

    return status;
}

MSTATUS SMP_API(TPM2, evictObject,
        TAP_ModuleHandle moduleHandle,
        TAP_Buffer *pObjectId,
        TAP_AttributeList *pAttributeList
)
{
    MSTATUS status = OK;
    SMP_Context *pSmpContext = NULL;
    byteBoolean moduleLocked = FALSE;
    TAP_ObjectId objectId = 0x00L;
    ubyte4 i = 0;
    ubyte4 count;
    TAP_Attribute *pAttribute = NULL;
    TAP_AUTH_CONTEXT_PROPERTY authContext = TAP_AUTH_CONTEXT_STORAGE;
    TPMI_RH_PROVISION authHandle;

    if (0 == moduleHandle || NULL == pObjectId || NULL == pObjectId->pBuffer)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input\n",
                __FUNCTION__, __LINE__);
        goto exit;
    }

    if (pObjectId->bufferLen > 8)
    {
        status = ERR_INVALID_INPUT;
        DB_PRINT("%s.%d Invalid Id Length of %d for tpm2\n",
                __FUNCTION__, __LINE__, pObjectId->bufferLen);
        goto exit;
    }

    for (i = 0; i < pObjectId->bufferLen; i++)
    {
        /* convert byte array as a big Endian integer */
        objectId |= ( ((TAP_ObjectId) (pObjectId->pBuffer[i])) << (8 * (pObjectId->bufferLen - 1 - i)) );
    }

    if (pAttributeList && pAttributeList->listLen)
    {
        for (count = 0; count < pAttributeList->listLen; count++)
        {
            pAttribute = &pAttributeList->pAttributeList[count];

            if (TAP_ATTR_AUTH_CONTEXT == pAttribute->type)
            {
                if ((sizeof(TAP_AUTH_CONTEXT_PROPERTY) != pAttribute->length) ||
                    (NULL == pAttribute->pStructOfType))
                {
                    status = ERR_INVALID_ARG;
                    DB_PRINT("%s.%d Invalid storage storage heirarchy length=%d, status = %d\n",
                        __FUNCTION__, __LINE__, pAttribute->length, status);
                    goto exit;
                }
                authContext =  *(TAP_AUTH_CONTEXT_PROPERTY *)(pAttribute->pStructOfType);
            }
        }
    }

    authHandle = (TAP_AUTH_CONTEXT_PLATFORM == authContext) ?
                    TPM2_RH_PLATFORM : TPM2_RH_OWNER;

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Wait on Mutex for module - %p, failed with error= %d\n",
                __FUNCTION__, __LINE__, moduleHandle, status);
        goto exit;
    }
    moduleLocked = TRUE;

    status = TPM2_evictKey(pSmpContext, objectId, authHandle);
    if (OK != status)
    {
        DB_PRINT("%s.%d TPM2_deleteObject failed, status = %d\n",
                __FUNCTION__, __LINE__, status);
    }

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);
    return status;
}

#endif

#ifdef __SMP_ENABLE_SMP_CC_PERSIST_OBJECT__

static MSTATUS TPM2_persistObject(
    SMP_Context *pSmpContext,
    CACHED_KeyInfo *pKeyObject,
    TAP_Buffer *pObjectId)
{
    TPM2B_NAME keyName = { 0 };
    MSTATUS status;
    TSS2_RC rc;
    TAP_ObjectId objectId = 0x00L;
    ubyte4 i = 0;

    /* pSmpContext and pKeyObject already checked for NULL */
    if (NULL == pObjectId || NULL == pObjectId->pBuffer)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input\n",
                __FUNCTION__, __LINE__);
        goto exit;
    }

    if (pObjectId->bufferLen > 8)
    {
        status = ERR_INVALID_INPUT;
        DB_PRINT("%s.%d Invalid Id Length of %d for tpm2\n",
                __FUNCTION__, __LINE__, pObjectId->bufferLen);
        goto exit;
    }

    for (i = 0; i < pObjectId->bufferLen; i++)
    {
        /* convert byte array as a big Endian integer */
        objectId |= ( ((TAP_ObjectId) (pObjectId->pBuffer[i])) << (8 * (pObjectId->bufferLen - 1 - i)) );
    }

    status = DIGI_MEMCPY(
        keyName.name, pKeyObject->keyName.name,
        pKeyObject->keyName.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error copying key name, status - %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }
    keyName.size = pKeyObject->keyName.size;

    rc = FAPI2_MGMT_persistObject(
        pSmpContext->pFapiContext, &keyName, objectId);
    if (rc != TSS2_RC_SUCCESS)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d FAPI2_MGMT_persistObject failed with %d\n",
                __FUNCTION__, __LINE__, rc);
    }

exit:

    return status;
}

MSTATUS SMP_API(TPM2, persistObject,
        TAP_ModuleHandle moduleHandle,
        TAP_ObjectHandle keyHandle,
        TAP_Buffer *pObjectId
)
{
    MSTATUS status = OK;
    SMP_Context *pSmpContext = NULL;
    CACHED_KeyInfo *pKeyObject;
    byteBoolean moduleLocked = FALSE;

    if ((0 == moduleHandle) || (0 == keyHandle))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "keyHandle = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                keyHandle);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pKeyObject = (CACHED_KeyInfo *)((uintptr)keyHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Wait on Mutex for module - %p, failed with error= %d\n",
                __FUNCTION__, __LINE__, moduleHandle, status);
        goto exit;
    }
    moduleLocked = TRUE;

    status = TPM2_persistObject(pSmpContext, pKeyObject, pObjectId);
    if (OK != status)
    {
        DB_PRINT("%s.%d TPM2_deleteObject failed, status = %d\n",
                __FUNCTION__, __LINE__, status);
    }

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_ASSOCIATE_OBJECT_CREDENTIALS__
MSTATUS SMP_API(TPM2, associateObjectCredentials,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_EntityCredentialList *pCredentials
)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    SMP_Context *pSmpContext = NULL;
    ContextSetObjectAuthIn authIn = {0};
    TPM2B_AUTH objAuth = {0};
    CACHED_KeyInfo *pCachedKey = NULL;
    byteBoolean moduleLocked = FALSE;

    if ((0 == moduleHandle) || (0 == objectHandle) ||
            (NULL == pCredentials))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p, "
                "objectHandle = %p, pCredentials = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                objectHandle, pCredentials);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pCachedKey = (CACHED_KeyInfo *)((uintptr)objectHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Wait on Mutex for module - %p, failed with error= %d\n",
                __FUNCTION__, __LINE__, moduleHandle, status);
        goto exit;
    }
    moduleLocked = TRUE;

    TPM2_getEntityCredentials(pCredentials, TAP_ENTITY_TYPE_OBJECT, 0, 0,
                &objAuth);

    authIn.objAuth = objAuth;
    authIn.objName = pCachedKey->keyName;
    authIn.forceUseAuthValue = 1;

    rc = FAPI2_CONTEXT_setObjectAuth(pSmpContext->pFapiContext,
            &authIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to set auth values, "
                "rc 0x%02x\n",
                __FUNCTION__,__LINE__, rc);
    }

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_VERIFY__

#if (defined(__ENABLE_DIGICERT_ECC__)) && (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
/* TODO: Possible to consolidate this with the tpm2EccKeyFromPublicPoint
 * function in sapi2_utils.c depending on how libraries are built.
 */
static MSTATUS tpm2EccKeyFromPublicPoint(
    MOC_ECC(hwAccelDescr hwAccelCtx)
    ECCKey **ppRetKey,
    ubyte4 keyType,
    ubyte4 eccCurveId,
    ubyte *pX,
    ubyte2 xLen,
    ubyte *pY,
    ubyte2 yLen,
    ubyte compressionType
    )
{
    MSTATUS status;
    ubyte *pPoint = NULL;
    ubyte4 pointLen;
    ECCKey *pNewKey = NULL;

    status = ERR_NULL_POINTER;
    if ( (NULL == ppRetKey) || (NULL == pX) || (NULL == pY) )
        goto exit;

    /* This function only allows software key creation.
     */
    status = ERR_EC;
    if (akt_ecc != keyType)
        goto exit;

    /* Create the new key.
     */
    if (OK != (status = CRYPTO_INTERFACE_EC_newKeyEx(
            eccCurveId, &pNewKey, keyType, NULL)))
        goto exit;

    /* Extract the element length
     */
    if (OK != (status = CRYPTO_INTERFACE_EC_getElementByteStringLen(
            pNewKey, &pointLen, keyType)))
        goto exit;

    /* Calculate the point lengths without padded 0's.
     */
    while ( (1 < xLen) && (0 == *pX) )
    {
        pX++;
        xLen--;
    }
    while ( (1 < yLen) && (0 == *pY) )
    {
        pY++;
        yLen--;
    }

    /* Ensure both values are equal to or less then element length.
     */
    status = ERR_BAD_LENGTH;
    if ( (yLen > pointLen) || (xLen > pointLen) )
        goto exit;

    /* Allocate memory for the point.
     */
    if (OK != (status = DIGI_CALLOC((void **) &pPoint, 0x00, pointLen * 2 + 1)))
        goto exit;

    /* Create the point array. The first byte is the compression type. The
     * next part of the array is the x coordinate which is then followed by the
     * y coordinate.
     */
    *pPoint = compressionType;
    if (OK != (status = DIGI_MEMCPY(pPoint + 1 + (pointLen - xLen), pX, xLen)))
        goto exit;

    if (OK != (status = DIGI_MEMCPY(
            pPoint + 1 + pointLen + (pointLen - yLen), pY, yLen)))
        goto exit;

    /* Set the public portion of the ECC key.
     */
    if (OK != (status = CRYPTO_INTERFACE_EC_setKeyParameters( MOC_ECC(hwAccelCtx)
            pNewKey, pPoint, pointLen * 2 + 1, NULL, 0, keyType)))
        goto exit;

    *ppRetKey = pNewKey;
    pNewKey = NULL;

exit:

    if (NULL != pNewKey)
        CRYPTO_INTERFACE_EC_deleteKey((void **) &pNewKey, keyType);

    if (NULL != pPoint)
        DIGI_FREE((void **) &pPoint);

    return status;
}
#endif

MSTATUS SMP_API(TPM2, verify,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_Buffer *pData,
        TAP_Signature *pSignature,
        byteBoolean *pSignatureValid
)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    byteBoolean isSymmetric = FALSE;
    TPM2B_NAME *pKeyName = NULL;
    TPM2B_DIGEST *pDigest = NULL;
    TAP_SymSignature *pSymSignature = NULL;
    AsymVerifySigIn  asymVerifyIn  = { 0 };
    AsymVerifySigOut asymVerifyOut = { 0 };
    SymVerifySigIn   symVerifyIn   = { 0 };
    SymVerifySigOut  symVerifyOut  = { 0 };
    SMP_Context *pSmpContext = NULL;
    CACHED_KeyInfo *pKeyObject = NULL;
    TAP_SIG_SCHEME sigScheme = TAP_SIG_SCHEME_PKCS1_5;
    TAP_Attribute *pAttribute = NULL;
    TAP_OP_EXEC_FLAG opExecFlag = TAP_OP_EXEC_FLAG_SW;
    AsymGetPublicKeyIn pubKeyIn = {0};
    AsymGetPublicKeyOut pubKeyOut = {0};
    ContextGetObjectPublicInfoIn publicInfoIn = {0};
    ContextGetObjectPublicInfoOut publicInfoOut = {0};
    AsymmetricKey asymKey = {0};
    ubyte *pResultBuf = NULL;
    ubyte4 resultBufSize = 0;
    sbyte4 cmpResult = 1;
    intBoolean sigretval = 0;
    static ubyte4 oidLen = SHA256_OID_LEN;
#ifdef __ENABLE_DIGICERT_ECC__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    ECCKey *pEccKey = NULL;
    ubyte4 vfySig;
#else
    PFEPtr r = NULL, s = NULL;
    PFEPtr Qx = NULL, Qy = NULL;
#endif
#endif
    ubyte4 listCount = 0;
    ubyte state=0x00;
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    hwAccelDescr hwAccelCtx = 0;
#endif

    if ((0 == moduleHandle) || (0 == keyHandle)
            || (NULL == pData) || (NULL == pSignature) ||
            (NULL == pSignatureValid))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "keyHandle = %p, pData = %p, pSignature = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                keyHandle, pData, pSignature);
        goto exit;
    }

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    status = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
        goto exit;
#endif

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pKeyObject = (CACHED_KeyInfo *)((uintptr)keyHandle);
    /* TODO RK: Can have utility functions to do conversions since it is done in many places. */
    /* If parameters are provided, use them */
    if (pMechanism && pMechanism->listLen)
    {
        pAttribute = pMechanism->pAttributeList;

        while (listCount < pMechanism->listLen)
        {
            /* handle parameters we need */
            switch (pAttribute->type)
            {
                case TAP_ATTR_SIG_SCHEME:
                    if ((NULL == pAttribute->pStructOfType) ||
                            (sizeof(TAP_SIG_SCHEME) != pAttribute->length))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid parameter %p or length %d\n",
                                __FUNCTION__,__LINE__, pAttribute->pStructOfType,
                                pAttribute->length);
                        goto exit;
                    }
                    sigScheme = *((TAP_SIG_SCHEME *)(pAttribute->pStructOfType));
                    break;

                case TAP_ATTR_OP_EXEC_FLAG:
                    if ((NULL == pAttribute->pStructOfType) ||
                            (sizeof(TAP_OP_EXEC_FLAG) != pAttribute->length))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid parameter %p or length %d\n",
                                __FUNCTION__,__LINE__, pAttribute->pStructOfType,
                                pAttribute->length);
                        goto exit;
                    }
                    opExecFlag = *(TAP_OP_EXEC_FLAG *)(pAttribute->pStructOfType);
                    break;

                default:
                    break;
            }

            pAttribute++;
            listCount++;
        }
    }

    switch (pKeyObject->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
        case TAP_KEY_ALGORITHM_ECC:
            isSymmetric = FALSE;
            break;

        case TAP_KEY_ALGORITHM_AES:
        case TAP_KEY_ALGORITHM_HMAC:
            isSymmetric = TRUE;
            break;

        default:
            status = ERR_TAP_INVALID_ALGORITHM;
            DB_PRINT("%s.%d Invalid key key algorithm %d, status = %d\n",
                    __FUNCTION__,__LINE__, pKeyObject->keyAlgorithm,
                    status);
            goto exit;
            break;
    }

    if (!((TAP_OP_EXEC_FLAG_SW == opExecFlag) ||
                (TAP_OP_EXEC_FLAG_HW == opExecFlag)))
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Unsupported operation execution flag %d\n",
                __FUNCTION__,__LINE__, (int)opExecFlag);
        goto exit;
    }

    if ((TAP_OP_EXEC_FLAG_SW == opExecFlag) && (TRUE == isSymmetric))
    {
        DB_PRINT("%s.%d override software symmetric verification with hardware\n",
                __FUNCTION__,__LINE__);
        opExecFlag = TAP_OP_EXEC_FLAG_HW;
    }

    if (TRUE == isSymmetric)
    {
        pKeyName = &(symVerifyIn.keyName);
        pDigest = &(symVerifyIn.digest);
    }
    else
    {
        /* TAP_SIG_SCHEME_PSS_SHA256 is not supported in s/w, push it h/w */
        if (TAP_SIG_SCHEME_PSS_SHA256 == sigScheme
            && TAP_OP_EXEC_FLAG_SW == opExecFlag)
        {
            DB_PRINT("%s.%d Signing scheme %d not supported in s/w, override "
                    "s/w verification to use hardware\n",
                __FUNCTION__,__LINE__, (int)sigScheme);
            opExecFlag = TAP_OP_EXEC_FLAG_HW;
        }

        if (TAP_OP_EXEC_FLAG_SW == opExecFlag)
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            if ((TAP_SIG_SCHEME_PSS_SHA1 == sigScheme) ||
                (TAP_SIG_SCHEME_PSS_SHA256 == sigScheme))
            {
                DB_PRINT("%s.%d Signing scheme %d not supported by cryptointerface\n",
                    __FUNCTION__,__LINE__, (int)sigScheme);
                status = ERR_INVALID_ARG;
                goto exit;
            }
#endif
            status = RTOS_mutexWait(pSmpContext->moduleMutex);
            if (OK != status)
            {
                DB_PRINT("%s.%d Wait on Mutex for module - %p, failed with error= %d\n",
                        __FUNCTION__, __LINE__, pSmpContext, status);
                goto exit;
            }

            /* Get Public key */
            pubKeyIn.keyName = pKeyObject->keyName;
            rc = FAPI2_ASYM_getPublicKey(pSmpContext->pFapiContext,
                    &pubKeyIn, &pubKeyOut);
            if (TSS2_RC_SUCCESS != rc)
            {
                status = SMP_TPM2_UTILS_getMocanaError(rc);
                DB_PRINT("%s.%d Failed to get key public, rc = 0x%02x\n",
                        __FUNCTION__, __LINE__, rc);
            }

            RTOS_mutexRelease(pSmpContext->moduleMutex);

            if(OK != status)
                goto exit;

            publicInfoIn.object = pKeyObject->keyName;
            rc = FAPI2_CONTEXT_getObjectPublicInfo(pSmpContext->pFapiContext,
                    &publicInfoIn, &publicInfoOut);
            if (TSS2_RC_SUCCESS != rc)
            {
                status = SMP_TPM2_UTILS_getMocanaError(rc);
                DB_PRINT("%s.%d Failed to get key public info, rc = 0x%02x\n",
                        __FUNCTION__, __LINE__, rc);
                goto exit;
            }

            switch (pubKeyOut.keyAlg)
            {
                case TPM2_ALG_RSA:
                    if (OK > (status = CRYPTO_initAsymmetricKey(&asymKey)))
                    {
                        DB_PRINT(__func__, __LINE__, "Error %d initializing Asymmetric key\n", status);
                        goto exit;
                    }

                    asymKey.type = akt_rsa;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                    status = CRYPTO_INTERFACE_RSA_createKey((void **)&asymKey.key.pRSA, akt_rsa, NULL);
#else
                    status = RSA_createKey(&asymKey.key.pRSA);
#endif

                    if (OK != status)
                    {
                        DB_PRINT(__func__, __LINE__,
                                "Error %d allocating RSA key structure\n", status);
                        goto exit;
                    }

                    state |= APISTATE_RSA_KEY_CREATED;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                    if (OK != (status = CRYPTO_INTERFACE_RSA_setPublicKeyParameters(MOC_RSA(hwAccelCtx) asymKey.key.pRSA,
                                    0x10001,
                                    pubKeyOut.publicKey.rsaPublic.buffer,
                                    pubKeyOut.publicKey.rsaPublic.size, NULL, akt_rsa)))
#else
                    if (OK != (status = RSA_setPublicKeyParameters(MOC_RSA(hwAccelCtx) asymKey.key.pRSA,
                                    0x10001,
                                    pubKeyOut.publicKey.rsaPublic.buffer,
                                    pubKeyOut.publicKey.rsaPublic.size, NULL)))
#endif
                    {
                        DB_PRINT("%s.%d RSA setPublicKey failed, status = %d\n",
                                __FUNCTION__, __LINE__, status);
                        goto exit;
                    }

                    /* Get scheme from input parameter if NULL scheme is set on the key */
                    if (TPM2_ALG_NULL == publicInfoOut.publicInfo.parameters.rsaDetail.scheme.scheme)
                    {
                        if (TAP_SIG_SCHEME_PSS_SHA1 == sigScheme)
                        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                            if (OK != (status = CRYPTO_INTERFACE_PKCS1_rsassaPssVerify(MOC_RSA(hwAccelCtx)
                                                                      asymKey.key.pRSA, sha1withRSAEncryption,
                                                                      CRYPTO_INTERFACE_PKCS1_MGF1,
                                                                      pData->pBuffer,
                                                                      pData->bufferLen,
                                                                      pSignature->signature.rsaSignature.pSignature,
                                                                      pSignature->signature.rsaSignature.signatureLen,
                                                                      (sbyte4) pData->bufferLen,
                                                                      &sigretval)))
#else
                            if (OK != (status = PKCS1_rsassaPssVerify(MOC_RSA(hwAccelCtx)
                                            asymKey.key.pRSA, sha1withRSAEncryption,
                                            PKCS1_MGF1_FUNC,
                                            pData->pBuffer,
                                            pData->bufferLen,
                                            pSignature->signature.rsaSignature.pSignature,
                                            pSignature->signature.rsaSignature.signatureLen,
                                            (sbyte4) pData->bufferLen,
                                            &sigretval)))
#endif
                            {
                                DB_PRINT(__func__, __LINE__,
                                        "RSA PSS verification failed! status %d = %s\n",
                                        status, MERROR_lookUpErrorCode(status));
                                goto exit;
                            }

                            /* Set result */
                            *pSignatureValid = (byteBoolean)sigretval;
                        }
                        else if (TAP_SIG_SCHEME_PSS_SHA256 == sigScheme)
                        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                            if (OK != (status = CRYPTO_INTERFACE_PKCS1_rsassaPssVerify(MOC_RSA(hwAccelCtx)
                                                                      asymKey.key.pRSA, sha256withRSAEncryption,
                                                                      CRYPTO_INTERFACE_PKCS1_MGF1,
                                                                      pData->pBuffer,
                                                                      pData->bufferLen,
                                                                      pSignature->signature.rsaSignature.pSignature,
                                                                      pSignature->signature.rsaSignature.signatureLen,
                                                                      (sbyte4) pData->bufferLen,
                                                                      &sigretval)))
#else
                            if (OK != (status = PKCS1_rsassaPssVerify(MOC_RSA(hwAccelCtx)
                                            asymKey.key.pRSA, sha256withRSAEncryption,
                                            PKCS1_MGF1_FUNC,
                                            pData->pBuffer,
                                            pData->bufferLen,
                                            pSignature->signature.rsaSignature.pSignature,
                                            pSignature->signature.rsaSignature.signatureLen,
                                            (sbyte4) pData->bufferLen,
                                            &sigretval)))
#endif
                            {
                                DB_PRINT(__func__, __LINE__,
                                        "RSA PSS verification failed! status %d = %s\n",
                                        status, MERROR_lookUpErrorCode(status));

                                goto exit;
                            }
                            /* Set result */
                            *pSignatureValid = (byteBoolean)sigretval;
                        }
                        else
                        {
                            /* Get Output buffer size */
                            resultBufSize =
                                (publicInfoOut.publicInfo.parameters.rsaDetail.keyBits / 8) + oidLen;
                            status = DIGI_CALLOC((void **)&pResultBuf, 1, resultBufSize);
                            if (OK != status)
                            {
                                DB_PRINT("%s.%d Error allocating %d bytes for output signature buffer, status = %d\n",
                                        __FUNCTION__, __LINE__, resultBufSize, status);
                                goto exit;
                            }

                            state |= APISTATE_RESULT_BUFFER_CREATED;

                            /* Setup to get the resulting buffer size */
                            resultBufSize = 0;

                            /* Verify input digest using public key */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                            if (OK != (status = CRYPTO_INTERFACE_RSA_verifySignature(MOC_RSA(hwAccelCtx) asymKey.key.pRSA,
                                            pSignature->signature.rsaSignature.pSignature,
                                            pResultBuf, &resultBufSize, NULL, akt_rsa)))
#else
                            if (OK != (status = RSA_verifySignature(MOC_RSA(hwAccelCtx) asymKey.key.pRSA,
                                            pSignature->signature.rsaSignature.pSignature,
                                            pResultBuf, &resultBufSize, NULL)))
#endif
                            {
                                DB_PRINT(__func__, __LINE__,
                                        "RSA_verifySignature failed! status %d = %s\n",
                                        status, MERROR_lookUpErrorCode(status));
                                goto exit;
                            }

                            if (pData->bufferLen != (resultBufSize - oidLen))
                            {
                                status = ERR_INVALID_ARG;
                                DB_PRINT("%s.%d Mismatched digest size, input digest "
                                        "length %d != key digest size %d\n",
                                        __FUNCTION__, __LINE__, pData->bufferLen,
                                        (resultBufSize - oidLen));
                                goto exit;
                            }

                            /* Compare output, skip the oid added by TPM */
                            if (OK != (status = DIGI_MEMCMP(&pResultBuf[oidLen],
                                        pData->pBuffer, pData->bufferLen,
                                        &cmpResult)))
                            {
                                DB_PRINT(__func__, __LINE__,
                                        "DIGI_MEMCMP failed! status %d = %s\n",
                                        status, MERROR_lookUpErrorCode(status));
                                goto exit;
                            }

                            /* Set result */
                            *pSignatureValid = (0 == cmpResult) ? TRUE : FALSE;
                        }
                    }
                    else
                    {
                        if (TPM2_ALG_RSASSA ==
                                publicInfoOut.publicInfo.parameters.rsaDetail.scheme.scheme)
                        {
                            /* Get Output buffer size */
                            resultBufSize =
                                (publicInfoOut.publicInfo.parameters.rsaDetail.keyBits / 8) + oidLen;
                            status = DIGI_CALLOC((void **)&pResultBuf, 1, resultBufSize);
                            if (OK != status)
                            {
                                DB_PRINT("%s.%d Error allocating %d bytes for output signature buffer, status = %d\n",
                                        __FUNCTION__, __LINE__, resultBufSize, status);
                                goto exit;
                            }

                            state |= APISTATE_RESULT_BUFFER_CREATED;

                            /* Setup to get the resulting buffer size */
                            resultBufSize = 0;

                            /* Verify input digest using public key */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                            if (OK != (status = CRYPTO_INTERFACE_RSA_verifySignature(MOC_RSA(hwAccelCtx) asymKey.key.pRSA,
                                            pSignature->signature.rsaSignature.pSignature,
                                            pResultBuf, &resultBufSize, NULL, akt_rsa)))
#else
                            if (OK != (status = RSA_verifySignature(MOC_RSA(hwAccelCtx) asymKey.key.pRSA,
                                            pSignature->signature.rsaSignature.pSignature,
                                            pResultBuf, &resultBufSize, NULL)))
#endif
                            {
                                DB_PRINT(__func__, __LINE__,
                                        "RSA_verifySignature failed! status %d = %s\n",
                                        status, MERROR_lookUpErrorCode(status));
                                goto exit;
                            }

                            if (pData->bufferLen != (resultBufSize - oidLen))
                            {
                                status = ERR_INVALID_ARG;
                                DB_PRINT("%s.%d Mismatched digest size, input digest "
                                        "length %d != key digest size %d\n",
                                        __FUNCTION__, __LINE__, pData->bufferLen,
                                        (resultBufSize - oidLen));
                                goto exit;
                            }

                            /* Compare output, skip the oid added by TPM */
                            if (OK != (status = DIGI_MEMCMP(&pResultBuf[oidLen],
                                        pData->pBuffer, pData->bufferLen,
                                        &cmpResult)))
                            {
                                DB_PRINT(__func__, __LINE__,
                                        "DIGI_MEMCMP failed! status %d = %s\n",
                                        status, MERROR_lookUpErrorCode(status));
                                goto exit;
                            }

                            /* Set result */
                            *pSignatureValid = (0 == cmpResult) ? TRUE : FALSE;
                        }
                        else if (TPM2_ALG_RSAPSS ==
                                publicInfoOut.publicInfo.parameters.rsaDetail.scheme.scheme)
                        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                            if (OK != (status = CRYPTO_INTERFACE_PKCS1_rsassaPssVerify(MOC_RSA(hwAccelCtx)
                                                                      asymKey.key.pRSA, sha256withRSAEncryption,
                                                                      CRYPTO_INTERFACE_PKCS1_MGF1,
                                                                      pData->pBuffer,
                                                                      pData->bufferLen,
                                                                      pSignature->signature.rsaSignature.pSignature,
                                                                      pSignature->signature.rsaSignature.signatureLen,
                                                                      (sbyte4) pData->bufferLen,
                                                                      &sigretval)))
#else
                            if (OK != (status = PKCS1_rsassaPssVerify(MOC_RSA(hwAccelCtx)
                                            asymKey.key.pRSA, sha256withRSAEncryption,
                                            PKCS1_MGF1_FUNC,
                                            pData->pBuffer,
                                            pData->bufferLen,
                                            pSignature->signature.rsaSignature.pSignature,
                                            pSignature->signature.rsaSignature.signatureLen,
                                            (sbyte4) pData->bufferLen,
                                            &sigretval)))
#endif
                            {
                                DB_PRINT(__func__, __LINE__,
                                        "RSA PSS verification failed! status %d = %s\n",
                                        status, MERROR_lookUpErrorCode(status));
                                goto exit;
                            }

                            /* Set result */
                            *pSignatureValid = (byteBoolean)sigretval;
                        }
                        else
                        {
                            status = ERR_INVALID_ARG;
                            DB_PRINT(__func__, __LINE__,
                                    "Invalid signing scheme %d, status %d = %s\n",
                                    (int)publicInfoOut.publicInfo.parameters.rsaDetail.scheme.scheme,
                                    status, MERROR_lookUpErrorCode(status));
                            goto exit;
                        }
                        break;
#ifdef __ENABLE_DIGICERT_ECC__
                        case TPM2_ALG_ECC:
                        /* Todo: Select the curve from key parameters EC_P256 ?? */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                        status = tpm2EccKeyFromPublicPoint( MOC_ECC(hwAccelCtx)
                            &pEccKey, akt_ecc, cid_EC_P256,
                            publicInfoOut.publicInfo.unique.ecc.x.buffer,
                            publicInfoOut.publicInfo.unique.ecc.x.size,
                            publicInfoOut.publicInfo.unique.ecc.y.buffer,
                            publicInfoOut.publicInfo.unique.ecc.y.size,
                            0x04);
                        if (OK != status)
                            goto exit;

                        status = CRYPTO_INTERFACE_ECDSA_verifySignatureDigest( MOC_ECC(hwAccelCtx)
                            pEccKey, pData->pBuffer, pData->bufferLen,
                            pSignature->signature.eccSignature.pRData,
                            pSignature->signature.eccSignature.rDataLen,
                            pSignature->signature.eccSignature.pSData,
                            pSignature->signature.eccSignature.sDataLen,
                            &vfySig, akt_ecc);
                        if ( (OK != status) || (0 != vfySig) )
                        {
                            DB_PRINT(__func__, __LINE__,
                                    "Failed software verification of TPM signature\n");
                            goto exit;
                        }
                        else
                        {
                            /* Set result */
                            *pSignatureValid = (byteBoolean)sigretval;
                        }

                        CRYPTO_INTERFACE_EC_deleteKey(
                            (void **) &pEccKey, akt_ecc);
#else
                        if (OK != (status = PRIMEFIELD_newElement(EC_P256->pPF, &r)))
                        {
                            goto exit;
                        }

                        if (OK != (status = PRIMEFIELD_newElement(EC_P256->pPF, &s)))
                        {
                            goto exit;
                        }

                        if (OK != (status = PRIMEFIELD_newElement(EC_P256->pPF, &Qx)))
                        {
                            goto exit;
                        }

                        if (OK != (status = PRIMEFIELD_newElement(EC_P256->pPF, &Qy)))
                        {
                            goto exit;
                        }

                        if (OK != (status = PRIMEFIELD_setToByteString(EC_P256->pPF, r,
                                        pSignature->signature.eccSignature.pRData,
                                        pSignature->signature.eccSignature.rDataLen)))
                        {
                            goto exit;
                        }

                        if (OK != (status = PRIMEFIELD_setToByteString(EC_P256->pPF, s,
                                        pSignature->signature.eccSignature.pSData,
                                        pSignature->signature.eccSignature.sDataLen)))
                        {
                            goto exit;
                        }

                        PRIMEFIELD_setToByteString(EC_P256->pPF, Qx,
                                publicInfoOut.publicInfo.unique.ecc.x.buffer,
                                publicInfoOut.publicInfo.unique.ecc.x.size);

                        PRIMEFIELD_setToByteString(EC_P256->pPF, Qy,
                                publicInfoOut.publicInfo.unique.ecc.y.buffer,
                                publicInfoOut.publicInfo.unique.ecc.y.size);

                        if (OK != (status = ECDSA_verifySignature(EC_P256,
                                        Qx, Qy, pData->pBuffer, pData->bufferLen,
                                        r, s)))
                        {
                            DB_PRINT(__func__, __LINE__,
                                    "Failed software verification of TPM signature\n");
                            goto exit;
                        }
                        else
                        {
                            /* Set result */
                            *pSignatureValid = (byteBoolean)sigretval;
                        }

                        /* Free Memory */
                        PRIMEFIELD_deleteElement(EC_P256->pPF, &r);
                        PRIMEFIELD_deleteElement(EC_P256->pPF, &s);
                        PRIMEFIELD_deleteElement(EC_P256->pPF, &Qx);
                        PRIMEFIELD_deleteElement(EC_P256->pPF, &Qy);

                        r = NULL;
                        s = NULL;
                        Qx = NULL;
                        Qy = NULL;
#endif
                        break;
#endif
                        default:
                        break;
                    }

                    goto exit;
            }
        }

        pKeyName = &(asymVerifyIn.keyName);
        pDigest = &(asymVerifyIn.digest);
    }

    *pKeyName = pKeyObject->keyName;

    /* Copy the digest on which the signature is to be verified */
    status = DIGI_MEMCPY(pDigest->buffer,
                        pData->pBuffer,
                        pData->bufferLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy digest, status = %d\n",
                    __FUNCTION__,__LINE__, status);
        goto exit;
    }
    pDigest->size = pData->bufferLen;

    if (TRUE == isSymmetric)
    {
        switch(pKeyObject->keyAlgorithm)
        {
            case TAP_KEY_ALGORITHM_AES:
                pSymSignature = (TAP_SymSignature *)&(pSignature->signature.aesSignature);
                break;

            case TAP_KEY_ALGORITHM_HMAC:
                pSymSignature = (TAP_SymSignature *)&(pSignature->signature.hmacSignature);
                break;

            default:
                status = ERR_TAP_INVALID_ALGORITHM;
                DB_PRINT("%s.%d Invalid key algorithm %d, status = %d\n",
                        __FUNCTION__,__LINE__, (int)pKeyObject->keyAlgorithm,
                        status);
                goto exit;
                break;
        }

        symVerifyIn.signature.size = pSymSignature->signatureLen;
        status = DIGI_MEMCPY(symVerifyIn.signature.buffer,
                pSymSignature->pSignature,
                pSymSignature->signatureLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy key signature, status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
    }
    else   /* Have an asymmetric key */
    {
        /* copy the sig scheme and hash alg */
        switch (sigScheme)
        {
            case TAP_SIG_SCHEME_PKCS1_5:
                asymVerifyIn.sigScheme = TPM2_ALG_RSASSA;
                asymVerifyIn.hashAlg = TPM2_ALG_SHA256;
                break;
            case TAP_SIG_SCHEME_PSS_SHA1:
                asymVerifyIn.sigScheme = TPM2_ALG_RSAPSS;
                asymVerifyIn.hashAlg = TPM2_ALG_SHA1;
                break;
            case TAP_SIG_SCHEME_PSS_SHA256:
                asymVerifyIn.sigScheme = TPM2_ALG_RSAPSS;
                asymVerifyIn.hashAlg = TPM2_ALG_SHA256;
                break;
            case TAP_SIG_SCHEME_PSS_SHA384:
                asymVerifyIn.sigScheme = TPM2_ALG_RSAPSS;
                asymVerifyIn.hashAlg = TPM2_ALG_SHA384;
                break;
            case TAP_SIG_SCHEME_PSS_SHA512:
                asymVerifyIn.sigScheme = TPM2_ALG_RSAPSS;
                asymVerifyIn.hashAlg = TPM2_ALG_SHA512;
                break;
            case TAP_SIG_SCHEME_PKCS1_5_SHA1:
                asymVerifyIn.sigScheme = TPM2_ALG_RSASSA;
                asymVerifyIn.hashAlg = TPM2_ALG_SHA1;
                break;
            case TAP_SIG_SCHEME_PKCS1_5_SHA256:
                asymVerifyIn.sigScheme = TPM2_ALG_RSASSA;
                asymVerifyIn.hashAlg = TPM2_ALG_SHA256;
                break;
            case TAP_SIG_SCHEME_PKCS1_5_SHA384:
                asymVerifyIn.sigScheme = TPM2_ALG_RSASSA;
                asymVerifyIn.hashAlg = TPM2_ALG_SHA384;
                break;
            case TAP_SIG_SCHEME_PKCS1_5_SHA512:
                asymVerifyIn.sigScheme = TPM2_ALG_RSASSA;
                asymVerifyIn.hashAlg = TPM2_ALG_SHA512;
                break;
            case TAP_SIG_SCHEME_NONE:
                asymVerifyIn.sigScheme = TPM2_ALG_NULL;
                asymVerifyIn.hashAlg = TPM2_ALG_NULL;
                break;
            case TAP_SIG_SCHEME_ECDSA_SHA1:
                asymVerifyIn.sigScheme = TPM2_ALG_ECDSA;
                asymVerifyIn.hashAlg = TPM2_ALG_SHA1;
                break;
            case TAP_SIG_SCHEME_ECDSA_SHA256:
                asymVerifyIn.sigScheme = TPM2_ALG_ECDSA;
                asymVerifyIn.hashAlg = TPM2_ALG_SHA256;
                break;
            case TAP_SIG_SCHEME_ECDSA_SHA384:
                asymVerifyIn.sigScheme = TPM2_ALG_ECDSA;
                asymVerifyIn.hashAlg = TPM2_ALG_SHA384;
                break;
            case TAP_SIG_SCHEME_ECDSA_SHA512:
                asymVerifyIn.sigScheme = TPM2_ALG_ECDSA;
                asymVerifyIn.hashAlg = TPM2_ALG_SHA512;
                break;
            default:
                status = ERR_TAP_INVALID_ALGORITHM;
                DB_PRINT("%s.%d Invalid signing scheme %d, status = %d\n",
                    	__FUNCTION__,__LINE__, (int)sigScheme,
                    	status);
                goto exit;
        }

        /* Copy to signature to verify */
        switch (pKeyObject->keyAlgorithm)
        {
            case TAP_KEY_ALGORITHM_RSA:
                asymVerifyIn.signature.rsaSignature.size = pSignature->signature.rsaSignature.signatureLen;
                status = DIGI_MEMCPY(asymVerifyIn.signature.rsaSignature.buffer,
                        pSignature->signature.rsaSignature.pSignature,
                        asymVerifyIn.signature.rsaSignature.size);
                break;

            case TAP_KEY_ALGORITHM_ECC:
                asymVerifyIn.signature.eccSignature.signatureR.size = pSignature->signature.eccSignature.rDataLen;
                status = DIGI_MEMCPY(asymVerifyIn.signature.eccSignature.signatureR.buffer,
                        pSignature->signature.eccSignature.pRData,
                        asymVerifyIn.signature.eccSignature.signatureR.size);

                asymVerifyIn.signature.eccSignature.signatureS.size = pSignature->signature.eccSignature.sDataLen;
                status = DIGI_MEMCPY(asymVerifyIn.signature.eccSignature.signatureS.buffer,
                        pSignature->signature.eccSignature.pSData,
                        asymVerifyIn.signature.eccSignature.signatureS.size);

                break;

            default:
                status = ERR_TAP_INVALID_ALGORITHM;
                DB_PRINT("%s.%d Invalid key algorithm %d, status = %d\n",
                        __FUNCTION__,__LINE__, (int)pKeyObject->keyAlgorithm,
                        status);
                break;
        }
        if(OK != status)
        {
            DB_PRINT("%s.%d Failed copying signature, error=%d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }
    }

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Wait on Mutex failed with error= %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    state |= APISTATE_MODULE_MUTEX_LOCKED;

    if (TRUE == isSymmetric)
        rc = FAPI2_SYM_verifySig(pSmpContext->pFapiContext, &symVerifyIn, &symVerifyOut);
    else
        rc = FAPI2_ASYM_verifySig(pSmpContext->pFapiContext, &asymVerifyIn, &asymVerifyOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to verify signature, rc = 0x%02x\n", __FUNCTION__, __LINE__,
                rc);
        goto exit;
    }

    if (TRUE == isSymmetric)
        *pSignatureValid = symVerifyOut.sigValid;
    else
        *pSignatureValid = asymVerifyOut.sigValid;

exit:
#ifdef __ENABLE_DIGICERT_ECC__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (pEccKey)
        CRYPTO_INTERFACE_EC_deleteKey((void **) &pEccKey, akt_ecc);
#else
    if (r && EC_P256->pPF)
        PRIMEFIELD_deleteElement(EC_P256->pPF, &r);

    if (s && EC_P256->pPF)
        PRIMEFIELD_deleteElement(EC_P256->pPF, &s);

    if (Qx && EC_P256->pPF)
        PRIMEFIELD_deleteElement(EC_P256->pPF, &Qx);

    if (Qy && EC_P256->pPF)
        PRIMEFIELD_deleteElement(EC_P256->pPF, &Qy);
#endif
#endif

    if (state & APISTATE_MODULE_MUTEX_LOCKED)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    if (state & APISTATE_RSA_KEY_CREATED)
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_RSA_freeKey((void **)&asymKey.key.pRSA, NULL, akt_rsa);
#else
        RSA_freeKey(&asymKey.key.pRSA, NULL);
#endif

    if (state & APISTATE_RESULT_BUFFER_CREATED)
    {
        if (OK != DIGI_FREE((void **)&pResultBuf))
        {
            DB_PRINT("%s.%d Failed to free memory allocated for result buffer\n",
                    __FUNCTION__, __LINE__);
        }
    }

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
#endif

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_VERIFY_INIT__
MSTATUS SMP_API(TPM2, verifyInit,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_OperationContext *pOpContext
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_VERIFY_UPDATE__
MSTATUS SMP_API(TPM2, verifyUpdate,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_OperationContext opContext,
        TAP_Buffer *pBuffer
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_VERIFY_FINAL__
MSTATUS SMP_API(TPM2, verifyFinal,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_OperationContext opContext,
        byteBoolean *pSignatureValid
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SIGN_DIGEST__
MSTATUS SMP_API(TPM2, signDigest,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_Buffer *pDigest,
        TAP_SIG_SCHEME sigScheme,
        TAP_SignAttributes *pSignatureAttributes,
        TAP_Signature **ppSignature
)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    byteBoolean isSymmetric = FALSE;
    AsymSignIn  asymSignIn  = { 0 };
    AsymSignOut asymSignOut = { 0 };
    SymSignIn   symSignIn   = { 0 };
    SymSignOut  symSignOut  = { 0 };
    TPM2B_DIGEST *pSignDigest = NULL;
    TPM2B_NAME *pKeyName = NULL;
    TAP_SymSignature *pSymSignature = NULL;
    TAP_RSASignature *pRsaSignature = NULL;
    TAP_ECCSignature *pEccSignature = NULL;
    SMP_Context *pSmpContext = NULL;
    CACHED_KeyInfo *pKeyObject = NULL;
    byteBoolean moduleLocked = FALSE;

    if ((0 == moduleHandle) || (0 == keyHandle)
        || (NULL == pDigest) || (NULL == ppSignature))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "keyHandle = %p, pDigest = %p, ppSignature = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                keyHandle, pDigest, ppSignature);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pKeyObject = (CACHED_KeyInfo *)((uintptr)keyHandle);

    switch (pKeyObject->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
        case TAP_KEY_ALGORITHM_ECC:
            isSymmetric = FALSE;
            break;

        default:
            isSymmetric = TRUE;
            break;
    }

    if (TRUE == isSymmetric)
    {
        pKeyName = &(symSignIn.keyName);
        pSignDigest = &(symSignIn.signDigest);
    }
    else
    {
        pKeyName = &(asymSignIn.keyName);
        pSignDigest = &(asymSignIn.signDigest);
    }

    if (sizeof(pSignDigest->buffer) < pDigest->bufferLen)
    {
        status = ERR_BUFFER_OVERFLOW;
        DB_PRINT("%s.%d Error, Digest length of %d exceeds max limit of %d, status = %d\n",
                __FUNCTION__, __LINE__, pDigest->bufferLen,
                sizeof(pSignDigest->buffer), status);
        goto exit;
    }

    /* Copy the key handle */
    *pKeyName = pKeyObject->keyName;

    pSignDigest->size = pDigest->bufferLen;
    status = DIGI_MEMCPY(pSignDigest->buffer, pDigest->pBuffer,
                        pSignDigest->size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed copying digest buffer, status - %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    if (FALSE == isSymmetric)
    {
        switch (sigScheme)
        {
            case TAP_SIG_SCHEME_PKCS1_5:
                asymSignIn.sigScheme = TPM2_ALG_RSASSA;
                asymSignIn.hashAlg = TPM2_ALG_SHA256;
                break;
            case TAP_SIG_SCHEME_PSS_SHA1:
                asymSignIn.sigScheme = TPM2_ALG_RSAPSS;
                asymSignIn.hashAlg = TPM2_ALG_SHA1;
                break;
            case TAP_SIG_SCHEME_PSS_SHA256:
                asymSignIn.sigScheme = TPM2_ALG_RSAPSS;
                asymSignIn.hashAlg = TPM2_ALG_SHA256;
                break;
            case TAP_SIG_SCHEME_PSS_SHA384:
                asymSignIn.sigScheme = TPM2_ALG_RSAPSS;
                asymSignIn.hashAlg = TPM2_ALG_SHA384;
                break;
            case TAP_SIG_SCHEME_PSS_SHA512:
                asymSignIn.sigScheme = TPM2_ALG_RSAPSS;
                asymSignIn.hashAlg = TPM2_ALG_SHA512;
                break;
            case TAP_SIG_SCHEME_PKCS1_5_SHA1:
                asymSignIn.sigScheme = TPM2_ALG_RSASSA;
                asymSignIn.hashAlg = TPM2_ALG_SHA1;
                break;
            case TAP_SIG_SCHEME_PKCS1_5_SHA256:
                asymSignIn.sigScheme = TPM2_ALG_RSASSA;
                asymSignIn.hashAlg = TPM2_ALG_SHA256;
                break;
            case TAP_SIG_SCHEME_PKCS1_5_SHA384:
                asymSignIn.sigScheme = TPM2_ALG_RSASSA;
                asymSignIn.hashAlg = TPM2_ALG_SHA384;
                break;
            case TAP_SIG_SCHEME_PKCS1_5_SHA512:
                asymSignIn.sigScheme = TPM2_ALG_RSASSA;
                asymSignIn.hashAlg = TPM2_ALG_SHA512;
                break;
            case TAP_SIG_SCHEME_NONE:
                asymSignIn.sigScheme = TPM2_ALG_NULL;
                asymSignIn.hashAlg = TPM2_ALG_NULL;
                break;
            case TAP_SIG_SCHEME_ECDSA_SHA1:
                asymSignIn.sigScheme = TPM2_ALG_ECDSA;
                asymSignIn.hashAlg = TPM2_ALG_SHA1;
                break;
            case TAP_SIG_SCHEME_ECDSA_SHA256:
                asymSignIn.sigScheme = TPM2_ALG_ECDSA;
                asymSignIn.hashAlg = TPM2_ALG_SHA256;
                break;
            case TAP_SIG_SCHEME_ECDSA_SHA384:
                asymSignIn.sigScheme = TPM2_ALG_ECDSA;
                asymSignIn.hashAlg = TPM2_ALG_SHA384;
                break;
            case TAP_SIG_SCHEME_ECDSA_SHA512:
                asymSignIn.sigScheme = TPM2_ALG_ECDSA;
                asymSignIn.hashAlg = TPM2_ALG_SHA512;
                break;
            default:
                status = ERR_TAP_INVALID_ALGORITHM;
                break;
        }
        if (OK != status)
        {
            DB_PRINT("%s.%d Error, Invalid algorithm selected, status = %d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }
    }

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error, Failed waiting on mutex for module - %p"
                ", status - %d\n",
                __FUNCTION__, __LINE__, pSmpContext, status);
        goto exit;
    }
    moduleLocked = TRUE;

    if (TRUE == isSymmetric)
        rc = FAPI2_SYM_sign(pSmpContext->pFapiContext, &symSignIn, &symSignOut);
    else
        rc = FAPI2_ASYM_sign(pSmpContext->pFapiContext, &asymSignIn, &asymSignOut);

    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to sign, rc = 0x%02x\n", __FUNCTION__, __LINE__,
                rc);
        goto exit;
    }

    RTOS_mutexRelease(pSmpContext->moduleMutex);
    moduleLocked = FALSE;

    status = DIGI_CALLOC((void **)ppSignature, 1, sizeof(**ppSignature));

    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for signature structure, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    switch (pKeyObject->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
            (*ppSignature)->keyAlgorithm = TAP_KEY_ALGORITHM_RSA;
            break;

        case TAP_KEY_ALGORITHM_ECC:
            (*ppSignature)->keyAlgorithm = TAP_KEY_ALGORITHM_ECC;
            break;

        case TAP_KEY_ALGORITHM_HMAC:
            (*ppSignature)->keyAlgorithm = TAP_KEY_ALGORITHM_HMAC;
            break;

        case TAP_KEY_ALGORITHM_AES:
            (*ppSignature)->keyAlgorithm = TAP_KEY_ALGORITHM_AES;
            break;

        default:
            status = ERR_TAP_INVALID_ALGORITHM;
            goto exit;
            break;
    }

    if (TRUE == isSymmetric)
    {
        switch((*ppSignature)->keyAlgorithm)
        {
            case TAP_KEY_ALGORITHM_HMAC:
                pSymSignature = &((*ppSignature)->signature.hmacSignature);
                break;

            case TAP_KEY_ALGORITHM_AES:
                pSymSignature = &((*ppSignature)->signature.aesSignature);
                break;

            default:
                status = ERR_TAP_INVALID_ALGORITHM;
                goto exit;
                break;
        }

        pSymSignature->signatureLen = symSignOut.signature.size;
        status = DIGI_CALLOC((void **)&(pSymSignature->pSignature), 1,
                                    pSymSignature->signatureLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Unable to allocate memory for signature buffer, status = %d\n",
                __FUNCTION__, __LINE__, status);
            goto exit;
        }
        status = DIGI_MEMCPY((ubyte *)(pSymSignature->pSignature),
                            (ubyte *)(symSignOut.signature.buffer),
                             pSymSignature->signatureLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy signature, status = %d\n",
                            __FUNCTION__,__LINE__, status);
            goto exit;
        }
    }
    else /* Have asymmetric key */
    {
        switch (asymSignOut.keyAlg)
        {
            case TPM2_ALG_RSA:
                pRsaSignature = &((*ppSignature)->signature.rsaSignature);
                pRsaSignature->signatureLen =
                    (ubyte4)(asymSignOut.signature.rsaSignature.size);
                status = DIGI_CALLOC((void **)&(pRsaSignature->pSignature), 1,
                        pRsaSignature->signatureLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Unable to allocate memory for "
                            "signature buffer, status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                status = DIGI_MEMCPY((ubyte *)(pRsaSignature->pSignature),
                        (ubyte *)(asymSignOut.signature.rsaSignature.buffer),
                        pRsaSignature->signatureLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed to copy signature, status = %d\n",
                            __FUNCTION__,__LINE__, status);
                    goto exit;
                }
                break;

            case TPM2_ALG_ECC:
                pEccSignature = &((*ppSignature)->signature.eccSignature);
                /* Copy R data */
                pEccSignature->rDataLen =
                    (ubyte4)(asymSignOut.signature.eccSignature.signatureR.size);
                status = DIGI_CALLOC((void **)&(pEccSignature->pRData), 1,
                        pEccSignature->rDataLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Unable to allocate memory for "
                            "signature buffer, status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                status = DIGI_MEMCPY((ubyte *)(pEccSignature->pRData),
                        (ubyte *)(asymSignOut.signature.eccSignature.signatureR.buffer),
                        pEccSignature->rDataLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed to copy signature, status = %d\n",
                            __FUNCTION__,__LINE__, status);
                    goto exit;
                }

                /* Copy S data */

                pEccSignature->sDataLen =
                    (ubyte4)(asymSignOut.signature.eccSignature.signatureS.size);
                status = DIGI_CALLOC((void **)&(pEccSignature->pSData), 1,
                        pEccSignature->sDataLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Unable to allocate memory for "
                            "signature buffer, status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                status = DIGI_MEMCPY((ubyte *)(pEccSignature->pSData),
                        (ubyte *)(asymSignOut.signature.eccSignature.signatureS.buffer),
                        pEccSignature->sDataLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed to copy signature, status = %d\n",
                            __FUNCTION__,__LINE__, status);
                    goto exit;
                }
                break;

            default:
                goto exit;
                break;
        }
    }

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    if (OK != status)
    {
        if (ppSignature)
        {
            if (pSymSignature)
            {
                if (pSymSignature->pSignature)
                    DIGI_FREE((void **)&pSymSignature->pSignature);
            }
            if (pRsaSignature)
            {
                if (pRsaSignature->pSignature)
                    DIGI_FREE((void **)&pRsaSignature->pSignature);
            }
            if (pEccSignature)
            {
                if (pEccSignature->pRData)
                    DIGI_FREE((void **)&pEccSignature->pRData);

                if (pEccSignature->pSData)
                    DIGI_FREE((void **)&pEccSignature->pSData);
            }

            DIGI_FREE((void **)ppSignature);
        }
    }

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_DIGEST__
MSTATUS SMP_API(TPM2, digest,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_Buffer *pInputBuffer,
        TAP_Buffer *pBuffer
)
{
    MSTATUS status = OK;
    SMP_Context *pSmpContext = NULL;
    TOKEN_Context *pToken = NULL;
    DataDigestIn digestIn = {0};
    DataDigestOut digestOut = {0};
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    static TAP_HASH_ALG hashAlg = TAP_HASH_ALG_SHA256;
    TAP_Attribute *pAttribute = NULL;
    ubyte4 listCount = 0;
    byteBoolean moduleLocked = FALSE;

    if ((0 == moduleHandle) || (0 == tokenHandle) ||
            (NULL == pInputBuffer) || (NULL == pBuffer))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "tokenHandle = %p, pInputBuffer = %p\n"
                "pBuffer = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                tokenHandle, pInputBuffer, pBuffer);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pToken = (TOKEN_Context *)((uintptr)tokenHandle);

    if (pMechanism && pMechanism->listLen)
    {
        pAttribute = pMechanism->pAttributeList;

        while (listCount < pMechanism->listLen)
        {
            /* handle parameters we need */
            if (TAP_ATTR_HASH_ALG == pAttribute->type)
            {
                if ((sizeof(hashAlg) != pAttribute->length) ||
                        (NULL == pAttribute->pStructOfType))
                {
                    status = ERR_INVALID_ARG;
                    DB_PRINT("%s.%d Invalid hash algorithm length %d, status = %d\n",
                        __FUNCTION__, __LINE__, pAttribute->length, status);
                    goto exit;
                }

                switch (*(TAP_HASH_ALG *)pAttribute->pStructOfType)
                {
                    case TAP_HASH_ALG_SHA256:
                        hashAlg = TPM2_ALG_SHA256;
                        break;

                    case TAP_HASH_ALG_SHA384:
                        hashAlg = TPM2_ALG_SHA384;
                        break;

                    case TAP_HASH_ALG_SHA512:
                        hashAlg = TPM2_ALG_SHA512;
                        break;

                    default:
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Unsupported hash algorithm %d, "
                                "status 0x%02x\n",
                                __FUNCTION__,__LINE__,
                                *((TAP_HASH_ALG *)(pAttribute->pStructOfType)),
                                status);
                        goto exit;
                }
            }

            pAttribute++;
            listCount++;
        }
    }

    digestIn.hashAlg = hashAlg;
    digestIn.pBuffer = pInputBuffer->pBuffer;
    digestIn.bufferLen = pInputBuffer->bufferLen;

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting on module mutex for module - %p\n",
                __FUNCTION__, __LINE__, moduleHandle);
        goto exit;
    }
    moduleLocked = TRUE;

    rc = FAPI2_DATA_digest(pSmpContext->pFapiContext,
            &digestIn, &digestOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to compute digest, rc = 0x%02x\n", __FUNCTION__,
                __LINE__, rc);
        goto exit;
    }

    status = DIGI_MALLOC((void **)&pBuffer->pBuffer, digestOut.digest.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error allocating %d bytes for output buffer, "
                "status = %d\n",
                __FUNCTION__,__LINE__, digestOut.digest.size,
                status);
        goto exit;
    }

    status = DIGI_MEMCPY(pBuffer->pBuffer, digestOut.digest.buffer,
            digestOut.digest.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error copying %d bytes to output buffer, "
                "status = %d\n",
                __FUNCTION__,__LINE__, digestOut.digest.size,
                status);
        goto exit;
    }

    pBuffer->bufferLen = digestOut.digest.size;

exit:
    if (OK != status)
    {
        if (OK != DIGI_FREE((void **)&pBuffer->pBuffer))
           DB_PRINT("%s.%d Failed freeing memory from out buffer on failure\n",
                   __FUNCTION__, __LINE__);
    }

    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SIGN_BUFFER__
static MSTATUS getTpm2SignatureSchemeAndHashAlgo(TAP_SIG_SCHEME sigScheme,
                                                TPMI_ALG_SIG_SCHEME *pSigScheme,
                                                TPMI_ALG_HASH *pHashAlgo)
{
    MSTATUS status = OK;

    switch (sigScheme)
    {
        case TAP_SIG_SCHEME_PKCS1_5:
            *pSigScheme = TPM2_ALG_RSASSA;
            *pHashAlgo = TPM2_ALG_SHA256;
            break;
        case TAP_SIG_SCHEME_PSS_SHA1:
            *pSigScheme = TPM2_ALG_RSAPSS;
            *pHashAlgo = TPM2_ALG_SHA1;
            break;
        case TAP_SIG_SCHEME_PSS_SHA256:
            *pSigScheme = TPM2_ALG_RSAPSS;
            *pHashAlgo = TPM2_ALG_SHA256;
            break;
        case TAP_SIG_SCHEME_PSS_SHA384:
            *pSigScheme = TPM2_ALG_RSAPSS;
            *pHashAlgo = TPM2_ALG_SHA384;
            break;
        case TAP_SIG_SCHEME_PSS_SHA512:
            *pSigScheme = TPM2_ALG_RSAPSS;
            *pHashAlgo = TPM2_ALG_SHA512;
            break;
        case TAP_SIG_SCHEME_PKCS1_5_SHA1:
            *pSigScheme = TPM2_ALG_RSASSA;
            *pHashAlgo = TPM2_ALG_SHA1;
            break;
        case TAP_SIG_SCHEME_PKCS1_5_SHA256:
            *pSigScheme = TPM2_ALG_RSASSA;
            *pHashAlgo = TPM2_ALG_SHA256;
            break;
        case TAP_SIG_SCHEME_PKCS1_5_SHA384:
            *pSigScheme = TPM2_ALG_RSASSA;
            *pHashAlgo = TPM2_ALG_SHA384;
            break;
        case TAP_SIG_SCHEME_PKCS1_5_SHA512:
            *pSigScheme = TPM2_ALG_RSASSA;
            *pHashAlgo = TPM2_ALG_SHA512;
            break;
        case TAP_SIG_SCHEME_NONE:
            *pSigScheme = TPM2_ALG_NULL;
            *pHashAlgo = TPM2_ALG_NULL;
            break;
        case TAP_SIG_SCHEME_ECDSA_SHA1:
            *pSigScheme = TPM2_ALG_ECDSA;
            *pHashAlgo = TPM2_ALG_SHA1;
            break;
        case TAP_SIG_SCHEME_ECDSA_SHA256:
            *pSigScheme = TPM2_ALG_ECDSA;
            *pHashAlgo = TPM2_ALG_SHA256;
            break;
        case TAP_SIG_SCHEME_ECDSA_SHA384:
            *pSigScheme = TPM2_ALG_ECDSA;
            *pHashAlgo = TPM2_ALG_SHA384;
            break;
        case TAP_SIG_SCHEME_ECDSA_SHA512:
            *pSigScheme = TPM2_ALG_ECDSA;
            *pHashAlgo = TPM2_ALG_SHA512;
            break;
        default:
            status = ERR_TAP_INVALID_ALGORITHM;
    }

    return status;
}

MSTATUS SMP_API(TPM2, signBuffer,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_Buffer *pData,
        TAP_SIG_SCHEME signScheme,
        TAP_SignAttributes *pSignatureAttributes,
        TAP_Signature **ppSignature
)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    AsymRestrictedSignIn asymSignIn  = { 0 };
    AsymRestrictedSignOut asymSignOut = { 0 };
    TPM2B_NAME *pKeyName = NULL;
    TAP_RSASignature *pRsaSignature = NULL;
    TAP_ECCSignature *pEccSignature = NULL;
    SMP_Context *pSmpContext = NULL;
    CACHED_KeyInfo *pKeyObject;
    byteBoolean moduleLocked = FALSE;

    if ((0 == moduleHandle) || (0 == keyHandle)
            || (NULL == pData) || (NULL == ppSignature))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "pObjectHandle = %p, pData = %p, ppSignature = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                keyHandle, pData, ppSignature);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pKeyObject = (CACHED_KeyInfo *)((uintptr)keyHandle);

    switch (pKeyObject->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
        case TAP_KEY_ALGORITHM_ECC:
            break;

        case TAP_KEY_ALGORITHM_HMAC:
            return(symSignHmac(moduleHandle, tokenHandle, keyHandle, signScheme, pSignatureAttributes,
                    pData, ppSignature));
            break;

        default:
            status = ERR_TAP_INVALID_ALGORITHM;
            DB_PRINT("%s.%d Unsupported key algorithm %d, status = %d\n",
                    __FUNCTION__,__LINE__, (int)pKeyObject->keyAlgorithm,
                    status);
            goto exit;
            break;
    }

    pKeyName = &(asymSignIn.keyName);

    /* Copy the key handle */
    status = DIGI_MEMCPY(pKeyName->name,
            pKeyObject->keyName.name,
            pKeyObject->keyName.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error copying key name, status - %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }
    pKeyName->size = pKeyObject->keyName.size;

    asymSignIn.bufferLen = pData->bufferLen;
    asymSignIn.pBuffer = pData->pBuffer;

    /* Set the signature scheme and hash algorithm. This will be passed to the
     * FAPI2 layer which may or may not use the signature scheme and hash
     * algorithm set here.
     *
     * Typically, if the TAP key is created with a particular signature scheme
     * the FAPI2 layer will only use that signature scheme, thus the signature
     * scheme being set here which is based on the caller will be ignored. The
     * same applies for the hash algorithm.
     *
     * Now, if the TAP key is created with a generic signature algorithm then
     * the FAPI2 layer expects the caller to provide the signature scheme and
     * hash algorithm.
     *
     * Since the underlying key creation algorithm is unknown at this point,
     * always set the appropriate signature scheme and hash algorithm based on
     * the signature scheme provided by the caller in case the FAPI2 layer uses
     * it.
     */
    status = getTpm2SignatureSchemeAndHashAlgo(
        signScheme, &(asymSignIn.sigScheme), &(asymSignIn.hashAlg));
    if (OK != status)
    {
        DB_PRINT("%s.%d Invalid algorithm selected, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error waiting on mutex for module - %p, status - %d\n",
                __FUNCTION__, __LINE__, pSmpContext, status);
        goto exit;
    }
    moduleLocked = TRUE;

    rc = FAPI2_ASYM_restrictedSign(pSmpContext->pFapiContext, &asymSignIn, &asymSignOut);

    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to sign, rc = 0x%02x\n", __FUNCTION__, __LINE__,
                rc);
        goto exit;
    }

    RTOS_mutexRelease(pSmpContext->moduleMutex);
    moduleLocked = FALSE;

    status = DIGI_CALLOC((void **)ppSignature, 1, sizeof(**ppSignature));

    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for "
                "signature structure, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    switch (pKeyObject->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
            (*ppSignature)->keyAlgorithm = TAP_KEY_ALGORITHM_RSA;
            break;

        case TAP_KEY_ALGORITHM_ECC:
            (*ppSignature)->keyAlgorithm = TAP_KEY_ALGORITHM_ECC;
            break;

        default:
            status = ERR_TAP_INVALID_ALGORITHM;
            goto exit;
            break;
    }

    switch (asymSignOut.keyAlg)
    {
        case TPM2_ALG_RSA:
            pRsaSignature = &((*ppSignature)->signature.rsaSignature);
            pRsaSignature->signatureLen =
                (ubyte4)(asymSignOut.signature.rsaSignature.size);
            status = DIGI_CALLOC((void **)&(pRsaSignature->pSignature), 1,
                    pRsaSignature->signatureLen);
            if (OK != status)
            {
                DB_PRINT("%s.%d Unable to allocate memory for signature buffer"
                        ", status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }
            status = DIGI_MEMCPY((ubyte *)(pRsaSignature->pSignature),
                    (ubyte *)(asymSignOut.signature.rsaSignature.buffer),
                    pRsaSignature->signatureLen);
            if (OK != status)
            {
                DB_PRINT("%s.%d Unable to copy signature buffer"
                        ", status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }
            break;

        case TPM2_ALG_ECC:
            pEccSignature = &((*ppSignature)->signature.eccSignature);
            /* Copy R data */
            pEccSignature->rDataLen =
                (ubyte4)(asymSignOut.signature.eccSignature.signatureR.size);
            status = DIGI_CALLOC((void **)&(pEccSignature->pRData), 1,
                    pEccSignature->rDataLen);
            if (OK != status)
            {
                DB_PRINT("%s.%d Unable to allocate memory for signature buffer"
                        ", status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }
            status = DIGI_MEMCPY((ubyte *)(pEccSignature->pRData),
                    (ubyte *)(asymSignOut.signature.eccSignature.signatureR.buffer),
                    pEccSignature->rDataLen);
            if (OK != status)
            {
                DB_PRINT("%s.%d Unable to copy signature buffer"
                        ", status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }

            /* Copy S data */

            pEccSignature->sDataLen =
                (ubyte4)(asymSignOut.signature.eccSignature.signatureS.size);
            status = DIGI_CALLOC((void **)&(pEccSignature->pSData), 1,
                    pEccSignature->sDataLen);
            if (OK != status)
            {
                DB_PRINT("%s.%d Unable to allocate memory for signature buffer"
                        ", status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }
            status = DIGI_MEMCPY((ubyte *)(pEccSignature->pSData),
                    (ubyte *)(asymSignOut.signature.eccSignature.signatureS.buffer),
                    pEccSignature->sDataLen);
            if (OK != status)
            {
                DB_PRINT("%s.%d Unable to copy signature buffer"
                        ", status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }
            break;

        default:
            goto exit;
            break;
    }

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    if (OK != status)
    {
        if (ppSignature)
        {
            if (pRsaSignature)
            {
                if (pRsaSignature->pSignature)
                    DIGI_FREE((void **)&pRsaSignature->pSignature);
            }
            if (pEccSignature)
            {
                if (pEccSignature->pRData)
                    DIGI_FREE((void **)&pEccSignature->pRData);

                if (pEccSignature->pSData)
                    DIGI_FREE((void **)&pEccSignature->pSData);
            }

            DIGI_FREE((void **)ppSignature);
        }
    }

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SIGN_INIT__
MSTATUS SMP_API(TPM2, signInit,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_SIG_SCHEME type,
        TAP_SignAttributes *pSignatureAttributes,
        TAP_OperationContext *pOpContext
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SIGN_UPDATE__
MSTATUS SMP_API(TPM2, signUpdate,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_Buffer *pBuffer,
        TAP_OperationContext opContext
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SIGN_FINAL__
MSTATUS SMP_API(TPM2, signFinal,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_OperationContext opContext,
        TAP_Signature **ppSignature
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif
#ifdef __SMP_ENABLE_SMP_CC_FREE_SIGNATURE_BUFFER__
MSTATUS SMP_API(TPM2, freeSignatureBuffer,
        TAP_Signature **ppSignature
)
{
    MSTATUS status = OK;

    if ((NULL == ppSignature) || (NULL == *ppSignature))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input,  ppSignature = %p",
                __FUNCTION__, __LINE__, ppSignature);
        goto exit;
    }

    switch ((*ppSignature)->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
            if ((*ppSignature)->signature.rsaSignature.pSignature)
            {
                status = DIGI_FREE((void **)&(*ppSignature)->signature.rsaSignature.pSignature);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error, Failed freeing memory from "
                            "RSA signature buffer, Status - %d\n",
                            __FUNCTION__, __LINE__, status);
                }
            }
            break;

        case TAP_KEY_ALGORITHM_ECC:
            if ((*ppSignature)->signature.eccSignature.pRData)
            {
                status = DIGI_FREE((void **)&(*ppSignature)->signature.eccSignature.pRData);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error, Failed freeing memory from "
                            "ECC signature buffer, Status - %d\n",
                            __FUNCTION__, __LINE__, status);
                }
            }
            if ((OK == status) && ((*ppSignature)->signature.eccSignature.pSData))
            {
                status = DIGI_FREE((void **)&(*ppSignature)->signature.eccSignature.pSData);
                if (OK != status)
                    DB_PRINT("%s.%d Error, Failed freeing memory from "
                            "ECC signature buffer, Status - %d\n",
                            __FUNCTION__, __LINE__, status);
            }
            break;

        case TAP_KEY_ALGORITHM_DSA:
            if ((*ppSignature)->signature.dsaSignature.pRData)
            {
                status = DIGI_FREE((void **)&(*ppSignature)->signature.dsaSignature.pRData);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error, Failed freeing memory from "
                            "DSA signature buffer, Status - %d\n",
                            __FUNCTION__, __LINE__, status);
                }
            }
            if ((OK == status) && ((*ppSignature)->signature.dsaSignature.pSData))
            {
                status = DIGI_FREE((void **)&(*ppSignature)->signature.dsaSignature.pSData);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error, Failed freeing memory from "
                            "DSA signature buffer, Status - %d\n",
                            __FUNCTION__, __LINE__, status);
                }
            }
            break;

        case TAP_KEY_ALGORITHM_AES:
            if ((*ppSignature)->signature.aesSignature.pSignature)
            {
                status = DIGI_FREE((void **)&(*ppSignature)->signature.aesSignature.pSignature);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error, Failed freeing memory from "
                            "AES signature buffer, Status - %d\n",
                            __FUNCTION__, __LINE__, status);
                }
            }
            break;

        case TAP_KEY_ALGORITHM_HMAC:
            if ((*ppSignature)->signature.hmacSignature.pSignature)
            {
                status = DIGI_FREE((void **)&(*ppSignature)->signature.hmacSignature.pSignature);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error, Failed freeing memory from "
                            "HMAC signature buffer, Status - %d\n",
                            __FUNCTION__, __LINE__, status);
                }
            }
            break;

        default:
            break;
    }

    if (OK == status)
    {
        status = DIGI_FREE((void **)ppSignature);
        if (OK != status)
        {
            DB_PRINT("%s.%d Error, Failed freeing memory of "
                    "Signature structure, Status - %d\n",
                    __FUNCTION__, __LINE__, status);
        }
    }

exit:
    return status;
}
#endif


#if (defined __SMP_ENABLE_SMP_CC_DECRYPT__) || (defined __SMP_ENABLE_SMP_CC_ENCRYPT__)
/*------------------------------------------------------------------*/
static MSTATUS TPM2_symEncryptDecrypt(SMP_Context *pSmpContext,
                                       byteBoolean isDecrypt,
                                       SymEncryptDecryptIn *pEncryptDecryptIn,
                                       SymEncryptDecryptOut *pEncryptDecryptOut,
                                       CACHED_KeyInfo *pKeyObject,
                                       TAP_ENC_SCHEME encScheme,
                                       TAP_Buffer *pLabel,
                                       TAP_Buffer *pData)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_RC_SUCCESS;
    ubyte iv[TPM2_MAX_SYM_BLOCK_SIZE] = {0};
    TAP_SYM_KEY_MODE symMode = TAP_SYM_KEY_MODE_UNDEFINED;
    byteBoolean moduleLocked = FALSE;

    if ((NULL == pSmpContext) || (NULL == pEncryptDecryptIn) ||
            (NULL == pEncryptDecryptOut) || (NULL == pData) ||
            (NULL == pKeyObject))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, pSmpContext = %p, "
                "pEncryptDecryptIn = %p, pEncryptDecryptOut = %p, "
                "pData = %p, pKeyObject = %p\n",
                __FUNCTION__, __LINE__, pSmpContext,
                pEncryptDecryptIn, pEncryptDecryptOut, pData,
                pKeyObject);
        goto exit;
    }
    /* Copy the key handle */
    if (TRUE == isDecrypt)
    {
        status = DIGI_MEMCPY(pEncryptDecryptIn->keyName.name,
                pKeyObject->keyName.name,
                pKeyObject->keyName.size);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy key name during decrypt operation, status = %d\n",
                            __FUNCTION__,__LINE__, status);
            goto exit;
        }
        pEncryptDecryptIn->keyName.size = pKeyObject->keyName.size;
    }
    else
    {
        status = DIGI_MEMCPY(pEncryptDecryptIn->keyName.name,
                pKeyObject->keyName.name,
                pKeyObject->keyName.size);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy key name during encrypt operation, status = %d\n",
                            __FUNCTION__,__LINE__, status);
            goto exit;
        }
        pEncryptDecryptIn->keyName.size = pKeyObject->keyName.size;
    }

    switch (symMode)
    {
        case TAP_SYM_KEY_MODE_CTR:
            pEncryptDecryptIn->symMode = TPM2_ALG_CTR;
            break;
        case TAP_SYM_KEY_MODE_OFB:
            pEncryptDecryptIn->symMode = TPM2_ALG_OFB;
            break;
        case TAP_SYM_KEY_MODE_CBC:
            pEncryptDecryptIn->symMode = TPM2_ALG_CBC;
            break;
        case TAP_SYM_KEY_MODE_CFB:
            pEncryptDecryptIn->symMode = TPM2_ALG_CFB;
            break;
        case TAP_SYM_KEY_MODE_ECB:
            pEncryptDecryptIn->symMode = TPM2_ALG_ECB;
            break;
        case TAP_SYM_KEY_MODE_UNDEFINED:
            pEncryptDecryptIn->symMode = TPM2_ALG_NULL;
            break;
        default:
            status = ERR_TAP_INVALID_SYM_MODE;
            DB_PRINT("%s.%d Invalid symmetric mode %d, status = %d\n",
                __FUNCTION__,__LINE__, (int)symMode, status);
            goto exit;
    }

    /* Copy the data to be encrypted or decrypted */
    pEncryptDecryptIn->bufferLen = pData->bufferLen;
    pEncryptDecryptIn->pBuffer = pData->pBuffer;

    status = DIGI_MEMCPY(pEncryptDecryptIn->iv.buffer, iv, sizeof(iv));
    if (OK != status)
    {
        DB_PRINT("%s.%d Error copying buffer, status - %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    pEncryptDecryptIn->iv.size = sizeof(iv);

    pEncryptDecryptIn->isDecryption = isDecrypt;

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting on mutex for module - %p, status - %d\n",
                __FUNCTION__, __LINE__, pSmpContext, status);
        goto exit;
    }
    moduleLocked = TRUE;

    rc = FAPI2_SYM_encryptDecrypt(pSmpContext->pFapiContext, pEncryptDecryptIn, pEncryptDecryptOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to encrypt data, rc = 0x%02x\n",
                __FUNCTION__, __LINE__, rc);
        goto exit;
    }

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    return status;
}


/*------------------------------------------------------------------*/

static MSTATUS TPM2_asymDecrypt(SMP_Context *pSmpContext,
                             AsymRsaDecryptIn *pDecryptIn,
                             AsymRsaDecryptOut *pDecryptOut,
                             CACHED_KeyInfo *pKeyObject,
                             TAP_ENC_SCHEME encScheme,
                             TAP_Buffer *pLabel,
                             TAP_Buffer *pData)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_RC_SUCCESS;
    byteBoolean moduleLocked = FALSE;

    if ((NULL == pSmpContext) || (NULL == pDecryptIn) ||
            (NULL == pDecryptOut) || (NULL == pKeyObject))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, pSmpContext = %p,"
                "pDecryptIn = %p, pDecryptOut = %p, "
                "pKeyObject = %p\n",
                __FUNCTION__, __LINE__, pSmpContext,
                pDecryptIn, pDecryptOut, pKeyObject);
        goto exit;
    }

    /* Copy the key handle */
    status = DIGI_MEMCPY(pDecryptIn->keyName.name,
            pKeyObject->keyName.name,
            pKeyObject->keyName.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy key name, status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    pDecryptIn->keyName.size = pKeyObject->keyName.size;

    /* copy the sig scheme and hash alg */
    switch (encScheme)
    {
        case TAP_ENC_SCHEME_PKCS1_5:
            pDecryptIn->scheme = TPM2_ALG_RSAES;
            pDecryptIn->hashAlg = TPM2_ALG_SHA256;
            break;
        case TAP_ENC_SCHEME_OAEP_SHA1:
            pDecryptIn->scheme = TPM2_ALG_OAEP;
            pDecryptIn->hashAlg = TPM2_ALG_SHA1;
            break;
        case TAP_ENC_SCHEME_OAEP_SHA256:
            pDecryptIn->scheme = TPM2_ALG_OAEP;
            pDecryptIn->hashAlg = TPM2_ALG_SHA256;
            break;
        case TAP_ENC_SCHEME_OAEP_SHA384:
            pDecryptIn->scheme = TPM2_ALG_OAEP;
            pDecryptIn->hashAlg = TPM2_ALG_SHA384;
            break;
        case TAP_ENC_SCHEME_OAEP_SHA512:
            pDecryptIn->scheme = TPM2_ALG_OAEP;
            pDecryptIn->hashAlg = TPM2_ALG_SHA512;
            break;
        case TAP_ENC_SCHEME_NONE:
            pDecryptIn->scheme = TPM2_ALG_NULL;
            pDecryptIn->hashAlg = TPM2_ALG_SHA256;
            break;
        default:
            status = ERR_TAP_INVALID_SCHEME;
            DB_PRINT("%s.%d Invalid encryption scheme specified - %d\n",
                    __FUNCTION__, __LINE__, encScheme);
            goto exit;
    }

    if (pLabel && pLabel->bufferLen)
    {
        if (sizeof(pDecryptIn->label.buffer) < pLabel->bufferLen)
        {
            status = ERR_BUFFER_OVERFLOW;
            DB_PRINT("%s.%d Error, Label length of %d exceeds max limit of %d, status = %d\n",
                __FUNCTION__, __LINE__, pLabel->bufferLen,
                sizeof(pDecryptIn->label.buffer), status);
            goto exit;
        }

        pDecryptIn->label.size = pLabel->bufferLen;
        status = DIGI_MEMCPY(pDecryptIn->label.buffer,
                pLabel->pBuffer, pLabel->bufferLen);

        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy key label, status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
    }

    /* Copy the data to be encrypted */
    status = DIGI_MEMCPY(pDecryptIn->cipherText.buffer,
                        pData->pBuffer,
                        pData->bufferLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy cipher text, status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }
    pDecryptIn->cipherText.size = pData->bufferLen;

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting on mutex for module- %p, status- %d\n",
                __FUNCTION__, __LINE__, pSmpContext, status);
        goto exit;
    }
    moduleLocked = TRUE;

    rc = FAPI2_ASYM_RSAdecrypt(pSmpContext->pFapiContext, pDecryptIn, pDecryptOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to decrypt data, rc = 0x%02x\n",
                __FUNCTION__, __LINE__,
                rc);
        goto exit;
    }

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS TPM2_asymEncrypt(SMP_Context *pSmpContext,
        AsymRsaEncryptIn *pEncryptIn,
        AsymRsaEncryptOut *pEncryptOut,
        CACHED_KeyInfo *pKeyObject, TAP_ENC_SCHEME encScheme,
        TAP_Buffer *pLabel, TAP_Buffer *pDataToEncrypt)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_RC_SUCCESS;
    byteBoolean moduleLocked = FALSE;

    if ((NULL == pSmpContext) || (NULL == pEncryptIn) ||
            (NULL == pEncryptOut) || (NULL == pKeyObject))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, pSmpContext = %p,"
                "pEncryptIn = %p, pEncryptOut = %p, pKeyObject = %p\n",
                __FUNCTION__, __LINE__, pSmpContext, pEncryptIn,
                pEncryptOut, pKeyObject);
        goto exit;
    }

    /* Copy the key handle */
    status = DIGI_MEMCPY(pEncryptIn->keyName.name,
            pKeyObject->keyName.name,
            pKeyObject->keyName.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy key name, status = %d\n",
                __FUNCTION__,__LINE__, status);

        goto exit;
    }

    pEncryptIn->keyName.size = pKeyObject->keyName.size;

    /* copy the sig scheme and hash alg, if provided */
    switch (encScheme)
    {
        case TAP_ENC_SCHEME_PKCS1_5:
            pEncryptIn->scheme = TPM2_ALG_RSAES;
            pEncryptIn->hashAlg = TPM2_ALG_SHA256;
            break;
        case TAP_ENC_SCHEME_OAEP_SHA1:
            pEncryptIn->scheme = TPM2_ALG_OAEP;
            pEncryptIn->hashAlg = TPM2_ALG_SHA1;
            break;
        case TAP_ENC_SCHEME_OAEP_SHA256:
            pEncryptIn->scheme = TPM2_ALG_OAEP;
            pEncryptIn->hashAlg = TPM2_ALG_SHA256;
            break;
        case TAP_ENC_SCHEME_OAEP_SHA384:
            pEncryptIn->scheme = TPM2_ALG_OAEP;
            pEncryptIn->hashAlg = TPM2_ALG_SHA384;
            break;
        case TAP_ENC_SCHEME_OAEP_SHA512:
            pEncryptIn->scheme = TPM2_ALG_OAEP;
            pEncryptIn->hashAlg = TPM2_ALG_SHA512;
            break;
        case TAP_ENC_SCHEME_NONE:
            pEncryptIn->scheme = TPM2_ALG_NULL;
            pEncryptIn->hashAlg = TPM2_ALG_SHA256;
            break;
        default:
            status = ERR_TAP_INVALID_SCHEME;
            DB_PRINT("%s.%d Invalid key encryption %d, status = %d\n",
                    __FUNCTION__,__LINE__, (int)encScheme,
                    status);
            goto exit;
    }

    if (pLabel && pLabel->bufferLen)
    {
        if (sizeof(pEncryptIn->label.buffer) < pLabel->bufferLen)
        {
            status = ERR_BUFFER_OVERFLOW;
            DB_PRINT("%s.%d Error, Label length of %d exceeds max limit of %d, status = %d\n",
                __FUNCTION__, __LINE__, pLabel->bufferLen,
                sizeof(pEncryptIn->label.buffer), status);
            goto exit;
        }

        /* Copy label */
        status = DIGI_MEMCPY(pEncryptIn->label.buffer,
                pLabel->pBuffer, pLabel->bufferLen);

        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy key label, status = %d\n",
                            __FUNCTION__,__LINE__, status);
            goto exit;
        }

        pEncryptIn->label.size = pLabel->bufferLen;
    }

    if (sizeof(pEncryptIn->message.buffer) < pDataToEncrypt->bufferLen)
    {
        status = ERR_BUFFER_OVERFLOW;
        DB_PRINT("%s.%d Error, Message length of %d exceeds max limit of %d, status = %d\n",
                __FUNCTION__, __LINE__, pDataToEncrypt->bufferLen,
                sizeof(pEncryptIn->message.buffer), status);
        goto exit;
    }

    /* Copy the data to be encrypted */
    status = DIGI_MEMCPY(pEncryptIn->message.buffer,
                        pDataToEncrypt->pBuffer,
                        pDataToEncrypt->bufferLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy message, status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    pEncryptIn->message.size = pDataToEncrypt->bufferLen;

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting on mutex for module- %p, status- %d\n",
                __FUNCTION__, __LINE__, pSmpContext, status);
        goto exit;
    }
    moduleLocked = TRUE;

    rc = FAPI2_ASYM_RSAencrypt(pSmpContext->pFapiContext, pEncryptIn, pEncryptOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to encrypt data, rc = 0x%02x\n",
                __FUNCTION__, __LINE__,
                rc);
        goto exit;
    }

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_ENCRYPT__
MSTATUS SMP_API(TPM2, encrypt,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_Buffer *pBuffer,
        TAP_Buffer *pCipherBuffer
)
{
    MSTATUS status = OK;
    byteBoolean isSymmetric = FALSE;
    CACHED_KeyInfo *pKeyObject = NULL;
    TAP_ENC_SCHEME encScheme = TAP_ENC_SCHEME_NONE;
    TAP_Buffer *pLabel = NULL;
    AsymRsaEncryptIn encryptIn = { 0 };
    AsymRsaEncryptOut encryptOut = { 0 };
    SymEncryptDecryptIn encryptDecryptIn = { 0 };
    SymEncryptDecryptOut encryptDecryptOut = { 0 };
    SMP_Context *pSmpContext = NULL;
    TAP_Attribute *pAttribute = NULL;
    AsymmetricKey asymKey = {0};
    AsymGetPublicKeyIn pubKeyIn = {0};
    AsymGetPublicKeyOut pubKeyOut = {0};
    TSS2_RC rc = TSS2_RC_SUCCESS;
    TAP_OP_EXEC_FLAG opExecFlag = TAP_OP_EXEC_FLAG_SW;
    ContextGetObjectPublicInfoIn publicInfoIn = {0};
    ContextGetObjectPublicInfoOut publicInfoOut = {0};
    ubyte *pSoftwareCipherBuffer = NULL;
    ubyte4 softwareCipherBufferLen = 0;
#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    hwAccelDescr hwAccelCtx = 0;
#endif
    vlong* pVlongQueue = NULL;
    ubyte4 listCount = 0;
    ubyte state = 0x00;

    if ((0 == moduleHandle) || (0 == keyHandle)
        || (NULL == pBuffer) || (NULL == pCipherBuffer))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, pModuleHandle = %p,"
                "pObjectHandle = %p, pBuffer = %p, pCipherBuffer = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                keyHandle, pBuffer, pCipherBuffer);
        goto exit;
    }

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    status = HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx);
    if (OK != status)
        goto exit;
#endif
    
    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pKeyObject = (CACHED_KeyInfo *)((uintptr)keyHandle);

    /* If parameters are provided, use them */
    if (pMechanism && pMechanism->listLen)
    {
        pAttribute = pMechanism->pAttributeList;

        while (listCount < pMechanism->listLen)
        {
            /* handle parameters we need */
            switch (pAttribute->type)
            {
                case TAP_ATTR_ENC_SCHEME:
                    if ((sizeof(TAP_ENC_SCHEME) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid encryption scheme length %d, status = %d\n",
                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    encScheme = *((TAP_ENC_SCHEME *)(pAttribute->pStructOfType));
                    break;

                case TAP_ATTR_OP_EXEC_FLAG:
                    if ((NULL == pAttribute->pStructOfType) ||
                            (sizeof(TAP_OP_EXEC_FLAG) != pAttribute->length))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid parameter %p or length %d\n",
                                __FUNCTION__,__LINE__, pAttribute->pStructOfType,
                                pAttribute->length);
                        goto exit;
                    }
                    opExecFlag = *(TAP_OP_EXEC_FLAG *)(pAttribute->pStructOfType);
                    break;

                case TAP_ATTR_ENC_LABEL:
                    pLabel = (TAP_Buffer *)(pAttribute->pStructOfType);
                    break;

                default:
                    break;
            }

            pAttribute++;
            listCount++;
        }
    }

    switch (pKeyObject->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
        case TAP_KEY_ALGORITHM_ECC:
            isSymmetric = FALSE;
            break;

        case TAP_KEY_ALGORITHM_AES:
        case TAP_KEY_ALGORITHM_HMAC:
            isSymmetric = TRUE;
            break;

        default:
            status = ERR_TAP_INVALID_ALGORITHM;
            DB_PRINT("%s.%d Invalid key algorithm %d, status = %d\n",
                    __FUNCTION__, __LINE__, (int)pKeyObject->keyAlgorithm,
                    status);
            goto exit;
    }

    if (!((TAP_OP_EXEC_FLAG_SW == opExecFlag) ||
                (TAP_OP_EXEC_FLAG_HW == opExecFlag)))
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Unsupported operation execution flag %d\n",
                __FUNCTION__,__LINE__, (int)opExecFlag);
        goto exit;
    }

    if (FALSE == isSymmetric)
    {
        if (TAP_OP_EXEC_FLAG_SW == opExecFlag)
        {
            status = RTOS_mutexWait(pSmpContext->moduleMutex);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed waiting on mutex for module- %p, "
                        "status-%d\n",
                        __FUNCTION__, __LINE__, pSmpContext, status);
                goto exit;
            }
            /* Get Public key */
            pubKeyIn.keyName = pKeyObject->keyName;
            rc = FAPI2_ASYM_getPublicKey(pSmpContext->pFapiContext,
                    &pubKeyIn, &pubKeyOut);

            RTOS_mutexRelease(pSmpContext->moduleMutex);

            if (TSS2_RC_SUCCESS != rc)
            {
                status = SMP_TPM2_UTILS_getMocanaError(rc);
                DB_PRINT("%s.%d Failed to get public key, "
                        "rc 0x%02x\n",
                        __FUNCTION__,__LINE__, rc);
                goto exit;
            }

            status = RTOS_mutexWait(pSmpContext->moduleMutex);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed waiting on mutex for module- %p, "
                        "status-%d\n",
                        __FUNCTION__, __LINE__, pSmpContext, status);
                goto exit;
            }

            /* Get Public key information */
            publicInfoIn.object = pKeyObject->keyName;
            rc = FAPI2_CONTEXT_getObjectPublicInfo(pSmpContext->pFapiContext,
                    &publicInfoIn, &publicInfoOut);

            RTOS_mutexRelease(pSmpContext->moduleMutex);
            if (TSS2_RC_SUCCESS != rc)
            {
                status = SMP_TPM2_UTILS_getMocanaError(rc);
                DB_PRINT("%s.%d Failed to get public key information, "
                        "rc 0x%02x\n",
                        __FUNCTION__,__LINE__, rc);
                goto exit;
            }

            if (TPM2_ALG_RSA == pubKeyOut.keyAlg)
            {
                if (OK > (status = CRYPTO_initAsymmetricKey(&asymKey)))
                {
                    DB_PRINT(__func__, __LINE__, "Error %d initializing Asymmetric key\n", status);
                    goto exit;
                }

                asymKey.type = akt_rsa;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                status = CRYPTO_INTERFACE_RSA_createKey((void **)&asymKey.key.pRSA, akt_rsa, NULL);
#else
                status = RSA_createKey(&asymKey.key.pRSA);
#endif

                if (OK != status)
                {
                    DB_PRINT(__func__, __LINE__,
                            "Error %d allocating RSA key structure\n", status);
                    goto exit;
                }
                state |= APISTATE_RSA_KEY_CREATED;

                /* The TPM default exponent is 0x10001 */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                if (OK != (status = CRYPTO_INTERFACE_RSA_setPublicKeyParameters(MOC_RSA(hwAccelCtx) asymKey.key.pRSA,
                                publicInfoOut.publicInfo.parameters.rsaDetail.exponent,
                                pubKeyOut.publicKey.rsaPublic.buffer,
                                pubKeyOut.publicKey.rsaPublic.size, &pVlongQueue, akt_rsa)))
#else
                if (OK != (status = RSA_setPublicKeyParameters(MOC_RSA(hwAccelCtx) asymKey.key.pRSA,
                                publicInfoOut.publicInfo.parameters.rsaDetail.exponent,
                                pubKeyOut.publicKey.rsaPublic.buffer,
                                pubKeyOut.publicKey.rsaPublic.size, &pVlongQueue)))
#endif
                {
                    DB_PRINT("%s.%d RSA setPublicKey failed, status = %d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }

                /* General key will not have enc scheme set in the public info
                    Use the input scheme
                    */
                if (TPM2_ALG_NULL ==
                        publicInfoOut.publicInfo.parameters.rsaDetail.scheme.scheme)
                {
                    if (TAP_ENC_SCHEME_OAEP_SHA256 == encScheme)
                    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                        if (OK != CRYPTO_INTERFACE_PKCS1_rsaOaepEncrypt( MOC_RSA(hwAccelCtx)
                            g_pRandomContext, asymKey.key.pRSA,
                            sha256withRSAEncryption, MOC_PKCS1_ALG_MGF1,
                            sha256withRSAEncryption, pBuffer->pBuffer,
                            pBuffer->bufferLen,
                            pLabel ? pLabel->pBuffer : NULL,
                            pLabel ? pLabel->bufferLen : 0,
                            &pSoftwareCipherBuffer,
                            &softwareCipherBufferLen))
#else
                        if (OK != PKCS1_rsaesOaepEncrypt( MOC_RSA(hwAccelCtx)
                                    g_pRandomContext, asymKey.key.pRSA,
                                    sha256withRSAEncryption, PKCS1_MGF1_FUNC,
                                    pBuffer->pBuffer, pBuffer->bufferLen,
                                    pLabel ? pLabel->pBuffer : NULL,
                                    pLabel ? pLabel->bufferLen : 0,
                                    &pSoftwareCipherBuffer, &softwareCipherBufferLen))
#endif
                        {
                            DB_PRINT("%s.%d Failed software OAEP encryption, "
                                    "status = %d\n", __FUNCTION__, __LINE__, status);
                            goto exit;
                        }
                    }
                    else if (TAP_ENC_SCHEME_OAEP_SHA1 == encScheme)
                    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                        if (OK != CRYPTO_INTERFACE_PKCS1_rsaOaepEncrypt( MOC_RSA(hwAccelCtx)
                            g_pRandomContext, asymKey.key.pRSA,
                            sha1withRSAEncryption, MOC_PKCS1_ALG_MGF1,
                            sha1withRSAEncryption, pBuffer->pBuffer,
                            pBuffer->bufferLen,
                            pLabel ? pLabel->pBuffer : NULL,
                            pLabel ? pLabel->bufferLen : 0,
                            &pSoftwareCipherBuffer,
                            &softwareCipherBufferLen))
#else
                        if (OK != PKCS1_rsaesOaepEncrypt( MOC_RSA(hwAccelCtx)
                                    g_pRandomContext, asymKey.key.pRSA,
                                    sha1withRSAEncryption, PKCS1_MGF1_FUNC,
                                    pBuffer->pBuffer, pBuffer->bufferLen,
                                    pLabel ? pLabel->pBuffer : NULL,
                                    pLabel ? pLabel->bufferLen : 0,
                                    &pSoftwareCipherBuffer, &softwareCipherBufferLen))
#endif
                        {
                            DB_PRINT("%s.%d Failed software OAEP encryption, "
                                    "status = %d\n", __FUNCTION__, __LINE__, status);
                            goto exit;
                        }
                    }
                    else if (TAP_ENC_SCHEME_PKCS1_5 == encScheme)
                    {
                        softwareCipherBufferLen =
                            publicInfoOut.publicInfo.parameters.rsaDetail.keyBits / 8;

                        status = DIGI_CALLOC((void **)&pSoftwareCipherBuffer, 1,
                                softwareCipherBufferLen);
                        if (OK != status)
                        {
                            DB_PRINT("%s.%d Failed to allocate %d bytes for "
                                    "software cipher buffer, status = %d\n",
                                    __FUNCTION__, __LINE__,
                                    softwareCipherBufferLen, status);
                            goto exit;
                        }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                        if (OK != (status = CRYPTO_INTERFACE_RSA_encrypt(MOC_RSA(hwAccelCtx) asymKey.key.pRSA,
                                        pBuffer->pBuffer, pBuffer->bufferLen,
                                        pSoftwareCipherBuffer, RANDOM_rngFun,
                                        g_pRandomContext, NULL, akt_rsa)))
#else
                        if (OK != (status = RSA_encrypt(MOC_RSA(hwAccelCtx) asymKey.key.pRSA,
                                        pBuffer->pBuffer, pBuffer->bufferLen,
                                        pSoftwareCipherBuffer, RANDOM_rngFun,
                                        g_pRandomContext, NULL)))
#endif
                        {
                            DB_PRINT("%s.%d Failed software PKCSV1.5 encryption, "
                                    "status = %d\n", __FUNCTION__, __LINE__, status);
                            goto exit;
                        }
                    }
                    else
                    {
                        softwareCipherBufferLen =
                            publicInfoOut.publicInfo.parameters.rsaDetail.keyBits / 8;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                        status = CRYPTO_INTERFACE_RSA_applyPublicKeyAux ( MOC_RSA(hwAccelCtx)
                            asymKey.key.pRSA, pBuffer->pBuffer, pBuffer->bufferLen,
                            &pSoftwareCipherBuffer, NULL);
#else
                        status = RSA_applyPublicKey ( MOC_RSA(hwAccelCtx)
                            asymKey.key.pRSA, pBuffer->pBuffer, pBuffer->bufferLen,
                            &pSoftwareCipherBuffer, NULL);
#endif
                        if (OK != status)
                        {
                            DB_PRINT("%s.%d Failed software raw encryption, "
                                    "status = %d\n", __FUNCTION__, __LINE__, status);
                            goto exit;
                        }
                    }
                }
                else
                {
                    /* Software encrypt */
                    if (TPM2_ALG_OAEP ==
                            publicInfoOut.publicInfo.parameters.rsaDetail.scheme.scheme)
                    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                        if (OK != CRYPTO_INTERFACE_PKCS1_rsaOaepEncrypt( MOC_RSA(hwAccelCtx)
                            g_pRandomContext, asymKey.key.pRSA,
                            sha256withRSAEncryption, MOC_PKCS1_ALG_MGF1,
                            sha256withRSAEncryption, pBuffer->pBuffer,
                            pBuffer->bufferLen,
                            pLabel ? pLabel->pBuffer : NULL,
                            pLabel ? pLabel->bufferLen : 0,
                            &pSoftwareCipherBuffer,
                            &softwareCipherBufferLen))
#else
                        if (OK != PKCS1_rsaesOaepEncrypt( MOC_RSA(hwAccelCtx)
                                    g_pRandomContext, asymKey.key.pRSA,
                                    sha256withRSAEncryption, PKCS1_MGF1_FUNC,
                                    pBuffer->pBuffer, pBuffer->bufferLen,
                                    pLabel ? pLabel->pBuffer : NULL,
                                    pLabel ? pLabel->bufferLen : 0,
                                    &pSoftwareCipherBuffer, &softwareCipherBufferLen))
#endif
                        {
                            DB_PRINT("%s.%d Failed software OAEP encryption, "
                                    "status = %d\n", __FUNCTION__, __LINE__, status);
                            goto exit;
                        }
                    }
                    else
                    {
                        softwareCipherBufferLen =
                            publicInfoOut.publicInfo.parameters.rsaDetail.keyBits / 8;

                        status = DIGI_CALLOC((void **)&pSoftwareCipherBuffer, 1,
                                softwareCipherBufferLen);
                        if (OK != status)
                        {
                            DB_PRINT("%s.%d Failed to allocate %d bytes for "
                                    "software cipher buffer, status = %d\n",
                                    __FUNCTION__, __LINE__,
                                    softwareCipherBufferLen, status);
                            goto exit;
                        }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
                        if (OK != (status = CRYPTO_INTERFACE_RSA_encrypt(MOC_RSA(hwAccelCtx) asymKey.key.pRSA,
                                        pBuffer->pBuffer, pBuffer->bufferLen,
                                        pSoftwareCipherBuffer, RANDOM_rngFun,
                                        g_pRandomContext, NULL, akt_rsa)))
#else
                        if (OK != (status = RSA_encrypt(MOC_RSA(hwAccelCtx) asymKey.key.pRSA,
                                        pBuffer->pBuffer, pBuffer->bufferLen,
                                        pSoftwareCipherBuffer, RANDOM_rngFun,
                                        g_pRandomContext, NULL)))
#endif
                        {
                            DB_PRINT("%s.%d Failed software PKCSV1.5 encryption, "
                                    "status = %d\n", __FUNCTION__, __LINE__, status);
                            goto exit;
                        }
                    }
                }

                pCipherBuffer->pBuffer = pSoftwareCipherBuffer;
                pCipherBuffer->bufferLen = softwareCipherBufferLen;


                goto exit;
            }
        }
        else
        {
            status = TPM2_asymEncrypt(pSmpContext, &encryptIn,
                &encryptOut, pKeyObject, encScheme, pLabel, pBuffer);
            if (OK != status)
            {
                DB_PRINT("%s.%d Asymmetric encryption failed, status - %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }
        }
    }
    else
    {
        status = TPM2_symEncryptDecrypt(pSmpContext,
                0, &encryptDecryptIn, &encryptDecryptOut, pKeyObject,
                encScheme, pLabel, pBuffer);
        if (OK != status)
        {
            DB_PRINT("%s.%d Symmetric encryption failed, status - %d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }
    }

    if (isSymmetric)
    {
        status = DIGI_CALLOC((void **)&(pCipherBuffer->pBuffer), 1,
                            encryptDecryptOut.outLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for encrypted data, status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
        pCipherBuffer->bufferLen = encryptDecryptOut.outLen;

        status = DIGI_MEMCPY((ubyte *)(pCipherBuffer->pBuffer),
                             encryptDecryptOut.pOutBuffer,
                             pCipherBuffer->bufferLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy encrypted data, status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        DIGI_FREE((void **)&encryptDecryptOut.pOutBuffer);
    }
    else
    {
        status = DIGI_CALLOC((void **)&(pCipherBuffer->pBuffer), 1,
                            encryptOut.encryptedData.size);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for encrypted data, status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        state |= APISTATE_RESULT_BUFFER_CREATED;
        pCipherBuffer->bufferLen = encryptOut.encryptedData.size;

        status = DIGI_MEMCPY((ubyte *)(pCipherBuffer->pBuffer),
                (ubyte *)(encryptOut.encryptedData.buffer),
                pCipherBuffer->bufferLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy encrypted data, status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
    }

exit:
    if (state & APISTATE_RSA_KEY_CREATED)
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
        CRYPTO_INTERFACE_RSA_freeKey((void **)&asymKey.key.pRSA, NULL, akt_rsa);
#else
        RSA_freeKey(&asymKey.key.pRSA, NULL);
#endif
    }

    if (  (OK != status)
       && (state & APISTATE_RESULT_BUFFER_CREATED) )
    {
        if (OK != DIGI_FREE((void **)&pCipherBuffer->pBuffer))
        {
            DB_PRINT("%s.%d Failed to free memory allocated to "
                    "cipher buffer, on error.\n",
                    __FUNCTION__, __LINE__);
        }
        pCipherBuffer->pBuffer = NULL;
        pCipherBuffer->bufferLen = 0;
    }

#if defined(__ENABLE_HARDWARE_ACCEL_SYNC_CRYPTO__) || defined(__ENABLE_HARDWARE_ACCEL_ASYNC_CRYPTO__)
    (void) HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);
#endif
    
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_ENCRYPT_INIT__
MSTATUS SMP_API(TPM2, encryptInit,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_OperationContext *pOpContext
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_ENCRYPT_UPDATE__
MSTATUS SMP_API(TPM2, encryptUpdate,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_Buffer *pBuffer,
        TAP_OperationContext opContext,
        TAP_Buffer *pCipherBuffer
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_ENCRYPT_FINAL__
MSTATUS SMP_API(TPM2, encryptFinal,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_OperationContext opContext,
        TAP_Buffer *pCipherBuffer
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_DECRYPT__
MSTATUS SMP_API(TPM2, decrypt,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_Buffer *pCipherBuffer,
        TAP_Buffer *pBuffer
)
{
    MSTATUS status = OK;
    AsymRsaDecryptIn decryptIn = { 0 };
    AsymRsaDecryptOut decryptOut = { 0 };
    SymEncryptDecryptIn encryptDecryptIn = { 0 };
    SymEncryptDecryptOut encryptDecryptOut = { 0 };
    CACHED_KeyInfo *pKeyObject = NULL;
    TAP_Buffer *pLabel = NULL;
    TAP_ENC_SCHEME encScheme = TAP_ENC_SCHEME_NONE;
    byteBoolean isSymmetric = FALSE;
    SMP_Context *pSmpContext = NULL;
    TAP_Attribute *pAttribute = NULL;
    ubyte4 listCount = 0;

    if ((0 == moduleHandle) || (0 == keyHandle) ||
            (NULL == pCipherBuffer) || (NULL == pBuffer))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, pModuleHandle = %p,"
                "pObjectHandle = %p, pCipherBuffer = %p, "
                "pDecryptedData = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                keyHandle, pCipherBuffer, pBuffer);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);

    /* If parameters are provided, use them */
    if (pMechanism && pMechanism->listLen)
    {
        pAttribute = pMechanism->pAttributeList;

        while (listCount < pMechanism->listLen)
        {
            /* handle parameters we need */
            switch (pAttribute->type)
            {
                case TAP_ATTR_ENC_SCHEME:
                    if ((sizeof(TAP_ENC_SCHEME) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid scheme structure length %d, "
                                "status = %d\n", __FUNCTION__, __LINE__,
                                pAttribute->length, status);
                        goto exit;
                    }

                    encScheme = *((TAP_ENC_SCHEME *)(pAttribute->pStructOfType));
                    break;

                case TAP_ATTR_ENC_LABEL:

                    pLabel = (TAP_Buffer *)(pAttribute->pStructOfType);
                    break;

                default:
                    break;
            }

            pAttribute++;
            listCount++;
        }
    }

    pKeyObject = (CACHED_KeyInfo *)((uintptr)keyHandle);

    switch (pKeyObject->keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_RSA:
        case TAP_KEY_ALGORITHM_ECC:
            isSymmetric = FALSE;
            break;

        case TAP_KEY_ALGORITHM_AES:
            isSymmetric = TRUE;
            break;

        default:
            status = ERR_TAP_INVALID_ALGORITHM;
            DB_PRINT("%s.%d Invalid key algorithm %d, status = %d\n",
                __FUNCTION__,__LINE__, (int)pKeyObject->keyAlgorithm,
                status);
            goto exit;
    }

    if (isSymmetric)
    {
        status = TPM2_symEncryptDecrypt(pSmpContext,
                1, &encryptDecryptIn, &encryptDecryptOut, pKeyObject,
                encScheme, pLabel, pCipherBuffer);
        if (OK != status)
        {
            DB_PRINT("%s.%d Symmetric decryption failed, status - %d",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }
    }
    else
    {
        status = TPM2_asymDecrypt(pSmpContext,
                &decryptIn, &decryptOut, pKeyObject, encScheme, pLabel, pCipherBuffer);
        if (OK != status)
        {
            DB_PRINT("%s.%d Asymmetric decryption failed, status - %d",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }
    }

    if (isSymmetric)
    {
        pBuffer->bufferLen = encryptDecryptOut.outLen;

        status = DIGI_CALLOC((void **)&(pBuffer->pBuffer), 1,
                pBuffer->bufferLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Unable to allocate memory for decrypted data, status = %d\n",
                __FUNCTION__, __LINE__, status);
            pBuffer->bufferLen = 0;
            goto exit;
        }
        status = DIGI_MEMCPY((ubyte *)(pBuffer->pBuffer),
                encryptDecryptOut.pOutBuffer,
                pBuffer->bufferLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy decrypted data, status = %d\n",
                __FUNCTION__,__LINE__, status);
            goto exit;
        }

        DIGI_FREE((void **)&encryptDecryptOut.pOutBuffer);
    }
    else
    {
        pBuffer->bufferLen = decryptOut.plainText.size;

        status = DIGI_CALLOC((void **)&(pBuffer->pBuffer), 1,
                pBuffer->bufferLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Unable to allocate memory for decrypted data, status = %d\n",
                __FUNCTION__, __LINE__, status);
            pBuffer->bufferLen = 0;
            goto exit;
        }
        status = DIGI_MEMCPY((ubyte *)(pBuffer->pBuffer),
                (ubyte *)(decryptOut.plainText.buffer),
                pBuffer->bufferLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy decrypted data, status = %d\n",
                __FUNCTION__,__LINE__, status);
            goto exit;
        }
    }

exit:

    if (OK != status)
    {
        if (pBuffer)
        {
            if (pBuffer->pBuffer)
            {
                DIGI_FREE((void **)&pBuffer->pBuffer);
            }
            pBuffer->bufferLen = 0;
        }
    }

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_DECRYPT_INIT__
MSTATUS SMP_API(TPM2, decryptInit,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_OperationContext *pOpContext
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_DECRYPT_UPDATE__
MSTATUS SMP_API(TPM2, decryptUpdate,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_Buffer *pCipherBuffer,
        TAP_OperationContext opContext,
        TAP_Buffer *pBuffer
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_DECRYPT_FINAL__
MSTATUS SMP_API(TPM2, decryptFinal,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_OperationContext opContext,
        TAP_Buffer *pBuffer
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_DIGEST_INIT__
MSTATUS SMP_API(TPM2, digestInit,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_MechanismAttributes *pMechanism,
        TAP_OperationContext *pOpContext
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_DIGEST_UPDATE__
MSTATUS SMP_API(TPM2, digestUpdate,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_OperationContext opContext,
        TAP_Buffer *pBuffer
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_DIGEST_FINAL__
MSTATUS SMP_API(TPM2, digestFinal,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_OperationContext opContext,
        TAP_Buffer *pBuffer
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_RANDOM__

static MSTATUS TPM2_fillBufferWithRandomData(SMP_Context *pSmpContext,
        TAP_Buffer *pRandom, ubyte4 bytesRequested)
{
    MSTATUS status = OK;
    RngGetRandomDataIn rngIn = { 0 };
    RngGetRandomDataOut rngOut = { 0 };
    ubyte4 remaining = bytesRequested;
    ubyte *pBufPtr = NULL;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    pRandom->pBuffer = NULL;
    pRandom->bufferLen = 0;

    /* Allocate memory for result */
    status = DIGI_CALLOC((void **)&pRandom->pBuffer, 1, bytesRequested);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory for random memory data buffer"
                "status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }
    pRandom->bufferLen = bytesRequested;

    pBufPtr = pRandom->pBuffer;

    while (remaining)
    {
        rngOut.randomBytes.size = 0;
        /* TODO RK:The number 32 is dependent on the chipset. This can be discovered. A chip may support only 16 bytes or may support 128 bytes. */
        rngIn.bytesRequested = MIN(remaining, 32);

        /* Make the call */
        rc = FAPI2_RNG_getRandomData(pSmpContext->pFapiContext,
                &rngIn, &rngOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d Failed to get Random data, "
                    "rc 0x%02x\n",
                    __FUNCTION__,__LINE__, rc);
            goto exit;
        }

        status = DIGI_MEMCPY(pBufPtr, rngOut.randomBytes.buffer,
                rngOut.randomBytes.size);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy random memory data to caller buffer"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        remaining -= MIN(remaining, rngOut.randomBytes.size);
        pBufPtr += MIN(remaining, rngOut.randomBytes.size);
    }

exit:
    if (OK != status)
    {
        if (pRandom->pBuffer)
            DIGI_FREE((void **)&pRandom->pBuffer);
        pRandom->bufferLen = 0;
    }

    return status;
}

MSTATUS SMP_API(TPM2, getRandom,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_RngAttributes *pRngRequest,
        ubyte4 bytesRequested,
        TAP_Buffer *pRandom
)
{
    MSTATUS status = OK;
    SMP_Context *pSmpContext = NULL;
    byteBoolean moduleLocked = FALSE;

    if ((0 == moduleHandle) || (0 == bytesRequested) ||
            (NULL == pRandom))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input, moduleHandle = %p, bytesRequested = %d,"
                "pRandom = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                (int)bytesRequested,
                pRandom);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting on mutex for module- %p, status- %d\n",
                __FUNCTION__, __LINE__, pSmpContext, status);
        goto exit;
    }
    moduleLocked = TRUE;

    status = TPM2_fillBufferWithRandomData((SMP_Context *)((uintptr)moduleHandle),
            pRandom, bytesRequested);

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_STIR_RANDOM__
MSTATUS SMP_API(TPM2, stirRandom,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_RngAttributes *pRngRequest
)
{
    MSTATUS status = OK;
    RngStirRNGIn stirIn = {0};
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    SMP_Context *pSmpContext = NULL;
    TOKEN_Context *pToken = NULL;
    byteBoolean moduleLocked = FALSE;

    if ((0 == moduleHandle) || (0 == tokenHandle))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p, "
                "tokenHandle = %p\n",
                __FUNCTION__, __LINE__, moduleHandle, tokenHandle);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pToken = (TOKEN_Context *)((uintptr)tokenHandle);

    if (SMP_TPM2_CRYPTO_TOKEN_ID != pToken->id)
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Invalid token, id %d, expected %d\n",
                __FUNCTION__, __LINE__, (int)pToken->id,
                (int)SMP_TPM2_CRYPTO_TOKEN_ID);

        goto exit;
    }

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting on module mutex for module - %p\n",
                __FUNCTION__, __LINE__, moduleHandle);
        goto exit;
    }
    moduleLocked = TRUE;

    /* stirIn.additionalData is optional at this time */
    rc = FAPI2_RNG_stirRNG(pSmpContext->pFapiContext, &stirIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to stir random number generator, "
                "rc 0x%02x\n",
                __FUNCTION__,__LINE__, rc);
        goto exit;
    }

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_TRUSTED_DATA__
MSTATUS SMP_API(TPM2, getTrustedData,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_TRUSTED_DATA_TYPE trustedDataType,
        TAP_TrustedDataInfo *pTrustedDataInfo,
        TAP_Buffer *pDataValue
)
{
    MSTATUS status = OK;
    TAP_Attribute *pAttribute = NULL;
    ubyte pcrIndex = 0;
    ubyte4 listCount = 0;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    IntegrityPcrReadIn pcrReadIn = {0};
    IntegrityPcrReadOut pcrReadOut = {0};
    SMP_Context *pSmpContext = NULL;
    TAP_HASH_ALG hashAlg = TPM2_ALG_SHA256;
    ubyte4 pcrDigestSize = SHA256_RESULT_SIZE, digestIndex = 0;
    ubyte4 loopCount = 0, loopIndex = 0;
    byteBoolean bReadAllPcrs = TRUE;
    TAP_Buffer *pKeyBuffer = NULL;
    ubyte4 i = 0;
    ubyte4 pcrMask = 0;
    ubyte4 numPcr = 0;
    ubyte4 dataOffset = 0;
    TOKEN_Context *pToken = NULL;
    ubyte state = 0x00;

    if ((0 == moduleHandle) ||
            (0 == tokenHandle) || (NULL == pDataValue))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p, "
                "pDataValue = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                pDataValue);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pToken = (TOKEN_Context *)((uintptr)tokenHandle);

    if (SMP_TPM2_CRYPTO_TOKEN_ID != pToken->id)
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Invalid token, id %d, expected %d\n",
                __FUNCTION__, __LINE__, (int)pToken->id, (int)SMP_TPM2_CRYPTO_TOKEN_ID);
        goto exit;
    }

    pDataValue->pBuffer = NULL;
    pDataValue->bufferLen = 0;

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting on mutex for module- %p, status- %d",
                __FUNCTION__, __LINE__, pSmpContext, status);
        goto exit;
    }
    state |= APISTATE_MODULE_MUTEX_LOCKED;

    /* Validate input */
    /* Todo: Update when Fapi implements trusted data time */
    if (TAP_TRUSTED_DATA_TYPE_MEASUREMENT != trustedDataType)
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Invalid TrustedDataType %d, expected %d\n",
                __FUNCTION__, __LINE__, (int)trustedDataType,
                (int)(TAP_TRUSTED_DATA_TYPE_MEASUREMENT));
        goto exit;
    }

    if (pTrustedDataInfo && (1 != pTrustedDataInfo->subType))
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Invalid Trusted SubType %d, expected 1\n",
                __FUNCTION__, __LINE__, (int)pTrustedDataInfo->subType);
        goto exit;
    }

    if (pTrustedDataInfo && pTrustedDataInfo->attributes.pAttributeList &&
            pTrustedDataInfo->attributes.listLen)
    {
        pAttribute = pTrustedDataInfo->attributes.pAttributeList;

        listCount = 0;
        while (listCount < pTrustedDataInfo->attributes.listLen)
        {
            /* handle parameters we need */
            switch (pAttribute->type)
            {
                case TAP_ATTR_HASH_ALG:
                    if ((sizeof (TAP_HASH_ALG) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid Hash algorithm Parameters, "
                                "length %d, expected %d, buffer %p\n",
                                __FUNCTION__, __LINE__, (int)pAttribute->length,
                                sizeof(TAP_HASH_ALG),
                                pAttribute->pStructOfType);
                        goto exit;
                    }

                    switch (*((TAP_HASH_ALG *)(pAttribute->pStructOfType)))
                    {
                        case TAP_HASH_ALG_SHA256:
                            hashAlg = TPM2_ALG_SHA256;
                            pcrDigestSize = SHA256_RESULT_SIZE;
                            break;

                        case TAP_HASH_ALG_SHA384:
                            hashAlg = TPM2_ALG_SHA384;
                            pcrDigestSize = SHA384_RESULT_SIZE;
                            break;

                        case TAP_HASH_ALG_SHA512:
                            hashAlg = TPM2_ALG_SHA512;
                            pcrDigestSize = SHA512_RESULT_SIZE;
                            break;

                        default:
                            status = ERR_TAP_UNSUPPORTED_ALGORITHM;
                            DB_PRINT("%s.%d Unsupported hash algorithm %d, "
                                    "status 0x%02x\n",
                                    __FUNCTION__,__LINE__,
                                    *((TAP_HASH_ALG *)(pAttribute->pStructOfType)),
                                    status);
                            goto exit;
                    }

                    break;

                case TAP_ATTR_TRUSTED_DATA_KEY:
                    pKeyBuffer = (TAP_Buffer *)pAttribute->pStructOfType;
                    if(pKeyBuffer == NULL)
                    {
                         status = ERR_INVALID_ARG;
                         DB_PRINT("%s.%d Invalid TrustedData \n",
                         __FUNCTION__,__LINE__);
                         goto exit;
                    }
                    /* Get the PCR Indexes to be read */
                    for (i = 0, numPcr = 0; i < pKeyBuffer->bufferLen; i++, numPcr++)
                    {
                        pcrIndex = pKeyBuffer->pBuffer[i];

                        if ((TPM2_PCR_LAST < pcrIndex))
                        {
                            status = ERR_INVALID_ARG;
                            DB_PRINT("%s.%d Invalid TrustedDataType key value, "
                                    "pcrIndex %d, expected 0 - %d\n",
                                    __FUNCTION__, __LINE__, (int)pcrIndex,
                                    (int)TPM2_PCR_LAST);
                            goto exit;
                        }
                        pcrMask |= (1 << pcrIndex);
                        if (pcrIndex >= 16)
                            loopCount = 3;
                        else if (pcrIndex >= 8)
                            loopCount = 2;
                        else
                            loopCount = 1;
                    }
                    if(numPcr)
                        bReadAllPcrs = FALSE;
                    break;

                default:
                    break;
            }

            pAttribute++;
            listCount++;
        }
    }

    if (FALSE == bReadAllPcrs)
    {
        pcrReadIn.pcrSelection = pcrMask;
    }
    else
    {
        pcrReadIn.pcrSelection = 0x00ff;
        loopCount = 3;
    }
    if (!pDataValue->pBuffer)
    {
        pDataValue->bufferLen = (FALSE == bReadAllPcrs) ?
            (numPcr * pcrDigestSize) : (8 * pcrDigestSize * loopCount);

        /* All PCR digests are of the same size */
        status = DIGI_CALLOC((void **)&pDataValue->pBuffer,
                1, pDataValue->bufferLen);
        if (OK != status)
        {
            DB_PRINT("%s.%d Error allocating %d bytes for PCR data, "
                    "status = %d\n",
                    __FUNCTION__,__LINE__,
                    (pcrReadOut.pcrDigests.count *
                     pcrDigestSize * loopCount), status);
            goto exit;
        }
        state |= APISTATE_RESULT_BUFFER_CREATED;
    }

    dataOffset = 0;
    for (loopIndex = 0; loopIndex < loopCount; loopIndex++)
    {
        pcrReadIn.hashAlg = hashAlg;
        if (TRUE == bReadAllPcrs)
            pcrReadIn.pcrSelection = (0xff << (loopIndex * 8));
        else
        {
            if (pcrMask & (0xff << (loopIndex * 8)))
                pcrReadIn.pcrSelection = (pcrMask & (0xff << (loopIndex * 8)));
            else
                continue;
        }

        /* Issue FAPI call to get the PCR index value */
        rc = FAPI2_INTEGRITY_pcrRead(pSmpContext->pFapiContext,
                &pcrReadIn, &pcrReadOut);

        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d Failed to read PCR index %d, "
                    "rc 0x%02x\n",
                    __FUNCTION__,__LINE__, (int)pcrIndex, rc);
            goto exit;
        }

        if (sizeof(pcrReadOut.pcrDigests.digests) / sizeof(TPM2B_DIGEST) <
                pcrReadOut.pcrDigests.count)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d PCR index read count %d, max 8, rc 0x%02x\n",
                    __FUNCTION__,__LINE__, (int)pcrReadOut.pcrDigests.count, rc);
            goto exit;
        }

        /* Allocate memory for read data */
        if (pcrReadOut.pcrDigests.digests[0].size)
        {
            for (digestIndex = 0; digestIndex < pcrReadOut.pcrDigests.count; digestIndex++)
            {
                status = DIGI_MEMCPY(&pDataValue->pBuffer[dataOffset*pcrDigestSize],
                        pcrReadOut.pcrDigests.digests[digestIndex].buffer,
                        pcrDigestSize);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Error copying %d PCR data bytes, "
                            "status = %d\n",
                            __FUNCTION__,__LINE__, pcrDigestSize, status);
                    goto exit;
                }

                dataOffset++;
            }
        }
        else
        {
            status = ERR_TAP_CMD_FAILED;
            DB_PRINT("%s.%d PCR index data length 0\n",
                    __FUNCTION__,__LINE__);
            goto exit;
        }
    }


exit:
    if (state & APISTATE_MODULE_MUTEX_LOCKED)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    if (  (OK != status)
            && (state & APISTATE_RESULT_BUFFER_CREATED) )
    {
        if (OK != DIGI_FREE((void **)&pDataValue->pBuffer))
        {
            DB_PRINT("%s.%d Failed to free memory allocated for "
                    "TrustedData buffer, on error.\n",
                    __FUNCTION__, __LINE__);
        }
        pDataValue->pBuffer = NULL;
        pDataValue->bufferLen = 0;
    }

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_UPDATE_TRUSTED_DATA__
MSTATUS SMP_API(TPM2, updateTrustedData,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_TRUSTED_DATA_TYPE trustedDataType,
        TAP_TrustedDataInfo *pTrustedDataInfo,
        TAP_TRUSTED_DATA_OPERATION trustedDataOp,
        TAP_Buffer *pDataValue,
        TAP_Buffer *pUpdatedDataValue
)
{
    MSTATUS status = OK;
    TAP_Attribute *pAttribute = NULL;
    ubyte pcrIndex = 0;
    ubyte4 listCount = 0;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    IntegrityPcrReadIn pcrReadIn = {0};
    IntegrityPcrReadOut pcrReadOut = {0};
    SMP_Context *pSmpContext = NULL;
    TAP_HASH_ALG hashAlg = TPM2_ALG_SHA256;
    IntegrityPcrExtendIn pcrExtendIn = {0};
    TAP_Buffer *pKeyBuffer = NULL;
    ubyte state = 0x00;

    if ((0 == moduleHandle) || (NULL == pTrustedDataInfo) ||
            (NULL == pDataValue) || (NULL == pUpdatedDataValue))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p, "
                "pTrustedDataInfo = %p, pDataValue = %p, "
                "pUpdatedDataValue = %p\n",
                __FUNCTION__, __LINE__, moduleHandle, pTrustedDataInfo,
                pDataValue, pUpdatedDataValue);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting on mutex for module- %p, status- %d\n",
                __FUNCTION__, __LINE__, pSmpContext, status);
        goto exit;
    }
    state |= APISTATE_MODULE_MUTEX_LOCKED;

    /* Validate digest length */
    if (sizeof(pcrExtendIn.digest.buffer) < pDataValue->bufferLen)
    {
        status = ERR_BUFFER_OVERFLOW;
        DB_PRINT("%s.%d Invalid digest length %d, max %d\n",
                __FUNCTION__, __LINE__, (int)pDataValue->bufferLen,
                (int)pcrExtendIn.digest.size);
        goto exit;
    }

    status = DIGI_MEMCPY(pcrExtendIn.digest.buffer, pDataValue->pBuffer,
            pDataValue->bufferLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error copying digest, status = %d\n",
                __FUNCTION__, __LINE__, (int)status);
        goto exit;
    }

    pcrExtendIn.digest.size = pDataValue->bufferLen;

    /* Validate type */
    if (TAP_TRUSTED_DATA_TYPE_MEASUREMENT != trustedDataType)
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Invalid TrustedDataType %d, expected %d\n",
                __FUNCTION__, __LINE__, (int)trustedDataType,
                (int)(TAP_TRUSTED_DATA_TYPE_MEASUREMENT));
        goto exit;
    }

    /* Validate operation */
    if (TAP_TRUSTED_DATA_OPERATION_UPDATE != trustedDataOp)
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Invalid TrustedDataOperation %d, expected %d\n",
                __FUNCTION__, __LINE__, (int)trustedDataOp,
                (int)(TAP_TRUSTED_DATA_OPERATION_UPDATE));
        goto exit;
    }

    /* Todo: replace 1 with #define .. figure out in which file should it be
       defined */
    if (1 != pTrustedDataInfo->subType)
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Invalid TrustedDataType %d, expected %d\n",
                __FUNCTION__, __LINE__, (int)trustedDataType,
                (int)(TAP_TRUSTED_DATA_TYPE_MEASUREMENT));
        goto exit;
    }

    if (pTrustedDataInfo->attributes.pAttributeList &&
            pTrustedDataInfo->attributes.listLen)
    {
        pAttribute = pTrustedDataInfo->attributes.pAttributeList;

        listCount = 0;
        while (listCount < pTrustedDataInfo->attributes.listLen)
        {
            /* handle parameters we need */
            switch (pAttribute->type)
            {
                case TAP_ATTR_HASH_ALG:
                    if ((sizeof (TAP_HASH_ALG) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid Hash algorithm Parameters, "
                                "length %d, expected %d, buffer %p\n",
                                __FUNCTION__, __LINE__, (int)pAttribute->length,
                                sizeof(TAP_HASH_ALG),
                                pAttribute->pStructOfType);
                        goto exit;
                    }

                    switch (*((TAP_HASH_ALG *)(pAttribute->pStructOfType)))
                    {
                        case TAP_HASH_ALG_SHA256:
                            hashAlg = TPM2_ALG_SHA256;
                            break;

                        case TAP_HASH_ALG_SHA384:
                            hashAlg = TPM2_ALG_SHA384;
                            break;

                        case TAP_HASH_ALG_SHA512:
                            hashAlg = TPM2_ALG_SHA512;
                            break;

                        default:
                            status = ERR_TAP_UNSUPPORTED_ALGORITHM;
                            DB_PRINT("%s.%d Unsupported hash algorithm %d, "
                                    "status 0x%02x\n",
                                    __FUNCTION__,__LINE__,
                                    *((TAP_HASH_ALG *)(pAttribute->pStructOfType)),
                                    status);
                            goto exit;
                    }

                    break;

                case TAP_ATTR_TRUSTED_DATA_KEY:
                    pKeyBuffer = (TAP_Buffer *)pAttribute->pStructOfType;
                    if(pKeyBuffer == NULL)
                    {
                         status = ERR_INVALID_ARG;
                         DB_PRINT("%s.%d Invalid TrustedDataType key \n",
                         __FUNCTION__,__LINE__);
                         goto exit;
                    }

                    pcrIndex = *pKeyBuffer->pBuffer;

                    if ((TPM2_PCR_LAST < pcrIndex))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid TrustedDataType key value, "
                                "pcrIndex %d, expected 0 - %d\n",
                                __FUNCTION__, __LINE__, (int)pcrIndex,
                                (int)TPM2_PCR_LAST);
                        goto exit;
                    }

                    break;

                default:
                    break;
            }

            pAttribute++;
            listCount++;
        }

        pcrExtendIn.hashAlg = hashAlg;
        pcrExtendIn.pcrIndex = pcrIndex;

        /* Issue FAPI call to update PCR index value */
        rc = FAPI2_INTEGRITY_pcrExtend(pSmpContext->pFapiContext,
                &pcrExtendIn);

        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d Failed to extend PCR index %d, "
                    "rc 0x%02x\n",
                    __FUNCTION__,__LINE__, (int)pcrIndex, rc);
            goto exit;
        }

        pcrReadIn.pcrSelection = (1 << pcrIndex);
        pcrReadIn.hashAlg = hashAlg;

        /* Issue FAPI call to get the PCR index value */
        rc = FAPI2_INTEGRITY_pcrRead(pSmpContext->pFapiContext,
                &pcrReadIn, &pcrReadOut);

        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d Failed to read PCR index %d, "
                    "rc 0x%02x\n",
                    __FUNCTION__,__LINE__, (int)pcrIndex, rc);
            goto exit;
        }

        if (1 != pcrReadOut.pcrDigests.count)
        {
            status = ERR_TAP_CMD_FAILED;
            DB_PRINT("%s.%d PCR index read count %d, expecting 1, rc = 0x%02x\n",
                    __FUNCTION__,__LINE__, (int)pcrReadOut.pcrDigests.count, rc);
            goto exit;
        }

        /* Allocate memory for read data */
        if (pcrReadOut.pcrDigests.digests[0].size)
        {
            status = DIGI_CALLOC((void **)&pUpdatedDataValue->pBuffer,
                    1, pcrReadOut.pcrDigests.digests[0].size);
            if (OK != status)
            {
                DB_PRINT("%s.%d Error allocating %d bytes for PCR data, "
                        "status = %d\n",
                        __FUNCTION__, __LINE__, pcrReadOut.pcrDigests.digests[0].size, status);
                goto exit;
            }
            state |= APISTATE_RESULT_BUFFER_CREATED;

            status = DIGI_MEMCPY(pUpdatedDataValue->pBuffer,
                    pcrReadOut.pcrDigests.digests[0].buffer,
                    pcrReadOut.pcrDigests.digests[0].size);
            if (OK != status)
            {
                DB_PRINT("%s.%d Error copying %d updated PCR data bytes, "
                        "status = %d\n",
                        __FUNCTION__, __LINE__, pcrReadOut.pcrDigests.digests[0].size, status);
                goto exit;
            }

            pUpdatedDataValue->bufferLen = pcrReadOut.pcrDigests.digests[0].size;
        }
        else
        {
            status = ERR_TAP_CMD_FAILED;
            DB_PRINT("%s.%d PCR index data length 0\n",
                    __FUNCTION__,__LINE__);
            goto exit;
        }
    }

exit:
    if (state & APISTATE_MODULE_MUTEX_LOCKED)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    if (  (OK != status)
       && (state & APISTATE_RESULT_BUFFER_CREATED) )
    {
        if (OK != DIGI_FREE((void **)&pUpdatedDataValue->pBuffer))
        {
            DB_PRINT("%s.%d Failed to free memory allocated for "
                    "TrustedData buffer, on error.\n",
                    __FUNCTION__, __LINE__);
        }
        pUpdatedDataValue->pBuffer = NULL;
        pUpdatedDataValue->bufferLen = 0;
    }

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SEAL_WITH_TRUSTED_DATA__
MSTATUS SMP_API(TPM2, sealWithTrustedData,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_SealAttributes *pRequestTemplate,
        TAP_Buffer *pDataToSeal,
        TAP_Buffer *pDataOut
)
{
    MSTATUS status = OK;
    DataSealIn dataIn = {0};
    DataSealOut dataOut = {0};
    TAP_Attribute *pAttribute = NULL;
    TPM2B_AUTH auth = {0};
    TPM2B_NAME *pParentName = NULL;
    SMP_Context *pSmpContext = NULL;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    byteBoolean moduleLocked = FALSE;
    ubyte4 listCount = 0;
    ubyte4 cnt = 0;
    ubyte2 numPolicyTerms = 0;
    ubyte trustedDataType = 0 ;
    byteBoolean  bTrustedDataTypePcr = FALSE ;
    ubyte4 pcrBitMask = 0 ;
    TAP_Buffer *pPcrBuf = NULL;
    PolicyAuthNode *pPolicy=NULL;

    if ((0 == moduleHandle) || (NULL == pDataToSeal) ||
            (NULL == pDataOut))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input, moduleHandle = %p, pDataToSeal = %p,"
                "pDataOut = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                pDataToSeal, pDataOut);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting on mutex for module- %p, status- %d\n",
                __FUNCTION__, __LINE__, moduleHandle, status);
        goto exit;
    }
    moduleLocked = TRUE;

    if (pDataToSeal->bufferLen > sizeof(dataIn.dataToSeal.buffer))
    {
        status = ERR_BUFFER_OVERFLOW;
        DB_PRINT("%s.%d Invalid input, Input buffer size of %d exceeds limit of %d\n",
                __FUNCTION__, __LINE__, pDataToSeal->bufferLen,
                sizeof(dataIn.dataToSeal.buffer));
        goto exit;
    }

    /* Pickup the Auth and Parent information */
    if (pRequestTemplate && pRequestTemplate->listLen)
    {
        pAttribute = pRequestTemplate->pAttributeList;

        while (listCount < pRequestTemplate->listLen)
        {
            switch (pAttribute->type)
            {
                case TAP_ATTR_CREDENTIAL:
                    TPM2_parseCredential(
                                (TAP_Credential *)pAttribute->pStructOfType,
                                 &auth);
                    break;
                case TAP_ATTR_TRUSTED_DATA_TYPE:
                    trustedDataType = *(TAP_TRUSTED_DATA_TYPE *)pAttribute->pStructOfType ;
                    break ;
                case TAP_ATTR_TRUSTED_DATA_KEY:
                    if(trustedDataType == TAP_TRUSTED_DATA_TYPE_MEASUREMENT)
                    {
                        numPolicyTerms++ ;
                        bTrustedDataTypePcr = TRUE ;
                    }
                    pPcrBuf = (TAP_Buffer *)pAttribute->pStructOfType ;
                    for(cnt = 0; cnt < pPcrBuf->bufferLen; cnt++)
                    {

                        pcrBitMask |= ((ubyte4)1<<pPcrBuf->pBuffer[cnt]) ;
                    }
                    break ;
                default:
                    break;
            }

            pAttribute++;
            listCount++;

        }
    }

    if(numPolicyTerms)
    {
        status = DIGI_CALLOC((void **)&pPolicy,numPolicyTerms,sizeof(PolicyAuthNode));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory; status - %d\n",
                        __FUNCTION__, __LINE__, status);
            goto exit;
        }
        for(cnt = 0 ; cnt < numPolicyTerms; cnt++)
        {
            if(bTrustedDataTypePcr == TRUE)
            {
                /* truested data type */
                pPolicy[cnt].policyType = FAPI2_POLICY_PCR ;
                pPolicy[cnt].policyInfo.policyPcr.pcrBitmask = pcrBitMask ;
            }
        }
    }

    dataIn.numPolicyTerms = numPolicyTerms ;
    dataIn.pPolicy = pPolicy ;
    dataIn.pParentName = pParentName;
    dataIn.authValue = auth;
    dataIn.dataToSeal.size = pDataToSeal->bufferLen;

    status = DIGI_MEMCPY(dataIn.dataToSeal.buffer, pDataToSeal->pBuffer,
            pDataToSeal->bufferLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error copying seal data buffer, error- %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    rc = FAPI2_DATA_seal(pSmpContext->pFapiContext,
            &dataIn, &dataOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to seal data, "
                "rc 0x%02x\n",
                __FUNCTION__,__LINE__, rc);
        goto exit;
    }

    if (dataOut.sealedObject.size)
    {
        status = DIGI_CALLOC((void **)&pDataOut->pBuffer, 1,
                dataOut.sealedObject.size);
        if (OK != status)
        {
            DB_PRINT("%s.%d Error allocating %d bytes for seal data, "
                    "status = %d\n", __FUNCTION__, __LINE__,
                     dataOut.sealedObject.size, status);
            goto exit;
        }
        pDataOut->bufferLen = dataOut.sealedObject.size;

        status = DIGI_MEMCPY(pDataOut->pBuffer, dataOut.sealedObject.buffer,
                dataOut.sealedObject.size);
        if (OK != status)
        {
            DB_PRINT("%s.%d Error copying seal data, status= %d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }
    }
    else
    {
        status = ERR_TAP_CMD_FAILED;
    }

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    if (OK != status)
    {
        if (pDataOut)
        {
            if(pDataOut->pBuffer)
                DIGI_FREE((void **)&pDataOut->pBuffer);
            pDataOut->bufferLen = 0;
        }
    }
    if(pPolicy)
    {
        DIGI_FREE((void *)&pPolicy);
    }
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNSEAL_WITH_TRUSTED_DATA__
MSTATUS SMP_API(TPM2, unsealWithTrustedData,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_SealAttributes *pRequestTemplate,
        TAP_Buffer *pDataToUnseal,
        TAP_Buffer *pDataOut
)
{
    MSTATUS status = OK;
    DataUnsealIn dataIn = {0};
    DataUnsealOut dataOut = {0};
    TAP_Attribute *pAttribute = NULL;
    TPM2B_AUTH auth = {0};
    SMP_Context *pSmpContext = NULL;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    ubyte4 listCount = 0;
    byteBoolean moduleLocked = FALSE;
    ubyte4 cnt = 0;
    ubyte2 numPolicyTerms = 0;
    ubyte trustedDataType = 0 ;
    byteBoolean  bTrustedDataTypePcr = FALSE ;
    ubyte4 pcrBitMask = 0 ;
    TAP_Buffer *pPcrBuf =NULL;
    PolicyAuthNode *pPolicy = NULL;

    if ((0 == moduleHandle) || (NULL == pDataToUnseal) ||
            (NULL == pDataOut))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input, moduleHandle = %p, pDataToUnseal = %p,"
                "pDataOut = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                pDataToUnseal, pDataOut);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting on mutex for module- %p, status- %d\n",
                __FUNCTION__, __LINE__, moduleHandle, status);
        goto exit;
    }
    moduleLocked = TRUE;

    if (pDataToUnseal->bufferLen > sizeof(dataIn.sealedObject.buffer))
    {
        status = ERR_BUFFER_OVERFLOW;
        DB_PRINT("%s.%d Invalid input, Input buffer size of %d exceeds limit of %d\n",
                __FUNCTION__, __LINE__, pDataToUnseal->bufferLen,
                sizeof(dataIn.sealedObject.buffer));
        goto exit;
    }

    /* Pickup the Auth and Parent information */
    if (pRequestTemplate && pRequestTemplate->listLen)
    {
        pAttribute = pRequestTemplate->pAttributeList;

        while (listCount < pRequestTemplate->listLen)
        {
            switch (pAttribute->type)
            {
                case TAP_ATTR_CREDENTIAL:
                    TPM2_parseCredential(
                                    (TAP_Credential *)pAttribute->pStructOfType,
                                     &auth);
                    break;
                    case TAP_ATTR_TRUSTED_DATA_TYPE:
                        trustedDataType = *(TAP_TRUSTED_DATA_TYPE *)pAttribute->pStructOfType ;
                        break ;
                    case TAP_ATTR_TRUSTED_DATA_KEY:
                    if(trustedDataType == TAP_TRUSTED_DATA_TYPE_MEASUREMENT)
                    {
                        numPolicyTerms++ ;
                        bTrustedDataTypePcr = TRUE ;
                    }
                    pPcrBuf = (TAP_Buffer *)pAttribute->pStructOfType ;
                    for(cnt = 0; cnt < pPcrBuf->bufferLen; cnt++)
                    {

                        pcrBitMask |= ((ubyte4)1<<pPcrBuf->pBuffer[cnt]) ;
                    }
                    break ;

                default:
                    break;
            }

            pAttribute++;
            listCount++;
        }
    }

    if(numPolicyTerms)
    {
        status = DIGI_CALLOC((void **)&pPolicy,numPolicyTerms,sizeof(PolicyAuthNode));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory; status - %d\n",
                        __FUNCTION__, __LINE__, status);
            goto exit;
        }
        for(cnt = 0 ; cnt < numPolicyTerms; cnt++)
        {
            if(bTrustedDataTypePcr == TRUE)
            {
                /* truested data type */
                pPolicy[cnt].policyType = FAPI2_POLICY_PCR ;
                pPolicy[cnt].policyInfo.policyPcr.pcrBitmask = pcrBitMask ;
            }
        }
    }

    dataIn.numPolicyTerms = numPolicyTerms ;
    dataIn.pPolicy = pPolicy ;
    dataIn.sealedObject.size = pDataToUnseal->bufferLen;
    dataIn.authValue = auth;

    status = DIGI_MEMCPY(dataIn.sealedObject.buffer, pDataToUnseal->pBuffer,
            pDataToUnseal->bufferLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed copying sealed data to unseal, status= %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    rc = FAPI2_DATA_unseal(pSmpContext->pFapiContext,
            &dataIn, &dataOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to unseal data, "
                "rc 0x%02x\n",
                __FUNCTION__,__LINE__, rc);
        goto exit;
    }

    if (dataOut.unsealedData.size)
    {
        status = DIGI_CALLOC((void **)&pDataOut->pBuffer, 1,
                dataOut.unsealedData.size);
        if (OK != status)
        {
            DB_PRINT("%s.%d Error allocating %d bytes for unseal data, "
                    "status = %d\n", __FUNCTION__,__LINE__,
                     dataOut.unsealedData.size, status);
            goto exit;
        }
        pDataOut->bufferLen = dataOut.unsealedData.size;

        status = DIGI_MEMCPY(pDataOut->pBuffer, dataOut.unsealedData.buffer,
                dataOut.unsealedData.size);
        if (OK != status)
        {
            DB_PRINT("%s.%d Error copying unsealed data buffer, status=%d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }
    }
    else
    {
        status = ERR_TAP_CMD_FAILED;
    }

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);
    if(pPolicy)
    {
        DIGI_FREE((void *)&pPolicy);
    }

    if (OK != status)
    {
        if (pDataOut)
        {
            if(pDataOut->pBuffer)
                DIGI_FREE((void **)&pDataOut->pBuffer);
            pDataOut->pBuffer = NULL;
            pDataOut->bufferLen = 0;
        }
    }

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SET_POLICY_STORAGE__
MSTATUS SMP_API(TPM2, setPolicyStorage,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_PolicyStorageAttributes *pPolicyAttributes,
        TAP_OperationAttributes *pOpAttributes,
        TAP_Buffer *pData
)
{
    MSTATUS status = OK;
    TPM2_OBJECT *pTpm2Object = NULL;
    SMP_Context *pSmpContext = NULL;
    NVWriteOpIn nvIn = {0};
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2B_AUTH nvAuth = {0};
    TAP_Attribute *pAttribute = NULL;
    ubyte writeOp = 1;
    ubyte4 listCount = 0;
    byteBoolean moduleLocked = FALSE;
    TAP_AUTH_CONTEXT_PROPERTY authContext = TAP_AUTH_CONTEXT_NONE;

    if ((0 == moduleHandle) ||
          (0 == objectHandle) || (NULL == pData))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p, "
                "objectHandle = %p, "
                "pData = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                objectHandle, pData);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pTpm2Object = (TPM2_OBJECT *)((uintptr)objectHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting on mutex for module- %p, status=%d\n",
                __FUNCTION__, __LINE__, moduleHandle, status);
        goto exit;
    }
    moduleLocked = TRUE;

    if (pOpAttributes && pOpAttributes->listLen)
    {
        pAttribute = pOpAttributes->pAttributeList;

        while (listCount < pOpAttributes->listLen)
        {
            switch (pAttribute->type)
            {
                case TAP_ATTR_WRITE_OP:
                    if ((sizeof(writeOp) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        goto exit;
                    }
                    writeOp = *((ubyte *)(pAttribute->pStructOfType));
                    break;

                case TAP_ATTR_CREDENTIAL_SET:
                    TPM2_parseCredentialList(
                            (TAP_CredentialList *)pAttribute->pStructOfType,
                            &nvAuth);
                    break;

                case TAP_ATTR_AUTH_CONTEXT:
                    if ((sizeof(TAP_AUTH_CONTEXT_PROPERTY) != pAttribute->length) ||
                        (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid storage storage heirarchy length=%d, status = %d\n",
                            __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    authContext =  *(TAP_AUTH_CONTEXT_PROPERTY *)(pAttribute->pStructOfType);
                    break;

                default:
                    break;
            }

            pAttribute++;
            listCount++;
        }
    }

    if (1 != writeOp)
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Invalid write operation code %d\n",
                __FUNCTION__, __LINE__, writeOp);
        goto exit;
    }

    if (pData->bufferLen > sizeof(nvIn.write.writeData.buffer))
    {
        status = ERR_BUFFER_OVERFLOW;
        DB_PRINT("%s.%d Invalid write length %d, max supported %d\n",
                __FUNCTION__, __LINE__, pData->bufferLen,
                nvIn.write.writeData.buffer);
        goto exit;
    }

    nvIn.nvIndex = (TPMI_RH_NV_INDEX)pTpm2Object->id;
    if (nvAuth.size)
        nvIn.nvAuth = nvAuth;
    else
        nvIn.nvAuth = pTpm2Object->auth;
    nvIn.writeOp = FAPI2_NV_WRITE_OP_WRITE;
    nvIn.write.writeData.size = pData->bufferLen;
    status = DIGI_MEMCPY(nvIn.write.writeData.buffer, pData->pBuffer,
            pData->bufferLen);;
    if (OK != status)
    {
        DB_PRINT("%s.%d Error copying NV Write data buffer, status= %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    nvIn.authHandle = (TAP_AUTH_CONTEXT_PLATFORM == authContext) ?
                    TPM2_RH_PLATFORM : TPM2_RH_OWNER;
    if (0 < pSmpContext->platformAuth.size)
    {
        nvIn.authHandleAuth = pSmpContext->platformAuth;
    }
    rc = FAPI2_NV_writeOp(pSmpContext->pFapiContext,
            &nvIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to write NV Index, "
                "rc 0x%02x\n",
                __FUNCTION__,__LINE__, rc);
        goto exit;
    }

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_POLICY_STORAGE__
MSTATUS SMP_API(TPM2, getPolicyStorage,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_OperationAttributes *pOpAttributes,
        TAP_Buffer *pData
)
{
    MSTATUS status = OK;
    TPM2_OBJECT *pTpm2Object = NULL;
    SMP_Context *pSmpContext = NULL;
    NVReadOpIn nvIn = {0};
    NVReadOpOut nvOut = {0};
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2B_AUTH nvAuth = {0};
    TAP_Attribute *pAttribute = NULL;
    ubyte readOp = 1;
    ubyte4 listCount = 0;
    byteBoolean moduleLocked = FALSE;
    TAP_AUTH_CONTEXT_PROPERTY authContext = TAP_AUTH_CONTEXT_STORAGE;

    if ((0 == moduleHandle) ||
          (0 == objectHandle) || (NULL == pData))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p, "
                "objectHandle = %p, "
                "pData = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                objectHandle, pData);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pTpm2Object = (TPM2_OBJECT *)((uintptr)objectHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting for mutex on module=%p, status=%d\n",
                __FUNCTION__, __LINE__, moduleHandle, status);
        goto exit;
    }
    moduleLocked = TRUE;

    if (pOpAttributes && pOpAttributes->listLen)
    {
        pAttribute = pOpAttributes->pAttributeList;

        while (listCount < pOpAttributes->listLen)
        {
            switch (pAttribute->type)
            {
                case TAP_ATTR_READ_OP:
                    if ((sizeof(readOp) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        goto exit;
                    }
                    readOp = *((ubyte *)(pAttribute->pStructOfType));
                    break;

                case TAP_ATTR_CREDENTIAL_SET:
                    TPM2_parseCredentialList(
                            (TAP_CredentialList *)pAttribute->pStructOfType,
                            &nvAuth);
                    break;

                case TAP_ATTR_AUTH_CONTEXT:
                    if ((sizeof(TAP_AUTH_CONTEXT_PROPERTY) != pAttribute->length) ||
                        (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid storage storage heirarchy length=%d, status = %d\n",
                            __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    authContext =  *(TAP_AUTH_CONTEXT_PROPERTY *)(pAttribute->pStructOfType);
                    break;

                default:
                    break;
            }

            pAttribute++;
            listCount++;
        }
    }

    if (1 != readOp)
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Invalid read operation code %d\n",
                __FUNCTION__, __LINE__, readOp);
        goto exit;
    }

    nvIn.nvIndex = (TPMI_RH_NV_INDEX)pTpm2Object->id;
    if (nvAuth.size)
        nvIn.nvAuth = nvAuth;
    else
        nvIn.nvAuth = pTpm2Object->auth;

    nvIn.authHandle = (TAP_AUTH_CONTEXT_PLATFORM == authContext) ?
                    TPM2_RH_PLATFORM : TPM2_RH_OWNER;
    if (0 < pSmpContext->platformAuth.size)
    {
        nvIn.authHandleAuth = pSmpContext->platformAuth;
    }
    rc = FAPI2_NV_readOp(pSmpContext->pFapiContext,
            &nvIn, &nvOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to read NV Index, "
                "rc 0x%02x\n",
                __FUNCTION__,__LINE__, rc);
        goto exit;
    }

    /* Allocate output buffer */
    status = DIGI_CALLOC((void **)&pData->pBuffer, 1,
            nvOut.readData.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error allocating %d bytes for NV data, "
                "status = %d\n",
                __FUNCTION__,__LINE__, nvOut.readData.size,
                status);
        goto exit;
    }

    status = DIGI_MEMCPY(pData->pBuffer, nvOut.readData.buffer, nvOut.readData.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error copying %d bytes to NV output buffer, "
                "status = %d\n",
                __FUNCTION__,__LINE__, nvOut.readData.size,
                status);
        goto exit;
    }

    pData->bufferLen = nvOut.readData.size;

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    if (OK != status)
    {
        if (pData)
        {
            if( pData->pBuffer)
                DIGI_FREE((void **)&pData->pBuffer);
            pData->pBuffer = NULL;
            pData->bufferLen = 0;
        }
    }

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_CERTIFICATE_REQUEST_VALIDATION_ATTRS__
MSTATUS SMP_API(TPM2, getCertificateRequestValidationAttrs,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_CSRAttributes *pCSRattributes,
        TAP_Blob *pBase64Blob
)
{
    MSTATUS status = OK;
    SMP_Context *pSmpContext = NULL;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    CredentialGetCsrAttrIn attrIn = {0};
    CredentialGetCsrAttrOut attrOut = {0};
    CACHED_KeyInfo *pCachedKey = NULL;
    ContextGetPrimaryObjectNameIn objNameIn = {0};
    ContextGetPrimaryObjectNameOut objNameOut = {0};
    byteBoolean moduleLocked = FALSE;

    if ((0 == moduleHandle) || (0 == tokenHandle) ||
            (0 == objectHandle) || (NULL == pBase64Blob))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input, moduleHandle = %p, tokenHandle = %p,"
                "objectHandle = %p, pBase64Blob = %p\n",
                __FUNCTION__, __LINE__, moduleHandle, tokenHandle,
                objectHandle, pBase64Blob);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pCachedKey = (CACHED_KeyInfo *)((uintptr)objectHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting on mutex for module=%p, status=%d\n",
                __FUNCTION__, __LINE__, moduleHandle, status);
        goto exit;
    }
    moduleLocked = TRUE;

    /* Use the EK for decryption */
    objNameIn.persistentHandle = FAPI2_RH_EK;

    rc = FAPI2_CONTEXT_getPrimaryObjectName(pSmpContext->pFapiContext,
            &objNameIn, &objNameOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to get primary object name for EK, "
                "rc 0x%02x\n",
                __FUNCTION__,__LINE__, rc);
        goto exit;
    }

    attrIn.decryptKey = objNameOut.objName;
    attrIn.activateKey = pCachedKey->keyName;

    rc = FAPI2_CREDENTIAL_getCSRAttr(pSmpContext->pFapiContext,
            &attrIn, &attrOut);

    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to validate certificate request, rc = 0x%02x\n",
                __FUNCTION__, __LINE__, rc);
        goto exit;
    }

    pBase64Blob->format = TAP_BLOB_FORMAT_MOCANA;
    pBase64Blob->encoding = TAP_BLOB_ENCODING_BASE64;

    status = DIGI_MALLOC((void **)&pBase64Blob->blob.pBuffer,
            attrOut.blobLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error allocating %d bytes for output buffer, "
                "status = %d\n",
                __FUNCTION__,__LINE__, attrOut.blobLen,
                status);
        goto exit;
    }

    status = DIGI_MEMCPY(pBase64Blob->blob.pBuffer, attrOut.pBase64Blob,
            attrOut.blobLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error copying %d bytes to output buffer, "
                "status = %d\n",
                __FUNCTION__,__LINE__, attrOut.blobLen,
                status);
        goto exit;
    }

    pBase64Blob->blob.bufferLen = attrOut.blobLen;

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    if (OK != status)
    {
        if (pBase64Blob)
        {
            if((NULL != pBase64Blob->blob.pBuffer))
            {
                if (OK != DIGI_FREE((void **)&(pBase64Blob->blob.pBuffer)))
                {
                    DB_PRINT("%s.%d Failed to free memory allocated for "
                            "csr attribute buffer on error\n",
                            __FUNCTION__, __LINE__);
                }
            }
            pBase64Blob->blob.pBuffer = NULL;
            pBase64Blob->blob.bufferLen = 0;
        }
    }

    if (attrOut.pBase64Blob)
        DIGI_FREE((void **)&attrOut.pBase64Blob);

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNWRAP_KEY_VALIDATED_SECRET__
MSTATUS SMP_API(TPM2, unWrapKeyValidatedSecret,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_ObjectHandle rtKeyHandle,
        TAP_Blob *pBlob,
        TAP_Buffer *pSecret
)
{
    MSTATUS status = OK;
    CredentialUnwrapSecretIn unwrapSecretIn = {0};
    CredentialUnwrapSecretOut unwrapSecretOut = {0};
    SMP_Context *pSmpContext = NULL;
    TOKEN_Context *pToken = NULL;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    CACHED_KeyInfo *pAKey = NULL;
    CACHED_KeyInfo *pDecryptKey = NULL;
    byteBoolean moduleLocked = FALSE;

    if ((0 == moduleHandle) || (0 == tokenHandle) ||
            (0 == objectHandle) || (0 == rtKeyHandle) ||
            (NULL == pBlob) || (NULL == pSecret))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input, moduleHandle = %p, tokenHandle = %p, "
                "objectHandle = %p, rtKeyHandle = %p, pBlob = %p, "
                "pSecret = %p\n",
                __FUNCTION__, __LINE__, moduleHandle, tokenHandle,
                objectHandle, rtKeyHandle, pBlob, pSecret);
        goto exit;
    }

    if (  (NULL == pBlob->blob.pBuffer)
       || (0 >= pBlob->blob.bufferLen) )
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Invalid input, secret to unwrap cannot be empty. "
                "buffer = %p, buffer length= %d\n",
                __FUNCTION__, __LINE__,
                pBlob->blob.pBuffer, pBlob->blob.bufferLen);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pToken = (TOKEN_Context *)((uintptr)tokenHandle);
    pAKey = (CACHED_KeyInfo *)((uintptr)objectHandle);
    pDecryptKey = (CACHED_KeyInfo *)((uintptr)rtKeyHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting on mutex for module=%p, status=%d\n",
                __FUNCTION__, __LINE__, moduleHandle, status);
        goto exit;
    }
    moduleLocked = TRUE;

    unwrapSecretIn.activateKey = pAKey->keyName;
    unwrapSecretIn.decryptKey = pDecryptKey->keyName;
    unwrapSecretIn.blobLen = pBlob->blob.bufferLen;
    unwrapSecretIn.pBase64Blob = pBlob->blob.pBuffer;

    rc = FAPI2_CREDENTIAL_unwrapSecret(pSmpContext->pFapiContext,
            &unwrapSecretIn, &unwrapSecretOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d FAPI2 unwrapSecret error, rc = 0x%02x\n",
                __FUNCTION__, __LINE__, rc);
        goto exit;
    }

    /* Allocate output buffer */
    status = DIGI_MALLOC((void **)&pSecret->pBuffer,
            unwrapSecretOut.secret.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for output secret buffer, status = %d\n",
                    __FUNCTION__, __LINE__, status);
        goto exit;
    }

    status = DIGI_MEMCPY(pSecret->pBuffer, unwrapSecretOut.secret.buffer,
        unwrapSecretOut.secret.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error copying unwrapped secret to output buffer, "
                "status = %d\n",
                __FUNCTION__, __LINE__, (int)status);
        goto exit;
    }

    pSecret->bufferLen = unwrapSecretOut.secret.size;

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    if (OK != status)
    {
        if(pSecret)
        {
            if (NULL != pSecret->pBuffer)
            {
                if (OK != DIGI_FREE((void **)&pSecret->pBuffer))
                {
                    DB_PRINT("%s.%d Failed to release memory allocated "
                            "to secret buffer=%p on failure.\n",
                            __FUNCTION__, __LINE__, pSecret->pBuffer);
                }
            }
            pSecret->pBuffer = NULL;
            pSecret->bufferLen = 0;
        }
    }

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SMP_GET_QUOTE__

#define APISTATE_GETQUOTE_SIG_CREATED           0x10
#define APISTATE_GETQUOTE_SIG_ECC_CREATED       0x20
#define APISTATE_GETQUOTE_SIG_RSA_CREATED       0x40
#define APISTATE_GETQUOTE_QUOTEDATA_CREATED     0x80

MSTATUS SMP_API(TPM2, getQuote,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_TRUSTED_DATA_TYPE trustedDataType,
        TAP_TrustedDataInfo *pTrustedDataInfo,
        TAP_Buffer *pNonce,
        TAP_AttributeList *pReserved,
        TAP_Blob *pQuoteData,
        TAP_Signature **ppQuoteSignature
)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    SMP_Context *pSmpContext = NULL;
    TAP_HASH_ALG hashAlg = TPM2_ALG_SHA256;
    AttestationGetQuoteIn quoteIn = {0};
    AttestationGetQuoteOut quoteOut = {0};
    CACHED_KeyInfo *pCachedKey = NULL;
    TAP_RSASignature *pRsaSignature = NULL;
    TAP_ECCSignature *pEccSignature = NULL;
    TAP_Attribute *pAttribute = NULL;
    ubyte4 listCount = 0;
    TAP_Buffer *pKeyBuffer = NULL;
    ubyte4 pcrIndex = 0;
    ubyte4 pcrSelection = 0;
    ubyte state = 0x00;
    ubyte4 i = 0;

    if ((0 == moduleHandle) || (0 == objectHandle) || (NULL == pTrustedDataInfo)
            || (NULL == pQuoteData) || (NULL == ppQuoteSignature))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p, "
                "objectHandle = %p, pQuoteData = %p, "
                "ppQuoteSignature = %p\n",
                __FUNCTION__, __LINE__, moduleHandle, objectHandle,
                pQuoteData, ppQuoteSignature);
        goto exit;
    }

    pQuoteData->blob.pBuffer = NULL;
    pQuoteData->blob.bufferLen = 0;

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pCachedKey = (CACHED_KeyInfo *)((uintptr)objectHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting on mutex for module=%p, status=%d\n",
                __FUNCTION__, __LINE__, moduleHandle, status);
        goto exit;
    }
    state |= APISTATE_MODULE_MUTEX_LOCKED;

    /* Validate input */
    if (TAP_TRUSTED_DATA_TYPE_MEASUREMENT != trustedDataType)
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Invalid TrustedDataType %d, expected %d\n",
                __FUNCTION__, __LINE__, (int)trustedDataType,
                (int)(TAP_TRUSTED_DATA_TYPE_MEASUREMENT));
        goto exit;
    }

    if (1 != pTrustedDataInfo->subType)
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Invalid Trusted SubType %d, expected 1\n",
                __FUNCTION__, __LINE__, (int)pTrustedDataInfo->subType);
        goto exit;
    }

    if (pTrustedDataInfo->attributes.pAttributeList &&
            pTrustedDataInfo->attributes.listLen)
    {
        pAttribute = pTrustedDataInfo->attributes.pAttributeList;

        listCount = 0;
        while (listCount < pTrustedDataInfo->attributes.listLen)
        {
            /* handle parameters we need */
            switch (pAttribute->type)
            {
                case TAP_ATTR_HASH_ALG:
                    if ((sizeof (TAP_HASH_ALG) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid Hash algorithm Parameters, "
                                "length %d, expected %d, buffer %p\n",
                                __FUNCTION__, __LINE__, (int)pAttribute->length,
                                sizeof(TAP_HASH_ALG),
                                pAttribute->pStructOfType);
                        goto exit;
                    }

                    switch (*((TAP_HASH_ALG *)(pAttribute->pStructOfType)))
                    {
                        case TAP_HASH_ALG_SHA256:
                            hashAlg = TPM2_ALG_SHA256;
                            break;

                        case TAP_HASH_ALG_SHA384:
                            hashAlg = TPM2_ALG_SHA384;
                            break;

                        case TAP_HASH_ALG_SHA512:
                            hashAlg = TPM2_ALG_SHA512;
                            break;

                        default:
                            status = ERR_TAP_UNSUPPORTED_ALGORITHM;
                            DB_PRINT("%s.%d Unsupported hash algorithm %d, "
                                    "status 0x%02x\n",
                                    __FUNCTION__,__LINE__,
                                    *((TAP_HASH_ALG *)(pAttribute->pStructOfType)),
                                    status);
                            goto exit;
                    }

                    break;

                case TAP_ATTR_TRUSTED_DATA_KEY:
                    pKeyBuffer = (TAP_Buffer *)pAttribute->pStructOfType;
                    if(pKeyBuffer == NULL)
                    {
                         status = ERR_INVALID_ARG;
                         DB_PRINT("%s.%d Invalid TrustedData Key Value \n",
                         __FUNCTION__,__LINE__);
                         goto exit;
                    }

                    pcrSelection = 0;

                    for (i = 0; i < pKeyBuffer->bufferLen; i++)
                    {
                        pcrIndex = pKeyBuffer->pBuffer[i];

                        if ((TPM2_PCR_LAST < pcrIndex))
                        {
                            status = ERR_INVALID_ARG;
                            DB_PRINT("%s.%d Invalid TrustedDataType key value, "
                                    "pcrIndex %d, expected 0 - %d\n",
                                    __FUNCTION__, __LINE__, (int)pcrIndex,
                                    (int)TPM2_PCR_LAST);
                            goto exit;
                        }

                        pcrSelection |= (1 << pcrIndex);
                    }

                    break;

                default:
                    break;
            }

            pAttribute++;
            listCount++;
        }

        if (pNonce && pNonce->pBuffer)
        {
            if (sizeof(quoteIn.qualifyingData.buffer) < pNonce->bufferLen)
            {
                status = ERR_BUFFER_OVERFLOW;
                DB_PRINT("%s.%d Nonce buffer size=%d exceeds max limit=%d\n",
                        __FUNCTION__, __LINE__, pNonce->bufferLen,
                        sizeof(quoteIn.qualifyingData.buffer));
                goto exit;
            }

            quoteIn.qualifyingData.size = pNonce->bufferLen;
            status = DIGI_MEMCPY(quoteIn.qualifyingData.buffer, pNonce->pBuffer,
                    pNonce->bufferLen);
            if (OK != status)
            {
                DB_PRINT("%s.%d Unable to copy nonce to quote request, status = %d\n",
                __FUNCTION__, __LINE__, status);
                goto exit;
            }
        }

        quoteIn.quoteKey = pCachedKey->keyName;
        quoteIn.pcrSelection = pcrSelection;

        rc = FAPI2_ATTESTATION_getQuote(pSmpContext->pFapiContext,
                &quoteIn, &quoteOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d FAPI2_ATTESTATION_getQuote error, rc = 0x%02x\n",
                    __FUNCTION__, __LINE__, rc);
            goto exit;
        }

        if (!quoteOut.quoted.size)
        {
            status = ERR_TAP_CMD_FAILED;
            DB_PRINT("%s.%d Error, Quote buffer length = %d\n",
                    __FUNCTION__, __LINE__, quoteOut.quoted.size);
            goto exit;
        }

        /* Allocate Quote buffer */
        status = DIGI_CALLOC((void **)&pQuoteData->blob.pBuffer, 1,
                quoteOut.quoted.size);
        if (OK != status)
        {
            DB_PRINT("%s.%d Error allocating %d bytes for Quote data, "
                    "status = %d\n",
                    __FUNCTION__,__LINE__, quoteOut.quoted.size,
                    status);
            goto exit;
        }
        state |= APISTATE_GETQUOTE_QUOTEDATA_CREATED;

        pQuoteData->encoding = TAP_BLOB_ENCODING_BINARY;
        pQuoteData->format = TAP_BLOB_FORMAT_MOCANA;
        pQuoteData->blob.bufferLen = quoteOut.quoted.size;

        status = DIGI_MEMCPY(pQuoteData->blob.pBuffer,
                quoteOut.quoted.attestationData,
                quoteOut.quoted.size);
        if (OK != status)
        {
            DB_PRINT("%s.%d Error copying %d Quote data bytes, "
                    "status = %d\n",
                    __FUNCTION__,__LINE__, quoteOut.quoted.size,
                    status);
            goto exit;
        }

        /* Allocate Signature structure */
        status = DIGI_CALLOC((void **)ppQuoteSignature, 1,
                sizeof(TAP_Signature));
        if (OK != status)
        {
            DB_PRINT("%s.%d Error allocating %d bytes for Quote signature, "
                    "status = %d\n",
                    __FUNCTION__,__LINE__, sizeof(TAP_Signature),
                    status);
            goto exit;
        }
        state |= APISTATE_GETQUOTE_SIG_CREATED;

        (*ppQuoteSignature)->isDEREncoded = 0;

        switch (quoteOut.keyAlg)
        {
            case TPM2_ALG_RSA:
                (*ppQuoteSignature)->keyAlgorithm = TAP_KEY_ALGORITHM_RSA;

                pRsaSignature = &((*ppQuoteSignature)->signature.rsaSignature);
                pRsaSignature->signatureLen =
                    (ubyte4)(quoteOut.signature.rsaSignature.size);

                status = DIGI_CALLOC((void **)&(pRsaSignature->pSignature), 1,
                        pRsaSignature->signatureLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed allocating memory for RSA signature"
                            ", status=%d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                state |= APISTATE_GETQUOTE_SIG_RSA_CREATED;

                status = DIGI_MEMCPY((ubyte *)(pRsaSignature->pSignature),
                        (ubyte *)(quoteOut.signature.rsaSignature.buffer),
                        pRsaSignature->signatureLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed copying signature buffer for RSA,"
                                " status=%d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                break;

            case TPM2_ALG_ECC:
                (*ppQuoteSignature)->keyAlgorithm = TAP_KEY_ALGORITHM_ECC;

                pEccSignature = &((*ppQuoteSignature)->signature.eccSignature);

                /* Copy R data */
                pEccSignature->rDataLen =
                    (ubyte4)(quoteOut.signature.eccSignature.signatureR.size);
                status = DIGI_CALLOC((void **)&(pEccSignature->pRData), 1,
                        pEccSignature->rDataLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed allocating signature buffer for"
                            " ECC R data, status=%d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                state |= APISTATE_GETQUOTE_SIG_ECC_CREATED;

                status = DIGI_MEMCPY((ubyte *)(pEccSignature->pRData),
                        (ubyte *)(quoteOut.signature.eccSignature.signatureR.buffer),
                        pEccSignature->rDataLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed copying signature buffer into"
                            " ECC R data, status=%d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }

                /* Copy S data */
                pEccSignature->sDataLen =
                    (ubyte4)(quoteOut.signature.eccSignature.signatureS.size);
                status = DIGI_CALLOC((void **)&(pEccSignature->pSData), 1,
                        pEccSignature->sDataLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed allocating signature buffer into"
                            " ECC S data, status=%d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                status = DIGI_MEMCPY((ubyte *)(pEccSignature->pSData),
                        (ubyte *)(quoteOut.signature.eccSignature.signatureS.buffer),
                        pEccSignature->sDataLen);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed copying signature buffer into"
                            " ECC S data, status=%d\n",
                            __FUNCTION__, __LINE__, status);
                    goto exit;
                }
                break;

            default:
                goto exit;
                break;
        }

        (*ppQuoteSignature)->derEncSignature.bufferLen = 0;
        (*ppQuoteSignature)->derEncSignature.pBuffer = NULL;
    }
    else
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Invalid input. No data in TrustedDataInfo."
                " pTrustedDataInfo->attributes.pAttributeList=%p,"
                " pTrustedDataInfo->attributes.listLen=%d\n",
                __FUNCTION__, __LINE__,
                pTrustedDataInfo->attributes.pAttributeList,
                pTrustedDataInfo->attributes.listLen);
    }

exit:
    if (state & APISTATE_MODULE_MUTEX_LOCKED)
        RTOS_mutexRelease(pSmpContext->moduleMutex);


    if (OK != status)
    {
        if (state & APISTATE_GETQUOTE_QUOTEDATA_CREATED)
        {
            if (NULL != pQuoteData->blob.pBuffer)
            {
                if (OK != DIGI_FREE((void **)&(pQuoteData->blob.pBuffer)))
                {
                    DB_PRINT("%s.%d Failed to release memory allocated"
                             " to quote-data=%p on failure\n",
                             __FUNCTION__, __LINE__, pQuoteData->blob.pBuffer);
                }
                pQuoteData->blob.pBuffer = NULL;
                pQuoteData->blob.bufferLen = 0;
            }
        }
        if (state & APISTATE_GETQUOTE_SIG_ECC_CREATED)
        {
            if (NULL != pEccSignature->pRData)
            {
                if (OK != DIGI_FREE((void**)&(pEccSignature->pRData)))
                {
                    DB_PRINT("%s.%d Failed releasing memory allocated to"
                        " ECC signature R Data=%p on Error\n",
                        __FUNCTION__, __LINE__, pEccSignature->pRData);
                }
                pEccSignature->pRData = NULL;
                pEccSignature->rDataLen = 0;
            }
            if (NULL != pEccSignature->pSData)
            {
                if (OK != DIGI_FREE((void **)&(pEccSignature->pSData)))
                {
                    DB_PRINT("%s.%d Failed releasing memory allocated to"
                        " ECC signature S Data=%p on Error\n",
                        __FUNCTION__, __LINE__, pEccSignature->pSData);
                }
                pEccSignature->pSData = NULL;
                pEccSignature->sDataLen = 0;
            }
        }
        if (state & APISTATE_GETQUOTE_SIG_RSA_CREATED)
        {
            if (OK != DIGI_FREE((void **)&(pRsaSignature->pSignature)))
            {
                DB_PRINT("%s.%d Failed releasing memory allocated to"
                        " RSA signature=%p on Error\n",
                        __FUNCTION__, __LINE__, pRsaSignature->pSignature);
            }
            pRsaSignature->pSignature = NULL;
            pRsaSignature->signatureLen = 0;

        }
        if (state & APISTATE_GETQUOTE_SIG_CREATED)
        {
            if (OK != DIGI_FREE((void **)ppQuoteSignature))
            {
                DB_PRINT("%s.%d Failed releasing memory allocated to"
                        " Quote Signature struct=%p on Error\n",
                        __FUNCTION__, __LINE__, *ppQuoteSignature);
                *ppQuoteSignature = NULL;
            }
        }
    }

    return status;
}
#endif

#if (defined __SMP_ENABLE_SMP_CC_CREATE_ASYMMETRIC_KEY__) || (defined __SMP_ENABLE_SMP_CC_CREATE_SYMMETRIC_KEY__)

MSTATUS TPM2_validateECCSigScheme(TAP_ECC_CURVE curveId, TAP_SIG_SCHEME sigScheme)
{
    MSTATUS status = ERR_TAP_INSUFFICIENT_HASH_LENGTH;

    /* Allow a NULL scheme */
    if (TAP_SIG_SCHEME_NONE == sigScheme)
    {
        status = OK;
        goto exit;
    }

    if ((TAP_SIG_SCHEME_ECDSA_SHA1 > sigScheme) || (TAP_SIG_SCHEME_ECDSA_SHA512 < sigScheme))
    {
        status = ERR_TAP_INVALID_SCHEME;
        goto exit;
    }

    status = OK;
    switch (curveId)
    {
        case TAP_ECC_CURVE_NIST_P192:
            break;
        case TAP_ECC_CURVE_NIST_P224:
            if ((TAP_SIG_SCHEME_ECDSA_SHA224 > sigScheme) && (TAP_SIG_SCHEME_NONE != sigScheme))
                status = ERR_TAP_INSUFFICIENT_HASH_LENGTH;
            break;
        case TAP_ECC_CURVE_NIST_P256:
            if ((TAP_SIG_SCHEME_ECDSA_SHA256 > sigScheme) && (TAP_SIG_SCHEME_NONE != sigScheme))
                status = ERR_TAP_INSUFFICIENT_HASH_LENGTH;
           break;
        case TAP_ECC_CURVE_NIST_P384:
            if ((TAP_SIG_SCHEME_ECDSA_SHA384 > sigScheme) && (TAP_SIG_SCHEME_NONE != sigScheme))
                status = ERR_TAP_INSUFFICIENT_HASH_LENGTH;
           break;
        case TAP_ECC_CURVE_NIST_P521:
            if ((TAP_SIG_SCHEME_ECDSA_SHA512 > sigScheme)&& (TAP_SIG_SCHEME_NONE != sigScheme))
                status = ERR_TAP_INSUFFICIENT_HASH_LENGTH;
            break;
        default:
                status = ERR_TAP_INVALID_CURVE_ID;
            break;
    }

exit:
    return status;
}

/*------------------------------------------------------------------*/
MSTATUS TPM2_keyCreated(SMP_Context *pSmpContext, TAP_ObjectId objectId,
        ubyte *pObjectPresent)
{
    MSTATUS status = OK;
    TAP_EntityList objectIdList = {0};
    ubyte4 i = 0;

    if ((NULL == pSmpContext) || (NULL == pObjectPresent))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    *pObjectPresent = 0;

    status = TPM2_getAllProvisionedIds(pSmpContext, &objectIdList);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to retrieve all provisioned IDs, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    if (objectIdList.entityType != TAP_ENTITY_TYPE_OBJECT)
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }

    for (i = 0; i < objectIdList.entityIdList.numEntities; i++)
    {
        if (objectId == objectIdList.entityIdList.pEntityIdList[i])
        {
            /* Found */
            *pObjectPresent = 1;
            break;
        }
    }

exit:
    if (objectIdList.entityIdList.pEntityIdList)
        DIGI_FREE((void **)&objectIdList.entityIdList.pEntityIdList);

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS TPM2_asymGeneratePrimaryKey(SMP_Context *pSmpContext,
                        TOKEN_Context *pToken,
                        AsymCreateKeyIn *pCreateKeyIn,
                        TAP_Buffer *pEntropyBuffer,
                        AsymCreateKeyOut *pCreateKeyOut)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    AsymCreatePrimaryKeyIn keyIn = { 0 };
    AsymCreatePrimaryKeyOut keyOut = { 0 };
    TPM2B_DATA outsideInfo = { 0 };
    AsymGetPublicKeyIn pubKeyIn = { 0 };
    AsymGetPublicKeyOut pubKeyOut = { 0 };
    ContextLoadObjectExIn loadIn = { 0 };
    ContextLoadObjectExOut loadOut = { 0 };
    ContextFlushObjectIn flushObjectIn = { 0 };
    byteBoolean flushObjectOnFailure = FALSE;

    if (!pSmpContext || !pCreateKeyIn || !pCreateKeyOut || !pToken)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid pointer inputs, status=%d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    if ((pCreateKeyIn->keyAlg != TPM2_ALG_RSA) && (pCreateKeyIn->keyAlg != TPM2_ALG_ECC))
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Invalid key algorithm, status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    keyIn.persistentHandle = pCreateKeyIn->objectId;

    if (SMP_TPM2_CRYPTO_TOKEN_ID == pToken->id)
    {
        keyIn.hierarchy = TPM2_RH_OWNER;
    }
    else if (SMP_TPM2_PLATFORM_TOKEN_ID == pToken->id)
    {
        keyIn.hierarchy = TPM2_RH_PLATFORM;
    }
    else
    {
        keyIn.hierarchy = TPM2_RH_ENDORSEMENT;
    }

    keyIn.pNewKeyAuth = &pCreateKeyIn->keyAuth;
    keyIn.pOutsideInfo = &outsideInfo;
    keyIn.keyAlg = pCreateKeyIn->keyAlg;

    if (pCreateKeyIn->keyAlg == TPM2_ALG_RSA)
    {
        keyIn.keyInfo.rsaInfo = pCreateKeyIn->keyInfo.rsaInfo;
        /* set entropy  */
        if (NULL != pEntropyBuffer && 0 < pEntropyBuffer->bufferLen)
        {
            /* Ensure entropy does not exceed RSA entropy buffer */
            if (sizeof(keyIn.externalEntryopy.rsaEntropy.buffer) < pEntropyBuffer->bufferLen)
            {
                status = ERR_TAP_INVALID_SIZE;
                DB_PRINT("%s.%d Provided entropy for RSA too large, status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }

            keyIn.externalEntryopy.rsaEntropy.size = pEntropyBuffer->bufferLen;
            status = DIGI_MEMCPY((void *)keyIn.externalEntryopy.rsaEntropy.buffer,
                    (void *)(pEntropyBuffer->pBuffer), pEntropyBuffer->bufferLen);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy RSA entropy, status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
        }
    }
    else
    {
        keyIn.keyInfo.eccInfo = pCreateKeyIn->keyInfo.eccInfo;
        /* set entropy  */
        if (NULL != pEntropyBuffer && 0 < pEntropyBuffer->bufferLen)
        {
            /* Ensure entropy does not exceed ECC entropy buffer */
            if (sizeof(keyIn.externalEntryopy.eccEntropy.x.buffer) < pEntropyBuffer->bufferLen)
            {
                status = ERR_TAP_INVALID_SIZE;
                DB_PRINT("%s.%d Provided entropy for ECC x too large, status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }

            keyIn.externalEntryopy.eccEntropy.x.size = pEntropyBuffer->bufferLen;
            status = DIGI_MEMCPY((void *)keyIn.externalEntryopy.eccEntropy.x.buffer,
                    (void *)(pEntropyBuffer->pBuffer), pEntropyBuffer->bufferLen);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy ECC x entropy, status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
        }

        /* For interoperability with TSS tools the ECC y entropy value is
         * NOT set. When setting ECC x entropy value, the TSS tools consume the
         * same entropy by constructing the ECC x and y value, where the entropy
         * for x and y is the same. */
    }

    keyIn.additionalAttributes |= TPMA_OBJECT_USERWITHAUTH;

    rc = FAPI2_ASYM_createPrimaryAsymKey(
        pSmpContext->pFapiContext, &(pSmpContext->platformAuth), &keyIn, &keyOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to Create primary key, status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    if (NULL == keyOut.pKey)
    {
        status = ERR_GENERAL;
        DB_PRINT("%s.%d Key-Buffer in primary key created is NULL, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    loadIn.pObj = keyOut.pKey;
    /*
     * Must already be set during creation
     */
    loadIn.pAuthObj = NULL;
    rc = FAPI2_CONTEXT_loadObjectEx(pSmpContext->pFapiContext, &loadIn, &loadOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to load object into context, "
                "status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }
    flushObjectOnFailure=TRUE;

    /* Copy key name */
    status = DIGI_MEMCPY(pCreateKeyOut->keyName.name, keyOut.pKey->objectName.name,
            keyOut.pKey->objectName.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy keyname, "
                "status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }
    pCreateKeyOut->keyName.size = keyOut.pKey->objectName.size;

    /* FAPI2_UTILS_serialize sets key buffer */
    rc = FAPI2_UTILS_serialize(&keyOut.pKey, FALSE, &pCreateKeyOut->key);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to get serialized key, "
                "status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    /* retrieve and set public key */
    pubKeyIn.keyName = pCreateKeyOut->keyName;
    rc = FAPI2_ASYM_getPublicKey(pSmpContext->pFapiContext, &pubKeyIn, &pubKeyOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to get public key, "
                "status=%d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }
    pCreateKeyOut->publicKey = pubKeyOut.publicKey;

    /* Copy key algorithm */
    pCreateKeyOut->keyAlg = pCreateKeyIn->keyAlg;

    rc = TSS2_RC_SUCCESS;

exit:
    if (TSS2_RC_SUCCESS != rc)
    {
        if (flushObjectOnFailure)
        {
            flushObjectIn.objName = loadOut.objName;
            FAPI2_CONTEXT_flushObject(pSmpContext->pFapiContext, &flushObjectIn);

            /* Destroy the primary key object after copying */
            if (NULL != keyOut.pKey)
            {
                rc = FAPI2_UTILS_destroyObject(&keyOut.pKey);
                if (TSS2_RC_SUCCESS != rc)
                {
                    status = SMP_TPM2_UTILS_getMocanaError(rc);
                    DB_PRINT("%s.%d Failed to destroy FAPI object, status = %d\n",
                            __FUNCTION__, __LINE__, status);
                }
            }
        }
    }

    return rc;
}

/*------------------------------------------------------------------*/
MSTATUS TPM2_asymGenerateKey(SMP_Context *pSmpContext, TOKEN_Context *pToken,
        TAP_ObjectId objectId, TAP_KeyAttributes *pKeyAttributeList,
        TAP_ObjectHandle *pKeyHandle,
        TAP_ObjectCapabilityAttributes *pKeyObjectAttributes)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_RC_SUCCESS;
    AsymCreateKeyIn createKeyIn = { 0 };
    AsymCreateKeyOut createKeyOut = { 0 };
    ContextSetObjectAuthIn objAuthIn = {0};
    TAP_KEY_ALGORITHM keyAlgorithm = TAP_KEY_ALGORITHM_RSA;
    TAP_KEY_USAGE keyUsage = TAP_KEY_USAGE_DECRYPT;
    TAP_KEY_SIZE keySize = TAP_KEY_SIZE_2048;
    TAP_ENC_SCHEME encScheme = TAP_ENC_SCHEME_PKCS1_5;
    TAP_SIG_SCHEME sigScheme = TAP_SIG_SCHEME_PKCS1_5;
    TAP_ECC_CURVE eccCurve =  TAP_ECC_CURVE_NIST_P192;
    TAP_KEY_CMK keyCmk = TAP_KEY_CMK_DISABLE;
    ubyte4 exponent = 0x10001;
    CACHED_KeyInfo *pCachedKey = NULL;
    ubyte4 numCreatedKeyAttributes = 0;
    TAP_Attribute *pCreatedKeyAttributes = NULL;
    TAP_Attribute *pAttribute = NULL;
    ubyte4 count = 0;
    ContextGetPrimaryObjectNameIn objNameIn = {0};
    ContextGetPrimaryObjectNameOut objNameOut = {0};
    TPM2B_AUTH *pKeyAuth = NULL;
    FAPI2_KEY_INFO_UNION *pKeyInfo = NULL;
    TAP_CredentialList *pKeyCredentials = NULL;
    ubyte objectPresent = 0;
    TAP_CREATE_KEY_TYPE keyType = TAP_CREATE_KEY_TYPE_NON_PRIMARY;
    TAP_Buffer *pKeyEntropyBuffer = NULL;
    TAP_Blob *pBlob = NULL;
    TAP_Buffer *pIdBuf = NULL;
    sbyte4 i = 0;

    if ((NULL == pSmpContext) || (NULL == pKeyHandle))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, pSmpContext = %p,"
                "pKeyHandle = %p\n",
                __FUNCTION__, __LINE__, pSmpContext, pKeyHandle);
        goto exit;
    }

    status = DIGI_CALLOC((void **)&pCachedKey, 1, sizeof(*pCachedKey));

    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for cached key object,"
               " status = %d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

    if (pKeyAttributeList && pKeyAttributeList->listLen)
    {
        for (count = 0; count < pKeyAttributeList->listLen; count++)
        {
            pAttribute = &pKeyAttributeList->pAttributeList[count];

            switch (pAttribute->type)
            {
                case TAP_ATTR_KEY_ALGORITHM:
                    if (sizeof(TAP_KEY_ALGORITHM) == pAttribute->length)
                        keyAlgorithm = *(TAP_KEY_ALGORITHM *)pAttribute->pStructOfType;
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key algorithm length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    break;

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
                case TAP_ATTR_KEY_CMK:
                    if (sizeof(TAP_KEY_CMK) == pAttribute->length)
                        keyCmk = *((TAP_KEY_CMK *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key cmk length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    break;
                case TAP_ATTR_CREDENTIAL_SET:
                    pKeyAuth = &createKeyIn.keyAuth;
                    pKeyCredentials = (TAP_CredentialList*)pAttribute->pStructOfType;
                    TPM2_getCredentialsList(
                                (TAP_CredentialList *)pAttribute->pStructOfType,
                                TAP_CREDENTIAL_TYPE_PASSWORD, pKeyAuth);

                    break;

                case TAP_ATTR_KEY_SIZE:
                    if (sizeof(TAP_KEY_SIZE) == pAttribute->length)
                        keySize = *((TAP_KEY_SIZE *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key size structure length %d, status = %d\n",
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

                case TAP_ATTR_CREATE_KEY_TYPE:
                    if (sizeof(TAP_CREATE_KEY_TYPE) == pAttribute->length)
                        keyType = *((TAP_CREATE_KEY_TYPE *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key curve structure length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    break;

                case TAP_ATTR_CREATE_KEY_ENTROPY:
                    if ((sizeof(TAP_Buffer) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid TAP Buffer. length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    pKeyEntropyBuffer = (TAP_Buffer *)(pAttribute->pStructOfType);
                    if ( (NULL == pKeyEntropyBuffer->pBuffer) ||
                         (0 == pKeyEntropyBuffer->bufferLen) )
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Entropy TAP Buffer is NULL or 0 length = %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }

                    break;

                case TAP_ATTR_OBJECT_ID_BYTESTRING:
                    if (0x00L != objectId)
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Multiple object ID values provided.\n",
                                __FUNCTION__, __LINE__);
                        goto exit;
                    }

                    if ((sizeof(TAP_Buffer) != pAttribute->length) ||
                        (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid storage structure length %d, "
                                "pStructOfType = %p\n",
                                __FUNCTION__, __LINE__, pAttribute->length,
                                pAttribute->pStructOfType);
                        goto exit;
                    }

                    pIdBuf = (TAP_Buffer *)(pAttribute->pStructOfType);
                    if (pIdBuf->bufferLen > 8)
                    {
                        status = ERR_INVALID_INPUT;
                        DB_PRINT("%s.%d Invalid id length %d\n",
                                __FUNCTION__, __LINE__, pIdBuf->bufferLen);
                        goto exit;                
                    }

                    if (NULL == pIdBuf->pBuffer)
                    {
                        status = ERR_NULL_POINTER;
                        DB_PRINT("%s.%d Null id buffer\n",
                                __FUNCTION__, __LINE__);
                        goto exit;   
                    }

                    for (i = 0; i < (sbyte4) pIdBuf->bufferLen; i++)
                    {
                        /* convert byte array as a big Endian integer */
                        objectId |= ( ((TAP_ObjectId) (pIdBuf->pBuffer[i])) << (8 * (pIdBuf->bufferLen - 1 - i)) );
                    }

                    break;
            }
        }
    }

    if (objectId)
    {
        status = TPM2_keyCreated(pSmpContext, objectId,
                &objectPresent);
        if (OK != status)
        {
            DB_PRINT("%s.%d Error getting key creation status, status %d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }

        /* If a key object is already present at the provided persistence ID, 
         * then do not proceed with the creation. */
        if (objectPresent)
        {
            status = ERR_INVALID_ARG;
            DB_PRINT("%s.%d An object already exists at the provided ID = 0x%08x, status=%d\n",
                    __FUNCTION__,__LINE__, objectId, status);
            goto exit;
        }
    }

    pCachedKey->keyAlgorithm = keyAlgorithm;
    switch(keyAlgorithm)
    {
        /* RSA Key handling */
        case TAP_KEY_ALGORITHM_RSA:
            {
                createKeyIn.keyAlg = TPM2_ALG_RSA;
                pKeyInfo = &createKeyIn.keyInfo;

                if (TAP_CREATE_KEY_TYPE_PRIMARY == keyType)
                {
                    exponent = 0x0000;
                }

                pKeyInfo->rsaInfo.exponent = exponent;

                switch(keySize)
                {
                    case TAP_KEY_SIZE_1024:
                        pKeyInfo->rsaInfo.keySize = 1024;
                        break;
                    case TAP_KEY_SIZE_2048:
                        pKeyInfo->rsaInfo.keySize = 2048;
                        break;
                    case TAP_KEY_SIZE_3072:
                        pKeyInfo->rsaInfo.keySize = 3072;
                        break;
                    case TAP_KEY_SIZE_4096:
                        pKeyInfo->rsaInfo.keySize = 4096;
                        break;
                    default:
                        status = ERR_TAP_INVALID_KEY_SIZE;
                        goto exit;
                }

                switch(keyUsage)
                {
                    case TAP_KEY_USAGE_SIGNING:
                    case TAP_KEY_USAGE_ATTESTATION:
                        {
                            if (TAP_KEY_USAGE_SIGNING == keyUsage)
                                pKeyInfo->rsaInfo.keyType = FAPI2_ASYM_TYPE_SIGNING;
                            else
                                pKeyInfo->rsaInfo.keyType = FAPI2_ASYM_TYPE_ATTESTATION;

                            switch(sigScheme)
                            {
                                case TAP_SIG_SCHEME_PKCS1_5:
                                    pKeyInfo->rsaInfo.scheme = TPM2_ALG_RSASSA;
                                    pKeyInfo->rsaInfo.hashAlg = TPM2_ALG_SHA256;
                                    break;
                                case TAP_SIG_SCHEME_PSS_SHA1:
                                    pKeyInfo->rsaInfo.scheme = TPM2_ALG_RSAPSS;
                                    pKeyInfo->rsaInfo.hashAlg = TPM2_ALG_SHA1;
                                    break;
                                case TAP_SIG_SCHEME_PSS_SHA256:
                                    pKeyInfo->rsaInfo.scheme = TPM2_ALG_RSAPSS;
                                    pKeyInfo->rsaInfo.hashAlg = TPM2_ALG_SHA256;
                                    break;
                                case TAP_SIG_SCHEME_PSS_SHA384:
                                    pKeyInfo->rsaInfo.scheme = TPM2_ALG_RSAPSS;
                                    pKeyInfo->rsaInfo.hashAlg = TPM2_ALG_SHA384;
                                    break;
                                case TAP_SIG_SCHEME_PSS_SHA512:
                                    pKeyInfo->rsaInfo.scheme = TPM2_ALG_RSAPSS;
                                    pKeyInfo->rsaInfo.hashAlg = TPM2_ALG_SHA512;
                                    break;
                                case TAP_SIG_SCHEME_PKCS1_5_SHA1:
                                    pKeyInfo->rsaInfo.scheme = TPM2_ALG_RSASSA;
                                    pKeyInfo->rsaInfo.hashAlg = TPM2_ALG_SHA1;
                                    break;
                                case TAP_SIG_SCHEME_PKCS1_5_SHA256:
                                    pKeyInfo->rsaInfo.scheme = TPM2_ALG_RSASSA;
                                    pKeyInfo->rsaInfo.hashAlg = TPM2_ALG_SHA256;
                                    break;
                                case TAP_SIG_SCHEME_PKCS1_5_SHA384:
                                    pKeyInfo->rsaInfo.scheme = TPM2_ALG_RSASSA;
                                    pKeyInfo->rsaInfo.hashAlg = TPM2_ALG_SHA384;
                                    break;
                                case TAP_SIG_SCHEME_PKCS1_5_SHA512:
                                    pKeyInfo->rsaInfo.scheme = TPM2_ALG_RSASSA;
                                    pKeyInfo->rsaInfo.hashAlg = TPM2_ALG_SHA512;
                                    break;
                                case TAP_SIG_SCHEME_NONE:
                                    if (TAP_KEY_USAGE_ATTESTATION == keyUsage)
                                    {
                                        status = ERR_TAP_INVALID_SCHEME;
                                        goto exit;
                                    }
                                    pKeyInfo->rsaInfo.scheme = TPM2_ALG_NULL;
                                    pKeyInfo->rsaInfo.hashAlg = TPM2_ALG_SHA256;
                                    break;
                                case TAP_SIG_SCHEME_PKCS1_5_DER:
                                default:
                                    status = ERR_TAP_INVALID_SCHEME;
                                    goto exit;
                            }
                            break;
                        } /* TAP_KEY_USAGE_SIGNING or TAP_KEY_USAGE_ATTESTATION */

                    case TAP_KEY_USAGE_DECRYPT:
                        {
                            pKeyInfo->rsaInfo.keyType = FAPI2_ASYM_TYPE_DECRYPT;

                            switch(encScheme)
                            {
                                case TAP_ENC_SCHEME_PKCS1_5:
                                    pKeyInfo->rsaInfo.scheme = TPM2_ALG_RSAES;
                                    pKeyInfo->rsaInfo.hashAlg = TPM2_ALG_SHA256;
                                    break;
                                case TAP_ENC_SCHEME_OAEP_SHA1:
                                    pKeyInfo->rsaInfo.scheme = TPM2_ALG_OAEP;
                                    pKeyInfo->rsaInfo.hashAlg = TPM2_ALG_SHA1;
                                    break;
                                case TAP_ENC_SCHEME_OAEP_SHA256:
                                    pKeyInfo->rsaInfo.scheme = TPM2_ALG_OAEP;
                                    pKeyInfo->rsaInfo.hashAlg = TPM2_ALG_SHA256;
                                    break;
                                case TAP_ENC_SCHEME_OAEP_SHA384:
                                    pKeyInfo->rsaInfo.scheme = TPM2_ALG_OAEP;
                                    pKeyInfo->rsaInfo.hashAlg = TPM2_ALG_SHA384;
                                    break;
                                case TAP_ENC_SCHEME_OAEP_SHA512:
                                    pKeyInfo->rsaInfo.scheme = TPM2_ALG_OAEP;
                                    pKeyInfo->rsaInfo.hashAlg = TPM2_ALG_SHA512;
                                    break;
                                case TAP_ENC_SCHEME_NONE:
                                    pKeyInfo->rsaInfo.scheme = TPM2_ALG_NULL;
                                    pKeyInfo->rsaInfo.hashAlg = TPM2_ALG_SHA256;
                                    break;
                                default:
                                    status = ERR_TAP_INVALID_SCHEME;
                                    goto exit;
                            }
                            break;
                        } /* TAP_KEY_USAGE_DECRYPT */

                    case TAP_KEY_USAGE_STORAGE:
                    case TAP_KEY_USAGE_GENERAL:
                        {
                            if (TAP_KEY_USAGE_STORAGE == keyUsage)
                                pKeyInfo->rsaInfo.keyType = FAPI2_ASYM_TYPE_STORAGE;
                            else
                                pKeyInfo->rsaInfo.keyType = FAPI2_ASYM_TYPE_GENERAL;

                            pKeyInfo->rsaInfo.scheme = TPM2_ALG_NULL;
                            pKeyInfo->rsaInfo.hashAlg = TPM2_ALG_SHA256;
                            break;
                        }  /* TAP_KEY_USAGE_STORAGE or TAP_KEY_USAGE_GENERAL */

                    default:
                        status = ERR_TAP_INVALID_KEY_USAGE;
                        DB_PRINT("%s.%d Invalid key usage value %d, status = %d\n",
                            __FUNCTION__,__LINE__, (int)keyUsage, status);
                        goto exit;
                }

                break;
            }    /* RSA Key Handling */

            /* ECC Key Handling */
        case TAP_KEY_ALGORITHM_ECC:
            {
                createKeyIn.keyAlg = TPM2_ALG_ECC;
                pKeyInfo = &createKeyIn.keyInfo;

                status = TPM2_validateECCSigScheme(eccCurve, sigScheme);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Invalid ECC key signing scheme %d or curveId %d, status = %d\n",
                            __FUNCTION__,__LINE__, (int)sigScheme,
                            (int)eccCurve, status);
                    goto exit;
                }

                switch (eccCurve)
                {
                    case TAP_ECC_CURVE_NIST_P192:
                        pKeyInfo->eccInfo.curveID = TPM2_ECC_NIST_P192;
                        break;
                    case TAP_ECC_CURVE_NIST_P224:
                        pKeyInfo->eccInfo.curveID = TPM2_ECC_NIST_P224;
                        break;
                    case TAP_ECC_CURVE_NIST_P256:
                        pKeyInfo->eccInfo.curveID = TPM2_ECC_NIST_P256;
                        break;
                    case TAP_ECC_CURVE_NIST_P384:
                        pKeyInfo->eccInfo.curveID = TPM2_ECC_NIST_P384;
                        break;
                    case TAP_ECC_CURVE_NIST_P521:
                        pKeyInfo->eccInfo.curveID = TPM2_ECC_NIST_P521;
                        break;
                    case TAP_ECC_CURVE_NONE:
                    default:
                        status = ERR_TAP_INVALID_CURVE_ID;
                        DB_PRINT("%s.%d Invalid ECC key curveId %d, status = %d\n",
                            __FUNCTION__,__LINE__, eccCurve, status);
                        goto exit;
                        break;
                }  /* curveId */

                switch(keyUsage)
                {
                    case TAP_KEY_USAGE_SIGNING:
                        {
                            pKeyInfo->eccInfo.keyType = FAPI2_ASYM_TYPE_SIGNING;
                            switch (sigScheme)
                            {
                                case TAP_SIG_SCHEME_ECDSA_SHA1:
                                case TAP_SIG_SCHEME_ECDSA_SHA256:
                                case TAP_SIG_SCHEME_ECDSA_SHA384:
                                case TAP_SIG_SCHEME_ECDSA_SHA512:
                                    pKeyInfo->eccInfo.scheme = TPM2_ALG_ECDSA;
                                    break;
                                case TAP_SIG_SCHEME_NONE:
                                default:
                                    status = ERR_TAP_INVALID_SCHEME;
                                    DB_PRINT("%s.%d Invalid ECDSA key signing scheme %d, status = %d\n",
                                            __FUNCTION__,__LINE__, (int)sigScheme, status);
                                    goto exit;
                            }
                            break;
                        }  /* TAP_KEY_USAGE_SIGNING */

                    case TAP_KEY_USAGE_ATTESTATION:
                        {
                            pKeyInfo->eccInfo.keyType = FAPI2_ASYM_TYPE_ATTESTATION;
                            switch (sigScheme)
                            {
                                case TAP_SIG_SCHEME_ECDSA_SHA1:
                                case TAP_SIG_SCHEME_ECDSA_SHA256:
                                case TAP_SIG_SCHEME_ECDSA_SHA384:
                                case TAP_SIG_SCHEME_ECDSA_SHA512:
                                    pKeyInfo->eccInfo.scheme = TPM2_ALG_ECDSA;
                                    break;
                                case TAP_SIG_SCHEME_NONE:
                                default:
                                    status = ERR_TAP_INVALID_SCHEME;
                                    DB_PRINT("%s.%d Invalid ECC key signing scheme %d, status = %d\n",
                                            __FUNCTION__,__LINE__, (int)sigScheme, status);
                                    goto exit;
                            }
                            break;
                        }  /* TAP_KEY_USAGE_ATTESTATION */

                    case TAP_KEY_USAGE_DECRYPT:
                        {
                            pKeyInfo->eccInfo.keyType = FAPI2_ASYM_TYPE_DECRYPT;
                            if (TAP_SIG_SCHEME_NONE == sigScheme)
                            {
                                pKeyInfo->eccInfo.scheme = TPM2_ALG_NULL;
                            }
                            else
                            {
                                status = ERR_TAP_INVALID_SCHEME;
                                DB_PRINT("%s.%d Invalid ECC key signing scheme %d, status = %d\n",
                                        __FUNCTION__,__LINE__, (int)sigScheme, status);
                                goto exit;
                            }
                            break;
                        }  /* TAP_KEY_USAGE_DECRYPT */

                    case TAP_KEY_USAGE_STORAGE:
                        {
                            pKeyInfo->eccInfo.keyType = FAPI2_ASYM_TYPE_STORAGE;
                            pKeyInfo->eccInfo.scheme = TPM2_ALG_NULL;
                            break;
                        }  /* TAP_KEY_USAGE_STORAGE */

                    case TAP_KEY_USAGE_GENERAL:
                        {
                            pKeyInfo->eccInfo.keyType = FAPI2_ASYM_TYPE_GENERAL;
                            /* sigScheme ignored for this key type */
                            pKeyInfo->eccInfo.scheme = TPM2_ALG_NULL;
                            break;
                        }  /* TAP_KEY_USAGE_GENERAL */

                }  /* keyUsage */
                break;
            }         /* ECC Key Handling */

        default:
            status = ERR_TAP_INVALID_ALGORITHM;
            DB_PRINT("%s.%d Invalid key algorithm %d, status = %d\n",
                            __FUNCTION__,__LINE__, (int)keyAlgorithm, status);
            goto exit;
    }

    createKeyIn.objectId = (ubyte4)objectId;

    if (TAP_CREATE_KEY_TYPE_PRIMARY == keyType)
    {

        rc = TPM2_asymGeneratePrimaryKey(pSmpContext,
                        pToken, &createKeyIn, pKeyEntropyBuffer, &createKeyOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d Primary Key creation failed, "
                    "rc 0x%02x\n",
                    __FUNCTION__,__LINE__, rc);
            goto exit;
        }
    }
    else
    {
        /* For now return an error if the user is trying to create a key under
         * the platform hierarchy. Should be possible in theory */
        if (SMP_TPM2_PLATFORM_TOKEN_ID == pToken->id)
        {
            status = ERR_TAP_NO_TOKEN_AVAILABLE;
            DB_PRINT("%s.%d Invalid token hierarchy %d, status = %d\n",
                            __FUNCTION__,__LINE__, (int)pToken->id, status);
            goto exit;
        }

        objNameIn.persistentHandle = (pToken->id == SMP_TPM2_CRYPTO_TOKEN_ID) ?
            FAPI2_RH_SRK : FAPI2_RH_EK;

        rc = FAPI2_CONTEXT_getPrimaryObjectName(pSmpContext->pFapiContext,
                &objNameIn, &objNameOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d Failed to get primary object name for id %d, "
                    "rc 0x%02x\n",
                    __FUNCTION__,__LINE__, (int)pToken->id, rc);
            goto exit;
        }

        createKeyIn.pParentName = &objNameOut.objName;
        createKeyIn.bEnableBackup = keyCmk ;
        rc = FAPI2_ASYM_createAsymKey(pSmpContext->pFapiContext,
                &createKeyIn, &createKeyOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d Failed to create child key under SRK, "
                    "rc 0x%02x\n",
                    __FUNCTION__,__LINE__, rc);
            goto exit;
        }

        objAuthIn.objName = createKeyOut.keyName;
        objAuthIn.objAuth = createKeyIn.keyAuth;
        objAuthIn.forceUseAuthValue = 1;

        rc = FAPI2_CONTEXT_setObjectAuth(pSmpContext->pFapiContext,
                &objAuthIn);
        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d Failed to set object auth, "
                    "rc 0x%02x\n",
                    __FUNCTION__,__LINE__, rc);
            goto exit;
        }
    }

    if (pKeyObjectAttributes)
    {
        /* Put together TAP Attribute list of the parameters used to create
           this key
         */
        numCreatedKeyAttributes = 7;
        pKeyObjectAttributes->listLen = numCreatedKeyAttributes;

        status = DIGI_CALLOC((void **)&pKeyObjectAttributes->pAttributeList, 1,
                sizeof(TAP_Attribute) * numCreatedKeyAttributes);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for created key attribute list"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        count = 0;
        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

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

        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

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

        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

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

        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

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

        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

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
        else
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

        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

        pCreatedKeyAttributes->type = TAP_ATTR_SERIALIZED_OBJECT_BLOB;
        pCreatedKeyAttributes->length = sizeof(TAP_Blob);
        status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                sizeof(TAP_Blob));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for Object blob attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        pBlob = (TAP_Blob *) pCreatedKeyAttributes->pStructOfType;

        status = DIGI_MALLOC((void **)&pBlob->blob.pBuffer, createKeyOut.key.size);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for Object blob buffer"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        pBlob->blob.bufferLen = createKeyOut.key.size;
        status = DIGI_MEMCPY(pBlob->blob.pBuffer, createKeyOut.key.buffer, createKeyOut.key.size);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for Object blob buffer"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        pBlob->format = TAP_BLOB_FORMAT_MOCANA;
        pBlob->encoding = TAP_BLOB_ENCODING_BINARY;

        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

        /* Last entry */
        pCreatedKeyAttributes->type = TAP_ATTR_NONE;
        pCreatedKeyAttributes->length = 0;
        pCreatedKeyAttributes->pStructOfType = NULL;
    }

    pCachedKey->keyAlgorithm = keyAlgorithm;

    status = DIGI_MEMCPY(pCachedKey->keyName.name, createKeyOut.keyName.name,
            createKeyOut.keyName.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy keyname, "
                "status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }
    pCachedKey->keyName.size = createKeyOut.keyName.size;

    status = DIGI_MEMCPY(pCachedKey->key.buffer, createKeyOut.key.buffer,
            createKeyOut.key.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy serialized key, "
                "status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }
    pCachedKey->key.size = createKeyOut.key.size;
    pCachedKey->objectType = TPM2_OBJECT_TYPE_KEY;
    pCachedKey->id = objectId;
    *pKeyHandle = (TAP_ObjectHandle)((uintptr)pCachedKey);
    pCachedKey = NULL;

exit:
    if (pCachedKey)
        DIGI_FREE((void **)&pCachedKey);

    if (OK != status)
    {
        if (NULL!=pKeyObjectAttributes)
            freeAttrList(pKeyObjectAttributes);
    }

    return status;
}

/*------------------------------------------------------------------*/
MSTATUS TPM2_symGenerateKey(SMP_Context *pSmpContext, TOKEN_Context *pToken,
         TAP_KeyAttributes *pKeyAttributeList, TAP_ObjectHandle *pKeyHandle,
         TAP_ObjectCapabilityAttributes *pKeyObjectAttributes)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_RC_SUCCESS;
    SymCreateCipherKeyIn createCipherKeyIn = { 0 };
    SymCreateCipherKeyOut createCipherKeyOut = { 0 };
    SymCreateSigningKeyIn createSigningKeyIn = { 0 };
    SymCreateCipherKeyOut createSigningKeyOut = { 0 };
    AsymCreateKeyOut *pCreateKeyOut = NULL;
    TAP_KEY_ALGORITHM keyAlgorithm = TAP_KEY_ALGORITHM_AES;
    TAP_KEY_USAGE keyUsage = TAP_KEY_USAGE_DECRYPT;
    TAP_KEY_SIZE keySize = TAP_KEY_SIZE_SYM_DEFAULT;
    TAP_SYM_KEY_MODE symMode = TAP_SYM_KEY_MODE_CTR;
    TAP_KEY_CMK keyCmk = TAP_KEY_CMK_DISABLE;
    CACHED_KeyInfo *pCachedKey = NULL;
    ubyte4 numCreatedKeyAttributes = 0;
    TAP_Attribute *pCreatedKeyAttributes = NULL;
    TAP_Attribute *pAttribute = NULL;
    ubyte4 count = 0;
    TAP_HASH_ALG hashAlg = TAP_HASH_ALG_SHA256;
    ContextGetPrimaryObjectNameIn objNameIn = {0};
    ContextGetPrimaryObjectNameOut objNameOut = {0};
    TPM2B_AUTH keyAuth = {0};
    TAP_Blob *pBlob = NULL;

    if ((NULL == pSmpContext) || (NULL == pKeyHandle))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, pSmpContext = %p,"
                "pKeyHandle = %p\n",
                __FUNCTION__, __LINE__, pSmpContext,
                pKeyHandle);
        goto exit;
    }

    status = DIGI_CALLOC((void **)&pCachedKey, 1, sizeof(*pCachedKey));

    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for cached key object, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    if (pKeyAttributeList && pKeyAttributeList->listLen)
    {
        for (count = 0; count < pKeyAttributeList->listLen; count++)
        {
            pAttribute = &pKeyAttributeList->pAttributeList[count];

            switch (pAttribute->type)
            {
                case TAP_ATTR_KEY_ALGORITHM:
                    if (sizeof(TAP_KEY_ALGORITHM) == pAttribute->length)
                        keyAlgorithm = *(TAP_KEY_ALGORITHM *)pAttribute->pStructOfType;
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key algorithm length %d, status = %d\n",
                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    break;

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
                case TAP_ATTR_KEY_CMK:
                    if (sizeof(TAP_KEY_CMK) == pAttribute->length)
                        keyCmk = *((TAP_KEY_CMK *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key cmk length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    break;
                case TAP_ATTR_CREDENTIAL_SET:
                    TPM2_parseCredentialList(
                            (TAP_CredentialList *)pAttribute->pStructOfType,
                            &keyAuth);
                    break;
                case TAP_ATTR_KEY_SIZE:
                    if (sizeof(TAP_KEY_SIZE) == pAttribute->length)
                        keySize = *((TAP_KEY_SIZE *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key size structure length %d,"
                               " status = %d\n", __FUNCTION__, __LINE__,
                               pAttribute->length, status);
                        goto exit;
                    }
                    break;

                case TAP_ATTR_HASH_ALG:
                    if (sizeof(TAP_HASH_ALG) == pAttribute->length)
                        hashAlg = *((TAP_HASH_ALG *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key hash structure length %d,"
                               " status = %d\n", __FUNCTION__, __LINE__,
                               pAttribute->length, status);
                        goto exit;
                    }
                    break;

                case TAP_ATTR_SYM_KEY_MODE:
                    if (sizeof(TAP_SYM_KEY_MODE) == pAttribute->length)
                        symMode = *((TAP_SYM_KEY_MODE *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid sym key mode structure length %d,"
                               " status = %d\n", __FUNCTION__, __LINE__,
                               pAttribute->length, status);
                        goto exit;
                    }
                    break;
            }
        }
    }

    pCachedKey->keyAlgorithm = keyAlgorithm;

    if (TAP_KEY_USAGE_DECRYPT == keyUsage)
    {
        createCipherKeyIn.keyAuth = keyAuth;
        createCipherKeyIn.bEnableBackup = keyCmk;

        if (TAP_KEY_ALGORITHM_AES == keyAlgorithm)
            createCipherKeyIn.symAlg = TPM2_ALG_AES;
        else
        {
            status = ERR_TAP_UNSUPPORTED_ALGORITHM;
            DB_PRINT("%s.%d Unsupported key algorithm %d, "
                    "status 0x%02x\n",
                    __FUNCTION__,__LINE__, keyAlgorithm, status);
            goto exit;
        }

        switch (keySize)
        {
            case TAP_KEY_SIZE_128:
                createCipherKeyIn.keyBits = 128;
                break;

            case TAP_KEY_SIZE_192:
                createCipherKeyIn.keyBits = 192;
                break;

            case TAP_KEY_SIZE_256:
                createCipherKeyIn.keyBits = 256;
                break;

            default:
                status = ERR_TAP_UNSUPPORTED_ALGORITHM;
                DB_PRINT("%s.%d Unsupported Key size %d, "
                        "status 0x%02x\n",
                        __FUNCTION__,__LINE__, keySize, status);
                goto exit;
        }

        switch (symMode)
        {
            case TAP_SYM_KEY_MODE_CTR:
                createCipherKeyIn.symMode = TPM2_ALG_CTR;
                break;

            case TAP_SYM_KEY_MODE_OFB:
                createCipherKeyIn.symMode = TPM2_ALG_OFB;
                break;

            case TAP_SYM_KEY_MODE_CBC:
                createCipherKeyIn.symMode = TPM2_ALG_CBC;
                break;

            case TAP_SYM_KEY_MODE_CFB:
                createCipherKeyIn.symMode = TPM2_ALG_CFB;
                break;

            case TAP_SYM_KEY_MODE_ECB:
                createCipherKeyIn.symMode = TPM2_ALG_ECB;
                break;

            default:
                status = ERR_TAP_UNSUPPORTED_ALGORITHM;
                DB_PRINT("%s.%d Unsupported sym key mode %d, "
                        "status 0x%02x\n",
                        __FUNCTION__,__LINE__, symMode, status);
                goto exit;
        }

        objNameIn.persistentHandle = (pToken->id == SMP_TPM2_CRYPTO_TOKEN_ID) ?
            FAPI2_RH_SRK : FAPI2_RH_EK;

        rc = FAPI2_CONTEXT_getPrimaryObjectName(pSmpContext->pFapiContext,
                &objNameIn, &objNameOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d Failed to primary object name for id %d, "
                    "rc 0x%02x\n",
                    __FUNCTION__,__LINE__, (int)pToken->id, rc);
            goto exit;
        }

        createCipherKeyIn.pParentName = &objNameOut.objName;

        rc = FAPI2_SYM_createCipherKey(pSmpContext->pFapiContext,
                &createCipherKeyIn, &createCipherKeyOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d Failed to create child key under SRK, "
                    "rc 0x%02x\n",
                    __FUNCTION__,__LINE__, rc);
            goto exit;
        }
        pCreateKeyOut = (AsymCreateKeyOut *)&createCipherKeyOut;
    }
    else
    {
        createSigningKeyIn.keyAuth = keyAuth;
        createSigningKeyIn.bEnableBackup = keyCmk;

        if (TAP_KEY_ALGORITHM_HMAC == keyAlgorithm)
            createSigningKeyIn.sigScheme = TPM2_ALG_HMAC;
        else
        {
            status = ERR_TAP_UNSUPPORTED_ALGORITHM;
            DB_PRINT("%s.%d Unsupported key algorithm %d, "
                    "status 0x%02x\n",
                    __FUNCTION__,__LINE__, keyAlgorithm, status);
            goto exit;
        }

        switch (hashAlg)
        {
            case TAP_HASH_ALG_SHA256:
                createSigningKeyIn.hashAlg = TPM2_ALG_SHA256;
                break;

            case TAP_HASH_ALG_SHA384:
                createSigningKeyIn.hashAlg = TPM2_ALG_SHA384;
                break;

            case TAP_HASH_ALG_SHA512:
                createSigningKeyIn.hashAlg = TPM2_ALG_SHA512;
                break;
        }

        objNameIn.persistentHandle = (pToken->id == SMP_TPM2_CRYPTO_TOKEN_ID) ?
            FAPI2_RH_SRK : FAPI2_RH_EK;

        rc = FAPI2_CONTEXT_getPrimaryObjectName(pSmpContext->pFapiContext,
                &objNameIn, &objNameOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d Failed to primary object name for id %d, "
                    "rc 0x%02x\n",
                    __FUNCTION__,__LINE__, (int)pToken->id, rc);
            goto exit;
        }

        createSigningKeyIn.pParentName = &objNameOut.objName;

        rc = FAPI2_SYM_createSigningKey(pSmpContext->pFapiContext,
                &createSigningKeyIn, &createSigningKeyOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d Failed to create child key under SRK, "
                    "rc 0x%02x\n",
                    __FUNCTION__,__LINE__, rc);
            goto exit;
        }
        pCreateKeyOut = (AsymCreateKeyOut *)&createSigningKeyOut;
    }

    if (pKeyObjectAttributes)
    {
        /* Put together TAP Attribute list of the parameters used to create
           this key
         */
        if (TAP_KEY_USAGE_DECRYPT == keyUsage)
        {
            numCreatedKeyAttributes = 6;
        }
        else
        {
            numCreatedKeyAttributes = 5;
        }

        pKeyObjectAttributes->listLen = numCreatedKeyAttributes;

        status = DIGI_CALLOC((void **)&pKeyObjectAttributes->pAttributeList, 1,
                sizeof(TAP_Attribute) * numCreatedKeyAttributes);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for created key attribute list"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        count = 0;

        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

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

        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

        pCreatedKeyAttributes->type = TAP_ATTR_KEY_USAGE;
        pCreatedKeyAttributes->length = sizeof(keyUsage);
        status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                sizeof(keyUsage));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for key usage attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
        status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &keyUsage,
                sizeof(keyUsage));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy key usage attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        if (TAP_KEY_USAGE_DECRYPT == keyUsage)
        {
            pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

            pCreatedKeyAttributes->type = TAP_ATTR_SYM_KEY_MODE;
            pCreatedKeyAttributes->length = sizeof(symMode);
            status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                    sizeof(symMode));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to allocate memory for sym mode attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
            status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &symMode,
                    sizeof(symMode));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy symMode attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }

            pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

            pCreatedKeyAttributes->type = TAP_ATTR_KEY_SIZE;
            pCreatedKeyAttributes->length = sizeof(keySize);
            status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                    sizeof(keySize));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to allocate memory for key size attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
            status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &keySize,
                    sizeof(keySize));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy key size attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
        }
        else
        {
            pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

            pCreatedKeyAttributes->type = TAP_ATTR_HASH_ALG;
            pCreatedKeyAttributes->length = sizeof(hashAlg);
            status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                    sizeof(hashAlg));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to allocate memory for Hash Algorithm attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
            status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &hashAlg,
                    sizeof(hashAlg));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy Hash Algorithm attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
        }

        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

        pCreatedKeyAttributes->type = TAP_ATTR_SERIALIZED_OBJECT_BLOB;
        pCreatedKeyAttributes->length = sizeof(TAP_Blob);
        status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                sizeof(TAP_Blob));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for Object blob attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        pBlob = (TAP_Blob *) pCreatedKeyAttributes->pStructOfType;

        status = DIGI_MALLOC((void **)&pBlob->blob.pBuffer, pCreateKeyOut->key.size);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for Object blob buffer"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        pBlob->blob.bufferLen = pCreateKeyOut->key.size;
        status = DIGI_MEMCPY(pBlob->blob.pBuffer, pCreateKeyOut->key.buffer, pCreateKeyOut->key.size);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for Object blob buffer"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        pBlob->format = TAP_BLOB_FORMAT_MOCANA;
        pBlob->encoding = TAP_BLOB_ENCODING_BINARY;

        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

        /* Last entry */
        pCreatedKeyAttributes->type = TAP_ATTR_NONE;
        pCreatedKeyAttributes->length = 0;
        pCreatedKeyAttributes->pStructOfType = NULL;
    }

    status = DIGI_MEMCPY(pCachedKey->keyName.name, pCreateKeyOut->keyName.name,
            pCreateKeyOut->keyName.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy keyname, "
                "status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }
    pCachedKey->keyName.size = pCreateKeyOut->keyName.size;

    status = DIGI_MEMCPY(pCachedKey->key.buffer, pCreateKeyOut->key.buffer,
            pCreateKeyOut->key.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy serialized key, "
                "status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }
    pCachedKey->key.size = pCreateKeyOut->key.size;

    pCachedKey->objectType = TPM2_OBJECT_TYPE_KEY;
    *pKeyHandle = (TAP_ObjectHandle)((uintptr)pCachedKey);
    pCachedKey = NULL;
exit:
    if (pCachedKey)
        DIGI_FREE((void **)&pCachedKey);

    if (OK != status)
    {
        if (NULL != pKeyObjectAttributes)
            freeAttrList(pKeyObjectAttributes);
    }

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_CREATE_ASYMMETRIC_KEY__
MSTATUS SMP_API(TPM2, createAsymmetricKey,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectId objectId,
        TAP_KeyAttributes *pKeyAttributes,
        byteBoolean initFlag,
        TAP_ObjectId *pObjectIdOut,
        TAP_ObjectAttributes *pObjectAttributes,
        TAP_ObjectHandle *pKeyHandle
)
{
    MSTATUS status = OK;
    SMP_Context *pSmpContext = NULL;
    byteBoolean moduleLocked = FALSE;

    if ((0 == moduleHandle) || (NULL == pKeyHandle) ||
            (0 == tokenHandle) || (NULL == pKeyAttributes))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "pKeyHandle = %p, tokenHandle = %p, pKeyAttributes = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                pKeyHandle, tokenHandle, pKeyAttributes);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting on mutex for module=%p, status=%d\n",
                __FUNCTION__, __LINE__, moduleHandle, status);
        goto exit;
    }

    moduleLocked = TRUE;

    status = TPM2_asymGenerateKey((SMP_Context *)((uintptr)moduleHandle),
            (TOKEN_Context *)((uintptr)tokenHandle), objectId,
            pKeyAttributes, pKeyHandle, pObjectAttributes);
    if ((OK == status) && pObjectIdOut)
        *pObjectIdOut = objectId;

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_PRIVATE_KEY__
MSTATUS SMP_API(TPM2, getPrivateKeyBlob,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_Blob *pPrivateBlob
)
{
    MSTATUS status = OK;
    SMP_Context *pSmpContext;
    CACHED_KeyInfo *pKeyObject = NULL;
    ContextGetObjectPrivateInfoIn privateInfoIn = {0};
    ContextGetObjectPrivateInfoBlobOut privateBlobOut = {0};
    TAP_Buffer *pPrivatekeyData = NULL;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    ubyte state = 0x00;

    if ((0 == moduleHandle) || (0 == objectHandle) ||
            (NULL == pPrivateBlob))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p, "
                "objectHandle = %p, ppPrivateKey = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                objectHandle, pPrivateBlob);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pKeyObject = (CACHED_KeyInfo *)((uintptr)objectHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting on mutex for module=%p, status=%d\n",
                __FUNCTION__, __LINE__, moduleHandle, status);
        goto exit;
    }
    state |= APISTATE_MODULE_MUTEX_LOCKED;

    privateInfoIn.object = pKeyObject->keyName;
    rc = FAPI2_CONTEXT_getObjectPrivateInfoBlob(pSmpContext->pFapiContext, &privateInfoIn, &privateBlobOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to get private key info, "
                "rc 0x%02x\n",
                __FUNCTION__,__LINE__, rc);
        goto exit;
    }
    pPrivatekeyData = &pPrivateBlob->blob ;
    status = DIGI_MALLOC((void **)&(pPrivatekeyData->pBuffer), sizeof(TPM2B_PRIVATE));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory for TAP_Buffer object,"
                " status = %d\n", __FUNCTION__,__LINE__, status);
        goto exit;
    }
    state |= APISTATE_RESULT_BUFFER_CREATED;
    status = DIGI_MEMCPY(pPrivatekeyData->pBuffer,privateBlobOut.pBuffer,privateBlobOut.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy data to TAP_Buffer object,"
                " status = %d\n", __FUNCTION__,__LINE__, status);
        goto exit;
    }
    pPrivatekeyData->bufferLen = privateBlobOut.size ;
    pPrivateBlob->format = TAP_BLOB_FORMAT_MOCANA;
    pPrivateBlob->encoding = TAP_BLOB_ENCODING_BINARY;

exit:
    if (state & APISTATE_MODULE_MUTEX_LOCKED)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    if (OK != status)
    {
        if (state & APISTATE_RESULT_BUFFER_CREATED)
        {
            if ( NULL != pPrivatekeyData->pBuffer)
            {
                DIGI_FREE((void **)&(pPrivatekeyData->pBuffer));
                pPrivatekeyData->pBuffer = NULL;
            }
        }
    }
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_PUBLIC_KEY__

#define APISTATE_GETPUBKEY_RSA_CREATED      0x10
#define APISTATE_GETPUBKEY_ECC_CREATED      0x20

MSTATUS SMP_API(TPM2, getPublicKey,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_PublicKey **ppPublicKey
)
{
    MSTATUS status = OK;
    SMP_Context *pSmpContext;
    CACHED_KeyInfo *pKeyObject = NULL;
    AsymGetPublicKeyIn pubKeyIn = {0};
    AsymGetPublicKeyOut pubKeyOut = {0};
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    ubyte4 exponent = 0x10001;
    ubyte state = 0x00;

    if ((0 == moduleHandle) || (0 == objectHandle) ||
            (NULL == ppPublicKey))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p, "
                "objectHandle = %p, ppPublicKey = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                objectHandle, ppPublicKey);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pKeyObject = (CACHED_KeyInfo *)((uintptr)objectHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting on mutex for module=%p, status=%d\n",
                __FUNCTION__, __LINE__, moduleHandle, status);
        goto exit;
    }
    state |= APISTATE_MODULE_MUTEX_LOCKED;

    pubKeyIn.keyName = pKeyObject->keyName;
    /* Get Public key */
    rc = FAPI2_ASYM_getPublicKey(pSmpContext->pFapiContext,
            &pubKeyIn, &pubKeyOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to get public key, "
                "rc 0x%02x\n",
                __FUNCTION__,__LINE__, rc);
        goto exit;
    }

    status = DIGI_CALLOC((void **)ppPublicKey, 1, sizeof(TAP_PublicKey));

    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory for TAP_PublicKey object,"
                " status = %d\n", __FUNCTION__,__LINE__, status);
        goto exit;
    }
    state |= APISTATE_RESULT_BUFFER_CREATED;

    switch (pubKeyOut.keyAlg)
    {
        case TPM2_ALG_RSA:
            status = DIGI_MALLOC((void **)&((*ppPublicKey)->publicKey.rsaKey.pModulus),
                    pubKeyOut.publicKey.rsaPublic.size);

            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to allocate memory for"
                        " RSA modulus buffer, status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
            state |= APISTATE_GETPUBKEY_RSA_CREATED;

            (*ppPublicKey)->keyAlgorithm = TAP_KEY_ALGORITHM_RSA;
            status = DIGI_MEMCPY((*ppPublicKey)->publicKey.rsaKey.pModulus,
                    pubKeyOut.publicKey.rsaPublic.buffer,
                    pubKeyOut.publicKey.rsaPublic.size);

            if (OK != status)
            {
                DB_PRINT("%s.%d Error copying RSA modulus buffer,"
                        " status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }

            (*ppPublicKey)->publicKey.rsaKey.modulusLen =
                pubKeyOut.publicKey.rsaPublic.size;

            /* Allocate room for exponent */
            status = DIGI_MALLOC((void **)&((*ppPublicKey)->publicKey.rsaKey.pExponent),
                    sizeof(exponent));
            if (OK != status)
            {
                DB_PRINT("%s.%d Unable to allocate memory for"
                        " public key exponent, status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }

            /* copy in Little Endian */
            (*ppPublicKey)->publicKey.rsaKey.pExponent[0] = (ubyte) (exponent & 0xff);
            (*ppPublicKey)->publicKey.rsaKey.pExponent[1] = (ubyte) ((exponent >> 8) & 0xff);
            (*ppPublicKey)->publicKey.rsaKey.pExponent[2] = (ubyte) ((exponent >> 16) & 0xff);
            (*ppPublicKey)->publicKey.rsaKey.pExponent[3] = (ubyte) ((exponent >> 24) & 0xff);
            (*ppPublicKey)->publicKey.rsaKey.exponentLen = sizeof(exponent);
            break;

        case TPM2_ALG_ECC:
            status = DIGI_MALLOC((void **)&((*ppPublicKey)->publicKey.eccKey.pPubX),
                    pubKeyOut.publicKey.eccPublic.x.size);
            if (OK != status)
            {
                DB_PRINT("%s.%d Unable to allocate memory for"
                        " ecc public key x value, status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }
            state |= APISTATE_GETPUBKEY_ECC_CREATED;

            (*ppPublicKey)->keyAlgorithm = TAP_KEY_ALGORITHM_ECC;
            (*ppPublicKey)->publicKey.eccKey.pubXLen =
                pubKeyOut.publicKey.eccPublic.x.size;
            status = DIGI_MEMCPY((*ppPublicKey)->publicKey.eccKey.pPubX,
                    pubKeyOut.publicKey.eccPublic.x.buffer,
                    (*ppPublicKey)->publicKey.eccKey.pubXLen);

            if (OK != status)
            {
                DB_PRINT("%s.%d Unable to copy value to "
                        " ecc public key x value, status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }

            status = DIGI_MALLOC((void **)&((*ppPublicKey)->publicKey.eccKey.pPubY),
                    pubKeyOut.publicKey.eccPublic.y.size);
            if (OK != status)
            {
                DB_PRINT("%s.%d Unable to allocate memory for"
                        " ecc public key y value, status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }

            (*ppPublicKey)->publicKey.eccKey.pubYLen =
                pubKeyOut.publicKey.eccPublic.y.size;
            status = DIGI_MEMCPY((*ppPublicKey)->publicKey.eccKey.pPubY,
                    pubKeyOut.publicKey.eccPublic.y.buffer,
                    (*ppPublicKey)->publicKey.eccKey.pubYLen);

            if (OK != status)
            {
                DB_PRINT("%s.%d Unable to copy value to "
                        " ecc public key y value, status = %d\n",
                        __FUNCTION__, __LINE__, status);
                goto exit;
            }
            break;

        default:
            break;
    }

exit:
    if (state & APISTATE_MODULE_MUTEX_LOCKED)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    if (OK != status)
    {
        if (state & APISTATE_GETPUBKEY_RSA_CREATED)
        {
            if (NULL != (*ppPublicKey)->publicKey.rsaKey.pModulus)
            {
                DIGI_FREE((void **)&((*ppPublicKey)->publicKey.rsaKey.pModulus));
                (*ppPublicKey)->publicKey.rsaKey.modulusLen = 0;
            }
            if (NULL != (*ppPublicKey)->publicKey.rsaKey.pExponent)
            {
                DIGI_FREE((void **)&((*ppPublicKey)->publicKey.rsaKey.pExponent));
                (*ppPublicKey)->publicKey.rsaKey.exponentLen = 0;
            }
        }
        if (state & APISTATE_GETPUBKEY_ECC_CREATED)
        {
            if (NULL != (*ppPublicKey)->publicKey.eccKey.pPubX)
            {
                DIGI_FREE((void **)&((*ppPublicKey)->publicKey.eccKey.pPubX));
                (*ppPublicKey)->publicKey.eccKey.pubXLen = 0;
            }
            if (NULL != (*ppPublicKey)->publicKey.eccKey.pPubY)
            {
                DIGI_FREE((void **)&((*ppPublicKey)->publicKey.eccKey.pPubY));
                (*ppPublicKey)->publicKey.eccKey.pubYLen = 0;
            }
        }
        if (state & APISTATE_RESULT_BUFFER_CREATED)
        {
            if ( NULL != *ppPublicKey)
            {
                DIGI_FREE((void **)ppPublicKey);
                *ppPublicKey = NULL;
            }
        }
    }

    return status;
}


MSTATUS SMP_API(TPM2, getPublicKeyBlob,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_Blob *pPublicBlob
)
{
    MSTATUS status = OK;
    SMP_Context *pSmpContext;
    CACHED_KeyInfo *pKeyObject = NULL;
    ContextGetObjectPublicInfoIn publicInfoIn = {0};
    ContextGetObjectPublicInfoBlobOut publicBlobOut = {0};
    TAP_Buffer *pPublickeyData = NULL;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    ubyte state = 0x00;

    if ((0 == moduleHandle) || (0 == objectHandle) ||
            (NULL == pPublicBlob))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p, "
                "objectHandle = %p, ppPublicKey = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                objectHandle, pPublicBlob);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pKeyObject = (CACHED_KeyInfo *)((uintptr)objectHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting on mutex for module=%p, status=%d\n",
                __FUNCTION__, __LINE__, moduleHandle, status);
        goto exit;
    }
    state |= APISTATE_MODULE_MUTEX_LOCKED;

    publicInfoIn.object = pKeyObject->keyName;
    rc = FAPI2_CONTEXT_getObjectPublicInfoBlob(pSmpContext->pFapiContext, &publicInfoIn, &publicBlobOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to get public key info, "
                "rc 0x%02x\n",
                __FUNCTION__,__LINE__, rc);
        goto exit;
    }
    pPublickeyData = &pPublicBlob->blob ;
    status = DIGI_MALLOC((void **)&(pPublickeyData->pBuffer), sizeof(TPM2B_PUBLIC));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory for TAP_Buffer object,"
                " status = %d\n", __FUNCTION__,__LINE__, status);
        goto exit;
    }
    state |= APISTATE_RESULT_BUFFER_CREATED;
    status = DIGI_MEMCPY(pPublickeyData->pBuffer,publicBlobOut.publicInfo.buffer,publicBlobOut.publicInfo.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy data to TAP_Buffer object,"
                " status = %d\n", __FUNCTION__,__LINE__, status);
        goto exit;
    }
    pPublickeyData->bufferLen = publicBlobOut.publicInfo.size ;
    pPublicBlob->format = TAP_BLOB_FORMAT_MOCANA;
    pPublicBlob->encoding = TAP_BLOB_ENCODING_BINARY;

exit:
    if (state & APISTATE_MODULE_MUTEX_LOCKED)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    if (OK != status)
    {
        if (state & APISTATE_RESULT_BUFFER_CREATED)
        {
            if ( NULL != pPublickeyData->pBuffer)
            {
                DIGI_FREE((void **)&(pPublickeyData->pBuffer));
                pPublickeyData->pBuffer = NULL;
            }
        }
    }
    return status;
}



#endif

#ifdef __SMP_ENABLE_SMP_CC_FREE_PUBLIC_KEY__
MSTATUS SMP_API(TPM2, freePublicKey,
        TAP_PublicKey **ppPublicKey
)
{
    return SMP_UTILS_freePublicKey(ppPublicKey);
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_CREATE_SYMMETRIC_KEY__
MSTATUS SMP_API(TPM2, createSymmetricKey,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectId objectId,
        TAP_KeyAttributes *pAttributeKey,
        byteBoolean initFlag,
        TAP_ObjectId *pObjectIdOut,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_ObjectHandle *pKeyHandle
)
{
    MSTATUS status = OK;
    SMP_Context *pSmpContext = NULL;
    byteBoolean moduleLocked = FALSE;

    if ((0 == moduleHandle) || (0 == pKeyHandle) ||
            (0 == tokenHandle))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "pKeyHandle = %p, tokenHandle = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                pKeyHandle, tokenHandle);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting on mutex for module=%p, status=%d\n",
                __FUNCTION__, __LINE__, moduleHandle, status);
        goto exit;
    }

    moduleLocked = TRUE;

    status = TPM2_symGenerateKey((SMP_Context *)((uintptr)moduleHandle),
            (TOKEN_Context *)((uintptr)tokenHandle),
            pAttributeKey, pKeyHandle, pObjectAttributes);
exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_IMPORT_EXTERNAL_KEY__
MSTATUS TPM2_symImportExternalKey(SMP_Context *pSmpContext, TOKEN_Context *pToken,
         TAP_KeyAttributes *pKeyAttributeList, TAP_ObjectHandle *pKeyHandle,
         TAP_ObjectCapabilityAttributes *pKeyObjectAttributes)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_RC_SUCCESS;
    FapisSymCreateExternalKeyIn keyIn = {0};
    SymCreateKeyOut keyOut = {0};
    /* defaults for when method gets extended to cipher keys */
    TAP_KEY_ALGORITHM keyAlgorithm = TAP_KEY_ALGORITHM_AES;
    TAP_KEY_USAGE keyUsage = TAP_KEY_USAGE_DECRYPT;
    TAP_KEY_SIZE keySize = TAP_KEY_SIZE_SYM_DEFAULT;
    TAP_SYM_KEY_MODE symMode = TAP_SYM_KEY_MODE_CTR;
    TAP_HASH_ALG hashAlg = TAP_HASH_ALG_SHA256;
    CACHED_KeyInfo *pCachedKey = NULL;
    ubyte4 numCreatedKeyAttributes = 0;
    TAP_Attribute *pCreatedKeyAttributes = NULL;
    TAP_Attribute *pAttribute = NULL;
    ubyte4 count = 0;
    TPM2B_AUTH keyAuth = {0};
    TAP_Buffer keyData = {0};

    if ((NULL == pSmpContext) || (NULL == pKeyHandle))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, pSmpContext = %p,"
                "pKeyHandle = %p\n",
                __FUNCTION__, __LINE__, pSmpContext,
                pKeyHandle);
        goto exit;
    }

    status = DIGI_CALLOC((void **)&pCachedKey, 1, sizeof(*pCachedKey));

    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for cached key object, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    if (pKeyAttributeList && pKeyAttributeList->listLen)
    {
        for (count = 0; count < pKeyAttributeList->listLen; count++)
        {
            pAttribute = &pKeyAttributeList->pAttributeList[count];

            switch (pAttribute->type)
            {
                case TAP_ATTR_KEY_ALGORITHM:
                    if (sizeof(TAP_KEY_ALGORITHM) == pAttribute->length)
                        keyAlgorithm = *(TAP_KEY_ALGORITHM *)pAttribute->pStructOfType;
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key algorithm length %d, status = %d\n",
                            __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    break;

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

                case TAP_ATTR_CREDENTIAL_SET:
                    TPM2_parseCredentialList(
                            (TAP_CredentialList *)pAttribute->pStructOfType,
                            &keyAuth);
                    break;
                case TAP_ATTR_KEY_SIZE:
                    if (sizeof(TAP_KEY_SIZE) == pAttribute->length)
                        keySize = *((TAP_KEY_SIZE *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key size structure length %d,"
                               " status = %d\n", __FUNCTION__, __LINE__,
                               pAttribute->length, status);
                        goto exit;
                    }
                    break;

                case TAP_ATTR_HASH_ALG:
                    if (sizeof(TAP_HASH_ALG) == pAttribute->length)
                        hashAlg = *((TAP_HASH_ALG *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key hash structure length %d,"
                               " status = %d\n", __FUNCTION__, __LINE__,
                               pAttribute->length, status);
                        goto exit;
                    }
                    break;

                case TAP_ATTR_SYM_KEY_MODE:
                    if (sizeof(TAP_SYM_KEY_MODE) == pAttribute->length)
                        symMode = *((TAP_SYM_KEY_MODE *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid sym key mode structure length %d,"
                               " status = %d\n", __FUNCTION__, __LINE__,
                               pAttribute->length, status);
                        goto exit;
                    }
                    break;

                case TAP_ATTR_OBJECT_VALUE:

                    if ((sizeof(TAP_Buffer) != pAttribute->length) ||
                            (NULL == pAttribute->pStructOfType))
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid TAP Buffer. length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    keyData = *((TAP_Buffer *)(pAttribute->pStructOfType));
                    break;
            }
        }
    }

    pCachedKey->keyAlgorithm = keyAlgorithm;

    if (TAP_KEY_USAGE_DECRYPT == keyUsage || TAP_KEY_ALGORITHM_HMAC != keyAlgorithm)
    {
        /* For now we just support hmac signing keys */
        status = ERR_NOT_IMPLEMENTED;
        DB_PRINT("%s.%d Unsupported key algorithm %d, "
                "status 0x%02x\n",
                __FUNCTION__,__LINE__, keyAlgorithm, status);
        goto exit;
    }

    keyIn.pKeyAuth = &keyAuth;
    keyIn.keyBits = keyData.bufferLen * 8;
    keyIn.pSymKeyBuffer = keyData.pBuffer;
    keyIn.symKeyBufferLen = keyData.bufferLen;
    keyIn.symAlg = TPM2_ALG_HMAC; 

    switch (hashAlg)
    {
        case TAP_HASH_ALG_SHA256:
            keyIn.hashAlg = TPM2_ALG_SHA256;
            break;

        case TAP_HASH_ALG_SHA384:
            keyIn.hashAlg = TPM2_ALG_SHA384;
            break;

        case TAP_HASH_ALG_SHA512:
            keyIn.hashAlg = TPM2_ALG_SHA512;
            break;
    }

    rc = FAPI2_SYM_createExternalSymKey(pSmpContext->pFapiContext, &keyIn, &keyOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to create external key, "
                "rc 0x%02x\n",
                __FUNCTION__,__LINE__, rc);
        goto exit;
    }

    if (pKeyObjectAttributes)
    {
        /* 
           Put together TAP Attribute list of the parameters used to create
           this key. uncomment below if decrypt key usage is later supported 
        */
        numCreatedKeyAttributes = 4;
        pKeyObjectAttributes->listLen = numCreatedKeyAttributes;

        status = DIGI_CALLOC((void **)&pKeyObjectAttributes->pAttributeList, 1,
                sizeof(TAP_Attribute) * numCreatedKeyAttributes);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for created key attribute list"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        count = 0;

        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

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

        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

        pCreatedKeyAttributes->type = TAP_ATTR_KEY_USAGE;
        pCreatedKeyAttributes->length = sizeof(keyUsage);
        status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                sizeof(keyUsage));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to allocate memory for key usage attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }
        status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &keyUsage,
                sizeof(keyUsage));
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed to copy key usage attribute"
                    "status = %d\n",
                    __FUNCTION__,__LINE__, status);
            goto exit;
        }

        if (TAP_KEY_USAGE_DECRYPT == keyUsage)
        {
            pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

            pCreatedKeyAttributes->type = TAP_ATTR_SYM_KEY_MODE;
            pCreatedKeyAttributes->length = sizeof(symMode);
            status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                    sizeof(symMode));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to allocate memory for sym mode attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
            status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &symMode,
                    sizeof(symMode));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy symMode attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }

            pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

            pCreatedKeyAttributes->type = TAP_ATTR_KEY_SIZE;
            pCreatedKeyAttributes->length = sizeof(keySize);
            status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                    sizeof(keySize));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to allocate memory for key size attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
            status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &keySize,
                    sizeof(keySize));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy key size attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
        }
        else
        {
            pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

            pCreatedKeyAttributes->type = TAP_ATTR_HASH_ALG;
            pCreatedKeyAttributes->length = sizeof(hashAlg);
            status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                    sizeof(hashAlg));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to allocate memory for Hash Algorithm attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }
            status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &hashAlg,
                    sizeof(hashAlg));
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy Hash Algorithm attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                goto exit;
            }

        }

        /* Last entry */
        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];
        pCreatedKeyAttributes->type = TAP_ATTR_NONE;
        pCreatedKeyAttributes->length = 0;
        pCreatedKeyAttributes->pStructOfType = NULL;
    }

    status = DIGI_MEMCPY(pCachedKey->keyName.name, keyOut.keyName.name, keyOut.keyName.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy keyname, "
                "status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }
    pCachedKey->keyName.size = keyOut.keyName.size;

    status = DIGI_MEMCPY(pCachedKey->key.buffer, keyOut.key.buffer, keyOut.key.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy serialized key, "
                "status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }
    pCachedKey->key.size = keyOut.key.size;

    pCachedKey->objectType = TPM2_OBJECT_TYPE_KEY;
    *pKeyHandle = (TAP_ObjectHandle)((uintptr)pCachedKey);
    pCachedKey = NULL;
exit:
    if (pCachedKey)
        DIGI_FREE((void **)&pCachedKey);

    if (OK != status)
    {
        if (NULL != pKeyObjectAttributes)
            freeAttrList(pKeyObjectAttributes);
    }

    return status;
}

/*------------------------------------------------------------------*/

MSTATUS SMP_API(TPM2, importExternalKey,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectId objectId,
        TAP_KeyAttributes *pAttributeKey,
        TAP_ObjectId *pObjectIdOut,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_ObjectHandle *pKeyHandle
)
{
    MSTATUS status = OK;
    SMP_Context *pSmpContext = NULL;
    byteBoolean moduleLocked = FALSE;

    if ((0 == moduleHandle) || (0 == pKeyHandle) ||
            (0 == tokenHandle))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "pKeyHandle = %p, tokenHandle = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                pKeyHandle, tokenHandle);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting on mutex for module=%p, status=%d\n",
                __FUNCTION__, __LINE__, moduleHandle, status);
        goto exit;
    }

    moduleLocked = TRUE;

    status = TPM2_symImportExternalKey((SMP_Context *)((uintptr)moduleHandle),
            (TOKEN_Context *)((uintptr)tokenHandle),
            pAttributeKey, pKeyHandle, pObjectAttributes);

    if ((OK == status) && pObjectIdOut)
        *pObjectIdOut = objectId;
exit:
    
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    return status;
}
#endif /* __SMP_ENABLE_SMP_CC_IMPORT_EXTERNAL_KEY__ */

#ifdef __SMP_ENABLE_SMP_CC_EXPORT_OBJECT__
MSTATUS SMP_API(TPM2, exportObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_Blob *pExportedObject
)
{
    MSTATUS status = OK;
    SMP_Context *pSmpContext = NULL;
    CACHED_KeyInfo *pKeyObject = NULL;

    if ((0 == moduleHandle) || (0 == objectHandle) ||
            (NULL == pExportedObject))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "ppObjectHandle = %p, pSerializedObject = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                objectHandle, pExportedObject);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pKeyObject = (CACHED_KeyInfo *)((uintptr)objectHandle);

    status = DIGI_MALLOC((void **)&pExportedObject->blob.pBuffer,
            pKeyObject->key.size);

    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory key object, status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    status = DIGI_MEMCPY(pExportedObject->blob.pBuffer,
            pKeyObject->key.buffer, pKeyObject->key.size);

    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy key object, status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    pExportedObject->format = TAP_BLOB_FORMAT_MOCANA;
    pExportedObject->encoding = TAP_BLOB_ENCODING_BINARY;
    pExportedObject->blob.bufferLen = pKeyObject->key.size;

exit:
    if (OK != status)
    {
        if(pExportedObject)
        {
            if (NULL != pExportedObject->blob.pBuffer)
            {
                if (OK != DIGI_FREE((void**)&(pExportedObject->blob.pBuffer)))
                {
                    DB_PRINT("%s.%d Failed releasing memory from object buffer=%p,"
                            " in case of failure\n",
                            __FUNCTION__, __LINE__, pExportedObject->blob.pBuffer);
                }
            }
            pExportedObject->blob.pBuffer = NULL;
            pExportedObject->blob.bufferLen = 0;
        }
    }

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SERIALIZE_OBJECT__
MSTATUS SMP_API(TPM2, serializeObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectId objectId,
        TAP_Blob *pSerializedObject
)
{
    return ERR_NOT_IMPLEMENTED;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_CREATE_OBJECT__

static TAP_ObjectId TPM2_getAvailableNVIndex(SMP_Context *pSmpContext,
        TOKEN_Context *pToken)
{
    TAP_ObjectId nvId = 0;
    TAP_EntityList objectIdList = {0};
    ubyte4 i = 0;

    /* Get Provisioned Ids */
    if (OK != TPM2_getProvisionedIds(pSmpContext, pToken, &objectIdList))
        goto exit;

    for (nvId = TPM2_NV_INDEX_FIRST; nvId < TPM2_NV_INDEX_LAST; nvId++)
    {
        for (i = 0; i < objectIdList.entityIdList.numEntities; i++)
        {
            if (nvId == objectIdList.entityIdList.pEntityIdList[i])
            {
                /* Found */
                break;
            }
        }

        /* If this nvID is not found, return it */
        if (i >= objectIdList.entityIdList.numEntities)
            break;
    }

    if (nvId >= TPM2_NV_INDEX_LAST)
        nvId = 0;

    /* Free object list */
    DIGI_FREE((void **)&objectIdList.entityIdList.pEntityIdList);

exit:
    return nvId;
}

MSTATUS SMP_API(TPM2, createObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectId objectIdIn,
        TAP_ObjectCapabilityAttributes *pObjectAttributes,
        TAP_ObjectCapabilityAttributes *pObjectAttributesOut,
        TAP_ObjectId *pObjectIdOut,
        TAP_ObjectHandle *pHandle
)
{
    MSTATUS status = OK;
    TAP_ObjectId nvId = 0;
    ubyte4 nvSize = 0;
    TAP_Attribute *pAttribute = NULL;
    TPM2B_AUTH nvAuth = { 0 };
    SMP_Context *pSmpContext = NULL;
    TOKEN_Context *pToken = NULL;
    byteBoolean moduleLocked = FALSE;
    TAP_AUTH_CONTEXT_PROPERTY authContext = TAP_AUTH_CONTEXT_STORAGE;

    if ((0 == moduleHandle) || (NULL == pObjectAttributes) ||
            (NULL == pHandle) || (0 == tokenHandle))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "pObjectAttributes = %p, pHandle = %p, "
                "tokenHandle = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                pObjectAttributes, pHandle, tokenHandle);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pToken = (TOKEN_Context *)((uintptr)tokenHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Wait on module mutex failed, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }
    moduleLocked = TRUE;

    if (TPM2_getAttribute(pObjectAttributes, TAP_ATTR_STORAGE_INDEX,
                &pAttribute))
    {
        if ((sizeof(ubyte4) != pAttribute->length) ||
                (NULL == pAttribute->pStructOfType))
        {
            status = ERR_INVALID_ARG;
            DB_PRINT("%s.%d Invalid storage structure index %d, status = %d\n",
                __FUNCTION__, __LINE__, pAttribute->length, status);
            goto exit;
        }

        /* If object id is not specified as input, get it from parameters */
        if (!objectIdIn)
            objectIdIn =  *(ubyte4 *)(pAttribute->pStructOfType);
    }

    if (objectIdIn)
        nvId = (ubyte4)objectIdIn;
    else
    {
        /* Get the first available ID */
        if (!(nvId = TPM2_getAvailableNVIndex(pSmpContext, pToken)))
        {
            status = ERR_TAP_CMD_FAILED;
            DB_PRINT("%s.%d NV Index full, status = %d\n",
                __FUNCTION__, __LINE__, status);
            goto exit;
        }
    }

    if (TPM2_getAttribute(pObjectAttributes, TAP_ATTR_STORAGE_SIZE,
                &pAttribute))
    {
        if ((sizeof(ubyte4) != pAttribute->length) ||
                (NULL == pAttribute->pStructOfType))
        {
            status = ERR_INVALID_ARG;
            DB_PRINT("%s.%d Invalid storage structure length %d, status = %d\n",
                __FUNCTION__, __LINE__, pAttribute->length, status);
            goto exit;
        }
        nvSize = *(ubyte4 *)(pAttribute->pStructOfType);
    }
    else
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Missing attribute - TAP_ATTR_STORAGE_SIZE\n",
                __FUNCTION__, __LINE__);
        goto exit;
    }

    if (TPM2_getAttribute(pObjectAttributes, TAP_ATTR_CREDENTIAL_SET,
                &pAttribute))
    {
        TPM2_parseCredentialList(
                (TAP_CredentialList *)pAttribute->pStructOfType,
                &nvAuth);
    }

    if (!nvSize)
    {
        DB_PRINT("%s.%d Invalid Object Size %d\n",
                __FUNCTION__, __LINE__, nvSize);
        status = ERR_INVALID_ARG;
        goto exit;
    }

    authContext = TAP_AUTH_CONTEXT_STORAGE;
    if (TPM2_getAttribute(pObjectAttributes, TAP_ATTR_AUTH_CONTEXT,
                &pAttribute))
    {
        if ((sizeof(TAP_AUTH_CONTEXT_PROPERTY) != pAttribute->length) ||
                (NULL == pAttribute->pStructOfType))
        {
            status = ERR_INVALID_ARG;
            DB_PRINT("%s.%d Invalid storage storage heirarchy length=%d, status = %d\n",
                __FUNCTION__, __LINE__, pAttribute->length, status);
            goto exit;
        }

        authContext =  *(TAP_AUTH_CONTEXT_PROPERTY *)(pAttribute->pStructOfType);
    }
    /* Create NV Object */
    status = TPM2_createNVObject(pSmpContext, pToken, nvId, nvSize, &nvAuth,
                    authContext, pHandle);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to create NVObject, status=%d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    if (pObjectIdOut)
        *pObjectIdOut = nvId;

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    return status;
}
#endif


#ifdef __SMP_ENABLE_SMP_CC_DELETE_OBJECT__
MSTATUS SMP_API(TPM2, deleteObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_AUTH_CONTEXT_PROPERTY authContext
)
{
    MSTATUS status = OK;
    SMP_Context *pSmpContext = NULL;
    TPM2_OBJECT *pTpm2Object = NULL;

    if ((0 == moduleHandle) || (0 == objectHandle))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "objectHandle = %p, tokenHandle = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                objectHandle, tokenHandle);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pTpm2Object = (TPM2_OBJECT *)((uintptr)objectHandle);

    if (TAP_AUTH_CONTEXT_NONE != authContext)
    {
        status = TPM2_deleteObject_usingAuthContext(pSmpContext, tokenHandle,
                                 pTpm2Object, TRUE, authContext);
        if (OK != status)
        {
            DB_PRINT("%s.%d TPM2_deleteObject failed, status = %d\n",
                    __FUNCTION__, __LINE__, status);
        }
    }
    else
    {
        status = TPM2_deleteObject(pSmpContext, tokenHandle, pTpm2Object, TRUE);
        if (OK != status)
        {
            DB_PRINT("%s.%d TPM2_deleteObject failed, status = %d\n",
                    __FUNCTION__, __LINE__, status);
        }
    }

exit:
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_ROOT_OF_TRUST_CERTIFICATE__
MSTATUS SMP_API(TPM2, getRootOfTrustCertificate,
        TAP_ModuleHandle moduleHandle,
        TAP_ObjectId objectId,
        TAP_ROOT_OF_TRUST_TYPE type,
        TAP_Blob *pCertificate
)
{
    MSTATUS status = OK;
    SMP_Context *pSmpContext = NULL;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    byteBoolean moduleLocked = FALSE;
    ContextGetPrimaryObjectNameIn objNameIn = {0};
    ContextGetPrimaryObjectNameOut objNameOut = {0};
    ContextGetObjectPublicInfoIn publicInfoIn = {0};
    ContextGetObjectPublicInfoOut publicInfoOut = {0};
    MgmtCapabilityIn capIn = {0};
    MgmtCapabilityOut capOut = {0};
    ubyte4 handleCount = 0;
    NVReadOpIn nvIn = {0};
    NVReadOpOut nvOut = {0};
    TAP_EntityId nvId = 0;

    if ((0 == moduleHandle) || (0 == objectId) ||
            (NULL == pCertificate))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input, moduleHandle = %p, objectId = %p,"
                "pCertificate = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                objectId, pCertificate);
        goto exit;
    }

    if (objectId != FAPI2_RH_EK)
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Invalid input, objectId = 0x%08x, expected 0x%08x\n",
                __FUNCTION__, __LINE__, (int)objectId, (int)FAPI2_RH_EK);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed waiting on module mutex for module - %p,"
               " status- %d\n", __FUNCTION__, __LINE__, moduleHandle, status);
        goto exit;
    }
    moduleLocked = TRUE;

    /* Get the key algorithm of EK */
    objNameIn.persistentHandle = objectId;
    rc = FAPI2_CONTEXT_getPrimaryObjectName(pSmpContext->pFapiContext,
            &objNameIn, &objNameOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to get primary object name for EK, "
                "rc 0x%02x\n",
                __FUNCTION__,__LINE__, rc);
        goto exit;
    }

    publicInfoIn.object = objNameOut.objName;
    rc = FAPI2_CONTEXT_getObjectPublicInfo(pSmpContext->pFapiContext,
            & publicInfoIn, &publicInfoOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to get key public info, rc = 0x%02x\n",
                __FUNCTION__, __LINE__, rc);
        goto exit;
    }

    switch (publicInfoOut.publicInfo.type)
    {
        case TPM2_ALG_RSA:
            nvId = TPM2_RSA_EK_CERTIFICATE_NVRAM_ID;
            break;

        case TPM2_ALG_ECC:
            nvId = TPM2_ECC_EK_CERTIFICATE_NVRAM_ID;
            break;

        default:
            status = ERR_INVALID_ARG; /* Todo: fix error code */
            DB_PRINT("%s.%d unexpected EK key algorithm %d\n",
                    __FUNCTION__, __LINE__, (int)publicInfoOut.publicInfo.type);
            goto exit;
    }

    /* Ensure that the NVRAM ID corresponding to the key algorithm is
       present */
    capIn.capability = TPM2_CAP_HANDLES;
    capIn.property = 0x01000000;
    capIn.propertyCount = 64;
    rc = FAPI2_MGMT_getCapability(pSmpContext->pFapiContext,
            &capIn, &capOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d FAPI2_MGMT_getCapability error, rc = 0x%02x\n",
                __FUNCTION__, __LINE__, rc);
        goto exit;
    }

    /* Map capability data to entityIdList */
    if (capOut.moreData)
    {
        /* Error out for now */
        DB_PRINT("%s.%d FAPI2_MGMT_getCapability nvHandles exceed limit of %d\n",
                 __FUNCTION__, __LINE__, capIn.propertyCount);
        status = ERR_TAP_CMD_FAILED;
        goto exit;
    }

    for (handleCount = 0; handleCount < capOut.capabilityData.data.handles.count;
            handleCount++)
    {
        if (nvId ==
                (TAP_EntityId)(capOut.capabilityData.data.handles.handle[handleCount]))
        {
            /* found, read the certificate */
            nvIn.nvIndex = (TPMI_RH_NV_INDEX)nvId;
            rc = FAPI2_NV_readOp(pSmpContext->pFapiContext,
                    &nvIn, &nvOut);
            if (TSS2_RC_SUCCESS != rc)
            {
                status = SMP_TPM2_UTILS_getMocanaError(rc);
                DB_PRINT("%s.%d Failed to read NV Index, "
                        "rc 0x%02x\n",
                        __FUNCTION__,__LINE__, rc);
                goto exit;
            }

            /* Allocate space for certificate */
            status = DIGI_MALLOC((void **)&pCertificate->blob.pBuffer,
                    nvOut.readData.size);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to allocate certificate blob,"
                       " status = %d\n", __FUNCTION__,__LINE__, status);
                goto exit;
            }

            status = DIGI_MEMCPY(pCertificate->blob.pBuffer,
                    nvOut.readData.buffer, nvOut.readData.size);
            if (OK != status)
            {
                DB_PRINT("%s.%d Failed to copy certificate blob,"
                       " status = %d\n", __FUNCTION__,__LINE__, status);
                goto exit;
            }

            pCertificate->blob.bufferLen = nvOut.readData.size;
            pCertificate->format = TAP_BLOB_FORMAT_DER; /* TODO check if PEM */
            pCertificate->encoding = TAP_BLOB_ENCODING_BINARY;

            goto exit;
        }
    }

    if (handleCount == capOut.capabilityData.data.handles.count)
        status = ERR_TAP_CMD_FAILED;

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    if (OK != status)
    {
        if(pCertificate)
        {
            if (NULL !=  pCertificate->blob.pBuffer)
            {
                if (OK != DIGI_FREE((void **)&pCertificate->blob.pBuffer))
                {
                    DB_PRINT("%s.%d Failed to release memory allocated to"
                            " certificate blob=%p, in case of failure\n",
                            __FUNCTION__, __LINE__, pCertificate->blob.pBuffer);
                }
            }
            pCertificate->blob.pBuffer = NULL;
            pCertificate->blob.bufferLen = 0;
        }
    }
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_ROOT_OF_TRUST_KEY_HANDLE__
MSTATUS SMP_API(TPM2, getRootOfTrustKeyHandle,
        TAP_ModuleHandle moduleHandle,
        TAP_ObjectId objectId,
        TAP_ROOT_OF_TRUST_TYPE type,
        TAP_ObjectHandle *pKeyHandle
)
{
    MSTATUS status = OK;
    ContextGetPrimaryObjectNameIn objNameIn = {0};
    ContextGetPrimaryObjectNameOut objNameOut = {0};
    byteBoolean moduleLocked = FALSE;
    CACHED_KeyInfo *pCachedKey = NULL;
    SMP_Context *pSmpContext = NULL;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if ((0 == moduleHandle) || (0 == objectId) ||
            (NULL == pKeyHandle))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input, moduleHandle = %p, objectId = %p,"
                "pKeyHandle = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                objectId, pKeyHandle);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);

    if ((FAPI2_RH_EK != objectId) && (FAPI2_RH_SRK != objectId))
    {
        if ((objectId < TPM2_PERSISTENT_FIRST) ||
                (objectId > TPM2_PERSISTENT_LAST))
        {
            status = ERR_INVALID_ARG;
            DB_PRINT("%s.%d object id 0x%08x is invalid\n",
                    __FUNCTION__,__LINE__, (int)objectId);
            goto exit;
        }
    }

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to wait on mutex for module=%p, status=%d",
                __FUNCTION__, __LINE__, moduleHandle, status);
        goto exit;
    }
    moduleLocked = TRUE;

    objNameIn.persistentHandle = objectId;
    rc = FAPI2_CONTEXT_getPrimaryObjectName(pSmpContext->pFapiContext,
            &objNameIn, &objNameOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to get primary object name for EK, "
                "rc 0x%02x\n",
                __FUNCTION__,__LINE__, rc);
        goto exit;
    }

    /* Allocate a key object */
    status = DIGI_CALLOC((void **)&pCachedKey, 1, sizeof(*pCachedKey));

    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for cached key object,"
               " status = %d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

    pCachedKey->objectType = TPM2_OBJECT_TYPE_KEY;
    pCachedKey->id = objectId;
    pCachedKey->keyName = objNameOut.objName;

    *pKeyHandle = (TAP_ObjectHandle)((uintptr)pCachedKey);

    pCachedKey = NULL;

exit:
    if (pCachedKey)
        DIGI_FREE((void **)&pCachedKey);

    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_DUPLICATEKEY__
MSTATUS SMP_API(TPM2, DuplicateKey,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_Blob *pNewPubkeyBlob,
        TAP_Buffer *pDuplicateBuf
)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    FAPI2_DuplicateIn  dupIn  = { 0 };
    FAPI2B_DUPLICATE   dupOut = { 0 };
    TPM2B_PUBLIC_BLOB  publicBlob = {0};
    SMP_Context *pSmpContext = NULL;
    CACHED_KeyInfo *pKeyObject = NULL;
    byteBoolean moduleLocked = FALSE;

    if ((0 == moduleHandle) || (0 == keyHandle)
        || (NULL == pNewPubkeyBlob) || (NULL == pDuplicateBuf)
        || (NULL == pNewPubkeyBlob->blob.pBuffer))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "keyHandle = %p, pNewPubkey = %p, pDuplicateBuf = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                keyHandle, pNewPubkeyBlob, pDuplicateBuf);
        goto exit;
    }
    if(pNewPubkeyBlob->blob.bufferLen > sizeof(TPM2B_PUBLIC))
    {
        status = ERR_BAD_LENGTH;
        DB_PRINT("%s.%d blob length %d exceeds TPM2B_PUBLIC size", __FUNCTION__, __LINE__, pNewPubkeyBlob->blob.bufferLen) ;
        goto exit;
    }
    pDuplicateBuf->pBuffer = NULL ;
    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pKeyObject = (CACHED_KeyInfo *)((uintptr)keyHandle);


    /* Copy the key handle */
    dupIn.keyName = pKeyObject->keyName;

    publicBlob.size = pNewPubkeyBlob->blob.bufferLen ;
    (void) DIGI_MEMCPY(publicBlob.buffer,pNewPubkeyBlob->blob.pBuffer,pNewPubkeyBlob->blob.bufferLen);
    dupIn.pNewParent = &publicBlob ;
    dupIn.newParentHierarchy = TPM2_RH_OWNER ;


    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error, Failed waiting on mutex for module - %p"
                ", status - %d\n",
                __FUNCTION__, __LINE__, pSmpContext, status);
        goto exit;
    }
    moduleLocked = TRUE;

    rc = FAPI2_ASYM_DuplicateKey(pSmpContext->pFapiContext, &dupIn, &dupOut) ;

    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to Duplicate, rc = 0x%02x\n", __FUNCTION__, __LINE__,
                rc);
        goto exit;
    }

    RTOS_mutexRelease(pSmpContext->moduleMutex);
    moduleLocked = FALSE;

    status = DIGI_MALLOC((void **)&(pDuplicateBuf->pBuffer), dupOut.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory for TAP_Buffer object,"
                " status = %d\n", __FUNCTION__,__LINE__, status);
        goto exit;
    }

    status = DIGI_MEMCPY((void *)pDuplicateBuf->pBuffer, (const void *)dupOut.buffer, dupOut.size) ;
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy memory for TAP_Buffer object,"
                " status = %d\n", __FUNCTION__,__LINE__, status);
        goto exit;
    }
    pDuplicateBuf->bufferLen = dupOut.size ;

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    if((OK != status) && pDuplicateBuf && (pDuplicateBuf->pBuffer))
    {
        DIGI_FREE((void **)&(pDuplicateBuf->pBuffer)) ;
    }
    return status ;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_IMPORTDUPLICATEKEY__
MSTATUS TPM2_ImportKey(SMP_Context *pSmpContext,
        TAP_KeyAttributes *pKeyAttributeList, FAPI2B_DUPLICATE *pFapiDup,
        TAP_ObjectHandle *pKeyHandle,
        TAP_ObjectCapabilityAttributes *pKeyObjectAttributes)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_RC_SUCCESS;
    FAPI2_ImportIn importIn = { 0 };
    FAPI2_ImportOut importOut = { 0 };
    ContextSetObjectAuthIn objAuthIn = {0};
    TAP_KEY_ALGORITHM keyAlgorithm = TAP_KEY_ALGORITHM_RSA;
    TAP_KEY_USAGE keyUsage = TAP_KEY_USAGE_DECRYPT;
    TAP_KEY_SIZE keySize = TAP_KEY_SIZE_2048;
    TAP_ENC_SCHEME encScheme = TAP_ENC_SCHEME_PKCS1_5;
    TAP_SIG_SCHEME sigScheme = TAP_SIG_SCHEME_PKCS1_5;
    TAP_ECC_CURVE eccCurve =  TAP_ECC_CURVE_NIST_P192;
    TAP_HASH_ALG hashAlg = TAP_HASH_ALG_NONE;
    TAP_SYM_KEY_MODE symMode = TAP_SYM_KEY_MODE_CTR;
    CACHED_KeyInfo *pCachedKey = NULL;
    ubyte4 numCreatedKeyAttributes = 0;
    TAP_Attribute *pCreatedKeyAttributes = NULL;
    TAP_Attribute *pAttribute = NULL;
    ubyte4 count = 0;
    ContextGetPrimaryObjectNameIn objNameIn = {0};
    ContextGetPrimaryObjectNameOut objNameOut = {0};
    TPM2B_AUTH keyAuth = { 0 };
    TPM2B_AUTH *pKeyAuth = NULL;
    TAP_CredentialList *pKeyCredentials = NULL;

    if ((NULL == pSmpContext) || (NULL == pKeyHandle))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, pSmpContext = %p,"
                "pKeyHandle = %p\n",
                __FUNCTION__, __LINE__, pSmpContext, pKeyHandle);
        goto exit;
    }

    status = DIGI_CALLOC((void **)&pCachedKey, 1, sizeof(*pCachedKey));

    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for cached key object,"
               " status = %d\n", __FUNCTION__, __LINE__, status);
        goto exit;
    }

    if (pKeyAttributeList && pKeyAttributeList->listLen)
    {
        for (count = 0; count < pKeyAttributeList->listLen; count++)
        {
            pAttribute = &pKeyAttributeList->pAttributeList[count];

            switch (pAttribute->type)
            {
                case TAP_ATTR_KEY_ALGORITHM:
                    if (sizeof(TAP_KEY_ALGORITHM) == pAttribute->length)
                        keyAlgorithm = *(TAP_KEY_ALGORITHM *)pAttribute->pStructOfType;
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key algorithm length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    break;

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
                case TAP_ATTR_CREDENTIAL_SET:
                    pKeyAuth = &keyAuth;
                    pKeyCredentials = (TAP_CredentialList*)pAttribute->pStructOfType;
                    TPM2_getCredentialsList(
                                (TAP_CredentialList *)pAttribute->pStructOfType,
                                TAP_CREDENTIAL_TYPE_PASSWORD, pKeyAuth);

                    break;

                case TAP_ATTR_KEY_SIZE:
                    if (sizeof(TAP_KEY_SIZE) == pAttribute->length)
                        keySize = *((TAP_KEY_SIZE *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key size structure length %d, status = %d\n",
                                __FUNCTION__, __LINE__, pAttribute->length, status);
                        goto exit;
                    }
                    break;

                case TAP_ATTR_HASH_ALG:
                    if (sizeof(TAP_HASH_ALG) == pAttribute->length)
                        hashAlg = *(TAP_KEY_ALGORITHM *)pAttribute->pStructOfType;
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid key algorithm length %d, status = %d\n",
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

                case TAP_ATTR_SYM_KEY_MODE:
                    if (sizeof(TAP_SYM_KEY_MODE) == pAttribute->length)
                        symMode = *((TAP_SYM_KEY_MODE *)(pAttribute->pStructOfType));
                    else
                    {
                        status = ERR_INVALID_ARG;
                        DB_PRINT("%s.%d Invalid sym key mode structure length %d,"
                               " status = %d\n", __FUNCTION__, __LINE__,
                               pAttribute->length, status);
                        goto exit;
                    }
                    break;
            }
        }
    }

    pCachedKey->keyAlgorithm = keyAlgorithm;

    objNameIn.persistentHandle = FAPI2_RH_SRK ;

    rc = FAPI2_CONTEXT_getPrimaryObjectName(pSmpContext->pFapiContext,
                &objNameIn, &objNameOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to get primary object name %d, "
                "rc 0x%02x, status = %d\n",
                __FUNCTION__,__LINE__, objNameIn.persistentHandle, rc, status);
        goto exit;
    }

    importIn.parentName = objNameOut.objName;
    importIn.pFapiDup = pFapiDup ;

    switch (keyAlgorithm)
    {
        case TAP_KEY_ALGORITHM_HMAC:
        case TAP_KEY_ALGORITHM_AES:
            rc = FAPI2_SYM_ImportDuplicateKey(pSmpContext->pFapiContext,
                &importIn, &importOut);
            break;

        default:
            rc = FAPI2_ASYM_ImportDuplicateKey(pSmpContext->pFapiContext,
                &importIn, &importOut);
            break;
    }
    if (TSS2_RC_SUCCESS != rc)
    {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d Failed to import key under SRK, "
                    "rc 0x%02x\n",
                    __FUNCTION__,__LINE__, rc);
            goto exit;
    }

    objAuthIn.objName = importOut.keyName;
    objAuthIn.objAuth = keyAuth;
    objAuthIn.forceUseAuthValue = 1;

    rc = FAPI2_CONTEXT_setObjectAuth(pSmpContext->pFapiContext,
                &objAuthIn);
    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to set object auth, "
                "rc 0x%02x\n",
                __FUNCTION__,__LINE__, rc);
        goto exit;
    }

    if (pKeyObjectAttributes)
    {
        switch (keyAlgorithm)
        {
            case TAP_KEY_ALGORITHM_HMAC:
            case TAP_KEY_ALGORITHM_AES:
                /* Put together TAP Attribute list of the parameters used to create
                 * this key */
                numCreatedKeyAttributes = 6;
                pKeyObjectAttributes->listLen = numCreatedKeyAttributes;

                status = DIGI_CALLOC((void **)&pKeyObjectAttributes->pAttributeList, 1,
                        sizeof(TAP_Attribute) * numCreatedKeyAttributes);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed to allocate memory for created key attribute list"
                            "status = %d\n",
                            __FUNCTION__,__LINE__, status);
                    goto exit;
                }

                count = 0;
                pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

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
                status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &(keyUsage),
                        sizeof(keyUsage));
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed to copy keyUsage attribute"
                            "status = %d\n",
                            __FUNCTION__,__LINE__, status);
                    goto exit;
                }

                pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

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
                status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &(keyAlgorithm),
                        sizeof(keyAlgorithm));
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed to copy keyAlgorithm attribute"
                            "status = %d\n",
                            __FUNCTION__,__LINE__, status);
                    goto exit;
                }

                pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

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
                status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &(keySize),
                                sizeof(keySize));
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed to copy keySize attribute"
                        "status = %d\n",
                        __FUNCTION__,__LINE__, status);
                    goto exit;
                }

                pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

                if (TAP_KEY_ALGORITHM_HMAC == keyAlgorithm)
                {
                    pCreatedKeyAttributes->type = TAP_ATTR_HASH_ALG;
                    pCreatedKeyAttributes->length = sizeof(hashAlg);
                    status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                        sizeof(hashAlg));
                    if (OK != status)
                    {
                        DB_PRINT("%s.%d Failed to allocate memory for hashAlg attribute"
                            "status = %d\n",
                            __FUNCTION__,__LINE__, status);
                        goto exit;
                    }
                    status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &(hashAlg),
                                    sizeof(hashAlg));
                    if (OK != status)
                    {
                        DB_PRINT("%s.%d Failed to copy hashAlg attribute"
                            "status = %d\n",
                            __FUNCTION__,__LINE__, status);
                        goto exit;
                    }
                }
                else /* TAP_KEY_ALGORITHM_AES */
                {
                    pCreatedKeyAttributes->type = TAP_ATTR_SYM_KEY_MODE;
                    pCreatedKeyAttributes->length = sizeof(symMode);
                    status = DIGI_MALLOC((void **)&pCreatedKeyAttributes->pStructOfType,
                        sizeof(symMode));
                    if (OK != status)
                    {
                        DB_PRINT("%s.%d Failed to allocate memory for symMode attribute"
                            "status = %d\n",
                            __FUNCTION__,__LINE__, status);
                        goto exit;
                    }
                    status = DIGI_MEMCPY(pCreatedKeyAttributes->pStructOfType, &(symMode),
                                    sizeof(symMode));
                    if (OK != status)
                    {
                        DB_PRINT("%s.%d Failed to copy symMode attribute"
                            "status = %d\n",
                            __FUNCTION__,__LINE__, status);
                        goto exit;
                    }
                }
                break;

            default:
                /* Put together TAP Attribute list of the parameters used to create
                 * this key */
                numCreatedKeyAttributes = 6;
                pKeyObjectAttributes->listLen = numCreatedKeyAttributes;

                status = DIGI_CALLOC((void **)&pKeyObjectAttributes->pAttributeList, 1,
                        sizeof(TAP_Attribute) * numCreatedKeyAttributes);
                if (OK != status)
                {
                    DB_PRINT("%s.%d Failed to allocate memory for created key attribute list"
                            "status = %d\n",
                            __FUNCTION__,__LINE__, status);
                    goto exit;
                }

                count = 0;
                pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

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

                pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

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

                pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

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

                pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

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

                pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

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
                else
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
                break;
        }

        pCreatedKeyAttributes = &pKeyObjectAttributes->pAttributeList[count++];

        /* Last entry */
        pCreatedKeyAttributes->type = TAP_ATTR_NONE;
        pCreatedKeyAttributes->length = 0;
        pCreatedKeyAttributes->pStructOfType = NULL;
    }

    status = DIGI_MEMCPY(pCachedKey->keyName.name, importOut.keyName.name,
                importOut.keyName.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy keyname, "
                "status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }
    pCachedKey->keyName.size = importOut.keyName.size;

    status = DIGI_MEMCPY(pCachedKey->key.buffer, importOut.object.buffer,
            importOut.object.size);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to copy serialized key, "
                "status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }
    pCachedKey->key.size = importOut.object.size;

    pCachedKey->objectType = TPM2_OBJECT_TYPE_KEY;
    *pKeyHandle = (TAP_ObjectHandle)((uintptr)pCachedKey);
    pCachedKey = NULL;
exit:
    if (pCachedKey)
        DIGI_FREE((void **)&pCachedKey);

    if (OK != status)
    {
        if (NULL!=pKeyObjectAttributes)
            freeAttrList(pKeyObjectAttributes);
    }

    return status;
}

MSTATUS SMP_API(TPM2, ImportDuplicateKey,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_KeyAttributes *pKeyAttributes,
        TAP_Buffer *pDuplicateBuf,
        TAP_ObjectAttributes *pObjectAttributes,
        TAP_ObjectHandle *pKeyHandle
)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    FAPI2B_DUPLICATE fapiDup = { 0 } ;
    SMP_Context *pSmpContext = NULL;
    byteBoolean moduleLocked = FALSE;

    if ((0 == moduleHandle) || (NULL == pKeyHandle)
        || (NULL == pDuplicateBuf))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "keyHandle = %p, pDuplicateBuf = %p\n",
                __FUNCTION__, __LINE__, moduleHandle, pKeyHandle,
                pDuplicateBuf);
        goto exit;
    }
    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);


    /* Copy the key handle */
    fapiDup.size = pDuplicateBuf->bufferLen ;
    if(fapiDup.size > sizeof(FAPI2_DuplicateOut))
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Duplicated buffer size %d exceeds expected size %d\n", __FUNCTION__,
                __LINE__, fapiDup.size, sizeof(FAPI2_DuplicateOut));
        goto exit;
    }
    (void) DIGI_MEMCPY((void *) fapiDup.buffer,(const void *)pDuplicateBuf->pBuffer ,fapiDup.size);

    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error, Failed waiting on mutex for module - %p"
                ", status - %d\n",
                __FUNCTION__, __LINE__, pSmpContext, status);
        goto exit;
    }
    moduleLocked = TRUE;

    rc = TPM2_ImportKey(pSmpContext, pKeyAttributes, &fapiDup, pKeyHandle, pObjectAttributes) ;

    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to Import, rc = 0x%02x\n", __FUNCTION__, __LINE__,
                rc);
        goto exit;
    }

    RTOS_mutexRelease(pSmpContext->moduleMutex);
    moduleLocked = FALSE;


exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    return status ;
}
#endif

/* freeAttrList
 * Internal Method used for freeing memory allocated to 'pAttributeList' member of struct TAP_AttributeList and its members
 * Note - This does not release memory associated with TAP_AttributeList *pAttrs itself. This has to be freed by caller as appropriate.
 */
static MSTATUS freeAttrList(TAP_AttributeList *pAttrs)
{
    MSTATUS status = OK;
    ubyte4 count = 0;
    TAP_Attribute *pAttr = NULL;

    if ((NULL == pAttrs) || (NULL == pAttrs->pAttributeList))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pAttr = pAttrs->pAttributeList;

    for (count = 0; count < pAttrs->listLen; count++)
    {
        if (NULL == pAttr)
        {
            /* stop on encountering null element */
            break;
        }

        if (OK != DIGI_FREE((void **)(&(pAttr->pStructOfType))))
        {
            DB_PRINT("%s.%d Failed freeing memory of pAttr->pStructOfType at %p\n",
                __FUNCTION__, __LINE__, pAttr->pStructOfType);
        }

        pAttr++;
    }

    /* Free the memory allocated to complete attr-list */
    if (OK != DIGI_FREE((void **)(&(pAttrs->pAttributeList))))
    {
        DB_PRINT("%s.%d Failed freeing memory of pAttrs->pAttributeList "
                "to attribute list at %p\n",
            __FUNCTION__, __LINE__, pAttrs->pAttributeList);
    }

    pAttrs->listLen = 0;

exit:
    return status;
}

#ifdef __SMP_ENABLE_SMP_CC_SELF_TEST__
MOC_EXTERN MSTATUS SMP_API(TPM2, selfTest,
        TAP_ModuleHandle moduleHandle,
        TAP_TestRequestAttributes *pTestRequest,
        TAP_TestResponseAttributes *pTestResponse
)
{
    MSTATUS status = OK;
    TestingSelfTestIn testIn = {0};
    TestingSelfTestOut testOut = {0};
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    SMP_Context *pSmpContext = NULL;
    TAP_TEST_MODE testMode = TAP_TEST_MODE_FULL;
    TAP_TEST_STATUS *pTestResult = NULL;
    TPM2_MODULE_CONFIG_SECTION *pModuleConfigInfo = NULL;
    byteBoolean moduleLocked = FALSE;
    TAP_Attribute *pAttribute = NULL;

    if ((0 == moduleHandle) ||
            (NULL == pTestResponse))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input, moduleHandle = %p, "
                "pTestResponse = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                pTestResponse);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);

    status = getModuleConnectionInfo(pSmpContext->moduleId,
            &pModuleConfigInfo);

    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to locate Device module, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    /* Get test mode */
    if (pTestRequest && pTestRequest->listLen)
    {
        if (TPM2_getAttribute(pTestRequest, TAP_ATTR_TEST_MODE,
                    &pAttribute))
        {
            if ((sizeof(testMode) != pAttribute->length) ||
                    (NULL == pAttribute->pStructOfType))
            {
                status = ERR_INVALID_ARG;
                DB_PRINT("%s.%d Invalid storage structure length %d, "
                        "pStructOfType = %p\n",
                        __FUNCTION__, __LINE__, pAttribute->length,
                        pAttribute->pStructOfType);
                goto exit;
            }

            testMode = *(TAP_TEST_MODE *)(pAttribute->pStructOfType);

            switch (testMode)
            {
                case TAP_TEST_MODE_FULL:
                case TAP_TEST_MODE_LAST_RESULTS:
                    break;

                default:
                    status = ERR_INVALID_ARG;
                    DB_PRINT("%s.%d Unsupported testmode %d\n",
                            __FUNCTION__, __LINE__, testMode);
                    goto exit;
            }
        }
    }

    if (TAP_TEST_MODE_FULL == testMode)
    {
        testIn.fullTest = 1;
        testIn.getResultsOnly = 0;

        status = RTOS_mutexWait(pSmpContext->moduleMutex);
        if (OK != status)
        {
            DB_PRINT("%s.%d Failed waiting on module mutex for module - %p,"
                    " status=%d\n", __FUNCTION__, __LINE__,
                    moduleHandle, status);
            goto exit;
        }
        moduleLocked = TRUE;

        rc = FAPI2_TESTING_SelfTest(pSmpContext->pFapiContext,
                &testIn, &testOut);

        if (TSS2_RC_SUCCESS != rc)
        {
            status = SMP_TPM2_UTILS_getMocanaError(rc);
            DB_PRINT("%s.%d Failed to start self test, "
                    "rc 0x%02x\n",
                    __FUNCTION__,__LINE__, rc);
            goto exit;
        }

        /* Save this result in module structure for future retrieval */
        pModuleConfigInfo->testResult = (OK == testOut.testResult) ? TAP_TEST_STATUS_SUCCESS :
            TAP_TEST_STATUS_FAILURE;

    }

    /* Populate result in attribute list */
    pTestResponse->listLen = 1;

    status = DIGI_CALLOC((void **)&pTestResponse->pAttributeList, 1,
            sizeof(TAP_Attribute) * pTestResponse->listLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory for test result attribute list"
                "status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    status = DIGI_MALLOC((void **)&pTestResult, sizeof(*pTestResult));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory for test result, "
                "status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    *pTestResult = pModuleConfigInfo->testResult;

    pTestResponse->pAttributeList[0].type = TAP_ATTR_TEST_STATUS;
    pTestResponse->pAttributeList[0].length = sizeof(*pTestResult);
    pTestResponse->pAttributeList[0].pStructOfType = pTestResult;

    pTestResult = NULL;
exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    if (OK != status)
    {
        /* Failed, release memory */
        if (pTestResult)
            DIGI_FREE((void **)&pTestResult);
        if (pTestResponse && pTestResponse->pAttributeList)
            DIGI_FREE((void **)&pTestResponse->pAttributeList);
    }

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SELF_TEST_POLL__
/* Returns the result of the last test */
MOC_EXTERN MSTATUS SMP_API(TPM2, selfTestPoll,
        TAP_ModuleHandle moduleHandle,
        TAP_TestRequestAttributes *pTestRequest,
        TAP_TestContext testContext,
        TAP_TestResponseAttributes *pTestResponse
)
{
    MSTATUS status = OK;
    SMP_Context *pSmpContext = NULL;
    TAP_TEST_MODE testMode = TAP_TEST_MODE_LAST_RESULTS;
    TAP_TEST_STATUS *pTestResult = NULL;
    TPM2_MODULE_CONFIG_SECTION *pModuleConfigInfo = NULL;
    TAP_Attribute *pAttribute = NULL;

    if ((0 == moduleHandle) ||
            (NULL == pTestResponse))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid input, moduleHandle = %p, "
                "pTestResponse = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                pTestResponse);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);

    status = getModuleConnectionInfo(pSmpContext->moduleId,
            &pModuleConfigInfo);

    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to locate Device module, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    /* Get test mode */
    if (pTestRequest && pTestRequest->listLen)
    {
        if (TPM2_getAttribute(pTestRequest, TAP_ATTR_TEST_MODE,
                    &pAttribute))
        {
            if ((sizeof(testMode) != pAttribute->length) ||
                    (NULL == pAttribute->pStructOfType))
            {
                status = ERR_INVALID_ARG;
                DB_PRINT("%s.%d Invalid storage structure length %d, "
                        "pStructOfType = %p\n",
                        __FUNCTION__, __LINE__, pAttribute->length,
                        pAttribute->pStructOfType);
                goto exit;
            }

            testMode = *(TAP_TEST_MODE *)(pAttribute->pStructOfType);

            if (TAP_TEST_MODE_LAST_RESULTS != testMode)
            {
                status = ERR_INVALID_ARG;
                DB_PRINT("%s.%d Unsupported testmode %d\n",
                        __FUNCTION__, __LINE__, testMode);
                goto exit;
            }
        }
    }

    /* Populate result in attribute list */
    pTestResponse->listLen = 1;

    status = DIGI_CALLOC((void **)&pTestResponse->pAttributeList, 1,
            sizeof(TAP_Attribute) * pTestResponse->listLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory for test result attribute list"
                "status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    status = DIGI_MALLOC((void **)&pTestResult, sizeof(*pTestResult));
    if (OK != status)
    {
        DB_PRINT("%s.%d Failed to allocate memory for test result, "
                "status = %d\n",
                __FUNCTION__,__LINE__, status);
        goto exit;
    }

    *pTestResult = pModuleConfigInfo->testResult;

    pTestResponse->pAttributeList[0].type = TAP_ATTR_TEST_STATUS;
    pTestResponse->pAttributeList[0].length = sizeof(*pTestResult);
    pTestResponse->pAttributeList[0].pStructOfType = pTestResult;

    pTestResult = NULL;
exit:
    if (OK != status)
    {
        /* Failed, release memory */
        if (pTestResult)
            DIGI_FREE((void **)&pTestResult);
        if (pTestResponse && pTestResponse->pAttributeList)
            DIGI_FREE((void **)&pTestResponse->pAttributeList);
    }

    return status;
}
#endif

static MSTATUS symSignHmac(
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle keyHandle,
        TAP_SIG_SCHEME signScheme,
        TAP_SignAttributes *pSignatureAttributes,
        TAP_Buffer *pInBuffer,
        TAP_Signature **ppSignature 
)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    SymHmacIn symHmacIn   = { 0 };
    SymHmacOut  symHmacOut  = { 0 };
    TPM2B_NAME *pKeyName = NULL;
    SMP_Context *pSmpContext = NULL;
    CACHED_KeyInfo *pKeyObject = NULL;
    byteBoolean moduleLocked = FALSE;
    TAP_SymSignature *pHmacSignature = NULL;
    TAP_Attribute *pAttribute = NULL;

    if ((0 == moduleHandle) || (0 == keyHandle)
        || (NULL == pInBuffer) || (NULL == ppSignature))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input, moduleHandle = %p,"
                "keyHandle = %p, pInBuffer = %p, ppSignature = %p\n",
                __FUNCTION__, __LINE__, moduleHandle,
                keyHandle, pInBuffer, ppSignature);
        goto exit;
    }

    pSmpContext = (SMP_Context *)((uintptr)moduleHandle);
    pKeyObject = (CACHED_KeyInfo *)((uintptr)keyHandle);

    pKeyName = &(symHmacIn.keyName);

    /* Copy the key handle */
    *pKeyName = pKeyObject->keyName;

    symHmacIn.bufferLen = pInBuffer->bufferLen;
    symHmacIn.pBuffer = pInBuffer->pBuffer;

    /* Set other attributes */
    symHmacIn.hashAlg = TPM2_ALG_NULL;
    /* Check if hash-algorithm attribute is present in attribute-list*/
    if (TPM2_getAttribute(pSignatureAttributes, TAP_ATTR_HASH_ALG,
                &pAttribute))
    {
        if ((sizeof(TAP_HASH_ALG) == pAttribute->length) &&
                            (NULL != pAttribute->pStructOfType))
        {

            switch (*(TAP_HASH_ALG *)pAttribute->pStructOfType)
            {
                case TAP_HASH_ALG_SHA256:
                    symHmacIn.hashAlg = TPM2_ALG_SHA256;
                    break;

                case TAP_HASH_ALG_SHA384:
                    symHmacIn.hashAlg = TPM2_ALG_SHA384;
                    break;

                case TAP_HASH_ALG_SHA512:
                    symHmacIn.hashAlg = TPM2_ALG_SHA512;
                    break;

                default:
                    symHmacIn.hashAlg = TPM2_ALG_NULL;
                    break;
            }
        }
    }
    /* If not present in attribute-list then check the signScheme , else keep it NULL */
    if (TPM2_ALG_NULL == symHmacIn.hashAlg)
    {
        switch (signScheme)
        {
            case TAP_SIG_SCHEME_HMAC_SHA1:
                symHmacIn.hashAlg = TPM2_ALG_SHA1;
                break;

            case TAP_SIG_SCHEME_HMAC_SHA256:
                symHmacIn.hashAlg = TPM2_ALG_SHA256;
                break;

            case TAP_SIG_SCHEME_HMAC_SHA384:
                symHmacIn.hashAlg = TPM2_ALG_SHA384;
                break;

            case TAP_SIG_SCHEME_HMAC_SHA512:
                symHmacIn.hashAlg = TPM2_ALG_SHA512;
                break;

            default:
                symHmacIn.hashAlg = TPM2_ALG_NULL;
                break;
        }
    }
    
    status = RTOS_mutexWait(pSmpContext->moduleMutex);
    if (OK != status)
    {
        DB_PRINT("%s.%d Error, Failed waiting on mutex for module - %p"
                ", status - %d\n",
                __FUNCTION__, __LINE__, pSmpContext, status);
        goto exit;
    }
    moduleLocked = TRUE;

    rc = FAPI2_SYM_Hmac(pSmpContext->pFapiContext, &symHmacIn, &symHmacOut);

    if (TSS2_RC_SUCCESS != rc)
    {
        status = SMP_TPM2_UTILS_getMocanaError(rc);
        DB_PRINT("%s.%d Failed to generate HMAC digest, rc = 0x%02x\n", __FUNCTION__, __LINE__,
                rc);
        goto exit;
    }

    RTOS_mutexRelease(pSmpContext->moduleMutex);
    moduleLocked = FALSE;

    status = DIGI_CALLOC((void **)ppSignature, 1, sizeof(**ppSignature));

    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for "
                "signature structure, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    if (TAP_KEY_ALGORITHM_HMAC == pKeyObject->keyAlgorithm)
    {
        (*ppSignature)->keyAlgorithm = TAP_KEY_ALGORITHM_HMAC;
    }
    else
    {
        status = ERR_TAP_INVALID_ALGORITHM;
        goto exit;
    }

    pHmacSignature = &((*ppSignature)->signature.hmacSignature);
    pHmacSignature->signatureLen = symHmacOut.outLen;
    status = DIGI_CALLOC((void **)&(pHmacSignature->pSignature), 1,
            pHmacSignature->signatureLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for signature buffer"
                ", status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }
    status = DIGI_MEMCPY((ubyte *)(pHmacSignature->pSignature),
            (ubyte *)(symHmacOut.pOutBuffer),
            symHmacOut.outLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to copy signature buffer"
                ", status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

exit:
    if (TRUE == moduleLocked)
        RTOS_mutexRelease(pSmpContext->moduleMutex);

    if (OK != status)
    {
        if (ppSignature)
        {
            if (pHmacSignature)
            {
                if (pHmacSignature->pSignature)
                    DIGI_FREE((void **)&pHmacSignature->pSignature);
            }

            DIGI_FREE((void **)ppSignature);
        }
    }

    if (symHmacOut.pOutBuffer)
    {
        DIGI_FREE((void **)&symHmacOut.pOutBuffer);
    }

    return status;
}

#endif /* #if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_TPM2__)) */
