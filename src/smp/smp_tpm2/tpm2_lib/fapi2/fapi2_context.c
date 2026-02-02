/**
 * @file fapi2_context.c
 * @brief This file contains code required to maintain state in FAPI2.
 * commands.
 * @flags
 *  To enable this file's functions, the following flags must be defined in
 * moptions.h:
 *
 *  + \c \__ENABLE_DIGICERT_TPM2__
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

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../../../../common/mtypes.h"
#include "../../../../common/merrors.h"
#include "../../../../common/mocana.h"
#include "../../../../common/mdefs.h"
#include "../../../../common/mstdlib.h"
#include "../../../../crypto/hw_accel.h"
#include "../../../../common/debug_console.h"
#include "../tpm_common/tpm_error_utils.h"
#include "fapi2.h"
#include "fapi2_internal.h"

TSS2_RC FAPI2_CONTEXT_init(FAPI2_CONTEXT **ppFapiContext,
        ubyte4 serverNameLen, ubyte *pServerName,
        ubyte2 serverPort, ubyte objCacheSize, void *pReserved)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    FAPI2_CONTEXT *pNewContext = NULL;
    MSTATUS status = ERR_GENERAL;
    UtilsCreateObjectIn createObjectIn = { 0 };
    UtilsCreateObjectOut createObjectOut = { 0 };
    MgmtCapabilityIn capabilityIn = { 0 };
    MgmtCapabilityOut capabilityOut = { 0 };
    const BulkHashAlgo *pHashAlgOut = NULL;
    TPM2B_AUTH emptyAuth = { 0 };

    if ((NULL == ppFapiContext) || (NULL != *ppFapiContext))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /* Check if initMocana called */
    if (NULL == g_pRandomContext)
    {
        rc = TSS2_SYS_RC_INSUFFICIENT_CONTEXT;
        DB_PRINT("%s.%d DIGICERT_initDigicert() not yet called, random"
                " context not initialized. rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (objCacheSize < 3)
    {
        rc = TSS2_SYS_RC_BAD_SIZE;
        DB_PRINT("%s.%d Object cache size must atleast be 3,"
                " rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    status = DIGI_CALLOC((void **)&pNewContext, 1, sizeof(FAPI2_CONTEXT));
    if (OK != status)
    {
        rc = TSS2_SYS_RC_INSUFFICIENT_BUFFER;
        DB_PRINT("%s.%d Failed to allocate memory for FAPI2_CONTEXT"
                ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = SAPI2_CONTEXT_init(&(pNewContext->pSapiCtx), serverNameLen,
            pServerName, serverPort, pReserved);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to Init SAPI2 context"
                ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    status = DIGI_CALLOC((void **)&(pNewContext->objCache.pObjectList),
            1, objCacheSize * sizeof(*(pNewContext->objCache.pObjectList)));
    if (OK != status)
    {
        rc = TSS2_SYS_RC_INSUFFICIENT_BUFFER;
        DB_PRINT("%s.%d Failed to allocate memory for object cache"
                ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pNewContext->objCache.objCacheSize = objCacheSize;
    pNewContext->objCache.numUsed = 0;

    /* Set session defaults */
    pNewContext->sessionParams.sessionType = TPM2_SE_HMAC;
    pNewContext->sessionParams.sessionAlg = TPM2_ALG_SHA256;
    pNewContext->sessionParams.sessionAlgSize = 32;
    pNewContext->sessionParams.paramEnc.algorithim = TPM2_ALG_NULL;
    pNewContext->sessionParams.sessionAttributes = TPMA_SESSION_CONTINUESESSION;

    /* Default name algorithm is SHA256 */
    pNewContext->nameAlg = TPM2_ALG_SHA256;
    pNewContext->nameAlgSize = 32;

    /* Mark this context as being one created by provisioning tool */
    if ((pReserved && (*(int *)pReserved == 1)))
        pNewContext->provision = 1;

    /*
     * At this point the context is valid and ready for use.
     */

    {
        /*
         * Create FAPI2_OBJECTS for the EK and SRK. It is possible that the TPM
         * has not yet been provisioned, or an advanced user has chosen to persist
         * the EK/SRK at different locations than those recommended by TCG. In
         * these cases, the creation of objects may fail but it does not preclude
         * the use of the FAPI2_CONTEXT. It is not an error if creation of these
         * objects fail. If the error is unexpected, ie the TPM is provisioned
         * and the EK/SRK's are at known locations, then the error occurs when these
         * keys are used. Also, at this point, we create objects for EK and SRK with
         * authValues equal to the EmptyBuffer. If they have different passwords
         * the application is expected to set the authValues explicitly.
         */
        createObjectIn.tpm2Handle = FAPI2_RH_EK;
        createObjectIn.numPolicyTerms = 1;
        createObjectIn.pObjectPolicy = &tcgEKPolicy;
        rc = FAPI2_UTILS_createObject(pNewContext, &createObjectIn, &createObjectOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            if (!(pReserved && (*(int *)pReserved == 1)))
            {
                DB_PRINT("%s.%d Failed to create EK object. Possible causes:"
                        "TPM Not provisioned yet or EK not at expected location(advanced"
                        "user). This is not a fatal error"
                        ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            }
        }
        else
        {
            pNewContext->primaryKeys.pEK = createObjectOut.pObject;
            rc = FAPI2_UTILS_setObjectAuth(pNewContext->primaryKeys.pEK, &emptyAuth);
            if (TSS2_RC_SUCCESS != rc)
            {
                DB_PRINT("%s.%d Unable to set EK object auth, rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            /*
             * Create object handle for EK.
             */
            rc = FAPI2_UTILS_loadObjectTree(pNewContext, pNewContext->primaryKeys.pEK,
                    &pNewContext->primaryKeys.pEKHandle);
            if (TSS2_RC_SUCCESS != rc)
            {
                DB_PRINT("%s.%d Failed to Create handle for EK"
                        ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }
        }

        createObjectOut.pObject = NULL;
        createObjectIn.tpm2Handle = FAPI2_RH_SRK;
        createObjectIn.numPolicyTerms = 0;
        createObjectIn.pObjectPolicy = NULL;
        rc = FAPI2_UTILS_createObject(pNewContext, &createObjectIn, &createObjectOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            if (!(pReserved && (*(int *)pReserved == 1)))
            {
                DB_PRINT("%s.%d Failed to create SRK object. Possible causes:"
                        "TPM Not provisioned yet or SRK not at expected location(advanced"
                        "user). This is not a fatal error"
                        ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            }
        }
        else
        {
            pNewContext->primaryKeys.pSRK = createObjectOut.pObject;

            rc = FAPI2_UTILS_setObjectAuth(pNewContext->primaryKeys.pSRK, &emptyAuth);
            if (TSS2_RC_SUCCESS != rc)
            {
                DB_PRINT("%s.%d Unable to set SRK object auth, rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            /*
             * Create object handle for EK.
             */
            rc = FAPI2_UTILS_loadObjectTree(pNewContext, pNewContext->primaryKeys.pSRK,
                    &pNewContext->primaryKeys.pSRKHandle);
            if (TSS2_RC_SUCCESS != rc)
            {
                DB_PRINT("%s.%d Failed to Create handle for SRK"
                        ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

        }
    }

    capabilityIn.capability = TPM2_CAP_TPM_PROPERTIES;
    capabilityIn.property = TPM2_PT_CONTEXT_HASH;
    capabilityIn.propertyCount = 256;

    rc = FAPI2_MGMT_getCapability(pNewContext, &capabilityIn, &capabilityOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get context hash length"
                ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (capabilityOut.capabilityData.data.tpmProperties.tpmProperty[0].property
            != TPM2_PT_CONTEXT_HASH)
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid property returned by TPM"
                ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pNewContext->tpmContextHashAlg =
            capabilityOut.capabilityData.data.tpmProperties.tpmProperty[0].value;

    if ((pNewContext->tpmContextHashAlg != TPM2_ALG_SHA256) &&
            (pNewContext->tpmContextHashAlg != TPM2_ALG_SHA384) &&
            (pNewContext->tpmContextHashAlg != TPM2_ALG_SHA512))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Unsupported hash algorithm returned by TPM for context hash"
                ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = SAPI2_UTILS_getHashAlg(pNewContext->tpmContextHashAlg, &pHashAlgOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get context hash algorithm"
                ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pNewContext->tpmContextHashAlgLen = pHashAlgOut->digestSize;

    capabilityIn.capability = TPM2_CAP_TPM_PROPERTIES;
    capabilityIn.property = TPM2_PT_NV_INDEX_MAX;
    capabilityIn.propertyCount = 256;

    rc = FAPI2_MGMT_getCapability(pNewContext, &capabilityIn, &capabilityOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get Max NV Index size"
                ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (capabilityOut.capabilityData.data.tpmProperties.count < 1 ||
            capabilityOut.capabilityData.data.tpmProperties.tpmProperty[0].property != TPM2_PT_NV_INDEX_MAX)
    {
        DB_PRINT("%s.%d Unexpected NV capability response."
                ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pNewContext->maxNvIndexSize =
            capabilityOut.capabilityData.data.tpmProperties.tpmProperty[0].value;

    capabilityIn.capability = TPM2_CAP_TPM_PROPERTIES;
    capabilityIn.property = TPM2_PT_NV_BUFFER_MAX;
    capabilityIn.propertyCount = 256;

    rc = FAPI2_MGMT_getCapability(pNewContext, &capabilityIn, &capabilityOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get Max NV transaction size"
                ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (capabilityOut.capabilityData.data.tpmProperties.count < 1 ||
            capabilityOut.capabilityData.data.tpmProperties.tpmProperty[0].property != TPM2_PT_NV_BUFFER_MAX)
    {
        DB_PRINT("WARNING: %s.%d Unexpected NV capability response."
                ", defaulting to 64 byte chunks\n",
                        __FUNCTION__,__LINE__);
        pNewContext->maxNvTransactionSize = 64;
    }
    else
    {
        pNewContext->maxNvTransactionSize =
                capabilityOut.capabilityData.data.tpmProperties.tpmProperty[0].value;
    }

    if (pNewContext->maxNvTransactionSize > TPM2_MAX_NV_BUFFER_SIZE)
    {
        DB_PRINT("%s.%d FAPI2 unusable on this TPM. MAX NV buffer size of TPM"
                " larger than supported by FAPI2."
                ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    *ppFapiContext = (FAPI2_CONTEXT *)pNewContext;

    rc = TSS2_RC_SUCCESS;
exit:
    if (TSS2_RC_SUCCESS != rc)
    {
        if (pNewContext)
            FAPI2_CONTEXT_uninit(&pNewContext);
    }

    return rc;
}

TSS2_RC FAPI2_CONTEXT_uninit(FAPI2_CONTEXT **ppFapiContext)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    FAPI2_CONTEXT *pFreeContext = NULL;
    int i = 0;

    if ((NULL == ppFapiContext) || (NULL == *ppFapiContext))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pFreeContext = *ppFapiContext;

    if (pFreeContext->primaryKeys.pEKHandle)
        FAPI2_UTILS_destroyHandle(pFreeContext,
                &pFreeContext->primaryKeys.pEKHandle);

    if (pFreeContext->primaryKeys.pSRKHandle)
        FAPI2_UTILS_destroyHandle(pFreeContext,
                &pFreeContext->primaryKeys.pSRKHandle);

    if (pFreeContext->primaryKeys.pEK)
        FAPI2_UTILS_destroyObject(&pFreeContext->primaryKeys.pEK);

    if (pFreeContext->primaryKeys.pSRK)
        FAPI2_UTILS_destroyObject(&pFreeContext->primaryKeys.pSRK);

    rc = SAPI2_CONTEXT_uninit(&(pFreeContext->pSapiCtx));
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to free sapi context, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    for (i = 0; i < pFreeContext->objCache.objCacheSize; i++)
    {
        if (pFreeContext->objCache.pObjectList[i].pObject)
        {
            DB_PRINT("Warning: Unflushed objects in context! Ref count: %d\n",
                    pFreeContext->objCache.pObjectList[i].refCount);

            FAPI2_UTILS_destroyObject(
                    &(pFreeContext->objCache.pObjectList[i].pObject));
        }
    }

    rc = TSS2_RC_SUCCESS;
exit:
    
    if (pFreeContext && pFreeContext->objCache.pObjectList)
        shredMemory((ubyte **)&(pFreeContext->objCache.pObjectList),
                pFreeContext->objCache.objCacheSize * sizeof(*(pFreeContext->objCache.pObjectList)),
                TRUE);

    if (pFreeContext)
        shredMemory((ubyte **)&pFreeContext, sizeof(FAPI2_CONTEXT), TRUE);
    return rc;
}

/*
 * An application is expected to call this API after creating a context
 * and set the authValues of all hierarchies. The hierarchy authValues
 * are used internally by many FAPI's. This is useful to applications
 * to avoid having to pass the authValue every time a FAPI is invoked.
 * If the application does not want the authValues lying around in the
 * context, it is expected to call this API with all inputs with size 0,
 * which will clear the authValues in memory.
 * The authValues are initialized to the EmptyBuffer(authValue of
 * size 0) during context creation.
 * If all parameters are of size 0, the function does NOT return
 * an error but does clear out the authValues in the context
 */
TSS2_RC FAPI2_CONTEXT_setHierarchyAuth(
        FAPI2_CONTEXT *pCtx,
        ContextSetHierarchyAuthIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    if (!pCtx || !pIn)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pIn->ownerAuth.size != 0 || pIn->forceUseOwnerAuth)
    {

        TPM2B_SIZE_CHECK(&pIn->ownerAuth, pCtx->tpmContextHashAlgLen);
        pCtx->authValues.ownerAuth = pIn->ownerAuth;
        pCtx->authValues.ownerAuthValid = TRUE;
    }
    else
    {
        DIGI_MEMSET((ubyte *)&pCtx->authValues.ownerAuth, 0,
                sizeof(pCtx->authValues.ownerAuth));
        pCtx->authValues.ownerAuthValid = FALSE;
    }

    if (pIn->endorsementAuth.size != 0 || pIn->forceUseEndorsementAuth)
    {
        TPM2B_SIZE_CHECK(&pIn->endorsementAuth, pCtx->tpmContextHashAlgLen);
        pCtx->authValues.endorsementAuth = pIn->endorsementAuth;
        pCtx->authValues.endorsementAuthValid = TRUE;
    }
    else
    {
        DIGI_MEMSET((ubyte *)&pCtx->authValues.endorsementAuth, 0,
                sizeof(pCtx->authValues.endorsementAuth));
        pCtx->authValues.endorsementAuthValid = FALSE;
    }

    if (pIn->lockoutAuth.size != 0 || pIn->forceUseLockoutAuth)
    {
        TPM2B_SIZE_CHECK(&pIn->lockoutAuth, pCtx->tpmContextHashAlgLen);
        pCtx->authValues.lockoutAuth = pIn->lockoutAuth;
        pCtx->authValues.lockoutAuthValid = TRUE;
    }
    else
    {
        DIGI_MEMSET((ubyte *)&pCtx->authValues.lockoutAuth, 0,
                sizeof(pCtx->authValues.lockoutAuth));
        pCtx->authValues.lockoutAuthValid = FALSE;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

/*
 * An application is expected to call this API after creating a context
 * and set the authValues of the EK and SRK. The EK and SRK objects are
 * created with authValues equal to the EmptyBuffer and will be used as
 * is unless the application explicitly sets their authValues.
 * This is useful to applications to avoid having to pass the authValue
 * every time a FAPI is invoked.
 * If the application does not want the authValues lying around in the
 * context, it is expected to call this API with all inputs as NULL,
 * which will clear the authValues in memory. Only non-NULL input parameters
 * are used. If all parameters are NULL, the function does NOT return an
 * error but does clear out the authValues in the context.
 */
TSS2_RC FAPI2_CONTEXT_setPrimaryKeyAuth(
        FAPI2_CONTEXT *pCtx,
        ContextSetPrimaryKeyAuthIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if (!pCtx || !pIn)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pIn->EKAuth.size != 0)
        TPM2B_SIZE_CHECK(&pIn->EKAuth, pCtx->nameAlgSize);

    if (pIn->SRKAuth.size != 0)
        TPM2B_SIZE_CHECK(&pIn->SRKAuth, pCtx->nameAlgSize);

    if (pCtx->primaryKeys.pEK)
    {
        /*
         * Invalidate authValue when 0 size authValue is set.
         */
        if (pIn->EKAuth.size != 0 || (pIn->forceUseEKAuth))
            FAPI2_UTILS_setObjectAuth(pCtx->primaryKeys.pEK, &pIn->EKAuth);
        else
            FAPI2_UTILS_setObjectAuth(pCtx->primaryKeys.pEK, NULL);
    }

    if (pCtx->primaryKeys.pSRK)
    {
        if (pIn->SRKAuth.size != 0 || ((pIn->forceUseSRKAuth)))
            FAPI2_UTILS_setObjectAuth(pCtx->primaryKeys.pSRK, &pIn->SRKAuth);
        else
            FAPI2_UTILS_setObjectAuth(pCtx->primaryKeys.pSRK, NULL);
    }

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

/*
 * This API can be used to obtain the max length that can be used for authValues
 * for regular objects and hierarchies.
 * The default name algorithm in a FAPI2_CONTEXT is SHA256, so 32 bytes is the
 * default value/expected value.
 */
TSS2_RC FAPI2_CONTEXT_getMaxAuthValueLength(
        FAPI2_CONTEXT *pCtx,
        ContextGetAuthValueLengthOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if (!pCtx || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->objectAuthValueLen = pCtx->nameAlgSize;
    pOut->hierarchyAuthValueLen = pCtx->tpmContextHashAlgLen;
    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

/*
 * This function loads a given object into the context and returns a handle(name)
 * to the object that can be used with the given context. Providing a handle
 * instead of passing around FAPI2_OBJECT structures is more efficient, especially
 * in case there is a remote application using FAPI2.
 */
TSS2_RC FAPI2_CONTEXT_loadObjectEx(
        FAPI2_CONTEXT *pCtx,
        ContextLoadObjectExIn *pIn,
        ContextLoadObjectExOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    int i = 0;
    byteBoolean objAdded = FALSE;
    FAPI2_OBJECT *pObject = NULL;
    ContextFlushObjectIn flushObjectIn = { 0 };

    if (!pCtx || !pIn || !pOut || !pIn->pObj)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pCtx->objCache.numUsed >= pCtx->objCache.objCacheSize)
    {
        rc = TSS2_SYS_RC_INSUFFICIENT_BUFFER;
        DB_PRINT("%s.%d Object cache full in this context, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * If the object already exists, return success.
     */
    rc = FAPI2_CONTEXT_lookupObject(pCtx, &(pIn->pObj->objectName), &pObject);
    if (TSS2_RC_SUCCESS == rc)
    {
        pOut->objName = pIn->pObj->objectName;
        /*
         * Flush reference to pObject that we may have obtained here
         */
        if (pObject)
        {
            flushObjectIn.objName = pObject->objectName;
            rc = FAPI2_CONTEXT_flushObject(pCtx, &flushObjectIn);
        }

        goto exit;
    }

    for (i = 0; i < pCtx->objCache.objCacheSize; i++)
    {
        if (NULL == pCtx->objCache.pObjectList[i].pObject)
        {
            if (pIn->pAuthObj && (pIn->pAuthObj->size != 0))
            {
                rc = FAPI2_UTILS_setObjectAuth(pIn->pObj, pIn->pAuthObj);
                if (TSS2_RC_SUCCESS != rc)
                {
                    DB_PRINT("%s.%d Failed to set objects authValue, rc 0x%02x = %s\n",
                            __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                    goto exit;
                }
            }

            pCtx->objCache.pObjectList[i].pObject = pIn->pObj;
            pCtx->objCache.pObjectList[i].refCount = 1;
            pCtx->objCache.numUsed++;
            pOut->objName = pIn->pObj->objectName;
            objAdded = TRUE;
            break;
        }
    }

    if (!objAdded)
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Failed to add object into context."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

/*
 * This API can be used to load an object into a FAPI2 CONTEXT. When a FAPI2
 * API to create an object is invoked, the serialized object suitable for storage
 * is returned. When a new context is created, this API must be used to make
 * the serialized object usable again.
 */
TSS2_RC FAPI2_CONTEXT_loadObject(
        FAPI2_CONTEXT *pCtx,
        ContextLoadObjectIn *pIn,
        ContextLoadObjectOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    FAPI2_OBJECT *pObject = NULL;
    ContextLoadObjectExIn loadIn = { 0 };
    ContextLoadObjectExOut loadOut = { 0 };

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->obj, TPM2B_MAX_SIZE(&pIn->obj));
    TPM2B_SIZE_CHECK(&pIn->objAuth, pCtx->nameAlgSize);

    rc = FAPI2_UTILS_deserialize(&pIn->obj, &pObject);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to de-serialized object, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    loadIn.pObj = pObject;
    loadIn.pAuthObj = &pIn->objAuth;

    rc = FAPI2_CONTEXT_loadObjectEx(pCtx, &loadIn, &loadOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to load object into context, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->objName = loadOut.objName;
    pOut->objectType = pObject->public.objectPublic.publicArea.type;
    pOut->parameters = pObject->public.objectPublic.publicArea.parameters;

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

/*
 * This API can be used to flush an object that is loaded into a FAPI2_CONTEXT.
 * This will destroy the object with the given Name and free all resources
 * used by the object. Objects are loaded when they are created or when they
 * are deserialized and explicitly loaded into the context.
 */
TSS2_RC FAPI2_CONTEXT_flushObject(
        FAPI2_CONTEXT *pCtx,
        ContextFlushObjectIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    sbyte4 cmpResult = 0;
    int i = 0;
    TPM2B_NAME *pObjName = NULL;
    FAPI2_OBJECT *pObject = NULL;
    byteBoolean objDestroyed = FALSE;

    if (!pCtx || !pIn)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->objName, TPM2B_MAX_SIZE(&pIn->objName));

    /*
     * For EK and SRK, context uninit will destroy the object, so flush need not
     * do anything. if it does attempt to free it here, there will be a double free
     * during context uninit. Also flushing it here means the context will become
     * unusable for other API's, since they all heavily rely on EK and SRK being
     * available.
     */
    if (pCtx->primaryKeys.pEK)
    {
        cmpResult = 0;
        if (OK != DIGI_MEMCMP((ubyte *)&pIn->objName,
                (ubyte *)&(pCtx->primaryKeys.pEK->objectName),
                sizeof(pIn->objName), &cmpResult))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d MEMCMP failed, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (!cmpResult)
        {
            objDestroyed = TRUE;
            rc = TSS2_RC_SUCCESS;
            goto exit;
        }
    }

    if (pCtx->primaryKeys.pSRK)
    {
        cmpResult = 0;
        if (OK != DIGI_MEMCMP((ubyte *)&pIn->objName,
                (ubyte *)&(pCtx->primaryKeys.pSRK->objectName),
                sizeof(pIn->objName), &cmpResult))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d MEMCMP failed, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (!cmpResult)
        {
            objDestroyed = TRUE;
            rc = TSS2_RC_SUCCESS;
            goto exit;
        }
    }

    for (i = 0; i < pCtx->objCache.objCacheSize; i++)
    {
        cmpResult = 0;

        if (NULL == pCtx->objCache.pObjectList[i].pObject)
            continue;

        pObjName = &pCtx->objCache.pObjectList[i].pObject->objectName;
        if (OK != DIGI_MEMCMP((ubyte *)pObjName, (ubyte *)&pIn->objName,
                sizeof(*pObjName), &cmpResult))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d MEMCMP failed, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (!cmpResult)
        {
            if (pCtx->objCache.pObjectList[i].refCount == 0)
            {
                rc = TSS2_SYS_RC_GENERAL_FAILURE;
                DB_PRINT("%s.%d Possible bug. Ref count is 0 and object was found in"
                        "cache., rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            pObject = pCtx->objCache.pObjectList[i].pObject;
            pCtx->objCache.pObjectList[i].refCount--;
            if (pCtx->objCache.pObjectList[i].refCount == 0)
            {
                rc = FAPI2_UTILS_destroyObject(&pObject);
                if (TSS2_RC_SUCCESS != rc)
                {
                    DB_PRINT("%s.%d Failed to destroy FAPI2_OBJECT, rc 0x%02x = %s\n",
                            __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                    goto exit;
                }
                pCtx->objCache.pObjectList[i].pObject = NULL;
                pCtx->objCache.pObjectList[i].refCount = 0;
                pCtx->objCache.numUsed--;
            }
            objDestroyed = TRUE;
            break;
        }
    }

    if (!objDestroyed)
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Object not found, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    rc = TSS2_RC_SUCCESS;
exit:

    return rc;
}

/*
 * This API can be used to evict key that s loaded into the TPM memory.
 * This will destroy the object with the given Name and free all resources
 * used by the object. Objects are loaded when they are created or when they
 * are deserialized and explicitly loaded into the context.
 */
TSS2_RC FAPI2_CONTEXT_evictKey(
        FAPI2_CONTEXT *pCtx,
        EvictKeyIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    sbyte4 cmpResult = 0;
    int i = 0;
    FAPI2_OBJECT *pObject = NULL;
    TPM2B_NAME *pObjName = NULL;
    byteBoolean objDestroyed = FALSE;
    EvictControlIn evictControlIn = { 0 };
    EvictControlOut evictControlOut = { 0 };
    MOCTPM2_OBJECT_HANDLE *pAuthSession = { 0 };
    MOCTPM2_OBJECT_HANDLE *pEvictHandle = {0};
    ContextFlushObjectIn flushObjectIn = { 0 };

    if (!pCtx || !pIn)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(&pIn->objName, TPM2B_MAX_SIZE(&pIn->objName));

    /* 
     * If this key is persisted to TPM2 
     * Evict it before freeing object memory
     */
    if (pIn->objectId)
    {
        rc = FAPI2_CONTEXT_lookupObject(pCtx, &pIn->objName, &pObject);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to locate FAPI object for this key, "
                    "rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        rc = FAPI2_UTILS_loadObjectTree(pCtx, pObject, &pEvictHandle); 
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to create handle to persist key, "
                    "rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        /*
         * Start regular session. 
         */
        rc = FAPI2_UTILS_startSession(pCtx, &pAuthSession);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to Start session."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        pEvictHandle->tpm2Handle = pIn->objectId;
        /*
         * Evict the key, set object handle and persistent handle to same value  
         */
        evictControlIn.authHandle = pIn->authHandle;
        evictControlIn.pObjectHandle = pEvictHandle;
        evictControlIn.persistentHandle = pIn->objectId;
        evictControlIn.pAuthAuthHandle = &(pIn->authHandleAuth);
        evictControlIn.pAuthSession = pAuthSession;

        rc = SAPI2_CTX_MGMT_EvictControl(pCtx->pSapiCtx,
                &evictControlIn, &evictControlOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to make primary key persistent."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        flushObjectIn.objName = pIn->objName;
        exit_rc = FAPI2_CONTEXT_flushObject(pCtx, &flushObjectIn);

        /*
         * For EK and SRK, context uninit will destroy the object, so flush need not
         * do anything. if it does attempt to free it here, there will be a double free
         * during context uninit. Also flushing it here means the context will become
         * unusable for other API's, since they all heavily rely on EK and SRK being
         * available.
         */
        if (pCtx->primaryKeys.pEK)
        {
            cmpResult = 0;
            if (OK != DIGI_MEMCMP((ubyte *)&pIn->objName,
                    (ubyte *)&(pCtx->primaryKeys.pEK->objectName),
                    sizeof(pIn->objName), &cmpResult))
            {
                rc = TSS2_SYS_RC_IO_ERROR;
                DB_PRINT("%s.%d MEMCMP failed, rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            if (!cmpResult)
            {
                objDestroyed = TRUE;
                rc = TSS2_RC_SUCCESS;
                goto exit;
            }
        }

        if (pCtx->primaryKeys.pSRK)
        {
            cmpResult = 0;
            if (OK != DIGI_MEMCMP((ubyte *)&pIn->objName,
                    (ubyte *)&(pCtx->primaryKeys.pSRK->objectName),
                    sizeof(pIn->objName), &cmpResult))
            {
                rc = TSS2_SYS_RC_IO_ERROR;
                DB_PRINT("%s.%d MEMCMP failed, rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            if (!cmpResult)
            {
                objDestroyed = TRUE;
                rc = TSS2_RC_SUCCESS;
                goto exit;
            }
        }

        for (i = 0; i < pCtx->objCache.objCacheSize; i++)
        {
            cmpResult = 0;

            if (NULL == pCtx->objCache.pObjectList[i].pObject)
                continue;

            pObjName = &pCtx->objCache.pObjectList[i].pObject->objectName;
            if (OK != DIGI_MEMCMP((ubyte *)pObjName, (ubyte *)&pIn->objName,
                    sizeof(*pObjName), &cmpResult))
            {
                rc = TSS2_SYS_RC_IO_ERROR;
                DB_PRINT("%s.%d MEMCMP failed, rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            if (!cmpResult)
            {
                if (pCtx->objCache.pObjectList[i].refCount == 0)
                {
                    rc = TSS2_SYS_RC_GENERAL_FAILURE;
                    DB_PRINT("%s.%d Possible bug. Ref count is 0 and object was found in"
                            "cache., rc 0x%02x = %s\n",
                            __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                    goto exit;
                }

                pObject = pCtx->objCache.pObjectList[i].pObject;
                pCtx->objCache.pObjectList[i].refCount--;
                if (pCtx->objCache.pObjectList[i].refCount == 0)
                {
                    rc = FAPI2_UTILS_destroyObject(&pObject);
                    if (TSS2_RC_SUCCESS != rc)
                    {
                        DB_PRINT("%s.%d Failed to destroy FAPI2_OBJECT, rc 0x%02x = %s\n",
                                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                        goto exit;
                    }
                    pCtx->objCache.pObjectList[i].pObject = NULL;
                    pCtx->objCache.pObjectList[i].refCount = 0;
                    pCtx->objCache.numUsed--;
                }
                objDestroyed = TRUE;
                break;
            }
        }

        if (!objDestroyed)
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Object not found, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
        rc = TSS2_RC_SUCCESS;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;
    
    if (pAuthSession)
    {
        exit_rc = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);

        if (TSS2_RC_SUCCESS == rc)
            rc = exit_rc;
    }

    return rc;
}

/*
 * This function looks up a FAPI2_OBJECT corresponding the given name.
 * It will return a failure if an object is not found.
 */
TSS2_RC FAPI2_CONTEXT_lookupObject(
        FAPI2_CONTEXT *pCtx,
        TPM2B_NAME *pName,
        FAPI2_OBJECT **ppObject
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    sbyte4 cmpResult = 0;
    int i = 0;
    byteBoolean objectFound = FALSE;

    if (!pCtx || !pName || !ppObject || (*ppObject != NULL))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pCtx->primaryKeys.pEK)
    {
        cmpResult = 0;
        if (OK != DIGI_MEMCMP((ubyte *)pName,
                (ubyte *)&(pCtx->primaryKeys.pEK->objectName),
                sizeof(*pName), &cmpResult))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d MEMCMP failed, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (!cmpResult)
        {
            *ppObject = pCtx->primaryKeys.pEK;
            objectFound = TRUE;
            goto exit;
        }
    }

    if (pCtx->primaryKeys.pSRK)
    {
        cmpResult = 0;
        if (OK != DIGI_MEMCMP((ubyte *)pName,
                (ubyte *)&(pCtx->primaryKeys.pSRK->objectName),
                sizeof(*pName), &cmpResult))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d MEMCMP failed, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (!cmpResult)
        {
            *ppObject = pCtx->primaryKeys.pSRK;
            objectFound = TRUE;
            goto exit;
        }
    }

    for (i = 0; i < pCtx->objCache.objCacheSize; i++)
    {
        if (NULL == pCtx->objCache.pObjectList[i].pObject)
            continue;

        cmpResult = 0;
        if (OK != DIGI_MEMCMP((ubyte *)pName,
                (ubyte *)&(pCtx->objCache.pObjectList[i].pObject->objectName),
                sizeof(*pName), &cmpResult))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d MEMCMP failed, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (!cmpResult)
        {
            *ppObject = pCtx->objCache.pObjectList[i].pObject;
            pCtx->objCache.pObjectList[i].refCount++;
            objectFound = TRUE;
            break;
        }
    }

exit:
    if (!objectFound)
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
    }
    else
    {
        rc = TSS2_RC_SUCCESS;
    }
    return rc;
}

/*
 * This function looks up a FAPI2_OBJECT corresponding to the given primary
 * handle. It will return a failure if an object is not found.
 */
TSS2_RC FAPI2_CONTEXT_lookupPrimaryObjectByHandle(
        FAPI2_CONTEXT *pCtx,
        TPM2_HANDLE objectHandle,
        FAPI2_OBJECT **ppObject
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    int i = 0;
    byteBoolean objectFound = FALSE;

    if (!pCtx || !IS_TPM2_PERSISTENT_HANDLE(objectHandle) ||
            !ppObject || (*ppObject != NULL))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pCtx->primaryKeys.pEK)
    {
        if (pCtx->primaryKeys.pEK->objectHandle == objectHandle)
        {
            *ppObject = pCtx->primaryKeys.pEK;
            objectFound = TRUE;
            goto exit;
        }
    }

    if (pCtx->primaryKeys.pSRK)
    {

        if (pCtx->primaryKeys.pSRK->objectHandle == objectHandle)
        {
            *ppObject = pCtx->primaryKeys.pSRK;
            objectFound = TRUE;
            goto exit;
        }
    }

    for (i = 0; i < pCtx->objCache.objCacheSize; i++)
    {
        if (NULL == pCtx->objCache.pObjectList[i].pObject)
            continue;

        if (pCtx->objCache.pObjectList[i].pObject->objectHandle == objectHandle)
        {
            *ppObject = pCtx->objCache.pObjectList[i].pObject;
            pCtx->objCache.pObjectList[i].refCount++;
            objectFound = TRUE;
            break;
        }
    }

exit:
    if (!objectFound)
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
    }
    else
    {
        rc = TSS2_RC_SUCCESS;
    }
    return rc;
}

TSS2_RC FAPI2_CONTEXT_getLastTpmError(
        FAPI2_CONTEXT *pCtx,
        ContextGetLastTpmErrorOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    if (!pCtx || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->tpmError = SAPI2_CONTEXT_getLastTpmError(pCtx->pSapiCtx);

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

/*
 * This API informs the caller if the TPM is provisioned or not. If there is no EK
 * or SRK provisioned on the TPM, the TPM can only be used as a crypto engine and
 * Key creation, attestation, signing etc cannot be performed using
 * the TPM.
 * Success returned in the API does not mean that the TPM is provisioned. The output
 * parameter must be checked by the caller.
 */
TSS2_RC FAPI2_CONTEXT_isTpmProvisioned(
        FAPI2_CONTEXT *pCtx,
        ContextIsTpmProvisionedOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if (!pCtx || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->provisioned = FALSE;

    if (pCtx->primaryKeys.pEK && pCtx->primaryKeys.pSRK)
        pOut->provisioned = TRUE;

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

/*
 * This API can be used to get handles/names of primary objects such as EK, SRK, AK etc.
 * For persistent/primary objects(which are typically primary keys), no handle is returned
 * when the objects are created. For non-persistent objects, a handle/name is returned
 * upon creation or when the serialized object is loaded into a context. Since the primary
 * keys/objects are persistent and no private area is returned by the TPM, there is no need
 * for a serialized object or handle to be returned. Any time there is a requirement to use
 * these primary/persistent objects, an application can provided the persistent handle to
 * this API to get a handle back, which can then be used in any other API's that require
 * a handle(such as FAPI2_ASYM_sign() etc). A slot in the object cache is used if an object
 * is created and does not already exist in the context.
 */
TSS2_RC FAPI2_CONTEXT_getPrimaryObjectName(
        FAPI2_CONTEXT *pCtx,
        ContextGetPrimaryObjectNameIn *pIn,
        ContextGetPrimaryObjectNameOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    FAPI2_OBJECT *pObject = NULL;
    TPM2B_NAME *pObjectName = NULL;
    UtilsCreateObjectIn createObjectIn = { 0 };
    UtilsCreateObjectOut createObjectOut = { 0 };
    ContextLoadObjectExIn loadIn = { 0 };
    ContextLoadObjectExOut loadOut = { 0 };
    ContextFlushObjectIn flushObjectIn = { 0 };

    if (!pCtx || !pOut || !pIn)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((FAPI2_RH_EK != pIn->persistentHandle) && (FAPI2_RH_SRK != pIn->persistentHandle))
    {
        if ((pIn->persistentHandle < TPM2_PERSISTENT_FIRST) ||
                (pIn->persistentHandle > TPM2_PERSISTENT_LAST))
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid persistent handle specified, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    /*
     * For SRK and EK, the context should contain the public information already. If
     * the context does not contain them, the TPM is not provisioned and there is no
     * point in going to the TPM to read the public area again.
     */
    if (FAPI2_RH_EK == pIn->persistentHandle)
    {
        if (NULL == pCtx->primaryKeys.pEK)
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            if (!pCtx->provision)
                DB_PRINT("%s.%d EK not provisioned in the TPM yet, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
        pObject = pCtx->primaryKeys.pEK;
        pObjectName = &(pCtx->primaryKeys.pEK->objectName);
    }
    else if (FAPI2_RH_SRK == pIn->persistentHandle)
    {
        if (NULL == pCtx->primaryKeys.pSRK)
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            if (!pCtx->provision)
                DB_PRINT("%s.%d SRK not provisioned in the TPM yet, rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        pObject = pCtx->primaryKeys.pSRK;
        pObjectName = &(pCtx->primaryKeys.pSRK->objectName);
    }
    else
    {
        rc = FAPI2_CONTEXT_lookupPrimaryObjectByHandle(pCtx,
                pIn->persistentHandle, &pObject);
        if (TSS2_RC_SUCCESS != rc)
        {
            /*
             * Create object only if it does not already exist.
             */
            createObjectIn.tpm2Handle = pIn->persistentHandle;
            rc = FAPI2_UTILS_createObject(pCtx, &createObjectIn, &createObjectOut);
            if (TSS2_RC_SUCCESS != rc)
            {
                DB_PRINT("%s.%d Failed to create object for persistent handle. Unable to get public key"
                        ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }
            pObject = createObjectOut.pObject;
            pObjectName = &loadOut.objName;

            /*
             * authValue must be set using setObjectAuth().
             */
            loadIn.pAuthObj = NULL;
            loadIn.pObj = pObject;

            rc = FAPI2_CONTEXT_loadObjectEx(pCtx, &loadIn, &loadOut);
            if (TSS2_RC_SUCCESS != rc)
            {
                DB_PRINT("%s.%d Failed to load object into context, "
                        "rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }
        }
        else
        {
            pObjectName = &(pObject->objectName);
        }
    }

    pOut->objName = *(pObjectName);

    rc = TSS2_RC_SUCCESS;
exit:
    if (rc != TSS2_RC_SUCCESS)
    {
        if (pObject)
        {
            flushObjectIn.objName = pObject->objectName;
            exit_rc = FAPI2_CONTEXT_flushObject(pCtx, &flushObjectIn);
        }
    }

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

/*
 * This API can be used to set the authValue for an object once it has been loaded. An
 * application may want to load an object using FAPI2_CONTEXT_loadObject but not want to
 * provide the authValue during load and instead only provided it right before use. This
 * API can be used in such situations. Using an authValue of size 0 will clear the authValue
 * in memory and applications can use this API to clear an authValue that has been set.
 * This will also invalidate the authValue.
 * If an application must use a 0 password, the flag, forceUseAuthValue must be set.
 * For EK and SRK, FAPI2_CONTEXT_setPrimaryKeyAuth() or FAPI2_CONTEXT_setPrimaryKeyAuth
 * can be used.
 */
TSS2_RC FAPI2_CONTEXT_setObjectAuth(
        FAPI2_CONTEXT *pCtx,
        ContextSetObjectAuthIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    FAPI2_OBJECT *pKey = NULL;
    ContextFlushObjectIn flushObjectIn = { 0 };

    if (!pCtx || !pIn)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * authValue for primary/peristent keys and regular objects cannt be more than
     * nameAlgSize. name length cant be greater than nameAlgSize + 2 since the name
     * includes the Name algorithm id.
     */
    TPM2B_SIZE_CHECK(&pIn->objAuth, pCtx->nameAlgSize);
    TPM2B_SIZE_CHECK(&pIn->objName, (pCtx->nameAlgSize + 2));

    rc = FAPI2_CONTEXT_lookupObject(pCtx, &pIn->objName, &pKey);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Unable to find key object, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pIn->objAuth.size != 0 || (pIn->forceUseAuthValue))
    {
        rc = FAPI2_UTILS_setObjectAuth(pKey, &pIn->objAuth);
    }
    else
    {
        rc = FAPI2_UTILS_setObjectAuth(pKey, NULL);
    }

    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Unable to set object auth, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    if (pKey)
    {
        flushObjectIn.objName = pKey->objectName;
        exit_rc = FAPI2_CONTEXT_flushObject(pCtx, &flushObjectIn);
    }

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

TSS2_RC FAPI2_CONTEXT_getObjectPrivateInfo(
        FAPI2_CONTEXT *pCtx,
        ContextGetObjectPrivateInfoIn *pIn,
        ContextGetObjectPrivateInfoOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    FAPI2_OBJECT *pObject = NULL;
    ContextFlushObjectIn flushObjectIn = { 0 };

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * name length cant be greater than nameAlgSize + 2 since the name
     * includes the Name algorithm id.
     */
    TPM2B_SIZE_CHECK(&pIn->object, (pCtx->nameAlgSize + 2));

    rc = FAPI2_CONTEXT_lookupObject(pCtx, &pIn->object, &pObject);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Unable to find object, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->privateInfo = pObject->private.tpmPrivate;
    rc = TSS2_RC_SUCCESS;
exit:
    if (pObject)
    {
        flushObjectIn.objName = pObject->objectName;
        exit_rc = FAPI2_CONTEXT_flushObject(pCtx, &flushObjectIn);
    }

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

/*
 * This API can be used to get an objects public information, which contains information about
 * its type, its name, its public key(if any), schemes, sizes, curvers, policy digests etc.
 * The object for which the information is required, must be loaded into the context.
 */
TSS2_RC FAPI2_CONTEXT_getObjectPublicInfo(
        FAPI2_CONTEXT *pCtx,
        ContextGetObjectPublicInfoIn *pIn,
        ContextGetObjectPublicInfoOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    FAPI2_OBJECT *pObject = NULL;
    ContextFlushObjectIn flushObjectIn = { 0 };

    if (!pCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * name length cant be greater than nameAlgSize + 2 since the name
     * includes the Name algorithm id.
     */
    TPM2B_SIZE_CHECK(&pIn->object, (pCtx->nameAlgSize + 2));

    rc = FAPI2_CONTEXT_lookupObject(pCtx, &pIn->object, &pObject);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Unable to find object, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->publicInfo = pObject->public.objectPublic.publicArea;
    rc = TSS2_RC_SUCCESS;
exit:
    if (pObject)
    {
        flushObjectIn.objName = pObject->objectName;
        exit_rc = FAPI2_CONTEXT_flushObject(pCtx, &flushObjectIn);
    }

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

TSS2_RC FAPI2_CONTEXT_getObjectPrivateInfoBlob(
        FAPI2_CONTEXT *pCtx,
        ContextGetObjectPrivateInfoIn *pIn,
        ContextGetObjectPrivateInfoBlobOut *pPrivateBlob
)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    ContextGetObjectPrivateInfoOut privateInfoOut = { 0 };
    ubyte4 serializedSize = 0;
    ubyte *pData;

    if (!pCtx || !pIn || !pPrivateBlob)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    rc = FAPI2_CONTEXT_getObjectPrivateInfo(pCtx, pIn, &privateInfoOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get private key info, "
                "rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    pData = pPrivateBlob->pBuffer;

    status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPM2B_PRIVATE, TAP_SD_IN,
            (ubyte*)&privateInfoOut.privateInfo, sizeof(TPM2B_PRIVATE),
            pData, sizeof(TPM2B_PRIVATE), &serializedSize);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to serialize objectHandle, status=%d\n", __FUNCTION__,
                __LINE__, status);
        goto exit;
    }
    pPrivateBlob->size = serializedSize;
    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC FAPI2_CONTEXT_getObjectPublicInfoBlob(
        FAPI2_CONTEXT *pCtx,
        ContextGetObjectPublicInfoIn *pIn,
        ContextGetObjectPublicInfoBlobOut *pPublicBlob
)
{
    MSTATUS status = OK;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    ContextGetObjectPublicInfoOut publicInfoOut = { 0 };
    ubyte4 serializedSize = 0;
    ubyte2 publicsize = 0;
    ubyte *pData;
    TPM2B_PUBLIC_BLOB *pPublickeyData = NULL;

    if (!pCtx || !pIn || !pPublicBlob)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    rc = FAPI2_CONTEXT_getObjectPublicInfo(pCtx, pIn, &publicInfoOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get public key info, "
                "rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    pPublickeyData = &(pPublicBlob->publicInfo);
    pData = pPublickeyData->buffer +2 ;
    
    status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPMT_PUBLIC, TAP_SD_IN,
            (ubyte*)&publicInfoOut.publicInfo, sizeof(TPMT_PUBLIC),
            pData, sizeof(TPMT_PUBLIC), &serializedSize);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to serialize objectHandle, status=%d\n", __FUNCTION__,
                __LINE__, status);
        goto exit;
    }
    pData = pPublickeyData->buffer ;
    publicsize = serializedSize;
    serializedSize = 0 ;
    status = SAPI2_SERIALIZE_serialize(SAPI2_ST_UBYTE2, TAP_SD_IN,
            (ubyte*)&publicsize, sizeof(publicsize),
            pData, sizeof(publicsize), &serializedSize);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to serialize objectHandle, status=%d\n", __FUNCTION__,
                __LINE__, status);
        goto exit;
    }
    pPublickeyData->size = publicsize+sizeof(publicsize) ;    
    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
