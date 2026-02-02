/**
 * @file fapi2_utils.c
 * @brief This file contains utility functions to be used with FAPI
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
#include "../tap_serialize_tpm2.h"

/*
 * Use this function to create a handle from a FAPI2_OBJECT.
 * This uses FAPI2_UTILS_loadObjectTreeEx() underneath to load
 * arbitrary(as allowed by the TPM spec) hierarchies of objects.
 * FAPI2_UTILS_loadObjectTreeEx() has a few more options and this is
 * a simpler wrapper that should suffices for most uses.
 *
 * Note that calling this function on the EK and SRK should be used carefully
 * since handles are already created and cached in the context.
 *
 */
TSS2_RC FAPI2_UTILS_loadObjectTree(
        FAPI2_CONTEXT *pCtx,
        FAPI2_OBJECT *pObject,
        MOCTPM2_OBJECT_HANDLE **ppHandle
)
{
    UtilsLoadObjectTreeExIn loadObjectTreeIn = { 0 };
    UtilsLoadObjectTreeExOut loadObjectTreeOut = { 0 };
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if (!pCtx || !pObject || !ppHandle || (NULL != *ppHandle))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid input pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    loadObjectTreeIn.pObject = pObject;
    loadObjectTreeIn.getParentHandle = FALSE;
    rc = FAPI2_UTILS_loadObjectTreeEx(pCtx, &loadObjectTreeIn,
            &loadObjectTreeOut);
    if (TSS2_RC_SUCCESS == rc)
    {
        *ppHandle = loadObjectTreeOut.pObjectHandle;
    }
    else
    {
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;

}

/*
 * Use this function to create a handle from a FAPI2_OBJECT.
 * This uses FAPI2_UTILS_createHandle() underneath to load
 * arbitrary(as allowed by the TPM spec) hierarchies of objects.
 * The main different between loadObjectTreeEx() and createHandle()
 * is that this function automatically figures out the object
 * hierarchy and loads the object into the TPM, whereas createHandle()
 * explicitly requires selection of parent. A flag can be set to leave
 * the parent loaded in the TPM.
 *
 * Note that calling this function on the EK and SRK should be used carefully
 * since handles are already created and cached in the context.
 */
TSS2_RC FAPI2_UTILS_loadObjectTreeEx(
        FAPI2_CONTEXT *pCtx,
        UtilsLoadObjectTreeExIn *pIn,
        UtilsLoadObjectTreeExOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    TSS2_RC exit_rc1 = TSS2_RC_SUCCESS;
    TSS2_RC exit_rc2 = TSS2_RC_SUCCESS;
    UtilsCreateHandleIn createHandleIn = { 0 };
    UtilsCreateHandleOut createHandleOut = { 0 };
    UtilsCreateHandleIn createParentHandleIn = { 0 };
    UtilsCreateHandleOut createParentHandleOut = { 0 };
    UtilsLoadObjectTreeExIn loadParentIn = { 0 };
    UtilsLoadObjectTreeExOut loadParentOut = { 0 };
    byteBoolean destroyParentHandle = FALSE;
    FAPI2_OBJECT *pParentObject = NULL;
    MOCTPM2_OBJECT_HANDLE *pParentHandle = NULL;
    ContextFlushObjectIn flushObjectIn = { 0 };

    if ((NULL == pCtx) || (NULL == pIn->pObject) || (NULL == pOut) ||
            (NULL != pOut->pParentObject) || (NULL != pOut->pParentHandle) ||
            (NULL != pOut->pObjectHandle))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid input pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pIn->pObject->authValueRequired) && (!pIn->pObject->authValueValid))
    {
        rc = TSS2_FAPI_RC_NOT_PERMITTED;
        DB_PRINT("%s.%d authValue not set for object."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * If the object to be loaded is a persistent/primary object, or NV index
     * or an external object, we can just called FAPI2_UTILS_createHandle().
     */
    if (IS_TPM2_PERSISTENT_HANDLE(pIn->pObject->objectHandle) ||
            IS_TPM2_NV_HANDLE(pIn->pObject->objectHandle) ||
            (pIn->pObject->isExternal && (0 == pIn->pObject->objectHandle)))
    {
        createHandleIn.pObject = pIn->pObject;

        rc = FAPI2_UTILS_createHandle(pCtx, &createHandleIn, &createHandleOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to create object for NV/Persistent/External object."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        pOut->pObjectHandle = createHandleOut.pHandle;
        /*
         * For NV, persistent objects or external keys, parents are hierarchies
         * and are already present in object. Set them to NULL here.
         */
        pOut->pParentHandle = NULL;
        pOut->pParentObject = NULL;

        rc = TSS2_RC_SUCCESS;
        goto exit;
    }

    /*
     * At this point the objectHandle must be 0, ie non-persistent object
     */
    if (0 != pIn->pObject->objectHandle)
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid objectHandle."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    createHandleIn.pObject = pIn->pObject;
    if (!pIn->getParentHandle)
        destroyParentHandle = TRUE;
    else
        destroyParentHandle = FALSE;

    /*
     * If this objects parents is a persistent object, then we can use
     * FAPI2_UTILS_createHandle() to create the handle for this object,
     * since this is the last object that needs loading through TPM2_load().
     * Terminal condition of the recursive function.
     */
    if (IS_TPM2_PERSISTENT_HANDLE(pIn->pObject->parentHandle))
    {
        /*
         * Optimization, if parent is EK or SRK, use the handles from the context,
         * if not we need to create a parent handle.
         * However, If the caller requested the parent handle, create one and send it,
         * since the caller will destroy the returned parent handle.
         */
        if (!pIn->getParentHandle)
        {
            if (pIn->pObject->parentHandle == FAPI2_RH_EK)
            {
                if ((NULL == pCtx->primaryKeys.pEK) ||
                        ((pCtx->primaryKeys.pEK->authValueRequired) && (!pCtx->primaryKeys.pEK->authValueValid)) ||
                        (NULL == pCtx->primaryKeys.pEKHandle))
                {
                    rc = TSS2_FAPI_RC_NOT_PERMITTED;
                    DB_PRINT("%s.%d EK authValue not valid or TPM not provisioned with EK."
                            ", rc 0x%02x = %s\n",
                            __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                    goto exit;
                }

                pParentObject = pCtx->primaryKeys.pEK;
                pParentHandle = pCtx->primaryKeys.pEKHandle;
                destroyParentHandle = FALSE;
            }
            else if (pIn->pObject->parentHandle == FAPI2_RH_SRK)
            {
                if ( (NULL == pCtx->primaryKeys.pSRK) ||
                        ((pCtx->primaryKeys.pSRK->authValueRequired) && (!pCtx->primaryKeys.pSRK->authValueValid)) ||
                        (NULL == pCtx->primaryKeys.pSRKHandle))
                {
                    rc = TSS2_FAPI_RC_NOT_PERMITTED;
                    DB_PRINT("%s.%d SRK authValue not valid or TPM not provisioned with SRK."
                            ", rc 0x%02x = %s\n",
                            __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                    goto exit;
                }

                pParentObject = pCtx->primaryKeys.pSRK;
                pParentHandle = pCtx->primaryKeys.pSRKHandle;
                destroyParentHandle = FALSE;
            }
        }
        else
        {
            /*
             * Parent is not EK or SRK, but some other persistent/primary key.
             * Create a handle for the parent.
             * We will directly look up the object by persistent handle. If the
             * object is not found, it means it isnt in the context and its
             * authValue has not been set by the user, which will lead to failure
             * when we check for validity of the authValue.
             */
            rc = FAPI2_CONTEXT_lookupPrimaryObjectByHandle(pCtx,
                    pIn->pObject->parentHandle, &pParentObject);
            if (TSS2_RC_SUCCESS != rc)
            {
                DB_PRINT("%s.%d Could not find primaryObject. isAuthValue for parent"
                        "object set?"
                        ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            /*
             * Even if the object exists in the context, its authValue may not be set.
             * Verify that authValue is explicitly set.
             */
            if ((pParentObject->authValueRequired) && (!pParentObject->authValueValid))
            {
                rc = TSS2_FAPI_RC_NOT_PERMITTED;
                DB_PRINT("%s.%d authValue of primary parent is not valid."
                        ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            /*
             * Create handle for parent object.
             */
            createParentHandleIn.pObject = pParentObject;
            rc = FAPI2_UTILS_createHandle(pCtx, &createParentHandleIn,
                    &createParentHandleOut);
            if (TSS2_RC_SUCCESS != rc)
            {
                DB_PRINT("%s.%d Failed to create handle for parent object."
                        ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            pParentHandle = createParentHandleOut.pHandle;
        }
    }
    else if ((0 == pIn->pObject->parentHandle) && (pIn->pObject->parentName.size != 0))
    {
        /*
         * Parent handle must be 0 and parentName should not be an empty buffer.
         * If this is the case, we have an error in object creation.
         */

        /*
         * Find parent object from context
         */
        rc = FAPI2_CONTEXT_lookupObject(pCtx, &(pIn->pObject->parentName),
                &pParentObject);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to find parent object. Parent object must "
                    "be loaded in the context"
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if ((pParentObject->authValueRequired) && (!pParentObject->authValueValid))
        {
            rc = TSS2_FAPI_RC_NOT_PERMITTED;
            DB_PRINT("%s.%d authValue of parent object is not valid."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        /*
         * Load the parent object itself and get a handle to it.
         * We dont need the parents, parent handle.
         */
        loadParentIn.pObject = pParentObject;
        loadParentIn.getParentHandle = FALSE;
        rc = FAPI2_UTILS_loadObjectTreeEx(pCtx, &loadParentIn, &loadParentOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to load parent object"
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        pParentHandle = loadParentOut.pObjectHandle;

    }
    else
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Unexpected condition."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if(!pParentHandle || !pParentObject)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Unexpected: ParentHandle can not be NULL."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    
    /*
     * Create handle for this object.
     */
    createHandleIn.pParentHandle = pParentHandle;
    createHandleIn.pAuthParentHandle =
            &(pParentObject->authValue);
    createHandleIn.numPolicyTerms = pParentObject->numPolicyTerms;
    createHandleIn.pParentPolicy = pParentObject->objectPolicy;
    rc = FAPI2_UTILS_createHandle(pCtx, &createHandleIn,
            &createHandleOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to create handle for object."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->pObjectHandle = createHandleOut.pHandle;
    pOut->pParentObject = pParentObject;
    if (pIn->getParentHandle && !destroyParentHandle)
        pOut->pParentHandle = pParentHandle;

    rc = TSS2_RC_SUCCESS;
exit:
    if (pParentHandle && destroyParentHandle)
    {
        exit_rc1 = FAPI2_UTILS_destroyHandle(pCtx, &pParentHandle);
    }

    if (TSS2_RC_SUCCESS != rc)
    {
        if (pOut && pOut->pObjectHandle)
            exit_rc2 = FAPI2_UTILS_destroyHandle(pCtx, &(pOut->pObjectHandle));
    }

    if (pParentObject)
    {
        flushObjectIn.objName = pParentObject->objectName;
        exit_rc = FAPI2_CONTEXT_flushObject(pCtx, &flushObjectIn);
    }

    if (TSS2_RC_SUCCESS == rc)
    {
        if (TSS2_RC_SUCCESS != exit_rc1)
            rc = exit_rc1;
        else if (TSS2_RC_SUCCESS != exit_rc2)
            rc = exit_rc2;
        else
            rc = exit_rc;
    }

    return rc;
}

/*
 * Use this function to create a handle from a FAPI2_OBJECT.
 * If the FAPI2_OBJECT represents a persistent or NV object,
 * this function simply creates a new MOCTPM2_OBJECT handle,
 * verifies if the object exists on the TPM and also compares
 * the names.
 * If the FAPI2_OBJECT represents a non-persistent object, it
 * loads the object into the TPM and returns a new handle.
 * Once again the Name of the object is verified.
 * pParentObject MUST be provided for non-persistent objects.
 *
 * The caller of this function needs to explicitly choose the
 * parent for the object being loaded. This function will return
 * an error from the TPM if the parent provided is not appropriate.
 * An alternate to using this function is to use
 * FAPI2_UTILS_loadObjectTree(), which automatically figures out
 * the correct parent for an object and loads it, since the object
 * itself contains information about its parents, and this function
 * also supports loading object tree's.
 */
TSS2_RC FAPI2_UTILS_createHandle(
        FAPI2_CONTEXT *pCtx,
        UtilsCreateHandleIn *pIn,
        UtilsCreateHandleOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    TSS2_RC exit_rc1 = TSS2_RC_SUCCESS;
    MOCTPM2_OBJECT_HANDLE *pNewHandle = NULL;
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;
    ReadPublicIn readPublicIn = { 0 };
    ReadPublicOut readPublicOut = { 0 };
    NVReadPublicIn nvReadPublicIn = { 0 };
    NVReadPublicOut nvReadPublicOut = { 0 };
    LoadIn loadIn = { 0 };
    LoadOut loadOut = { 0 };
    LoadExternalIn loadExternalIn = { 0 };
    LoadExternalOut loadExternalOut = { 0 };

    if ((NULL == pIn) || (NULL == pIn->pObject) ||
            (NULL == pOut) || !pCtx ||
            (NULL != pOut->pHandle))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid input pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pIn->pAuthParentHandle)
        TPM2B_SIZE_CHECK(pIn->pAuthParentHandle,
                TPM2B_MAX_SIZE(pIn->pAuthParentHandle));
    /*
     * We only accept NV, non-persistent or persistent handles.
     * Non persistent handles have pObject->objectHandle == 0
     */
    if ((0 != pIn->pObject->objectHandle) &&
            (!IS_TPM2_PERSISTENT_HANDLE(pIn->pObject->objectHandle)) &&
            (!IS_TPM2_NV_HANDLE(pIn->pObject->objectHandle)))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid handle type supplied, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Persistent or NV objects, already reside in the TPM. Create a handle,
     * read the public area from the TPM and verify that the provided
     * FAPI2_OBJECT is correct for the handle being referred to.
     */
    if (IS_TPM2_PERSISTENT_HANDLE(pIn->pObject->objectHandle))
    {
        rc = SAPI2_HANDLES_createObjectHandle(pIn->pObject->objectHandle,
                &pIn->pObject->public.objectPublic.publicArea, &pNewHandle);

        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to create handle for persistent object"
                    ", rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        /*
         * Read public area with newly created handle. SAPI2_OBJECT_ReadPublic
         * will automatically verify the name in pNewHandle with the one
         * obtained from the TPM.
         */
        readPublicIn.pObjectHandle = pNewHandle;

        rc = SAPI2_OBJECT_ReadPublic(pCtx->pSapiCtx,
                &readPublicIn,
                &readPublicOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Unable to read public area of"
                    "persistent object."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }
    else if (IS_TPM2_NV_HANDLE(pIn->pObject->objectHandle))
    {
        rc = SAPI2_HANDLES_createNvHandle(pIn->pObject->objectHandle,
                        &pIn->pObject->public.nvPublic.nvPublic, &pNewHandle);

        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to create handle for NV object"
                    ", rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        /*
         * Read public area with newly created handle. SAPI2_NV_NVReadPublic
         * will automatically verify the name in pNewHandle with the one
         * obtained from the TPM.
         */
        nvReadPublicIn.pNvIndexHandle = pNewHandle;

        rc = SAPI2_NV_NVReadPublic(pCtx->pSapiCtx,
                &nvReadPublicIn,
                &nvReadPublicOut);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Unable to read public area of"
                    "NV object."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }
    else if (0 == pIn->pObject->objectHandle)
    {

        /*
         * Non-persistent external object. Use TPM2_LoadExternal to load the object
         * into the TPM and create a handle.
         */

        if (pIn->pObject->isExternal)
        {
            loadExternalIn.hierarchy = TPM2_RH_NULL;
            loadExternalIn.pInPublic = &pIn->pObject->public.objectPublic;
            loadExternalIn.pInSensitive = &pIn->pObject->private.sensitive;

            rc = SAPI2_OBJECT_LoadExternal(pCtx->pSapiCtx, &loadExternalIn,
                    &loadExternalOut);
            if (TSS2_RC_SUCCESS != rc)
            {
                DB_PRINT("%s.%d Failed to load external object"
                        ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            pNewHandle = loadExternalOut.pObjectHandle;
        }
        else
        {
            /*
             * Non-persistent TPM object. Use TPM2_Load to load the object into
             * the TPM and create a handle.
             */
            if ((NULL == pIn->pParentHandle) ||
                    (NULL == pIn->pAuthParentHandle))
            {
                rc = TSS2_SYS_RC_BAD_REFERENCE;
                DB_PRINT("%s.%d Parent handle/policy not provided,"
                        " rc 0x%02x = %s\n", __FUNCTION__,
                        __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            /*
             * All persistent and transient objects are expected to have
             * policies for authorization. However, if there is a situation
             * where we need to load objects without policies, we can use
             * hmac sessions.
             */
            if ((pIn->numPolicyTerms != 0) && pIn->pParentPolicy)
            {
                rc = FAPI2_UTILS_createPolicySessionAndExecutePolicy(
                        pCtx,
                        pIn->numPolicyTerms,
                        pIn->pParentPolicy,
                        NULL,
                        &pAuthSession
                );
                if (TSS2_RC_SUCCESS != rc)
                {
                    DB_PRINT("%s.%d Failed to start auth session"
                            ", rc 0x%02x = %s\n",
                            __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                    goto exit;
                }
            }
            else
            {
                rc = FAPI2_UTILS_startSession(pCtx, &pAuthSession);
                if (TSS2_RC_SUCCESS != rc)
                {
                    DB_PRINT("%s.%d Failed to start auth session"
                            ", rc 0x%02x = %s\n",
                            __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                    goto exit;
                }
            }

            loadIn.pInPrivate = &pIn->pObject->private.tpmPrivate;
            loadIn.pInPublic = &pIn->pObject->public.objectPublic;
            loadIn.pAuthSession = pAuthSession;
            loadIn.pAuthParentHandle = pIn->pAuthParentHandle;
            loadIn.pParentHandle = pIn->pParentHandle;

            rc = SAPI2_OBJECT_Load(pCtx->pSapiCtx, &loadIn, &loadOut);
            if (TSS2_RC_SUCCESS != rc)
            {
                DB_PRINT("%s.%d Failed to load object"
                        ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            pNewHandle = loadOut.pObjectHandle;
        }
    }
    else
    {
        DB_PRINT("%s.%d Unexpected scenario, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pOut->pHandle = pNewHandle;
    rc = TSS2_RC_SUCCESS;
exit:
    if (pAuthSession)
        exit_rc1 = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);

    if (TSS2_RC_SUCCESS != rc)
    {
        if (pNewHandle)
            exit_rc = FAPI2_UTILS_destroyHandle(pCtx, &pNewHandle);
    }

    if (TSS2_RC_SUCCESS == rc)
    {
        /* If there are multiple errors, return the first one encountered */
        if (TSS2_RC_SUCCESS != exit_rc1)
            rc = exit_rc1;
        else
            rc = exit_rc;
    }

    return rc;
}

TSS2_RC FAPI2_UTILS_destroyHandle(
        FAPI2_CONTEXT *pCtx,
        MOCTPM2_OBJECT_HANDLE **ppHandle
)
{
    FlushContextIn flushContextIn = { 0 };
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if ((NULL == ppHandle) || (NULL == *ppHandle) || !pCtx)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid input pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * We only accept session, NV, transient or persistent handles.
     */
    if ((!IS_TPM2_TRANSIENT_HANDLE((*ppHandle)->tpm2Handle)) &&
            (!IS_TPM2_PERSISTENT_HANDLE((*ppHandle)->tpm2Handle)) &&
            (!IS_TPM2_SESSION_HANDLE((*ppHandle)->tpm2Handle)) &&
            (!IS_TPM2_NV_HANDLE((*ppHandle)->tpm2Handle)) &&
            (!IS_TPM2_PERMANENT_HANDLE((*ppHandle)->tpm2Handle)))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid handle type supplied, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Use flush context to destroy the handle for sessions and
     * transient objects. This also removes the object/session
     * from TPM memory.
     */
    if (IS_TPM2_TRANSIENT_HANDLE((*ppHandle)->tpm2Handle) ||
            (IS_TPM2_SESSION_HANDLE((*ppHandle)->tpm2Handle)))
    {
        flushContextIn.ppObjectHandle = ppHandle;

        rc = SAPI2_CTX_MGMT_FlushContext(
                pCtx->pSapiCtx,
                &flushContextIn
        );

        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to flush object context,"
                    " rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }
    else if (IS_TPM2_PERSISTENT_HANDLE((*ppHandle)->tpm2Handle) ||
            IS_TPM2_NV_HANDLE((*ppHandle)->tpm2Handle) ||
            IS_TPM2_PERMANENT_HANDLE((*ppHandle)->tpm2Handle))
    {
        /*
         * If this is a persistent or NV handle, simply destroy the handle.
         * The object will still remain persistent in the TPM NV
         * and this just destroys the handle in memory.
         */

        rc = SAPI2_HANDLES_destroyHandle(ppHandle, TRUE);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to destroy persistent object handle,"
                    " rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }
    else
    {
        DB_PRINT("%s.%d Unexpected scenario, rc 0x%02x = %s\n", __FUNCTION__,
                        __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC FAPI2_UTILS_startPolicySession(
        FAPI2_CONTEXT *pCtx,
        MOCTPM2_OBJECT_HANDLE **ppSessionHandle,
        byteBoolean isTrial
)
{
    TPM2_SE savedSessionType = TPM2_SE_HMAC;
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if (!pCtx || !ppSessionHandle || (NULL != *ppSessionHandle))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid fapi context, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    savedSessionType = pCtx->sessionParams.sessionType;

    if (isTrial)
        pCtx->sessionParams.sessionType = TPM2_SE_TRIAL;
    else
        pCtx->sessionParams.sessionType = TPM2_SE_POLICY;

    rc = FAPI2_UTILS_startSession(pCtx, ppSessionHandle);

    pCtx->sessionParams.sessionType = savedSessionType;

    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to start policy session, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

/*
 * This function starts a session as setup in the
 * FAPI context and returns a session handle to the
 * caller
 */
TSS2_RC FAPI2_UTILS_startSession(
        FAPI2_CONTEXT *pCtx,
        MOCTPM2_OBJECT_HANDLE **ppSessionHandle
)
{
    StartAuthSessionIn startAuthSessionIn = { 0 };
    StartAuthSessionOut startAuthSessionOut = { 0 };
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    const BulkHashAlgo *pHashAlgOut = NULL;
    MSTATUS status = ERR_GENERAL;
    FAPI2_CONTEXT *pFapiCtx = pCtx;

    if (!pCtx || !ppSessionHandle || (NULL != *ppSessionHandle))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid fapi context, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = SAPI2_UTILS_getHashAlg(
            pFapiCtx->sessionParams.sessionAlg,
            &pHashAlgOut
    );
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to get hash algorithm"
                ", rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Set nonce size to maximum possible, which is the digest size
     * of the session algorithm.
     * See TPM Library Specification, Part 1, session nonce size.
     */
    startAuthSessionIn.nonceCaller.size = pHashAlgOut->digestSize;
    status = RANDOM_numberGenerator(g_pRandomContext,
            (ubyte *)&startAuthSessionIn.nonceCaller.buffer,
            startAuthSessionIn.nonceCaller.size);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to get nonce, rc 0x%02x = %s\n", __FUNCTION__,
        __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    startAuthSessionIn.sessionType = pFapiCtx->sessionParams.sessionType;
    startAuthSessionIn.symmetric = pFapiCtx->sessionParams.paramEnc;
    startAuthSessionIn.authHash = pFapiCtx->sessionParams.sessionAlg;

    if (pFapiCtx->primaryKeys.pEKHandle)
        startAuthSessionIn.pTpmKey = pFapiCtx->primaryKeys.pEKHandle;

    rc = SAPI2_SESSION_StartAuthSession(pFapiCtx->pSapiCtx,
            &startAuthSessionIn, &startAuthSessionOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to start session with TPM"
                ", rc 0x%02x = %s\n", __FUNCTION__,
        __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (!startAuthSessionOut.pSessionHandle)
    {
        rc = TSS2_SYS_RC_INVALID_SESSIONS;
        DB_PRINT("%s.%d Unable to get session handle from TPM"
                ", rc 0x%02x = %s\n", __FUNCTION__,
        __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /* Set session attributes */
    rc = SAPI2_SESSION_setSessionAttributes(
            startAuthSessionOut.pSessionHandle,
            pFapiCtx->sessionParams.sessionAttributes);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Unable to set session attributes"
                ", rc 0x%02x = %s\n", __FUNCTION__,
        __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    *ppSessionHandle = startAuthSessionOut.pSessionHandle;
    rc = TSS2_RC_SUCCESS;
exit:
    if (TSS2_RC_SUCCESS != rc)
    {
        if (startAuthSessionOut.pSessionHandle)
        {
            exit_rc = FAPI2_UTILS_closeSession(pCtx, &startAuthSessionOut.pSessionHandle);
        }
    }

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;

}

TSS2_RC FAPI2_UTILS_closeSession(
        FAPI2_CONTEXT *pCtx,
        MOCTPM2_OBJECT_HANDLE **ppSessionHandle
)
{
    return FAPI2_UTILS_destroyHandle(pCtx, ppSessionHandle);
}

TSS2_RC FAPI2_UTILS_createObject(
        FAPI2_CONTEXT *pCtx,
        UtilsCreateObjectIn *pIn,
        UtilsCreateObjectOut *pOut
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    FAPI2_OBJECT *pNewObject = NULL;
    ReadPublicIn readPublicIn = { 0 };
    ReadPublicOut readPublicOut = { 0 };
    NVReadPublicIn nvReadPublicIn = { 0 };
    NVReadPublicOut nvReadPublicOut = { 0 };
    TPM2B_PUBLIC *pPublic = NULL;
    TPM2B_NV_PUBLIC *pNvPublic = NULL;
    ubyte4 i = 0;

    if (!pIn || !pOut || (NULL != pOut->pObject) ||
            ((pIn->numPolicyTerms != 0) && (!pIn->pObjectPolicy)) ||
            ((pIn->pObjectPolicy) && (pIn->numPolicyTerms == 0)))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid inputs, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ((pIn->tpm2Handle != 0) &&
            (!IS_TPM2_PERSISTENT_HANDLE(pIn->tpm2Handle)) &&
            (!IS_TPM2_NV_HANDLE(pIn->tpm2Handle)))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid handle type, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pIn->numPolicyTerms > FAPI2_MAX_POLICY_CHAIN_LENGTH)
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Too many policy terms, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Every non-persistent object must have a public and private area.
     * Private areas are not returned by the TPM for only primary objects.
     * For non persistent objects, tpm2Handle must be 0. Either the TPM
     * generated private area pPrivate or externally generated private/
     * sensitive area may be provided. If pSensitive is provided, the object
     * is marked as an externally generated object. If both are pPrivate and
     * pSensitive are provided, the TPM generated area is used and the object
     * is marked as a TPM object. If neither are provided, the object will
     * be marked as an external object and can be used for public operations.
     */
    if ((0 == pIn->tpm2Handle) && (NULL == pIn->pPublic))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d No public area specified for non persistent object"
                ", rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * parentHandle must be 0 or a persistent handle
     */
    if ((!IS_TPM2_PERSISTENT_HANDLE(pIn->parentHandle)) &&
            (pIn->parentHandle != 0) )
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d parentHandle is not a valid persistent handle, TPM2_RH_NULL is not 0"
                ", rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pIn->pParentName)
    {
        TPM2B_SIZE_CHECK(pIn->pParentName, TPM2B_MAX_SIZE(pIn->pParentName));
    }

    if (OK != DIGI_CALLOC((void **)&pNewObject, 1, sizeof(FAPI2_OBJECT)))
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        DB_PRINT("%s.%d Failed memory allocation"
                ", rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pPublic = pIn->pPublic;
    pNvPublic = pIn->pNvPublic;
    pNewObject->isExternal = TRUE;
    pNewObject->objectHandle = pIn->tpm2Handle;

    if (pIn->pPublic)
        TPM2B_SIZE_CHECK(pIn->pPublic, TPM2B_MAX_SIZE(pIn->pPublic));

    if (pIn->pAuthValue)
    {
        TPM2B_SIZE_CHECK(pIn->pAuthValue, TPM2B_MAX_SIZE(pIn->pAuthValue));
        pNewObject->authValue = *(pIn->pAuthValue);
        pNewObject->authValueValid = TRUE;
    }

    if (pIn->pPrivate)
    {
        TPM2B_SIZE_CHECK(pIn->pPrivate, TPM2B_MAX_SIZE(pIn->pPrivate));
        pNewObject->private.tpmPrivate = *(pIn->pPrivate);
        pNewObject->isExternal = FALSE;
    }
    else if (pIn->pSensitive)
    {
        TPM2B_SIZE_CHECK(pIn->pSensitive, TPM2B_MAX_SIZE(pIn->pSensitive));
        pNewObject->private.sensitive = *(pIn->pSensitive);
    }

    if (pIn->pCreationData)
    {
        TPM2B_SIZE_CHECK(pIn->pCreationData, TPM2B_MAX_SIZE(pIn->pCreationData));
        pNewObject->creationData = *(pIn->pCreationData);
    }

    if (pIn->pCreationHash)
    {
        TPM2B_SIZE_CHECK(pIn->pCreationHash, TPM2B_MAX_SIZE(pIn->pCreationHash));
        pNewObject->creationHash = *(pIn->pCreationHash);
    }

    if (pIn->pCreationTicket)
        pNewObject->creationTicket = *(pIn->pCreationTicket);

    /*
     * Non-persistent object.
     */
    if (0 == pIn->tpm2Handle)
    {
        pNewObject->public.objectPublic = *(pPublic);
        rc = SAPI2_UTILS_getObjectName(
                (TPM2_HT_TRANSIENT << TPM2_HR_SHIFT), &pPublic->publicArea,
                &(pNewObject->objectName));
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Unable to get name of persistent object"
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        /*
         * Only store parentHandle and parentName for non-persistent AND
         * non-external(tpm created) objects
         */
        if (FALSE == pNewObject->isExternal)
        {
            if (IS_TPM2_PERSISTENT_HANDLE(pIn->parentHandle))
            {
                pNewObject->parentHandle = pIn->parentHandle;
                pNewObject->parentName.size = 0;
            }
            else if (pIn->parentHandle == 0)
            {
                /*
                 * if parentHandle is 0 and parentName is present, then the objects
                 * parent is a non-persistent object, so record its name.
                 */
                if (pIn->pParentName && (pIn->pParentName->size != 0))
                {
                    pNewObject->parentHandle = 0;
                    pNewObject->parentName = *(pIn->pParentName);
                }
                else
                {
                    pNewObject->parentHandle = FAPI2_RH_SRK;
                    pNewObject->parentName.size = 0;
                }
            }
            else
            {
                /*
                 * This will occur if the object is determined to be not external but
                 * parentHandle is set to TPM2_RH_NULL.
                 */
                rc = TSS2_SYS_RC_BAD_VALUE;
                DB_PRINT("%s.%d parentHandle is not a valid persistent handle, TPM2_RH_NULL"
                        "and  is not 0"
                        ", rc 0x%02x = %s\n", __FUNCTION__,
                        __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }
        }
    }
    else if (IS_TPM2_PERSISTENT_HANDLE(pIn->tpm2Handle))
    {
        /*
         * Persistent/primary/NV objects will not contain a private area
         * in the FAPI2_OBJECT, since they are in the TPM. if the public
         * area is not provided in the input parameters, the public
         * area will be read from the TPM.
         */
        if ((pIn->tpm2Handle < TPM2_PERSISTENT_FIRST) ||
                (pIn->tpm2Handle > TPM2_PERSISTENT_LAST) ||
                (NULL != pIn->pPrivate && 0 != pIn->pPrivate->size))
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid persistent handle specified."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        /*
         * Get public area from the TPM using TPM2_ReadPublic
         */
        if (NULL == pIn->pPublic)
        {
            /*
             * Need context in this case to read the public area from the
             * TPM.
             */
            if (!pCtx)
            {
                rc = TSS2_SYS_RC_BAD_REFERENCE;
                DB_PRINT("%s.%d Invalid context, and no public area provided."
                        "Cannot create object."
                        ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }
            readPublicIn.pObjectHandle = NULL;
            readPublicIn.objectHandle = pIn->tpm2Handle;

            rc = SAPI2_OBJECT_ReadPublic(pCtx->pSapiCtx,
                    &readPublicIn,
                    &readPublicOut);
            if (TSS2_RC_SUCCESS != rc)
            {
                if (!(pCtx->provision && (0x18b == rc)))
                {
                    DB_PRINT("%s.%d Unable to read public area of"
                            " persistent object."
                            ", rc 0x%02x = %s\n",
                            __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                }
                goto exit;
            }

            pPublic = &readPublicOut.outPublic;
            pNewObject->objectName = readPublicOut.name;
        }
        else
        {
            rc = SAPI2_UTILS_getObjectName(
                    pIn->tpm2Handle, &pPublic->publicArea,
                    &(pNewObject->objectName));
            if (TSS2_RC_SUCCESS != rc)
            {
                DB_PRINT("%s.%d Unable to get name of persistent object"
                        ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }
        }
        pNewObject->isExternal = FALSE;
        pNewObject->public.objectPublic = *(pPublic);
    }
    else if (IS_TPM2_NV_HANDLE(pIn->tpm2Handle))
    {
        if ((pIn->tpm2Handle < TPM2_NV_INDEX_FIRST) ||
                ((pIn->tpm2Handle > TPM2_NV_INDEX_LAST)) ||
                (pIn->pPrivate != NULL))
        {
            rc = TSS2_SYS_RC_BAD_VALUE;
            DB_PRINT("%s.%d Invalid NV handle specified."
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        /*
         * Get public area from the TPM using TPM2_NV_ReadPublic
         */
        if (NULL == pIn->pPublic)
        {
            /*
             * Need context in this case to read the public area from the
             * TPM.
             */
            if (!pCtx)
            {
                rc = TSS2_SYS_RC_BAD_REFERENCE;
                DB_PRINT("%s.%d Invalid context, and no public area provided."
                        "Cannot create object."
                        ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            nvReadPublicIn.pNvIndexHandle = NULL;
            nvReadPublicIn.nvIndex = pIn->tpm2Handle;

            rc = SAPI2_NV_NVReadPublic(pCtx->pSapiCtx,
                    &nvReadPublicIn,
                    &nvReadPublicOut);
            if (TSS2_RC_SUCCESS != rc)
            {
                DB_PRINT("%s.%d Unable to read public area of"
                        "NV object."
                        ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }

            pNvPublic = &nvReadPublicOut.nvPublic;
            pNewObject->objectName = nvReadPublicOut.nvName;
        }
        else
        {
            rc = SAPI2_UTILS_getNvName(
                    pIn->tpm2Handle, &pNvPublic->nvPublic,
                    &(pNewObject->objectName));
            if (TSS2_RC_SUCCESS != rc)
            {
                DB_PRINT("%s.%d Unable to get name of persistent object"
                        ", rc 0x%02x = %s\n",
                        __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
                goto exit;
            }
        }
        pNewObject->isExternal = FALSE;
        pNewObject->public.nvPublic = *(pNvPublic);
    }
    else
    {
        DB_PRINT("%s.%d Unexpected scenario, rc 0x%02x = %s\n", __FUNCTION__,
                        __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    /*
     * Copy input policy if provided.
     */
    pNewObject->authValueRequired = FALSE;
    if (pIn->numPolicyTerms)
    {
        if (1 == pIn->numPolicyTerms &&
            FAPI2_POLICY_NO_DEFAULT == pIn->pObjectPolicy[0].policyType)
        {
            pNewObject->numPolicyTerms = 0;
        }
        else
        {
            pNewObject->numPolicyTerms = pIn->numPolicyTerms;
            for (i = 0; i < pIn->numPolicyTerms; i++)
            {
                if (pIn->pObjectPolicy[i].policyType == FAPI2_POLICY_AUTH_VALUE)
                    pNewObject->authValueRequired = TRUE;

                pNewObject->objectPolicy[i] = pIn->pObjectPolicy[i];
            }
        }
    }
    else
    {
#if defined(__RTOS_WIN32__) && !defined(__USE_TPM_EMULATOR__)
        pNewObject->numPolicyTerms = 0;
#else
        pNewObject->numPolicyTerms = 1;
        pNewObject->objectPolicy[0].policyType = FAPI2_POLICY_AUTH_VALUE;
        pNewObject->authValueRequired = TRUE;
#endif
    }

    pOut->pObject = pNewObject;

    rc = TSS2_RC_SUCCESS;
exit:
    if (TSS2_RC_SUCCESS != rc)
    {
        if (pNewObject)
            shredMemory((ubyte**)&pNewObject, sizeof(FAPI2_OBJECT),
                    TRUE);
    }
    return rc;
}

TSS2_RC FAPI2_UTILS_destroyObject(
        FAPI2_OBJECT **ppObject
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if (!ppObject || (!*ppObject))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid inputs, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (OK != shredMemory((ubyte **)ppObject,
            sizeof(FAPI2_OBJECT), TRUE))
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        DB_PRINT("%s.%d Failed to shredMemory, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

/*
 * This function sets the authValue for the object. If pAuth
 * is NULL, the authValue is cleared.
 */
TSS2_RC FAPI2_UTILS_setObjectAuth(
        FAPI2_OBJECT *pObject,
        TPM2B_AUTH *pAuth
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if (!pObject)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid object, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pAuth)
    {
        if (pAuth->size != 0)
        {
            TPM2B_SIZE_CHECK(pAuth, TPM2B_MAX_SIZE(pAuth));
            pObject->authValue = *(pAuth);
            pObject->authValueValid = TRUE;
        }
        else
        {
            DIGI_MEMSET((ubyte *)&pObject->authValue, 0, sizeof(pObject->authValue));
            pObject->authValueValid = TRUE;
        }
    }
    else
    {
        DIGI_MEMSET((ubyte *)&pObject->authValue, 0, sizeof(pObject->authValue));
        pObject->authValueValid = FALSE;
    }

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

/*
 * This function can be used to change the authValue of a FAPI2_OBJECT.
 * This must be TPM created object and not external. This API cannot be
 * used to change the authValue of a persistent/primary object or NV index.
 * The authValue must be set and valid, so an application must call
 * FAPI2_UTILS_setObjectAuth if the object was serialized and deserialized.
 */
TSS2_RC FAPI2_UTILS_changeObjectAuth(
        FAPI2_CONTEXT *pCtx,
        UtilsChangeObjectAuthIn *pIn
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    TSS2_RC exit_rc1 = TSS2_RC_SUCCESS;
    TSS2_RC exit_rc2 = TSS2_RC_SUCCESS;
    ObjectChangeAuthIn changeAuthIn = { 0 };
    ObjectChangeAuthOut changeAuthOut = { 0 };
    MOCTPM2_OBJECT_HANDLE *pAuthSession = NULL;
    MOCTPM2_OBJECT_HANDLE *pObjectHandle = NULL;
    MOCTPM2_OBJECT_HANDLE *pParentHandle = NULL;
    UtilsLoadObjectTreeExIn loadObjectTreeIn = { 0 };
    UtilsLoadObjectTreeExOut loadObjectTreeOut = { 0 };

    if (!pCtx || !pIn || !pIn->pObject || !pIn->pNewAuth)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(pIn->pNewAuth, pCtx->nameAlgSize);

    if (((pIn->pObject->authValueRequired) && (!pIn->pObject->authValueValid)) ||
            (pIn->pObject->objectHandle != 0) ||
            (pIn->pObject->isExternal))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid authValue or object handle, or external key"
                ", rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    loadObjectTreeIn.pObject = pIn->pObject;
    loadObjectTreeIn.getParentHandle = TRUE;

    rc = FAPI2_UTILS_loadObjectTreeEx(pCtx, &loadObjectTreeIn, &loadObjectTreeOut);
    if ((TSS2_RC_SUCCESS != rc) || (!loadObjectTreeOut.pObjectHandle) ||
            ((!loadObjectTreeOut.pParentHandle)))
    {
        DB_PRINT("%s.%d Failed to create handle for object or parent."
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pObjectHandle = loadObjectTreeOut.pObjectHandle;
    pParentHandle = loadObjectTreeOut.pParentHandle;

    rc = FAPI2_UTILS_startSession(pCtx, &pAuthSession);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to start auth session"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    changeAuthIn.pAuthObjectHandle = &pIn->pObject->authValue;
    changeAuthIn.pAuthSession = pAuthSession;
    changeAuthIn.pNewAuth = pIn->pNewAuth;
    changeAuthIn.pParentHandle = pParentHandle;
    changeAuthIn.pObjectHandle = pObjectHandle;

    rc = SAPI2_OBJECT_ObjectChangeAuth(pCtx->pSapiCtx, &changeAuthIn,
            &changeAuthOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to change object auth"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    DIGI_MEMSET((ubyte *)&(pIn->pObject->private.tpmPrivate), 0,
            sizeof(pIn->pObject->private.tpmPrivate));

    DIGI_MEMSET((ubyte *)&(pIn->pObject->authValue), 0,
                sizeof(pIn->pObject->authValue));

    pIn->pObject->private.tpmPrivate = changeAuthOut.outPrivate;
    pIn->pObject->authValue = *(pIn->pNewAuth);

    rc = TSS2_RC_SUCCESS;
exit:
    if (pAuthSession)
        exit_rc1 = FAPI2_UTILS_closeSession(pCtx,
                &pAuthSession);

    if (pParentHandle)
        exit_rc2 = FAPI2_UTILS_destroyHandle(pCtx, &pParentHandle);

    if (pObjectHandle)
        exit_rc = FAPI2_UTILS_destroyHandle(pCtx, &pObjectHandle);

    if (TSS2_RC_SUCCESS == rc)
    {
        /* If there are multiple errors, return the first one encountered */
        if (TSS2_RC_SUCCESS != exit_rc1)
            rc = exit_rc1;
        else if (TSS2_RC_SUCCESS != exit_rc2)
            rc = exit_rc2;
        else
            rc = exit_rc;
    }

    return rc;
}

/*
 * This function takes in a FAPI2_OBJECT, serializes in into a buffer
 * and returns the buffer and length of the serialized buffer. It also
 * destroys and free's the memory used by the FAPI2_OBJECT, if the
 * destroyObject flag is true.
 * If the buffer is written to a file, an application can use
 * DIGI_FREE to free the serialized buffer.
 */
TSS2_RC FAPI2_UTILS_serialize(
        FAPI2_OBJECT **ppObject,
        byteBoolean destroyObject,
        FAPI2B_OBJECT *pSerializedObject
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    ubyte *pSerialized = NULL;
    MSTATUS status = ERR_GENERAL;
    FAPI2_OBJECT *pObject = NULL;
    ubyte4 serializedSize = 0;
    ubyte4 i = 0;
    ubyte2 numPolicyTerms;
    PolicyAuthNode noDefaultPolicy = {0};

    if (!ppObject || (NULL == *ppObject) || (NULL == pSerializedObject))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pObject = *ppObject;

    /*
     * Allocate buffer equivalent to sizeof(FAPI2_OBJECT). The serialized buffer
     * cannot be larger that that, since FAPI2_OBJECT contains no pointers.
     */
    if (OK != DIGI_CALLOC((void **)&pSerialized, 1, sizeof(FAPI2_OBJECT)))
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        DB_PRINT("%s.%d Failed memory allocation, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPM2_HANDLE, TAP_SD_IN,
            (ubyte*)(&pObject->objectHandle), sizeof(pObject->objectHandle),
            pSerialized, sizeof(FAPI2_OBJECT), &serializedSize);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to serialize objectHandle, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    status = SAPI2_SERIALIZE_serialize(SAPI2_ST_UBYTE2, TAP_SD_IN,
            (ubyte*)(&pObject->isExternal), sizeof(pObject->isExternal),
            pSerialized, sizeof(FAPI2_OBJECT), &serializedSize);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to serialize isExternal, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pObject->isExternal)
    {
        status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPM2B_SENSITIVE, TAP_SD_IN,
                (ubyte*)(&pObject->private.sensitive),
                sizeof(pObject->private.sensitive),
                pSerialized, sizeof(FAPI2_OBJECT), &serializedSize);
        if (OK != status)
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("%s.%d Failed to serialize sensitive Area, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }
    else
    {
        /*
         * Store parentHandle and parentName for non-persistent, tpm created objects
         * only.
         */
        status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPM2_HANDLE, TAP_SD_IN,
                (ubyte*)(&pObject->parentHandle), sizeof(pObject->parentHandle),
                pSerialized, sizeof(FAPI2_OBJECT), &serializedSize);
        if (OK != status)
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("%s.%d Failed to serialize parentHandle, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        /*
         * parentName is only used if parentHandle is 0.
         */
        if (0 == pObject->parentHandle)
        {
            status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPM2B_NAME, TAP_SD_IN,
                    (ubyte*)(&pObject->parentName), sizeof(pObject->parentName),
                    pSerialized, sizeof(FAPI2_OBJECT), &serializedSize);
            if (OK != status)
            {
                rc = TSS2_SYS_RC_GENERAL_FAILURE;
                DB_PRINT("%s.%d Failed to serialize parentName, rc 0x%02x = %s\n", __FUNCTION__,
                        __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }
        }

        status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPM2B_PRIVATE, TAP_SD_IN,
                (ubyte*)(&pObject->private.tpmPrivate),
                sizeof(pObject->private.tpmPrivate),
                pSerialized, sizeof(FAPI2_OBJECT), &serializedSize);
        if (OK != status)
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("%s.%d Failed to serialize private Area, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    if (IS_TPM2_NV_HANDLE(pObject->objectHandle))
    {
        status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPM2B_NV_PUBLIC, TAP_SD_IN,
                (ubyte*)(&pObject->public.nvPublic), sizeof(pObject->public.nvPublic),
                pSerialized, sizeof(FAPI2_OBJECT), &serializedSize);
        if (OK != status)
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("%s.%d Failed to serialize nv public Area, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }
    else
    {
        status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPM2B_PUBLIC, TAP_SD_IN,
                (ubyte*)(&pObject->public.objectPublic), sizeof(pObject->public.objectPublic),
                pSerialized, sizeof(FAPI2_OBJECT), &serializedSize);
        if (OK != status)
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("%s.%d Failed to serialize public Area, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPM2B_CREATION_DATA, TAP_SD_IN,
            (ubyte*)(&pObject->creationData), sizeof(pObject->creationData),
            pSerialized, sizeof(FAPI2_OBJECT), &serializedSize);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to serialize creation data, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPM2B_DATA, TAP_SD_IN,
            (ubyte*)(&pObject->creationHash), sizeof(pObject->creationHash),
            pSerialized, sizeof(FAPI2_OBJECT), &serializedSize);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to serialize creation hash, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPMT_TK_CREATION, TAP_SD_IN,
            (ubyte*)(&pObject->creationTicket), sizeof(pObject->creationTicket),
            pSerialized, sizeof(FAPI2_OBJECT), &serializedSize);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to serialize creation ticket, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (0 == pObject->numPolicyTerms)
    {
        numPolicyTerms = 1;
        noDefaultPolicy.policyType = FAPI2_POLICY_NO_DEFAULT;

        status = TAP_SERIALIZE_serialize(&TAP_SHADOW_ubyte2, TAP_SD_IN,
                (ubyte *)&(numPolicyTerms), sizeof(numPolicyTerms),
                pSerialized, sizeof(FAPI2_OBJECT), &serializedSize);
        if (OK != status)
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("%s.%d Failed to serialize no default numPolicyTerms, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        status = TAP_SERIALIZE_serialize(&TPM2_SHADOW_POLICY_AUTH_NODE, TAP_SD_IN,
                (ubyte *)&(noDefaultPolicy), sizeof(PolicyAuthNode),
                pSerialized, sizeof(FAPI2_OBJECT), &serializedSize);
        if (OK != status)
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("%s.%d Failed to serialize no default policy auth node %d, status = %d\n", __FUNCTION__,
                    __LINE__, i, status);
            goto exit;
        }
    }
    else
    {
        status = TAP_SERIALIZE_serialize(&TAP_SHADOW_ubyte2, TAP_SD_IN,
                (ubyte *)&(pObject->numPolicyTerms), sizeof(pObject->numPolicyTerms),
                pSerialized, sizeof(FAPI2_OBJECT), &serializedSize);
        if (OK != status)
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("%s.%d Failed to serialize numPolicyTerms, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        for (i = 0; i < pObject->numPolicyTerms; i++)
        {
            status = TAP_SERIALIZE_serialize(&TPM2_SHADOW_POLICY_AUTH_NODE, TAP_SD_IN,
                    (ubyte *)&(pObject->objectPolicy[i]), sizeof(PolicyAuthNode),
                    pSerialized, sizeof(FAPI2_OBJECT), &serializedSize);
            if (OK != status)
            {
                rc = TSS2_SYS_RC_GENERAL_FAILURE;
                DB_PRINT("%s.%d Failed to serialize policy auth node %d, status = %d\n", __FUNCTION__,
                        __LINE__, i, status);
                goto exit;
            }
        }
    }

    status = TAP_SERIALIZE_serialize(&TAP_SHADOW_ubyte, TAP_SD_IN,
            (ubyte *)&(pObject->authValueRequired), sizeof(ubyte),
            pSerialized, sizeof(FAPI2_OBJECT), &serializedSize);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to serialize authValueRequired flag, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (destroyObject)
    {
        rc = FAPI2_UTILS_destroyObject(ppObject);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to destroy key object, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    if (serializedSize > sizeof(pSerializedObject->buffer))
    {
        rc = TSS2_SYS_RC_INSUFFICIENT_BUFFER;
        DB_PRINT("%s.%d FAPI2B_OBJECT not big enough, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    DIGI_MEMCPY(pSerializedObject->buffer, pSerialized, serializedSize);
    pSerializedObject->size = serializedSize;

    rc = TSS2_RC_SUCCESS;
exit:
    if (pSerialized)
        shredMemory(&pSerialized, sizeof(FAPI2_OBJECT), TRUE);

    return rc;
}

TSS2_RC FAPI2_UTILS_deserialize(
        FAPI2B_OBJECT *pSerializedObject,
        FAPI2_OBJECT **ppObject
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TPM2_HANDLE objectHandle = TPM2_RH_NULL;
    TPM2_HANDLE parentHandle = 0;
    TPM2B_NAME parentName = { 0 };
    ubyte2 isExternal = FALSE;
    TPM2B_PRIVATE private = { 0 };
    TPM2B_SENSITIVE sensitive = { 0 };
    TPM2B_PUBLIC objectPublic = { 0 };
    TPM2B_NV_PUBLIC nvPublic = { 0 };
    TPM2B_CREATION_DATA creationData = { 0 };
    TPM2B_DIGEST creationHash = { 0 };
    TPMT_TK_CREATION creationTicket = { 0 };
    MSTATUS status = ERR_GENERAL;
    ubyte4 serializedSize = 0;
    UtilsCreateObjectIn createObjectIn = { 0 };
    UtilsCreateObjectOut createObjectOut = { 0 };
    ubyte *pBuffer = NULL;
    ubyte4 len = 0;
    ubyte2 numPolicyTerms = 0;
    PolicyAuthNode objectPolicy[FAPI2_MAX_POLICY_CHAIN_LENGTH] = { 0 };
    byteBoolean authValueRequired = FALSE;
    ubyte4 i = 0;

    if (!pSerializedObject || !ppObject || (NULL != *ppObject))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    TPM2B_SIZE_CHECK(pSerializedObject, TPM2B_MAX_SIZE(pSerializedObject));

    pBuffer = pSerializedObject->buffer;
    len = pSerializedObject->size;

    status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPM2_HANDLE, TAP_SD_OUT,
            pBuffer, len,
            (ubyte*)(&objectHandle), sizeof(objectHandle), &serializedSize);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to de-serialize objectHandle, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    status = SAPI2_SERIALIZE_serialize(SAPI2_ST_UBYTE2, TAP_SD_OUT,
            pBuffer, len,
            (ubyte*)(&isExternal), sizeof(isExternal), &serializedSize);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to de-serialize isExternal, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (isExternal)
    {
        status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPM2B_SENSITIVE, TAP_SD_OUT,
                pBuffer, len,
                (ubyte*)(&sensitive), sizeof(sensitive), &serializedSize);
        if (OK != status)
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("%s.%d Failed to de-serialize sensitive Area, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }
    else
    {
        /*
         * parentHandle and parentName are only serialized for non-persistent,
         * tpm created objects.
         */
        status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPM2_HANDLE, TAP_SD_OUT,
                pBuffer, len,
                (ubyte*)(&parentHandle), sizeof(parentHandle), &serializedSize);
        if (OK != status)
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("%s.%d Failed to de-serialize parentHandle, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        if (0 == parentHandle)
        {
            status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPM2B_NAME, TAP_SD_OUT,
                    pBuffer, len,
                    (ubyte*)(&parentName), sizeof(parentName), &serializedSize);
            if (OK != status)
            {
                rc = TSS2_SYS_RC_GENERAL_FAILURE;
                DB_PRINT("%s.%d Failed to de-serialize parentName, rc 0x%02x = %s\n", __FUNCTION__,
                        __LINE__, rc, tss2_err_string(rc));
                goto exit;
            }
        }

        status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPM2B_PRIVATE, TAP_SD_OUT,
                pBuffer, len,
                (ubyte*)(&private), sizeof(private), &serializedSize);
        if (OK != status)
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("%s.%d Failed to de-serialize private Area, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    if (IS_TPM2_NV_HANDLE(objectHandle))
    {
        status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPM2B_NV_PUBLIC, TAP_SD_OUT,
                pBuffer, len,
                (ubyte*)(&nvPublic), sizeof(nvPublic), &serializedSize);
        if (OK != status)
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("%s.%d Failed to de-serialize nv public Area, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }
    else
    {
        status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPM2B_PUBLIC, TAP_SD_OUT,
                pBuffer, len,
                (ubyte*)(&objectPublic), sizeof(objectPublic), &serializedSize);
        if (OK != status)
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("%s.%d Failed to de-serialize public Area, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPM2B_CREATION_DATA, TAP_SD_OUT,
            pBuffer, len,
            (ubyte*)(&creationData), sizeof(creationData), &serializedSize);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to de-serialize creation data, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPM2B_DATA, TAP_SD_OUT,
            pBuffer, len,
            (ubyte*)(&creationHash), sizeof(creationHash), &serializedSize);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to de-serialize creation hash, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPMT_TK_CREATION, TAP_SD_OUT,
            pBuffer, len,
            (ubyte*)(&creationTicket), sizeof(creationTicket), &serializedSize);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to de-serialize creation ticket, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    status = TAP_SERIALIZE_serialize(&TAP_SHADOW_ubyte2, TAP_SD_OUT,
            pBuffer, len,
            (ubyte *)(&numPolicyTerms), sizeof(numPolicyTerms), &serializedSize);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to de-serialize numPolicyTerms, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    for (i = 0; i < numPolicyTerms; i++)
    {
        status = TAP_SERIALIZE_serialize(&TPM2_SHADOW_POLICY_AUTH_NODE, TAP_SD_OUT,
                pBuffer, len,
                (ubyte *)(&objectPolicy[i]), sizeof(PolicyAuthNode), &serializedSize);
        if (OK != status)
        {
            rc = TSS2_SYS_RC_GENERAL_FAILURE;
            DB_PRINT("%s.%d Failed to de-serialize object policy %d, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, i, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    status = TAP_SERIALIZE_serialize(&TAP_SHADOW_ubyte, TAP_SD_OUT,
            pBuffer, len,
            (ubyte *)(&authValueRequired), sizeof(authValueRequired), &serializedSize);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to de-serialize authValue required flag rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    createObjectIn.tpm2Handle = objectHandle;
    createObjectIn.parentHandle = parentHandle;
    createObjectIn.pParentName = &parentName;
    if (isExternal)
        createObjectIn.pSensitive = &sensitive;
    else
        createObjectIn.pPrivate = &private;
    createObjectIn.pPublic = &objectPublic;
    createObjectIn.pNvPublic = &nvPublic;
    createObjectIn.pCreationData = &creationData;
    createObjectIn.pCreationHash = &creationHash;
    createObjectIn.pCreationTicket = &creationTicket;
    createObjectIn.numPolicyTerms = numPolicyTerms;
    if (numPolicyTerms > 0)
        createObjectIn.pObjectPolicy = objectPolicy;

    rc = FAPI2_UTILS_createObject(NULL, &createObjectIn, &createObjectOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to create object, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    *ppObject = createObjectOut.pObject;

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC FAPI2_UTILS_createPolicySessionAndExecutePolicy(
        FAPI2_CONTEXT *pCtx,
        ubyte2 numPolicyTerms,
        PolicyAuthNode *pPolicyToExecute,
        TPM2B_DIGEST *pPolicyDigestOut,
        MOCTPM2_OBJECT_HANDLE **ppSessionHandle
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    TSS2_RC exit_rc = TSS2_RC_SUCCESS;
    EaExecutePolicyIn eaExecutePolicyIn = { 0 };
    EaExecutePolicyOut eaExecutePolicyOut = { 0 };

    if (!pCtx || (0 == numPolicyTerms) || !pPolicyToExecute)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    eaExecutePolicyIn.numPolicyTerms = numPolicyTerms;
    eaExecutePolicyIn.pObjectPolicy = pPolicyToExecute;

    if (ppSessionHandle)
    {
        rc = FAPI2_UTILS_startPolicySession(pCtx, ppSessionHandle, FALSE);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to start auth session"
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        eaExecutePolicyIn.pSession = *ppSessionHandle;
    }

    rc = FAPI2_EA_executePolicy(pCtx, &eaExecutePolicyIn, &eaExecutePolicyOut);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to start auth session"
                ", rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pPolicyDigestOut)
        *pPolicyDigestOut = eaExecutePolicyOut.policyDigest;

    rc = TSS2_RC_SUCCESS;
exit:
    if (TSS2_RC_SUCCESS != rc)
        exit_rc = FAPI2_UTILS_closeSession(pCtx, ppSessionHandle);

    if (TSS2_RC_SUCCESS == rc)
        rc = exit_rc;

    return rc;
}

TSS2_RC FAPI2_UTILS_fillPolicyDigest(
        FAPI2_CONTEXT *pCtx,
        ubyte2 numPolicyTerms,
        PolicyAuthNode *pPolicy,
        TPM2B_DIGEST *pPolicyDigest
)
{
    return FAPI2_UTILS_createPolicySessionAndExecutePolicy(
            pCtx, numPolicyTerms, pPolicy, pPolicyDigest, NULL
            );
}

TSS2_RC FAPI2_UTILS_getObjectAuthSession(
        FAPI2_CONTEXT *pCtx,
        FAPI2_OBJECT *pObject,
        MOCTPM2_OBJECT_HANDLE **ppSessionHandle
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if (!pCtx || !pObject || !ppSessionHandle || *ppSessionHandle)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointer inputs, rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (pObject->numPolicyTerms != 0)
    {
        rc = FAPI2_UTILS_createPolicySessionAndExecutePolicy(
                pCtx,
                pObject->numPolicyTerms,
                pObject->objectPolicy,
                NULL,
                ppSessionHandle
        );
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to start auth session"
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }
    else
    {
        rc = FAPI2_UTILS_startSession(pCtx, ppSessionHandle);
        if (TSS2_RC_SUCCESS != rc)
        {
            DB_PRINT("%s.%d Failed to start auth session"
                    ", rc 0x%02x = %s\n",
                    __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}


TSS2_RC FAPI2_UTILS_serialize_Duplicate(
        FAPI2_DuplicateOut *pDuplicate,
        FAPI2B_DUPLICATE *pSerializedDup
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    MSTATUS status = ERR_GENERAL;
    ubyte4 serializedSize = 0;

    if ((NULL == pDuplicate)  || (NULL == pSerializedDup))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }



    status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPM2_FAPI2_DUPLICATEOUT, TAP_SD_IN,
            (ubyte*)pDuplicate, sizeof(FAPI2_DuplicateOut),
            pSerializedDup->buffer, sizeof(FAPI2_DuplicateOut), &serializedSize);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to serialize objectHandle, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    pSerializedDup->size = serializedSize;

    rc = TSS2_RC_SUCCESS;
exit:

    return rc;
}


TSS2_RC FAPI2_UTILS_deserialize_Duplicate(
        FAPI2B_DUPLICATE *pSerializedDup,
        FAPI2_DuplicateOut *pDuplicate
)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    MSTATUS status = ERR_GENERAL;
    ubyte4 serializedSize = 0;

    if ((NULL == pDuplicate)  || (NULL == pSerializedDup))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }



    status = SAPI2_SERIALIZE_serialize(SAPI2_ST_TPM2_FAPI2_DUPLICATEOUT, TAP_SD_OUT,
            (ubyte*)pSerializedDup->buffer, pSerializedDup->size,
            (ubyte*)pDuplicate, sizeof(FAPI2_DuplicateOut), &serializedSize);
    if (OK != status)
    {
        rc = TSS2_SYS_RC_GENERAL_FAILURE;
        DB_PRINT("%s.%d Failed to deserialize objectHandle, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = TSS2_RC_SUCCESS;
exit:

    return rc;
}


#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
