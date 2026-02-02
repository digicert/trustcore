/*
 * smp_tee_api.c
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
 * @file       smp_tee_api.c
 * @brief      NanoSMP module feature API definitions for TEE.
 * @details    This C file contains feature function
               definitions implemented by the TEE NanoSMP.
 */

#include "../../common/moptions.h"

#if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_TEE__))
#include "tee_client_api.h"
#include "secure_storage_ta.h"

#include "smp_tee_api.h"
#include "smp_tee.h"

#if !(defined(__ENABLE_DIGICERT_DEBUG_CONSOLE__))
#define DB_PRINT(...)
#endif

/* We'll only have one module and config */
Tee_Module gModule = {0};

/* Global Mutex for protecting Tee modules */
/* RTOS_MUTEX gGemMutex = NULL; */

/* uuid's of TAs must be in order of macros
   in smp_tap_tee.h */
static TEEC_UUID gTeecUuid[2] =
{
    {0},
    TA_SECURE_STORAGE_UUID
};

#ifdef __SMP_ENABLE_SMP_CC_GET_MODULE_LIST__
MOC_EXTERN MSTATUS SMP_API(TEE, getModuleList,
    TAP_ModuleCapabilityAttributes *pModuleAttributes,
    TAP_EntityList *pModuleIdList
)
{
    MSTATUS status = OK;

    if (NULL == pModuleIdList)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d NULL pointer on input pModuleIdList\n",
                __FUNCTION__, __LINE__);
        goto exit;
    }

    pModuleIdList->entityType = TAP_ENTITY_TYPE_MODULE;

    /* Check to see if we really have a module initialized */
    if (NULL != gModule.pConfig)
    {
        status = DIGI_CALLOC((void **)&pModuleIdList->entityIdList.pEntityIdList, 1, sizeof(TAP_EntityId));
        if (OK != status)
        {
            DB_PRINT("%s.%d Unable to allocate memory for Module list, status = %d\n",
                    __FUNCTION__, __LINE__, status);
            goto exit;
        }

        pModuleIdList->entityIdList.numEntities = 1;
        pModuleIdList->entityIdList.pEntityIdList[0] = gModule.pConfig->moduleId;
    }
    else
    {
        pModuleIdList->entityIdList.numEntities = 0;
    }

exit:

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_INIT_MODULE__
MOC_EXTERN MSTATUS SMP_API(TEE, initModule,
        TAP_ModuleId moduleId,
        TAP_ModuleCapabilityAttributes* pModuleAttributes,
        TAP_CredentialList *pCredentials,
        TAP_ModuleHandle *pModuleHandle
)
{
    MSTATUS status = OK;

    MOC_UNUSED(pModuleAttributes);
    MOC_UNUSED(pCredentials);

    if (NULL == pModuleHandle)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Error initModule, status  = %d\n",
            __FUNCTION__, __LINE__, (int)status);
    }
    else
    {
        /* there is only one module, make sure we have the right one */
        if ((ubyte4) moduleId != gModule.pConfig->moduleId)
        {
            status = ERR_TAP_MODULE_NOT_FOUND;
            DB_PRINT("%s.%d Error Module %d not found, status = %d\n",
                __FUNCTION__, __LINE__, (int) moduleId, (int)status);
        }
        else
        {
            *pModuleHandle = (TAP_ModuleHandle) ((uintptr) &gModule);
        }
    }

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNINIT_MODULE__
MOC_EXTERN MSTATUS SMP_API(TEE, uninitModule,
        TAP_ModuleHandle moduleHandle
)
{
    MSTATUS status = OK, fstatus = OK;
    Tee_Module *pModule = (Tee_Module *) ((uintptr) moduleHandle);
    Tee_Token *pToken = NULL;
    Tee_Token *pLast = NULL;

    if (NULL == pModule)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Error uninitModule, status = %d\n",
            __FUNCTION__, __LINE__, (int) status);
        goto exit;
    }
    
    pToken = pModule->pTokenHead;
    while (NULL != pToken)
    {
        if (pToken->sessionActive)
        {
            TEEC_CloseSession(&pToken->sess);
            TEEC_FinalizeContext(&pToken->ctx);
            pToken->sessionActive = FALSE;
            pToken->uuid = 0;
        }
        pLast = pToken;
        pToken = pToken->pNext;
        fstatus = DIGI_FREE((void **) &pLast);
        if (OK == status)
            status = fstatus;
    }

    pModule->pTokenHead = NULL;
    /* config cleand up on SMP_TEE_uninit() */

exit:

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_INIT_TOKEN__
static byteBoolean isTokenAvailable(ubyte4 token, ubyte4 *pTokens, ubyte4 numTokens)
{
    byteBoolean found = FALSE;
    ubyte4 i = 0;

    while (i < numTokens)
    {
        if (pTokens[i] == token)
        {
            found = TRUE;
            break;
        }
        i++;
    }
    
    return found;
}

MSTATUS SMP_API(TEE, initToken,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenCapabilityAttributes *pTokenAttributes,
        TAP_TokenId tokenId,
        TAP_EntityCredentialList *pCredentials,
        TAP_TokenHandle *pTokenHandle)
{
    MSTATUS status = OK;
    Tee_Module *pModule = (Tee_Module *) ((uintptr) moduleHandle);
    Tee_Token *pLast = NULL;
    Tee_Token *pToken = NULL;
	uint32_t origin;
	TEEC_Result res;
    byteBoolean found = FALSE;

    MOC_UNUSED(pTokenAttributes);
    MOC_UNUSED(pCredentials);

    if (NULL == pModule || NULL == pModule->pConfig)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Error initToken, status = %d\n",
            __FUNCTION__, __LINE__, (int) status);
        goto exit;
    }

    if ((ubyte4) tokenId > TEE_MAX_TRUSTED_APPLICATION_ID)
    {
        status = ERR_SMP_UNSUPPORTED_FUNCTIONALITY;
        DB_PRINT("%s.%d Error Token (TA) value too large, status = %d\n",
            __FUNCTION__, __LINE__, (int) status);
        goto exit;
    }

    pToken = pModule->pTokenHead;
    while (NULL != pToken)
    {
        if (pToken->uuid == tokenId)
        {
            found = TRUE;
            break;
        }
        pLast = pToken;
        pToken = pToken->pNext;
    }
    
    if (!found) /* validate and allocate a new one */
    {
        if (!isTokenAvailable((ubyte4) tokenId, (ubyte4 *) pModule->pConfig->tokens, pModule->pConfig->numTokens))
        {
            status = ERR_SMP_UNSUPPORTED_FUNCTIONALITY;
            DB_PRINT("%s.%d Error Token (TA) not available for use, status = %d\n",
                                    __FUNCTION__, __LINE__, (int)status);
            
            goto exit;
        }

        status = DIGI_CALLOC((void **) &pToken, 1, sizeof(Tee_Token));
        if (OK != status)
            goto exit;

        pToken->uuid = tokenId;
    }

    if (FALSE == pToken->sessionActive)
    {
        res = TEEC_InitializeContext(NULL, &pToken->ctx);
        if (res != TEEC_SUCCESS)
        {
            DB_PRINT("%s.%d Error TEEC_InitializeContext, res = %d\n",
                                    __FUNCTION__, __LINE__, (int)res);
            status = ERR_GENERAL;
            goto exit;
        }
        
        /* Open a session with the TA */
        res = TEEC_OpenSession(&pToken->ctx, &pToken->sess, &gTeecUuid[pToken->uuid], TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
        if (res != TEEC_SUCCESS)
        {
            DB_PRINT("%s.%d Error TEEC_Opensession, res = %d, origin = 0x%x\n",
                                    __FUNCTION__, __LINE__, (int)res, origin);
            status = ERR_GENERAL;
            goto exit;        
        }

        pToken->sessionActive = TRUE;
    }

    if (NULL != pLast)
    {
        pLast->pNext = pToken;
    }
    else
    {
        pModule->pTokenHead = pToken;
    }

    *pTokenHandle = (TAP_TokenHandle) ((uintptr) pToken);
    pToken = NULL;

exit:

    /* free on error if we allocated */
    if (NULL != pToken && !found)
    {
        (void) DIGI_FREE((void **) &pToken);
    }
    
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_UNINIT_TOKEN__
MSTATUS SMP_API(TEE, uninitToken,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle
)
{
    MSTATUS status = OK;
    Tee_Module *pModule = (Tee_Module *) ((uintptr) moduleHandle);
    Tee_Token *pToken = NULL;
    Tee_Token *pIn = (Tee_Token *) ((uintptr) tokenHandle);

    if (NULL == pModule)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Error uninitToken, status = %d\n",
            __FUNCTION__, __LINE__, (int) status);
        goto exit;
    }

    pToken = pModule->pTokenHead;
    while (NULL != pToken)
    {
        if ((uintptr) pToken == (uintptr) pIn)
        {
            break;
        }
        pToken = pToken->pNext;
    }

    if (NULL != pToken)
    {
        TEEC_CloseSession(&pToken->sess);
        TEEC_FinalizeContext(&pToken->ctx);
        pToken->sessionActive = FALSE;
    }

exit:

    return status;
}
#endif

#if defined(__SMP_ENABLE_SMP_CC_INIT_OBJECT__)
static MSTATUS TEE_freeId(TAP_Buffer **ppIdBuf)
{
    MSTATUS status = OK, fstatus = OK;

    /* internal method, no NULL check*/

    if (NULL == *ppIdBuf)
        goto exit; /* nothing to do */
    
    if (NULL != (*ppIdBuf)->pBuffer)
    {
        if ((*ppIdBuf)->bufferLen > 0)
        {
            status = DIGI_MEMSET_FREE(&((*ppIdBuf)->pBuffer), (*ppIdBuf)->bufferLen);
        }
        else
        {
            status = DIGI_FREE((void **) &((*ppIdBuf)->pBuffer));
        }
    }

    fstatus = DIGI_MEMSET_FREE((ubyte **) ppIdBuf, sizeof(TAP_Buffer));
    if (OK == status)
        status = fstatus;

exit:
    
    return status;
}

static MSTATUS TEE_getId(TAP_ObjectAttributes *pObjectAttributes,
                         TAP_Buffer **ppIdBuf)
{
    MSTATUS status = OK;
    TAP_Attribute *pAttribute  = NULL;
    TAP_Buffer *pIncomingId = NULL;
    TAP_Buffer *pIdBuf = NULL;
    ubyte4 attrCount = 0;

    if (pObjectAttributes && pObjectAttributes->listLen)
    {
        pAttribute = pObjectAttributes->pAttributeList;
        attrCount = 0;

        while (attrCount < pObjectAttributes->listLen)
        {
            if (TAP_ATTR_OBJECT_ID_BYTESTRING == pAttribute->type)
            {
                break;
            }

            pAttribute++;
            attrCount++;
        }
    }

    if (NULL == pAttribute)
    {
        status = ERR_NOT_FOUND;
        DB_PRINT("%s.%d Error TEE_getId, status  = %d\n",
            __FUNCTION__, __LINE__, (int)status);
        goto exit; 
    }

    if ((sizeof(TAP_Buffer) != pAttribute->length) || (NULL == pAttribute->pStructOfType))
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d Invalid storage structure length %d, "
                "pStructOfType = %p\n",
                __FUNCTION__, __LINE__, pAttribute->length,
                pAttribute->pStructOfType);
        goto exit;
    }

    pIncomingId = (TAP_Buffer *)(pAttribute->pStructOfType);

    if (NULL == pIncomingId->pBuffer)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Null id buffer\n", __FUNCTION__, __LINE__);
        goto exit;   
    }

    /* In TAP remote the incoming id attribute will be thrown away, make a deep copy */
    status = DIGI_CALLOC((void **) &pIdBuf, 1, sizeof(TAP_Buffer));
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to allocate memory for the id, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    status = DIGI_MALLOC_MEMCPY((void **) &(pIdBuf->pBuffer), pIncomingId->bufferLen, pIncomingId->pBuffer, pIncomingId->bufferLen);
    if (OK != status)
    {
        DB_PRINT("%s.%d Unable to copy the id, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }
    pIdBuf->bufferLen = pIncomingId->bufferLen;

    *ppIdBuf = pIdBuf; pIdBuf = NULL;

exit:

    if (NULL != pIdBuf)
    {
        (void) TEE_freeId(&pIdBuf);
    }

    return status;
}

MSTATUS SMP_API(TEE, initObject,
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
    TAP_Buffer *pId = NULL;

    MOC_UNUSED(moduleHandle);
    MOC_UNUSED(tokenHandle);
    MOC_UNUSED(objectIdIn);
    MOC_UNUSED(pCredentials);
    MOC_UNUSED(pObjectIdOut);
    MOC_UNUSED(pObjectAttributesOut);

    if ((NULL == pObjectAttributes) || (NULL == pObjectHandle))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Error initObject, status  = %d\n",
            __FUNCTION__, __LINE__, (int)status);
        goto exit;
    }

    status = TEE_getId(pObjectAttributes, &pId);
    if (OK != status) /* error already printed */
        goto exit;

    /* We make an object handle just a pointer to the id */                       
    *pObjectHandle = (TAP_ObjectHandle) ((uintptr) pId);

exit:
    
    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_DELETE_OBJECT__
MSTATUS SMP_API(TEE, deleteObject,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle
)
{
    MSTATUS status = OK;
    Tee_Token *pToken = (Tee_Token *) ((uintptr) tokenHandle);
	TAP_Buffer *pId = (TAP_Buffer *) ((uintptr) objectHandle);
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

    MOC_UNUSED(moduleHandle);

    if ((NULL == pToken) || (NULL == pId))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Error deleteObject, status  = %d\n",
            __FUNCTION__, __LINE__, (int)status);
        goto exit;
    }

    status = DIGI_MEMSET((void *) &op, 0x00, sizeof(op));
    if (OK != status)
        goto exit;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = (char *) pId->pBuffer;
	op.params[0].tmpref.size = (size_t) pId->bufferLen;

	res = TEEC_InvokeCommand(&pToken->sess, TA_SECURE_STORAGE_CMD_DELETE, &op, &origin);
    if (res != TEEC_SUCCESS)
    {
        if (res == TEEC_ERROR_ITEM_NOT_FOUND)
        {
            status = ERR_NOT_FOUND;
        }
        else
        {
            status = ERR_GENERAL;
        }
        DB_PRINT("%s.%d Error TEEC_InvokeCommand, res  = %d, status = %d\n",
            __FUNCTION__, __LINE__, (int)res, (int) status);
    }

exit:

    /* Object was init-ed prior to all set, get, delete calls, always free */
#if defined(__SMP_ENABLE_SMP_CC_INIT_OBJECT__)
    (void) TEE_freeId(&pId);
#endif

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_SET_POLICY_STORAGE__
MSTATUS SMP_API(TEE, setPolicyStorage,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_PolicyStorageAttributes *pPolicyAttributes,
        TAP_OperationAttributes *pOpAttributes,
        TAP_Buffer *pData
)
{
    MSTATUS status = OK;
    Tee_Token *pToken = (Tee_Token *) ((uintptr) tokenHandle);
    TAP_Buffer *pId = (TAP_Buffer *) ((uintptr) objectHandle);
    TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

    MOC_UNUSED(moduleHandle);
    MOC_UNUSED(pPolicyAttributes);
    MOC_UNUSED(pOpAttributes);
 
    if ((NULL == pToken) || (NULL == pData) || (NULL == pId))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Error setPolicyStorage, status  = %d\n",
            __FUNCTION__, __LINE__, (int)status);
        goto exit;
    }

    status = DIGI_MEMSET((void *) &op, 0x00, sizeof(op));
    if (OK != status)
        goto exit;

    /* First we check if something is already there with this ID*/
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);

    op.params[0].tmpref.buffer = (char *) pId->pBuffer;
    op.params[0].tmpref.size = (size_t) pId->bufferLen;

    /* pass with NULL buffer ok since we don't actually need to retrieve the item */
    op.params[1].tmpref.buffer = NULL;
    op.params[1].tmpref.size = 0;

    res = TEEC_InvokeCommand(&pToken->sess, TA_SECURE_STORAGE_CMD_READ_RAW, &op, &origin);
    if (res != TEEC_ERROR_ITEM_NOT_FOUND)
    {
        if (TEEC_ERROR_SHORT_BUFFER == res)
        {
            status = ERR_PREVIOUSLY_EXISTING_ITEM;
        }
        else
        {
            status = ERR_GENERAL;
        }
        DB_PRINT("%s.%d Error TEEC_InvokeCommand, res  = %d, status = %d\n",
            __FUNCTION__, __LINE__, (int)res, (int) status);
        goto exit;
    }
 
    /* Now write to secure storage */
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT,
                                        TEEC_NONE, TEEC_NONE);

    op.params[1].tmpref.buffer = (char *) pData->pBuffer;
    op.params[1].tmpref.size = (size_t) pData->bufferLen;

    res = TEEC_InvokeCommand(&pToken->sess, TA_SECURE_STORAGE_CMD_WRITE_RAW, &op, &origin);
    if (res != TEEC_SUCCESS)
    {
        status = ERR_GENERAL;
        DB_PRINT("%s.%d Error TEEC_InvokeCommand, res  = %d\n",
            __FUNCTION__, __LINE__, (int)res);
    }

exit:

    /* Object was init-ed prior to all set, get, delete calls, always free */
#if defined(__SMP_ENABLE_SMP_CC_INIT_OBJECT__)
    (void) TEE_freeId(&pId);
#endif

    return status;
}
#endif

#ifdef __SMP_ENABLE_SMP_CC_GET_POLICY_STORAGE__
MSTATUS SMP_API(TEE, getPolicyStorage,
        TAP_ModuleHandle moduleHandle,
        TAP_TokenHandle tokenHandle,
        TAP_ObjectHandle objectHandle,
        TAP_OperationAttributes *pOpAttributes,
        TAP_Buffer *pData
)
{
    MSTATUS status = OK;
    Tee_Token *pToken = (Tee_Token *) ((uintptr) tokenHandle);
    TAP_Buffer *pId = (TAP_Buffer *) ((uintptr) objectHandle);
    TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;
    byteBoolean alloced = FALSE;
 
    MOC_UNUSED(moduleHandle);
    MOC_UNUSED(objectHandle);

    if ((NULL == pToken) || (NULL == pData) || (NULL == pId))
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Error getPolicyStorage, status  = %d\n",
            __FUNCTION__, __LINE__, (int)status);
        goto exit;
    }

    status = DIGI_MEMSET((void *) &op, 0x00, sizeof(op));
    if (OK != status)
        goto exit;

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);

    op.params[0].tmpref.buffer = (char *) pId->pBuffer;
    op.params[0].tmpref.size = pId->bufferLen;

    /* pass with NULL buffer to get size first */
    op.params[1].tmpref.buffer = NULL;
    op.params[1].tmpref.size = 0;

    res = TEEC_InvokeCommand(&pToken->sess, TA_SECURE_STORAGE_CMD_READ_RAW, &op, &origin);
    if (res != TEEC_ERROR_SHORT_BUFFER)
    {
        if (res == TEEC_ERROR_ITEM_NOT_FOUND)
        {
            status = ERR_NOT_FOUND;
        }
        else
        {
            status = ERR_GENERAL;
        }
        DB_PRINT("%s.%d Error TEEC_InvokeCommand, res  = %d, status = %d\n",
            __FUNCTION__, __LINE__, (int)res, (int) status);
        goto exit;
    }

    /* If buffer is there but not big enough, free it */
    if (NULL != pData->pBuffer && pData->bufferLen < (ubyte4) op.params[1].tmpref.size)
    {
        status = DIGI_FREE((void **) &pData->pBuffer);
        if (OK != status)
            goto exit;
    }

    if (NULL == pData->pBuffer)
    {
        status = DIGI_MALLOC((void **) &pData->pBuffer, op.params[1].tmpref.size);
        if (OK != status)
            goto exit;
        
        pData->bufferLen = (ubyte4) op.params[1].tmpref.size;
        alloced = TRUE;
    }

    op.params[1].tmpref.buffer = (char *) pData->pBuffer;
    op.params[1].tmpref.size = pData->bufferLen;

    res = TEEC_InvokeCommand(&pToken->sess, TA_SECURE_STORAGE_CMD_READ_RAW, &op, &origin);
    if (res != TEEC_SUCCESS)
    {
        if (res == TEEC_ERROR_SHORT_BUFFER)
        {
            status = ERR_BUFFER_TOO_SMALL;
        }
        else if (res == TEEC_ERROR_ITEM_NOT_FOUND)
        {
            status = ERR_NOT_FOUND;
        }
        else
        {
            status = ERR_GENERAL;
        }
        DB_PRINT("%s.%d Error TEEC_InvokeCommand, res  = %d, status = %d\n",
            __FUNCTION__, __LINE__, (int)res, (int) status);
        goto exit;
    }

    pData->bufferLen = (ubyte4) op.params[1].tmpref.size;

exit:
 
    /* Object was init-ed prior to all set, get, delete calls, always free */
#if defined(__SMP_ENABLE_SMP_CC_INIT_OBJECT__)
    (void) TEE_freeId(&pId);
#endif

    if (OK != status && alloced)
    {
        /* don't need to memset to zero, TEEC_InvokeCommand was only failure case */
        (void) DIGI_FREE((void **) &pData->pBuffer);
    }
    
    return status;
}
#endif

#endif /* #if (defined (__ENABLE_DIGICERT_SMP__) && defined (__ENABLE_DIGICERT_TEE__)) */
