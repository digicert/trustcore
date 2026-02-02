/*
 * tbs_utils.c
 *
 * Functions needed from TBS by TPM 2.0
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

#ifdef __RTOS_WIN32__

#if defined(__ENABLE_DIGICERT_TPM2__)

#include <Windows.h>
#include <Tbs.h>

#include "../../../../common/mtypes.h"
#include "../../../../common/moptions.h"
#include "../../../../common/merrors.h"
#include "../../../../common/mstdlib.h"
#include "../../../../common/debug_console.h"

#include "tbs_util.h"

/*------------------------------------------------------------------*/

/**
 * @brief Function to create TBS Context
 * @note  Function to create TBS Context
 */
MSTATUS TBS_UTIL_ContextCreate(TPM2_TBS_CONTEXT * pTbsContext)
{
    MSTATUS status = OK;
    TBS_RESULT tbsResult;
    TBS_CONTEXT_PARAMS2 tbsContextParams = {
                                            .version = TBS_CONTEXT_VERSION_TWO,
                                            .includeTpm12 = 0,
                                            .includeTpm20 = 1,
                                        };
	TBS_HCONTEXT hContext = NULL;

    if (NULL == pTbsContext)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid arguments, status = %d",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    if (NULL != *pTbsContext)
    {
        status = ERR_INVALID_ARG;
        DB_PRINT("%s.%d: Invalid arguments, TBS-Context already present %p\n",
                __FUNCTION__, __LINE__, *pTbsContext);
        goto exit;
    }

    tbsResult = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&tbsContextParams, &hContext);

    if (TBS_SUCCESS != tbsResult)
    {
        DB_PRINT("[MAJOR] %s.%d: Error 0x%08x creating TBS context\n",
                __FUNCTION__, __LINE__, (unsigned int )tbsResult);
        status = ERR_TPM_CONNECTION_ERROR;
        goto exit;
    }

    *pTbsContext = (TPM2_TBS_CONTEXT)hContext;
    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/**
 * @brief Function to close TBS Context
 * @note  Function to close TBS Context
 */
MSTATUS TBS_UTIL_ContextClose(TPM2_TBS_CONTEXT * pTbsContext)
{
    MSTATUS status = OK;
    TBS_RESULT tbsResult;
	TBS_HCONTEXT hContext=NULL;

    if (NULL == pTbsContext || NULL == *pTbsContext)
    {
        status = ERR_NULL_POINTER;
        DB_PRINT("%s.%d Invalid arguments, status = %d",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    hContext = (TBS_HCONTEXT)(*pTbsContext);
    tbsResult = Tbsip_Context_Close(hContext);
    if (TBS_SUCCESS != tbsResult)
    {
        DB_PRINT("%s.%d: Error 0x%08x closing TBS context\n",
                __FUNCTION__, __LINE__, (unsigned int )tbsResult);
        status = ERR_TPM_TBS_METHOD_FAILED;
        goto exit;
    }

    *pTbsContext = NULL;
    status = OK;

exit:
    return status;
}


/*------------------------------------------------------------------*/

/**
 * @brief Function to retrieve owner-auth from TBS
 * @note  Function to retrieve owner-auth from TBS
 */
MOC_EXTERN MSTATUS TPM2_TBS_UTIL_GetOwnerAuth(TPM2_TBS_OWNERAUTH_TYPE ownerAuthType,
                              ubyte **ppOwnerAuth, ubyte4 *pOwnerAuthLen)
{
    MSTATUS status = OK;
    TPM2_TBS_CONTEXT tbsContext = NULL;
    TBS_HCONTEXT hContext = NULL;
    TPM2_TBS_OWNERAUTH_TYPE tbsOwnerAuthType = TBS_OWNERAUTH_TYPE_FULL;
    TBS_RESULT tbsResult;

	if (NULL == pOwnerAuthLen || NULL == ppOwnerAuth)
	{
        status = ERR_NULL_POINTER;
		DB_PRINT("%s.%d: NULL input params, status = %d\n",
                __FUNCTION__, __LINE__, status);
		goto exit;
	}

    /*Create context for calling TBS methods*/
    status = TBS_UTIL_ContextCreate(&tbsContext);
    if (OK != status)
    {
        DB_PRINT("%s.%d - Failed creating TBS context, status = %d\n",
                __FUNCTION__, __LINE__, status);
        goto exit;
    }

    hContext = (TBS_HCONTEXT)tbsContext;

    switch (ownerAuthType)
    {
        case TPM2_TBS_OWNERAUTH_TYPE_FULL:
            tbsOwnerAuthType = TBS_OWNERAUTH_TYPE_FULL;
            break;
        case TPM2_TBS_OWNERAUTH_TYPE_ENDORSEMENT:
            tbsOwnerAuthType = TBS_OWNERAUTH_TYPE_ENDORSEMENT_20;
            break;
        case TPM2_TBS_OWNERAUTH_TYPE_OWNER_ADMIN:
            tbsOwnerAuthType = TBS_OWNERAUTH_TYPE_STORAGE_20;
            break;
        default:
        {
            DB_PRINT("[MAJOR] %s: Invalid auth-type %d\n",
                    __FUNCTION__, ownerAuthType);
            status = ERR_INVALID_ARG;
            goto exit;
        }
            break;
    }

    /*Check if owner auth is retrievable and get appropriate buffer length*/
    tbsResult = Tbsi_Get_OwnerAuth(hContext, tbsOwnerAuthType, *ppOwnerAuth, pOwnerAuthLen);
    if (TBS_SUCCESS != tbsResult && TBS_E_INSUFFICIENT_BUFFER != tbsResult)
    {
        if (TBS_E_OWNERAUTH_NOT_FOUND != tbsResult)
        {
            DB_PRINT("[MAJOR] %s: Error 0x%08x reading owner auth type=%d\n",
                    __FUNCTION__, (unsigned int)tbsResult, tbsOwnerAuthType);
        }
        status = ERR_TPM_OWNERAUTH_READ_ERROR;
        goto exit;
    }

    /*Retrieve the value in buffer now, Added len+1 for NULL termination*/
    status = DIGI_CALLOC(ppOwnerAuth, 1, sizeof(ubyte) * ((*pOwnerAuthLen) + 1));
    if (OK != status)
    {
        DB_PRINT("[MAJOR] %s: Error in allocating memory for owner secret\n",
                __FUNCTION__);
        goto exit;
    }

    tbsResult = Tbsi_Get_OwnerAuth(hContext, tbsOwnerAuthType, *ppOwnerAuth, pOwnerAuthLen);
    if (TBS_SUCCESS != tbsResult)
    {
        DB_PRINT("[MAJOR] readOwnerAuth: Error 0x%08x reading owner auth type=%d\n", (unsigned int)tbsResult, tbsOwnerAuthType);
        status = ERR_TPM_OWNERAUTH_READ_ERROR;
        goto exit;
    }

    status = OK;

exit:
	if (NULL != tbsContext)
    {
		TBS_UTIL_ContextClose(&tbsContext);
    }

    if (OK != status)
    {
        if (NULL != ppOwnerAuth && NULL != *ppOwnerAuth)
        {
            DIGI_FREE(ppOwnerAuth);
        }
    }

    return status;
}


#endif /* __ENABLE_DIGICERT_TPM2__ */

#endif /* __RTOS_WIN32__ */
