/**
 * @file sapi2_handles.c
 * @brief This file contains SAPI2 HANDLES related functions for TPM2.
 *
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
#include "sapi2_utils.h"
#include "sapi2_handles.h"

static TSS2_RC SAPI2_HANDLES_createHandle(TPM2_HANDLE inTpm2Handle,
        void *pInPublicArea, MOCTPM2_OBJECT_HANDLE **ppOutObjectHandle)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if ((NULL == ppOutObjectHandle) || (NULL != *ppOutObjectHandle))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid object handles, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (!IS_VALID_TPM2_HANDLE(inTpm2Handle))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid TPM handle, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (OK != DIGI_CALLOC((void **)ppOutObjectHandle, 1,
            sizeof(MOCTPM2_OBJECT_HANDLE)))
    {
        rc = TSS2_SYS_RC_IO_ERROR;
        DB_PRINT("%s.%d Failed to allocate memory for new object,"
                "rc 0x%02x = %s\n", __FUNCTION__, __LINE__,
                rc, tss2_err_string(rc));
        goto exit;
    }

    (*ppOutObjectHandle)->tpm2Handle = inTpm2Handle;

    if (IS_TPM2_OBJECT_HANDLE(inTpm2Handle))
    {
        rc = SAPI2_UTILS_getObjectName(inTpm2Handle,
                (TPMT_PUBLIC *)pInPublicArea,
                &(*ppOutObjectHandle)->objectName);
        if (rc != TSS2_RC_SUCCESS)
        {
            DB_PRINT("%s.%d Failed SAPI2_UTILS_getObjectName(),"
                    " rc 0x%02x = %s\n", __FUNCTION__, __LINE__,
                    rc, tss2_err_string(rc));
            goto exit;
        }

        /* public are is not present for session handles, pcr handles
         * sequence handles and permanent entity handles. Copy only if present.
         */
        if (pInPublicArea)
        {
            (*ppOutObjectHandle)->publicArea.objectPublicArea =
                    (*((TPMT_PUBLIC *)pInPublicArea));
        }
    }
    else
    {
        /* For NV's there must be a public area */
        if (NULL == pInPublicArea)
        {
            rc = TSS2_SYS_RC_BAD_REFERENCE;
            DB_PRINT("%s.%d Invalid public are for NV, rc 0x%02x = %s\n",
                    __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        rc = SAPI2_UTILS_getNvName(inTpm2Handle,
                (TPMS_NV_PUBLIC *)pInPublicArea,
                &(*ppOutObjectHandle)->objectName);
        if (rc != TSS2_RC_SUCCESS)
        {
            DB_PRINT("%s.%d Failed SAPI2_UTILS_getNvName(), rc 0x%02x = %s\n",
                    __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }

        ((*ppOutObjectHandle)->publicArea.nvPublicArea) =
                (*((TPMS_NV_PUBLIC *)pInPublicArea));

    }

    rc = TSS2_RC_SUCCESS;
exit:
    if (rc != TSS2_RC_SUCCESS)
    {
        if (ppOutObjectHandle && (*ppOutObjectHandle))
        {
            if (OK != shredMemory((ubyte **)ppOutObjectHandle,
                    sizeof(MOCTPM2_OBJECT_HANDLE), TRUE))
            {
                rc = TSS2_SYS_RC_IO_ERROR;
                DB_PRINT("%s.%d Failed to shredMemory, rc 0x%02x = %s\n", __FUNCTION__,
                        __LINE__, rc, tss2_err_string(rc));
            }
        }
    }

    return rc;
}

TSS2_RC SAPI2_HANDLES_createObjectHandle(TPM2_HANDLE inTpm2Handle,
        TPMT_PUBLIC *pInPublicArea, MOCTPM2_OBJECT_HANDLE **ppOutObjectHandle)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if ((NULL == ppOutObjectHandle) || (NULL != *ppOutObjectHandle))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid object handle pointers, rc 0x%02x = %s\n",
                __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (!IS_TPM2_OBJECT_HANDLE(inTpm2Handle))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Failed TPM object handle, rc 0x%02x = %s\n",
                __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = SAPI2_HANDLES_createHandle(inTpm2Handle, pInPublicArea,
            ppOutObjectHandle);
exit:
    return rc;
}

TSS2_RC SAPI2_HANDLES_createNvHandle(TPM2_HANDLE inTpm2Handle,
        TPMS_NV_PUBLIC *pInPublicArea, MOCTPM2_OBJECT_HANDLE **ppOutObjectHandle)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if ((NULL == ppOutObjectHandle) || (NULL != *ppOutObjectHandle))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid object handle pointers, rc 0x%02x = %s\n",
                __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (!IS_TPM2_NV_HANDLE(inTpm2Handle))
    {
        rc = TSS2_SYS_RC_BAD_VALUE;
        DB_PRINT("%s.%d Invalid TPM NV handle, rc 0x%02x = %s\n", __FUNCTION__,
                __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = SAPI2_HANDLES_createHandle(inTpm2Handle, pInPublicArea,
            ppOutObjectHandle);
exit:
    return rc;
}

TSS2_RC SAPI2_HANDLES_destroyHandle(MOCTPM2_OBJECT_HANDLE **ppInObjectHandle,
        byteBoolean freeMetadata)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if ((NULL == ppInObjectHandle) || (NULL == *ppInObjectHandle))
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid object handle pointers, rc 0x%02x = %s\n",
                __FUNCTION__, __LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (freeMetadata && ((*ppInObjectHandle)->pMetadata != NULL))
    {
        if (OK != shredMemory((ubyte **)&((*ppInObjectHandle)->pMetadata),
                (*ppInObjectHandle)->metaDataSize, TRUE))
        {
            rc = TSS2_SYS_RC_IO_ERROR;
            DB_PRINT("%s.%d Failed to shredMemory, rc 0x%02x = %s\n", __FUNCTION__,
                    __LINE__, rc, tss2_err_string(rc));
            goto exit;
        }
    }

    if (OK != shredMemory((ubyte **)ppInObjectHandle,
            sizeof(MOCTPM2_OBJECT_HANDLE), TRUE))
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

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
