/*  tcti.c
 *
 *  This file includes definitions for the TCTI layer
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
#include "../../../../common/mdefs.h"
#include "../../../../common/merrors.h"
#include "../../../../common/mrtos.h"
#include "../../../../common/mstdlib.h"
#include "../../../../common/debug_console.h"
#include "tcti.h"
#include "tcti_os.h"
#include "../tpm_common/tpm_error_utils.h"

typedef struct {
    void *pOsContext;
    TCTI_OS_OPS *pOps;
} _TCTI_CONTEXT;

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__)
extern TCTI_OS_OPS tcti_posix_ops;
#else
#if defined(__RTOS_WIN32__)
extern TCTI_OS_OPS tcti_win_ops;
#endif
#endif

byteBoolean gShouldReuseContext = FALSE;
TCTI_CONTEXT *gpSharedTctiCtx = NULL;

/* Should be called once in the begining from tap if sharedcontext is enabled.
 * This is not a thread-safe method */
MOC_EXTERN TSS2_RC TSS2_TCTI_sharedContextInit(TctiContextInitIn *pIn)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    gShouldReuseContext = TRUE;
    if (NULL == gpSharedTctiCtx)
    {
        rc = TSS2_TCTI_contextInit(pIn, &gpSharedTctiCtx);

        if (OK != rc)
        {
            goto exit;
        }
    }

exit:
    return rc;
}

/* Should be called once in the end from tap if sharedcontext is enabled.
 * This is not a thread-safe method */
MOC_EXTERN TSS2_RC TSS2_TCTI_sharedContextUninit()
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;

    if (NULL != gpSharedTctiCtx)
    {
        gShouldReuseContext = FALSE;
        rc = TSS2_TCTI_contextUninit(&gpSharedTctiCtx);

        if (OK != rc)
        {
            goto exit;
        }
    }

exit:
    return rc;
}

TSS2_RC TSS2_TCTI_contextInit(TctiContextInitIn *pIn, TCTI_CONTEXT **ppTctiContext)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    _TCTI_CONTEXT *pNewContext = NULL;

    if (!pIn || !ppTctiContext || *ppTctiContext)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers supplied. rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if ( (TRUE == gShouldReuseContext) && (NULL != gpSharedTctiCtx) )
    {
        *ppTctiContext = gpSharedTctiCtx;
        rc = TSS2_RC_SUCCESS;
        goto exit;
    }

    if (OK != DIGI_CALLOC((void **)&pNewContext, 1, sizeof(*pNewContext)))
    {
        rc = TSS2_BASE_RC_INSUFFICIENT_BUFFER;
        DB_PRINT("%s.%d Could not allocate memory for TCTI"
                "context, rc 0x%02x = %s\n",
                 __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

#if defined(__RTOS_LINUX__) || defined(__RTOS_OSX__)
    pNewContext->pOps = &tcti_posix_ops;
#else
#if defined(__RTOS_WIN32__)
    pNewContext->pOps = &tcti_win_ops;
#endif
#endif

    if (!pNewContext->pOps || !pNewContext->pOps->contextInit)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Context init not registered. rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = pNewContext->pOps->contextInit(pIn, &pNewContext->pOsContext);
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to initialize OS specific context, rc 0x%02x = %s\n",
                 __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    *ppTctiContext = (TCTI_CONTEXT *)pNewContext;
    pNewContext = NULL;

    rc = TSS2_RC_SUCCESS;

exit:

    if (pNewContext)
        DIGI_FREE((void **)&pNewContext);

    return rc;
}

TSS2_RC TSS2_TCTI_contextUninit(TCTI_CONTEXT **ppTctiContext)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    _TCTI_CONTEXT *pContextToFree = NULL;

    if (!ppTctiContext || !*ppTctiContext)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers supplied. rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    if (TRUE == gShouldReuseContext)
    {
        *ppTctiContext = NULL;
        rc = TSS2_RC_SUCCESS;
        goto exit;
    }

    pContextToFree = (_TCTI_CONTEXT *)*ppTctiContext;
    if (!pContextToFree->pOps->contextUnint)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Context uninit not registered. rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    rc = pContextToFree->pOps->contextUnint(&(pContextToFree->pOsContext));
    if (TSS2_RC_SUCCESS != rc)
    {
        DB_PRINT("%s.%d Failed to un-initialize OS specific context, rc 0x%02x = %s\n",
                 __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }

    DIGI_FREE((void **)&pContextToFree);
    *ppTctiContext = NULL;
    rc = TSS2_RC_SUCCESS;
exit:
    return rc;
}

TSS2_RC TSS2_TCTI_transmitReceive(TCTI_CONTEXT *pTctiCtx, TctiTransmitRecieveIn *pIn, TctiTransmitRecieveOut *pOut)
{
    TSS2_RC rc = TSS2_SYS_RC_GENERAL_FAILURE;
    _TCTI_CONTEXT *pContext = NULL;

    if (!pTctiCtx || !pIn || !pOut)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Invalid pointers supplied. rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    pContext = (_TCTI_CONTEXT *)pTctiCtx;
    if (!pContext->pOps->transmitRecieve)
    {
        rc = TSS2_SYS_RC_BAD_REFERENCE;
        DB_PRINT("%s.%d Transmit Recieve not registered. rc 0x%02x = %s\n",
                __FUNCTION__,__LINE__, rc, tss2_err_string(rc));
        goto exit;
    }
    rc = pContext->pOps->transmitRecieve(pContext->pOsContext, pIn, pOut);

exit:
    return rc;
}

#endif /* __ENABLE_DIGICERT_TPM2__ */
