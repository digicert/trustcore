/**
 * @file secmod.c
 *
 * @brief General Public SECMOD Definitions & Types Header
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


/*------------------------------------------------------------------*/

#include "../common/moptions.h"
#include "../common/mdefs.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../common/merrors.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#ifdef __ENABLE_DIGICERT_HW_SECURITY_MODULE__
#include "../common/random.h"
#include "../common/vlong.h"
#include "../crypto/secmod.h"
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#include "../crypto/pubcrypto.h"
#include "../smp/smp_tpm12/tpm12_lib/ekey_box.h"

#ifdef __ENABLE_DIGICERT_TPM__
#include "../smp/smp_tpm12/tpm12_lib/tpm/fapi/fapi_admin.h"
#endif



/**
 * @brief Function to initialize a secModDescr
 */
MOC_EXTERN MSTATUS SECMOD_init(secModDescr* secModContext, SECMOD_TYPE secmodType, ubyte4 serverNameLen, ubyte *pServerName, ubyte2 serverPort, void* params)
{
    MSTATUS status = OK;

    DIGI_MEMSET((ubyte *)secModContext, 0, sizeof (*secModContext));

    /* switch between the diffent init methods for different secmods*/
    switch(secmodType)
    {
#ifdef __ENABLE_DIGICERT_TPM__
        case secmod_TPM12:
        {
            TSS_SYS_CONTEXT *sysContext;
            secModContext->type = secmodType;
            secModContext->lastErr = NULL;

            if (OK != (status = FAPI_ADMIN_init(secmodType, serverNameLen, pServerName, serverPort, &sysContext)))
                goto exit;

#ifndef __DISABLE_DIGICERT_TPM_EKEYBOX__
            if (OK != (status = EKEY_BOX_init(secModContext)))
                goto exit;
#endif /* !__DISABLE_DIGICERT_TPM_EKEYBOX__ */

            secModContext->secmodCtx.TPM12Ctx = sysContext;
            break;
        }
#endif
        default:
        {
            status = ERR_SECMOD_INVALID_SECMOD_TYPE;
            break;
        }
    }

#ifdef __ENABLE_DIGICERT_TPM__
exit:
    if ((OK != status) && (NULL != secModContext->secmodCtx.TPM12Ctx))
    {
        FAPI_ADMIN_uninit(&(secModContext->secmodCtx.TPM12Ctx));
    }
#endif

    return status;
}

/* Uninitialize the hardware security module */
MOC_EXTERN MSTATUS SECMOD_uninit(secModDescr* secModContext)
{
    MSTATUS status = OK;

    switch(secModContext->type)
    {
#ifdef __ENABLE_DIGICERT_TPM__
        case secmod_TPM12:
        {
#ifndef __DISABLE_DIGICERT_TPM_EKEYBOX__
            status = EKEY_BOX_deinit(secModContext);
#endif /* !__DISABLE_DIGICERT_TPM_EKEYBOX__ */

            if (NULL != secModContext->secmodCtx.TPM12Ctx)
            {
                if (OK > (status = FAPI_ADMIN_uninit(&(secModContext->secmodCtx.TPM12Ctx))))
                    goto exit;
            }
            break;
        }
#endif
        default:
        {
            status = ERR_SECMOD_INVALID_SECMOD_TYPE;
            break;
        }
    }

#ifdef __ENABLE_DIGICERT_TPM__
exit:
#endif
    return status;
}



/**
 * @brief Function to free a secModDescr
 * @note This function also frees up the HSM specific context held in the secModDescr
 */
MSTATUS SECMOD_free_secModDescr(secModDescr *secModContext)
{
    MSTATUS status;
    
    if (NULL == secModContext)
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }
    
    if (NULL != secModContext->lastErr)
    {
        FREE(secModContext->lastErr);
    }
    
#ifdef __ENABLE_DIGICERT_TPM__
    if (NULL != secModContext->secmodCtx.TPM12Ctx)
    {
        status = SAPI_CONTEXT_Finalize(secModContext->secmodCtx.TPM12Ctx);
        if (OK != status)
            goto exit;
    }
#endif
    
    status = OK;
    
exit:
    return status;
    
}



/**
 * @brief Function to copy a secModDescr
 * @param pDestContext[in/out]  secModDescr to copy to
 * @param pSrcContext[in]    secModDescr to copy from
 * @return OK on success
 * @return ERR_NULL_POINTER if secModContext is NULL
 */
MSTATUS SECMOD_copy_secModDescr(secModDescr *pDestContext, secModDescr *pSrcContext)
{
    MSTATUS status = OK;

    if ((NULL == pDestContext) || (NULL == pSrcContext))
    {
        status = ERR_NULL_POINTER;
        goto exit;
    }

    pDestContext->id = pSrcContext->id;
    pDestContext->type = pSrcContext->type;
    pDestContext->lastErr = pSrcContext->lastErr;
    switch(pSrcContext->type)
    {
#ifdef __ENABLE_DIGICERT_TPM__
        case secmod_TPM12:
        {
            TSS2_RC rc;
            if(TSS2_RC_SUCCESS != (rc = SAPI_CONTEXT_Copy(&(pDestContext->secmodCtx.TPM12Ctx), pSrcContext->secmodCtx.TPM12Ctx)))
            {
                status = ERR_SECMOD_CONTEXT_CREATE_FAILED;
                goto exit;
            }
        }
#endif
        default:
        {
            status = ERR_SECMOD_INVALID_SECMOD_TYPE;
            break;
        }
        
    }   

exit:
    return status;
}
#endif /* __ENABLE_DIGICERT_HW_SECURITY_MODULE__*/
