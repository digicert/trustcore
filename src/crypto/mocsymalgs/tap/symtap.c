/*
 * symtap.c
 *
 * Common methods for symmetric key TAP operators.
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

#include "../../../crypto/mocsym.h"
#include "../../../crypto/mocsymalgs/tap/symtap.h"
#include "../../../tap/tap_api.h"

#ifdef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
#include "../../../crypto_interface/cryptointerface.h"
#endif

#if defined(__ENABLE_DIGICERT_SYM__) && defined(__ENABLE_DIGICERT_TAP__)

extern MSTATUS SymTapCreate(MocSymCtx pMocSymCtx, MSymTapKeyGenArgs *pKeyGenArgs, ubyte4 localType, MSymOperator operator)
{
    MSTATUS status = ERR_NULL_POINTER;
    MTapKeyData *pNewData = NULL;

    if (NULL == pMocSymCtx)
        goto exit;

    /* free any previously existing data */
    status = SymTapFree(pMocSymCtx);
    if (OK != status)
        goto exit;

    /* Must be able to still create with no key gen args (ie input info), status still OK */
    if (NULL == pKeyGenArgs)
        goto exit;

    /* Allocate a new MAesTapKeyData and copy in what we can */
    status = DIGI_CALLOC ((void **)&pNewData, 1, sizeof(MTapKeyData));
    if (OK != status)
        goto exit;

    pNewData->pTapCtx = pKeyGenArgs->pTapCtx;
    pNewData->pKeyCredentials = pKeyGenArgs->pKeyCredentials;
    pNewData->pEntityCredentials = pKeyGenArgs->pEntityCredentials;
    pNewData->pKeyAttributes = pKeyGenArgs->pKeyAttributes;
    pNewData->symMode = pKeyGenArgs->symMode;

    pMocSymCtx->pLocalData = (void *)pNewData; pNewData = NULL;
    pMocSymCtx->localType = localType;
    pMocSymCtx->SymOperator = operator;

exit:

    /* Allocation is last possible failure step, no need to cleanup on error */

    return status;
}

extern MSTATUS SymTapFree(MocSymCtx pMocSymCtx)
{
    MSTATUS status = OK;
    MSTATUS fStatus = OK;
    MTapKeyData *pKeyData = NULL;
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;
#ifdef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_Context *pTapContext = NULL;
    TAP_Key *pTapKey = NULL;
#endif

    /* OK if nothing to free */
    if (NULL == pMocSymCtx)
        goto exit;

    pKeyData = (MTapKeyData *) pMocSymCtx->pLocalData;

    /* Delete any previously existing localData */
    if (NULL != pKeyData)
    {
        if (NULL != pKeyData->pKey)
        {
#ifndef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
            /* if not externally loaded, and it's in state init or update then the tap key needs to be unloaded */
            if (!pKeyData->isDeferUnload && (CTX_STATE_INIT == pMocSymCtx->state || CTX_STATE_UPDATE == pMocSymCtx->state) )
            {
                status = TAP_unloadKey(pKeyData->pKey, pErrContext);
                pKeyData->isKeyLoaded = FALSE;
            }
#endif
#ifdef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
            pTapKey = (TAP_Key *)pKeyData->pKey;
            if (g_pFuncPtrGetTapContext != NULL)
            {
                if (OK > (status = g_pFuncPtrGetTapContext(&pTapContext,
                                &pEntityCredentials,
                                &pKeyCredentials,
                                (void *)pMocSymCtx, tap_aes_encrypt, 1/*get context*/)))
                {
                    goto exit;
                }
            }
            else
            {
                status = ERR_NOT_IMPLEMENTED;
                goto exit;
            }

            if (!pKeyData->isKeyLoaded)
            {
                status = TAP_loadKey(pTapContext, pEntityCredentials, pTapKey, pKeyCredentials, NULL, pErrContext);
                if (OK != status)
                    goto exit;

                pKeyData->isKeyLoaded = TRUE;
            }
#endif

            fStatus = TAP_freeKey(&(pKeyData->pKey));
            if (OK == status)
                status = fStatus;
        }

        fStatus = DIGI_MEMSET_FREE((ubyte **) &pKeyData, sizeof(MTapKeyData));
        if (OK == status)
            status = fStatus;
    }

exit:
#ifdef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
    if (g_pFuncPtrGetTapContext != NULL)
    {
        g_pFuncPtrGetTapContext(&pTapContext,
                        &pEntityCredentials,
                        &pKeyCredentials,
                        (void *)pMocSymCtx, tap_aes_encrypt, 0/*release context*/);
    }
#endif
    return status;
}

#endif /* __ENABLE_DIGICERT_SYM__ && __ENABLE_DIGICERT_TAP__ */
