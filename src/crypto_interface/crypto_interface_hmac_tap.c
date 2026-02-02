/*
 * crypto_interface_hmac_tap.c
 *
 * Cryptographic Interface specification for HMAC TAP.
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

#include "../crypto/mocsym.h"
#include "../common/debug_console.h"
#include "../crypto_interface/crypto_interface_hmac_tap.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "../tap/tap.h"
#include "../tap/tap_smp.h"
#include "../tap/tap_api.h"
#include "../tap/tap_utils.h"
#include "../asn1/mocasn1.h"
#include "../crypto/hmac.h"
#include "../crypto/mocsymalgs/tap/symtap.h"
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/cryptointerface.h"
#endif

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_TAP_getHmacCtxFromSymmetricKeyAlloc (
    SymmetricKey *pSymKey,
    HMAC_CTX **ppCtx
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER;
    HMAC_CTX *pNewCtx = NULL;

    if (NULL == ppCtx || NULL == pSymKey || NULL == pSymKey->pKeyData)
        goto exit;

    status = DIGI_CALLOC((void **) &pNewCtx, 1, sizeof(HMAC_CTX));
    if (OK != status)
        goto exit;

    /* Transfer control of the underlying MocSymCtx to the wrapper */
    pNewCtx->pMocSymCtx = (MocSymCtx) (pSymKey->pKeyData); pSymKey->pKeyData = NULL;

    /* Ensure the state is create */
    pNewCtx->pMocSymCtx->state = CTX_STATE_CREATE;

    /* Mark this object as crypto interface enabled */
    pNewCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

    *ppCtx = pNewCtx; pNewCtx = NULL;

exit:

    if (NULL != pNewCtx)
    {
        (void) DIGI_FREE((void **)&pNewCtx);
    }

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_TAP_HmacDeferKeyUnload (
    HMAC_CTX *pCtx,
    byteBoolean deferredTokenUnload
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    if (NULL == pCtx)
        return ERR_NULL_POINTER;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != pCtx->enabled)
        return ERR_TAP_INVALID_KEY_TYPE;

    return CRYPTO_INTERFACE_TAP_SymDeferUnload(pCtx->pMocSymCtx, deferredTokenUnload);
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_TAP__
extern MSTATUS CRYPTO_INTERFACE_TAP_HmacGetKeyInfo (
    HMAC_CTX *pCtx,
    TAP_TokenHandle *pTokenHandle,
    TAP_KeyHandle *pKeyHandle
    )
{
    if (NULL == pCtx) /* other params validated in below call */
        return ERR_NULL_POINTER;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != pCtx->enabled)
        return ERR_TAP_INVALID_KEY_TYPE;

    return CRYPTO_INTERFACE_TAP_SymGetKeyInfo (pCtx->pMocSymCtx, pTokenHandle, pKeyHandle);
}
#endif /* __ENABLE_DIGICERT_TAP__ */

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_TAP_HmacReset(MocSymCtx pCtx)
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = CRYPTO_INTERFACE_TAP_HmacFinal(pCtx, NULL);
    pCtx->state = CTX_STATE_CREATE;

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_TAP_HmacUpdate (MocSymCtx pCtx, const ubyte *pData, ubyte4 dataLen)
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER;
    MSTATUS status2 = OK;
    MTapKeyData *pTapData = NULL;
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_Context *pTapContext = NULL;
    TAP_Key *pTapKey = NULL;
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_Buffer data = {0};

    if (NULL == pCtx || NULL == pCtx->pLocalData || (NULL == pData && dataLen))
        goto exit;

    status = ERR_CRYPTO_CTX_STATE;
    if (CTX_STATE_CREATE != pCtx->state && CTX_STATE_INIT != pCtx->state)
        goto exit;

    pTapData = (MTapKeyData *) pCtx->pLocalData;
    pTapKey = (TAP_Key *) pTapData->pKey;

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status = g_pFuncPtrGetTapContext(&pTapContext,
                        &pEntityCredentials,
                        &pKeyCredentials,
                        (void *)pCtx, tap_hmac_sign, 1/*get context*/)))
        {
            goto exit;
        }
    }
    else
    {
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
    }

    if (CTX_STATE_CREATE == pCtx->state)
    {
        if (!pTapData->isKeyLoaded)
        {
            status = TAP_loadKey(pTapContext, pEntityCredentials, pTapKey, pKeyCredentials, NULL, pErrContext);
            if (OK != status)
                goto exit1;

            pTapData->isKeyLoaded = TRUE;
        }

        status = TAP_symSignInit(pTapKey, pEntityCredentials, pTapData->pKeyAttributes, pErrContext);
        if (OK != status)
            goto exit1;

        pCtx->state = CTX_STATE_INIT;
    }

    data.pBuffer = (ubyte *) pData;
    data.bufferLen = dataLen;

    if (dataLen)
    {
        status = TAP_symSignUpdate(pTapKey, &data, pErrContext);
        if (OK != status)
            goto exit1;
    }

    status = OK;

exit1:

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status2 = g_pFuncPtrGetTapContext(&pTapContext,
                        &pEntityCredentials,
                        &pKeyCredentials,
                        (void *)pCtx, tap_hmac_sign, 0/*release context*/)))
        {
            DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"Tap Context release failed with status = ", status2);
        }
    }
    /* Return 'cleanup' error when it does not override a 'real' error */
    if ((OK != status2) && (OK == status))
    {
        status = status2;
    }

exit:

    /* data.pBuffer was a set pointer, no allocation, no cleanup needed */

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_TAP_HmacFinal (MocSymCtx pCtx, ubyte *pResult)
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER;
    MSTATUS status2 = OK;
    MTapKeyData *pTapData = NULL;
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_Signature result = {0};

    if (NULL == pCtx || NULL == pCtx->pLocalData)
        goto exit;

    status = OK; /* if already finalized, then an ok no-op */
    if (CTX_STATE_FINAL == pCtx->state)
         goto exit;

    pTapData = (MTapKeyData *) pCtx->pLocalData;

    status = TAP_symSignFinal(pTapData->pKey, &result, pErrContext);
    if (OK != status)
        goto exit;

    if (NULL != pResult)
    {
        status = DIGI_MEMCPY(pResult, result.signature.hmacSignature.pSignature, result.signature.hmacSignature.signatureLen);
    }

#ifndef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
    if (!pTapData->isDeferUnload)
    {
        status2 = TAP_unloadKey(pTapData->pKey, pErrContext);
        if (OK != status2)
        {
            DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"TAP_unloadKey failed with status = ", status2);
        }
        if (OK == status)
            status = status2;

        pTapData->isKeyLoaded = FALSE;
    }
#endif

    pCtx->state = CTX_STATE_FINAL;

exit:

    (void) TAP_freeSignature(&result);

    return status;

#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

extern MSTATUS CRYPTO_INTERFACE_TAP_HmacSingle (MocSymCtx pCtx, const ubyte *pData, ubyte4 dataLen, ubyte *pResult)
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER;
    MSTATUS status2 = OK;
    MTapKeyData *pTapData = NULL;
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_Context *pTapContext = NULL;
    TAP_Key *pTapKey = NULL;
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_Buffer data = {0};
    TAP_Signature result = {0};

    if (NULL == pCtx || NULL == pCtx->pLocalData || (NULL == pData && dataLen))
        goto exit;

    status = ERR_CRYPTO_CTX_STATE;
    if (CTX_STATE_CREATE != pCtx->state && CTX_STATE_INIT != pCtx->state)
        goto exit;

    pTapData = (MTapKeyData *) pCtx->pLocalData;
    pTapKey = (TAP_Key *) pTapData->pKey;

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status = g_pFuncPtrGetTapContext(&pTapContext,
                        &pEntityCredentials,
                        &pKeyCredentials,
                        (void *)pCtx, tap_hmac_sign, 1/*get context*/)))
        {
            goto exit;
        }
    }
    else
    {
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
    }

    /* status is OK at this point */
    if (!pTapData->isKeyLoaded)
    {
        status = TAP_loadKey(pTapContext, pEntityCredentials, pTapKey, pKeyCredentials, NULL, pErrContext);
        if (OK != status)
            goto exit1;

        pTapData->isKeyLoaded = TRUE;
    }

    data.pBuffer = (ubyte *) pData;
    data.bufferLen = dataLen;

    if (dataLen)
    {
        status = TAP_symSign(pTapKey, pEntityCredentials, pTapData->pKeyAttributes, TRUE, &data, &result, pErrContext);
        if (OK != status)
            goto exit1;

        status = DIGI_MEMCPY(pResult, result.signature.hmacSignature.pSignature, result.signature.hmacSignature.signatureLen);
        if (OK != status)
            goto exit1;
    }

#ifndef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
    if (!pTapData->isDeferUnload)
    {
        status2 = TAP_unloadKey(pTapData->pKey, pErrContext);
        if (OK != status2)
        {
            DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"TAP_unloadKey failed with status = ", status2);
        }
        if (OK == status)
            status = status2;

        pTapData->isKeyLoaded = FALSE;
    }
#endif

    pCtx->state = CTX_STATE_FINAL;

exit1:

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status2 = g_pFuncPtrGetTapContext(&pTapContext,
                        &pEntityCredentials,
                        &pKeyCredentials,
                        (void *)pCtx, tap_hmac_sign, 0/*release context*/)))
        {
            DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"Tap Context release failed with status = ", status2);
        }
    }
    /* Return 'cleanup' error when it does not override a 'real' error */
    if ((OK != status2) && (OK == status))
    {
        status = status2;
    }

exit:

    (void) TAP_freeSignature(&result);

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}
