/*
 * crypto_interface_aes_ctr_tap.c
 *
 * Cryptographic Interface specification for AES-CTR TAP.
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
#include "../crypto_interface/crypto_interface_sym_tap.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "../tap/tap.h"
#include "../tap/tap_smp.h"
#include "../tap/tap_api.h"
#include "../tap/tap_utils.h"
#include "../asn1/mocasn1.h"
#include "../crypto/aes.h"
#include "../crypto/aes_ctr.h"
#include "../crypto/mocsymalgs/tap/symtap.h"
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_aes_ctr_tap.h"
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_getAesCtrCtxFromSymmetricKeyAlloc (
    SymmetricKey *pSymKey,
    BulkCtx *ppNewCtx,
    ubyte *pIv
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER;
    MSTATUS status2 = OK;
    aesCTRCipherContext *pNewCtx = NULL;
    MocSymCtx pSymCtx = NULL;
    MTapKeyData *pTapData = NULL;
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_Context *pTapContext = NULL;
    TAP_Key *pTapKey = NULL;
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_Buffer iv = {0};

    if ( (NULL == pSymKey) || (NULL == pSymKey->pKeyData) || (NULL == ppNewCtx) || (NULL == pIv) )
    {
        goto exit;
    }

    pSymCtx = (MocSymCtx) pSymKey->pKeyData;
    pTapData = (MTapKeyData *) pSymCtx->pLocalData;

    if (NULL == pTapData)
        goto exit;

    pTapKey = (TAP_Key *) pTapData->pKey;
    pTapData->symMode = TAP_SYM_KEY_MODE_CTR;

    /* Override the internal TAP structure sym mode */
    pTapData->pKey->keyData.algKeyInfo.aesInfo.symMode = pTapData->symMode;

    /* Direction does not matter for CTR, enc by default */
    pTapData->direction = MOCANA_SYM_TAP_ENCRYPT;

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status = g_pFuncPtrGetTapContext(&pTapContext,
                        &pEntityCredentials,
                        &pKeyCredentials,
                        (void *)pSymCtx, tap_aes_encrypt, 1/*get context*/)))
        {
            goto exit;
        }
    }
    else
    {
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
    }

    if (!pTapData->isKeyLoaded)
    {
        status = TAP_loadKey(pTapContext, pEntityCredentials, pTapKey, pKeyCredentials,
                             pTapData->pKeyAttributes, pErrContext);
        if (OK != status)
            goto exit1;

        pTapData->isKeyLoaded = TRUE;
    }

    iv.pBuffer = pIv;
    iv.bufferLen = AES_BLOCK_SIZE;

    status = TAP_symEncryptInit(pTapKey, pEntityCredentials, NULL, pTapData->symMode,
                                &iv, pErrContext);
    if (OK != status)
        goto exit1;

    pSymCtx->state = CTX_STATE_INIT;

    /* Allocate the new wrapper */
    status = DIGI_CALLOC((void **) &pNewCtx, 1, sizeof(aesCipherContext));
    if (OK != status)
        goto exit1;

    /* Transfer control of the underlying MocSymCtx to the wrapper */
    pNewCtx->pMocSymCtx = pSymCtx; pSymCtx = NULL;
    pSymKey->pKeyData = NULL;

    /* Mark this object as crypto interface enabled */
    pNewCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

    *ppNewCtx = pNewCtx;
    pNewCtx = NULL;

exit1:

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"CI AES-CTR TAP Encrypt failed with status = ", status);

        if (!pTapData->isDeferUnload)
        {
            if (OK > (status2 = TAP_unloadKey(pTapKey, pErrContext)))
            {
                DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"TAP_unloadKey failed with status = ", status2);
            }
            pTapData->isKeyLoaded = FALSE;
        }
    }

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status2 = g_pFuncPtrGetTapContext(&pTapContext,
                        &pEntityCredentials,
                        &pKeyCredentials,
                        (void *)pSymCtx, tap_aes_encrypt, 0/*release context*/)))
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

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_AesCtrDeferKeyUnload (
    BulkCtx pCtx,
    byteBoolean deferredTokenUnload
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    aesCTRCipherContext *pAesCtx = (aesCTRCipherContext *) pCtx;

    if (NULL == pCtx)
        return ERR_NULL_POINTER;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != pAesCtx->enabled)
        return ERR_TAP_INVALID_KEY_TYPE;

    return CRYPTO_INTERFACE_TAP_SymDeferUnload(pAesCtx->pMocSymCtx, deferredTokenUnload);

#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_TAP__
extern MSTATUS CRYPTO_INTERFACE_TAP_AesCtrGetKeyInfo (
    BulkCtx pCtx,
    TAP_TokenHandle *pTokenHandle,
    TAP_KeyHandle *pKeyHandle
    )
{
    aesCTRCipherContext *pAesCtx = (aesCTRCipherContext *) pCtx;

    if (NULL == pAesCtx) /* other params validated in below call */
        return ERR_NULL_POINTER;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != pAesCtx->enabled)
        return ERR_TAP_INVALID_KEY_TYPE;

    return CRYPTO_INTERFACE_TAP_SymGetKeyInfo (pAesCtx->pMocSymCtx, pTokenHandle, pKeyHandle);
}
#endif /* __ENABLE_DIGICERT_TAP__ */

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_DoAESCTR (
    MocSymCtx pCtx,
    ubyte* pData,
    sbyte4 dataLength,
    ubyte* pIv
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER;
    MTapKeyData *pTapData = NULL;
    TAP_Key *pTapKey = NULL;
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_Buffer plainText = {0};
    TAP_Buffer cipherText = {0};

    MOC_UNUSED(pIv);

    if (NULL == pCtx || NULL == pCtx->pLocalData || NULL == pData)
        goto exit;

    /* dataLength does not have to be a multiple of 16 */

    status = ERR_CRYPTO_CTX_STATE;  /* TO DO can we reset the IV here for state CREATE */
    if (CTX_STATE_INIT != pCtx->state)
        goto exit;

    pTapData = (MTapKeyData *) pCtx->pLocalData;
    pTapKey = (TAP_Key *)pTapData->pKey;

    plainText.pBuffer = pData;
    plainText.bufferLen = dataLength;

    status = TAP_symEncryptUpdate(pTapKey, pTapData->pEntityCredentials, NULL, pTapData->symMode,
                                  &plainText, &cipherText, pErrContext);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY (pData, cipherText.pBuffer, cipherText.bufferLen);

exit:

    if (NULL != cipherText.pBuffer)
    {
        (void) TAP_UTILS_freeBuffer(&cipherText);
    }

    return status;

#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_DeleteAESCTRCtx (
    MocSymCtx pCtx
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER;
    MTapKeyData *pTapData = NULL;
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;

    if (NULL == pCtx || NULL == pCtx->pLocalData)
        goto exit;

    pTapData = (MTapKeyData *) pCtx->pLocalData;

    status = TAP_symEncryptFinal(pTapData->pKey, pTapData->pEntityCredentials,
                                 pTapData->pKeyAttributes, pTapData->symMode, NULL, pErrContext);

#ifndef __ENABLE_DIGICERT_PKCS11_DEBUG_PURGE_ALL_OBJ__
    if (!pTapData->isDeferUnload)
    {
        MSTATUS status2 = TAP_unloadKey(pTapData->pKey, pErrContext);
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

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}
