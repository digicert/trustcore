/*
 * crypto_interface_aes_gcm_tap.c
 *
 * Cryptographic Interface specification for AES GCM TAP.
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
#include "../crypto_interface/crypto_interface_aes_gcm.h"
#include "../crypto_interface/crypto_interface_sym_tap.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "../tap/tap.h"
#include "../tap/tap_smp.h"
#include "../tap/tap_api.h"
#include "../tap/tap_utils.h"
#include "../crypto/aes.h"
#include "../crypto/aesalgo.h"
#include "../crypto/aes_ctr.h"
#include "../crypto/gcm.h"
#include "../crypto/mocsymalgs/tap/symtap.h"
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_aes_tap.h"
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_getAesGcmCtxFromSymmetricKeyAlloc(
    SymmetricKey *pSymKey,
    BulkCtx *ppNewCtx,
    sbyte4 mode,
    sbyte4 encrypt
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER;
    MocSymCtx pSymCtx = NULL;
    MTapKeyData *pAesTapData = NULL;
#ifdef __ENABLE_DIGICERT_GCM_256B__
    gcm_ctx_256b *pCtx256b = NULL;
#endif
#ifdef __ENABLE_DIGICERT_GCM_4K__
    gcm_ctx_4k *pCtx4k = NULL;
#endif
#ifdef __ENABLE_DIGICERT_GCM_64K__
    gcm_ctx_64k *pCtx64k = NULL;
#endif
    AES_GCM_CTX *pCtxGen = NULL;

    if ( (NULL == pSymKey) || (NULL == pSymKey->pKeyData) || (NULL == ppNewCtx) )
    {
        goto exit;
    }

    pSymCtx = (MocSymCtx)pSymKey->pKeyData;
    pAesTapData = (MTapKeyData *)pSymCtx->pLocalData;

    if (NULL == pAesTapData)
        goto exit;

    /* This key must be for mode-less AES or mode-bound AES-GCM */
    status = ERR_INVALID_INPUT;
    if ( (MOC_SYM_ALG_AES != pSymKey->keyType) &&
         (MOC_SYM_ALG_AES_GCM != pSymKey->keyType) )
    {
        goto exit;
    }

    pAesTapData->symMode = TAP_SYM_KEY_MODE_GCM;
    pAesTapData->direction = encrypt ? MOCANA_SYM_TAP_ENCRYPT : MOCANA_SYM_TAP_DECRYPT;

    /* Allocate the new wrapper */
    switch(mode)
    {
#ifdef __ENABLE_DIGICERT_GCM_256B__
        case GCM_MODE_256B:
            status = DIGI_CALLOC((void **) &pCtx256b, 1, sizeof(gcm_ctx_256b));
            if (OK != status)
                goto exit;

            pCtx256b->encrypt = encrypt;
            pCtx256b->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

            /* Transfer ownership of the underlying MocSymCtx to the newly
             * allocated wrapper */
            pCtx256b->pMocSymCtx = pSymCtx;
            pSymKey->pKeyData = NULL;
            *ppNewCtx = (BulkCtx) pCtx256b;
            pCtx256b = NULL;
            break;
#endif
#ifdef __ENABLE_DIGICERT_GCM_4K__
        case GCM_MODE_4K:
            status = DIGI_CALLOC((void **) &pCtx4k, 1, sizeof(gcm_ctx_4k));
            if (OK != status)
                goto exit;

            pCtx4k->encrypt = encrypt;
            pCtx4k->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

            /* Transfer ownership of the underlying MocSymCtx to the newly
             * allocated wrapper */
            pCtx4k->pMocSymCtx = pSymCtx;
            pSymKey->pKeyData = NULL;
            *ppNewCtx = (BulkCtx) pCtx4k;
            pCtx4k = NULL;
            break;
#endif
#ifdef __ENABLE_DIGICERT_GCM_64K__
        case GCM_MODE_64K:
            status = DIGI_CALLOC((void **) &pCtx64k, 1, sizeof(gcm_ctx_64k));
            if (OK != status)
                goto exit;

            pCtx64k->encrypt = encrypt;
            pCtx64k->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

            /* Transfer ownership of the underlying MocSymCtx to the newly
             * allocated wrapper */
            pCtx64k->pMocSymCtx = pSymCtx;
            pSymKey->pKeyData = NULL;
            *ppNewCtx = (BulkCtx) pCtx64k;
            pCtx64k = NULL;
            break;
#endif
        case GCM_MODE_GENERAL:
            status = DIGI_CALLOC((void **) &pCtxGen, 1, sizeof(AES_GCM_CTX));
            if (OK != status)
                goto exit;

            pCtxGen->pMocSymCtx = pSymCtx;
            pCtxGen->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;
            pSymKey->pKeyData = NULL;
            *ppNewCtx = (BulkCtx) pCtxGen;
            pCtxGen = NULL;

            break;
        default:
            goto exit;
    }

exit:

#ifdef __ENABLE_DIGICERT_GCM_256B__
    if (NULL != pCtx256b)
    {
        DIGI_FREE((void **)&pCtx256b);
    }
#endif
#ifdef __ENABLE_DIGICERT_GCM_4K__
    if (NULL != pCtx4k)
    {
        DIGI_FREE((void **)&pCtx4k);
    }
#endif
#ifdef __ENABLE_DIGICERT_GCM_64K__
    if (NULL != pCtx64k)
    {
        DIGI_FREE((void **)&pCtx64k);
    }
#endif
    if (NULL != pCtxGen)
    {
        DIGI_FREE((void **)&pCtxGen);
    }

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_AesGcmDeferKeyUnload (
    BulkCtx pCtx,
    sbyte4 mode,
    byteBoolean deferredTokenUnload
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER;

    /* Cast to each but we'll only use the correct context */
#ifdef __ENABLE_DIGICERT_GCM_256B__
    gcm_ctx_256b *pCtx256b = (gcm_ctx_256b *) pCtx;
#endif
#ifdef __ENABLE_DIGICERT_GCM_4K__
    gcm_ctx_4k *pCtx4k = (gcm_ctx_4k *) pCtx;
#endif
#ifdef __ENABLE_DIGICERT_GCM_64K__
    gcm_ctx_64k *pCtx64k = (gcm_ctx_64k *) pCtx;
#endif
    AES_GCM_CTX *pGenCtx = (AES_GCM_CTX *) pCtx;

    if (NULL == pCtx)
        goto exit;

    status = ERR_TAP_INVALID_KEY_TYPE;
    switch(mode)
    {
#ifdef __ENABLE_DIGICERT_GCM_256B__
        case GCM_MODE_256B:

            if (CRYPTO_INTERFACE_ALGO_ENABLED != pCtx256b->enabled)
                goto exit;

            status = CRYPTO_INTERFACE_TAP_SymDeferUnload(pCtx256b->pMocSymCtx, deferredTokenUnload);
            break;
#endif
#ifdef __ENABLE_DIGICERT_GCM_4K__
        case GCM_MODE_4K:

            if (CRYPTO_INTERFACE_ALGO_ENABLED != pCtx4k->enabled)
                goto exit;

            status = CRYPTO_INTERFACE_TAP_SymDeferUnload(pCtx4k->pMocSymCtx, deferredTokenUnload);
            break;
#endif
#ifdef __ENABLE_DIGICERT_GCM_64K__
        case GCM_MODE_64K:

            if (CRYPTO_INTERFACE_ALGO_ENABLED != pCtx64k->enabled)
                goto exit;

            status = CRYPTO_INTERFACE_TAP_SymDeferUnload(pCtx64k->pMocSymCtx, deferredTokenUnload);
            break;
#endif
        case GCM_MODE_GENERAL:

            if (CRYPTO_INTERFACE_ALGO_ENABLED != pGenCtx->enabled)
                goto exit;

            status = CRYPTO_INTERFACE_TAP_SymDeferUnload(pGenCtx->pMocSymCtx, deferredTokenUnload);
            break;

        default:
            status = ERR_INVALID_INPUT;
    }

exit:

    return status;

#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_TAP__
extern MSTATUS CRYPTO_INTERFACE_TAP_AesGcmGetKeyInfo (
    BulkCtx pCtx,
    sbyte4 mode,
    TAP_TokenHandle *pTokenHandle,
    TAP_KeyHandle *pKeyHandle
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    /* Cast to each but we'll only use the correct context */
#ifdef __ENABLE_DIGICERT_GCM_256B__
    gcm_ctx_256b *pCtx256b = (gcm_ctx_256b *) pCtx;
#endif
#ifdef __ENABLE_DIGICERT_GCM_4K__
    gcm_ctx_4k *pCtx4k = (gcm_ctx_4k *) pCtx;
#endif
#ifdef __ENABLE_DIGICERT_GCM_64K__
    gcm_ctx_64k *pCtx64k = (gcm_ctx_64k *) pCtx;
#endif
    AES_GCM_CTX *pGenCtx = (AES_GCM_CTX *) pCtx;

    if (NULL == pCtx) /* other params validated in below calls */
        goto exit;

    status = ERR_TAP_INVALID_KEY_TYPE;;
    switch(mode)
    {
#ifdef __ENABLE_DIGICERT_GCM_256B__
        case GCM_MODE_256B:

            if (CRYPTO_INTERFACE_ALGO_ENABLED != pCtx256b->enabled)
                goto exit;

            status = CRYPTO_INTERFACE_TAP_SymGetKeyInfo (pCtx256b->pMocSymCtx, pTokenHandle, pKeyHandle);
            break;
#endif
#ifdef __ENABLE_DIGICERT_GCM_4K__
        case GCM_MODE_4K:

            if (CRYPTO_INTERFACE_ALGO_ENABLED != pCtx4k->enabled)
                goto exit;

            status = CRYPTO_INTERFACE_TAP_SymGetKeyInfo (pCtx4k->pMocSymCtx, pTokenHandle, pKeyHandle);
            break;
#endif
#ifdef __ENABLE_DIGICERT_GCM_64K__
        case GCM_MODE_64K:

            if (CRYPTO_INTERFACE_ALGO_ENABLED != pCtx64k->enabled)
                goto exit;

            status = CRYPTO_INTERFACE_TAP_SymGetKeyInfo (pCtx64k->pMocSymCtx, pTokenHandle, pKeyHandle);
            break;
#endif
        case GCM_MODE_GENERAL:

            if (CRYPTO_INTERFACE_ALGO_ENABLED != pGenCtx->enabled)
                goto exit;

            status = CRYPTO_INTERFACE_TAP_SymGetKeyInfo (pGenCtx->pMocSymCtx, pTokenHandle, pKeyHandle);
            break;

        default:
            status = ERR_INVALID_INPUT;
    }

exit:

    return status;
}
#endif /* __ENABLE_DIGICERT_TAP__ */

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_GCM_init (
    MocSymCtx pCtx,
    ubyte *pNonce,
    ubyte4 nonceLen,
    ubyte *pAaData,
    ubyte4 aadLen,
    ubyte4 tagLenBytes,
    sbyte4 encrypt
    )
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
    TAP_Buffer nonce = {0};
    TAP_Buffer aad = {0};
    TAP_AttributeList opAttributes = { 0, };
    ubyte4 tagLenBits = tagLenBytes * 8;
    ubyte4 numAttrs;
    TapOperation op;

    if ( (NULL == pCtx) || (NULL == pCtx->pLocalData) || (NULL == pNonce) )
    {
        goto exit;
    }

    if (TRUE == encrypt)
    {
        op = tap_aes_encrypt;
    }
    else
    {
        op = tap_aes_decrypt;
    }

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status = g_pFuncPtrGetTapContext(&pTapContext,
                        &pEntityCredentials,
                        &pKeyCredentials,
                        (void *)pCtx, op, 1/*get context*/)))
        {
            goto exit;
        }
    }
    else
    {
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
    }

    pTapData = (MTapKeyData *)pCtx->pLocalData;
    pTapKey = pTapData->pKey;

    if (!pTapData->isKeyLoaded)
    {
        status = TAP_loadKey(pTapContext, pEntityCredentials, pTapKey, pKeyCredentials, NULL, pErrContext);
        if (OK != status)
            goto exit1;

        pTapData->isKeyLoaded = TRUE;
    }

    if ( (NULL != pAaData) && (0 != aadLen) )
    {
        numAttrs = 2;
    }
    else
    {
        numAttrs = 1;
    }

    /* Allocate the atribute list to send the GCM tag size and optional additional auth data */
    status = DIGI_CALLOC((void **)&opAttributes.pAttributeList, 1, numAttrs * sizeof(TAP_Attribute));
    if (OK != status)
        goto exit1;

    /* We always send the tag len */
    opAttributes.listLen = numAttrs;
    opAttributes.pAttributeList[0].type = TAP_ATTR_TAG_LEN_BITS;
    opAttributes.pAttributeList[0].length = sizeof(tagLenBits);
    opAttributes.pAttributeList[0].pStructOfType = (void *)&tagLenBits;

    /* AAD is optional */
    if (2 == numAttrs)
    {
        aad.pBuffer = pAaData;
        aad.bufferLen = aadLen;
        opAttributes.pAttributeList[1].type = TAP_ATTR_ADDITIONAL_AUTH_DATA;
        opAttributes.pAttributeList[1].length = sizeof(TAP_Buffer);
        opAttributes.pAttributeList[1].pStructOfType = &aad;
    }

    nonce.pBuffer = pNonce;
    nonce.bufferLen = nonceLen;

    if (TRUE == encrypt)
    {
        status = TAP_symEncryptInit (
            pTapKey, pEntityCredentials, &opAttributes, pTapData->symMode, &nonce, pErrContext);
        if (OK != status)
            goto exit;
    }
    else
    {
        status = TAP_symDecryptInit (
            pTapKey, pEntityCredentials, &opAttributes, pTapData->symMode, &nonce, pErrContext);
        if (OK != status)
            goto exit;
    }

    pCtx->state = CTX_STATE_INIT;

exit1:

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"CI AES TAP GCM init failed with status = ", status);

        if(!pTapData->isDeferUnload)
        {
            if (OK > (status2 = TAP_unloadKey(pTapKey, pErrContext)))
            {
                DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"TAP_unloadKey failed with status = ", status2);
            }
            else
            {
                pTapData->isKeyLoaded = FALSE;
            }
        }
    }

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status2 = g_pFuncPtrGetTapContext(&pTapContext,
                        &pEntityCredentials,
                        &pKeyCredentials,
                       (void *)pCtx, op, 0/*release context*/)))
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

    if (NULL != opAttributes.pAttributeList)
    {
        (void) DIGI_FREE((void **)&(opAttributes.pAttributeList));
    }

    return status;

#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_GCM_update (
    MocSymCtx pCtx,
    ubyte *pInput,
    sbyte4 inputLen,
    ubyte *pOutput,
    sbyte4 encrypt
    )
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
    TAP_Buffer plainText = {0};
    TAP_Buffer cipherText = {0};
    ubyte *pBuf = NULL;
    ubyte4 bufLen = 0;
    TapOperation op;

    if ( (NULL == pCtx) || (NULL == pCtx->pLocalData) || (NULL == pInput) || (NULL == pOutput) )
    {
        goto exit;
    }

    status = ERR_CRYPTO_CTX_STATE;
    if (CTX_STATE_INIT != pCtx->state && CTX_STATE_UPDATE != pCtx->state)
        goto exit;

    if (TRUE == encrypt)
    {
        op = tap_aes_encrypt;
    }
    else
    {
        op = tap_aes_decrypt;
    }

    pTapData = (MTapKeyData *)pCtx->pLocalData;
    pTapKey = pTapData->pKey;

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status = g_pFuncPtrGetTapContext(&pTapContext,
                        &pEntityCredentials,
                        &pKeyCredentials,
                        (void *)pCtx, op, 1/*get context*/)))
        {
            goto exit;
        }
    }
    else
    {
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
    }

    if (TRUE == encrypt)
    {
        plainText.pBuffer = pInput;
        plainText.bufferLen = inputLen;

        status = TAP_symEncryptUpdate (
            pTapKey, pEntityCredentials, NULL, pTapData->symMode, &plainText,
            &cipherText, pErrContext);
        if (OK != status)
            goto exit1;

        pBuf = cipherText.pBuffer;
        bufLen = cipherText.bufferLen;
    }
    else
    {
        cipherText.pBuffer = pInput;
        cipherText.bufferLen = inputLen;

        status = TAP_symDecryptUpdate (
            pTapKey, pEntityCredentials, NULL, pTapData->symMode, &cipherText,
            &plainText, pErrContext);
        if (OK != status)
            goto exit1;

        pBuf = plainText.pBuffer;
        bufLen = plainText.bufferLen;
    }

    if (NULL != pBuf)
    {
        status = DIGI_MEMCPY(pOutput, pBuf, bufLen);
        if (OK != status)
            goto exit1;
    }

    pCtx->state = CTX_STATE_UPDATE;

exit1:

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"CI AES TAP GCM Update failed with status = ", status);

        if(!pTapData->isDeferUnload)
        {
            if (OK > (status2 = TAP_unloadKey(pTapKey, pErrContext)))
            {
                DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"TAP_unloadKey failed with status = ", status2);
            }
            else
            {
                pTapData->isKeyLoaded = FALSE;
            }
        }
    }

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status2 = g_pFuncPtrGetTapContext(&pTapContext,
                        &pEntityCredentials,
                        &pKeyCredentials,
                        (void *)pCtx, op, 0/*release context*/)))
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

    if (NULL != pBuf)
    {
        (void) DIGI_FREE((void **)&pBuf);
    }

    return status;

#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_GCM_final (
    MocSymCtx pCtx,
    ubyte *pTag,
    ubyte4 tagLenBytes,
    ubyte **ppDecryptedData,
    ubyte4 *pDecryptedDataLen,
    sbyte4 encrypt
    )
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
    TAP_Buffer cipherText = {0};
    TAP_Buffer plainText = {0};
    TapOperation op;

    if (NULL == pCtx)
        goto exit;

    status = ERR_CRYPTO_CTX_STATE;
    if (CTX_STATE_UPDATE != pCtx->state)
        goto exit;

    if (TRUE == encrypt)
    {
        if (NULL == pTag)
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }
        op = tap_aes_encrypt;
    }
    else
    {
        if ( (NULL == ppDecryptedData) || (NULL == pDecryptedDataLen) )
        {
            status = ERR_NULL_POINTER;
            goto exit;
        }

        op = tap_aes_decrypt;
    }

    pTapData = (MTapKeyData *)pCtx->pLocalData;
    pTapKey = pTapData->pKey;

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status = g_pFuncPtrGetTapContext(&pTapContext,
                        &pEntityCredentials,
                        &pKeyCredentials,
                        (void *)pCtx, op, 1/*get context*/)))
        {
            goto exit;
        }
    }
    else
    {
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
    }

    if (TRUE == encrypt)
    {
        status = TAP_symEncryptFinal (
            pTapKey, pEntityCredentials, NULL, pTapData->symMode, &cipherText,
            pErrContext);
        if (OK != status)
            goto exit1;

        status = DIGI_MEMCPY(pTag, cipherText.pBuffer, cipherText.bufferLen);
        if (OK != status)
            goto exit1;
    }
    else
    {
        if (NULL != pTag)
        {
            cipherText.pBuffer = pTag;
            cipherText.bufferLen = tagLenBytes;

            /* Update with the tag data */
            status = TAP_symDecryptUpdate (
                pTapKey, pEntityCredentials, NULL, pTapData->symMode, &cipherText,
                &plainText, pErrContext);
            if (OK != status)
                goto exit1;
        }

        /* Finalize to get back all the decrypted data */
        status = TAP_symDecryptFinal (
            pTapKey, pEntityCredentials, NULL, pTapData->symMode, &plainText,
            pErrContext);
        if (OK != status)
            goto exit1;

        *ppDecryptedData = plainText.pBuffer;
        *pDecryptedDataLen = plainText.bufferLen;
    }

    pCtx->state = CTX_STATE_FINAL;

exit1:

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"CI AES TAP GCM Final failed with status = ", status);

        if(!pTapData->isDeferUnload)
        {
            if (OK > (status2 = TAP_unloadKey(pTapKey, pErrContext)))
            {
                DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"TAP_unloadKey failed with status = ", status2);
            }
            else
            {
                pTapData->isKeyLoaded = FALSE;
            }
        }
    }

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status2 = g_pFuncPtrGetTapContext(&pTapContext,
                        &pEntityCredentials,
                        &pKeyCredentials,
                        (void *)pCtx, op, 0/*release context*/)))
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

    if (NULL != cipherText.pBuffer)
    {
        (void) DIGI_MEMSET_FREE(&cipherText.pBuffer, cipherText.bufferLen);
    }

    return status;

#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_TAP__
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_GCM_encrypt(
    MocSymCtx pCtx,
    ubyte *pNonce,
    ubyte4 *pNonceLen,
    intBoolean *pWasNonceUsed,
    ubyte *pAad,
    ubyte4 aadLen,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte4 tagLenBytes)
{
    MSTATUS status = ERR_NULL_POINTER;
    MSTATUS status2 = OK;
    MTapKeyData *pTapData = NULL;
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_Context *pTapContext = NULL;
    TAP_Key *pTapKey = NULL;
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_Buffer nonce = {0};
    TAP_Buffer aad = {0};
    TAP_Buffer plainText = {0};
    TAP_Buffer cipherText = {0};
    TAP_AttributeList opAttributes = { 0, };
    ubyte4 tagLenBits = tagLenBytes * 8;
    ubyte4 numAttrs = 0;
    ubyte pNonceCopy[16] = {0};
    sbyte4 compare = -1;

    if (NULL == pCtx || NULL == pCtx->pLocalData || NULL == pNonce || NULL == pNonceLen || NULL == pWasNonceUsed)
    {
        goto exit;
    }

    if (*pNonceLen > sizeof(pNonceCopy))
    {
        status = ERR_BAD_LENGTH;
        goto exit;
    }

    status = DIGI_MEMCPY(pNonceCopy, pNonce, *pNonceLen);
    if (OK != status)
        goto exit;

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status = g_pFuncPtrGetTapContext(&pTapContext,
                        &pEntityCredentials,
                        &pKeyCredentials,
                        (void *)pCtx, tap_aes_encrypt, 1/*get context*/)))
        {
            goto exit;
        }
    }
    else
    {
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
    }

    pTapData = (MTapKeyData *)pCtx->pLocalData;
    pTapKey = pTapData->pKey;

    if (!pTapData->isKeyLoaded)
    {
        status = TAP_loadKey(pTapContext, pEntityCredentials, pTapKey, pKeyCredentials, NULL, pErrContext);
        if (OK != status)
            goto exit1;

        pTapData->isKeyLoaded = TRUE;
    }

    if ( (NULL != pAad) && (0 != aadLen) )
    {
        numAttrs = 2;
    }
    else
    {
        numAttrs = 1;
    }

    /* Allocate the atribute list to send the GCM tag size and optional additional auth data */
    status = DIGI_CALLOC((void **)&opAttributes.pAttributeList, 1, numAttrs * sizeof(TAP_Attribute));
    if (OK != status)
        goto exit1;

    /* We always send the tag len */
    opAttributes.listLen = numAttrs;
    opAttributes.pAttributeList[0].type = TAP_ATTR_TAG_LEN_BITS;
    opAttributes.pAttributeList[0].length = sizeof(tagLenBits);
    opAttributes.pAttributeList[0].pStructOfType = (void *)&tagLenBits;

    /* AAD is optional */
    if (2 == numAttrs)
    {
        aad.pBuffer = pAad;
        aad.bufferLen = aadLen;
        opAttributes.pAttributeList[1].type = TAP_ATTR_ADDITIONAL_AUTH_DATA;
        opAttributes.pAttributeList[1].length = sizeof(TAP_Buffer);
        opAttributes.pAttributeList[1].pStructOfType = &aad;
    }

    nonce.pBuffer = pNonce;
    nonce.bufferLen = *pNonceLen;

    plainText.pBuffer = pData;
    plainText.bufferLen = dataLen;

    status = TAP_symEncrypt(pTapKey, pEntityCredentials, &opAttributes, pTapData->symMode, &nonce, &plainText, &cipherText, pErrContext);
    if (OK != status)
        goto exit1;

    if (NULL != cipherText.pBuffer && cipherText.bufferLen)
    {
        status = DIGI_MEMCPY(pData, cipherText.pBuffer, cipherText.bufferLen);
        if (OK != status)
            goto exit1;
    }

    status = DIGI_MEMCMP(pNonce, pNonceCopy, *pNonceLen, &compare);
    if (OK != status)
        goto exit1;

    if (compare)
    {
        *pWasNonceUsed = FALSE;
    }
    else
    {
        *pWasNonceUsed = TRUE;
    }

    pCtx->state = CTX_STATE_FINAL;

exit1:

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"CI AES TAP GCM encrypt failed with status = ", status);

        if(!pTapData->isDeferUnload)
        {
            if (OK > (status2 = TAP_unloadKey(pTapKey, pErrContext)))
            {
                DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"TAP_unloadKey failed with status = ", status2);
            }
            else
            {
                pTapData->isKeyLoaded = FALSE;
            }
        }
    }

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status2 = g_pFuncPtrGetTapContext(&pTapContext,
                        &pEntityCredentials,
                        &pKeyCredentials,
                       (void *)pCtx, tap_aes_encrypt, 0/*release context*/)))
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

    if (NULL != cipherText.pBuffer)
    {
        (void) DIGI_MEMSET_FREE(&cipherText.pBuffer, cipherText.bufferLen);
    }

    if (NULL != opAttributes.pAttributeList)
    {
        (void) DIGI_FREE((void **)&(opAttributes.pAttributeList));
    }

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_GCM_decrypt(
    MocSymCtx pCtx,
    ubyte *pNonce,
    ubyte4 nonceLen,
    ubyte *pAad,
    ubyte4 aadLen,
    ubyte *pData,
    ubyte4 dataLen,
    ubyte4 tagLenBytes)
{
    MSTATUS status = ERR_NULL_POINTER;
    MSTATUS status2 = OK;
    MTapKeyData *pTapData = NULL;
    TAP_CredentialList *pKeyCredentials = NULL;
    TAP_EntityCredentialList *pEntityCredentials = NULL;
    TAP_Context *pTapContext = NULL;
    TAP_Key *pTapKey = NULL;
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;
    TAP_Buffer nonce = {0};
    TAP_Buffer aad = {0};
    TAP_Buffer plainText = {0};
    TAP_Buffer cipherText = {0};
    TAP_AttributeList opAttributes = { 0, };
    ubyte4 tagLenBits = tagLenBytes * 8;
    ubyte4 numAttrs = 0;

    if (NULL == pCtx || NULL == pCtx->pLocalData || NULL == pNonce)
    {
        goto exit;
    }

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status = g_pFuncPtrGetTapContext(&pTapContext,
                        &pEntityCredentials,
                        &pKeyCredentials,
                        (void *)pCtx, tap_aes_decrypt, 1/*get context*/)))
        {
            goto exit;
        }
    }
    else
    {
        status = ERR_NOT_IMPLEMENTED;
        goto exit;
    }

    pTapData = (MTapKeyData *)pCtx->pLocalData;
    pTapKey = pTapData->pKey;

    if (!pTapData->isKeyLoaded)
    {
        status = TAP_loadKey(pTapContext, pEntityCredentials, pTapKey, pKeyCredentials, NULL, pErrContext);
        if (OK != status)
            goto exit1;

        pTapData->isKeyLoaded = TRUE;
    }

    if ( (NULL != pAad) && (0 != aadLen) )
    {
        numAttrs = 2;
    }
    else
    {
        numAttrs = 1;
    }

    /* Allocate the atribute list to send the GCM tag size and optional additional auth data */
    status = DIGI_CALLOC((void **)&opAttributes.pAttributeList, 1, numAttrs * sizeof(TAP_Attribute));
    if (OK != status)
        goto exit1;

    /* We always send the tag len */
    opAttributes.listLen = numAttrs;
    opAttributes.pAttributeList[0].type = TAP_ATTR_TAG_LEN_BITS;
    opAttributes.pAttributeList[0].length = sizeof(tagLenBits);
    opAttributes.pAttributeList[0].pStructOfType = (void *)&tagLenBits;

    /* AAD is optional */
    if (2 == numAttrs)
    {
        aad.pBuffer = pAad;
        aad.bufferLen = aadLen;
        opAttributes.pAttributeList[1].type = TAP_ATTR_ADDITIONAL_AUTH_DATA;
        opAttributes.pAttributeList[1].length = sizeof(TAP_Buffer);
        opAttributes.pAttributeList[1].pStructOfType = &aad;
    }

    nonce.pBuffer = pNonce;
    nonce.bufferLen = nonceLen;

    cipherText.pBuffer = pData;
    cipherText.bufferLen = dataLen + tagLenBytes; /* include the tag as part of the ciphertext */

    status = TAP_symDecrypt(pTapKey, pEntityCredentials, &opAttributes, pTapData->symMode, &nonce, &cipherText, &plainText, pErrContext);
    if (OK != status)
        goto exit1;

    if (NULL != plainText.pBuffer && plainText.bufferLen)
    {
        status = DIGI_MEMCPY(pData, plainText.pBuffer, plainText.bufferLen);
        if (OK != status)
            goto exit1;
    }

    pCtx->state = CTX_STATE_FINAL;

exit1:

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"CI AES TAP GCM decrypt failed with status = ", status);

        if(!pTapData->isDeferUnload)
        {
            if (OK > (status2 = TAP_unloadKey(pTapKey, pErrContext)))
            {
                DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"TAP_unloadKey failed with status = ", status2);
            }
            else
            {
                pTapData->isKeyLoaded = FALSE;
            }
        }
    }

    if (g_pFuncPtrGetTapContext != NULL)
    {
        if (OK > (status2 = g_pFuncPtrGetTapContext(&pTapContext,
                        &pEntityCredentials,
                        &pKeyCredentials,
                       (void *)pCtx, tap_aes_decrypt, 0/*release context*/)))
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

    if (NULL != plainText.pBuffer)
    {
        (void) DIGI_MEMSET_FREE(&plainText.pBuffer, plainText.bufferLen);
    }

    if (NULL != opAttributes.pAttributeList)
    {
        (void) DIGI_FREE((void **)&(opAttributes.pAttributeList));
    }

    return status;
}
#endif


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_DeleteAESGCMCtx (
    MocSymCtx pCtx
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER;
    MSTATUS status2 = OK;
    MTapKeyData *pTapData = NULL;
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;

    if (NULL == pCtx || NULL == pCtx->pLocalData)
        goto exit;

    pTapData = (MTapKeyData *) pCtx->pLocalData;
    
    status = OK;
    if(CTX_STATE_INIT == pCtx->state || CTX_STATE_UPDATE == pCtx->state)
    {
        if (MOCANA_SYM_TAP_ENCRYPT == pTapData->direction)
        {
            status = TAP_symEncryptFinal(pTapData->pKey, pTapData->pEntityCredentials, NULL, pTapData->symMode, NULL, pErrContext);
        }
        else if (MOCANA_SYM_TAP_DECRYPT == pTapData->direction)
        {
            status = TAP_symDecryptFinal(pTapData->pKey, pTapData->pEntityCredentials, NULL, pTapData->symMode, NULL, pErrContext);
        }
        else
        {
            status = ERR_INVALID_INPUT;
        }
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

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}
