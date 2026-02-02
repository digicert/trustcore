/*
 * crypto_interface_aes_tap.c
 *
 * Cryptographic Interface specification for AES TAP.
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
#include "../crypto/mocsymalgs/tap/symtap.h"
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_aes_tap.h"
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_AESALGO_blockEncrypt (
    MocSymCtx pCtx,
    ubyte *pIv,
    ubyte *pInput,
    sbyte4 inputLen,
    ubyte *pOutBuffer,
    sbyte4 *pRetLength
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

    if (NULL == pCtx || NULL == pCtx->pLocalData || NULL == pOutBuffer || NULL == pInput || NULL == pRetLength)
        goto exit;

    /* inputLen is in bits, make sure its a multiple of the block size 128 */
    status = ERR_INVALID_INPUT;
    if (inputLen & (sbyte4) 0x7f)
        goto exit;

    status = ERR_CRYPTO_CTX_STATE;
    if (CTX_STATE_CREATE != pCtx->state && CTX_STATE_INIT != pCtx->state)
        goto exit;

    pTapData = (MTapKeyData *) pCtx->pLocalData;
    pTapKey = (TAP_Key *)pTapData->pKey;

    status = ERR_WRONG_CTX_TYPE;
    if (MOCANA_SYM_TAP_ENCRYPT != pTapData->direction)
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

    if (CTX_STATE_CREATE == pCtx->state)
    {
        TAP_Buffer iv = {0};

        if (!pTapData->isKeyLoaded)
        {
            status = TAP_loadKey(pTapContext, pEntityCredentials, pTapKey, pKeyCredentials,
                                pTapData->pKeyAttributes, pErrContext);
            if (OK != status)
                goto exit1;

            pTapData->isKeyLoaded = TRUE;
        }

        iv.pBuffer = pIv;
        iv.bufferLen = (NULL != pIv) ? 16 : 0;

        status = TAP_symEncryptInit(pTapKey, pEntityCredentials, NULL, pTapData->symMode,
                            &iv, pErrContext);
        if (OK != status)
            goto exit1;

        pCtx->state = CTX_STATE_INIT;
    }

    plainText.pBuffer = pInput;
    plainText.bufferLen = inputLen/8; /* convert to bytes */

    status = TAP_symEncryptUpdate(pTapKey, pEntityCredentials, NULL, pTapData->symMode,
                                  &plainText, &cipherText, pErrContext);
    if (OK != status)
        goto exit1;

    status = DIGI_MEMCPY (pOutBuffer, cipherText.pBuffer, cipherText.bufferLen);
    if (OK != status)
        goto exit1;

    *pRetLength = (sbyte4) (cipherText.bufferLen * 8); /* convert back to bits */

exit1:

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"CI AES TAP Encrypt failed with status = ", status);

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
        (void) TAP_UTILS_freeBuffer(&cipherText);
    }

    return status;

#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_AESALGO_blockDecrypt (
    MocSymCtx pCtx,
    ubyte *pIv,
    ubyte *pInput,
    sbyte4 inputLen,
    ubyte *pOutBuffer,
    sbyte4 *pRetLength
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

    if (NULL == pCtx || NULL == pCtx->pLocalData || NULL == pOutBuffer || NULL == pInput || NULL == pRetLength)
        goto exit;

    /* inputLen is in bits, make sure its a multiple of the block size 128 */
    status = ERR_INVALID_INPUT;
    if (inputLen & (sbyte4) 0x7f)
        goto exit;

    status = ERR_CRYPTO_CTX_STATE;
    if (CTX_STATE_CREATE != pCtx->state && CTX_STATE_INIT != pCtx->state)
        goto exit;

    pTapData = (MTapKeyData *) pCtx->pLocalData;
    pTapKey = (TAP_Key *)pTapData->pKey;

    status = ERR_WRONG_CTX_TYPE;
    if (MOCANA_SYM_TAP_DECRYPT != pTapData->direction)
        goto exit;

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

    if (CTX_STATE_CREATE == pCtx->state)
    {
        TAP_Buffer iv = {0};

        if (!pTapData->isKeyLoaded)
        {
            status = TAP_loadKey(pTapContext, pEntityCredentials, pTapKey, pKeyCredentials, NULL, pErrContext);
            if (OK != status)
                goto exit1;

            pTapData->isKeyLoaded = TRUE;
        }

        iv.pBuffer = pIv;
        iv.bufferLen = (NULL != pIv) ? 16 : 0;

        status = TAP_symDecryptInit(pTapKey, pEntityCredentials, pTapData->pKeyAttributes, pTapData->symMode,
                            &iv, pErrContext);
        if (OK != status)
            goto exit1;

        pCtx->state = CTX_STATE_INIT;
    }

    cipherText.pBuffer = pInput;
    cipherText.bufferLen = inputLen/8;  /* convert to bytes */

    status = TAP_symDecryptUpdate(pTapKey, pEntityCredentials, pTapData->pKeyAttributes, pTapData->symMode,
                                  &cipherText, &plainText, pErrContext);
    if (OK != status)
        goto exit1;

    status = DIGI_MEMCPY (pOutBuffer, plainText.pBuffer, plainText.bufferLen);
    if (OK != status)
        goto exit1;

    *pRetLength = (sbyte4) (plainText.bufferLen * 8); /* convert back to bits */

exit1:

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"CI AES TAP Decrypt failed with status = ", status);

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
        (void) TAP_UTILS_freeBuffer(&plainText);
    }

    return status;

#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_TAP__
static MSTATUS CRYPTO_INTERFACE_TAP_finalizeCtx(
    MocSymCtx pCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MSTATUS status2 = OK;
    MTapKeyData *pTapData = NULL;
    TAP_ErrorContext errContext = {0};
    TAP_ErrorContext *pErrContext = &errContext;

    if (NULL == pCtx || NULL == pCtx->pLocalData)
        goto exit;

    pTapData = (MTapKeyData *) pCtx->pLocalData;

    if (MOCANA_SYM_TAP_ENCRYPT == pTapData->direction)
    {
        status = TAP_symEncryptFinal(pTapData->pKey, pTapData->pEntityCredentials,
                                     pTapData->pKeyAttributes, pTapData->symMode, NULL, pErrContext);
    }
    else if (MOCANA_SYM_TAP_DECRYPT == pTapData->direction)
    {
        status = TAP_symDecryptFinal(pTapData->pKey, pTapData->pEntityCredentials,
                                     pTapData->pKeyAttributes, pTapData->symMode, NULL, pErrContext);
    }
    else
    {
        status = ERR_INVALID_INPUT;
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
}
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_ResetAESCtx (
    MocSymCtx pCtx
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = CRYPTO_INTERFACE_TAP_finalizeCtx(pCtx);
    if (OK != status)
        goto exit;

    /* set state back to CREATE for re-use */
    pCtx->state = CTX_STATE_CREATE;

exit:

    return status;

#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_DeleteAESCtx (
    MocSymCtx pCtx
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    return CRYPTO_INTERFACE_TAP_finalizeCtx(pCtx);
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_getAesCtxFromSymmetricKeyAlloc(
    SymmetricKey *pSymKey,
    BulkCtx *ppNewCtx,
    sbyte4 mode,
    sbyte4 encrypt
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER;
    aesCipherContext *pNewCtx = NULL;
    MocSymCtx pSymCtx = NULL;
    MTapKeyData *pAesTapData = NULL;

    if ( (NULL == pSymKey) || (NULL == pSymKey->pKeyData) || (NULL == ppNewCtx) )
    {
        goto exit;
    }

    pSymCtx = (MocSymCtx)pSymKey->pKeyData;
    pAesTapData = (MTapKeyData *)pSymCtx->pLocalData;

    if (NULL == pAesTapData)
        goto exit;

    pAesTapData->symMode = TAP_SYM_KEY_MODE_UNDEFINED;

    /* Set the internal mode of operation. If this key was mode-bound at
     * serialization time, the mode will be validated here */
    switch(mode)
    {
        case MODE_ECB:
            if ( (MOC_SYM_ALG_AES == pSymKey->keyType) ||
                 (MOC_SYM_ALG_AES_ECB == pSymKey->keyType) )
            {
                pAesTapData->symMode = TAP_SYM_KEY_MODE_ECB;
            }
            break;

        case MODE_CBC:
            if ( (MOC_SYM_ALG_AES == pSymKey->keyType) ||
                 (MOC_SYM_ALG_AES_CBC == pSymKey->keyType) )
            {
                pAesTapData->symMode = TAP_SYM_KEY_MODE_CBC;
            }
            break;

        case MODE_CFB128:
            if ( (MOC_SYM_ALG_AES == pSymKey->keyType) ||
                 (MOC_SYM_ALG_AES_CFB == pSymKey->keyType) )
            {
                pAesTapData->symMode = TAP_SYM_KEY_MODE_CFB;
            }
            break;

        case MODE_OFB:
            if ( (MOC_SYM_ALG_AES == pSymKey->keyType) ||
                 (MOC_SYM_ALG_AES_OFB == pSymKey->keyType) )
            {
                pAesTapData->symMode = TAP_SYM_KEY_MODE_OFB;
            }
            break;

        default:
            status = ERR_INVALID_INPUT;
            goto exit;
    }

    /* If symMode is still undefined we failed mode validation */
    status = ERR_INVALID_INPUT;
    if (TAP_SYM_KEY_MODE_UNDEFINED == pAesTapData->symMode)
        goto exit;

    /* Override the internal TAP structure sym mode */
    pAesTapData->pKey->keyData.algKeyInfo.aesInfo.symMode = pAesTapData->symMode;

    /* Set the direction */
    pAesTapData->direction = encrypt ? MOCANA_SYM_TAP_ENCRYPT : MOCANA_SYM_TAP_DECRYPT;

    /* Allocate the new wrapper */
    status = DIGI_CALLOC((void **) &pNewCtx, 1, sizeof(aesCipherContext));
    if (OK != status)
        goto exit;


    pNewCtx->encrypt = encrypt;

    /* Transfer control of the underlying MocSymCtx to the wrapper */
    pNewCtx->pMocSymCtx = pSymCtx; pSymCtx = NULL;
    pSymKey->pKeyData = NULL;

    /* Mark this object as crypto interface enabled */
    pNewCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

    *ppNewCtx = pNewCtx;
    pNewCtx = NULL;

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

extern MSTATUS CRYPTO_INTERFACE_TAP_AesDeferKeyUnload (
    BulkCtx pCtx,
    byteBoolean deferredTokenUnload
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    aesCipherContext *pAesCtx = (aesCipherContext *) pCtx;

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
extern MSTATUS CRYPTO_INTERFACE_TAP_AesGetKeyInfo (
    BulkCtx pCtx,
    TAP_TokenHandle *pTokenHandle,
    TAP_KeyHandle *pKeyHandle
    )
{
    aesCipherContext *pAesCtx = (aesCipherContext *) pCtx;

    if (NULL == pAesCtx) /* other params validated in below call */
        return ERR_NULL_POINTER;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != pAesCtx->enabled)
        return ERR_TAP_INVALID_KEY_TYPE;

    return CRYPTO_INTERFACE_TAP_SymGetKeyInfo (pAesCtx->pMocSymCtx, pTokenHandle, pKeyHandle);
}
#endif /* __ENABLE_DIGICERT_TAP__ */