/*
 * crypto_interface_des_tap.c
 *
 * Cryptographic Interface specification for DES TAP.
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
#include "../crypto_interface/crypto_interface_des_tap.h"

#ifdef __ENABLE_DIGICERT_TAP__
#include "../tap/tap.h"
#include "../tap/tap_smp.h"
#include "../tap/tap_api.h"
#include "../tap/tap_utils.h"
#include "../asn1/mocasn1.h"
#include "../crypto/mocsymalgs/tap/symtap.h"
#include "../crypto_interface/crypto_interface_priv.h"
#include "../crypto_interface/cryptointerface.h"
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_getDesCbcCtxFromSymmetricKeyAlloc(
    SymmetricKey *pSymKey,
    BulkCtx *ppNewCtx,
    sbyte4 encrypt
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER;
    DES_CTX *pNewCtx = NULL;
    MocSymCtx pSymCtx = NULL;
    MTapKeyData *pTapData = NULL;

    if ( (NULL == pSymKey) || (NULL == pSymKey->pKeyData) || (NULL == ppNewCtx) )
    {
        goto exit;
    }

    pSymCtx = (MocSymCtx)pSymKey->pKeyData;
    pTapData = (MTapKeyData *)pSymCtx->pLocalData;

    if (NULL == pTapData)
        goto exit;

    /* This method is defined for use with only for CBC mode! */
    pTapData->symMode = TAP_SYM_KEY_MODE_CBC;

    /* Override the internal TAP structure sym mode too */
    pTapData->pKey->keyData.algKeyInfo.desInfo.symMode = TAP_SYM_KEY_MODE_CBC;

    /* Set the direction */
    pTapData->direction = encrypt ? MOCANA_SYM_TAP_ENCRYPT : MOCANA_SYM_TAP_DECRYPT;

    /* Allocate the new wrapper */
    status = DIGI_CALLOC((void **) &pNewCtx, 1, sizeof(DES_CTX));
    if (OK != status)
        goto exit;

    /* Transfer control of the underlying MocSymCtx to the wrapper */
    pNewCtx->pMocSymCtx = pSymCtx; pSymCtx = NULL;
    pSymKey->pKeyData = NULL;

    /* Mark this object as crypto interface enabled */
    pNewCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

    *ppNewCtx = (BulkCtx) pNewCtx; pNewCtx = NULL;

exit:

    /* Allocation is last thing to fail, no cleanup needed on it */

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_initDesEcbCtxFromSymmetricKey (
    SymmetricKey *pSymKey,
    DES_CTX *pCtx
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    MSTATUS status = ERR_NULL_POINTER;
    MocSymCtx pSymCtx = NULL;
    MTapKeyData *pTapData = NULL;

    if ( (NULL == pSymKey) || (NULL == pSymKey->pKeyData) || (NULL == pCtx) )
    {
        goto exit;
    }

    pSymCtx = (MocSymCtx)pSymKey->pKeyData;
    pTapData = (MTapKeyData *)pSymCtx->pLocalData;

    if (NULL == pTapData)
        goto exit;

    /* clear any existing key */
    status = CRYPTO_INTERFACE_DES_clearKey(pCtx);
    if (OK != status)
        goto exit;

    /* This method is defined for use with only for EBC mode! */
    pTapData->symMode = TAP_SYM_KEY_MODE_ECB;

    /* Override the internal TAP structure sym mode too */
    pTapData->pKey->keyData.algKeyInfo.desInfo.symMode = TAP_SYM_KEY_MODE_ECB;

    /* Transfer control of the underlying MocSymCtx to the wrapper */
    pCtx->pMocSymCtx = pSymCtx; pSymCtx = NULL;
    pSymKey->pKeyData = NULL;

    /* Mark this object as crypto interface enabled */
    pCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;

exit:

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_DesDeferKeyUnload (
    BulkCtx pCtx,
    byteBoolean deferredTokenUnload
    )
{
#ifdef __ENABLE_DIGICERT_TAP__
    DES_CTX *pDesCtx = (DES_CTX *) pCtx;

    if (NULL == pCtx)
        return ERR_NULL_POINTER;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != pDesCtx->enabled)
        return ERR_TAP_INVALID_KEY_TYPE;

    return CRYPTO_INTERFACE_TAP_SymDeferUnload(pDesCtx->pMocSymCtx, deferredTokenUnload); 
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_TAP__
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_DesGetKeyInfo (
    BulkCtx pCtx,
    TAP_TokenHandle *pTokenHandle,
    TAP_KeyHandle *pKeyHandle
    )
{
    DES_CTX *pDesCtx = (DES_CTX *) pCtx;

    if (NULL == pDesCtx)
        return ERR_NULL_POINTER;

    if (CRYPTO_INTERFACE_ALGO_ENABLED != pDesCtx->enabled)
        return ERR_TAP_INVALID_KEY_TYPE;

    return CRYPTO_INTERFACE_TAP_SymGetKeyInfo(pDesCtx->pMocSymCtx, pTokenHandle, pKeyHandle); 
}
#endif /* __ENABLE_DIGICERT_TAP__ */

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_DoDES (
    MocSymCtx pCtx,
    ubyte *pData,
    sbyte4 dataLen,
    sbyte4 encrypt,
    ubyte *pIv
    )
{
    return CRYPTO_INTERFACE_TAP_DES_CBC(pCtx, pData, dataLen, encrypt, pIv, FALSE);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_DES_encipher (
    MocSymCtx pCtx,
    ubyte *pSrc,
    ubyte *pDest,
    ubyte4 numBytes
    )
{
    return CRYPTO_INTERFACE_TAP_DES_ECB(pCtx, pSrc, pDest, numBytes, TRUE, FALSE);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_DES_decipher (
    MocSymCtx pCtx,
    ubyte *pSrc,
    ubyte *pDest,
    ubyte4 numBytes
    )
{
    return CRYPTO_INTERFACE_TAP_DES_ECB(pCtx, pSrc, pDest, numBytes, FALSE, FALSE);
}

/*---------------------------------------------------------------------------*/

/* extern for use by triple des too */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_DES_CBC (
    MocSymCtx pCtx,
    ubyte *pData,
    sbyte4 dataLen,
    sbyte4 encrypt,
    ubyte *pIv,
    byteBoolean isTDes
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
    TAP_Buffer input = {0};
    TAP_Buffer output = {0};
    TapOperation op = encrypt ? (isTDes ? tap_tdes_encrypt : tap_des_encrypt) : (isTDes ? tap_tdes_decrypt : tap_des_decrypt);

    if (NULL == pCtx || NULL == pCtx->pLocalData || NULL == pData || NULL == pIv)
        goto exit;

    /* imake sure numBytes is a multiple of the block size of 8 */
    status = ERR_INVALID_INPUT;
    if (dataLen & (sbyte4) 0x07)
        goto exit;

    status = ERR_CRYPTO_CTX_STATE;
    if (CTX_STATE_CREATE != pCtx->state && CTX_STATE_INIT != pCtx->state)
        goto exit;

    pTapData = (MTapKeyData *) pCtx->pLocalData;
    pTapKey = (TAP_Key *)pTapData->pKey;

    status = ERR_WRONG_CTX_TYPE;
    if ( (encrypt && MOCANA_SYM_TAP_ENCRYPT != pTapData->direction) || (!encrypt && MOCANA_SYM_TAP_DECRYPT != pTapData->direction) )
        goto exit;

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
        iv.bufferLen = (NULL != pIv) ? 8 : 0;

        if (encrypt)
        {
            status = TAP_symEncryptInit(pTapKey, pEntityCredentials, pTapData->pKeyAttributes, pTapData->symMode,
                                        &iv, pErrContext);
        }
        else
        {
            status = TAP_symDecryptInit(pTapKey, pEntityCredentials, pTapData->pKeyAttributes, pTapData->symMode,
                                        &iv, pErrContext);
        }
        if (OK != status)
            goto exit1;

        pCtx->state = CTX_STATE_INIT;
    }

    input.pBuffer = pData;
    input.bufferLen = dataLen;

    if (encrypt)
    {
        status = TAP_symEncryptUpdate(pTapKey, pEntityCredentials, pTapData->pKeyAttributes, pTapData->symMode,
                                      &input, &output, pErrContext);

    }
    else
    {
        status = TAP_symDecryptUpdate(pTapKey, pEntityCredentials, pTapData->pKeyAttributes, pTapData->symMode,
                                      &input, &output, pErrContext);
    }
    if (OK != status)
        goto exit1;

    status = DIGI_MEMCPY (pData, output.pBuffer, output.bufferLen);

exit1:

    if (OK > status)
    {
        DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"CI DES/TDES TAP Decrypt failed with status = ", status);

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

    if (NULL != output.pBuffer)
    {
        (void) TAP_UTILS_freeBuffer(&output);
    }

    return status;

#else
    return ERR_TAP_UNSUPPORTED;
#endif
}

/*---------------------------------------------------------------------------*/

/* extern for use by the 3 des API's too */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_DES_ECB (
    MocSymCtx pCtx,
    ubyte *pSrc,
    ubyte *pDest,
    ubyte4 numBytes,
    byteBoolean isEncrypt,
    byteBoolean isTDes
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
    TAP_Buffer input = {0};
    TAP_Buffer output = {0};
    TAP_Buffer iv = {0};
    TapOperation op = isEncrypt ? (isTDes ? tap_tdes_encrypt : tap_des_encrypt) : (isTDes ? tap_tdes_decrypt : tap_des_decrypt);

    if (NULL == pCtx || NULL == pCtx->pLocalData || NULL == pSrc || NULL == pDest)
        goto exit;

    /* imake sure numBytes is a multiple of the block size of 8 */
    status = ERR_INVALID_INPUT;
    if (numBytes & 0x07)
        goto exit;

    pTapData = (MTapKeyData *) pCtx->pLocalData;
    pTapKey = (TAP_Key *)pTapData->pKey;

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

    if (!pTapData->isKeyLoaded)
    {
        status = TAP_loadKey(pTapContext, pEntityCredentials, pTapKey, pKeyCredentials,
                                pTapData->pKeyAttributes, pErrContext);
        if (OK != status)
            goto exit1;

        pTapData->isKeyLoaded = TRUE;
    }

    input.pBuffer = pSrc;
    input.bufferLen = numBytes;

    if (isEncrypt)
    {
        status = TAP_symEncrypt(pTapKey, pEntityCredentials, NULL, pTapData->symMode, &iv, &input, &output, pErrContext);
        if (OK != status)
            goto exit1;
    }
    else
    {
        status = TAP_symDecrypt(pTapKey, pEntityCredentials, NULL, pTapData->symMode, &iv, &input, &output, pErrContext);
        if (OK != status)
            goto exit1;
    }

    status = DIGI_MEMCPY (pDest, output.pBuffer, output.bufferLen);

exit1:

    if (!pTapData->isDeferUnload)
    {
        status2 = TAP_unloadKey(pTapKey, pErrContext);
        if (OK != status2)
        {
                DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"TAP_unloadKey failed with status = ", status2);
        }
        else
        {
            pTapData->isKeyLoaded = FALSE;
        }
        if (OK == status)
            status = status2;
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
    if (OK == status)
        status = status2;

exit:

    if (NULL != output.pBuffer)
    {
        (void) TAP_UTILS_freeBuffer(&output);
    }

    return status;
#else
    return ERR_NOT_IMPLEMENTED;
#endif
}

/*---------------------------------------------------------------------------*/

/* extern for three des use also */
MOC_EXTERN MSTATUS CRYPTO_INTERFACE_TAP_DES_Final(
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

    if (pTapData->isKeyLoaded && !pTapData->isDeferUnload)
    {
        status2 = TAP_unloadKey(pTapData->pKey, pErrContext);
        if (OK != status2)
        {
            DEBUG_ERROR(DEBUG_TAP_MESSAGES, (sbyte*)"TAP_unloadKey failed with status = ", status2);
        }
        else
        {
            pTapData->isKeyLoaded = FALSE;
        }

        if (OK == status)
            status = status2;
    }

    pCtx->state = CTX_STATE_FINAL;

exit:

    return status;
#else
    return ERR_TAP_UNSUPPORTED;
#endif
}
