/*
 * crypto_interface_aes_xts.c
 *
 * Cryptographic Interface specification for AES-XTS mode.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_XTS_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../crypto/aes.h"
#include "../crypto/aes_xts.h"
#include "../crypto_interface/crypto_interface_aes_xts.h"
#include "../crypto_interface/crypto_interface_priv.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_XTS__

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_XTS__))
#define MOC_AES_XTS_CREATE_CTX(_pCtx, _pKey, _keyLen, _encrypt, pExtCtx)      \
    _pCtx = CreateAESXTSCtxExt(MOC_SYM(hwAccelCtx) _pKey, _keyLen, _encrypt, pExtCtx);            \
    if (NULL != _pCtx)                                                        \
    {                                                                         \
        _pCtx->pMocSymCtx = NULL;                                             \
        _pCtx->enabled = CRYPTO_INTERFACE_ALGO_DISABLED;                      \
    }
#else
#define MOC_AES_XTS_CREATE_CTX(_pCtx, _pKey, _keyLen, _encrypt, pExtCtx)      \
    _pCtx = NULL
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_XTS__))
#define MOC_AES_XTS_DELETE_CTX(_status, _pCtx, pExtCtx)                       \
    _status = DeleteAESXTSCtxExt(MOC_SYM(hwAccelCtx) _pCtx, pExtCtx)
#else
#define MOC_AES_XTS_DELETE_CTX(_status, _pCtx, pExtCtx)                       \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_XTS__))
#define MOC_AES_DOAESXTS(_status, _pCtx, _pData, _dataLength, _encrypt, _iv, pExtCtx)  \
    _status = DoAESXTSExt(MOC_SYM(hwAccelCtx) _pCtx, _pData, _dataLength, _encrypt, _iv, pExtCtx)
#else
#define MOC_AES_DOAESXTS(_status, _pCtx, _pData, _dataLength, _encrypt, _iv, pExtCtx)  \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_XTS__))
#define MOC_AES_AESXTSEncrypt(_status, _pCtx, _tweak, _plain, _plainLen, pExtCtx)      \
    _status = AESXTSEncryptExt(MOC_SYM(hwAccelCtx) _pCtx, _tweak, _plain, _plainLen, pExtCtx)
#else
#define MOC_AES_AESXTSEncrypt(_status, _pCtx, _tweak, _plain, _plainLen, pExtCtx)      \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_XTS__))
#define MOC_AES_AESXTSDecrypt(_status, _pCtx, _tweak, _cipher, _cipherLen, pExtCtx)    \
    _status = AESXTSDecryptExt(MOC_SYM(hwAccelCtx) _pCtx, _tweak, _cipher, _cipherLen, pExtCtx)
#else
#define MOC_AES_AESXTSDecrypt(_status, _pCtx, _tweak, _cipher, _cipherLen, pExtCtx)    \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#if (!defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__)) && \
    (!defined(__DISABLE_AES_CIPHERS__)) && \
    (!defined(__DISABLE_AES_XTS__))
#define MOC_AES_AESXTSClone(_status, _pSrc, _ppDest)         \
    _status = CloneAESXTSCtx(MOC_SYM(hwAccelCtx) _pSrc, _ppDest)
#else
#define MOC_AES_AESXTSClone(_status, _pSrc, _ppDest)         \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateAESXTSCtx(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *pKeyMaterial,
    sbyte4 keyLength,
    sbyte4 encrypt
    )
{
    return CRYPTO_INTERFACE_CreateAESXTSCtxExt(MOC_SYM(hwAccelCtx) pKeyMaterial, keyLength, encrypt, NULL);
}

MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateAESXTSCtxExt(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *pKeyMaterial,
    sbyte4 keyLength,
    sbyte4 encrypt,
    void *pExtCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 algoStatus = CRYPTO_INTERFACE_ALGO_DISABLED;
    ubyte4 index = 0;
    aesXTSCipherContext *pCtx = NULL;
    MocSymCtx pNewSymCtx = NULL;
    
    if (NULL == pKeyMaterial)
        goto exit;

    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_aes_xts, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        status = DIGI_CALLOC((void **)&pCtx, 1, sizeof(aesXTSCipherContext));
        if (OK != status)
            goto exit;
        
        /* set enabled flag right away so in case of error delete will properly handle */
        pCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;
        
        /* MocSymCtx has to be created before we updateSymOperatorData. */
        status = CRYPTO_INTERFACE_createAndLoadSymKey (index, NULL, pKeyMaterial, (ubyte4) keyLength, &pNewSymCtx);
        if (OK != status)
            goto exit;
        
        /* initialize cipher operation since we have all necessary data */
        status = CRYPTO_cipherInit(pNewSymCtx, encrypt ? MOC_CIPHER_FLAG_ENCRYPT : MOC_CIPHER_FLAG_DECRYPT);
        if (OK != status)
            goto exit;
        
        pCtx->pMocSymCtx = pNewSymCtx;
        pNewSymCtx = NULL;
    }
    else
    {
        MOC_AES_XTS_CREATE_CTX(pCtx, pKeyMaterial, keyLength, encrypt, pExtCtx);
    }
    
exit:

    if (NULL != pNewSymCtx)
    {
        (void) CRYPTO_freeMocSymCtx(&pNewSymCtx);
    }
    if (OK != status && NULL != pCtx)
    {
        (void) CRYPTO_INTERFACE_DeleteAESXTSCtxExt(MOC_SYM(hwAccelCtx) (BulkCtx *) &pCtx, pExtCtx);
    }

    return (BulkCtx) pCtx;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DeleteAESXTSCtx (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx
    )
{
    return CRYPTO_INTERFACE_DeleteAESXTSCtxExt(MOC_SYM(hwAccelCtx) ppCtx, NULL);
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DeleteAESXTSCtxExt (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx,
    void *pExtCtx
    )
{
    MSTATUS status, fstatus;
    aesXTSCipherContext *pCtx = NULL;
    
    status = ERR_NULL_POINTER;
    if (NULL == ppCtx)
        goto exit;
    
    /* It is not an error to attempt to free a NULL context */
    status = OK;
    pCtx = (aesXTSCipherContext *)(*ppCtx);
    if (NULL == pCtx)
        goto exit;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        /* Free the underlying context.  */
        status = CRYPTO_freeMocSymCtx(&(pCtx->pMocSymCtx));
        
        /* even if we error we zero and free the outer shell */
        
        /*
         zero the context, this will also set the enabled flag back to 0
         ok to ignore DIGI_MEMSET return code.
         */
        DIGI_MEMSET((ubyte *) pCtx, 0x00, sizeof(aesXTSCipherContext));
        
        /* Free the shell */
        fstatus = DIGI_FREE((void **)&pCtx);
        if (OK == status)
            status = fstatus;
        
        /* NULL out the callers pointer */
        *ppCtx = NULL;
    }
    else
    {
        MOC_AES_XTS_DELETE_CTX(status, ppCtx, pExtCtx);
    }
    
exit:
    
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoAESXTS (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte *pData,
    sbyte4 dataLen,
    sbyte4 encrypt,
    ubyte *pTweak
    )
{
    return CRYPTO_INTERFACE_DoAESXTSExt(MOC_SYM(hwAccelCtx) pCtx, pData, dataLen, encrypt, pTweak, NULL);
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoAESXTSExt (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte *pData,
    sbyte4 dataLen,
    sbyte4 encrypt,
    ubyte *pTweak,
    void *pExtCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    
    aesXTSCipherContext *pAesCtx = (aesXTSCipherContext *)pCtx;
    if (NULL == pAesCtx)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pAesCtx->enabled)
    {
        MAesUpdateData aesParams = {0};
        ubyte4 retLen;
        MocCtx pMocCtx = NULL;
        
        status = ERR_NULL_POINTER;
        if (NULL == pData || NULL == pTweak)
            goto exit;
        
        status = CRYPTO_INTERFACE_getMocCtx (&pMocCtx);
        if (OK != status)
            goto exit;
        
        aesParams.pInitVector = pTweak;
        aesParams.initVectorLen = AES_BLOCK_SIZE;
        
        status = CRYPTO_updateSymOperatorData (pAesCtx->pMocSymCtx, pMocCtx, (void *)&aesParams);
        if (OK != status)
            goto exit;
       
        status = CRYPTO_cipherUpdate (pAesCtx->pMocSymCtx, encrypt ? MOC_CIPHER_FLAG_ENCRYPT : MOC_CIPHER_FLAG_DECRYPT,
                                      pData, (ubyte4)dataLen, pData, (ubyte4)dataLen, &retLen);
    }
    else
    {
        MOC_AES_DOAESXTS(status, pCtx, pData, dataLen, encrypt, pTweak, pExtCtx);
    }
    
exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESXTSEncrypt(
    MOC_SYM(hwAccelDescr hwAccelCtx) aesXTSCipherContext *pCtx,
    ubyte pTweak[AES_BLOCK_SIZE],
    ubyte *pPlain,
    ubyte4 plainLen
    )
{
    return CRYPTO_INTERFACE_AESXTSEncryptExt(MOC_SYM(hwAccelCtx) pCtx, pTweak, pPlain, plainLen, NULL);
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESXTSEncryptExt(
    MOC_SYM(hwAccelDescr hwAccelCtx) aesXTSCipherContext *pCtx,
    ubyte pTweak[AES_BLOCK_SIZE],
    ubyte *pPlain,
    ubyte4 plainLen,
    void *pExtCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pCtx)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        status = CRYPTO_INTERFACE_DoAESXTSExt(MOC_SYM(hwAccelCtx) (BulkCtx) pCtx, pPlain, plainLen, TRUE, pTweak, pExtCtx);
    }
    else
    {
        MOC_AES_AESXTSEncrypt(status, pCtx, pTweak, pPlain, plainLen, pExtCtx);
    }
    
exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESXTSDecrypt(
    MOC_SYM(hwAccelDescr hwAccelCtx) aesXTSCipherContext *pCtx,
    ubyte pTweak[AES_BLOCK_SIZE],
    ubyte *pCipher,
    ubyte4 cipherLen
    )
{
    return CRYPTO_INTERFACE_AESXTSDecryptExt(MOC_SYM(hwAccelCtx) pCtx, pTweak, pCipher, cipherLen, NULL);
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_AESXTSDecryptExt(
    MOC_SYM(hwAccelDescr hwAccelCtx) aesXTSCipherContext *pCtx,
    ubyte pTweak[AES_BLOCK_SIZE],
    ubyte *pCipher,
    ubyte4 cipherLen,
    void *pExtCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    
    if (NULL == pCtx)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        status = CRYPTO_INTERFACE_DoAESXTSExt(MOC_SYM(hwAccelCtx) (BulkCtx) pCtx, pCipher, cipherLen, FALSE, pTweak, pExtCtx);
    }
    else
    {
        MOC_AES_AESXTSDecrypt(status, pCtx, pTweak, pCipher, cipherLen, pExtCtx);
    }
    
exit:
    
    return status;
}

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_CloneAESXTSCtx (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    BulkCtx *ppNewCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    aesXTSCipherContext *pAesCtx = NULL;
    aesXTSCipherContext *pNewAesCtx = NULL;
    MocSymCtx pNewSymCtx = NULL;

    if (NULL == pCtx || NULL == ppNewCtx )
        goto exit;

    pAesCtx = (aesXTSCipherContext *) pCtx;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pAesCtx->enabled)
    {
        /* Clone the underlying MocSymCtx */
        status = CRYPTO_cloneMocSymCtx(pAesCtx->pMocSymCtx, &pNewSymCtx);
        if (OK != status)
            goto exit;

        status = DIGI_CALLOC((void **)&pNewAesCtx, 1, sizeof(aesCipherContext));
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY((void *)pNewAesCtx, (void *)pAesCtx, sizeof(aesCipherContext));
        if (OK != status)
            goto exit;

        pNewAesCtx->pMocSymCtx = pNewSymCtx;
        pNewSymCtx = NULL;
        *ppNewCtx = (BulkCtx) pNewAesCtx;
        pNewAesCtx = NULL;
    }
    else
    {
        MOC_AES_AESXTSClone(status, pCtx, ppNewCtx);
    }

exit:

    if (NULL != pNewSymCtx)
    {
        CRYPTO_freeMocSymCtx(&pNewSymCtx);
    }
    if (NULL != pNewAesCtx)
    {
        DIGI_FREE((void **)&pNewAesCtx);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_AES_XTS__ */
