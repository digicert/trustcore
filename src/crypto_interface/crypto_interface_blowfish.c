/*
 * crypto_interface_blowfish.c
 *
 * Cryptographic Interface specification for Blowfish.
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

#define __ENABLE_DIGICERT_CRYPTO_INTERFACE_BLOWFISH_INTERNAL__

#include "../crypto/mocsym.h"
#include "../common/initmocana.h"
#include "../crypto/blowfish.h"
#include "../crypto_interface/crypto_interface_priv.h"

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_BLOWFISH__

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_BLOWFISH_CREATE(_pCtx, _pKey, _keyLen, _encrypt)                  \
    _pCtx = CreateBlowfishCtx(MOC_SYM(hwAccelCtx) _pKey, _keyLen, _encrypt)
#else
#define MOC_BLOWFISH_CREATE(_pCtx, _pKey, _keyLen, _encrypt)                  \
    _pCtx = NULL
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_BLOWFISH_DELETE(_status, _pCtx)                                   \
    _status = DeleteBlowfishCtx(MOC_SYM(hwAccelCtx) _pCtx)
#else
#define MOC_BLOWFISH_DELETE(_status, _pCtx)                                   \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_BLOWFISH_DO(_status, _pCtx, _pData, _dataLen, _encrypt, _iv)      \
    _status = DoBlowfish(MOC_SYM(hwAccelCtx) _pCtx, _pData, _dataLen, _encrypt, _iv)
#else
#define MOC_BLOWFISH_DO(_status, _pCtx, _pData, _dataLen, _encrypt, _iv)      \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE
#endif

/*---------------------------------------------------------------------------*/

#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
#define MOC_BF_CLONE(_status, _pCtx, _ppNewCtx)                               \
    _status = CloneBlowfishCtx(MOC_SYM(hwAccelCtx) _pCtx, _ppNewCtx);
#else
#define MOC_BF_CLONE(_status, _pCtx, _ppNewCtx)                               \
    _status = ERR_CRYPTO_INTERFACE_NO_IMPLEMENTATION_AVAILABLE;
#endif

/*---------------------------------------------------------------------------*/

MOC_EXTERN BulkCtx CRYPTO_INTERFACE_CreateBlowfishCtx(
    MOC_SYM(hwAccelDescr hwAccelCtx) ubyte *pKeyMaterial,
    sbyte4 keyLen,
    sbyte4 encrypt
    )
{
    MSTATUS status;
    ubyte4 algoStatus;
    ubyte4 index;
    blf_ctx *pNewCtx = NULL;
    MocSymCtx pNewSymCtx = NULL;
    
    status = CRYPTO_INTERFACE_checkSymAlgoStatus (moc_alg_blowfish_cbc, &algoStatus, &index);
    if (OK != status)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == algoStatus)
    {
        /* Create a copy of the Operator MocSymCtx and store the key within it */
        status = CRYPTO_INTERFACE_createAndLoadSymKey (index, NULL, pKeyMaterial, keyLen, &pNewSymCtx);
        if (OK != status)
            goto exit;
        
        status = CRYPTO_cipherInit(pNewSymCtx, 0);
        if (OK != status)
            goto exit;
        
        /* Allocate the blowfish context */
        status = DIGI_CALLOC ((void **) &pNewCtx, 1, sizeof (blf_ctx));
        if (OK != status)
            goto exit;
        
        pNewCtx->pMocSymCtx = pNewSymCtx;
        pNewSymCtx = NULL;
        
        /* Mark this object to indicate that it is using an alternate
         * implementation through the crypto interface */
        pNewCtx->enabled = CRYPTO_INTERFACE_ALGO_ENABLED;
        
        /* initialized flag set to 0 via the CALLOC above */
    }
    else
    {
        MOC_BLOWFISH_CREATE(pNewCtx, pKeyMaterial, keyLen, encrypt);
    }
    
exit:
    if (NULL != pNewSymCtx)
        CRYPTO_freeMocSymCtx (&pNewSymCtx); /* ok to ignore return, here only on error */
    
    return (BulkCtx) pNewCtx;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DeleteBlowfishCtx(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx *ppCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    blf_ctx *pCtx = NULL;
    
    if (NULL == ppCtx)
        goto exit;
    
    status = OK; /* ok no-op if the context was already deleted */
    pCtx = (blf_ctx *) (*ppCtx);
    if (NULL == pCtx)
        goto exit;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pCtx->enabled)
    {
        MSTATUS fstatus;
        
        /* Free the underlying context */
        status = CRYPTO_freeMocSymCtx (&(pCtx->pMocSymCtx));
        
        /* Free the shell */
        fstatus = DIGI_FREE((void **) &pCtx);
        if (OK == status)
            status = fstatus;
        
        /* NULL-out the caller's pointer */
        *ppCtx = NULL;
    }
    else
    {
        MOC_BLOWFISH_DELETE(status, ppCtx);
    }
    
exit:
    
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoBlowfish(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte *pData,
    sbyte4 dataLen,
    sbyte4 encrypt,
    ubyte *pIv
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    blf_ctx *pBFCtx = NULL;
    
    if (NULL == pCtx)
        goto exit;
    
    pBFCtx = (blf_ctx *) pCtx;
    
    if (CRYPTO_INTERFACE_ALGO_ENABLED == pBFCtx->enabled)
    {
        MocCtx pMocCtx = NULL;
        ubyte4 cipherFlag = MOC_CIPHER_FLAG_ENCRYPT;
        ubyte4 outLen;
        
        status = ERR_INVALID_ARG;
        if ( dataLen < 0)
            goto exit;
        
        /* Get a reference to the MocCtx registered with the Crypto Interface */
        status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
        if (OK != status)
            goto exit;
        
        /* We assumed encryption to start, check for decryption */
        if (0 == encrypt)
            cipherFlag = MOC_CIPHER_FLAG_DECRYPT;
        
        /* If this is the first call to DoBlowfish for this ctx, update the
         * underlying MocSymCtx with the initialization vector and then
         * initialize the operation. If this is a continuation of a previous
         * operation, simply continue the update process */
        if (0 == pBFCtx->initialized)
        {
            MBlowfishUpdateData params;
            
            /* Update the operator with the initialization vector */
            params.pInitVector = pIv;
            params.initVectorLen = BLOWFISH_BLOCK_SIZE;
            
            status = CRYPTO_updateSymOperatorData (pBFCtx->pMocSymCtx, pMocCtx, (void *)&params);
            if (OK != status)
                goto exit;
            
            /* Initialize the cipher operation  */
            status = CRYPTO_cipherInit(pBFCtx->pMocSymCtx, cipherFlag);
            if (OK != status)
                goto exit;
            
            /* Mark this object as initialized so we dont overwrite the
             * initialization vector within the object on the next call */
            pBFCtx->initialized = 1;
        }
        
        /* Update the cipher operation */
        if (dataLen)
            status = CRYPTO_cipherUpdate (pBFCtx->pMocSymCtx, cipherFlag, pData, (ubyte4)dataLen, pData, (ubyte4)dataLen, &outLen);
    }
    else
    {
        MOC_BLOWFISH_DO(status, pCtx, pData, dataLen, encrypt, pIv);
    }
    
exit:
    
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_DoBlowfishEx(
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    ubyte *pData,
    sbyte4 dataLen,
    sbyte4 encrypt,
    ubyte *pIv
    )
{
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE_EXPORT__
    MSTATUS status = ERR_NULL_POINTER;
    blf_ctx *pBFCtx = (blf_ctx*)pCtx;
    
    if (NULL == pBFCtx)
        goto exit;

    /* We want to update the IV the operator is using with the one that is passed
     * to this function call. if initialized is set to zero, then
     * CRYPTO_INTERFACE_DoBlowfish call will make updateSymOperatorData call,
     * otherwise we have to make it ourselves.
     */
    if (1 == pBFCtx->initialized)
    {
        MocCtx pMocCtx = NULL;
        MBlowfishUpdateData params = {0};
        
        /* Get a reference to the MocCtx registered with the Crypto Interface */
        status = CRYPTO_INTERFACE_getMocCtx(&pMocCtx);
        if (OK != status)
            goto exit;
        
        /* Update the operator with the initialization vector */
        params.pInitVector = pIv;
        params.initVectorLen = BLOWFISH_BLOCK_SIZE;
        
        status = CRYPTO_updateSymOperatorData (pBFCtx->pMocSymCtx, pMocCtx, (void *)&params);
        if (OK != status)
            goto exit;
    }
    
    status = CRYPTO_INTERFACE_DoBlowfish(MOC_SYM(hwAccelCtx) pCtx, pData, dataLen, encrypt, pIv);
    if (OK != status)
        goto exit;

    /* update the passed in pIv to the latest copy */
    status = CRYPTO_INTERFACE_getIv(pBFCtx->pMocSymCtx, pIv);

exit:
    return status;
#else
    return CRYPTO_INTERFACE_DoBlowfish(MOC_SYM(hwAccelCtx) pCtx, pData, dataLen, encrypt, pIv);
#endif
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS CRYPTO_INTERFACE_CloneBlowfishCtx (
    MOC_SYM(hwAccelDescr hwAccelCtx) BulkCtx pCtx,
    BulkCtx *ppNewCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    blf_ctx *pBlowfishCtx = NULL;
    blf_ctx *pNewBlowfishCtx = NULL;
    MocSymCtx pNewSymCtx = NULL;

    if ( (NULL == pCtx) || (NULL == ppNewCtx) )
        goto exit;

    pBlowfishCtx = (blf_ctx *)pCtx;

    if (CRYPTO_INTERFACE_ALGO_ENABLED == pBlowfishCtx->enabled)
    {
        /* Clone the underlying MocSymCtx */
        status = CRYPTO_cloneMocSymCtx(pBlowfishCtx->pMocSymCtx, &pNewSymCtx);
        if (OK != status)
        goto exit;

        status = DIGI_CALLOC((void **)&pNewBlowfishCtx, 1, sizeof(blf_ctx));
        if (OK != status)
        goto exit;

        status = DIGI_MEMCPY((void *)pNewBlowfishCtx, (void *)pBlowfishCtx, sizeof(blf_ctx));
        if (OK != status)
        goto exit;

        pNewBlowfishCtx->pMocSymCtx = pNewSymCtx;
        pNewSymCtx = NULL;
        *ppNewCtx = (BulkCtx)pNewBlowfishCtx;
        pNewBlowfishCtx = NULL;
    }
    else
    {
        MOC_BF_CLONE(status, pCtx, ppNewCtx)
    }

exit:

    if (NULL != pNewSymCtx)
    {
        (void) CRYPTO_freeMocSymCtx(&pNewSymCtx);
    }
    if (NULL != pNewBlowfishCtx)
    {
        (void) DIGI_FREE((void **)&pNewBlowfishCtx);
    }
    return status;
}
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE_BLOWFISH__ */
