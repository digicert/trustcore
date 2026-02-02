/*
 * mbedaescmac.c
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


#ifdef __ENABLE_DIGICERT_AES_CMAC_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbedaescmac.h"

#define MOC_MBED_CMAC_RESULT_SIZE 16 /* operator is just aes-cmac */

MOC_EXTERN MSTATUS MAesCmacMbedCreate(
    MocSymCtx pSymCtx
)
{
    MSTATUS status = ERR_NULL_POINTER;
    MbedAesCmacInfo *pNewInfo = NULL;
    mbedtls_cipher_context_t *pNewCtx = NULL;
    
    if (NULL == pSymCtx)
        goto exit;

    status = DIGI_CALLOC((void **) &pNewInfo, 1, sizeof(MbedAesCmacInfo));
    if (OK != status)
        goto exit;

    status = DIGI_CALLOC((void **) &pNewCtx, 1, sizeof(mbedtls_cipher_context_t));
    if (OK != status)
        goto exit;

    mbedtls_cipher_init(pNewCtx);
    
    pNewInfo->pCmacCtx = pNewCtx;
    pNewCtx = NULL;
    
    pSymCtx->localType = MOC_LOCAL_TYPE_AES_CMAC_OPERATOR;
    pSymCtx->SymOperator = SymOperatorAesCmac;
    pSymCtx->pLocalData = (void *) pNewInfo;
    pNewInfo = NULL;
    
exit:
    
    if (NULL != pNewCtx)
    {
        mbedtls_cipher_free(pNewCtx);
        DIGI_FREE((void **) &pNewCtx); /* only here on error, no need to check return */
    }

    if (NULL != pNewInfo)
    {   /* don't need to zero, nothing inside ever set */
        DIGI_FREE((void **) &pNewInfo); /* only here on error, no need to check return */
    }
    
    return status;
}

MOC_EXTERN MSTATUS MAesCmacMbedLoadKey(
    MocSymCtx pSymCtx,
    MSymOperatorData *pKeyData
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MbedAesCmacInfo *pInfo;
    
    if (NULL == pKeyData || NULL == pSymCtx || NULL == pSymCtx->pLocalData)
        goto exit;
    
    pInfo = (MbedAesCmacInfo *) pSymCtx->pLocalData;
    
    /* If there already is a key in the info then free it. */
    if (NULL != pInfo->pKey)
    {
        status = DIGI_MEMSET_FREE((ubyte **) &(pInfo->pKey), pInfo->keyLen);
        if (OK != status)
            goto exit;
        
        pInfo->keyLen = 0;
    }
    
    /*
     If a key was provided then store it within the info. It is not an
     error if no key is provided.
     */
    if (NULL != pKeyData->pData)
    {
        status = DIGI_MALLOC((void **) &(pInfo->pKey), pKeyData->length);
        if (OK != status)
            goto exit;
        
        status = DIGI_MEMCPY(pInfo->pKey, pKeyData->pData, pKeyData->length);
        if (OK != status)
            goto exit;
        
        pInfo->keyLen = pKeyData->length;
    }
    
    status = OK;
    
exit:
    
    return status;
}


MOC_EXTERN MSTATUS MAesCmacMbedInit(
    MocSymCtx pSymCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MbedAesCmacInfo *pInfo;
    ubyte4 keyLenBits = 0;
    const mbedtls_cipher_info_t *pMbedInfo;
    int mbedStatus;
    
    if (NULL == pSymCtx || NULL == pSymCtx->pLocalData)
        goto exit;
    
    pInfo = (MbedAesCmacInfo *) pSymCtx->pLocalData;
    
    if (NULL == pInfo->pCmacCtx || NULL == pInfo->pKey)
        goto exit;
    
    keyLenBits = 8 * pInfo->keyLen;
    
    status = ERR_AES_BAD_KEY_LENGTH;
    switch (keyLenBits)
    {
        case 128:
            pMbedInfo = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
            break;
            
        case 192:
            pMbedInfo = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_ECB);
            break;
            
        case 256:
            pMbedInfo = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB);
            break;
            
        default:
            goto exit;
    }
    
    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_cipher_setup(pInfo->pCmacCtx, pMbedInfo);
    if (0 != mbedStatus)
        goto exit;
    
    mbedStatus = mbedtls_cipher_cmac_starts(pInfo->pCmacCtx, pInfo->pKey, keyLenBits);
    if (0 != mbedStatus)
        goto exit;
    
    status = OK;
    
exit:
    
    return status;
}

MOC_EXTERN MSTATUS MAesCmacMbedUpdate(
    MocSymCtx pSymCtx,
    MSymOperatorData *pInput
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MbedAesCmacInfo *pInfo;
    int mbedStatus;
    
    if (NULL == pSymCtx || NULL == pSymCtx->pLocalData || NULL == pInput)
        goto exit;
    
    pInfo = (MbedAesCmacInfo *) pSymCtx->pLocalData;
    
    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_cipher_cmac_update(pInfo->pCmacCtx, pInput->pData, pInput->length);
    if (0 != mbedStatus)
        goto exit;
    
    status = OK;
    
exit:
    
    return status;
}

MOC_EXTERN MSTATUS MAesCmacMbedFinal(
    MocSymCtx pSymCtx,
    MSymOperatorBuffer *pOutput
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MbedAesCmacInfo *pInfo;
    int mbedStatus;
    
    if (NULL == pSymCtx || NULL == pSymCtx->pLocalData || NULL == pOutput || NULL == pOutput->pOutputLen)
        goto exit;
    
    pInfo = (MbedAesCmacInfo *) pSymCtx->pLocalData;
    
    /* Check to see if the output buffer is large enough. */
    status = ERR_BUFFER_TOO_SMALL;
    *(pOutput->pOutputLen) = MOC_MBED_CMAC_RESULT_SIZE;
    if (pOutput->bufferSize < MOC_MBED_CMAC_RESULT_SIZE)
        goto exit;
    
    *(pOutput->pOutputLen) = 0;
    
    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_cipher_cmac_finish(pInfo->pCmacCtx, pOutput->pBuffer);
    if (0 != mbedStatus)
        goto exit;
    
    *(pOutput->pOutputLen) = MOC_MBED_CMAC_RESULT_SIZE;
    status = OK;
    
exit:
    
    return status;
}

MOC_EXTERN MSTATUS MAesCmacMbedFree(
    MocSymCtx pSymCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MbedAesCmacInfo *pInfo;
    
    if (NULL == pSymCtx)
        goto exit;
    
    pInfo = (MbedAesCmacInfo *) pSymCtx->pLocalData;

    status = OK; /* OK if there is nothing to free */
    if (NULL != pInfo)
    {
        MSTATUS fstatus;

        if (NULL != pInfo->pCmacCtx)
        {
            mbedtls_cipher_free(pInfo->pCmacCtx);
            status = DIGI_FREE((void **) &(pInfo->pCmacCtx));
        }
        
        if (NULL != pInfo->pKey)
        {
            DIGI_MEMSET(pInfo->pKey, 0x00, pInfo->keyLen);
            fstatus = DIGI_FREE((void **) &pInfo->pKey);
            if (OK == status)
                status = fstatus;
            
            pInfo->keyLen = 0;
        }

        fstatus = DIGI_FREE((void **) &pInfo);
        if (OK == status)
            status = fstatus;
        
        /* NULL the context's copy of the pointer too */
        pSymCtx->pLocalData = NULL;
    }
        
exit:
    
    return status;
}

MOC_EXTERN MSTATUS MAesCmacMbedClone(
    MocSymCtx pSymCtx,
    MocSymCtx pCopyCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    int mbedStatus = 0;
    MbedAesCmacInfo *pInfo = NULL;
    MbedAesCmacInfo *pNewInfo = NULL;
    mbedtls_cipher_context_t *pNewCtx = NULL;
    const mbedtls_cipher_info_t *pMbedInfo;
    
    if ( (NULL == pSymCtx) || (NULL == pCopyCtx) || (NULL == pSymCtx->pLocalData) )
        goto exit;
    
    pInfo = (MbedAesCmacInfo *) pSymCtx->pLocalData;

    /* Allocate the info shell */
    status = DIGI_CALLOC((void **) &pNewInfo, 1, sizeof(MbedAesCmacInfo));
    if (OK != status)
        goto exit;

    /* Copy the info shell */
    status = DIGI_MEMCPY((void *)pNewInfo, (void *)pInfo, sizeof(MbedAesCmacInfo));
    if (OK != status)
        goto exit;

    if (NULL != pInfo->pKey)
    {
        status = DIGI_MALLOC_MEMCPY (
            (void **)&pNewInfo->pKey, pInfo->keyLen, (void *)pInfo->pKey, pInfo->keyLen);
        if (OK != status)
            goto exit;
    }

    if (NULL != pInfo->pCmacCtx)
    {
        /* Instantiate a new cmac cipher context */
        switch (pInfo->keyLen)
        {
            case 16:
                pMbedInfo = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
                break;
                
            case 24:
                pMbedInfo = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_192_ECB);
                break;
                
            case 32:
                pMbedInfo = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB);
                break;
                
            default:
                goto exit;
        }

        status = DIGI_CALLOC((void **)&pNewCtx, 1, sizeof(mbedtls_cipher_context_t));
        if (OK != status)
            goto exit;

        status = ERR_MBED_FAILURE;
        mbedStatus = mbedtls_cipher_setup(pNewCtx, pMbedInfo);
        if (0 != mbedStatus)
            goto exit;

        mbedStatus = mbedtls_cipher_cmac_starts(pNewCtx, pNewInfo->pKey, pInfo->keyLen * 8);
        if (0 != mbedStatus)
            goto exit;

        if (NULL != pInfo->pCmacCtx->cmac_ctx)
        {
            /* Copy the underlying MBED context data */
            status = DIGI_MEMCPY (
                pNewCtx->cmac_ctx, (void *)pInfo->pCmacCtx->cmac_ctx, sizeof(mbedtls_cmac_context_t));
            if (OK != status)
                goto exit;
        }

        pNewInfo->pCmacCtx = pNewCtx;
        pNewCtx = NULL;
    }

    pCopyCtx->pLocalData = (void *)pNewInfo;
    pNewInfo = NULL;

exit:
    if (NULL != pNewInfo)
    {
        if (NULL != pNewInfo->pKey)
        {
            DIGI_FREE((void **)&pNewInfo->pKey);
        }
        DIGI_FREE((void **)&pNewInfo);
    }
    if (NULL != pNewCtx)
    {
        DIGI_FREE((void **)&pNewCtx);
    }

    return status;
    
}

#endif /* __ENABLE_DIGICERT_AES_CMAC_MBED__ */

