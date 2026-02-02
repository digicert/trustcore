/*
 * mbedaesxts.c
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


#ifdef __ENABLE_DIGICERT_AES_XTS_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbedaesxts.h"

MOC_EXTERN MSTATUS MAesXtsMbedCreate(
    MocSymCtx pSymCtx,
    MAesUpdateData *pInput,
    ubyte4 localType,
    MSymOperator pSymOp
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesXtsMbedInfo *pNewInfo = NULL;
    
    if (NULL == pSymCtx)
        goto exit;
    
    status = DIGI_CALLOC((void **) &pNewInfo, 1, sizeof(MAesXtsMbedInfo));
    if (OK != status)
        goto exit;
    
    pSymCtx->pLocalData = (void *) pNewInfo;
    
    if (NULL != pInput)
    {
        status = MAesXtsMbedUpdateInfo(pSymCtx, pInput);
        if (OK != status)
            goto exit;
    }
    
    pSymCtx->localType = localType;
    pSymCtx->SymOperator = pSymOp;
    
    pNewInfo = NULL;
    
exit:
    
    if (NULL != pNewInfo)
    {
        DIGI_MEMSET((ubyte *) pNewInfo, 0x00, sizeof(MAesXtsMbedInfo));
        DIGI_FREE((void **) &pNewInfo);
    }

    return status;
}

MOC_EXTERN MSTATUS MAesXtsMbedUpdateInfo(
    MocSymCtx pSymCtx,
    MAesUpdateData *pInput
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesXtsMbedInfo *pInfo;
    
    if (NULL == pSymCtx || NULL == pSymCtx->pLocalData || NULL == pInput)
        goto exit;
    
    pInfo = (MAesXtsMbedInfo *) pSymCtx->pLocalData;
    
    if ( (NULL != pInput->pInitVector) && (0 != pInput->initVectorLen) )
    {
        /* make sure the tweak, ie iv, is correct length */
        status = ERR_AES_BAD_IV_LENGTH;
        if (16 != pInput->initVectorLen)
            goto exit;
        
        status = DIGI_MEMCPY(pInfo->pTweak, pInput->pInitVector, 16);
        if (OK != status)
            goto exit;
    }
    
    status = OK;
    
exit:
    
    return status;
}

MOC_EXTERN MSTATUS MAesXtsMbedLoadKey(
    MocSymCtx pSymCtx,
    MSymOperatorData *pKeyData
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesXtsMbedInfo *pInfo;
    
    if ( NULL == pSymCtx || NULL == pSymCtx->pLocalData || NULL == pKeyData || NULL == pKeyData->pData )
        goto exit;
    
    pInfo = (MAesXtsMbedInfo *) pSymCtx->pLocalData;
    
    status = ERR_AES_BAD_KEY_LENGTH;
    if (32 != pKeyData->length && 64 != pKeyData->length)
        goto exit;
    
    status = DIGI_MEMCPY(pInfo->pKey, pKeyData->pData, pKeyData->length);
    if (OK != status)
        goto exit;
    
    pInfo->keyLen = pKeyData->length;
    
exit:
    
    return status;
}

MOC_EXTERN MSTATUS MAesXtsMbedInit(
    MocSymCtx pSymCtx,
    MbedAesXtsSetKey pSetKeyMethod,
    sbyte4 flag
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesXtsMbedInfo *pInfo;
    mbedtls_aes_xts_context *pNewCtx = NULL;
    int mbedStatus;
    
    if (NULL == pSymCtx || NULL == pSetKeyMethod || NULL == pSymCtx->pLocalData)
        goto exit;
    
    pInfo = (MAesXtsMbedInfo *) pSymCtx->pLocalData;
    
    /* sanity check on the keyLen, still 2 keys concatenated */
    status = ERR_AES_BAD_KEY_LENGTH;
    if (32 != pInfo->keyLen && 64 != pInfo->keyLen)
        goto exit;
    
    pNewCtx = pInfo->pAesXtsCtx;
    
    if (NULL == pNewCtx)
    {
        status = DIGI_MALLOC((void **) &pNewCtx, sizeof(mbedtls_aes_xts_context));
        if (OK != status)
            goto exit;
    }
    
    mbedtls_aes_xts_init(pNewCtx);
    
    status = ERR_MBED_FAILURE;
    mbedStatus = pSetKeyMethod(pNewCtx, pInfo->pKey, pInfo->keyLen * 8);
    if (0 != mbedStatus)
        goto exit;
    
    pInfo->opFlag = flag;
    
    pInfo->pAesXtsCtx = pNewCtx;
    pNewCtx = NULL;
    status = OK;
    
exit:
    
    if (NULL != pNewCtx)
    {
        mbedtls_aes_xts_free(pNewCtx);
        DIGI_FREE((void **) &pNewCtx); /* ok to ignore return code */
    }
    
    return status;
}

MOC_EXTERN MSTATUS MAesXtsMbedUpdate(
    MocSymCtx pSymCtx,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesXtsMbedInfo *pInfo;
    int mbedStatus;
    ubyte *pTempOutput = NULL;
    ubyte *pOutPtr = NULL;
    
    if (NULL == pSymCtx || NULL == pSymCtx->pLocalData || NULL == pInput || NULL == pOutput || NULL == pOutput->pOutputLen)
        goto exit;
    
    status = ERR_INVALID_ARG;
    if (pInput->length < 16 || pInput->length > 0x1000000)
        goto exit;
    
    pInfo = (MAesXtsMbedInfo *) pSymCtx->pLocalData;
    
    /* Check to see if the output buffer is large enough. */
    status = ERR_BUFFER_TOO_SMALL;
    *(pOutput->pOutputLen) = pInput->length;
    if (pOutput->bufferSize < pInput->length)
        goto exit;
    
    *(pOutput->pOutputLen) = 0;
    
    status = ERR_MBED_FAILURE;
    /* mbed does not allow inplace encryption/decryption for uneven block lengths, we need a temp output */
    if (pInput->length & 0x0f)
    {
        status = DIGI_MALLOC((void **) &pTempOutput, pInput->length);
        if (OK != status)
            goto exit;
        
        pOutPtr = pTempOutput;
    }
    else
    {
        pOutPtr = pOutput->pBuffer;
    }
    
    mbedStatus = mbedtls_aes_crypt_xts(pInfo->pAesXtsCtx, pInfo->opFlag, pInput->length, pInfo->pTweak, pInput->pData, pOutPtr);
    if (0 != mbedStatus)
        goto exit;
    
    if (pInput->length & 0x0f) /* mod 16 */
    {
        status = DIGI_MEMCPY(pOutput->pBuffer, pOutPtr, pInput->length);
        if (OK != status)
            goto exit;
    }
    
    *(pOutput->pOutputLen) = pInput->length;
    status = OK;
    
exit:
    
    if (NULL != pTempOutput)
    {
        /* don't change status, ok to ignore return codes */
        DIGI_MEMSET(pTempOutput, 0x00, pInput->length);
        DIGI_FREE((void **) &pTempOutput);
    }
    
    return status;
}

MOC_EXTERN MSTATUS MAesXtsMbedFree(
    MocSymCtx pSymCtx
    )
{
    MSTATUS status, fstatus;
    MAesXtsMbedInfo *pInfo;

    status = ERR_NULL_POINTER;
    if (NULL == pSymCtx)
        goto exit;
    
    pInfo = (MAesXtsMbedInfo *) pSymCtx->pLocalData;
    
    status = OK;
    if (NULL != pInfo)
    {
        if (NULL != pInfo->pAesXtsCtx)
        {
            mbedtls_aes_xts_free(pInfo->pAesXtsCtx);
            status = DIGI_FREE((void **) &(pInfo->pAesXtsCtx));
        }
        
        fstatus = DIGI_MEMSET((ubyte *)pInfo, 0x00, sizeof(MAesXtsMbedInfo));
        if (OK == status)
            status = fstatus;
        
        fstatus = DIGI_FREE((void **) &pInfo);
        if (OK == status)
            status = fstatus;
        
        /* make sure to NULL the context's copy of the pointer too */
        pSymCtx->pLocalData = NULL;
    }
    
exit:
    
    return status;
}
#endif /* __ENABLE_DIGICERT_AES_XTS_MBED__ */
