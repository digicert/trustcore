/*
 * mbedblowfish.c
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


#ifdef __ENABLE_DIGICERT_BLOWFISH_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbedblowfish.h"

MOC_EXTERN MSTATUS MBlowfishMbedCreate(
    MocSymCtx pSymCtx,
    MBlowfishUpdateData *pInput
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MBlowfishMbedInfo *pNewInfo = NULL;
    mbedtls_blowfish_context *pNewCtx = NULL;
    
    if (NULL == pSymCtx)
        goto exit;
    
    status = DIGI_CALLOC((void **) &pNewInfo, 1, sizeof(MBlowfishMbedInfo));
    if (OK != status)
        goto exit;
    
    status = DIGI_MALLOC((void **) &pNewCtx, sizeof(mbedtls_blowfish_context));
    if (OK != status)
        goto exit;
    
    mbedtls_blowfish_init(pNewCtx);
    
    pNewInfo->pBfCtx = pNewCtx;
    pSymCtx->pLocalData = (void *) pNewInfo;
    
    if (NULL != pInput)
    {
        status = MBlowfishMbedUpdateInfo(pSymCtx, pInput);
        if (OK != status)
            goto exit;
    }
    
    pSymCtx->localType = MOC_LOCAL_TYPE_BLOWFISH_CBC_OPERATOR;
    pSymCtx->SymOperator = SymOperatorBlowfish;
    
    pNewCtx = NULL;
    pNewInfo = NULL;
    
exit:
    
    if (NULL != pNewCtx)
        DIGI_FREE((void **) &pNewCtx);  /* here on error only, ignore return */
    
    if (NULL != pNewInfo)
        DIGI_FREE((void **) &pNewInfo); /* here on error only, ignore return */
    
    return status;
}


MOC_EXTERN MSTATUS MBlowfishMbedUpdateInfo(
    MocSymCtx pSymCtx,
    MBlowfishUpdateData *pInput
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MBlowfishMbedInfo *pInfo;
    
    if (NULL == pInput || NULL == pSymCtx || NULL == pSymCtx->pLocalData)
        goto exit;
    
    pInfo = (MBlowfishMbedInfo *) pSymCtx->pLocalData;
    
    if (NULL != pInput->pInitVector && 0 != pInput->initVectorLen)
    {
        status = ERR_BLOWFISH_BAD_IV_LENGTH;
        if (MBEDTLS_BLOWFISH_BLOCKSIZE != pInput->initVectorLen)
            goto exit;
        
        status = DIGI_MEMCPY(pInfo->pIv, pInput->pInitVector, MBEDTLS_BLOWFISH_BLOCKSIZE);
        if (OK != status)
            goto exit;
        
        pInfo->hasIv = TRUE;
    }
    
    status = OK;
    
exit:
    
    return status;
}


MOC_EXTERN MSTATUS MBlowfishMbedLoadKey(
    MocSymCtx pSymCtx,
    MSymOperatorData *pKeyData
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MBlowfishMbedInfo *pInfo;
    int mbedStatus;
    
    if (NULL == pKeyData || NULL == pKeyData->pData || NULL == pSymCtx || NULL == pSymCtx->pLocalData)
        goto exit;
    
    pInfo = (MBlowfishMbedInfo *) pSymCtx->pLocalData;
    if (NULL == pInfo->pBfCtx)
        goto exit;
    
    status = ERR_BLOWFISH_BAD_KEY_LENGTH;
    if ( pKeyData->length < (MBEDTLS_BLOWFISH_MIN_KEY_BITS/8) || pKeyData->length > (MBEDTLS_BLOWFISH_MAX_KEY_BITS/8) )
        goto exit;
    
    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_blowfish_setkey(pInfo->pBfCtx, (const unsigned char *) pKeyData->pData, (unsigned int) (8 * (pKeyData->length)) );
    if (mbedStatus)
        goto exit;
    
    status = OK;
    
exit:
    
    return status;
}


MOC_EXTERN MSTATUS MBlowfishMbedUpdate(
    MocSymCtx pSymCtx,
    ubyte4 opFlag,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MBlowfishMbedInfo *pInfo;
    int mbedStatus;
    
    if (NULL == pInput || NULL == pInput->pData || NULL == pSymCtx || NULL == pSymCtx->pLocalData ||
        NULL == pOutput || NULL == pOutput->pBuffer || NULL == pOutput->pOutputLen)
        goto exit;
    
    pInfo = (MBlowfishMbedInfo *) pSymCtx->pLocalData;
    if (NULL == pInfo->pBfCtx)
        goto exit;
    
    /* Check to see if the output buffer is large enough. */
    status = ERR_BUFFER_TOO_SMALL;
    *(pOutput->pOutputLen) = pInput->length;
    if (pOutput->bufferSize < pInput->length)
        goto exit;
    
    *(pOutput->pOutputLen) = 0;
    
    status = ERR_INVALID_INPUT;
    if ( !(pInfo->hasIv) )
        goto exit;
    
    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_blowfish_crypt_cbc( pInfo->pBfCtx, (int) opFlag, (size_t) pInput->length, pInfo->pIv,
                                            (const unsigned char *) pInput->pData, (unsigned char *) pOutput->pBuffer);
    if (mbedStatus)
        goto exit;
    
    *(pOutput->pOutputLen) = pInput->length;
    
    status = OK;
    
exit:
    
    return status;
}

MOC_EXTERN MSTATUS MBlowfishGetOpData(
    MBlowfishMbedInfo *pCtx,
    MSymOperatorData *pOutput
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    if(NULL == pCtx || NULL == pOutput || NULL == pOutput->pData)
        goto exit;
    
    status = DIGI_MEMCPY(pOutput->pData, pCtx->pIv, MBEDTLS_BLOWFISH_BLOCKSIZE);
    if (OK != status)
        goto exit;

    pOutput->length = MBEDTLS_BLOWFISH_BLOCKSIZE;

exit:
    return status;
}

MSTATUS MBlowfishMbedClone(
    MocSymCtx pCtx,
    MocSymCtx pCopyCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MBlowfishMbedInfo *pBlowfishInfo = NULL;
    MBlowfishMbedInfo *pNewInfo = NULL;
    mbedtls_blowfish_context *pNewCtx = NULL;

    if ( (NULL == pCtx) || (NULL == pCtx->pLocalData) || (NULL == pCopyCtx) )
        goto exit;

    pBlowfishInfo = (MBlowfishMbedInfo *)pCtx->pLocalData;

    /* Allocate the info shell */
    status = DIGI_CALLOC((void **) &pNewInfo, 1, sizeof(MBlowfishMbedInfo));
    if (OK != status)
        goto exit;

    /* Copy the info shell */
    status = DIGI_MEMCPY((void *)pNewInfo, (void *)pBlowfishInfo, sizeof(MBlowfishMbedInfo));
    if (OK != status)
        goto exit;

    if (NULL != pBlowfishInfo->pBfCtx)
    {
        /* Allocate the underlying MBED context */
        status = DIGI_MALLOC((void **)&pNewCtx, sizeof(mbedtls_blowfish_context));
        if (OK != status)
            goto exit;

        /* Copy the underlying MBED context data */
        status = DIGI_MEMCPY (
            pNewCtx, (void *)pBlowfishInfo->pBfCtx, sizeof(mbedtls_blowfish_context));
        if (OK != status)
            goto exit;

        pNewInfo->pBfCtx = pNewCtx;
        pNewCtx = NULL;
    }

    pCopyCtx->pLocalData = (void *)pNewInfo;
    pNewInfo = NULL;

exit:

    if (NULL != pNewInfo)
    {
        (void) DIGI_FREE((void **)&pNewInfo);
    }
    if (NULL != pNewCtx)
    {
        (void) DIGI_FREE((void **)&pNewCtx);
    }

    return status;
}

MOC_EXTERN MSTATUS MBlowfishMbedFree(
    MocSymCtx pSymCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MBlowfishMbedInfo *pInfo;
    
    if (NULL == pSymCtx)
        goto exit;
    
    pInfo = (MBlowfishMbedInfo *) pSymCtx->pLocalData;
    
    status = OK;
    if (NULL != pInfo)
    {
        MSTATUS fstatus;
        
        if (NULL != pInfo->pBfCtx)
        {
            mbedtls_blowfish_free(pInfo->pBfCtx);
            status = DIGI_FREE((void **) &(pInfo->pBfCtx));
        }
        
        fstatus = DIGI_MEMSET((ubyte *)pInfo, 0x00, sizeof(MBlowfishMbedInfo));
        if (OK == status)
            status = fstatus;
        
        fstatus = DIGI_FREE((void **) &pInfo);
        if (OK == status)
            status = fstatus;
        
        /* set the context's local data to NULL too */
        pSymCtx->pLocalData = NULL;
    }
    
exit:
    
    return status;
}
#endif /* __ENABLE_DIGICERT_BLOWFISH_MBED__ */
