/*
 * mbedaesecb.c
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


#ifdef __ENABLE_DIGICERT_AES_ECB_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbedaesecb.h"

MOC_EXTERN MSTATUS MAesEcbMbedCreate(
    MocSymCtx pSymCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesEcbMbedInfo *pNewCtx = NULL;

    if (NULL == pSymCtx)
        goto exit;

    status = DIGI_CALLOC((void **) &pNewCtx, 1, sizeof(MAesEcbMbedInfo));
    if (OK != status)
        goto exit;

    pSymCtx->localType = MOC_LOCAL_TYPE_AES_ECB_OPERATOR;
    pSymCtx->SymOperator = SymOperatorAesEcb;
    pSymCtx->pLocalData = pNewCtx;

    pNewCtx = NULL;

exit:

    if (NULL != pNewCtx)
        DIGI_FREE((void **) &pNewCtx);

    return status;
}

MOC_EXTERN MSTATUS MAesEcbMbedLoadKey(
    MocSymCtx pSymCtx,
    MSymOperatorData *pKeyData
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesEcbMbedInfo *pCtx;

    if ( (NULL == pSymCtx) || (NULL == pSymCtx->pLocalData) || (NULL == pKeyData) || (NULL == pKeyData->pData))
        goto exit;

    pCtx = (MAesEcbMbedInfo *) pSymCtx->pLocalData;

    switch (pKeyData->length)
    {
        default:
            status = ERR_AES_BAD_KEY_LENGTH;
            goto exit;

        case 16:
        case 24:
        case 32:
            break;
    }

    status = DIGI_MEMCPY(pCtx->pKey, pKeyData->pData, pKeyData->length);
    if (OK != status)
        goto exit;

    pCtx->keyLen = pKeyData->length;

exit:

    return status;
}

MOC_EXTERN MSTATUS MAesEcbMbedInit(
    MocSymCtx pSymCtx,
    MbedAesEcbSetKey pAesEcbSetKey
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesEcbMbedInfo *pCtx;
    mbedtls_aes_context *pNewCtx;
    int mbedStatus;
    byteBoolean isAllocated = FALSE;

    if ( (NULL == pSymCtx) || (NULL == pSymCtx->pLocalData) || (NULL == pAesEcbSetKey) )
        goto exit;

    pCtx = (MAesEcbMbedInfo *) pSymCtx->pLocalData;

    switch (pCtx->keyLen)
    {
        default:
            status = ERR_AES_BAD_KEY_LENGTH;
            goto exit;

        case 16:
        case 24:
        case 32:
            break;
    }

    pNewCtx = pCtx->pAesCtx;

    if (NULL == pNewCtx)
    {
        status = DIGI_MALLOC((void **) &pNewCtx, sizeof(mbedtls_aes_context));
        if (OK != status)
            goto exit;

        isAllocated = TRUE;
    }

    mbedtls_aes_init(pNewCtx);

    status = ERR_MBED_FAILURE;
    mbedStatus = pAesEcbSetKey(pNewCtx, pCtx->pKey, pCtx->keyLen * 8);
    if (0 != mbedStatus)
        goto exit;

    if (mbedtls_aes_setkey_enc == pAesEcbSetKey)
        pCtx->opFlag = MBEDTLS_AES_ENCRYPT;
    else
        pCtx->opFlag = MBEDTLS_AES_DECRYPT;

    pCtx->pAesCtx = pNewCtx;
    pNewCtx = NULL;
    status = OK;

exit:

    if (isAllocated && NULL != pNewCtx)
    {
        mbedtls_aes_free(pNewCtx);
        DIGI_FREE((void **) &pNewCtx); /* ok to ignore return, only here on error */
    }

    return status;
}

MOC_EXTERN MSTATUS MAesEcbMbedUpdate(
    MocSymCtx pSymCtx,
    ubyte opFlag,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesEcbMbedInfo *pCtx;
    ubyte4 blocks, curBlock;
    int mbedStatus;

    if (NULL == pSymCtx || NULL == pSymCtx->pLocalData || NULL == pInput || NULL == pOutput)
        goto exit;

    pCtx = (MAesEcbMbedInfo *) pSymCtx->pLocalData;

    status = ERR_AES_BAD_OPERATION;
    if (pCtx->opFlag != opFlag)
        goto exit;

    status = ERR_AES_BAD_LENGTH;
    if ( 0 != (pInput->length % 16) )
        goto exit;

    /* Check to see if the output buffer is large enough.
     */
    status = ERR_BUFFER_TOO_SMALL;
    *(pOutput->pOutputLen) = pInput->length;
    if (pOutput->bufferSize < pInput->length)
        goto exit;

    *(pOutput->pOutputLen) = 0;

    blocks = (pInput->length / 16);

    status = ERR_MBED_FAILURE;
    for (curBlock = 0; curBlock < blocks; ++curBlock)
    {
        mbedStatus = mbedtls_aes_crypt_ecb(
            pCtx->pAesCtx, opFlag, pInput->pData + (curBlock * 16),
            pOutput->pBuffer + (curBlock * 16));
        if (0 != mbedStatus)
            goto exit;
    }

    *(pOutput->pOutputLen) = pInput->length;
    status = OK;

exit:

    return status;
}

MOC_EXTERN MSTATUS MAesEcbMbedFree(
    MocSymCtx pSymCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesEcbMbedInfo *pCtx;

    if (NULL == pSymCtx)
        goto exit;

    pCtx = (MAesEcbMbedInfo *) pSymCtx->pLocalData;

    status = OK;
    if (NULL != pCtx)
    {
        MSTATUS fstatus;

        if (NULL != pCtx->pAesCtx)
        {
            mbedtls_aes_free(pCtx->pAesCtx);
            status = DIGI_FREE((void **) &(pCtx->pAesCtx));
        }

        fstatus = DIGI_MEMSET((ubyte *)pCtx, 0x00, sizeof(MAesEcbMbedInfo));
        if (OK == status)
            status = fstatus;

        fstatus = DIGI_FREE((void **) &pCtx);
        if (OK == status)
            status = fstatus;

        /* and set the context's copy to NULL too */
        pSymCtx->pLocalData = NULL;
    }

exit:

    return status;
}

MOC_EXTERN MSTATUS MAesEcbMbedClone(
    MocSymCtx pCtx,
    MocSymCtx pCopyCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesEcbMbedInfo *pAesInfo = NULL;
    MAesEcbMbedInfo *pNewInfo = NULL;
    mbedtls_aes_context *pNewCtx = NULL;

    if ( (NULL == pCtx) || (NULL == pCtx->pLocalData) || (NULL == pCopyCtx) )
        goto exit;

    pAesInfo = (MAesEcbMbedInfo *)pCtx->pLocalData;

    /* Allocate the info shell */
    status = DIGI_CALLOC((void **) &pNewInfo, 1, sizeof(MAesEcbMbedInfo));
    if (OK != status)
        goto exit;

    /* Copy the info shell */
    status = DIGI_MEMCPY((void *)pNewInfo, (void *)pAesInfo, sizeof(MAesEcbMbedInfo));
    if (OK != status)
        goto exit;

    if (NULL != pAesInfo->pAesCtx)
    {
        /* Allocate the underlying MBED context */
        status = DIGI_MALLOC((void **)&pNewCtx, sizeof(mbedtls_aes_context));
        if (OK != status)
            goto exit;

        /* Copy the underlying MBED context data */
        status = DIGI_MEMCPY (
            pNewCtx, (void *)pAesInfo->pAesCtx, sizeof(mbedtls_aes_context));
        if (OK != status)
            goto exit;

        /* Redirect internal pointer */
        if (NULL != pNewCtx->rk)
            pNewCtx->rk = pNewCtx->buf;

        pNewInfo->pAesCtx = pNewCtx;
        pNewCtx = NULL;
    }

    pCopyCtx->pLocalData = (void *)pNewInfo;
    pNewInfo = NULL;

exit:
    if (NULL != pNewInfo)
    {
        DIGI_FREE((void **)&pNewInfo);
    }
    if (NULL != pNewCtx)
    {
        DIGI_FREE((void **)&pNewCtx);
    }

    return status;
}

#endif /* __ENABLE_DIGICERT_AES_ECB_MBED__ */
