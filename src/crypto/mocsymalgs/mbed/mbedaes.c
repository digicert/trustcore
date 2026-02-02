/*
 * mbedaes.c
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


#if ( defined(__ENABLE_DIGICERT_AES_CBC_MBED__) || \
      defined(__ENABLE_DIGICERT_AES_CFB128_MBED__) || \
      defined(__ENABLE_DIGICERT_AES_OFB_MBED__) || \
      defined(__ENABLE_DIGICERT_AES_CTR_MBED__) )

#include "../../../crypto/mocsymalgs/mbed/mbedaes.h"

MOC_EXTERN MSTATUS MAesMbedCreate(
    MocSymCtx pSymCtx,
    MAesUpdateData *pInput,
    ubyte4 localType,
    MSymOperator pSymOp
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesMbedInfo *pNewCtx = NULL;

    if (NULL == pSymCtx)
        goto exit;

    status = DIGI_CALLOC((void **) &pNewCtx, 1, sizeof(MAesMbedInfo));
    if (OK != status)
        goto exit;

    pSymCtx->pLocalData = pNewCtx;

    if (NULL != pInput)
    {
        status = MAesMbedUpdateInfo(pSymCtx, pInput);
        if (OK != status)
            goto exit;
    }

    pSymCtx->localType = localType;
    pSymCtx->SymOperator = pSymOp;

    pNewCtx = NULL;

exit:

    if (NULL != pNewCtx)
        DIGI_FREE((void **) &pNewCtx);

    return status;
}

MOC_EXTERN MSTATUS MAesMbedUpdateInfo(
    MocSymCtx pSymCtx,
    MAesUpdateData *pInput
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesMbedInfo *pInfo;

    if (NULL == pInput || NULL == pSymCtx || NULL == pSymCtx->pLocalData)
        goto exit;

    pInfo = (MAesMbedInfo *) pSymCtx->pLocalData;

    if ( (NULL != pInput->pInitVector) && (0 != pInput->initVectorLen) )
    {
        status = ERR_AES_BAD_IV_LENGTH;
        if (16 != pInput->initVectorLen)
            goto exit;

        status = DIGI_MEMCPY(pInfo->pIv, pInput->pInitVector, 16);
        if (OK != status)
            goto exit;

        pInfo->ivLen = 16;
    }

    status = OK;

exit:

    return status;
}

MOC_EXTERN MSTATUS MAesMbedLoadKey(
    MocSymCtx pSymCtx,
    MSymOperatorData *pKeyData
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesMbedInfo *pCtx;

    if (NULL == pKeyData || NULL == pKeyData->pData ||
        NULL == pSymCtx || NULL == pSymCtx->pLocalData)
        goto exit;

    pCtx = (MAesMbedInfo *) pSymCtx->pLocalData;

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

MOC_EXTERN MSTATUS MAesMbedInit(
    MocSymCtx pSymCtx,
    MbedAesSetKey pAesSetKey,
    ubyte4 opFlag
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesMbedInfo *pCtx;
    mbedtls_aes_context *pNewCtx = NULL;
    int mbedStatus;
    byteBoolean isAllocated = FALSE;

    if ((NULL == pAesSetKey) || (NULL == pSymCtx) || (NULL == pSymCtx->pLocalData))
        goto exit;

    pCtx = (MAesMbedInfo *) pSymCtx->pLocalData;

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

    status = ERR_AES_BAD_IV_LENGTH;
    if (16 != pCtx->ivLen)
        goto exit;

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
    mbedStatus = pAesSetKey(pNewCtx, pCtx->pKey, pCtx->keyLen * 8);
    if (0 != mbedStatus)
        goto exit;

    pCtx->opFlag = opFlag;

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

MOC_EXTERN MSTATUS MAesMbedUpdate(
    MocSymCtx pSymCtx,
    ubyte opFlag,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput,
    MAesCrypt pAesCrypt
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesMbedInfo *pCtx;

    if (NULL == pSymCtx || NULL == pSymCtx->pLocalData || NULL == pInput ||
        NULL == pOutput || NULL == pOutput->pOutputLen)
        goto exit;

    pCtx = (MAesMbedInfo *) pSymCtx->pLocalData;

    status = ERR_AES_BAD_OPERATION;
    if (pCtx->opFlag != opFlag)
        goto exit;

    /* Check to see if the output buffer is large enough.
     */
    status = ERR_BUFFER_TOO_SMALL;
    *(pOutput->pOutputLen) = pInput->length;
    if (pOutput->bufferSize < pInput->length)
        goto exit;

    *(pOutput->pOutputLen) = 0;

    status = pAesCrypt(pCtx, pInput, pOutput);
    if (OK != status)
        goto exit;

    *(pOutput->pOutputLen) = pInput->length;

exit:

    return status;
}

MOC_EXTERN MSTATUS MAesMbedFree(
    MocSymCtx pSymCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MSTATUS fstatus;
    MAesMbedInfo *pCtx;

    if (NULL == pSymCtx)
        goto exit;

    pCtx = (MAesMbedInfo *) pSymCtx->pLocalData;

    status = OK;
    if (NULL != pCtx)
    {
        if (NULL != pCtx->pAesCtx)
        {
            mbedtls_aes_free(pCtx->pAesCtx);
            status = DIGI_FREE((void **) &(pCtx->pAesCtx));
        }

        fstatus = DIGI_MEMSET((ubyte *)pCtx, 0x00, sizeof(MAesMbedInfo));
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

MOC_EXTERN MSTATUS MAesGetOpData(
    MAesMbedInfo *pCtx,
    MSymOperatorData *pOutput
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    if (NULL == pCtx || NULL == pOutput || NULL == pOutput->pData)
        goto exit;

    status = DIGI_MEMCPY(pOutput->pData, pCtx->pIv, 16);
    if (OK != status)
        goto exit;

    pOutput->length = 16;

exit:
    return status;
}

MSTATUS MAesMbedClone(
    MocSymCtx pCtx,
    MocSymCtx pCopyCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesMbedInfo *pAesInfo = NULL;
    MAesMbedInfo *pNewInfo = NULL;
    mbedtls_aes_context *pNewCtx = NULL;

    if ( (NULL == pCtx) || (NULL == pCtx->pLocalData) || (NULL == pCopyCtx) )
        goto exit;

    pAesInfo = (MAesMbedInfo *)pCtx->pLocalData;

    /* Allocate the info shell */
    status = DIGI_CALLOC((void **) &pNewInfo, 1, sizeof(MAesMbedInfo));
    if (OK != status)
        goto exit;

    /* Copy the info shell */
    status = DIGI_MEMCPY((void *)pNewInfo, (void *)pAesInfo, sizeof(MAesMbedInfo));
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


#ifdef __ENABLE_DIGICERT_AES_CBC_MBED__

MOC_EXTERN MSTATUS MAesCbcMbedCrypt(
    MAesMbedInfo *pCtx,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput
    )
{
    MSTATUS status = ERR_AES_BAD_LENGTH;
    int mbedStatus;

    /*
     internal method used as function pointer,
     input params already checked to be non-null
     however check that the input is an even block length
     */

    if ( 0 != (pInput->length % 16) )
        goto exit;

    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_aes_crypt_cbc(
        pCtx->pAesCtx, pCtx->opFlag, pInput->length, pCtx->pIv,
        pInput->pData, pOutput->pBuffer);
    if (0 != mbedStatus)
        goto exit;

    status = OK;

exit:

    return status;
}

#endif

#ifdef __ENABLE_DIGICERT_AES_CFB128_MBED__

MOC_EXTERN MSTATUS MAesCfb128MbedCrypt(
    MAesMbedInfo *pCtx,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput
    )
{
    MSTATUS status = ERR_AES_BAD_LENGTH;
    int mbedStatus;
    size_t ivOffset = 0;

    /*
     internal method used as function pointer,
     input params already checked to be non-null
     */

    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_aes_crypt_cfb128(
        pCtx->pAesCtx, pCtx->opFlag, pInput->length, &ivOffset,
        pCtx->pIv, pInput->pData, pOutput->pBuffer);
    if (0 != mbedStatus)
        goto exit;

    status = OK;

exit:

    return status;
}

#endif

#ifdef __ENABLE_DIGICERT_AES_OFB_MBED__

MOC_EXTERN MSTATUS MAesOfbMbedCrypt(
    MAesMbedInfo *pCtx,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput
    )
{
    MSTATUS status = ERR_AES_BAD_LENGTH;
    int mbedStatus;
    size_t ivOffset = 0;

    /*
     internal method used as function pointer,
     input params already checked to be non-null
     */

    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_aes_crypt_ofb(
        pCtx->pAesCtx, pInput->length, &ivOffset, pCtx->pIv,
        pInput->pData, pOutput->pBuffer);
    if (0 != mbedStatus)
        goto exit;

    status = OK;

exit:

    return status;
}

#endif

#ifdef __ENABLE_DIGICERT_AES_CTR_MBED__

MOC_EXTERN MSTATUS MAesCtrMbedCrypt(
    MAesMbedInfo *pCtx,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput
    )
{
    MSTATUS status = ERR_MBED_FAILURE;
    int mbedStatus;
    size_t ivOffset = (size_t) pCtx->ivOffset;

    /*
     internal method used as function pointer,
     input params already checked to be non-null
     NONCE operates like IV in other APIS
     */
    mbedStatus = mbedtls_aes_crypt_ctr(
        pCtx->pAesCtx, pInput->length, &ivOffset, pCtx->pIv,
        pCtx->pStreamBlock, pInput->pData, pOutput->pBuffer);
    if (0 != mbedStatus)
        goto exit;

    pCtx->ivOffset = (ubyte) ivOffset;
    status = OK;

exit:

    return status;
}

MOC_EXTERN MSTATUS MAesCtrMbedGetCounterBlock(
    MAesMbedInfo *pCtx,
    MSymOperatorData *pOutput
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    if (NULL == pCtx || NULL == pOutput || NULL == pOutput->pData)
        goto exit;

    status = DIGI_MEMCPY(pOutput->pData, pCtx->pIv, 16);
    if (OK != status)
        goto exit;

    pOutput->length = 16;

exit:
    return status;
}

MOC_EXTERN MSTATUS MAesCtrMbedUpdateInfo(
    MocSymCtx pSymCtx,
    MAesCtrUpdateData *pInput
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesMbedInfo *pInfo;

    if (NULL == pInput || NULL == pSymCtx || NULL == pSymCtx->pLocalData)
        goto exit;

    pInfo = (MAesMbedInfo *) pSymCtx->pLocalData;

    /*
     pInfo->pIv needs to consist of [4 byte nonce || 8 byte iv || 4 byte ctr ].
     If we passed in 16 bytes for the iv then it is the full concatentation above.

     Otherwise we update the appropriate portions.

     We set pInfo->ivLen to 16 for all cases as we assume any missing portion
     was already or will be updated before performing the cipher operation.
     */
    if (NULL != pInput->iv.pData && pInput->iv.length)
    {
        if (16 == pInput->iv.length)
        {
            status = DIGI_MEMCPY(pInfo->pIv, pInput->iv.pData, 16);
            if (OK != status)
                goto exit;
        }
        else if (8 == pInput->iv.length)
        {
            status = DIGI_MEMCPY(pInfo->pIv + 4, pInput->iv.pData, 8);
            if (OK != status)
                goto exit;
        }
        else
        {
            status = ERR_AES_BAD_IV_LENGTH;
            goto exit;
        }
    }

    if (NULL != pInput->nonce.pData && pInput->nonce.length)
    {
        status = ERR_AES_BAD_NONCE_LENGTH;
        if (4 != pInput->nonce.length)
            goto exit;

        status = DIGI_MEMCPY(pInfo->pIv, pInput->nonce.pData, 4);
        if (OK != status)
            goto exit;
    }

    if (NULL != pInput->ctr.pData && pInput->ctr.length)
    {
        status = ERR_AES_BAD_CTR_LENGTH;
        if (4 != pInput->ctr.length)
            goto exit;

        status = DIGI_MEMCPY(pInfo->pIv + 12, pInput->ctr.pData, 4);
        if (OK != status)
            goto exit;
    }

    pInfo->ivLen = 16;

    /* And finally set the stream offset if needbe (which we called ivOffset) */
    if (pInput->updateStreamOffset)
        pInfo->ivOffset = pInput->streamOffset;

    status = OK;

exit:

    return status;
}

#endif /* __ENABLE_DIGICERT_AES_CTR_MBED__ */

#endif /* __ENABLE_DIGICERT_AES_CBC_MBED__ ||
          __ENABLE_DIGICERT_AES_CFB128_MBED__ ||
          __ENABLE_DIGICERT_AES_OFB_MBED__ ||
          __ENABLE_DIGICERT_AES_CTR_MBED__ */
