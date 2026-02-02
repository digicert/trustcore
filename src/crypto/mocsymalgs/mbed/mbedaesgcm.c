/*
 * mbedaesgcm.c
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


#ifdef __ENABLE_DIGICERT_AES_GCM_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbedaesgcm.h"

MOC_EXTERN MSTATUS MAesGcmMbedCreate(
    MocSymCtx pSymCtx,
    MAesGcmUpdateData *pGcmData
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    MAesGcmMbedInfo *pNewInfo = NULL;

    if (NULL == pSymCtx)
        goto exit;

    status = DIGI_CALLOC((void **) &pNewInfo, 1, sizeof(MAesGcmMbedInfo));
    if (OK != status)
        goto exit;

    pSymCtx->pLocalData = pNewInfo;

    if (NULL != pGcmData)
    {
        status = MAesGcmMbedUpdateInfo(pSymCtx, pGcmData);
        if (OK != status)
            goto exit;
    }

    pSymCtx->localType = MOC_LOCAL_TYPE_AES_GCM_OPERATOR;
    pSymCtx->SymOperator = SymOperatorAesGcm;

    pNewInfo = NULL;

exit:

    if (NULL != pNewInfo)
        DIGI_FREE((void **) &pNewInfo);

    return status;
}

MOC_EXTERN MSTATUS MAesGcmMbedUpdateInfo(
    MocSymCtx pSymCtx,
    MAesGcmUpdateData *pGcmData
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesGcmMbedInfo *pInfo;

    if ( (NULL == pGcmData) || (NULL == pSymCtx) || (NULL == pSymCtx->pLocalData) )
        goto exit;

    pInfo = (MAesGcmMbedInfo *) pSymCtx->pLocalData;

    if (0 != pGcmData->tagLen)
    {
        status = ERR_AES_BAD_ARG;
        switch(pGcmData->tagLen)
        {
            case 16:
            case 15:
            case 14:
            case 13:
            case 12:
            case 8:
            case 4:
                break;

            default:
                goto exit;
        }

        pInfo->tagLen = pGcmData->tagLen;
    }

    if ( (0 != pGcmData->nonce.length) && (NULL != pGcmData->nonce.pData) )
    {
        if (NULL != pInfo->pNonce)
        {
            status = DIGI_FREE((void **) &(pInfo->pNonce));
            if (OK != status)
                goto exit;

            pInfo->nonceLen = 0;
        }

        status = DIGI_MALLOC(
            (void **) &(pInfo->pNonce), pGcmData->nonce.length);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(
            (void *) pInfo->pNonce, pGcmData->nonce.pData,
            pGcmData->nonce.length);
        if (OK != status)
            goto exit;

        pInfo->nonceLen = pGcmData->nonce.length;
    }

    if ( (NULL != pGcmData->aad.pData) || (0 != pGcmData->aad.length) )
    {
        if (NULL != pInfo->pAad)
        {
            status = DIGI_FREE((void **) &(pInfo->pAad));
            if (OK != status)
                goto exit;

            pInfo->aadLen = 0;
        }

        status = DIGI_MALLOC(
            (void **) &(pInfo->pAad), pGcmData->aad.length);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(
            (void *) pInfo->pAad, pGcmData->aad.pData, pGcmData->aad.length);
        if (OK != status)
            goto exit;

        pInfo->aadLen = pGcmData->aad.length;
    }

    status = OK;

exit:

    return status;
}

MOC_EXTERN MSTATUS MAesGcmMbedFree(
    MocSymCtx pSymCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesGcmMbedInfo *pInfo;

    if (NULL == pSymCtx)
        goto exit;

    pInfo = (MAesGcmMbedInfo *) pSymCtx->pLocalData;

    status = OK;  /* ok if there is nothing to free */
    if (NULL != pInfo)
    {
        MSTATUS fstatus;

        if (NULL != pInfo->pGcmCtx)
        {
            mbedtls_gcm_free(pInfo->pGcmCtx);
            status = DIGI_FREE((void **) &(pInfo->pGcmCtx));
        }

        if (NULL != pInfo->pNonce)
        {
            fstatus = DIGI_FREE((void **) &(pInfo->pNonce));
            if (OK == status)
                status = fstatus;
        }

        if (NULL != pInfo->pAad)
        {
            fstatus = DIGI_FREE((void **) &(pInfo->pAad));
            if (OK == status)
                status = fstatus;
        }

        fstatus = DIGI_MEMSET((ubyte *) pInfo, 0x00, sizeof(MAesGcmMbedInfo));
        if (OK == status)
            status = fstatus;

        fstatus = DIGI_FREE((void **) &pInfo);
        if (OK == status)
            status = fstatus;

        /* and set the context's copy to NULL too */
        pSymCtx->pLocalData = NULL;
    }

exit:

    return status;
}

MOC_EXTERN MSTATUS MAesGcmMbedGenKey (
    MocSymCtx pCtx,
    MSymKeyGenInfo *pGenInfo,
    MSymOperatorBuffer *pOutput
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesGcmMbedInfo *pInfo;
    ubyte4 bufSize, keyLenBytes;

    if ( (NULL == pGenInfo->pRandInfo) || (NULL == pGenInfo->pRandInfo->RngFun) ||
         (NULL == pCtx) || (NULL == pCtx->pLocalData) )
        goto exit;

    pInfo = (MAesGcmMbedInfo *) pCtx->pLocalData;

    switch (pGenInfo->keySizeBits)
    {
        default:
            status = ERR_AES_BAD_KEY_LENGTH;
            goto exit;

        case 128:
        case 192:
        case 256:
            keyLenBytes = pGenInfo->keySizeBits / 8;
            break;
    }

    if ( (NULL != pOutput) && (NULL != pOutput->pOutputLen) )
    {
        bufSize = 0;
        if (NULL != pOutput->pBuffer)
            bufSize = pOutput->bufferSize;

        status = ERR_BUFFER_TOO_SMALL;
        *(pOutput->pOutputLen) = keyLenBytes;
        if (bufSize < keyLenBytes)
            goto exit;

        *(pOutput->pOutputLen) = 0;
    }

    status = pGenInfo->pRandInfo->RngFun(
        pGenInfo->pRandInfo->pRngFunArg, keyLenBytes, pInfo->pKey);
    if (OK != status)
        goto exit;

    pInfo->keyLen = keyLenBytes;

    if ( (NULL != pOutput) && (NULL != pOutput->pBuffer) &&
         (NULL != pOutput->pOutputLen) )
    {
        status = DIGI_MEMCPY(
            pOutput->pBuffer, pInfo->pKey, keyLenBytes);
        if (OK != status)
            goto exit;

        *(pOutput->pOutputLen) = keyLenBytes;
    }

exit:

    return status;
}

MOC_EXTERN MSTATUS MAesGcmMbedLoadKey (
    MocSymCtx pCtx,
    MSymOperatorData *pKeyData
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesGcmMbedInfo *pInfo;

    if (NULL == pCtx || NULL == pCtx->pLocalData || NULL == pKeyData)
        goto exit;

    pInfo = (MAesGcmMbedInfo *) pCtx->pLocalData;

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

    pInfo->keyLen = 0;

    status = DIGI_MEMCPY(
        pInfo->pKey, pKeyData->pData, pKeyData->length);
    if (OK != status)
        goto exit;

    pInfo->keyLen = pKeyData->length;

exit:

    return status;
}

MOC_EXTERN MSTATUS MAesGcmMbedInit (
    MocSymCtx pCtx,
    ubyte4 cipherFlag
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesGcmMbedInfo *pInfo;
    int mbedStatus;
    byteBoolean isAllocated = FALSE;

    if (NULL == pCtx || NULL == pCtx->pLocalData)
        goto exit;

    pInfo = (MAesGcmMbedInfo *) pCtx->pLocalData;

    /* Check for the key and nonce. The tag can be specified later. */
    status = ERR_INVALID_ARG;
    if ( (0 == pInfo->keyLen) || (NULL == pInfo->pNonce) )
        goto exit;

    if (NULL == pInfo->pGcmCtx)
    {
        status = DIGI_MALLOC(
            (void **) &(pInfo->pGcmCtx), sizeof(mbedtls_gcm_context));
        if (OK != status)
            goto exit;

        mbedtls_gcm_init(pInfo->pGcmCtx);
        isAllocated = TRUE;
    }

    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_gcm_setkey(
        pInfo->pGcmCtx, MBEDTLS_CIPHER_ID_AES, pInfo->pKey, pInfo->keyLen * 8);
    if (0 != mbedStatus)
        goto exit;

    mbedStatus = mbedtls_gcm_starts(
        pInfo->pGcmCtx, cipherFlag, pInfo->pNonce, pInfo->nonceLen,
        pInfo->pAad, pInfo->aadLen);
    if (0 != mbedStatus)
        goto exit;

    pInfo->cryptFlag = cipherFlag;
    status = OK;

exit:

    if (isAllocated && OK != status && NULL != pInfo->pGcmCtx)
    {
        mbedtls_gcm_free(pInfo->pGcmCtx);
        DIGI_FREE((void **) &(pInfo->pGcmCtx)); /* ok to ignore return code, only here on error */
    }

    return status;
}

static MSTATUS MbedAesGcmTempBlockSizeUpdate(
    mbedtls_gcm_context *pGcmCtx,
    ubyte *pData,
    ubyte4 processedDataLen,
    ubyte4 dataToProcess,
    ubyte *pOutput
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    mbedtls_gcm_context tempCtx = { 0 };
    ubyte pTemp[16];
    int mbedStatus;

    if (NULL == pGcmCtx || NULL == pData || NULL == pOutput)
        goto exit;

    /* Copy over the state of the AES-GCM context into the temporary context.
     */
    status = DIGI_MEMCPY(&tempCtx, pGcmCtx, sizeof(tempCtx));
    if (OK != status)
        goto exit;

    /* NULL out the cipher context underneath in case an error occurs on the
     * upcoming malloc. If an error occurs there then the clean up code will
     * free the pointer store in this location which is the original pointer,
     * which we don't want to do.
     */
    tempCtx.cipher_ctx.cipher_ctx = NULL;

    status = DIGI_MALLOC(
        (void **) &(tempCtx.cipher_ctx.cipher_ctx),
        sizeof(mbedtls_aes_context));
    if (OK != status)
        goto exit;

    /* Copy over the state of the underneath AES context into the underneath
     * AES context of the temporary AES-GCM context.
     */
    status = DIGI_MEMCPY(
        tempCtx.cipher_ctx.cipher_ctx, pGcmCtx->cipher_ctx.cipher_ctx,
        sizeof(mbedtls_aes_context));
    if (OK != status)
        goto exit;

    /* Redirect internal pointer */
    if (NULL != ((mbedtls_aes_context *) tempCtx.cipher_ctx.cipher_ctx)->rk)
        ((mbedtls_aes_context *) tempCtx.cipher_ctx.cipher_ctx)->rk = ((mbedtls_aes_context *) tempCtx.cipher_ctx.cipher_ctx)->buf;

    /* Process the data with the temporary context. The temporary context must
     * be used because mbedtls only allows multiples of block size on update
     * calls. Only the last call to update will be allowed to pass in an input
     * length of non-block size.
     *
     * Also, copy into a temporary buffer because if there was any leftover data
     * then it was already processed in a previous call, so it doesn't need to
     * be processed again and copied into the caller provided output buffer.
     */
    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_gcm_update(
        &tempCtx, processedDataLen + dataToProcess, pData, pTemp);
    if (0 != mbedStatus)
        goto exit;

    /* Copy however much data needs to be copied over.
     */
    status = DIGI_MEMCPY(pOutput, pTemp + processedDataLen, dataToProcess);
    if (OK != status)
        goto exit;

exit:

    DIGI_MEMSET(pTemp, 0x00, 16);

    if (NULL != tempCtx.cipher_ctx.cipher_ctx)
        DIGI_FREE(&(tempCtx.cipher_ctx.cipher_ctx));

    return status;
}

MSTATUS MAesGcmMbedClone(
    MocSymCtx pCtx,
    MocSymCtx pCopyCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesGcmMbedInfo *pAesInfo = NULL;
    MAesGcmMbedInfo *pNewInfo = NULL;
    void *pNewCtx = NULL;
    mbedtls_aes_context *pNewCipherCtx = NULL;
    void *pNewNonce = NULL;
    void *pNewAad = NULL;

    if ( (NULL == pCtx) || (NULL == pCtx->pLocalData) || (NULL == pCopyCtx) )
        goto exit;

    pAesInfo = (MAesGcmMbedInfo *)pCtx->pLocalData;

    /* Allocate the info shell */
    status = DIGI_CALLOC((void **) &pNewInfo, 1, sizeof(MAesGcmMbedInfo));
    if (OK != status)
        goto exit;

    /* Copy the info shell */
    status = DIGI_MEMCPY((void *)pNewInfo, (void *)pAesInfo, sizeof(MAesGcmMbedInfo));
    if (OK != status)
        goto exit;

    if (NULL != pAesInfo->pNonce)
    {
        status = DIGI_MALLOC((void **)&pNewNonce, pAesInfo->nonceLen);
        if (OK != status)
            goto exit;

        /* Copy the underlying MBED context data */
        status = DIGI_MEMCPY (
            pNewNonce, (void *)pAesInfo->pNonce, pAesInfo->nonceLen);
        if (OK != status)
            goto exit;

        pNewInfo->pNonce = pNewNonce;
        pNewNonce = NULL;
    }

    if (NULL != pAesInfo->pAad)
    {
        status = DIGI_MALLOC((void **)&pNewAad, pAesInfo->aadLen);
        if (OK != status)
            goto exit;

        /* Copy the underlying MBED context data */
        status = DIGI_MEMCPY (
            pNewAad, (void *)pAesInfo->pAad, pAesInfo->aadLen);
        if (OK != status)
            goto exit;

        pNewInfo->pAad = pNewAad;
        pNewAad = NULL;
    }

    if (NULL != pAesInfo->pGcmCtx)
    {
        /* Allocate the underlying MBED context */
        status = DIGI_MALLOC((void **)&pNewCtx, sizeof(mbedtls_gcm_context));
        if (OK != status)
            goto exit;

        /* Copy the underlying MBED context data */
        status = DIGI_MEMCPY (
            pNewCtx, (void *)pAesInfo->pGcmCtx, sizeof(mbedtls_gcm_context));
        if (OK != status)
            goto exit;

        pNewInfo->pGcmCtx = (mbedtls_gcm_context *)pNewCtx;
        pNewCtx = NULL;

        if (NULL != pAesInfo->pGcmCtx->cipher_ctx.cipher_ctx)
        {
            status = DIGI_MALLOC((void **)&pNewCipherCtx, sizeof(mbedtls_aes_context));
            if (OK != status)
                goto exit;

            status = DIGI_MEMCPY (
                pNewCipherCtx, pAesInfo->pGcmCtx->cipher_ctx.cipher_ctx, sizeof(mbedtls_aes_context));
            if (OK != status)
                goto exit;

            /* Redirect internal pointer */
            if (NULL != pNewCipherCtx->rk)
                pNewCipherCtx->rk = pNewCipherCtx->buf;

            pNewInfo->pGcmCtx->cipher_ctx.cipher_ctx = pNewCipherCtx;
            pNewCipherCtx = NULL;
        }

        /* This pointer is not actually allocated by MBED, it points to existing memory
         * managed by MBED so simply copy the reference */
        if (NULL != pAesInfo->pGcmCtx->cipher_ctx.cipher_info)
        {
            pNewInfo->pGcmCtx->cipher_ctx.cipher_info = pAesInfo->pGcmCtx->cipher_ctx.cipher_info;
        }
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
    if (NULL != pNewCipherCtx)
    {
        DIGI_FREE((void **)&pNewCipherCtx);
    }
    if (NULL != pNewNonce)
    {
        DIGI_FREE((void **)&pNewNonce);
    }
    if (NULL != pNewAad)
    {
        DIGI_FREE((void **)&pNewAad);
    }

    return status;
}

MOC_EXTERN MSTATUS MAesGcmMbedUpdate (
    MocSymCtx pCtx,
    MSymOperatorData *pInputInfo,
    MSymOperatorBuffer *pOutputInfo
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesGcmMbedInfo *pInfo;
    ubyte4 outLen, copyLen;
    int mbedStatus;
    ubyte pTemp[16];

    if (NULL == pCtx || NULL == pCtx->pLocalData || NULL == pInputInfo || NULL == pOutputInfo)
        goto exit;

    pInfo = (MAesGcmMbedInfo *) pCtx->pLocalData;

    if (NULL == pInfo->pGcmCtx)
        goto exit;

    status = OK;
    if (0 == pInputInfo->length)
        goto exit;

    outLen = pInputInfo->length;

    status = ERR_BUFFER_TOO_SMALL;
    *(pOutputInfo->pOutputLen) = outLen;
    if (pOutputInfo->bufferSize < outLen)
        goto exit;

    *(pOutputInfo->pOutputLen) = 0;

    copyLen = 16 - pInfo->leftoverLen;
    if (pInputInfo->length < copyLen)
        copyLen = pInputInfo->length;

    status = DIGI_MEMCPY(
        pInfo->pLeftovers + pInfo->leftoverLen, pInputInfo->pData, copyLen);
    if (OK != status)
        goto exit;

    /* If there is any data in the leftovers buffer then process the data using
     * a temporary context. If the total amount of leftovers does not equate to
     * a block size then this call should be the only call that needs to be
     * made, otherwise if the leftovers does equate to a block size, the
     * temporary context will process the data AND the actual context will need
     * to process the data. Once the actual context processed the data it can
     * then proceed to process the remaining data if there is any.
     */
    status = MbedAesGcmTempBlockSizeUpdate(
        pInfo->pGcmCtx, pInfo->pLeftovers, pInfo->leftoverLen, copyLen,
        pOutputInfo->pBuffer);
    if (OK != status)
        goto exit;

    pInfo->leftoverLen += copyLen;
    pInputInfo->pData += copyLen;
    pInputInfo->length -= copyLen;
    pOutputInfo->pBuffer += copyLen;

    /* If there is enough data in the leftovers buffer to form an AES block then
     * process it using the actual context, but don't output the data anywhere,
     * it will be thrown away. This is because the previous call should've
     * handled the leftovers buffer.
     */
    if (16 == pInfo->leftoverLen)
    {
        status = ERR_MBED_FAILURE;
        mbedStatus = mbedtls_gcm_update(
            pInfo->pGcmCtx, 16, pInfo->pLeftovers, pTemp);
        if (0 != mbedStatus)
            goto exit;

        copyLen = pInputInfo->length & ~0x0F;

        /* Process the actual data now, but only for a multiple of block size.
         */
        mbedStatus = mbedtls_gcm_update(
            pInfo->pGcmCtx, copyLen, pInputInfo->pData, pOutputInfo->pBuffer);
        if (0 != mbedStatus)
            goto exit;

        pInputInfo->pData += copyLen;
        pInputInfo->length -= copyLen;
        pOutputInfo->pBuffer += copyLen;

        /* At this point if there is still data remaining then process it using
         * the temporary context and copy it into the leftovers buffer.
         */
        if (0 != pInputInfo->length)
        {
            status = DIGI_MEMCPY(
                pInfo->pLeftovers, pInputInfo->pData, pInputInfo->length);
            if (OK != status)
                goto exit;

            status = MbedAesGcmTempBlockSizeUpdate(
                pInfo->pGcmCtx, pInputInfo->pData, 0, pInputInfo->length,
                pOutputInfo->pBuffer);
            if (OK != status)
                goto exit;

            pInfo->leftoverLen = pInputInfo->length;
            pOutputInfo->pBuffer += pInputInfo->length;
        }
        else
        {
            pInfo->leftoverLen = 0;
            status = OK;
        }
    }

    *(pOutputInfo->pOutputLen) = outLen;

exit:

    DIGI_MEMSET(pTemp, 0x00, 16);

    return status;
}

MOC_EXTERN MSTATUS MAesGcmMbedFinal (
    MocSymCtx pCtx,
    MSymOperatorData *pInputInfo,
    MSymOperatorBuffer *pOutputInfo
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MAesGcmMbedInfo *pInfo;
    ubyte4 remaining, offset = 0, copyLen = 0;
    sbyte4 cmpRes = -1;
    int mbedStatus;
    ubyte pTemp[16];

    if (NULL == pCtx || NULL == pCtx->pLocalData || NULL == pInputInfo || NULL == pOutputInfo)
        goto exit;

    pInfo = (MAesGcmMbedInfo *) pCtx->pLocalData;

    status = ERR_AES;
    if ( (4 > pInfo->tagLen) || (16 < pInfo->tagLen) )
        goto exit;

    /* Ensure that the output buffer is large enough to store the tag along with
     * the data to be processed, only if an output buffer was provided.
     */
    if ( (NULL != pOutputInfo->pBuffer) ||
         (MBEDTLS_GCM_ENCRYPT == pInfo->cryptFlag) )
    {
        remaining = pInputInfo->length + pInfo->tagLen;

        status = ERR_BUFFER_TOO_SMALL;
        *(pOutputInfo->pOutputLen) = remaining;
        if (pOutputInfo->bufferSize < remaining)
            goto exit;

        /* Store the amount of bytes that will need to be ignored when outputting
         * the data.
         */
        offset = pInfo->leftoverLen;

        /* Check for how many bytes need to be copied over.
         */
        copyLen = 16 - offset;
        if (pInputInfo->length < copyLen)
            copyLen = pInputInfo->length;
    }

    *(pOutputInfo->pOutputLen) = 0;

    /* Copy over bytes into the leftover buffer.
     */
    if (0 != copyLen)
    {
        status = DIGI_MEMCPY(
            pInfo->pLeftovers + pInfo->leftoverLen, pInputInfo->pData, copyLen);
        if (OK != status)
            goto exit;

        pInfo->leftoverLen += copyLen;
    }

    /* Process the leftovers buffer. If the leftover length is less then the
     * mbedtls AES-GCM context can not call update anymore. Also process the
     * data into a temporary buffer so that no data from leftovers is put into
     * the output data.
     */
    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_gcm_update(
        pInfo->pGcmCtx, pInfo->leftoverLen, pInfo->pLeftovers, pTemp);
    if (0 != mbedStatus)
        goto exit;

    pInfo->leftoverLen = 0;

    if ( (NULL != pOutputInfo->pBuffer) ||
         (MBEDTLS_GCM_ENCRYPT == pInfo->cryptFlag) )
    {
        /* Only copy over the data that wasn't part of the original leftovers
         * buffer.
         */
        status = DIGI_MEMCPY(pOutputInfo->pBuffer, pTemp + offset, copyLen);
        if (OK != status)
            goto exit;

        /* This call should only happen if the previous update call updated on
         * exactly 16 bytes. This call will not work if the previous update call is
         * not a multipled of AES block size.
         */
        status = ERR_MBED_FAILURE;
        if ( 0 != (pInputInfo->length - copyLen) )
        {
            mbedStatus = mbedtls_gcm_update(
                pInfo->pGcmCtx, pInputInfo->length - copyLen,
                pInputInfo->pData + copyLen, pOutputInfo->pBuffer + copyLen);
            if (0 != mbedStatus)
                goto exit;
        }
    }

    /* Output the tag into the output buffer. The call to update should update
     * the output buffer pointer so it points to where the tag data should go.
     * If the output buffer is NULL and decryption is being performed then the
     * tag must be checked internally.
     */
    if ( (NULL != pOutputInfo->pBuffer) ||
         (MBEDTLS_GCM_ENCRYPT == pInfo->cryptFlag) )
    {
        mbedStatus = mbedtls_gcm_finish(
            pInfo->pGcmCtx, pOutputInfo->pBuffer + pInputInfo->length,
            pInfo->tagLen);
        if (0 != mbedStatus)
            goto exit;

        *(pOutputInfo->pOutputLen) = pInputInfo->length + pInfo->tagLen;
    }
    else
    {
        mbedStatus = mbedtls_gcm_finish(
            pInfo->pGcmCtx, pTemp, pInfo->tagLen);
        if (0 != mbedStatus)
            goto exit;

        status = DIGI_CTIME_MATCH(
            pTemp, pInputInfo->pData, pInfo->tagLen, &cmpRes);
        if (OK != status)
            goto exit;

        if (0 != cmpRes)
        {
            status = ERR_CRYPTO_AEAD_FAIL;
            goto exit;
        }
    }

    status = OK;

exit:

    DIGI_MEMSET(pTemp, 0x00, 16);

    return status;
}

#endif /* __ENABLE_DIGICERT_AES_GCM_MBED__ */
