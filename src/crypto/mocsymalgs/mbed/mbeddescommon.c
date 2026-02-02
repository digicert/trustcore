/*
 * mbeddescommon.c
 *
 * Common wrapper methods for des and tdes operations.
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

#include "../../../crypto/mocsymalgs/mbed/mbeddescommon.h"


#ifdef __ENABLE_DIGICERT_DES_MBED__

void mbedtls_des_init_wrap(void *pCtx)
{
    mbedtls_des_init((mbedtls_des_context *) pCtx);
}

void mbedtls_des_free_wrap(void *pCtx)
{
    mbedtls_des_free((mbedtls_des_context *) pCtx);
}

int mbedtls_des_setkey_enc_wrap( void *pCtx, const unsigned char key[MBEDTLS_DES_KEY_SIZE] )
{
    return mbedtls_des_setkey_enc((mbedtls_des_context *) pCtx, key);
}

int mbedtls_des_setkey_dec_wrap( void *pCtx, const unsigned char key[MBEDTLS_DES_KEY_SIZE] )
{
    return mbedtls_des_setkey_dec((mbedtls_des_context *) pCtx, key);
}

int mbedtls_des_crypt_ecb_wrap( void *pCtx, int mode, unsigned int length, unsigned char *pIv, const unsigned char *pInput, unsigned char *pOutput)
{
    MOC_UNUSED(mode);
    MOC_UNUSED(length);
    MOC_UNUSED(pIv);

    return mbedtls_des_crypt_ecb((mbedtls_des_context *) pCtx, pInput, pOutput);
}

int mbedtls_des_crypt_cbc_wrap( void *pCtx, int mode, unsigned int length, unsigned char *pIv, const unsigned char *pInput, unsigned char *pOutput)
{
    return mbedtls_des_crypt_cbc((mbedtls_des_context *) pCtx, mode, (size_t) length, pIv, pInput, pOutput);
}

#endif /* __ENABLE_DIGICERT_DES_MBED__ */

/* ------------------------------------------------------------------------------------- */

#ifdef __ENABLE_DIGICERT_TDES_MBED__

void mbedtls_des3_init_wrap(void *pCtx)
{
    mbedtls_des3_init((mbedtls_des3_context *) pCtx);
}

void mbedtls_des3_free_wrap(void *pCtx)
{
    mbedtls_des3_free((mbedtls_des3_context *) pCtx);
}

int mbedtls_des3_set3key_enc_wrap( void *pCtx, const unsigned char key[MBEDTLS_TDES_KEY_SIZE] )
{
    return mbedtls_des3_set3key_enc((mbedtls_des3_context *) pCtx, key);
}

int mbedtls_des3_set3key_dec_wrap( void *pCtx, const unsigned char key[MBEDTLS_TDES_KEY_SIZE] )
{
    return mbedtls_des3_set3key_dec((mbedtls_des3_context *) pCtx, key);
}

int mbedtls_des3_crypt_ecb_wrap(void *pCtx, int mode, unsigned int length, unsigned char *pIv, const unsigned char *pInput, unsigned char *pOutput)
{
    MOC_UNUSED(mode);
    MOC_UNUSED(length);
    MOC_UNUSED(pIv);

    return mbedtls_des3_crypt_ecb((mbedtls_des3_context *) pCtx, pInput, pOutput);
}

int mbedtls_des3_crypt_cbc_wrap( void *pCtx, int mode, unsigned int length, unsigned char *pIv, const unsigned char *pInput, unsigned char *pOutput)
{
    return mbedtls_des3_crypt_cbc((mbedtls_des3_context *) pCtx, mode, (size_t) length, pIv, pInput, pOutput);
}

#endif /* __ENABLE_DIGICERT_TDES_MBED__ */

/* ------------------------------------------------------------------------------------- */

#if defined(__ENABLE_DIGICERT_DES_MBED__) || defined(__ENABLE_DIGICERT_TDES_MBED__)

MSTATUS MDesMbedCreate (
    MocSymCtx pCtx,
    void *pDesData,
    ubyte4 localType,
    MSymOperator symOperator
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MbedDesInfo *pNewCtx = NULL;

    if (NULL == pCtx)
        goto exit;

    status = DIGI_CALLOC((void **) &pNewCtx, 1, sizeof(MbedDesInfo));
    if (OK != status)
        goto exit;

    if (NULL != pDesData)
    {
        if (MOC_LOCAL_TYPE_CBC == (localType & MOC_LOCAL_TYPE_ALG_MASK))
        {
            status = ERR_NOT_IMPLEMENTED;
            if (TRUE == ((MDesCbcOperatorData *) pDesData)->padding)
                goto exit;

            if (NULL != ((MDesCbcOperatorData *) pDesData)->pInitVector)
            {
                status = ERR_DES_BAD_IV_LENGTH;
                if (MBEDTLS_DES_IV_SIZE != ((MDesCbcOperatorData *) pDesData)->initVectorLen)
                    goto exit;

                status = DIGI_MEMCPY(pNewCtx->pIv, ((MDesCbcOperatorData *) pDesData)->pInitVector, MBEDTLS_DES_IV_SIZE);
                if (OK != status)
                    goto exit;

                pNewCtx->hasIv = TRUE;
            }

            status = OK;
        }
        else if (MOC_LOCAL_TYPE_ECB == (localType & MOC_LOCAL_TYPE_ALG_MASK))
        {
            if (TRUE == ((MDesEcbOperatorData *) pDesData)->padding)
                goto exit;
        }
        else
        {
            status = ERR_INVALID_INPUT;
            goto exit;
        }
    }

    pNewCtx->hasKey = FALSE;
    pCtx->localType = localType;
    pCtx->SymOperator = symOperator;
    pCtx->pLocalData = (void *) pNewCtx;

    pNewCtx = NULL;

exit:

    if (NULL != pNewCtx)
        DIGI_FREE((void **) &pNewCtx);

    return status;
}

MSTATUS MDesMbedInit (
    MocSymCtx pCtx,
    MbedDesInitFree desInitFunc,
    MbedDesSetKey desSetKeyFunc
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MbedDesInfo *pInfo;
    void *pDesCtx = NULL;
    byteBoolean isAllocated = FALSE;
    int mbedStatus;

    if (NULL == pCtx || NULL == pCtx->pLocalData)
        goto exit;

    pInfo = (MbedDesInfo *) pCtx->pLocalData;
    pDesCtx = pInfo->pDesCtx;

    status = ERR_INVALID_INPUT;
    if (FALSE == pInfo->hasKey)
        goto exit;

    if (NULL == pDesCtx)
    {
        if (MOC_LOCAL_TYPE_DES == (pCtx->localType & MOC_LOCAL_TYPE_COM_MASK))
            status = DIGI_MALLOC(&pDesCtx, sizeof(mbedtls_des_context));
        else if (MOC_LOCAL_TYPE_TDES == (pCtx->localType & MOC_LOCAL_TYPE_COM_MASK))
            status = DIGI_MALLOC(&pDesCtx, sizeof(mbedtls_des3_context));
        else
            status = ERR_INVALID_INPUT;

        if (OK != status)
            goto exit;

        isAllocated = TRUE;
    }

    desInitFunc(pDesCtx);

    status = ERR_MBED_FAILURE;
    mbedStatus = desSetKeyFunc(pDesCtx, pInfo->pKey);
    if (0 != mbedStatus)
        goto exit;

    pInfo->pDesCtx = pDesCtx;
    pDesCtx = NULL;

    status = OK;

exit:

    if (isAllocated && NULL != pDesCtx)
        DIGI_FREE(&pDesCtx); /* here on error only, ignore return code */

    return status;
}


MSTATUS MDesMbedGenerateKey (
    MocSymCtx pCtx,
    MSymKeyGenInfo *pGenInfo,
    MSymOperatorBuffer *pOutput
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MbedDesInfo *pInfo;
    ubyte4 bufSize = 0, keyLen;

    if ( NULL == pCtx || NULL == pGenInfo || NULL == pOutput || NULL == pGenInfo->pRandInfo ||
         NULL == pGenInfo->pRandInfo->RngFun || NULL == pOutput->pOutputLen || NULL == pCtx->pLocalData )
        goto exit;

    pInfo = (MbedDesInfo *) pCtx->pLocalData;
    keyLen = pGenInfo->keySizeBits / 8;

    /* up to the caller to input a valid key len for 1 key DES, 2 key or 3 key TDES */
    status = ERR_DES_BAD_KEY_LENGTH;
    if (MBEDTLS_DES_KEY_SIZE != keyLen && MBEDTLS_TDES_TWO_KEY_SIZE != keyLen && MBEDTLS_TDES_KEY_SIZE != keyLen)
        goto exit;

    if (NULL != pOutput->pBuffer)
        bufSize = pOutput->bufferSize;

    status = ERR_BUFFER_TOO_SMALL;
    *(pOutput->pOutputLen) = keyLen;
    if (bufSize < keyLen)
        goto exit;

    *(pOutput->pOutputLen) = 0;

    status = pGenInfo->pRandInfo->RngFun(pGenInfo->pRandInfo->pRngFunArg, keyLen, (ubyte *)(pInfo->pKey));
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pOutput->pBuffer, pInfo->pKey, keyLen);
    if (OK != status)
        goto exit;

    pInfo->hasKey = TRUE;
    *(pOutput->pOutputLen) = keyLen;

exit:

    return status;
}

/* ------------------------------------------------------------------------------------- */

MSTATUS MDesMbedLoadKey (
    MocSymCtx pCtx,
    MSymOperatorData *pKeyData
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MbedDesInfo *pInfo;

    if (NULL == pCtx || NULL == pKeyData)
        goto exit;

    pInfo = (MbedDesInfo *) pCtx->pLocalData;

    /* up to the caller to input a valid key len for 1 key DES, 2 key or 3 key TDES */
    status = ERR_DES_BAD_KEY_LENGTH;
    if (MBEDTLS_DES_KEY_SIZE != pKeyData->length && MBEDTLS_TDES_TWO_KEY_SIZE != pKeyData->length && MBEDTLS_TDES_KEY_SIZE != pKeyData->length)
        goto exit;

    status = DIGI_MEMCPY(pInfo->pKey, pKeyData->pData, pKeyData->length);
    if (OK != status)
        goto exit;

    pInfo->hasKey = TRUE;

exit:

    return status;
}

/* ------------------------------------------------------------------------------------- */

MSTATUS MDesMbedUpdate (
    MocSymCtx pCtx,
    ubyte4 cipherFlag,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput,
    MbedDesCrypt desCryptFunc
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MbedDesInfo *pInfo;
    void *pDesCtx;
    ubyte *pInPtr;
    ubyte *pOutPtr;
    ubyte4 bytesLeft, outLen;
    int mbedStatus;

    if (NULL == pCtx || NULL == pCtx->pLocalData || NULL == pInput || NULL == pOutput || NULL == pOutput->pOutputLen)
        goto exit;

    pInfo = (MbedDesInfo *) pCtx->pLocalData;
    pDesCtx = pInfo->pDesCtx;

    if (NULL == pDesCtx)
        goto exit;

    status = OK;
    if (0 == pInput->length)
        goto exit;

    pInPtr = pInput->pData;
    pOutPtr = pOutput->pBuffer;
    bytesLeft = pInput->length;

    outLen = ((pInfo->leftoverLen + bytesLeft)/MBEDTLS_DES_BLOCK_SIZE) * MBEDTLS_DES_BLOCK_SIZE;

    status = ERR_BUFFER_TOO_SMALL;
    *(pOutput->pOutputLen) = outLen;
    if (pOutput->bufferSize < outLen)
        goto exit;

    *(pOutput->pOutputLen) = 0;

    if (outLen)  /* we have at least one block to process */
    {
        /* process the first block */
        status = DIGI_MEMCPY(pInfo->pLeftovers + pInfo->leftoverLen, pInPtr, MBEDTLS_DES_BLOCK_SIZE - pInfo->leftoverLen);
        if (OK != status)
            goto exit;

        status = ERR_MBED_FAILURE;

        /* call the mbed function pointer, if this is ecb then the 2nd, 3rd, 4th params are ignored */
        mbedStatus = desCryptFunc(pDesCtx, cipherFlag, MBEDTLS_DES_BLOCK_SIZE, pInfo->pIv, pInfo->pLeftovers, pOutPtr);
        if (0 != mbedStatus)
            goto exit;

        pInPtr += (MBEDTLS_DES_BLOCK_SIZE - pInfo->leftoverLen);
        bytesLeft -= (MBEDTLS_DES_BLOCK_SIZE - pInfo->leftoverLen);
        pOutPtr += MBEDTLS_DES_BLOCK_SIZE;
        *(pOutput->pOutputLen) += MBEDTLS_DES_BLOCK_SIZE;
        pInfo->leftoverLen = 0;

        /* process any additional full blocks */
        if ( (MOC_LOCAL_TYPE_CBC == (pCtx->localType & MOC_LOCAL_TYPE_ALG_MASK)) && bytesLeft >= MBEDTLS_DES_BLOCK_SIZE)  /* we can make one single call to desCryptFunc */
        {
            ubyte4 bytesToProcess = bytesLeft & 0xFFFFFFF8; /* rounded down to multiple of the block size of 8 */

            mbedStatus = desCryptFunc(pDesCtx, cipherFlag, bytesToProcess, pInfo->pIv, pInPtr, pOutPtr);
            if (0 != mbedStatus)
                goto exit;

            pInPtr += bytesToProcess;
            *(pOutput->pOutputLen) += bytesToProcess;

            /* last processed data so no need to update pOutPtr */
            bytesLeft -= bytesToProcess;
        }
        else  /* we need to call desCryptFunc a block at a time */
        {
            while (bytesLeft >= MBEDTLS_DES_BLOCK_SIZE)
            {
                mbedStatus = desCryptFunc(pDesCtx, 0, 0, 0, pInPtr, pOutPtr);

                pInPtr += MBEDTLS_DES_BLOCK_SIZE;
                bytesLeft -= MBEDTLS_DES_BLOCK_SIZE;
                pOutPtr += MBEDTLS_DES_BLOCK_SIZE;
                *(pOutput->pOutputLen) += MBEDTLS_DES_BLOCK_SIZE;
            }
        }
    }

    /* copy any leftovers to the buffer, (bytesLeft + pInfo->leftoverLen) has to be less than a block length now */
    if (bytesLeft)
    {
        status = DIGI_MEMCPY(pInfo->pLeftovers, pInPtr, bytesLeft);
        if (OK != status)
            goto exit;

        pInfo->leftoverLen += bytesLeft;
    }

    status = OK;

exit:

    return status;
}


/* ------------------------------------------------------------------------------------- */

MSTATUS MDesMbedFinal (
    MocSymCtx pCtx,
    ubyte4 cipherFlag,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput,
    MbedDesCrypt desCryptFunc
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MbedDesInfo *pInfo;

    if (NULL == pCtx || NULL == pCtx->pLocalData || NULL == pInput)
        goto exit;

    pInfo = (MbedDesInfo *) pCtx->pLocalData;

    status = ERR_INVALID_INPUT;
    if (0 == ((pInfo->leftoverLen + pInput->length) % MBEDTLS_DES_BLOCK_SIZE))
        status = MDesMbedUpdate(pCtx, cipherFlag, pInput, pOutput, desCryptFunc);

exit:

    return status;
}

/* ------------------------------------------------------------------------------------- */

MSTATUS MDesMbedFree (
    MocSymCtx pCtx,
    MbedDesInitFree desFreeFunc
    )
{
    MSTATUS status = ERR_NULL_POINTER, fstatus;
    MbedDesInfo *pInfo;

    if (NULL == pCtx)
        goto exit;

    pInfo = (MbedDesInfo *) pCtx->pLocalData;

    status = OK; /* ok if nothing to free */
    if (NULL != pInfo)
    {
        if (NULL != pInfo->pDesCtx)
        {
            desFreeFunc(pInfo->pDesCtx);
            status = DIGI_FREE(&(pInfo->pDesCtx));
            if (OK != status)
                goto exit;
        }

        fstatus = DIGI_MEMSET((ubyte *) pInfo, 0x00, sizeof(MbedDesInfo));
        if (OK == status)
            status = fstatus;

        fstatus = DIGI_FREE((void **) &pInfo);
        if (OK == status)
            status = fstatus;

        /* set the context's pointer to NULL too */
        pCtx->pLocalData = NULL;
    }

exit:

    return status;
}

/* ------------------------------------------------------------------------------------- */

MSTATUS MDesMbedUpdateOperatorData (MocSymCtx pCtx, MDesUpdateData *pDesData)
{
    MSTATUS status = ERR_NULL_POINTER;
    MbedDesInfo *pInfo;

    if (NULL == pCtx || NULL == pCtx->pLocalData || NULL == pDesData)
        goto exit;

    pInfo = (MbedDesInfo *) pCtx->pLocalData;

    status = ERR_NOT_IMPLEMENTED;
    if (MOC_LOCAL_TYPE_CBC == (pCtx->localType & MOC_LOCAL_TYPE_ALG_MASK))
    {
        if (TRUE == pDesData->padding)
            goto exit;

        /* The initialization vector must be present in the update structure */
        status = ERR_NULL_POINTER;
        if (NULL == pDesData->pInitVector)
            goto exit;

        status = ERR_DES_BAD_IV_LENGTH;
        if (MBEDTLS_DES_IV_SIZE != pDesData->initVectorLen)
            goto exit;

        status = DIGI_MEMCPY(pInfo->pIv, pDesData->pInitVector, MBEDTLS_DES_IV_SIZE);
        if (OK != status)
            goto exit;

        pInfo->hasIv = TRUE;
    }
    else if (MOC_LOCAL_TYPE_ECB == (pCtx->localType & MOC_LOCAL_TYPE_ALG_MASK))
    {
        if (TRUE == pDesData->padding)
            goto exit;

        status = OK;
    }
    else
        status = ERR_INVALID_ARG;

exit:

    return status;
}

/* ------------------------------------------------------------------------------------- */

MSTATUS MDesMbedGetOpData(
    MbedDesInfo *pCtx,
    MSymOperatorData *pOutput
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    if (NULL == pCtx || NULL == pOutput || NULL == pOutput->pData)
        goto exit;

    status = DIGI_MEMCPY(pOutput->pData, pCtx->pIv, MBEDTLS_DES_IV_SIZE);
    if (OK != status)
        goto exit;

    pOutput->length = MBEDTLS_DES_IV_SIZE;
exit:
    return status;
}

/* ------------------------------------------------------------------------------------- */

MSTATUS MDesMbedClone(
    MocSymCtx pCtx,
    MocSymCtx pCopyCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MbedDesInfo *pDesInfo = NULL;
    MbedDesInfo *pNewInfo = NULL;
    void *pNewCtx = NULL;

    if ( (NULL == pCtx) || (NULL == pCtx->pLocalData) || (NULL == pCopyCtx) )
        goto exit;

    pDesInfo = (MbedDesInfo *)pCtx->pLocalData;

    /* Allocate the info shell */
    status = DIGI_CALLOC((void **) &pNewInfo, 1, sizeof(MbedDesInfo));
    if (OK != status)
        goto exit;

    /* Copy the info shell */
    status = DIGI_MEMCPY((void *)pNewInfo, (void *)pDesInfo, sizeof(MbedDesInfo));
    if (OK != status)
        goto exit;

    if (NULL != pDesInfo->pDesCtx)
    {
        ubyte4 ctxSize = (ubyte4) sizeof(mbedtls_des3_context);

        if (MOC_LOCAL_TYPE_DES == (pCtx->localType & MOC_LOCAL_TYPE_COM_MASK))
            ctxSize = (ubyte4) sizeof(mbedtls_des_context);

        /* Allocate the underlying MBED context */
        status = DIGI_MALLOC((void **)&pNewCtx, ctxSize);
        if (OK != status)
            goto exit;

        /* Copy the underlying MBED context data */

        status = DIGI_MEMCPY (
            pNewCtx, (void *)pDesInfo->pDesCtx, ctxSize);
        if (OK != status)
            goto exit;

        pNewInfo->pDesCtx = pNewCtx;
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

/* ------------------------------------------------------------------------------------- */

#endif /* #if defined(__ENABLE_DIGICERT_DES_MBED__) || defined(__ENABLE_DIGICERT_TDES_MBED__) */
