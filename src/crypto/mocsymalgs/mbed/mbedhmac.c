/*
 * mbedhmac.c
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


#ifdef __ENABLE_DIGICERT_HMAC_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbedhmac.h"
#include "../../../crypto/mocsymalgs/mbed/mbedhmaccommon.h"

static MSTATUS MHmacMbedFreeData(
    MbedHmacInfo **ppCtx
    )
{
    MSTATUS status, fstatus;

    status = ERR_NULL_POINTER;
    if (NULL == ppCtx)
        goto exit;

    status = OK;
    if (NULL != *ppCtx)
    {
        /* Free the HMAC context using the mbedtls API.
         */
        if (NULL != (*ppCtx)->pHmacCtx)
        {
            mbedtls_md_free((*ppCtx)->pHmacCtx);
            fstatus = DIGI_FREE((void **)(&((*ppCtx)->pHmacCtx)));
            if (OK == status)
                status = fstatus;
        }

        /* Clear out and free the key data.
         */
        if (NULL != (*ppCtx)->pKey)
        {
            fstatus = DIGI_MEMSET_FREE(
                (ubyte **) &((*ppCtx)->pKey), (*ppCtx)->keyLen);
            if (OK == status)
                status = fstatus;
            
            (*ppCtx)->keyLen = 0;
        }

        /* Free the shell.
         */
        fstatus = DIGI_FREE((void **) ppCtx);
        if (OK == fstatus)
            status = fstatus;
    }

exit:

    return status;
}


MOC_EXTERN MSTATUS MHmacMbedCreate(
    MocSymCtx pSymCtx,
    ubyte *pDigestFlag
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MbedHmacInfo *pNewCtx = NULL;

    mbedtls_md_type_t digestId;
    int mbedStatus;

    if (NULL == pSymCtx)
        goto exit;
    
    /* Create the HMAC context and attempt to set it up. */
    status = DIGI_CALLOC((void **) &pNewCtx, 1, sizeof(MbedHmacInfo));
    if (OK != status)
        goto exit;

    /*
     we allow creation of the operator with no pDigestFlag
     for crypto interface core initialization
     */
    if (NULL != pDigestFlag)
    {
        status = DIGI_MALLOC(
            (void **) &(pNewCtx->pHmacCtx), sizeof(mbedtls_md_context_t));
        if (OK != status)
            goto exit;

        /* Convert the Digicert digest flag into a mbedtls digest ID. */
        status = ConvertMocDigestIdToMbedDigestId(*pDigestFlag, &digestId);
        if (OK != status)
            goto exit;

        mbedtls_md_init(pNewCtx->pHmacCtx);

        status = ERR_MBED_HMAC_SETUP_FAIL;
        mbedStatus = mbedtls_md_setup(
            pNewCtx->pHmacCtx, mbedtls_md_info_from_type(digestId), 1);
        if (0 != mbedStatus)
            goto exit;

        /* Store digestid for possible cloning later */
        pNewCtx->digestId = digestId;
    }

    pSymCtx->localType = MOC_LOCAL_TYPE_HMAC_OPERATOR;
    pSymCtx->SymOperator = SymOperatorHmac;
    pSymCtx->pLocalData = (void *) pNewCtx;

    pNewCtx = NULL;

    status = OK;

exit:

    if (NULL != pNewCtx)
        MHmacMbedFreeData(&pNewCtx);

    return status;
}

MOC_EXTERN MSTATUS MHmacMbedLoadKey(
    MocSymCtx pSymCtx,
    MSymOperatorData *pKeyData
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MbedHmacInfo *pCtx;

    if ( NULL == pSymCtx || NULL == pSymCtx->pLocalData || NULL == pKeyData )
        goto exit;
    
    pCtx = (MbedHmacInfo *) pSymCtx->pLocalData;
    
    /* If there already is a key in the context then free it.
     */
    if (NULL != pCtx->pKey)
    {
        status = DIGI_MEMSET_FREE((ubyte **) &(pCtx->pKey), pCtx->keyLen);
        if (OK != status)
            goto exit;

        pCtx->keyLen = 0;
    }

    /* If a key was provided then store it within the context. It is not an
     * error if no key is provided.
     */
    if (NULL != pKeyData->pData)
    {
        status = DIGI_MALLOC((void **) &(pCtx->pKey), pKeyData->length);
        if (OK != status)
            goto exit;

        status = DIGI_MEMCPY(pCtx->pKey, pKeyData->pData, pKeyData->length);
        if (OK != status)
            goto exit;

        pCtx->keyLen = pKeyData->length;
    }

    status = OK;

exit:

    return status;
}

MOC_EXTERN MSTATUS MHmacMbedInit(
    MocSymCtx pSymCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MbedHmacInfo *pCtx;
    int mbedStatus;

    if ( NULL == pSymCtx || NULL == pSymCtx->pLocalData )
        goto exit;
    
    pCtx = (MbedHmacInfo *) pSymCtx->pLocalData;
    
    /* Attempt to load in the key data into the context.
     */
    status = ERR_MBED_HMAC_START_FAIL;
    mbedStatus = mbedtls_md_hmac_starts(
        pCtx->pHmacCtx, pCtx->pKey, pCtx->keyLen);
    if (0 != mbedStatus)
        goto exit;

    /* Reset the context. This will not reset the key in the context.
     */
    status = ERR_MBED_HMAC_INIT_FAIL;
    mbedStatus = mbedtls_md_hmac_reset(pCtx->pHmacCtx);
    if (0 != mbedStatus)
        goto exit;

    status = OK;

exit:

    return status;
}

MOC_EXTERN MSTATUS MHmacMbedUpdate(
    MocSymCtx pSymCtx,
    MSymOperatorData *pInput
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MbedHmacInfo *pCtx;
    int mbedStatus;
    
    if ( NULL == pSymCtx || NULL == pSymCtx->pLocalData || NULL == pInput)
        goto exit;
    
    pCtx = (MbedHmacInfo *) pSymCtx->pLocalData;

    status = ERR_MBED_HMAC_UPDATE_FAIL;
    mbedStatus = mbedtls_md_hmac_update(
        pCtx->pHmacCtx, pInput->pData, pInput->length);
    if (0 != mbedStatus)
        goto exit;

    status = OK;

exit:

    return status;
}

MOC_EXTERN MSTATUS MHmacMbedFinal(
    MocSymCtx pSymCtx,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MbedHmacInfo *pCtx;
    ubyte4 outputLen;
    int mbedStatus;

    if ( NULL == pSymCtx || NULL == pSymCtx->pLocalData || NULL == pOutput || NULL == pOutput->pOutputLen)
        goto exit;

    pCtx = (MbedHmacInfo *) pSymCtx->pLocalData;
    
    if (NULL == pCtx->pHmacCtx)
        goto exit;
    
    outputLen = (ubyte4) mbedtls_md_get_size(pCtx->pHmacCtx->md_info);

    status = ERR_BUFFER_TOO_SMALL;
    *(pOutput->pOutputLen) = outputLen;
    if (outputLen > pOutput->bufferSize)
        goto exit;

    *(pOutput->pOutputLen) = 0;

    /* pInput is optional */
    if (NULL != pInput)
    {
        status = MHmacMbedUpdate(pSymCtx, pInput);
        if (OK != status)
            goto exit;
    }
    
    status = ERR_MBED_HMAC_FINISH_FAIL;
    mbedStatus = mbedtls_md_hmac_finish(pCtx->pHmacCtx, pOutput->pBuffer);
    if (0 != mbedStatus)
        goto exit;

    *(pOutput->pOutputLen) = outputLen;
    status = OK;

exit:

    return status;
}

MOC_EXTERN MSTATUS MHmacMbedFree(
    MocSymCtx pSymCtx
    )
{
    if (NULL == pSymCtx)
        return ERR_NULL_POINTER;
    
    return MHmacMbedFreeData((MbedHmacInfo **) &(pSymCtx->pLocalData));
}

MOC_EXTERN MSTATUS MHmacMbedClone(
    MocSymCtx pCtx,
    MocSymCtx pCopyCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    MbedHmacInfo *pInfo = NULL;
    MbedHmacInfo *pNewInfo = NULL;
    mbedtls_md_context_t *pNewCtx = NULL;
    mbedtls_md_info_t *pMdInfo = NULL;
    int mbedStatus;

    if ( (NULL == pCtx) || (NULL == pCtx->pLocalData) || (NULL == pCopyCtx) )
        goto exit;

    pInfo = (MbedHmacInfo *)pCtx->pLocalData;

    /* Allocate the info shell */
    status = DIGI_CALLOC((void **) &pNewInfo, 1, sizeof(MbedHmacInfo));
    if (OK != status)
        goto exit;

    /* Copy the info shell */
    status = DIGI_MEMCPY((void *)pNewInfo, (void *)pInfo, sizeof(MbedHmacInfo));
    if (OK != status)
        goto exit;

    if (NULL != pInfo->pKey)
    {
        status = DIGI_MALLOC_MEMCPY (
            (void **)&pNewInfo->pKey, pInfo->keyLen, (void *)pInfo->pKey, pInfo->keyLen);
        if (OK != status)
            goto exit;
    }

    if (NULL != pInfo->pHmacCtx)
    {
        status = DIGI_MALLOC(
            (void **) &pNewCtx, sizeof(mbedtls_md_context_t));
        if (OK != status)
            goto exit;

        mbedtls_md_init(pNewCtx);
        pMdInfo = (mbedtls_md_info_t *)mbedtls_md_info_from_type(pInfo->digestId);

        status = ERR_MBED_HMAC_SETUP_FAIL;
        mbedStatus = mbedtls_md_setup(
            pNewCtx, pMdInfo, 1);
        if (0 != mbedStatus)
            goto exit;

        status = ERR_MBED_FAILURE;
        mbedStatus = mbedtls_md_clone(pNewCtx, pInfo->pHmacCtx);
        if (0 != mbedStatus)
            goto exit;

        /* The md_clone above does not cover the hmac internal buffer. Copy the data over directly. */
        if (NULL != pInfo->pHmacCtx->hmac_ctx)
        {
            status = DIGI_MEMCPY (
                pNewCtx->hmac_ctx, pInfo->pHmacCtx->hmac_ctx, pMdInfo->block_size * 2);
            if (OK != status)
                goto exit;
        }

        /* Store digestid for possible cloning later */
        pNewInfo->digestId = pInfo->digestId;
        pNewInfo->pHmacCtx = pNewCtx;
        pNewCtx = NULL;
    }

    pCopyCtx->pLocalData = (void *)pNewInfo;
    pNewInfo = NULL;
    status = OK;

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

#endif /* __ENABLE_DIGICERT_HMAC_MBED__ */
