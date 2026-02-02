/*
 * mbedarc4.c
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


#ifdef __ENABLE_DIGICERT_ARC4_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbedarc4.h"
#include "mbedtls/arc4.h"

MOC_EXTERN MSTATUS MArc4MbedCreate(
    MocSymCtx pSymCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    mbedtls_arc4_context *pNewCtx = NULL;

    if (NULL == pSymCtx)
        goto exit;

    status = DIGI_MALLOC((void **) &pNewCtx, sizeof(mbedtls_arc4_context));
    if (OK != status)
        goto exit;

    mbedtls_arc4_init(pNewCtx);

    pSymCtx->pLocalData = (void *) pNewCtx;
    pSymCtx->localType = MOC_LOCAL_TYPE_ARC4_OPERATOR;
    pSymCtx->SymOperator = SymOperatorArc4;

    pNewCtx = NULL;

exit:

    /* no error possibilities happen after allocation, no cleanup needed */
    return status;
}

MOC_EXTERN MSTATUS MArc4MbedLoadKey(
    MocSymCtx pSymCtx,
    MSymOperatorData *pKeyData
    )
{
    if (NULL == pKeyData || NULL == pKeyData->pData || NULL == pSymCtx || NULL == pSymCtx->pLocalData)
        return ERR_NULL_POINTER;

    mbedtls_arc4_setup((mbedtls_arc4_context *) pSymCtx->pLocalData, (const unsigned char *) pKeyData->pData, (unsigned int) pKeyData->length);

    return OK;
}

MOC_EXTERN MSTATUS MArc4MbedUpdate(
    MocSymCtx pSymCtx,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    int mbedStatus;

    if (NULL == pSymCtx || NULL == pSymCtx->pLocalData || NULL == pInput || NULL == pInput->pData ||
        NULL == pOutput || NULL == pOutput->pBuffer || NULL == pOutput->pOutputLen)
        goto exit;

    /* Check to see if the output buffer is large enough. */
    status = ERR_BUFFER_TOO_SMALL;
    *(pOutput->pOutputLen) = pInput->length;
    if (pOutput->bufferSize < pInput->length)
        goto exit;

    *(pOutput->pOutputLen) = 0;

    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_arc4_crypt((mbedtls_arc4_context *) pSymCtx->pLocalData, (size_t) pInput->length, (const unsigned char *) pInput->pData, (unsigned char *) pOutput->pBuffer);
    if (mbedStatus)
        goto exit;

    status = OK;
    *(pOutput->pOutputLen) = pInput->length;

exit:

    return status;
}

MSTATUS MArc4MbedClone(
    MocSymCtx pCtx,
    MocSymCtx pCopyCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    mbedtls_arc4_context *pMbedCtx = NULL;
    mbedtls_arc4_context *pNewMbedCtx = NULL;

    if ( (NULL == pCtx) || (NULL == pCtx->pLocalData) || (NULL == pCopyCtx) )
        goto exit;

    pMbedCtx = (mbedtls_arc4_context *)pCtx->pLocalData;

    /* Allocate the underlying MBED context */
    status = DIGI_MALLOC((void **)&pNewMbedCtx, sizeof(mbedtls_arc4_context));
    if (OK != status)
        goto exit;

    /* Copy the underlying MBED context data */
    status = DIGI_MEMCPY (
        pNewMbedCtx, (void *)pMbedCtx, sizeof(mbedtls_arc4_context));
    if (OK != status)
        goto exit;

    pCopyCtx->pLocalData = (void *)pNewMbedCtx;
    pNewMbedCtx = NULL;

exit:
    if (NULL != pNewMbedCtx)
    {
        DIGI_FREE((void **)&pNewMbedCtx);
    }

    return status;
}

MOC_EXTERN MSTATUS MArc4MbedFree(
    MocSymCtx pSymCtx
    )
{
    if (NULL == pSymCtx)
        return ERR_NULL_POINTER;

    if (NULL != pSymCtx->pLocalData)
    {
        mbedtls_arc4_free((mbedtls_arc4_context *) pSymCtx->pLocalData);

        return DIGI_FREE( &(pSymCtx->pLocalData) );
    }

    return OK;
}
#endif /* __ENABLE_DIGICERT_ARC4_MBED__ */
