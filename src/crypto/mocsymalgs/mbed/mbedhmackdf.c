/*
 * mbedhmackdf.c
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


#ifdef __ENABLE_DIGICERT_HMAC_KDF_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbedhmackdf.h"
#include "../../../crypto/mocsymalgs/mbed/mbedhmaccommon.h"

MOC_EXTERN MSTATUS MHmacKdfMbedCreate(
    MocSymCtx pSymCtx,
    ubyte *pDigestFlag
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    const mbedtls_md_info_t *pMdInfo = NULL;
    mbedtls_md_type_t digestId;

    if (NULL == pSymCtx)
        goto exit;
    
    /* allow NULL pDigestFlag for crypto interface core initialization */
    if (NULL != pDigestFlag)
    {
         /* Convert the Digicert digest flag into a mbedtls digest ID. */
        status = ConvertMocDigestIdToMbedDigestId(*pDigestFlag, &digestId);
        if (OK != status)
            goto exit;

        pMdInfo = mbedtls_md_info_from_type(digestId);
    }
    
    pSymCtx->localType = MOC_LOCAL_TYPE_HMAC_KDF_OPERATOR;
    pSymCtx->SymOperator = SymOperatorHmacKdf;
    pSymCtx->pLocalData = (void *) pMdInfo;
    
    status = OK;
    
exit:
    
    return status;
}


MOC_EXTERN MSTATUS MHmacKdfMbedDeriveKey(
    MocSymCtx pSymCtx,
    MHmacKdfOperatorData *pOpData,
    MSymOperatorBuffer *pOutput
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    mbedtls_md_info_t *pMdInfo = NULL;
    ubyte4 digestSize;
    int mbedStatus;
    
    if (NULL == pSymCtx || NULL == pSymCtx->pLocalData || NULL == pOpData || NULL == pOutput || NULL == pOutput->pOutputLen)
        goto exit;
    
    pMdInfo = (mbedtls_md_info_t *) pSymCtx->pLocalData;
    digestSize = (ubyte4) mbedtls_md_get_size(pMdInfo);
    
    if (MOC_SYM_HMAC_KDF_EXTRACT == pOpData->flag)
    {
        if ( NULL == pOutput->pBuffer || (NULL == pOpData->pSalt && pOpData->saltLen) ||
                                         (NULL == pOpData->pInputKeyMaterial && pOpData->inputKeyMaterialLen) )
            goto exit;
        
        /*
         use ERR_BAD_LENGTH instead of ERR_BUFFER_TOO_SMALL to be consistent
         with the original hmac-kdf extract API which does not have an outLen pointer parameter
         */
        status = ERR_BAD_LENGTH;
        *(pOutput->pOutputLen) = digestSize;
        if (pOutput->bufferSize < digestSize)
            goto exit;
        
        *(pOutput->pOutputLen) = 0;
            
        status = ERR_MBED_FAILURE;
        mbedStatus = mbedtls_hkdf_extract(pMdInfo, pOpData->pSalt, pOpData->saltLen, pOpData->pInputKeyMaterial,
                                          pOpData->inputKeyMaterialLen, pOutput->pBuffer);
        if (0 != mbedStatus)
            goto exit;
        
        *(pOutput->pOutputLen) = digestSize;
    }
    else if (MOC_SYM_HMAC_KDF_EXPAND == pOpData->flag)
    {
        if ( NULL == pOutput->pBuffer || NULL == pOpData->pPseudoRandomKey ||
            (NULL == pOpData->pContext && pOpData->contextLen) )
            goto exit;
        
        *(pOutput->pOutputLen) = 0;

        if ( (NULL != pOpData->pIv) && (0 != pOpData->ivLen) )
        {
            status = ERR_UNSUPPORTED_OPERATION;
            goto exit;
        }
    
        /* input pseduo key length must be at least the digest size */
        status = ERR_BAD_LENGTH;
        if (pOpData->pseudoRandomKeyLen < digestSize)
            goto exit;
        
        status = OK;  /* return OK no-op if no key length is requested */
        if (!pOutput->bufferSize)
            goto exit;
        
        status = ERR_MBED_FAILURE;
        mbedStatus = mbedtls_hkdf_expand(pMdInfo, pOpData->pPseudoRandomKey, pOpData->pseudoRandomKeyLen, pOpData->pContext,
                                         pOpData->contextLen, pOutput->pBuffer, pOutput->bufferSize);
        if (0 != mbedStatus)
            goto exit;
        
        *(pOutput->pOutputLen) = pOutput->bufferSize;
    }
    else
    {
        status = ERR_INVALID_ARG;
        goto exit;
    }
    
    status = OK;
    
exit:
    
    return status;
}

MOC_EXTERN MSTATUS MHmacKdfMbedFree(
    MocSymCtx pSymCtx
    )
{
    /* no memory allocated, just zero the pSymCtx, DIGI_MEMSET will handle NULL correctly */
    return DIGI_MEMSET((ubyte *) pSymCtx, 0x00, sizeof(MocSymContext));
}
#endif /* __ENABLE_DIGICERT_HMAC_KDF_MBED__ */
