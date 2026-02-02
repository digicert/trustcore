/*
 * mbedctrdrbgaes.c
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


#ifdef __ENABLE_DIGICERT_CTR_DRBG_AES_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbedctrdrbgaes.h"

/*----------------------------------------------------------------------------*/

typedef int (*MbedEntropyFuncType) (void *, unsigned char *, size_t);

/*----------------------------------------------------------------------------*/

#pragma GCC diagnostic ignored "-Wcast-function-type"

MOC_EXTERN MSTATUS MCtrDrbgAesMbedSeed (
    MocSymCtx pSymCtx,
    MRandomSeedInfo *pSeedInfo
    )
{
    MSTATUS status;
    int mbedStatus = 0;
    mbedtls_ctr_drbg_context *pNewCtx = NULL;
    MCtrDrbgAesSeedInfo *pCtrDrbgSeedInfo = NULL;
    int reseedInterval = 100000000;
    byteBoolean isAllocated = FALSE;

    status = ERR_NULL_POINTER;
    if ( (NULL == pSymCtx) || (NULL == pSeedInfo) ||
         (NULL == pSeedInfo->pOperatorSeedInfo) )
    {
        goto exit;
    }

    pCtrDrbgSeedInfo = pSeedInfo->pOperatorSeedInfo;

    /* The desired key length must be the same as the mbed default */
    status = ERR_NIST_RNG_CTR_INVALID_KEY_LENGTH;
    if (pCtrDrbgSeedInfo->keyLenBytes != MBEDTLS_CTR_DRBG_KEYSIZE)
        goto exit;

    /* We need a valid function pointer to collect entropy */
    status = ERR_MBED_CTR_DRBG_AES_NULL_ENTROPY_FUNC;
    if (NULL == pCtrDrbgSeedInfo->EntropyFunc)
        goto exit;

    status = ERR_MBED_CTR_DRBG_AES_UNSUPPORTED_NO_DF_MODE;
    if (!pCtrDrbgSeedInfo->useDf)
        goto exit;
    
    /* If there is no underlying context, allocate it now */
    pNewCtx = pSymCtx->pLocalData;
    if (NULL == pNewCtx)
    {
        status = DIGI_CALLOC((void **)&pNewCtx, 1, sizeof(mbedtls_ctr_drbg_context));
        if (OK != status)
            goto exit;
        
        isAllocated = TRUE;
    }

    mbedtls_ctr_drbg_init(pNewCtx);

    /* Seed the context using the provided function pointer for entropy collection */
    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_ctr_drbg_seed_entropy_len (
        pNewCtx, (MbedEntropyFuncType)pCtrDrbgSeedInfo->EntropyFunc,
        pCtrDrbgSeedInfo->pEntropyCtx, pCtrDrbgSeedInfo->pCustom,
        pCtrDrbgSeedInfo->customLen, pCtrDrbgSeedInfo->entropyCollectLen);
    if (0 != mbedStatus)
        goto exit;

    /* The default reseed interval of 10000 is too low for our needs. The
     * Mocana entropy collection takes 8-10 seconds depending on the platform,
     * performing that every 10000 calls is far too much work. NIST SP 800-90A
     * specifies the reseed interval only needs to be <= 2^48 so having a
     * larger interval than the mbed default is not a problem. */
    mbedtls_ctr_drbg_set_reseed_interval(pNewCtx, reseedInterval);

    pSymCtx->pLocalData = pNewCtx;
    pNewCtx = NULL;
    
    status = OK;

exit:

    if (isAllocated && NULL != pNewCtx)
    {
        mbedtls_ctr_drbg_free(pNewCtx);
        DIGI_FREE((void **)&pNewCtx); /* ok to ignore return code, only here on error */
    }

    return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MCtrDrbgAesMbedGenerate (
    MocSymCtx pSymCtx,
    MSymOperatorData *pInput,
    MSymOperatorBuffer *pOutput
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pAdd = NULL;
    ubyte4 addLen = 0;
    mbedtls_ctr_drbg_context *pCtx = NULL;
    int mbedStatus = 0;

    if ( (NULL == pSymCtx) || (NULL == pSymCtx->pLocalData) || (NULL == pOutput) )
        goto exit;

    pCtx = (mbedtls_ctr_drbg_context *) pSymCtx->pLocalData;

    /* Use the additional info if provided */
    if (NULL != pInput)
    {
        pAdd = pInput->pData;
        addLen = pInput->length;
    }

    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_ctr_drbg_random_with_add (
      (void *)pCtx, pOutput->pBuffer, pOutput->bufferSize,
      (const ubyte *)pAdd, addLen);
    if (0 != mbedStatus)
        goto exit;

    status = OK;

exit:
    
    return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MCtrDrbgAesMbedReseed (
    MocSymCtx pSymCtx,
    MRandomReseedInfo *pReseedInfo
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pAdd = NULL;
    ubyte4 addLen = 0;
    mbedtls_ctr_drbg_context *pCtx = NULL;
    int mbedStatus = 0;

    /* We must have an allocated context */
    if (NULL == pSymCtx || NULL == pSymCtx->pLocalData)
        goto exit;

    pCtx = (mbedtls_ctr_drbg_context *) pSymCtx->pLocalData;

    /* Use the additional info if provided */
    if (NULL != pReseedInfo)
    {
        pAdd = pReseedInfo->pAdditionalData;
        addLen = pReseedInfo->additionalDataLen;
        
        /* Use the specific seed as the p_entropy context if provided */
        if (NULL != pReseedInfo->pEntropyMaterial)
        {
            pCtx->p_entropy = (void *) pReseedInfo->pEntropyMaterial;
        }
    }
    
    /* Perform the reseed */
    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_ctr_drbg_reseed(pCtx, pAdd, addLen);
    if (0 != mbedStatus)
        goto exit;

    status = OK;

exit:
    
    return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MCtrDrbgAesMbedGetState (
    MocSymCtx pSymCtx,
    MSymOperatorData *pState
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    mbedtls_ctr_drbg_context *pCtx = NULL;
    ubyte *pBuff = NULL;

    /* We must have an allocated context */
    if (NULL == pSymCtx || NULL == pSymCtx->pLocalData)
        goto exit;
    
    pCtx = (mbedtls_ctr_drbg_context *) pSymCtx->pLocalData;
    
    status = DIGI_MALLOC((void **) &pBuff, MBEDTLS_CTR_DRBG_SEEDLEN);
    if (OK != status)
        goto exit;
    
    status = DIGI_MEMCPY(pBuff, pCtx->counter, MBEDTLS_CTR_DRBG_BLOCKSIZE);
    if (OK != status)
        goto exit;
    
    status = DIGI_MEMCPY(pBuff + MBEDTLS_CTR_DRBG_BLOCKSIZE, (ubyte *) pCtx->aes_ctx.rk, MBEDTLS_CTR_DRBG_KEYSIZE);
    if (OK != status)
        goto exit;
    
    pState->pData = pBuff; pBuff = NULL;
    pState->length = MBEDTLS_CTR_DRBG_SEEDLEN;
    
exit:
    
    if (NULL != pBuff)
    {
        DIGI_FREE((void **) &pBuff); /* only here on error, ignore return */
    }
    
    return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MCtrDrbgAesMbedSetState (
    MocSymCtx pSymCtx,
    MSymOperatorData *pState
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    mbedtls_ctr_drbg_context *pCtx = NULL;
    int mbedStatus = 0;
   
    /* We must have an allocated context */
    if (NULL == pSymCtx || NULL == pSymCtx->pLocalData)
        goto exit;
    
    pCtx = (mbedtls_ctr_drbg_context *) pSymCtx->pLocalData;
    
    status = DIGI_MEMCPY(pCtx->counter, pState->pData, MBEDTLS_CTR_DRBG_BLOCKSIZE);
    if (OK != status)
        goto exit;
    
    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_aes_setkey_enc(&pCtx->aes_ctx, pState->pData + MBEDTLS_CTR_DRBG_BLOCKSIZE, MBEDTLS_CTR_DRBG_KEYSIZE * 8);
    if (mbedStatus)
        goto exit;
    
    pState->length = MBEDTLS_CTR_DRBG_SEEDLEN;
    status = OK;
    
exit:
    
    return status;
}

/*----------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS MCtrDrbgAesMbedFree (
    MocSymCtx pSymCtx
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    mbedtls_ctr_drbg_context *pCtx = NULL;

    if (NULL == pSymCtx)
        goto exit;

    pCtx = (mbedtls_ctr_drbg_context *) pSymCtx->pLocalData;
    
    status = OK;
    if (NULL != pCtx)
    {
        mbedtls_ctr_drbg_free(pCtx);
        status = DIGI_FREE((void **)&pCtx);
        pSymCtx->pLocalData = NULL;
    }

exit:
    
    return status;
}
#endif
