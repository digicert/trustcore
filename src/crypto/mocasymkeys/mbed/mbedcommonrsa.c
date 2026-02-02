/*
 * rsambedsign.c
 *
 * Operator for Software version of RSA MocAsym Key.
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

#include "../../../crypto/mocasym.h"


#ifdef __ENABLE_DIGICERT_RSA_MBED__

#define MOC_MAX_DIGEST_RESULT_SIZE 64

#include "../../../crypto/mocasymkeys/mbed/mbedcommonrsa.h"
#include "../../../crypto/mocsymalgs/mbed/mbedrandom.h"

/*---------------------------------------------------------------------------*/

static MSTATUS RsaMbedConvertHashAlgo (
    ubyte hashAlgo,
    int *pMbedHashAlgo
    );

static MSTATUS RsaMbedProcessOaepInfo (
    MKeyAsymEncryptInfo *pInputInfo,
    ubyte4 *pHashAlgo,
    ubyte **ppLabel,
    ubyte4 *pLabelLen
    );

static MSTATUS RsaMbedProcessPssInfo (
    mbedtls_rsa_context *pCtx,
    MRsaPssInfo *pPssInfo,
    int *pHashAlgo,
    sbyte4 *pSaltLen,
    ubyte isSign
    );

/*---------------------------------------------------------------------------*/

MSTATUS RsaMbedGetSecuritySize(
    MocAsymKey pMocAsymKey,
    ubyte4 *pOutputInfo
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    mbedtls_rsa_context *pRsaCtx = NULL;
    size_t rsaModLen;

    if (NULL == pMocAsymKey || NULL == pOutputInfo)
        goto exit;
    
    status = ERR_RSA_KEY_NOT_READY;
    if (NULL == pMocAsymKey->pKeyData)
        goto exit;

    pRsaCtx = pMocAsymKey->pKeyData;

    status = ERR_RSA_UNSUPPORTED_KEY_LENGTH;
    rsaModLen = 8 * mbedtls_rsa_get_len(pRsaCtx);
    if (0 == rsaModLen)
        goto exit;

    *pOutputInfo = (ubyte4) rsaModLen;
    status = OK;

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS RsaMbedGenerateKeyPair(
    MocCtx pMocCtx,
    MKeyPairGenInfo *pInputInfo,
    MKeyPairGenResult *pOutputInfo
    )
{
    MSTATUS status;

    int mbedStatus;
    mbedtls_rsa_context *pRsaCtx = NULL;
    ubyte4 keySize;
    MocAsymKey pPub = NULL, pPri = NULL;

    status = ERR_NULL_POINTER;
    if ( (NULL == pInputInfo->pRandInfo) ||
         (NULL == pInputInfo->pRandInfo->RngFun) ||
         (NULL == pInputInfo->pOperatorInfo ) ||
         (NULL == pOutputInfo->ppPubKey) || (NULL == pOutputInfo->ppPriKey) )
        goto exit;

    keySize = *((ubyte4 *)(pInputInfo->pOperatorInfo));

    switch (keySize)
    {
        default:
            status = ERR_RSA_UNSUPPORTED_KEY_LENGTH;
            goto exit;

        case 1024:
        case 2048:
        case 3072:
        case 4096:
            break;
    }

    status = DIGI_MALLOC((void **) &pRsaCtx, sizeof(mbedtls_rsa_context));
    if (OK != status)
        goto exit;

    mbedtls_rsa_init(pRsaCtx, 0, 0);

    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_rsa_gen_key(
        pRsaCtx, MocMbedRngFun, pInputInfo->pRandInfo, (unsigned int) keySize,
        DEFAULT_MBED_RSA_EXPONENT);
    if (0 != mbedStatus)
        goto exit;

    status = CRYPTO_createMocAsymKey(
        KeyOperatorRsa, NULL, pMocCtx, MOC_ASYM_KEY_TYPE_PRIVATE,
        &pPri);
    if (OK != status)
        goto exit;

    pPri->pKeyData = pRsaCtx;
    pRsaCtx = NULL;

    status = CRYPTO_getPubFromPri(pPri, &pPub, NULL);
    if (OK != status)
        goto exit;

    *(pOutputInfo->ppPubKey) = pPub;
    *(pOutputInfo->ppPriKey) = pPri;

    pPub = NULL;
    pPri = NULL;

exit:

    if (NULL != pRsaCtx)
    {
        mbedtls_rsa_free(pRsaCtx);
        DIGI_FREE((void **) &pRsaCtx);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS RsaMbedEncrypt (
    MocAsymKey pMocAsymKey,
    MKeyAsymEncryptInfo *pInputInfo,
    MKeyOperatorBuffer *pOutputInfo
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 details = 0;
    ubyte4 keyLenBytes = 0;
    int mbedStatus = 0;
    int hashAlgo = 0;
    mbedtls_rsa_context *pRsaCtx = NULL;
    ubyte *pLabel = NULL;
    ubyte4 labelLen = 0;

    if (NULL == pMocAsymKey || NULL == pInputInfo || NULL == pOutputInfo || NULL == pOutputInfo->pLength)
        goto exit;
    
    pRsaCtx = (mbedtls_rsa_context *) pMocAsymKey->pKeyData;
    
    status = ERR_RSA_KEY_NOT_READY;
    if (NULL == pRsaCtx)
        goto exit;

    details = pInputInfo->algorithmDetails;

    status = ERR_NOT_IMPLEMENTED;
    if (NULL != pInputInfo->pAlgId)
        goto exit;

    status = ERR_INVALID_INPUT;
    if ( (MOC_ASYM_KEY_ALG_RSA_ENC_P1_PAD != details) &&
         (MOC_ASYM_KEY_ALG_RSA_OAEP_PAD != details) &&
         (MOC_ASYM_KEY_ALG_RSA_ENC_NO_PAD != details) )
        goto exit;

    if (MOC_LOCAL_KEY_RSA_PUB_OPERATOR != pMocAsymKey->localType)
        goto exit;

    keyLenBytes = (ubyte4) mbedtls_rsa_get_len(pRsaCtx);

    status = ERR_BUFFER_TOO_SMALL;
    *(pOutputInfo->pLength) = keyLenBytes;
    if (pOutputInfo->bufferSize < keyLenBytes)
        goto exit;

    *(pOutputInfo->pLength) = 0;

    status = ERR_MBED_FAILURE;
    if (MOC_ASYM_KEY_ALG_RSA_ENC_NO_PAD == details)
    {
        mbedStatus = mbedtls_rsa_public(
            pRsaCtx, pInputInfo->pData, pOutputInfo->pBuffer);
        if (0 != mbedStatus)
            goto exit;
    }
    else if (MOC_ASYM_KEY_ALG_RSA_ENC_P1_PAD == details)
    {
        mbedtls_rsa_set_padding(pRsaCtx, MBEDTLS_RSA_PKCS_V15, 0);
        mbedStatus = mbedtls_rsa_rsaes_pkcs1_v15_encrypt(
            pRsaCtx, MocMbedRngFun, pInputInfo->pRandInfo, MBEDTLS_RSA_PUBLIC,
            pInputInfo->length, pInputInfo->pData, pOutputInfo->pBuffer);
        if (0 != mbedStatus)
            goto exit;
    }
    else
    {
        /* Default to SHA1 */
        hashAlgo = MBEDTLS_MD_SHA1;

        /* Did the caller provide additional info to override default parameters? */
        if (NULL != pInputInfo->pAdditionalInfo)
        {
            status = RsaMbedProcessOaepInfo (
                pInputInfo, (ubyte4*)&hashAlgo, &pLabel, &labelLen);
            if (OK != status)
                goto exit;

            status = ERR_NULL_POINTER;
            if (labelLen && NULL == pLabel)
                goto exit;
            
            /* Reset status */
            status = ERR_MBED_FAILURE;
        }

        mbedtls_rsa_set_padding(pRsaCtx, MBEDTLS_RSA_PKCS_V21, hashAlgo);
        mbedStatus = mbedtls_rsa_rsaes_oaep_encrypt(
            pRsaCtx, MocMbedRngFun, pInputInfo->pRandInfo, MBEDTLS_RSA_PUBLIC,
            pLabel, labelLen, pInputInfo->length, pInputInfo->pData,
            pOutputInfo->pBuffer);
        if (0 != mbedStatus)
            goto exit;
    }

    *(pOutputInfo->pLength) = keyLenBytes;
    status = OK;

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS RsaMbedDecrypt (
    MocAsymKey pMocAsymKey,
    MKeyAsymEncryptInfo *pInputInfo,
    MKeyOperatorBuffer *pOutputInfo
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    ubyte4 details = 0;
    ubyte4 keyLenBytes = 0;
    int mbedStatus = 0;
    size_t plainLen = 0;
    int hashAlgo = 0;
    mbedtls_rsa_context *pRsaCtx = NULL;
    ubyte *pLabel = NULL;
    ubyte4 labelLen = 0;

    if (NULL == pMocAsymKey || NULL == pInputInfo || NULL == pOutputInfo || NULL == pOutputInfo->pLength)
        goto exit;
    
    pRsaCtx = (mbedtls_rsa_context *) pMocAsymKey->pKeyData;
    
    status = ERR_RSA_KEY_NOT_READY;
    if (NULL == pRsaCtx)
        goto exit;

    details = pInputInfo->algorithmDetails;

    status = ERR_NOT_IMPLEMENTED;
    if (NULL != pInputInfo->pAlgId)
        goto exit;

    status = ERR_INVALID_INPUT;
    if ( (MOC_ASYM_KEY_ALG_RSA_ENC_P1_PAD != details) &&
         (MOC_ASYM_KEY_ALG_RSA_OAEP_PAD != details) &&
         (MOC_ASYM_KEY_ALG_RSA_ENC_NO_PAD != details) )
        goto exit;

    if (MOC_LOCAL_KEY_RSA_PRI_OPERATOR != pMocAsymKey->localType)
        goto exit;

    keyLenBytes = (ubyte4) mbedtls_rsa_get_len(pRsaCtx);

    /* Ensure the input is the same length as the RSA modulus size.
     */
    status = ERR_BAD_LENGTH;
    if (keyLenBytes != pInputInfo->length)
        goto exit;

    status = ERR_BUFFER_TOO_SMALL;
    *(pOutputInfo->pLength) = keyLenBytes;
    if (pOutputInfo->bufferSize < keyLenBytes)
        goto exit;

    *(pOutputInfo->pLength) = 0;

    plainLen = pInputInfo->length;

    status = ERR_MBED_FAILURE;
    if (MOC_ASYM_KEY_ALG_RSA_ENC_NO_PAD == details)
    {
        if (NULL != pInputInfo->pRandInfo)
        {
            mbedStatus = mbedtls_rsa_private(
                pRsaCtx, MocMbedRngFun, pInputInfo->pRandInfo,
                pInputInfo->pData, pOutputInfo->pBuffer);
        }
        else
        {
            mbedStatus = mbedtls_rsa_private(
                pRsaCtx, NULL, NULL, pInputInfo->pData, pOutputInfo->pBuffer);
        }
        if (0 != mbedStatus)
            goto exit;
    }
    else if (MOC_ASYM_KEY_ALG_RSA_ENC_P1_PAD == details)
    {
        mbedtls_rsa_set_padding(pRsaCtx, MBEDTLS_RSA_PKCS_V15, 0);
        mbedStatus = mbedtls_rsa_rsaes_pkcs1_v15_decrypt(
            pRsaCtx, MocMbedRngFun, pInputInfo->pRandInfo, MBEDTLS_RSA_PRIVATE,
            &plainLen, pInputInfo->pData, pOutputInfo->pBuffer,
            pOutputInfo->bufferSize);
        if (0 != mbedStatus)
            goto exit;
    }
    else
    {
        /* Default to SHA1 */
        hashAlgo = MBEDTLS_MD_SHA1;

        /* Did the caller provide additional info to override default parameters? */
        if (NULL != pInputInfo->pAdditionalInfo)
        {
            status = RsaMbedProcessOaepInfo (
                pInputInfo, (ubyte4*)&hashAlgo, &pLabel, &labelLen);
            if (OK != status)
                goto exit;

            status = ERR_NULL_POINTER;
            if (labelLen && NULL == pLabel)
                goto exit;
            
            /* Reset status */
            status = ERR_MBED_FAILURE;
        }
    
        mbedtls_rsa_set_padding(pRsaCtx, MBEDTLS_RSA_PKCS_V21, hashAlgo);
        mbedStatus = mbedtls_rsa_rsaes_oaep_decrypt(
            pRsaCtx, MocMbedRngFun, pInputInfo->pRandInfo, MBEDTLS_RSA_PRIVATE,
            pLabel, labelLen, &plainLen, pInputInfo->pData, pOutputInfo->pBuffer,
            pOutputInfo->bufferSize);
        if (0 != mbedStatus)
            goto exit;
    }

    *(pOutputInfo->pLength) = (ubyte4) plainLen;
    status = OK;

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS RSAMbedHash(int hashAlgo, ubyte *pData, ubyte4 dataLen, ubyte *pHashResult, ubyte4 *pHashLen)
{
    MSTATUS status = ERR_MBED_FAILURE;
    int mbedStatus = 0;

    mbedtls_md_context_t hashCtx;
    const mbedtls_md_info_t *pMdInfo = NULL;
    
    /* internal method, no null checks needed */
    
    pMdInfo = mbedtls_md_info_from_type((mbedtls_md_type_t)hashAlgo);
    if (NULL == pMdInfo)
        return status;  /* no cleanup */
    
    *pHashLen  = mbedtls_md_get_size(pMdInfo);
    
    mbedtls_md_init(&hashCtx);
    
    mbedStatus = mbedtls_md_setup(&hashCtx, pMdInfo, 0);
    if (0 != mbedStatus)
        goto exit;
    
    mbedStatus = mbedtls_md_starts(&hashCtx);
    if (0 != mbedStatus)
        goto exit;
    
    mbedStatus = mbedtls_md_update(&hashCtx, pData, dataLen);
    if (0 != mbedStatus)
        goto exit;
    
    mbedStatus = mbedtls_md_finish(&hashCtx, pHashResult);
    if (0 != mbedStatus)
        goto exit;

    status = OK;
    
exit:
    
    mbedtls_md_free( &hashCtx );
    
    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS RsaMbedSign (
    MocAsymKey pMocAsymKey,
    MKeyAsymSignInfo *pInputInfo,
    MKeyOperatorBuffer *pOutputInfo
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    mbedtls_rsa_context *pRsaCtx = NULL;
    int mbedStatus = 0;
    ubyte4 modLenBytes = 0;
    ubyte4 details = 0;
    
    if (NULL == pMocAsymKey || NULL == pInputInfo || NULL == pOutputInfo || NULL == pOutputInfo->pLength)
        goto exit;
    
    pRsaCtx = (mbedtls_rsa_context *) pMocAsymKey->pKeyData;
    
    status = ERR_RSA_KEY_NOT_READY;
    if (NULL == pRsaCtx)
        goto exit;

    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_rsa_check_privkey(pRsaCtx);
    if (0 != mbedStatus)
        goto exit;

    /* Make sure we support the algorithm for signing.
     */
    details = pInputInfo->algorithmDetails;
    status = ERR_RSA_INVALID_SIGNATURE_SCHEME;
    if ( (MOC_ASYM_KEY_ALG_RSA_SIGN_P1_PAD != details) &&
         (MOC_ASYM_KEY_ALG_RSA_PSS_PAD != details) )
        goto exit;

    /* Get the length of the modulus in bytes.
     */
    modLenBytes = (ubyte4) mbedtls_rsa_get_len(pRsaCtx);

    /* Check if the output buffer contains at least as many bytes as the
     * modulus.
     */
    status = ERR_BUFFER_TOO_SMALL;
    *(pOutputInfo->pLength) = modLenBytes;
    if (pOutputInfo->bufferSize < modLenBytes)
        goto exit;

    *(pOutputInfo->pLength) = 0;

    /* Perform PKCS #1 v1.5 or PKCS #1 PSS
     */
    if (MOC_ASYM_KEY_ALG_RSA_SIGN_P1_PAD == details)
    {
        status = ERR_RSA_BAD_SIGNATURE;
        mbedStatus = mbedtls_rsa_rsassa_pkcs1_v15_sign(
            pRsaCtx, MocMbedRngFun, pInputInfo->pRandInfo, MBEDTLS_RSA_PRIVATE,
            MBEDTLS_MD_NONE, pInputInfo->length, pInputInfo->pData,
            pOutputInfo->pBuffer);
    }
    else
    {
        int hashAlgo = 0;
        ubyte4 hashLen = 0;
        ubyte pHashResult[MOC_MAX_DIGEST_RESULT_SIZE];
        
        status = RsaMbedProcessPssInfo (
            pRsaCtx, (MRsaPssInfo *)pInputInfo->pAdditionalInfo,
            &hashAlgo, NULL, TRUE);
        if (OK != status)
            goto exit;

        /* We need to hash the message first */
        status = RSAMbedHash(hashAlgo, pInputInfo->pData, pInputInfo->length, pHashResult, &hashLen);
        if (OK != status)
            goto exit;
    
        status = ERR_MBED_FAILURE;
        mbedtls_rsa_set_padding(pRsaCtx, MBEDTLS_RSA_PKCS_V21, hashAlgo);
        mbedStatus = mbedtls_rsa_rsassa_pss_sign(
            pRsaCtx, MocMbedRngFun, pInputInfo->pRandInfo, MBEDTLS_RSA_PRIVATE,
            hashAlgo, hashLen, pHashResult,
            pOutputInfo->pBuffer);
        
        DIGI_MEMSET(pHashResult, 0x00, hashLen);
    }
    if (0 != mbedStatus)
        goto exit;

    *(pOutputInfo->pLength) = modLenBytes;
    status = OK;

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS RsaMbedVerify (
    MocAsymKey pMocAsymKey,
    MKeyAsymVerifyInfo *pInputInfo,
    ubyte4 *pOutputInfo
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    mbedtls_rsa_context *pRsaCtx = NULL;
    ubyte4 details = 0;
    int mbedStatus = 0;

    if (NULL == pMocAsymKey || NULL == pInputInfo || NULL == pOutputInfo)
        goto exit;
   
    pRsaCtx = (mbedtls_rsa_context *) pMocAsymKey->pKeyData;
    
    status = ERR_RSA_KEY_NOT_READY;
    if (NULL == pRsaCtx)
        goto exit;
    
    /* Make sure we support the algorithm for signing.
     */
    details = pInputInfo->algorithmDetails;
    status = ERR_INVALID_ARG;
    if ( (MOC_ASYM_KEY_ALG_RSA_SIGN_P1_PAD != details) &&
         (MOC_ASYM_KEY_ALG_RSA_PSS_PAD != details) )
        goto exit;

    if (MOC_ASYM_KEY_ALG_RSA_SIGN_P1_PAD == details)
    {
        mbedStatus = mbedtls_rsa_rsassa_pkcs1_v15_verify(
            pRsaCtx, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_NONE,
            pInputInfo->length, pInputInfo->pData,
            pInputInfo->pSignature);
    }
    else
    {
        sbyte4 saltLen = 0;
        ubyte4 hashLen = 0;
        int hashAlgo = 0;
        ubyte pHashResult[MOC_MAX_DIGEST_RESULT_SIZE];
        
        status = RsaMbedProcessPssInfo (
            pRsaCtx, (MRsaPssInfo *)pInputInfo->pAdditionalVfyInfo,
            &hashAlgo, &saltLen, FALSE);
        if (OK != status)
            goto exit;

        /* We need to hash the message first */
        status = RSAMbedHash(hashAlgo, pInputInfo->pData, pInputInfo->length, pHashResult, &hashLen);
        if (OK != status)
            goto exit;

        mbedStatus = mbedtls_rsa_rsassa_pss_verify_ext(
            pRsaCtx, NULL, NULL, MBEDTLS_RSA_PUBLIC, hashAlgo,
            hashLen, pHashResult, hashAlgo, saltLen,
            pInputInfo->pSignature);
        
        DIGI_MEMSET(pHashResult, 0x00, hashLen);
    }

    if (0 != mbedStatus)
        *pOutputInfo = MOC_ASYM_VFY_FAIL_INCOMPLETE;
    else
        *pOutputInfo = 0;

    status = OK;

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS RsaMbedGetPubFromPri(
    MocAsymKey pMocAsymKey,
    MocAsymKey *ppRetKey
    )
{
    MSTATUS status;

    mbedtls_rsa_context *pRsaCtx = NULL, *pRsaPubCtx = NULL;
    MocAsymKey pNewPub = NULL;
    int mbedStatus;

    status = ERR_NULL_POINTER;
    if ( (NULL == pMocAsymKey) || (NULL == ppRetKey) ||
         (NULL == pMocAsymKey->pKeyData) )
        goto exit;

    pRsaCtx = pMocAsymKey->pKeyData;

    status = DIGI_MALLOC((void **) &pRsaPubCtx, sizeof(mbedtls_rsa_context));
    if (OK != status)
        goto exit;

    mbedtls_rsa_init(pRsaPubCtx, 0, 0);

    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_rsa_import(
        pRsaPubCtx, &(pRsaCtx->N), NULL, NULL, NULL, &(pRsaCtx->E));
    if (0 != mbedStatus)
        goto exit;

    mbedStatus = mbedtls_rsa_complete(pRsaCtx);
    if (0 != mbedStatus)
        goto exit;

    status = CRYPTO_createMocAsymKey(
        KeyOperatorRsa, NULL, pMocAsymKey->pMocCtx,
        MOC_ASYM_KEY_TYPE_PUBLIC, &pNewPub);
    if (OK != status)
        goto exit;

    pNewPub->pKeyData = pRsaPubCtx;
    pRsaPubCtx = NULL;

    *ppRetKey = pNewPub;
    pNewPub = NULL;

exit:

    if (NULL != pRsaPubCtx)
    {
        mbedtls_rsa_free(pRsaPubCtx);
        DIGI_FREE((void **) &pRsaPubCtx);
    }

    if (NULL != pNewPub)
        CRYPTO_freeMocAsymKey(&pNewPub, NULL);

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS RsaMbedCloneKey (
    MocAsymKey pMocAsymKey,
    MocAsymKey *ppNewKey
    )
{
    MSTATUS status;

    mbedtls_rsa_context *pNewCtx = NULL;
    mbedtls_rsa_context *pInfo = pMocAsymKey->pKeyData;
    int mbedStatus;
    MocAsymKey pNewKey = NULL;

    status = DIGI_MALLOC((void **) &pNewCtx, sizeof(mbedtls_rsa_context));
    if (OK != status)
        goto exit;

    mbedtls_rsa_init(pNewCtx, 0, 0);

    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_rsa_copy(pNewCtx, pInfo);
    if (0 != mbedStatus)
        goto exit;

    status = CRYPTO_createMocAsymKey(
        KeyOperatorRsa, NULL, pMocAsymKey->pMocCtx,
        MOC_ASYM_KEY_TYPE_UNKNOWN, &pNewKey);
    if (OK != status)
        goto exit;

    pNewKey->pKeyData = pNewCtx;
    pNewKey->localType = pMocAsymKey->localType;
    pNewKey->pMocCtx = pMocAsymKey->pMocCtx;
    pNewKey->KeyOperator = pMocAsymKey->KeyOperator;
    *ppNewKey = pNewKey;
    pNewKey = NULL;
    pNewCtx = NULL;


exit:

    if (NULL != pNewCtx)
    {
        mbedtls_rsa_free(pNewCtx);
        DIGI_FREE((void **) &pNewCtx);
    }

    if (NULL != pNewKey)
        CRYPTO_freeMocAsymKey(&pNewKey, NULL);

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS RsaMbedSetKeyData (
    MocAsymKey pMocAsymKey,
    MRsaKeyTemplate *pTemplate
    )
{
    MSTATUS status;
    byteBoolean keyAllocated = FALSE;
    
    mbedtls_rsa_context *pRsaCtx = NULL;
    int mbedStatus;

    status = ERR_NULL_POINTER;
    if ( (NULL == pMocAsymKey) || (NULL == pTemplate) )
        goto exit;

    pRsaCtx = pMocAsymKey->pKeyData;

    if (NULL == pRsaCtx)
    {
        status = DIGI_MALLOC((void **) &(pRsaCtx), sizeof(mbedtls_rsa_context));
        if (OK != status)
            goto exit;
        
        keyAllocated = TRUE;
        mbedtls_rsa_init(pRsaCtx, 0, 0);
    }

    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_rsa_import_raw(
        pRsaCtx, pTemplate->pN, pTemplate->nLen,
        pTemplate->pP, pTemplate->pLen, pTemplate->pQ,
        pTemplate->qLen, NULL, 0,
        pTemplate->pE, pTemplate->eLen);
    if (0 != mbedStatus)
        goto exit;

    mbedStatus = mbedtls_rsa_complete(pRsaCtx);
    if (0 != mbedStatus)
        goto exit;

    if (NULL != pTemplate->pP)
        pMocAsymKey->localType = MOC_LOCAL_KEY_RSA_PRI_OPERATOR;
    else
        pMocAsymKey->localType = MOC_LOCAL_KEY_RSA_PUB_OPERATOR;
    pMocAsymKey->KeyOperator = KeyOperatorRsa;
    pMocAsymKey->pKeyData = pRsaCtx;
    pRsaCtx = NULL;
    status = OK;

exit:

    if (NULL != pRsaCtx)
    {
        mbedtls_rsa_free(pRsaCtx);
     
        /*
         Only free pRsaCtx if allocated this time (and not in a previous call).
         Make sure to set pMocAsymKey->pKeyData to NULL too.
         */
        if (keyAllocated)
        {
            DIGI_FREE((void **) &pRsaCtx);
            pMocAsymKey->pKeyData = NULL;
        }
    }

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS RsaMbedGetKeyDataAlloc (
    MocAsymKey pMocAsymKey,
    MRsaKeyTemplate *pTemplate,
    ubyte *pInputInfo
    )
{
    MSTATUS status;
    int mbedStatus;
    ubyte reqType;
    ubyte *pE = NULL;
    ubyte *pN = NULL;
    ubyte *pP = NULL;
    ubyte *pQ = NULL;
    ubyte *pD = NULL;
    ubyte *pDp = NULL;
    ubyte *pDq = NULL;
    ubyte *pQinv = NULL;
    ubyte4 eLen, nLen, pLen, qLen, dLen, dpLen, dqLen, qInvLen;
    mbedtls_rsa_context *pRsaCtx = NULL;

    status = ERR_NULL_POINTER;
    if ( (NULL == pMocAsymKey) || (NULL == pMocAsymKey->pKeyData) ||
         (NULL == pTemplate) || (NULL == pInputInfo) )
    {
        goto exit;
    }

    eLen = nLen = pLen = qLen = dLen = dpLen = dqLen = qInvLen = 0;
    pRsaCtx = pMocAsymKey->pKeyData;
    reqType = *pInputInfo;

    /* Must have the proper key type flag defined */
    status = ERR_INVALID_ARG;
    if ( (MOC_GET_PUBLIC_KEY_DATA  != reqType) &&
         (MOC_GET_PRIVATE_KEY_DATA != reqType) )
    {
        goto exit;
    }

    /* Process E */
    status = ERR_MBED_FAILURE;
    eLen = (ubyte4) mbedtls_mpi_size(&(pRsaCtx->E));
    if (0 == eLen)
        goto exit;

    status = DIGI_MALLOC((void **)&pE, eLen);
    if (OK != status)
        goto exit;

    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_mpi_write_binary(&(pRsaCtx->E), pE, eLen);
    if (0 != mbedStatus)
        goto exit;

    /* Process N */
    nLen = (ubyte4) mbedtls_mpi_size(&(pRsaCtx->N));
    if (0 == nLen)
        goto exit;

    status = DIGI_MALLOC((void **)&pN, nLen);
    if (OK != status)
        goto exit;

    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_mpi_write_binary(&(pRsaCtx->N), pN, nLen);
    if (0 != mbedStatus)
        goto exit;

    /* If private data was requested, process the private fields */
    if (MOC_GET_PRIVATE_KEY_DATA == reqType)
    {
        /* Process P */
        pLen = (ubyte4) mbedtls_mpi_size(&(pRsaCtx->P));
        if (0 == pLen)
            goto exit;

        status = DIGI_MALLOC((void **)&pP, pLen);
        if (OK != status)
            goto exit;

        status = ERR_MBED_FAILURE;
        mbedStatus = mbedtls_mpi_write_binary(&(pRsaCtx->P), pP, pLen);
        if (0 != mbedStatus)
            goto exit;

        /* Process Q */
        qLen = (ubyte4) mbedtls_mpi_size(&(pRsaCtx->Q));
        if (0 == qLen)
            goto exit;

        status = DIGI_MALLOC((void **)&pQ, qLen);
        if (OK != status)
            goto exit;

        status = ERR_MBED_FAILURE;
        mbedStatus = mbedtls_mpi_write_binary(&(pRsaCtx->Q), pQ, qLen);
        if (0 != mbedStatus)
            goto exit;

        /* Process D */
        dLen = (ubyte4) mbedtls_mpi_size(&(pRsaCtx->D));
        if (0 == dLen)
            goto exit;

        status = DIGI_MALLOC((void **)&pD, dLen);
        if (OK != status)
            goto exit;

        status = ERR_MBED_FAILURE;
        mbedStatus = mbedtls_mpi_write_binary(&(pRsaCtx->D), pD, dLen);
        if (0 != mbedStatus)
            goto exit;

        /* Process Dp */
        dpLen = (ubyte4) mbedtls_mpi_size(&(pRsaCtx->DP));
        if (0 == dpLen)
            goto exit;

        status = DIGI_MALLOC((void **)&pDp, dpLen);
        if (OK != status)
            goto exit;

        status = ERR_MBED_FAILURE;
        mbedStatus = mbedtls_mpi_write_binary(&(pRsaCtx->DP), pDp, dpLen);
        if (0 != mbedStatus)
            goto exit;

        /* Process Dq */
        dqLen = (ubyte4) mbedtls_mpi_size(&(pRsaCtx->DQ));
        if (0 == dqLen)
            goto exit;

        status = DIGI_MALLOC((void **)&pDq, dqLen);
        if (OK != status)
            goto exit;

        status = ERR_MBED_FAILURE;
        mbedStatus = mbedtls_mpi_write_binary(&(pRsaCtx->DQ), pDq, dqLen);
        if (0 != mbedStatus)
            goto exit;

        /* Process Qinv */
        qInvLen = (ubyte4) mbedtls_mpi_size(&(pRsaCtx->QP));
        if (0 == qInvLen)
            goto exit;

        status = DIGI_MALLOC((void **)&pQinv, qInvLen);
        if (OK != status)
            goto exit;

        status = ERR_MBED_FAILURE;
        mbedStatus = mbedtls_mpi_write_binary(&(pRsaCtx->QP), pQinv, qInvLen);
        if (0 != mbedStatus)
            goto exit;
    }

    pTemplate->pE = pE;
    pTemplate->eLen = eLen;
    pTemplate->pN = pN;
    pTemplate->nLen = nLen;
    pTemplate->pP = pP;
    pTemplate->pLen = pLen;
    pTemplate->pQ = pQ;
    pTemplate->qLen = qLen;
    pTemplate->pD = pD;
    pTemplate->dLen = dLen;
    pTemplate->pDp = pDp;
    pTemplate->dpLen = dpLen;
    pTemplate->pDq = pDq;
    pTemplate->dqLen = dqLen;
    pTemplate->pQinv = pQinv;
    pTemplate->qInvLen = qInvLen;
    pE = NULL;
    pN = NULL;
    pP = NULL;
    pQ = NULL;
    pD = NULL;
    pDp = NULL;
    pDq = NULL;
    pQinv = NULL;
    status = OK;

exit:

    if (NULL != pE)
    {
        DIGI_FREE((void **)&pE);
    }
    if (NULL != pN)
    {
        DIGI_FREE((void **)&pN);
    }
    if (NULL != pP)
    {
        DIGI_FREE((void **)&pP);
    }
    if (NULL != pQ)
    {
        DIGI_FREE((void **)&pQ);
    }
    if (NULL != pD)
    {
        DIGI_FREE((void **)&pD);
    }
    if (NULL != pDp)
    {
        DIGI_FREE((void **)&pDp);
    }
    if (NULL != pDq)
    {
        DIGI_FREE((void **)&pDq);
    }
    if (NULL != pQinv)
    {
        DIGI_FREE((void **)&pQinv);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS RsaMbedFreeKey(
    MocAsymKey pMocAsymKey
    )
{
    MSTATUS status = OK;

    if (NULL == pMocAsymKey)
        return ERR_NULL_POINTER;

    if (NULL != pMocAsymKey->pKeyData)
    {
        mbedtls_rsa_free((mbedtls_rsa_context *) pMocAsymKey->pKeyData);
        status = DIGI_FREE( &(pMocAsymKey->pKeyData) );
    }
    
    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS RsaMbedProcessOaepInfo (
    MKeyAsymEncryptInfo *pInputInfo,
    ubyte4 *pHashAlgo,
    ubyte **ppLabel,
    ubyte4 *pLabelLen
    )
{
    MSTATUS status = ERR_INVALID_ARG;
    MRsaOaepInfo *pOaepInfo = NULL;

    /* Additional parameter info for OAEP was provided. Mbedtls does
     * not support using a different hash algorithm for the MGF, and
     * it also mandates use of MGF1. Ensure that the requested param
     * info is valid */
    pOaepInfo = (MRsaOaepInfo *)(pInputInfo->pAdditionalInfo);
    if ( (MOC_PKCS1_ALG_MGF1 != pOaepInfo->mgfAlgo) ||
        (pOaepInfo->hashAlgo != pOaepInfo->mgfHashAlgo) )
    {
        goto exit;
    }
    
    *ppLabel = pOaepInfo->pLabel;
    *pLabelLen = pOaepInfo->labelLen;
    
    /* Convert the hash algorithm to a value mbedtls will understand */
    switch(pOaepInfo->hashAlgo)
    {
        case ht_sha1:
            *pHashAlgo = MBEDTLS_MD_SHA1;
            break;
            
        case ht_sha224:
            *pHashAlgo = MBEDTLS_MD_SHA224;
            break;
            
        case ht_sha256:
            *pHashAlgo = MBEDTLS_MD_SHA256;
            break;
            
        case ht_sha384:
            *pHashAlgo = MBEDTLS_MD_SHA384;
            break;
            
        case ht_sha512:
            *pHashAlgo = MBEDTLS_MD_SHA512;
            break;
            
        default:
            goto exit;
    }
    
    status = OK;

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS RsaMbedProcessPssInfo (
    mbedtls_rsa_context *pCtx,
    MRsaPssInfo *pPssInfo,
    int *pHashAlgo,
    sbyte4 *pSaltLen,
    ubyte isSign
    )
{
    MSTATUS status = ERR_NULL_POINTER;

    if (NULL == pPssInfo)
        goto exit;

    /* Additional parameter info for PSS was provided. Mbedtls does
     * not support using a different hash algorithm for the MGF, and
     * it also mandates use of MGF1. Ensure that the requested param
     * info is valid */
    status = ERR_INVALID_ARG;  /* same return for digicert RSA */
    if ( (pPssInfo->hashAlgo != pPssInfo->mgfHashAlgo) ||
         (MOC_PKCS1_ALG_MGF1 != pPssInfo->mgfAlgo) )
    {
        goto exit;
    }

    /* Convert the hash algorithm to a value mbedtls will understand */
    status = RsaMbedConvertHashAlgo(pPssInfo->hashAlgo, pHashAlgo);
    if (OK != status)
        goto exit;

    /* Mbed does not support specifying your own params on signing, only
     * verifying. */
    if (TRUE == isSign)
    {
        /* Mbed uses a salt length equal to the length of the hash algorithm output */
        status = ERR_INVALID_ARG;
        if (pPssInfo->saltLen != (sbyte4)
                mbedtls_md_get_size(mbedtls_md_info_from_type(*pHashAlgo)))
        {
            goto exit;
        }
    }

    if (NULL != pSaltLen)
    {
        *pSaltLen = pPssInfo->saltLen;
    }

    status = OK;

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS RsaMbedConvertHashAlgo (
    ubyte hashAlgo,
    int *pMbedHashAlgo
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    
    if (NULL == pMbedHashAlgo)
        goto exit;

    status = ERR_INVALID_ARG;
    switch(hashAlgo)
    {
        case ht_sha1:
            *pMbedHashAlgo = MBEDTLS_MD_SHA1;
            break;

        case ht_sha224:
            *pMbedHashAlgo = MBEDTLS_MD_SHA224;
            break;

        case ht_sha256:
            *pMbedHashAlgo = MBEDTLS_MD_SHA256;
            break;

        case ht_sha384:
            *pMbedHashAlgo = MBEDTLS_MD_SHA384;
            break;

        case ht_sha512:
            *pMbedHashAlgo = MBEDTLS_MD_SHA512;
            break;

        default:
            goto exit;
    }

    status = OK;

exit:
    return status;
}

#endif
