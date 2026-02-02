/*
 * mbedcommonecc.c
 *
 * Operator for Software version of ECC MocAsym Key.
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


#if (defined(__ENABLE_DIGICERT_ECC_P192_MBED__) || \
     defined(__ENABLE_DIGICERT_ECC_P224_MBED__) || \
     defined(__ENABLE_DIGICERT_ECC_P256_MBED__) || \
     defined(__ENABLE_DIGICERT_ECC_P384_MBED__) || \
     defined(__ENABLE_DIGICERT_ECC_P521_MBED__))

#include "../../../crypto/crypto.h"

#include "../../../crypto/mocasymkeys/mbed/mbedcommonecc.h"
#include "../../../crypto/mocsymalgs/mbed/mbedrandom.h"

/*---------------------------------------------------------------------------*/

#define MOC_ECC_BLOB_START_LEN 12
#define MOC_ECC_BLOB_START \
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, \
    0x00, 0x00, 0x00, 0x02

static MSTATUS EccMbedBuildMocanaBlob (
    MocAsymKey pMocAsymKey,
    MKeyOperatorDataReturn *pOutputInfo
    );

static MSTATUS EccMbedReadMocanaBlob (
    MocAsymKey pMocAsymKey,
    mbedtls_ecp_group_id eccGroupId,
    MKeyOperatorData *pInputInfo
    );

/*
 For hashAlgo ht_none only the leftmost n bits of the message
 will be used where n is the curve bit size, hence 521 maximum
 bits or 66 bytes.
 */
#define MBED_ECC_MAX_DIGEST_LEN 66

/* It is up to the caller to make sure pDigest has at least MBED_ECC_MAX_DIGEST_LEN bytes of space */
static MSTATUS ECCMbedDigestMessage(
    ubyte hashAlgo,
    ubyte *pMessage,
    ubyte4 msgLen,
    ubyte *pDigest,
    ubyte4 *pDigestLen
    )
{
    MSTATUS status = OK;
    int mbedStatus = 0;
    
    /* internal method, NULL checks not necessary */
    
    switch (hashAlgo)
    {
        case ht_none:
            
            *pDigestLen = msgLen < MBED_ECC_MAX_DIGEST_LEN ? msgLen : MBED_ECC_MAX_DIGEST_LEN;
            status = DIGI_MEMCPY(pDigest, pMessage, *pDigestLen);
            break;
            
        case ht_sha1:
            
            *pDigestLen = 20;
            mbedStatus = mbedtls_sha1_ret(pMessage, msgLen, pDigest);
            break;
            
        case ht_sha224:
            
            *pDigestLen = 28;
            mbedStatus = mbedtls_sha256_ret(pMessage, msgLen, pDigest, 1);
            break;
            
        case ht_sha256:
            
            *pDigestLen = 32;
            mbedStatus = mbedtls_sha256_ret(pMessage, msgLen, pDigest, 0);
            break;
            
        case ht_sha384:
            
            *pDigestLen = 48;
            mbedStatus = mbedtls_sha512_ret(pMessage, msgLen, pDigest, 1);
            break;
            
        case ht_sha512:
            
            *pDigestLen = 64;
            mbedStatus = mbedtls_sha512_ret(pMessage, msgLen, pDigest, 0);
            break;
            
        default:
            
            status = ERR_EC_INVALID_HASH_ALGO;
            break;
    }
    
    if (mbedStatus)
        status = ERR_MBED_FAILURE;

    return status;
    
}

/*---------------------------------------------------------------------------*/

MSTATUS EccMbedSign (
  MocAsymKey pMocAsymKey,
  MKeyAsymSignInfo *pInputInfo,
  MKeyOperatorBuffer *pOutputInfo
  )
{
    MSTATUS status;

    mbedtls_ecp_keypair *pKey = pMocAsymKey->pKeyData;
    int mbedStatus, modLen;
    ubyte4 outLen;
    ubyte4 format;
    ubyte *pAlgId = NULL, *pOutput = NULL;
    mbedtls_mpi r, s;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    status = ERR_NULL_POINTER;
    if (NULL == pKey)
        goto exit;

    format = MOC_ECDSA_SIGN_FORMAT_RAW;
    if (NULL != pInputInfo->pAdditionalInfo)
    {
        format = *((ubyte4 *) pInputInfo->pAdditionalInfo);

        /* Do we recognize this format? */
        status = ERR_INVALID_INPUT;
        if (MOC_ECDSA_SIGN_FORMAT_RAW != format)
            goto exit;
    }

    /* Make sure the algorithmDetails is one we support.
     */
    status = ERR_INVALID_INPUT;
    if (MOC_ASYM_KEY_ALG_ECDSA != pInputInfo->algorithmDetails)
        goto exit;

    /* Get the length based on the curve order
     */
    modLen = (ubyte4) mbedtls_mpi_size(&(pKey->grp.N));
    outLen = modLen * 2;
    
    status = ERR_BUFFER_TOO_SMALL;
    *pOutputInfo->pLength = outLen;
    if (pOutputInfo->bufferSize < outLen)
        goto exit;

    *pOutputInfo->pLength = 0;

    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_ecdsa_sign(
        &(pKey->grp), &r, &s, &(pKey->d), pInputInfo->pData,
        pInputInfo->length, MocMbedRngFun, pInputInfo->pRandInfo);
    if (0 != mbedStatus)
        goto exit;

    mbedStatus = mbedtls_mpi_write_binary(&r, pOutputInfo->pBuffer, modLen);
    if (0 != mbedStatus)
        goto exit;

    mbedStatus = mbedtls_mpi_write_binary(
        &s, pOutputInfo->pBuffer + modLen, modLen);
    if (0 != mbedStatus)
        goto exit;

    *pOutputInfo->pLength = (ubyte4) outLen;
    status = OK;

exit:

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS EccMbedSignDigestInfo (
    MocAsymKey pMocAsymKey,
    MKeyAsymSignInfo *pInputInfo,
    MKeyOperatorBuffer *pOutputInfo
    )
{
    MSTATUS status;

    ubyte *pOid = NULL, *pDigest = NULL;
    ubyte4 oidLen, digestLen, digestAlg;

    status = ERR_NOT_IMPLEMENTED;
    if (NULL != pInputInfo->pAlgId)
        goto exit;

    /* Decode the DigestInfo.
     * This will determine the algorithm as well as point to the actual digest.
     */
    status = ASN1_parseDigestInfo (
        pInputInfo->pData, pInputInfo->length,
        &pOid, &oidLen, &pDigest, &digestLen, &digestAlg);
    if (OK != status)
        goto exit;

    /* Set the InputInfo's data pointer to that of the digest since we're just
     * going to hand it off to the sign digest function */
    pInputInfo->pData = pDigest;
    pInputInfo->length = digestLen;

    status = EccMbedSign(pMocAsymKey, pInputInfo, pOutputInfo);

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS EccMbedSignMessage (
    MocAsymKey pMocAsymKey,
    MKeyAsymSignInfo *pInputInfo,
    MKeyOperatorBuffer *pOutputInfo
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 digestLen = 0;
    MEccDsaInfo *eccDsaInfo;
    
    ubyte pTemp[MBED_ECC_MAX_DIGEST_LEN];
   
    if (NULL == pInputInfo || (NULL == pInputInfo->pData && pInputInfo->length) || NULL == pInputInfo->pAdditionalInfo)
        goto exit;
    
    eccDsaInfo = (MEccDsaInfo *) pInputInfo->pAdditionalInfo;
    
    status = ECCMbedDigestMessage(eccDsaInfo->hashAlgo, pInputInfo->pData, pInputInfo->length, pTemp, &digestLen);
    if (OK != status)
        goto exit;
    
    /* reset the input info to what EccMbedSign wants */
    pInputInfo->pData = (ubyte *) pTemp;
    pInputInfo->length = digestLen;
    pInputInfo->pAdditionalInfo = (void *) &(eccDsaInfo->format);
    
    status = EccMbedSign(pMocAsymKey, pInputInfo, pOutputInfo);
    
exit:
    
    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS EccMbedVerify (
    MocAsymKey pMocAsymKey,
    MKeyAsymVerifyInfo *pInputInfo,
    ubyte4 *pOutputInfo
    )
{
    MSTATUS status;
    ubyte *pRVal = NULL;
    ubyte *pSVal = NULL;
    mbedtls_ecp_keypair *pKey = pMocAsymKey->pKeyData;
    sbyte4 rLen, sLen;
    ubyte4 format;
    int mbedStatus;
    mbedtls_mpi r, s;

    status = ERR_NULL_POINTER;
    if ( (NULL == pInputInfo) || (NULL == pInputInfo->pSignature) )
        goto exit;

    format = 0;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    /* Did the caller specify a format? */
    if (NULL != pInputInfo->pAdditionalVfyInfo)
    {
        /* They did specify a format */
        format = *((ubyte4 *)pInputInfo->pAdditionalVfyInfo);

        /* Do we recognize this format? */
        status = ERR_INVALID_INPUT;
        if (MOC_ECDSA_SIGN_FORMAT_RAW != format)
        {
            goto exit;
        }
    }

    pRVal = pInputInfo->pSignature;
    pSVal = pInputInfo->pSignature + (pInputInfo->signatureLen / 2);
    rLen = pInputInfo->signatureLen / 2;
    sLen = rLen;

    mbedStatus = mbedtls_mpi_read_binary(&r, pRVal, rLen);
    if (0 != mbedStatus)
        goto exit;

    mbedStatus = mbedtls_mpi_read_binary(&s, pSVal, sLen);
    if (0 != mbedStatus)
        goto exit;

    status = ERR_NULL_POINTER;
    if (NULL == pKey)
        goto exit;

    status = OK;
    mbedStatus = mbedtls_ecdsa_verify(
        &(pKey->grp), pInputInfo->pData, pInputInfo->length, &(pKey->Q),
        &r, &s);
    if (0 == mbedStatus)
        *pOutputInfo = 0;
    else
        *pOutputInfo = MOC_ASYM_VFY_FAIL_VALUE;


exit:

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS EccMbedVerifyDigestInfo (
    MocAsymKey pMocAsymKey,
    MKeyAsymVerifyInfo *pInputInfo,
    ubyte4 *pOutputInfo
    )
{
    MSTATUS status;

    mbedtls_ecp_keypair *pKey = pMocAsymKey->pKeyData;
    ubyte *pOid = NULL, *pDigest = NULL;
    ubyte4 oidLen, digestLen, digestAlg;

    status = ERR_NULL_POINTER;
    if (NULL == pKey)
        goto exit;

    /* Decode the DigestInfo.
     * This will determine the algorithm as well as point to the actual digest.
     */
    status = ASN1_parseDigestInfo (
        pInputInfo->pData, pInputInfo->length,
        &pOid, &oidLen, &pDigest, &digestLen, &digestAlg);
    if (OK != status)
        goto exit;

    pInputInfo->pData = pDigest;
    pInputInfo->length = digestLen;

    status = EccMbedVerify(pMocAsymKey, pInputInfo, pOutputInfo);

exit:

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS EccMbedVerifyMessage (
    MocAsymKey pMocAsymKey,
    MKeyAsymVerifyInfo *pInputInfo,
    ubyte4 *pOutputInfo
    )
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte4 digestLen = 0;
    MEccDsaInfo *eccDsaInfo;
    
    ubyte pTemp[MBED_ECC_MAX_DIGEST_LEN];
    
    if (NULL == pInputInfo || (NULL == pInputInfo->pData && pInputInfo->length) || NULL == pInputInfo->pAdditionalVfyInfo)
        goto exit;
    
    eccDsaInfo = (MEccDsaInfo *) pInputInfo->pAdditionalVfyInfo;
    
    status = ECCMbedDigestMessage(eccDsaInfo->hashAlgo, pInputInfo->pData, pInputInfo->length, pTemp, &digestLen);
    if (OK != status)
        goto exit;
    
    /* reset the input info to what EccMbedVerify wants */
    pInputInfo->pData = (ubyte *) pTemp;
    pInputInfo->length = digestLen;
    pInputInfo->pAdditionalVfyInfo = (void *) &(eccDsaInfo->format);
    
    status = EccMbedVerify(pMocAsymKey, pInputInfo, pOutputInfo);
    
exit:
    
    return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS EccMbedGenerateKeyPair(
    MocCtx pMocCtx,
    MKeyOperator KeyOperator,
    MKeyPairGenInfo *pInputInfo,
    MKeyPairGenResult *pOutputInfo,
    mbedtls_ecp_group_id eccGroupId
    )
{
    MSTATUS status;

    MocAsymKey pPub = NULL;
    MocAsymKey pPri = NULL;
    mbedtls_ecp_keypair *pKeyPair = NULL;
    int mbedStatus;

    status = ERR_NULL_POINTER;
    if ( (NULL == pInputInfo->pRandInfo) ||
         (NULL == pInputInfo->pRandInfo->RngFun) ||
         (NULL == pOutputInfo->ppPubKey) ||
         (NULL == pOutputInfo->ppPriKey) )
        goto exit;

    status = DIGI_MALLOC((void **) &pKeyPair, sizeof(mbedtls_ecp_keypair));
    if (OK != status)
        goto exit;

    mbedtls_ecp_keypair_init(pKeyPair);

    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_ecp_gen_key(
        eccGroupId, pKeyPair, MocMbedRngFun, pInputInfo->pRandInfo);
    if (0 != mbedStatus)
        goto exit;

    status = CRYPTO_createMocAsymKey(
        KeyOperator, NULL, pMocCtx, MOC_ASYM_KEY_TYPE_PRIVATE,
        &pPri);
    if (OK != status)
        goto exit;

    pPri->pKeyData = pKeyPair;
    pKeyPair = NULL;

    status = CRYPTO_getPubFromPri(pPri, &pPub, NULL);
    if (OK != status)
        goto exit;

    *(pOutputInfo->ppPubKey) = pPub;
    *(pOutputInfo->ppPriKey) = pPri;

    pPub = NULL;
    pPri = NULL;

exit:

    if (NULL != pKeyPair)
    {
        mbedtls_ecp_keypair_free(pKeyPair);
        DIGI_FREE((void **) &pKeyPair);
    }

    if (NULL != pPub)
        CRYPTO_freeMocAsymKey(&pPub, NULL);

    if (NULL != pPri)
        CRYPTO_freeMocAsymKey(&pPri, NULL);

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS EccMbedComputeSharedSecret (
  MocAsymKey pMocAsymKey,
  MKeyOperatorData *pPubVal,
  MKeyOperatorBuffer *pSharedSecret
  )
{
    MSTATUS status;

    int mbedStatus;
    mbedtls_mpi secret;
    mbedtls_ecp_point pubPoint;
    mbedtls_ecp_keypair *pPriKey = pMocAsymKey->pKeyData;
    ubyte4 secretLen;

    mbedtls_mpi_init(&secret);
    mbedtls_ecp_point_init(&pubPoint);

    status = ERR_NULL_POINTER;
    if (NULL == pPriKey)
        goto exit;

    secretLen = (ubyte4) ( pPriKey->grp.pbits + 7 ) / 8;

    status = ERR_BUFFER_TOO_SMALL;
    *(pSharedSecret->pLength) = secretLen;
    if (pSharedSecret->bufferSize < secretLen)
        goto exit;

    *(pSharedSecret->pLength) = 0;

    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_ecp_point_read_binary(
        &(pPriKey->grp), &pubPoint, pPubVal->pData, pPubVal->length);
    if (0 != mbedStatus)
        goto exit;

    mbedStatus = mbedtls_ecdh_compute_shared(
        &(pPriKey->grp), &secret, &pubPoint, &(pPriKey->d), NULL, NULL);
    if (0 != mbedStatus)
        goto exit;

    mbedStatus = mbedtls_mpi_write_binary(
        &secret, pSharedSecret->pBuffer, secretLen);
    if (0 != mbedStatus)
        goto exit;

    *(pSharedSecret->pLength) = secretLen;
    status = OK;

exit:

    mbedtls_mpi_free(&secret);
    mbedtls_ecp_point_free(&pubPoint);

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS EccMbedSetKeyData (
    MocAsymKey pMocAsymKey,
    MKeyOperator operator,
    ubyte4 localType,
    MEccKeyTemplate *pTemplate,
    mbedtls_ecp_group_id eccGroupId
    )
{
    MSTATUS status;

    mbedtls_ecp_keypair *pData = NULL;
    int mbedStatus;
    byteBoolean keyAllocated = FALSE;

    status = ERR_NULL_POINTER;
    if ( (NULL == pMocAsymKey) || (NULL == pTemplate) )
        goto exit;

    if ( (NULL == pTemplate->pPublicKey) && (NULL == pTemplate->pPrivateKey) )
        goto exit;

    pData = pMocAsymKey->pKeyData;

    if (NULL == pData)
    {
        status = DIGI_MALLOC((void **) &pData, sizeof(mbedtls_ecp_keypair));
        if (OK != status)
            goto exit;

        mbedtls_ecp_keypair_init(pData);
        keyAllocated = TRUE;
    }

    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_ecp_group_load(&(pData->grp), eccGroupId);
    if (0 != mbedStatus)
        goto exit;

    if (NULL != pTemplate->pPublicKey)
    {
        pMocAsymKey->localType = localType;
        mbedStatus = mbedtls_ecp_point_read_binary(
            &(pData->grp), &(pData->Q), pTemplate->pPublicKey,
            pTemplate->publicKeyLen);
        if (0 != mbedStatus)
            goto exit;
    }

    if (NULL != pTemplate->pPrivateKey)
    {
        pMocAsymKey->localType = localType | MOC_LOCAL_KEY_PRI;
        mbedStatus = mbedtls_mpi_read_binary(
            &(pData->d), pTemplate->pPrivateKey, pTemplate->privateKeyLen);
        if (0 != mbedStatus)
            goto exit;
       
        if (NULL == pTemplate->pPublicKey) /* then compute the public key */
        {
            mbedStatus = mbedtls_ecp_mul( &(pData->grp), &(pData->Q), &(pData->d), 
                                          &(pData->grp.G), NULL, NULL);
            if (0 != mbedStatus)
                goto exit;                     
        }
    }

    pMocAsymKey->KeyOperator = operator;
    pMocAsymKey->pKeyData = pData;
    pData = NULL;
    status = OK;

exit:

    if (NULL != pData)
    {
        mbedtls_ecp_keypair_free(pData);
        
        /*
         Only free pData if allocated this time (and not in a previous call).
         Make sure to set pMocAsymKey->pKeyData to NULL too.
         */
        if (keyAllocated)
        {
            DIGI_FREE((void **) &pData);
            pMocAsymKey->pKeyData = NULL;
        }
    }

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS EccMbedGetKeyDataAlloc(
    MocAsymKey pMocAsymKey,
    MEccKeyTemplate *pTemplate,
    ubyte *pInputInfo
    )
{
    MSTATUS status;

    mbedtls_ecp_keypair *pData = NULL;

    ubyte *pPri = NULL, *pPub = NULL;
    ubyte reqType;
    ubyte4 priLen = 0, pubLen = 0, elemLen;
    size_t outLen;
    int mbedStatus;

    status = ERR_NULL_POINTER;
    if ( (NULL == pMocAsymKey) || (NULL == pTemplate) ||
         (NULL == pMocAsymKey->pKeyData) || (NULL == pInputInfo) )
        goto exit;

    reqType = *pInputInfo;
    pData = pMocAsymKey->pKeyData;

    /* Must have the proper key type flag defined */
    status = ERR_INVALID_ARG;
    if ( (MOC_GET_PUBLIC_KEY_DATA  != reqType) &&
         (MOC_GET_PRIVATE_KEY_DATA != reqType) )
        goto exit;

    elemLen = (ubyte4) mbedtls_mpi_size(&(pData->grp.N));
    if (0 == elemLen)
        goto exit;
    
    if (MOC_GET_PRIVATE_KEY_DATA == reqType)
    {
        priLen = elemLen;
        
        status = DIGI_MALLOC((void **) &pPri, priLen);
        if (OK != status)
            goto exit;

        mbedStatus = mbedtls_mpi_write_binary(&(pData->d), pPri, priLen);
        if (0 != mbedStatus)
            goto exit;
    }

    status = DIGI_MALLOC((void **) &pPub, 2 * elemLen + 1);
    if (OK != status)
        goto exit;

    pubLen = 2 * elemLen + 1;

    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_ecp_point_write_binary(
        &(pData->grp), &(pData->Q), MBEDTLS_ECP_PF_UNCOMPRESSED, &outLen,
        pPub, pubLen);
    if (0 != mbedStatus)
        goto exit;

    /* no errors, set all template paramters (even if pPrivBytes is NULL) */
    pTemplate->pPrivateKey = pPri;
    pTemplate->privateKeyLen = priLen;
    pPri = NULL;

    pTemplate->pPublicKey = pPub;
    pTemplate->publicKeyLen = pubLen;
    pPub = NULL;

    status = OK;

exit:

    /* Only on error will any of these not be NULL. Don't change status */
    if (NULL != pPri)
    {
        DIGI_MEMSET(pPri, 0x00, elemLen);
        DIGI_FREE((void **) &pPri);
    }

    if (NULL != pPub)
    {
        DIGI_MEMSET(pPub, 0x00, pubLen);
        DIGI_FREE((void **) &pubLen);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS EccMbedCloneKey (
    MocAsymKey pMocAsymKey,
    MocAsymKey *ppNewKey
    )
{
    MSTATUS status;

    mbedtls_ecp_keypair *pNewKey = NULL;
    mbedtls_ecp_keypair *pInfo = pMocAsymKey->pKeyData;
    int mbedStatus;
    MocAsymKey pRetKey = NULL;

    status = DIGI_MALLOC((void **) &pNewKey, sizeof(mbedtls_ecp_keypair));
    if (OK != status)
        goto exit;

    mbedtls_ecp_keypair_init(pNewKey);

    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_ecp_group_copy(&(pNewKey->grp), &(pInfo->grp));
    if (0 != mbedStatus)
        goto exit;

    mbedStatus = mbedtls_ecp_copy(&(pNewKey->Q), &(pInfo->Q));
    if (0 != mbedStatus)
        goto exit;

    mbedStatus = mbedtls_mpi_copy(&(pNewKey->d), &(pInfo->d));
    if (0 != mbedStatus)
        goto exit;

    status = CRYPTO_createMocAsymKey(
        pMocAsymKey->KeyOperator, NULL, pMocAsymKey->pMocCtx,
        MOC_ASYM_KEY_TYPE_UNKNOWN, &pRetKey);
    if (OK != status)
        goto exit;

    pRetKey->pKeyData = pNewKey;
    pRetKey->localType = pMocAsymKey->localType;
    pRetKey->pMocCtx = pMocAsymKey->pMocCtx;
    pRetKey->KeyOperator = pMocAsymKey->KeyOperator;
    *ppNewKey = pRetKey;
    pNewKey = NULL;
    pRetKey = NULL;

exit:

    if (NULL != pNewKey)
    {
        mbedtls_ecp_keypair_free(pNewKey);
        DIGI_FREE((void **) &pNewKey);
    }

    if (NULL != pRetKey)
        CRYPTO_freeMocAsymKey(&pRetKey, NULL);

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS EccMbedBuildMocanaBlob(
    MocAsymKey pMocAsymKey,
    MKeyOperatorDataReturn *pOutputInfo
    )
{
    MSTATUS status;
    int mbedStatus;
    size_t outLen;
    ubyte4 temp, elementLen, curveId, priLen, totalLen;
    mbedtls_ecp_keypair *pData = NULL;
    ubyte *pBuf = NULL;
    ubyte *pIter = NULL;
    ubyte pBlobStart[MOC_ECC_BLOB_START_LEN] = {
        MOC_ECC_BLOB_START
    };

    status = ERR_NULL_POINTER;
    if ( (NULL == pMocAsymKey) || (NULL == pMocAsymKey->pKeyData) ||
         (NULL == pOutputInfo) )
    {
        goto exit;
    }

    /* The key blob is
     *   prefix || curve ID || pubLen || pub point [ || priLen || priVal ]
     * If this is a public key, there is no priLen or priVal.
     * The curveId, pubLen, and priLen are each 4 bytes.
     * The length of the blob is dependent on the prime size.
     * Determine the length. The pub point will be (2 * primeSize) + 1. The priVal
     * will be elementLen.
     */
    status = ERR_MBED_FAILURE;
    pData = pMocAsymKey->pKeyData;

    /* Get the element length */
    elementLen = (ubyte4) mbedtls_mpi_size(&(pData->grp.N));
    if (0 == elementLen)
        goto exit;

    /* Determine the curve id from the element len */
    switch(elementLen)
    {
        case 24:
            curveId = cid_EC_P192;
            break;

        case 28:
            curveId = cid_EC_P224;
            break;

        case 32:
            curveId = cid_EC_P256;
            break;

        case 48:
            curveId = cid_EC_P384;
            break;

        case 66:
            curveId = cid_EC_P521;
            break;

        default:
            goto exit;
    }

    /* Is this a private key? */
    priLen = (ubyte4) mbedtls_mpi_size(&(pData->d));
    if (0 != priLen)
    {
        priLen = elementLen + 4;
    }

    totalLen = MOC_ECC_BLOB_START_LEN + 9 + (2 * elementLen) + priLen;

    status = DIGI_MALLOC ((void **)&pBuf, totalLen);
    if (OK != status)
        goto exit;

    pIter = pBuf;

    /* Write out the prefix */
    status = DIGI_MEMCPY (
        (void *)pIter, (void *)pBlobStart, MOC_ECC_BLOB_START_LEN);
    if (OK != status)
        goto exit;

    pIter += MOC_ECC_BLOB_START_LEN;

    /* Set the curve id */
    BIGEND32(pIter, curveId);
    pIter += 4;

    /* Set the point length */
    temp = (2 * elementLen) + 1;
    BIGEND32(pIter, temp);
    pIter += 4;

    /* Write the public point */
    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_ecp_point_write_binary(
        &(pData->grp), &(pData->Q), MBEDTLS_ECP_PF_UNCOMPRESSED, &outLen,
        pIter, temp);
    if (0 != mbedStatus)
        goto exit;

    /* Write the private data if present */
    pIter += temp;
    if (0 != priLen)
    {
        /* Write the length of the private value */
        BIGEND32(pIter, elementLen);
        pIter += 4;

        /* Write the private value */
        mbedStatus = mbedtls_mpi_write_binary(&(pData->d), pIter, elementLen);
        if (0 != mbedStatus)
            goto exit;
    }


    *(pOutputInfo->ppData) = pBuf;
    *(pOutputInfo->pLength) = totalLen;
    pBuf = NULL;
    status = OK;

exit:

    if (NULL != pBuf)
    {
        DIGI_FREE((void **)&pBuf);
    }

    return status;
}

/*---------------------------------------------------------------------------*/

static MSTATUS EccMbedReadMocanaBlob (
    MocAsymKey pMocAsymKey,
    mbedtls_ecp_group_id eccGroupId,
    MKeyOperatorData *pInputInfo
    )
{
    MSTATUS status;
    sbyte4 cmpResult = 0;
    ubyte4 curveId, elementLen, dataLen, pubLen, priLen;
    MEccKeyTemplate keyTemplate = {0};
    ubyte *pIter = NULL;
    ubyte *pPoint = NULL;
    ubyte *pPriVal = NULL;
    ubyte pBlobStart[MOC_ECC_BLOB_START_LEN] = {
        MOC_ECC_BLOB_START
    };

    /* This MocAsymKey should have been created earlier, ensure it has an
     * operator and a type */
    status = ERR_NULL_POINTER;
    if ( (NULL == pMocAsymKey) || (NULL == pMocAsymKey->KeyOperator) ||
         (0 == pMocAsymKey->localType) )
    {
        goto exit;
    }

    pubLen = priLen = 0;
    pIter = pInputInfo->pData;
    dataLen = pInputInfo->length;

    /* The key blob is
     *   prefix || curve ID || pubLen || pub point [ || priLen || priVal ]
     * First, make sure there are prefixLen + 8 bytes, so we can read the prefix,
     * curveId, and pubLen.
     */
    status = ERR_INVALID_INPUT;
    if ((MOC_ECC_BLOB_START_LEN + 8) > dataLen)
        goto exit;

    /* Make sure the prefix is what we expect */
    status = DIGI_MEMCMP (
        (void *)pIter, (void *)pBlobStart, MOC_ECC_BLOB_START_LEN,
        &cmpResult);
    if (OK != status)
        goto exit;

    status = ERR_INVALID_INPUT;
    if (0 != cmpResult)
        goto exit;

    pIter += MOC_ECC_BLOB_START_LEN;
    dataLen -= MOC_ECC_BLOB_START_LEN;

    /* Read the curveId and pubLen */
    curveId = (((ubyte4)pIter[0]) << 24) +
              (((ubyte4)pIter[1]) << 16) +
              (((ubyte4)pIter[2]) <<  8) +
              ((ubyte4)pIter[3]);

    pubLen = (((ubyte4)pIter[4]) << 24) +
             (((ubyte4)pIter[5]) << 16) +
             (((ubyte4)pIter[6]) <<  8) +
             ((ubyte4)pIter[7]);

    /* Can we deserialize this curve? */
    switch(eccGroupId)
    {
        case MBEDTLS_ECP_DP_SECP192R1:
            if (cid_EC_P192 != curveId)
            {
                goto exit;
            }
            elementLen = 24;
            break;

        case MBEDTLS_ECP_DP_SECP224R1:
            if (cid_EC_P224 != curveId)
            {
                goto exit;
            }
            elementLen = 28;
            break;

        case MBEDTLS_ECP_DP_SECP256R1:
            if (cid_EC_P256 != curveId)
            {
                goto exit;
            }
            elementLen = 32;
            break;

        case MBEDTLS_ECP_DP_SECP384R1:
            if (cid_EC_P384 != curveId)
            {
                goto exit;
            }
            elementLen = 48;
            break;

        case MBEDTLS_ECP_DP_SECP521R1:
            if (cid_EC_P521 != curveId)
            {
                goto exit;
            }
            elementLen = 66;
            break;

        default:
            goto exit;
    }

    pIter += 8;
    dataLen -= 8;

    /* There should be at least pubLen bytes left */
    if (pubLen > dataLen)
        goto exit;

    /* Validate public point length */
    if ( ((2 * elementLen) + 1) != pubLen)
        goto exit;

    pPoint = pIter;
    pIter += pubLen;
    dataLen -= pubLen;

    /* If there is still data left, it is the private value */
    if (0 < dataLen)
    {
        /* We should have at least 4 bytes for the length */
        if (4 > dataLen)
            goto exit;

        priLen = (((ubyte4)pIter[0]) << 24) +
                 (((ubyte4)pIter[1]) << 16) +
                 (((ubyte4)pIter[2]) <<  8) +
                 ((ubyte4)pIter[3]);

        /* Private length should be exactly elementLen */
        if (elementLen != priLen)
            goto exit;

        /* Do we have as much data as we should? */
        if (dataLen < (priLen + 4))
            goto exit;

        pIter += 4;
        pPriVal = pIter;
    }

    /* We now have all the data we need, prepare the key template */
    keyTemplate.pPublicKey = pPoint;
    keyTemplate.publicKeyLen = pubLen;
    keyTemplate.pPrivateKey = pPriVal;
    keyTemplate.privateKeyLen = priLen;

    /* This function will create a new underlying key object and fill it
     * with the provided data */
    status = EccMbedSetKeyData (
        pMocAsymKey, pMocAsymKey->KeyOperator, pMocAsymKey->localType,
        &keyTemplate, eccGroupId);

 exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS EccMbedReturnPubValAlloc (
  MocAsymKey pMocAsymKey,
  MKeyOperatorDataReturn *pPubVal
  )
{
    MSTATUS status;

    mbedtls_ecp_keypair *pKey = pMocAsymKey->pKeyData;
    ubyte4 bufferLen;
    ubyte *pBuffer = NULL;
    int mbedStatus;
    size_t outputLen = 0;

    status = ERR_NULL_POINTER;
    if (NULL == pKey)
        goto exit;

    bufferLen = (ubyte4) (2 * mbedtls_mpi_size(&(pKey->grp.P)) + 1);

    status = DIGI_MALLOC((void **) &pBuffer, bufferLen);
    if (OK != status)
        goto exit;

    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_ecp_point_write_binary(
        &(pKey->grp), &(pKey->Q), MBEDTLS_ECP_PF_UNCOMPRESSED,
        &outputLen, pBuffer, bufferLen);
    if (0 != mbedStatus)
        goto exit;

    *(pPubVal->ppData) = pBuffer;
    *(pPubVal->pLength) = (ubyte4) outputLen;

    pBuffer = NULL;

    status = OK;

exit:

    if (NULL != pBuffer)
        DIGI_FREE((void **) &pBuffer);

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS EccMbedGetPubFromPri (
  MocAsymKey pMocAsymKey,
  MKeyOperator KeyOperator,
  MocAsymKey *ppPubKey
  )
{
    MSTATUS status;

    mbedtls_ecp_keypair *pNewKey = NULL, *pKey = NULL;
    MocAsymKey pNewPub = NULL;
    int mbedStatus;

    status = ERR_NULL_POINTER;
    if ( (NULL == pMocAsymKey) || (NULL == ppPubKey) ||
         (NULL == pMocAsymKey->pKeyData) )
        goto exit;

    pKey = pMocAsymKey->pKeyData;

    status = DIGI_MALLOC((void **) &pNewKey, sizeof(mbedtls_ecp_keypair));
    if (OK != status)
        goto exit;

    mbedtls_ecp_keypair_init(pNewKey);

    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_ecp_group_copy(&(pNewKey->grp), &(pKey->grp));
    if (0 != mbedStatus)
        goto exit;

    mbedStatus = mbedtls_ecp_copy(&(pNewKey->Q), &(pKey->Q));
    if (0 != mbedStatus)
        goto exit;

    status = CRYPTO_createMocAsymKey(
        KeyOperator, NULL, pMocAsymKey->pMocCtx,
        MOC_ASYM_KEY_TYPE_PUBLIC, &pNewPub);
    if (OK != status)
        goto exit;

    pNewPub->pKeyData = pNewKey;
    pNewKey = NULL;

    *ppPubKey = pNewPub;
    pNewPub = NULL;

exit:

    if (NULL != pNewKey)
    {
        mbedtls_ecp_keypair_free(pKey);
        DIGI_FREE((void **) &pKey);
    }

    if (NULL != pNewPub)
        CRYPTO_freeMocAsymKey(&pNewPub, NULL);

    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS EccMbedValidatePubPriMatch (
    MocAsymKey pMocAsymKey,
    MocAsymKey pPubKey,
    byteBoolean *pMatch
    )
{
    MSTATUS status;
    int mbedStatus = 0;
    mbedtls_ecp_keypair *pMbedPriKey = NULL, *pMbedPubKey = NULL;

    status = ERR_NULL_POINTER;
    if ( (NULL == pMocAsymKey) || (NULL == pPubKey) || (NULL == pMatch) ||
         (NULL == pMocAsymKey->pKeyData) || (NULL == pPubKey->pKeyData))
    {
        goto exit;
    }

    pMbedPriKey = (mbedtls_ecp_keypair *)pMocAsymKey->pKeyData;
    pMbedPubKey = (mbedtls_ecp_keypair *)pPubKey->pKeyData;

    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_ecp_check_pub_priv(
        (const mbedtls_ecp_keypair *)pMbedPubKey,
        (const mbedtls_ecp_keypair *)pMbedPriKey);
    if (MBEDTLS_ERR_ECP_BAD_INPUT_DATA == mbedStatus)
    {
        *pMatch = FALSE;
        status = OK;
    }
    else if (0 == mbedStatus)
    {
        *pMatch = TRUE;
        status = OK;
    }
    else
    {
        *pMatch = FALSE;
    }

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS EccMbedValidateKey (
    MocAsymKey pMocAsymKey,
    byteBoolean *pIsValid
    )
{
    MSTATUS status;
    int mbedStatus = 0;
    mbedtls_ecp_keypair *pKey = NULL;

    status = ERR_NULL_POINTER;
    if ( (NULL == pMocAsymKey) || (NULL == pMocAsymKey->pKeyData) ||
         (NULL == pIsValid) )
    {
        goto exit;
    }

    pKey = (mbedtls_ecp_keypair *)pMocAsymKey->pKeyData;

    /* Default to false */
    *pIsValid = FALSE;

    status = ERR_MBED_FAILURE;
    mbedStatus = mbedtls_ecp_check_pubkey (
        (const mbedtls_ecp_group *)&pKey->grp,
        (const mbedtls_ecp_point *)&pKey->Q);
    if (0 == mbedStatus)
    {
        *pIsValid = TRUE;
    }

    status = OK;

exit:
    return status;
}

/*---------------------------------------------------------------------------*/

MSTATUS EccMbedFreeKey (
  MocAsymKey pMocAsymKey
  )
{
    MSTATUS status = OK;

    if (NULL == pMocAsymKey)
        return ERR_NULL_POINTER;
    
    if (NULL != pMocAsymKey->pKeyData)
    {
        mbedtls_ecp_keypair_free((mbedtls_ecp_keypair *) pMocAsymKey->pKeyData);
        status = DIGI_FREE( &(pMocAsymKey->pKeyData) );
    }

    return status;
}

#endif /* __ENABLE_DIGICERT_ECC_P256_MBED__ */
