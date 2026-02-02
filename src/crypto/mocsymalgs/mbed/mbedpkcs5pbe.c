/*
 * mbedpkcs5pbe.c
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


#ifdef __ENABLE_DIGICERT_PKCS5_MBED__

#include "../../../asn1/oiddefs.h"

#include "mbedpkcs5pbe.h"
#include "../../../crypto/mocsymalgs/mbed/mbedhmaccommon.h"

#include "mbedtls/asn1write.h"

/* --------------------------------------------------------------- */

/* MUST match the enum values in pkcs5.h
   MBED only supports TDES and DES */
#define PKCS5_MBED_TDES 1
#define PKCS5_MBED_DES 3

/* MBED supports only sha1 and sha2 */
#define PKCS5_MBED_SHA1 5
#define PKCS5_MBED_SHA256 11
#define PKCS5_MBED_SHA384 12
#define PKCS5_MBED_SHA512 13
#define PKCS5_MBED_SHA224 14 /* YES SHA224 is here after the others */

static const ubyte pkcs5_root_OID[] = /* 1.2.840.113549.1.5 */
  { 8, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05 };

static const ubyte pkcs5_PBKDF2_OID[] =  /* 1.2.840.113549.1.5.12 */
  { 9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C };

static const ubyte pkcs5_PBES2_OID[] =   /* 1.2.840.113549.1.5.13 */
  { 9, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0D };


#ifdef __RTOS_WIN32__
static const ubyte hmacWithSHA1_OID[] = { 8, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x07};
static const ubyte hmacWithSHA224_OID[] = { 8, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x08};
static const ubyte hmacWithSHA256_OID[] = { 8, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09};
static const ubyte hmacWithSHA384_OID[] = { 8, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0A};
static const ubyte hmacWithSHA512_OID[] = { 8, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0B};

static const ubyte desCBC_OID[] = { 5, 0x2B, 0x0E, 0x03, 0x02, 0x07 }; 
static const ubyte desEDE3CBC_OID[] = { 8, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x03, 0x07};  
#endif


/* --------------------------------------------------------------- */

/* Free the inner mbedtls ctx */
static MSTATUS MPkcs5PbeMbedFreeData (
  MbedPkcs5PbeInfo **ppCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER, fstatus = OK;
  mbedtls_md_context_t *pMbedCtx = NULL;
  mbedtls_asn1_buf *pPBEparams = NULL;
  MPkcs5OperatorData *pOpData = NULL;

  if (NULL == ppCtx)
    goto exit;

  /* Null MbedPkcs5PbeInfo is ok bc of null opdata during ci core init */
  status = OK;
  if (NULL == *ppCtx)
    goto exit;

  pMbedCtx = (*ppCtx)->pMbedCtx;
  pPBEparams = (*ppCtx)->pPBEparams;
  pOpData = (MPkcs5OperatorData *) (*ppCtx)->pOpData;

  /* Free the inner contexts */
  if (NULL != pMbedCtx)
  {
    mbedtls_md_free (pMbedCtx);
    fstatus = DIGI_FREE ((void **) &pMbedCtx);
    if (OK == status)
      status = fstatus;
    (*ppCtx)->pMbedCtx = NULL;
  }

  if (NULL != pPBEparams)
  {
    /* Only free the buffer p if it was allocated for encryption. decrypt does not allocate it! */
    if (MOC_SYM_OP_PKCS5_ENCRYPT == pOpData->operation && pPBEparams->len > 0 && NULL != pPBEparams->p)
    {
      fstatus = DIGI_MEMSET_FREE(&pPBEparams->p, pPBEparams->len);
      if (OK == status)
        status = fstatus;

      pPBEparams->len = 0;
    }

    fstatus = DIGI_FREE((void **) &pPBEparams);
    if (OK == status)
      status = fstatus;
  }

  /* DO NOT free pOpData as it was just a shallow copy */

  /* Free the context itself */
  fstatus = DIGI_FREE ((void **) ppCtx);
  if (OK == status)
    status = fstatus;

exit:

  return status;
}


/* --------------------------------------------------------------- */

MOC_EXTERN MSTATUS MPkcs5PbeMbedCreate (
  MocSymCtx pSymCtx,
  void *pOpInputData
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MbedPkcs5PbeInfo *pPkcs5Info = NULL;
  mbedtls_md_type_t digestId;
  int mbedStatus = 0;
  MPkcs5OperatorData *pOpData = (MPkcs5OperatorData *) pOpInputData;

  /* Allow NULL pOpData for Crypto Interface core initialization */
  if (NULL == pSymCtx)
    goto exit;

  /* Allocate the outer info context using calloc to handle a NULL pDigestFlag */
  status = DIGI_CALLOC (
    (void **) &pPkcs5Info, 1, sizeof(MbedPkcs5PbeInfo));
  if (OK != status)
    goto exit;

  /* Save the op data. Ok to shallow copy since all pkcs5 APIs are one-shot APIs */
  pPkcs5Info->pOpData = pOpInputData;

  if (NULL != pOpData && MOC_SYM_OP_PKCS5_KDF == pOpData->operation)
  {
    /* Allocate inner mbed ctx */
    status = DIGI_MALLOC (
      (void **) &(pPkcs5Info->pMbedCtx), sizeof(mbedtls_md_context_t));
    if (OK != status)
      goto exit;

    /* Convert the Digicert digest flag to an mbedTLS digest flag */
    status = ConvertMocDigestIdToMbedDigestId (pOpData->digestAlg, &digestId);
    if (OK != status)
      goto exit;

    /* mbed func to memset the context */
    mbedtls_md_init (pPkcs5Info->pMbedCtx);

    status = ERR_MBED_PKCS5_PBE_SETUP_FAIL;
    /* mbed func to allocate pPkcs5Info's inner ctx */
    mbedStatus = mbedtls_md_setup (
      pPkcs5Info->pMbedCtx, mbedtls_md_info_from_type (digestId), TRUE);
    if (0 != mbedStatus)
      goto exit;
  }

  pSymCtx->localType = MOC_LOCAL_TYPE_PKCS5_PBE_OPERATOR;
  pSymCtx->SymOperator = SymOperatorPkcs5Pbe;
  pSymCtx->pLocalData = (void *) pPkcs5Info;

  pPkcs5Info = NULL;

  status = OK;

exit:

  if (NULL != pPkcs5Info)
    MPkcs5PbeMbedFreeData (&pPkcs5Info);

  return status;
}


/* --------------------------------------------------------------- */

MOC_EXTERN MSTATUS MPkcs5PbeMbedDeriveKey (
  MocSymCtx pSymCtx,
  MSymOperatorBuffer *pOutput
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MbedPkcs5PbeInfo *pPkcs5Info = NULL;
  ubyte4 digestSize = 0;
  int mbedStatus = 0;
  MPkcs5OperatorData *pOpData = NULL;

  if (NULL == pSymCtx || NULL == pSymCtx->pLocalData ||
      NULL == pOutput || NULL == pOutput->pOutputLen)
    goto exit;

  pPkcs5Info = (MbedPkcs5PbeInfo *) pSymCtx->pLocalData;
  pOpData = (MPkcs5OperatorData *) pPkcs5Info->pOpData;

  /* sanity checks! */
  if (NULL == pOpData)
    goto exit;
   
  status = ERR_INVALID_ARG;
  if (MOC_SYM_OP_PKCS5_KDF != pOpData->operation)
    goto exit;

  digestSize = (ubyte4) mbedtls_md_get_size (pPkcs5Info->pMbedCtx->md_info);

  if (NULL == pOutput->pBuffer || (NULL == pOpData->pPassword && pOpData->passwordLen) ||
                                  (NULL == pOpData->pSalt && pOpData->saltLen))
    goto exit;

  *(pOutput->pOutputLen) = 0;

  status = OK; /* Return OK no-op if no key length is requested */
  if(!pOutput->bufferSize)
    goto exit;

  status = ERR_MBED_FAILURE;
  mbedStatus = mbedtls_pkcs5_pbkdf2_hmac (
    pPkcs5Info->pMbedCtx, pOpData->pPassword, pOpData->passwordLen,
    pOpData->pSalt, pOpData->saltLen, pOpData->iterationCount,
    pOutput->bufferSize, pOutput->pBuffer);
  if (0 != mbedStatus)
    goto exit;

  *(pOutput->pOutputLen) = pOutput->bufferSize;

  status = OK;

exit:

  return status;
}

/* --------------------------------------------------------------- */

#ifndef MOC_MBED_PKCS_MAX_ASN1_BUFFER
#define MOC_MBED_PKCS_MAX_ASN1_BUFFER 1024
#endif

MOC_EXTERN MSTATUS MPkcs5PbeMbedInitEncrypt (
  MocSymCtx pSymCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MbedPkcs5PbeInfo *pPkcs5Info = NULL;
  MPkcs5OperatorData *pOpData = NULL;
  mbedtls_asn1_buf *pPBEparams = NULL;
  ubyte pBuffer[MOC_MBED_PKCS_MAX_ASN1_BUFFER]={0};
  ubyte *pEnd = pBuffer + MOC_MBED_PKCS_MAX_ASN1_BUFFER;
  sbyte4 len = 0;
  sbyte4 subLen = 0;
  sbyte4 tempLen = 0;
  ubyte *pAsn1 = NULL;
  const char *pEncOid = NULL;
  size_t encOidLen = 0;
  const char *pDigestOid = NULL;
  size_t digestOidLen = 0;

  if (NULL == pSymCtx || NULL == pSymCtx->pLocalData)
    goto exit;

  pPkcs5Info = (MbedPkcs5PbeInfo *) pSymCtx->pLocalData;
  pOpData = (MPkcs5OperatorData *) pPkcs5Info->pOpData;

  /* sanity checks! */
  if (NULL == pOpData)
    goto exit;
   
  status = ERR_INVALID_ARG;
  if (MOC_SYM_OP_PKCS5_ENCRYPT != pOpData->operation)
    goto exit;

  switch(pOpData->encAlg)
  {
    case PKCS5_MBED_TDES:
      pEncOid = (const char *) desEDE3CBC_OID + 1;
      encOidLen = (size_t) desEDE3CBC_OID[0];
      break;

    case PKCS5_MBED_DES:
      pEncOid = (const char *) desCBC_OID + 1;
      encOidLen = (size_t) desCBC_OID[0];
      break;
    
    default:
      status = ERR_PKCS5_INVALID_ENC_FUNCTION;
      goto exit;
  }

  switch(pOpData->digestAlg)
  {
    case PKCS5_MBED_SHA1:
      pDigestOid = (const char *) hmacWithSHA1_OID + 1;
      digestOidLen = (size_t) hmacWithSHA1_OID[0];
      break;

    case PKCS5_MBED_SHA224:
      pDigestOid = (const char *) hmacWithSHA224_OID + 1;
      digestOidLen = (size_t) hmacWithSHA224_OID[0];
      break;

    case PKCS5_MBED_SHA256:
      pDigestOid = (const char *) hmacWithSHA256_OID + 1;
      digestOidLen = (size_t) hmacWithSHA256_OID[0];
      break;

    case PKCS5_MBED_SHA384:
      pDigestOid = (const char *) hmacWithSHA384_OID + 1;
      digestOidLen = (size_t) hmacWithSHA384_OID[0];
      break;

    case PKCS5_MBED_SHA512:
      pDigestOid = (const char *) hmacWithSHA512_OID + 1;
      digestOidLen = (size_t) hmacWithSHA512_OID[0];
      break;

    default:
      status = ERR_PKCS5_INVALID_HASH_FUNCTION;
      goto exit;
  }

  /* MBED ASN1 engine starts at the end of the buffer and works backwards
   * We first do the encryption identifier and then the kdf params
   *
   *  PBES2-params ::= SEQUENCE {
   *    keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
   *    encryptionScheme AlgorithmIdentifier {{PBES2-Encs}}
   *  }
   *
   *  PBKDF2-params ::= SEQUENCE {
   *    salt              OCTET STRING,
   *    iterationCount    INTEGER,
   *    keyLength         INTEGER OPTIONAL  (we ignore)
   *    prf               AlgorithmIdentifier DEFAULT algid-hmacWithSHA1
   *  }
   *
   */
  len = mbedtls_asn1_write_octet_string(&pEnd, pBuffer, (const unsigned char *) pOpData->pIv , 8);
  len = mbedtls_asn1_write_algorithm_identifier( &pEnd, pBuffer, pEncOid, encOidLen, len);

  subLen = mbedtls_asn1_write_algorithm_identifier( &pEnd, pBuffer, pDigestOid, digestOidLen, 0);

  /* mbed mbedtls_asn1_write_int is only for ints with absolute value < 128, manually handle bigger */ 
  if (pOpData->iterationCount < 0x80)
  {
    subLen += mbedtls_asn1_write_int(&pEnd, pBuffer, (int) pOpData->iterationCount);
  }
  else if (pOpData->iterationCount < 0x8000) /* we'll only support up to 32K */
  {
    pEnd--;
    *pEnd = (ubyte) (pOpData->iterationCount & 0xff);
    pEnd--;
    *pEnd = (ubyte) ((pOpData->iterationCount >> 8) & 0xff);
    pEnd--;
    *pEnd = 0x02; /* length */
    pEnd--;
    *pEnd = 0x02; /* integer tag */
    subLen += 4;
  }
  else
  { 
    status = ERR_PKCS5_BAD_ITERATION_COUNT;
    goto exit;
  }
 
  tempLen = mbedtls_asn1_write_octet_string(&pEnd, pBuffer, (const unsigned char *) pOpData->pSalt ,(size_t) pOpData->saltLen);
  if (tempLen > 0)
  {
     subLen += tempLen;
  }
  else
  {
    status = ERR_PKCS5_BAD_SALT_LEN;
    goto exit;
  }

  subLen += mbedtls_asn1_write_len( &pEnd, pBuffer, (size_t) subLen );
  subLen += mbedtls_asn1_write_tag( &pEnd, pBuffer, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE );

  subLen = mbedtls_asn1_write_algorithm_identifier( &pEnd, pBuffer, (const char *) pkcs5_PBKDF2_OID + 1, (size_t) pkcs5_PBKDF2_OID[0], subLen);
  
  len += subLen;

  status = DIGI_MALLOC((void** ) &pAsn1, len);
  if (OK != status)
    goto exit;

  status = DIGI_MEMCPY(pAsn1, pEnd, len);
  if (OK != status)
    goto exit;

  status = DIGI_CALLOC((void** ) &pPBEparams, 1, sizeof(mbedtls_asn1_buf));
  if (OK != status)
    goto exit;

  pPBEparams->tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;
  pPBEparams->len = len;
  pPBEparams->p = pAsn1; pAsn1 = NULL;

  pPkcs5Info->pPBEparams = pPBEparams; pPBEparams = NULL;

exit:
  
  if (NULL != pAsn1)
  {
    (void) DIGI_MEMSET_FREE(&pAsn1, len);
  }

  if (NULL != pPBEparams)
  {
    (void) DIGI_FREE((void **) &pPBEparams);
  }

  return status;
}

/* --------------------------------------------------------------- */

MOC_EXTERN MSTATUS MPkcs5PbeMbedInitDecrypt (
  MocSymCtx pSymCtx
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MbedPkcs5PbeInfo *pPkcs5Info = NULL;
  MPkcs5OperatorData *pOpData = NULL;
  mbedtls_asn1_buf *pPBEparams = NULL;
  int mbedStatus = 0;
  ubyte *pStart = NULL;
  ubyte *pEnd = NULL;

  if (NULL == pSymCtx || NULL == pSymCtx->pLocalData)
    goto exit;

  pPkcs5Info = (MbedPkcs5PbeInfo *) pSymCtx->pLocalData;
  pOpData = (MPkcs5OperatorData *) pPkcs5Info->pOpData;

  /* sanity checks! */
  if (NULL == pOpData || NULL == pOpData->pPBEInfo)
    goto exit;
  
  status = ERR_INVALID_ARG;
  if (MOC_SYM_OP_PKCS5_DECRYPT != pOpData->operation)
    goto exit;

  if (!pOpData->pbeLen)
    goto exit;

  pStart = pOpData->pPBEInfo;
  pEnd = pOpData->pPBEInfo + pOpData->pbeLen;

  status = DIGI_CALLOC((void** ) &pPBEparams, 1, sizeof(mbedtls_asn1_buf));
  if (OK != status)
    goto exit;

  /* first byte is the tag */
  pPBEparams->tag = *pStart;
  pStart++;
  
  /* length is next */
  status = ERR_MBED_FAILURE;
  mbedStatus = mbedtls_asn1_get_len (&pStart, pEnd, (size_t *) &pPBEparams->len);
  if (0 != mbedStatus)
    goto exit;

  status = OK;
  pPBEparams->p = pStart;
  pPkcs5Info->pPBEparams = pPBEparams; pPBEparams = NULL;

exit:

  if (NULL != pPBEparams)
  {
    (void) DIGI_FREE((void **) &pPBEparams);
  }
  
  return status;
}

/* --------------------------------------------------------------- */

MOC_EXTERN MSTATUS MPkcs5PbeMbedCipher(
  MocSymCtx pSymCtx, 
  sbyte4 direction, 
  MSymOperatorData *pInput,
  MSymOperatorBuffer *pOutput
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  MbedPkcs5PbeInfo *pPkcs5Info = NULL;
  int mbedStatus = 0;
  MPkcs5OperatorData *pOpData = NULL;

  if (NULL == pSymCtx || NULL == pSymCtx->pLocalData || NULL == pInput || NULL == pInput->pData || 
      NULL == pOutput || NULL == pOutput->pOutputLen)
    goto exit;

  pPkcs5Info = (MbedPkcs5PbeInfo *) pSymCtx->pLocalData;
  pOpData = (MPkcs5OperatorData *) pPkcs5Info->pOpData;

  /* sanity checks */
  if (NULL == pOpData)
    goto exit;
   
  if (NULL == pOpData->pPassword && pOpData->passwordLen)
    goto exit;

  /* This operator is for DES/TDES ONLY so we know padding will be 8 bytes */
  if (MBEDTLS_PKCS5_ENCRYPT == direction)
     *(pOutput->pOutputLen) = pInput->length + 8;
  else
     *(pOutput->pOutputLen) = pInput->length - 8;
  
  status = ERR_BUFFER_TOO_SMALL;
  if (NULL == pOutput->pBuffer || *(pOutput->pOutputLen) > pOutput->bufferSize)
    goto exit;

  /* we don't know the outLen until we remove the padding so no need to check pOutput->bufferSize */
  status = ERR_MBED_FAILURE;
  mbedStatus = mbedtls_pkcs5_pbes2( (const mbedtls_asn1_buf *) pPkcs5Info->pPBEparams, (int) direction, 
                                    (const unsigned char *) pOpData->pPassword, (size_t) pOpData->passwordLen,
                                    (const unsigned char *) pInput->pData, (size_t)  pInput->length, 
                                    (unsigned char *) pOutput->pBuffer);
  if (0 != mbedStatus)
    goto exit;

  status = OK;

exit:

  return status;
}

/* --------------------------------------------------------------- */

MOC_EXTERN MSTATUS MPkcs5PbeMbedFree (
  MocSymCtx pSymCtx
  )
{
  if (NULL == pSymCtx)
    return ERR_NULL_POINTER;

  return MPkcs5PbeMbedFreeData ((MbedPkcs5PbeInfo **) &(pSymCtx->pLocalData));
}


/* --------------------------------------------------------------- */


#endif /* ifdef __ENABLE_DIGICERT_PKCS5_MBED__ */
