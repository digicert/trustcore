/*
 * asn1cert.c
 *
 * ASN.1 Certificate Encoding
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

#include "../common/moptions.h"

#ifndef __DISABLE_DIGICERT_CERTIFICATE_GENERATION__

#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/datetime.h"
#include "../crypto/md5.h"
#include "../crypto/md2.h"
#include "../crypto/md4.h"
#include "../crypto/sha1.h"
#include "../crypto/sha256.h"
#include "../crypto/sha512.h"
#include "../crypto/crypto.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/rsa.h"
#include "../crypto/dsa.h"
#include "../crypto/primefld.h"
#include "../crypto/ecc.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/pubcrypto_data.h"
#include "../harness/harness.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../asn1/parsecert.h"
#include "../asn1/derencoder.h"
#include "../crypto/asn1cert.h"
#include "../crypto/malgo_id.h"

#ifdef __ENABLE_DIGICERT_PKCS1__
#include "../crypto/pkcs1.h"
#endif

#ifdef __ENABLE_DIGICERT_TAP__
#include "../smp/smp_cc.h"
#include "../tap/tap_api.h"
#include "../tap/tap_utils.h"
#include "../tap/tap_smp.h"
#include "../crypto/mocasym.h"
#include "../crypto/mocasymkeys/tap/rsatap.h"
#include "../crypto/mocasymkeys/tap/ecctap.h"
#endif

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
#include "../crypto_interface/cryptointerface.h"
#include "../crypto_interface/crypto_interface_dsa.h"
#include "../crypto_interface/crypto_interface_sha1.h"
#include "../crypto_interface/crypto_interface_sha256.h"
#include "../crypto_interface/crypto_interface_sha512.h"
#if (defined(__ENABLE_DIGICERT_PKCS1__))
#include "../crypto_interface/crypto_interface_pkcs1.h"
#endif
#if (defined(__ENABLE_DIGICERT_PQC__))
#include "../crypto_interface/crypto_interface_qs.h"
#include "../crypto_interface/crypto_interface_qs_sig.h"
#include "../crypto_interface/crypto_interface_qs_composite.h"
#endif
#endif

/*------------------------------------------------------------------*/

static MSTATUS
ASN1CERT_StoreNamePart( DER_ITEMPTR pRoot, const ubyte* oid,
                       const sbyte* namePart, ubyte4 namePartLen, ubyte type)
{
    DER_ITEMPTR pTemp;
    MSTATUS status;

    if ( OK > ( status = DER_AddSet( pRoot, &pTemp)))
        return status;

    if ( OK > ( status = DER_AddSequence( pTemp, &pTemp)))
        return status;

    if ( OK > ( status = DER_AddOID( pTemp, oid, NULL)))
        return status;

    if ( OK > ( status = DER_AddItem( pTemp, type, namePartLen, (ubyte *)namePart, NULL)))
        return status;

    return OK;
}


/*------------------------------------------------------------------*/

MSTATUS
ASN1CERT_StoreDistinguishedName( DER_ITEMPTR pRoot, const certDistinguishedName* pCertInfo)
{
    MSTATUS status;
    relativeDN *pDistinguishedName;
    relativeDN *pRDN;
    ubyte4 i;
    ubyte4 j;
    DER_ITEMPTR pSequence;

    if (NULL == pCertInfo || NULL == pCertInfo->pDistinguishedName)
    {
        return ERR_NULL_POINTER;
    }

    pDistinguishedName = pCertInfo->pDistinguishedName;

    if (OK > (status = DER_AddSequence( pRoot, &pSequence)))
        return status;

    for (i = 0, pRDN = pDistinguishedName; i < pCertInfo->dnCount; i++, pRDN = (pDistinguishedName+i))
    {
        nameAttr *pNameComponent;
        for (j = 0, pNameComponent = pRDN->pNameAttr; j < pRDN->nameAttrCount; j++, pNameComponent = (pRDN->pNameAttr+j))
        {
            if (!pNameComponent || !pNameComponent->value || !pNameComponent->oid)
            {
                return ERR_NULL_POINTER;
            }

            if (EqualOID(pNameComponent->oid, pkcs9_emailAddress_OID)) /* add domainComponent later */
            {
                if (OK > (status = ASN1CERT_StoreNamePart( pSequence, pNameComponent->oid,
                    (sbyte *)pNameComponent->value, pNameComponent->valueLen,
                    IA5STRING)))
                    return status;
            } else
            {
                if (OK > (status = ASN1CERT_StoreNamePart( pSequence, pNameComponent->oid,
                    (sbyte *)pNameComponent->value, pNameComponent->valueLen,
                    (pNameComponent->type == 0? PRINTABLESTRING: pNameComponent->type))))
                    return status;
            }
        }
    }

    return OK;
}


/*------------------------------------------------------------------*/

static MSTATUS
ASN1CERT_AddExtensionsToTBSCertificate(DER_ITEMPTR pCertificate,
                       const certExtensions* pExtensions)
{
    MSTATUS         status;
    DER_ITEMPTR     pTempItem;

    if ( !pExtensions)
        return ERR_NULL_POINTER;

    if ( !pExtensions->hasBasicConstraints && !pExtensions->hasKeyUsage && !pExtensions->otherExts)
        return OK; /* nothing to do */

    /* add the tag for extensions [3] and a sequence */
    if (OK > ( status = DER_AddTag( pCertificate, 3, &pTempItem)))
        goto exit;

    if (OK > ( status = ASN1CERT_AddExtensions(pTempItem, pExtensions, NULL)))
        goto exit;
exit:
    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
ASN1CERT_AddExtensions(DER_ITEMPTR pExtensionTag,
                          const certExtensions* pExtensions, DER_ITEMPTR *ppExtsItem)
{
    MSTATUS status;
    DER_ITEMPTR    pExtsItem, pTempItem;
    ubyte           copyData[MAX_DER_STORAGE];

    if ( !pExtensions)
        return ERR_NULL_POINTER;

    if ( !pExtensions->hasBasicConstraints && !pExtensions->hasKeyUsage && !pExtensions->otherExts)
        return OK; /* nothing to do */

    if (OK > ( status = DER_AddSequence( pExtensionTag, &pExtsItem)))
        goto exit;

    if (ppExtsItem)
    {
        *ppExtsItem = pExtsItem;
    }

    /* add basicConstraints if there */
    if (pExtensions->hasBasicConstraints)
    {
        if (OK > ( status = DER_AddSequence( pExtsItem, &pTempItem)))
            goto exit;

        if (OK > (status = DER_AddOID( pTempItem, basicConstraints_OID, NULL)))
            goto exit;

        /*
         * Section 4.2.1.10  Basic Constraints: This extension MUST appear as
         * a critical extension in all CA certificates.
         */
        if (pExtensions->isCA)
        {
            copyData[0] = 0xFF;
            if (OK > ( status = DER_AddItemCopyData( pTempItem, BOOLEAN, 1, copyData, NULL)))
                goto exit;
        }

        if (OK > (status = DER_AddItem( pTempItem, OCTETSTRING, 0, NULL, &pTempItem)))
            goto exit;

        if (OK > ( status = DER_AddSequence( pTempItem, &pTempItem)))
            goto exit;

        copyData[0] = pExtensions->isCA ? 0xFF : 0x00;
        if (OK > ( status = DER_AddItemCopyData( pTempItem, BOOLEAN, 1, copyData, NULL)))
            goto exit;

        /* add OPTIONAL certPathLen if positive */
        if ( pExtensions->certPathLen >= 0)
        {
            copyData[0] = pExtensions->certPathLen;
            if (OK > ( status = DER_AddItemCopyData(pTempItem, INTEGER, 1, copyData, NULL)))
                goto exit;
        }
    }

    /* add key usage if there */
    if (pExtensions->hasKeyUsage)
    {
        if (OK > ( status = DER_AddSequence( pExtsItem, &pTempItem)))
            goto exit;

        if (OK > (status = DER_AddOID( pTempItem, keyUsage_OID, NULL)))
            goto exit;

        /*
         * Section 4.2.1.3 Key Usage: When used, this extension SHOULD be marked critical.
         */
        copyData[0] = 0xFF;
        if (OK > ( status = DER_AddItemCopyData( pTempItem, BOOLEAN, 1, copyData, NULL)))
            goto exit;

        if (OK > (status = DER_AddItem( pTempItem, OCTETSTRING, 0, NULL, &pTempItem)))
            goto exit;

        /* but the data in little endian order: least significant bit is always first  */
        copyData[1] = (ubyte) (pExtensions->keyUsage >> 8);
        copyData[0] = (ubyte) (pExtensions->keyUsage);
        if ( OK > ( status = DER_AddBitString( pTempItem, 2, copyData, NULL)))
            goto exit;
    }

    if (pExtensions->otherExts)
    {
        ubyte4 i;
        extensions *pExt;
        for (i = 0, pExt = pExtensions->otherExts; i < pExtensions->otherExtCount; i++, pExt = pExtensions->otherExts + i)
        {
            status = ERR_NULL_POINTER;
            if ( (NULL == pExt) || (NULL == pExt->oid) || (NULL == pExt->value))
                goto exit;

            /* add a single extension */
            if ( OK > (status = DER_AddSequence( pExtsItem, &pTempItem)))
                goto exit;
            /* extnID */
            if (OK > (status = DER_AddOID(pTempItem, pExt->oid, NULL)))
                goto exit;
            /* if crital == TRUE, add critical */
            if (pExt->isCritical)
            {
                copyData[0] = 0xFF;
                if (OK > ( status = DER_AddItemCopyData( pTempItem, BOOLEAN, 1, copyData, NULL)))
                    goto exit;
            }
            /* extnValue */
            if (OK > (status = DER_AddItem(pTempItem, OCTETSTRING, pExt->valueLen, pExt->value, NULL)))
                goto exit;
        }
    }
exit:

    return status;
}

/*---------------------------------------------------------------------------*/
#if (defined(__ENABLE_DIGICERT_ASYM_KEY__))
static MSTATUS
ASN1CERT_mocAsymSign (
  MOC_RSA(hwAccelDescr hwAccelCtx)
  DER_ITEMPTR pSignedHead,
  MocAsymKey pSignKey,
  ubyte signAlgo,
  RNGFun rngFun,
  void *rngFunArg,
  ubyte **ppRetDEREncoding,
  ubyte4 *pRetDEREncodingLen
  )
{
  MSTATUS status;
  ubyte4 algIdLen, dataToSignLen, digestLen, signatureLen;
  ubyte *pAlgId = NULL;
  ubyte *pDataToSign = NULL;
  ubyte *pSignature = NULL;
  ubyte *pItem = NULL;
  DER_ITEMPTR pTemp = NULL;
  MKeyOperatorAlgIdReturn algIdReturn;
  MKeyOperatorDataReturn dataReturn;
  MKeyOperatorSignInfo signInfo;
  ubyte pDigest[CERT_MAXDIGESTSIZE];

  digestLen = 0;
  dataToSignLen = 0;

  status = ERR_NULL_POINTER;
  if ( (NULL == pSignedHead) || (NULL == pSignKey) ||
       (NULL == ppRetDEREncoding) || (NULL == pRetDEREncodingLen) )
    goto exit;

  if (NULL == pSignKey->KeyOperator)
    goto exit;

  /* Whoever called this has started building something that is going to be
   *   SEQUENCE {
   *     dataToSign   Something,
   *     signAlgId    AlgId,
   *     signature    BIT STRING }
   * The caller has started the ASN.1 tree and filled in the dataToSign. We need
   * to get the algorithm ID from the pSignKey, add it to the tree, then digest
   * the encoding of dataToSign, using the digest algorithm specified by
   * signAlgo, then call the MocAsymKey's Operator with MOC_ASYM_OP_SIGN_DIGEST_INFO. Next, we make
   * the BIT STRING with the resulting signature and add it to the tree. Finally,
   * we build the encoding of the entire tree.
   */

  /* Get the algorithm ID.
   */
  algIdReturn.function = MOC_ASYM_KEY_FUNCTION_SIGN;
  algIdReturn.digestAlgorithm = (ubyte4)signAlgo;
  dataReturn.ppData = &pAlgId;
  dataReturn.pLength = &algIdLen;
  status = pSignKey->KeyOperator (
    pSignKey, NULL, MOC_ASYM_OP_GET_ALG_ID, (void *)&algIdReturn,
    (void *)&dataReturn, NULL);
  if (OK != status)
    goto exit;

  /* Encode ths data to sign.
   */
  status = ERR_DER_ENCODER;
  pTemp = DER_FIRST_CHILD (pSignedHead);
  if (NULL == pTemp)
    goto exit;

  status = DER_Serialize (pTemp, &pDataToSign, &dataToSignLen);
  if (OK != status)
    goto exit;

  /* Digest the data.
   */
  switch (signAlgo)
  {
    default:
      status = ERR_CERT_AUTH_BAD_SIGN_ALGO;
      goto exit;

    case ht_md5:
      status = MD5_completeDigest (
        MOC_HASH (hwAccelCtx) pDataToSign, dataToSignLen, pDigest);
      if (OK != status)
        goto exit;

      digestLen = MD5_RESULT_SIZE;
      break;

    case ht_sha1:
      status = SHA1_completeDigest (
        MOC_HASH (hwAccelCtx) pDataToSign, dataToSignLen, pDigest);
      if (OK != status)
        goto exit;

      digestLen = SHA1_RESULT_SIZE;
      break;

#ifndef __DISABLE_DIGICERT_SHA224__
    case ht_sha224:
      status = SHA224_completeDigest (
        MOC_HASH (hwAccelCtx) pDataToSign, dataToSignLen, pDigest);
      if (OK != status)
        goto exit;

      digestLen = SHA224_RESULT_SIZE;
      break;
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
    case ht_sha256:
      status = SHA256_completeDigest (
        MOC_HASH (hwAccelCtx) pDataToSign, dataToSignLen, pDigest);
      if (OK != status)
        goto exit;

      digestLen = SHA256_RESULT_SIZE;
      break;
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
    case ht_sha384:
      status = SHA384_completeDigest (
        MOC_HASH (hwAccelCtx) pDataToSign, dataToSignLen, pDigest);
      if (OK != status)
        goto exit;

      digestLen = SHA384_RESULT_SIZE;
      break;
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
    case ht_sha512:
      status = SHA512_completeDigest (
        MOC_HASH (hwAccelCtx) pDataToSign, dataToSignLen, pDigest);
      if (OK != status)
        goto exit;

      digestLen = SHA512_RESULT_SIZE;
#endif
  }

  /* Now sign that data.
   */
  signInfo.pDigest = pDigest;
  signInfo.digestLen = digestLen;
  signInfo.digestAlgorithm = signAlgo;
  signInfo.rngFun = rngFun;
  signInfo.rngFunArg = rngFunArg;
  dataReturn.ppData = &pSignature;
  dataReturn.pLength = &signatureLen;
  status = pSignKey->KeyOperator (
    pSignKey, NULL, MOC_ASYM_OP_SIGN_DIGEST_INFO, (void *)&signInfo, (void *)&dataReturn, NULL);
  if (OK != status)
    goto exit;

  /* Now add the alg ID and signature to the pSignedHead.
   */
  status = DER_AddDERBuffer (
    pSignedHead, algIdLen, pAlgId, NULL);
  if (OK != status)
    goto exit;

  /* We need to add a BIT STRING, but we need to guarantee that the unused bits
   * is 0, no matter what. If we call DER_AddBitString, it will reverse the bits.
   * If we call DER_AddItem with BITSTRING, it won't put the unusedBits into the
   * encoding.
   * So we need to make a new buffer with 00 prepended to the signature, then
   * call AddItem.
   */
  status = DIGI_MALLOC ((void **)&pItem, signatureLen + 1);
  if (OK != status)
    goto exit;

  status = DIGI_MEMCPY (
    (void *)(pItem + 1), (void *)pSignature, signatureLen);
  if (OK != status)
    goto exit;

  pItem[0] = 0;
  status = DER_AddItem (
    pSignedHead, BITSTRING, signatureLen + 1, pItem, NULL);
  if (OK != status)
    goto exit;

  /* Now DER encode.
   */
  status = DER_Serialize (pSignedHead, ppRetDEREncoding, pRetDEREncodingLen);

exit:

  DIGI_MEMSET ((void *)pDigest, 0, CERT_MAXDIGESTSIZE);

  if (NULL != pItem)
  {
    DIGI_FREE ((void **)&pItem);
  }
  if (NULL != pSignature)
  {
    DIGI_FREE ((void **)&pSignature);
  }
  if (NULL != pDataToSign)
  {
    DIGI_MEMSET ((void *)pDataToSign, 0, dataToSignLen);
    DIGI_FREE ((void **)&pDataToSign);
  }
  if (NULL != pAlgId)
  {
    DIGI_FREE ((void **)&pAlgId);
  }

  return (status);
}
#endif /* __ENABLE_DIGICERT_ASYM_KEY__ */

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PKCS1__
static MSTATUS ASN1CERT_rsaPssSign(MOC_RSA(hwAccelDescr hwAccelCtx) RSAKey *pRSAKey, DER_ITEMPTR pToSign, DER_ITEMPTR pSignature, 
                                   void* pRandomContext, MAlgoId *pAlgoId)
{
    MSTATUS status = OK;
    ubyte *pData = NULL;
    ubyte4 dataLen = 0;
    ubyte *pSig = NULL;
    ubyte4 sigLen = 0;
    ubyte *pSerializedBitStr = NULL;
    RsaSsaPssAlgIdParams *pPssParams = (RsaSsaPssAlgIdParams *) pAlgoId->pParams;

    /* manually check the trailerfield. Other params will be checked by the rsaPssSign API */
    if (0xBC != pPssParams->trailerField)
    {
        status = ERR_RSA_INVALID_PSS_PARAMETERS;
        goto exit;
    }

    if (OK > ( status = DER_GetASNBufferInfo( pToSign, &pData, &dataLen)))
        goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK > ( status = CRYPTO_INTERFACE_PKCS1_rsaPssSign ( MOC_RSA(hwAccelCtx) pRandomContext, pRSAKey, pPssParams->digestId, pPssParams->mgfAlgo, 
                                                            pPssParams->mgfDigestId, pData, dataLen, pPssParams->saltLen, &pSig, &sigLen)))
        goto exit;
#else
    if (OK > ( status = PKCS1_rsaPssSign( MOC_RSA(hwAccelCtx) pRandomContext, pRSAKey, pPssParams->digestId, pPssParams->mgfAlgo, 
                                           pPssParams->mgfDigestId, pData, dataLen, pPssParams->saltLen, &pSig, &sigLen)))
        goto exit;
#endif

    /* copy the signature directly into the BITSTRING data */
    if ( OK > ( status = DER_GetSerializedDataPtr( pSignature, &pSerializedBitStr)))
        goto exit;

    if ( OK > ( status = DIGI_MEMCPY(pSerializedBitStr + 1, pSig, sigLen)))
        goto exit;
    
      /* then make sure unused bits is set to 0 */
    *pSerializedBitStr = 0x00;

exit:

    /* pData and pSerializedBitStr aren't allocated */
    if (NULL != pSig)
    {
        (void) DIGI_MEMSET_FREE(&pSig, sigLen);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_PKCS1__ */

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
/**
@cond
@brief      This function generates RSA signature.

@details    This function generates generates the hash of the input
            and does the RSA signature. This API also supports TAP key
            for RSA Sign. Based on the key type it calls appropriate
            RSA Sign API.

@param pRSAKey     Pointer to SW or TAP RSAKey.
@param keyType     Type of key. whether it is TAP Key or SW key.
@param pToSign     Pointer to the data to be signed.
@param pSignature  Pointer to the DER_ITEM where the signature to be added.
@param signAlgo    signAlgorithm to be used for Hashing.

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@endcond
*/
static MSTATUS
ASN1CERT_rsaSignAux( MOC_RSA(hwAccelDescr hwAccelCtx) void *pRSAKey,
                DER_ITEMPTR pToSign, DER_ITEMPTR pSignature, ubyte signAlgo, ubyte4 keyType)
#else
static MSTATUS
ASN1CERT_rsaSignAux( MOC_RSA(hwAccelDescr hwAccelCtx) RSAKey *pRSAKey,
                DER_ITEMPTR pToSign, DER_ITEMPTR pSignature, ubyte signAlgo)
#endif
{
    ubyte*          pHash = NULL;
    ubyte*          pTempBuf = NULL;
    ubyte*          pData;
    ubyte4          dataLen;
    ubyte4          digestSize = 0;
    DER_ITEMPTR     pSequence = 0;
    ubyte*          pBuffer = 0;
    ubyte*          serializedBitStr;
    const ubyte*    hashAlgoOID = 0;
    MSTATUS         status = OK;
#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_TAP__)
    ubyte4          tempDataLen = 0;
#endif

    if (OK > ( status = DER_GetASNBufferInfo( pToSign, &pData, &dataLen)))
       goto exit;

#if defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__) && defined(__ENABLE_DIGICERT_TAP__)
    tempDataLen = dataLen;
#endif

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, CERT_MAXDIGESTSIZE, TRUE, &pHash)))
        goto exit;

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, dataLen, TRUE, &pTempBuf)))
        goto exit;

    DIGI_MEMCPY(pTempBuf, pData, dataLen);

    switch ( signAlgo )
    {
        case ht_md5:
            digestSize = MD5_RESULT_SIZE;
            hashAlgoOID = md5_OID;
            status = MD5_completeDigest(MOC_HASH(hwAccelCtx) pTempBuf, dataLen, pHash);
            break;

        case sha1_with_no_sig:
        case ht_sha1:
            digestSize = SHA1_RESULT_SIZE;
            hashAlgoOID = sha1_OID;
            status = SHA1_completeDigest(MOC_HASH(hwAccelCtx) pTempBuf, dataLen, pHash);
            break;

#ifndef __DISABLE_DIGICERT_SHA224__
        case ht_sha224:
            digestSize = SHA224_RESULT_SIZE;
            hashAlgoOID = sha224_OID;
            status = SHA224_completeDigest(MOC_HASH(hwAccelCtx) pTempBuf, dataLen, pHash);
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
        case ht_sha256:
            digestSize = SHA256_RESULT_SIZE;
            hashAlgoOID = sha256_OID;
            status = SHA256_completeDigest(MOC_HASH(hwAccelCtx) pTempBuf, dataLen, pHash);
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
        case ht_sha384:
            digestSize = SHA384_RESULT_SIZE;
            hashAlgoOID = sha384_OID;
            status = SHA384_completeDigest(MOC_HASH(hwAccelCtx) pTempBuf, dataLen, pHash);
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
        case ht_sha512:
            digestSize = SHA512_RESULT_SIZE;
            hashAlgoOID = sha512_OID;
            status = SHA512_completeDigest(MOC_HASH(hwAccelCtx) pTempBuf, dataLen, pHash);
            break;
#endif

        default:
            status = ERR_CERT_AUTH_BAD_SIGN_ALGO;
            goto exit;
    }

    CRYPTO_FREE(hwAccelCtx, TRUE, &pTempBuf);
    pTempBuf = NULL;
    if (OK > status) goto exit;

    /* now construct a new ASN.1 DER encoding with this */
    if ( OK > (status = DER_AddSequence( NULL, &pSequence)))
        goto exit;

    if ( OK > ( status = DER_StoreAlgoOID( pSequence, hashAlgoOID, TRUE)))
       goto exit;

    if ( OK > ( status = DER_AddItem( pSequence, OCTETSTRING, digestSize, pHash, NULL)))
       goto exit;

    if ( OK > ( status = DER_Serialize( pSequence, &pBuffer, &dataLen)))
        goto exit;

    /* put the signature directly into the BITSTRING data */
    if ( OK > ( status = DER_GetSerializedDataPtr( pSignature, &serializedBitStr)))
        goto exit;

    if (sha1_with_no_sig == signAlgo)
    {
      status = DIGI_MEMCPY (
        serializedBitStr + 1, pHash, digestSize);
      if (OK != status)
        goto exit;
    }
    else
    {
#if (!defined(__DISABLE_DIGICERT_RSA__) && !defined(__DISABLE_DIGICERT_RSA_SIGN__))
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
        ubyte keyUsage = 0;
        if (OK != (status = CRYPTO_INTERFACE_getKeyUsage(pRSAKey, keyType, &keyUsage)))
        {
            goto exit;
        }
#if defined(__ENABLE_DIGICERT_TAP__)
        if (TAP_KEY_USAGE_ATTESTATION == keyUsage)
        {
            if (OK > (status = CRYPTO_INTERFACE_RSA_signMessageEx(MOC_RSA(hwAccelCtx) pRSAKey, pData, tempDataLen,
                            serializedBitStr + 1, NULL, keyType)))
                goto exit;
        }
        else
#endif
        {
            if (OK > (status = CRYPTO_INTERFACE_RSA_signMessage(MOC_RSA(hwAccelCtx) pRSAKey, pBuffer, dataLen,
                            serializedBitStr + 1, NULL, keyType)))
                goto exit;
        }
#else
      if ( OK > ( status = RSA_signMessage(MOC_RSA(hwAccelCtx) pRSAKey, pBuffer, dataLen,
        serializedBitStr + 1, NULL)))
        goto exit;
#endif
#else
      status = ERR_RSA_DISABLED;
      goto exit;
#endif
    }
    /* then make sure unused bits is set to 0 */
    *serializedBitStr = 0x00;

exit:
    if (pHash)
    {
        CRYPTO_FREE(hwAccelCtx, TRUE, &pHash);
    }
    if (pTempBuf)
    {
        CRYPTO_FREE(hwAccelCtx, TRUE, &pTempBuf);
    }
    if ( pSequence)
    {
        TREE_DeleteTreeItem( (TreeItem*) pSequence);
    }

    if ( pBuffer)
    {
        FREE( pBuffer);
    }

    return status;
}

#if (defined(__ENABLE_DIGICERT_DSA__))
static MSTATUS
ASN1CERT_dsaSignAux(MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey* pSignKey,
                    DER_ITEMPTR pToSign, ubyte signAlgo,
                    RNGFun rngFun, void* rngFunArg,
                    ubyte* pR, ubyte* pS)
{
    ubyte*          pHash = NULL;
    ubyte*          pTempBuf = NULL;
    ubyte*          pData;
    ubyte4          dataLen;
    ubyte4          digestSize = 0;
    MSTATUS         status = OK;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    ubyte *pRtemp = NULL;
    ubyte4 rLen = 0;
    ubyte *pStemp = NULL;
    ubyte4 sLen = 0;
#else
    vlong*          pVlongQueue = NULL;
    vlong*        vR = NULL;
    vlong*        vS = NULL;
    vlong*        pM = NULL;
#endif
    MOC_UNUSED(rngFun);
    MOC_UNUSED(rngFunArg);

    if (OK > ( status = DER_GetASNBufferInfo( pToSign, &pData, &dataLen)))
        goto exit;

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, CERT_MAXDIGESTSIZE, TRUE, &pHash)))
        goto exit;

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, dataLen, TRUE, &pTempBuf)))
        goto exit;

    DIGI_MEMCPY(pTempBuf, pData, dataLen);
    switch ( signAlgo )
    {
      case ht_sha1:
        digestSize = SHA1_RESULT_SIZE;
        status = SHA1_completeDigest(MOC_HASH(hwAccelCtx) pTempBuf, dataLen, pHash);
        break;
#ifndef __DISABLE_DIGICERT_SHA256__
      case ht_sha256:
        digestSize = SHA256_RESULT_SIZE;
        status = SHA256_completeDigest(MOC_HASH(hwAccelCtx) pTempBuf, dataLen, pHash);
        break;
#endif
      default:
        status = ERR_CERT_AUTH_BAD_SIGN_ALGO;
        goto exit;
    }

    CRYPTO_FREE(hwAccelCtx, TRUE, &pTempBuf);
    pTempBuf = NULL;
    if (OK > status) goto exit;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (OK > (status = CRYPTO_INTERFACE_DSA_computeSignatureAux(MOC_DSA(hwAccelCtx) g_pRandomContext, pSignKey, pHash, digestSize, NULL, &pRtemp, &rLen, &pStemp, &sLen, NULL)))
        goto exit;

    /* sanity check, we should have rLen = SLen = qLen = digestSize */
    status = ERR_INTERNAL_ERROR;
    if (rLen != digestSize || sLen != digestSize)
        goto exit;

    if (OK > (status = DIGI_MEMCPY(pR, pRtemp, rLen)))
        goto exit;

    if (OK > (status = DIGI_MEMCPY(pS, pStemp, sLen)))
        goto exit;
#else

    if (OK > (status = VLONG_vlongFromByteString(pHash, digestSize, &pM, &pVlongQueue)))
        goto exit;

    if (OK > (status = DSA_computeSignature(MOC_DSA(hwAccelCtx) g_pRandomContext, pSignKey, pM, NULL, &vR, &vS,
          &pVlongQueue)))
        goto exit;
    if (OK > (status = VLONG_fixedByteStringFromVlong(vR, pR, digestSize)))
        goto exit;
    if (OK > (status = VLONG_fixedByteStringFromVlong(vS, pS, digestSize)))
        goto exit;
#endif

exit:
    if (pHash)
    {
        CRYPTO_FREE(hwAccelCtx, TRUE, &pHash);
    }
    if (pTempBuf)
    {
        CRYPTO_FREE(hwAccelCtx, TRUE, &pTempBuf);
    }
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (NULL != pRtemp)
    {
        (void) DIGI_MEMSET_FREE(&pRtemp, rLen);
    }
    if (NULL != pStemp)
    {
        (void) DIGI_MEMSET_FREE(&pStemp, sLen);
    }
#else
    VLONG_freeVlong(&pM, &pVlongQueue);
    VLONG_freeVlong(&vR, &pVlongQueue);
    VLONG_freeVlong(&vS, &pVlongQueue);
    VLONG_freeVlongQueue( &pVlongQueue);
#endif
    return status;
}

static MSTATUS
ASN1CERT_dsaSign (
  MOC_DSA(hwAccelDescr hwAccelCtx) DER_ITEMPTR pSignedHead,
  DSAKey* pDSAKey, ubyte signAlgo, RNGFun rngFun, void* rngFunArg,
  ubyte **ppRetDEREncoding, ubyte4 *pRetDEREncodingLen)
{
    /* this function is more complicated so that we do one and only
    one memory allocation to save memory and to avoid fragmentation */

    MSTATUS   status = OK;
    ubyte*   pRetDEREncoding = 0;
    ubyte4   retDEREncodingLen;
    sbyte4   elementLen = 0;
    ubyte   signAlgoOID[4+MAX_SIG_OID_LEN];
    ubyte       copyData[MAX_DER_STORAGE];
    ubyte*      pSignatureBuffer = 0;
    ubyte*      pRBuffer;
    ubyte*      pSBuffer;
    DER_ITEMPTR  pTemp, pR, pS;
    ubyte4          offset;

    if ((0 == pSignedHead) || (0 == pDSAKey) ||
        (0 == ppRetDEREncoding) || ( 0 == pRetDEREncodingLen))
    {
        return ERR_NULL_POINTER;
    }

    if (OK > ( status = CRYPTO_getDSAHashAlgoOID( signAlgo, signAlgoOID)))
        goto exit;

    /* signature algo */
    if ( OK > (status = DER_StoreAlgoOID( pSignedHead, signAlgoOID, FALSE)))
        goto exit;

    copyData[0] = 0; /* unused bits */
    if (OK > ( status = DER_AddItemCopyData( pSignedHead, BITSTRING, 1, copyData, &pTemp)))
        goto exit;

    switch ( signAlgo )
    {
      case ht_sha1:
        elementLen = SHA1_RESULT_SIZE;
        break;
#ifndef __DISABLE_DIGICERT_SHA256__
      case ht_sha256:
        elementLen = SHA256_RESULT_SIZE;
        break;
#endif
      default:
        status = ERR_CERT_AUTH_BAD_SIGN_ALGO;
        goto exit;
    }

    /* allocate 2 extra bytes for the possible zero padding */
    pSignatureBuffer = (ubyte*) MALLOC( 2 + 2 * elementLen);
    if (! pSignatureBuffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    pRBuffer = pSignatureBuffer;
    *pRBuffer = 0x00; /* leading 0 */
    pSBuffer = pSignatureBuffer + 1 + elementLen;
    *pSBuffer = 0x00; /* leading 0 */

    if (OK > ( status = DER_AddSequence( pTemp, &pTemp)))
        goto exit;
    /* add the two integers --use maximum size i.e. assume leading zero */
    if (OK > ( status = DER_AddItem( pTemp, INTEGER, 1 + elementLen, pRBuffer, &pR)))
        goto exit;

    if (OK > ( status = DER_AddItem( pTemp, INTEGER, 1 + elementLen, pSBuffer, &pS)))
        goto exit;

    /* write the whole thing */
    if ( OK > ( status = DER_Serialize( pSignedHead, &pRetDEREncoding, &retDEREncodingLen)))
        goto exit;

    /* now generate the signature in the buffers after the leading zero */
    if ( OK > ( status = ASN1CERT_dsaSignAux( MOC_DSA(hwAccelCtx) pDSAKey,
                                                DER_FIRST_CHILD(pSignedHead),
                                                signAlgo, rngFun, rngFunArg,
                                                pRBuffer + 1, pSBuffer + 1)))
    {
        goto exit;
    }

    /* format the buffers for proper INTEGER DER encoding */
    if ( OK > ( status = DER_GetIntegerEncodingOffset( 1 + elementLen, pRBuffer, &offset)))
        goto exit;
    if (OK > (status = DER_SetItemData( pR, elementLen + 1 - offset, pRBuffer + offset)))
        goto exit;

    if ( OK > ( status = DER_GetIntegerEncodingOffset( 1 + elementLen, pSBuffer, &offset)))
        goto exit;
    if (OK > (status = DER_SetItemData( pS, elementLen + 1 - offset, pSBuffer + offset)))
        goto exit;

    /* in every case, we need to rewrite the certificate in the allocated buffer */
    if (OK > ( status = DER_SerializeInto( pSignedHead, pRetDEREncoding, &retDEREncodingLen)))
        goto exit;

    *pRetDEREncodingLen = retDEREncodingLen;
    *ppRetDEREncoding = pRetDEREncoding;
    pRetDEREncoding = NULL;

exit:
    if (pSignatureBuffer) {
  FREE (pSignatureBuffer);
    }
    if ( pRetDEREncoding)
    {
        FREE (pRetDEREncoding);
    }
    return status;
}
#endif

/*------------------------------------------------------------------*/
#ifndef __DISABLE_DIGICERT_RSA__
/**
@cond
@brief      This function initiates generating RSA signature.

@details    This function helps in generating RSA Signature.

@param pSignedHead         Pointer to DERITEM where signature to be added.
@param pRSAKey             Pointer to SW or TAP RSAKey.
@param signAlgo            signAlgorithm to be used for Hashing.
@param keyType             Type of key. whether it is TAP Key or SW key.
@param ppRetDEREncoding    On return, Pointer to the serialized data.
@param pRetDEREncodingLen  On return, Pointer to the length of the serialized data.

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@endcond
*/
static MSTATUS
ASN1CERT_rsaSign(MOC_RSA(hwAccelDescr hwAccelCtx) DER_ITEMPTR pSignedHead,
                 void* pRSAKey, ubyte signAlgo, ubyte **ppRetDEREncoding,
                 ubyte4 *pRetDEREncodingLen, ubyte4 keyType, void *pRandomContext, MAlgoId *pAlgoId)
{
    /* this function is more complicated so that we do one and only
    one memory allocation to save memory and to avoid fragmentation */

    MSTATUS status = OK;
    ubyte* pRetDEREncoding = 0;
    ubyte4 retDEREncodingLen;
    sbyte4 signatureLen;
    DER_ITEMPTR pBitString;
    ubyte signAlgoOID[2+MAX_SIG_OID_LEN];

#ifdef __ENABLE_DIGICERT_PKCS1__
    ubyte *pPssBuff = NULL;
    ubyte4 pssBuffLen = 0;
#endif

    if ((0 == pSignedHead) || (0 == pRSAKey) ||
        (0 == ppRetDEREncoding) || ( 0 == pRetDEREncodingLen))
    {
        return ERR_NULL_POINTER;
    }

#ifdef __ENABLE_DIGICERT_PKCS1__
    if ( (NULL != pAlgoId) && (ALG_ID_RSA_SSA_PSS_OID == pAlgoId->oidFlag) )
    {       
        status = ALG_ID_serializeAlloc(pAlgoId, &pPssBuff, &pssBuffLen);
        if (OK != status)
            goto exit;

        status = DER_AddDERBufferOwn( pSignedHead, pssBuffLen, (const ubyte **) &pPssBuff, NULL );
        if (OK != status)
            goto exit;
    }
    else
#endif
    {
        if (OK > ( status = CRYPTO_getRSAHashAlgoOID( signAlgo, signAlgoOID)))
            goto exit;

        /* signature algo */
        if ( OK > (status = DER_StoreAlgoOID( pSignedHead, signAlgoOID, TRUE)))
            goto exit;
    }


    /* signature (place holder for the moment)
     */
    /* If this is no sig, get the digest length.
     */
    signatureLen = 20;
    if (sha1_with_no_sig != signAlgo)
    {
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
        if (OK != (status = CRYPTO_INTERFACE_getRSACipherTextLength(MOC_RSA(hwAccelCtx) pRSAKey, &signatureLen, keyType)))
        {
            goto exit;
        }
#else
      if ( OK > ( status = RSA_getCipherTextLength(MOC_RSA(hwAccelCtx) pRSAKey, &signatureLen)))
        goto exit;
#endif
    }

    if ( OK > ( status = DER_AddItem( pSignedHead, BITSTRING, signatureLen + 1, /* +1 unused bits octets */
                                        NULL, &pBitString)))
        goto exit;

    /* write the whole thing */
    if ( OK > ( status = DER_Serialize( pSignedHead, &pRetDEREncoding, &retDEREncodingLen)))
        goto exit;

    /* now generate the signature */
#ifdef __ENABLE_DIGICERT_PKCS1__
    if ( NULL != pAlgoId && ALG_ID_RSA_SSA_PSS_OID == pAlgoId->oidFlag )
    {
        if ( OK > ( status = ASN1CERT_rsaPssSign( MOC_RSA(hwAccelCtx) pRSAKey, DER_FIRST_CHILD(pSignedHead),
                                                  pBitString, pRandomContext, pAlgoId)))
            goto exit;
    }
    else
#endif
    {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__ 
        if ( OK > ( status = ASN1CERT_rsaSignAux( MOC_RSA(hwAccelCtx) pRSAKey, DER_FIRST_CHILD(pSignedHead),
                                                pBitString, signAlgo, keyType)))
            goto exit;
#else
        if ( OK > ( status = ASN1CERT_rsaSignAux( MOC_RSA(hwAccelCtx) pRSAKey, DER_FIRST_CHILD(pSignedHead),
                                                pBitString, signAlgo)))
            goto exit;
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
    }

    *pRetDEREncodingLen = retDEREncodingLen;
    *ppRetDEREncoding = pRetDEREncoding;
    pRetDEREncoding = NULL;

exit:

#ifdef __ENABLE_DIGICERT_PKCS1__
    if (NULL != pPssBuff)
    {
        (void) DIGI_MEMSET_FREE(&pPssBuff, pssBuffLen);
    }
#endif

    if ( pRetDEREncoding)
    {
        FREE (pRetDEREncoding);
    }
    return status;
}
#endif

#if defined(__ENABLE_DIGICERT_DSA__)
static MSTATUS
DSA_DER_StoreAlgoOID(MOC_DSA(hwAccelDescr hwAccelCtx) DER_ITEMPTR pRoot, const ubyte* oid, DSAKey* pDSAKey)
{
    DER_ITEMPTR     pSequence, pPQGSequence;
    DER_ITEMPTR     pBitstr;
    MSTATUS         status;
    ubyte4          tmpLen;
    ubyte          *pTmp = NULL;
    MDsaKeyTemplate keyData = {0};
    ubyte           copyData[MAX_DER_STORAGE];

    if ( OK > ( status = DER_AddSequence( pRoot, &pSequence)))
        return status;
    if ( OK > ( status = DER_AddOID( pSequence, oid, NULL)))
        return status;
    /* TODO: Add p, q, and g as integers */
    if ( OK > ( status = DER_AddSequence(pSequence, &pPQGSequence)))
        return status;

    /* Get the public key data */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    status = CRYPTO_INTERFACE_DSA_getKeyParametersAlloc(MOC_DSA(hwAccelCtx) pDSAKey, &keyData, MOC_GET_PUBLIC_KEY_DATA);
#else
    status = DSA_getKeyParametersAlloc(MOC_DSA(hwAccelCtx) pDSAKey, &keyData, MOC_GET_PUBLIC_KEY_DATA);
#endif
    if (OK != status)
        goto exit;

    if ( (0 == keyData.pLen) || (0 == keyData.qLen) || (0 == keyData.gLen) )
    {
        status = ERR_BAD_KEY;
        goto exit;
    }

    status = DIGI_MALLOC((void **)&pTmp, keyData.pLen + 1);
    if (OK != status)
        goto exit;

    pTmp[0] = 0;

    status = DIGI_MEMCPY(pTmp + 1, keyData.pP, keyData.pLen);
    if (OK != status)
        goto exit;

    /* add the modulus with the leading zero -- DER_AddInteger will do the right thing */
    if (OK > ( status = DER_AddIntegerCopyData( pPQGSequence, keyData.pLen + 1, pTmp, NULL)))
        goto exit;

    tmpLen = keyData.pLen;

    if (keyData.qLen > tmpLen)
    {
        DIGI_FREE((void **)&pTmp);
        status = DIGI_MALLOC((void **)&pTmp, keyData.qLen + 1);
        if (OK != status)
            goto exit;

        pTmp[0] = 0;
        tmpLen = keyData.qLen;
    }

    status = DIGI_MEMSET(pTmp, 0, tmpLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pTmp + 1, keyData.pQ, keyData.qLen);
    if (OK != status)
        goto exit;

    /* add the modulus with the leading zero -- DER_AddInteger will do the right thing */
    if (OK > ( status = DER_AddIntegerCopyData( pPQGSequence, keyData.qLen + 1, pTmp, NULL)))
        goto exit;

    if (keyData.gLen > tmpLen)
    {
        DIGI_FREE((void **)&pTmp);
        status = DIGI_MALLOC((void **)&pTmp, keyData.gLen + 1);
        if (OK != status)
            goto exit;

        pTmp[0] = 0;
        tmpLen = keyData.gLen;
    }

    status = DIGI_MEMSET(pTmp, 0, tmpLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pTmp + 1, keyData.pG, keyData.gLen);
    if (OK != status)
        goto exit;

    /* add the modulus with the leading zero -- DER_AddInteger will do the right thing */
    if (OK > ( status = DER_AddIntegerCopyData( pPQGSequence, keyData.gLen + 1, pTmp, NULL)))
        goto exit;

    copyData[0] = 0; /* num unused bits in bitstring */

    /* Now add the public key Y under the bitstring */
    if (OK > ( status = DER_AddItemCopyData( pRoot, BITSTRING, 1, copyData, &pBitstr)))
        goto exit;

    if (keyData.yLen > tmpLen)
    {
        DIGI_FREE((void **)&pTmp);
        status = DIGI_MALLOC((void **)&pTmp, keyData.yLen + 1);
        if (OK != status)
            goto exit;

        pTmp[0] = 0;
        tmpLen = keyData.yLen;
    }

    status = DIGI_MEMSET(pTmp, 0, tmpLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(pTmp + 1, keyData.pY, keyData.yLen);
    if (OK != status)
        goto exit;

    /* make the sequence the owner of the buffer but set length to 0 so that it is not
        written as the sequence data! */
    if (OK > ( status = DER_AddIntegerCopyData( pBitstr, keyData.yLen + 1, pTmp, &pBitstr)))
        goto exit;

exit:

    if (NULL != pTmp)
    {
        DIGI_FREE((void **)&pTmp);
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    CRYPTO_INTERFACE_DSA_freeKeyTemplate(pDSAKey, &keyData);
#else
    DSA_freeKeyTemplate(pDSAKey, &keyData);
#endif

    return status;
}

static MSTATUS
ASN1CERT_storeDSAPublicKeyInfo(MOC_DSA(hwAccelDescr hwAccelCtx) DSAKey* pDSAKey, DER_ITEMPTR pCertificate)
{
    DER_ITEMPTR pTemp;
    MSTATUS status;

    if ( (0 == pDSAKey) || (0 == pCertificate) )
    {
        return ERR_NULL_POINTER;
    }

    /* subject public key */
    if (OK > ( status = DER_AddSequence( pCertificate, &pTemp)))
        return status;
    status = DSA_DER_StoreAlgoOID(MOC_DSA(hwAccelCtx) pTemp, dsa_OID, pDSAKey);
    return status;
}
#endif

/*------------------------------------------------------------------*/
#if (defined(__ENABLE_DIGICERT_ECC__))
/**
@cond
@brief      This function generates ECDSA signature.

@details    This function generates ECDSA Signature.
            This API also supports TAP key for ECDSA Sign.
            Based on the keytype it calls appropriate ECDSA Sign API.

@param pSignKey   Pointer to the key. It could be MocAsymKey or ECCKey.
@param pPF        Pointer to the PrimeField.
@param pToSign    Pointer to the DER_ITEM to be signed.
@param hashAlgo   Hash Algorithm to be used.
@param rngFun     Random generation function
@param rngFunArg  Argument to the random generation fucntion.
@param pR         On return, Pointer to the r buffer.
@param pS         On return, Pointer to the s buffer.
@param bufferLen  Length of the buffer.

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@endcond
*/
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
static MSTATUS ASN1CERT_eccSignAux(
    MOC_ECC(hwAccelDescr hwAccelCtx)
    AsymmetricKey* pSignKey,
    DER_ITEMPTR pToSign,
    ubyte hashAlgo,
    RNGFun rngFun,
    void* rngFunArg,
    ubyte* pR,
    ubyte* pS,
    sbyte4 buffLen
    )
#else
static MSTATUS
ASN1CERT_eccSignAux(MOC_ECC(hwAccelDescr hwAccelCtx) ECCKey* pSignKey,
                    PrimeFieldPtr pPF, DER_ITEMPTR pToSign, ubyte hashAlgo,
                    RNGFun rngFun, void* rngFunArg,
                    ubyte* pR, ubyte* pS, sbyte4 buffLen)
#endif
{
    ubyte*          pData;
    ubyte4          dataLen;
    MSTATUS         status = OK;
    ubyte*          pHash = NULL;
    ubyte4          digestSize = 0;
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    ubyte* pSignatureBuffer = 0;
    ubyte4 signatureBufferLength = 0;
    ubyte4 sigLength = 0;
    ubyte4 elementLen = 0;
#if defined(__ENABLE_DIGICERT_TAP__)
    ubyte keyUsage = 0;
#endif /* __ENABLE_DIGICERT_TAP__ */
    MOC_UNUSED(buffLen);
#else
    PFEPtr          r = 0, s = 0;
    ubyte*          pTempBuf = NULL;
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

    if (OK > ( status = DER_GetASNBufferInfo( pToSign, &pData, &dataLen)))
        goto exit;

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    if (OK > (status = CRYPTO_INTERFACE_EC_getElementByteStringLen(
            pSignKey->key.pECC, &elementLen, pSignKey->type)))
        goto exit;

    sigLength = elementLen * 2;
    pSignatureBuffer = (ubyte *)MALLOC(sigLength);

    if (NULL == pSignatureBuffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

#if defined(__ENABLE_DIGICERT_TAP__)
    /* MocAsymKey is been set to CRYPTO INTERFACE layer from client itself */
    if (OK != (status = CRYPTO_INTERFACE_getKeyUsage(
        pSignKey->key.pECC, pSignKey->type, &keyUsage)))
    {
        goto exit;
    }

    if (TAP_KEY_USAGE_ATTESTATION == keyUsage)
    {
        if (OK > ( status =  CRYPTO_INTERFACE_ECDSA_signMessage( pSignKey->key.pECC, rngFun, rngFunArg,
                                                                 pData, dataLen,
                                                                 pSignatureBuffer, sigLength,
                                                                 &signatureBufferLength,
                                                                 pSignKey->type)))
        {
            goto exit;
        }

    }
    else
#endif
    {
        if (akt_ecc_ed == (pSignKey->type & 0xFF))
        {
            if (OK > ( status =  CRYPTO_INTERFACE_ECDSA_signMessageExt( MOC_ECC(hwAccelCtx) pSignKey->key.pECC, rngFun, rngFunArg,
                                                                        hashAlgo, pData, dataLen,
                                                                        pSignatureBuffer, sigLength,
                                                                        &signatureBufferLength, NULL)))
            {
                goto exit;
            }
        }
        else
        {
            if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, CERT_MAXDIGESTSIZE, TRUE, &pHash)))
                goto exit;

            switch (hashAlgo)
            {
                case ht_sha1:
                    digestSize = SHA1_RESULT_SIZE;
                    status = CRYPTO_INTERFACE_SHA1_completeDigest(MOC_HASH(hwAccelCtx) pData, dataLen, pHash);
                    break;

#ifndef __DISABLE_DIGICERT_SHA224__
                case ht_sha224:
                    digestSize = SHA224_RESULT_SIZE;
                    status = CRYPTO_INTERFACE_SHA224_completeDigest(MOC_HASH(hwAccelCtx) pData, dataLen, pHash);
                    break;
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
                case ht_sha256:
                    digestSize = SHA256_RESULT_SIZE;
                    status = CRYPTO_INTERFACE_SHA256_completeDigest(MOC_HASH(hwAccelCtx) pData, dataLen, pHash);
                    break;
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
                case ht_sha384:
                    digestSize = SHA384_RESULT_SIZE;
                    status = CRYPTO_INTERFACE_SHA384_completeDigest(MOC_HASH(hwAccelCtx) pData, dataLen, pHash);
                    break;
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
                case ht_sha512:
                    digestSize = SHA512_RESULT_SIZE;
                    status = CRYPTO_INTERFACE_SHA512_completeDigest(MOC_HASH(hwAccelCtx) pData, dataLen, pHash);
                    break;
#endif

                default:
                    status = ERR_CERT_AUTH_BAD_SIGN_ALGO;
                    goto exit;
            }
            if (OK != status)
            {
                goto exit;
            }

            status = CRYPTO_INTERFACE_ECDSA_signDigestAux( MOC_ECC(hwAccelCtx)
                pSignKey->key.pECC, rngFun, rngFunArg, pHash, digestSize,
                pSignatureBuffer, sigLength, &signatureBufferLength);
            if (OK != status)
            {
                goto exit;
            }
        }
    }

    /* write R */
    if (OK > (status = DIGI_MEMCPY(pR, pSignatureBuffer, (signatureBufferLength / 2))))
    {
        goto exit;
    }

    /* write S */
    if (OK > (status = DIGI_MEMCPY(pS, pSignatureBuffer + (signatureBufferLength / 2),
                                  (signatureBufferLength / 2))))
    {
        goto exit;
    }
#else /* crypto interface */

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, CERT_MAXDIGESTSIZE, TRUE, &pHash)))
        goto exit;

    if (OK > (status = CRYPTO_ALLOC(hwAccelCtx, dataLen, TRUE, &pTempBuf)))
        goto exit;

    DIGI_MEMCPY(pTempBuf, pData, dataLen);

    switch ( hashAlgo )
    {
        case ht_sha1:
            digestSize = SHA1_RESULT_SIZE;
            status = SHA1_completeDigest(MOC_HASH(hwAccelCtx) pTempBuf, dataLen, pHash);
            break;

#ifndef __DISABLE_DIGICERT_SHA224__
        case ht_sha224:
            digestSize = SHA224_RESULT_SIZE;
            status = SHA224_completeDigest(MOC_HASH(hwAccelCtx) pTempBuf, dataLen, pHash);
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA256__
        case ht_sha256:
            digestSize = SHA256_RESULT_SIZE;
            status = SHA256_completeDigest(MOC_HASH(hwAccelCtx) pTempBuf, dataLen, pHash);
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA384__
        case ht_sha384:
            digestSize = SHA384_RESULT_SIZE;
            status = SHA384_completeDigest(MOC_HASH(hwAccelCtx) pTempBuf, dataLen, pHash);
            break;
#endif

#ifndef __DISABLE_DIGICERT_SHA512__
        case ht_sha512:
            digestSize = SHA512_RESULT_SIZE;
            status = SHA512_completeDigest(MOC_HASH(hwAccelCtx) pTempBuf, dataLen, pHash);
            break;
#endif

        default:
            status = ERR_CERT_AUTH_BAD_SIGN_ALGO;
            goto exit;
    }

    CRYPTO_FREE(hwAccelCtx, TRUE, &pTempBuf);
    pTempBuf = NULL;
    if (OK > status) goto exit;

    if (OK > ( status = PRIMEFIELD_newElement( pPF, &r)))
        goto exit;

    if (OK > (status = PRIMEFIELD_newElement( pPF, &s)))
        goto exit;

    if (OK > ( status =  ECDSA_signDigestAux( pSignKey->pCurve, pSignKey->k, rngFun,
                                    rngFunArg, pHash, digestSize, r, s)))
    {
        goto exit;
    }

    /* write R */
    if ( OK > ( status = PRIMEFIELD_writeByteString( pPF, r, pR, buffLen)))
        goto exit;

    /* write S */
    if ( OK > ( status = PRIMEFIELD_writeByteString( pPF, s, pS, buffLen)))
        goto exit;

#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

exit:

    if (pHash)
    {
        CRYPTO_FREE(hwAccelCtx, TRUE, &pHash);
    }

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    if (pSignatureBuffer)
    {
        DIGI_MEMSET_FREE(&pSignatureBuffer, signatureBufferLength);
    }
#else
    PRIMEFIELD_deleteElement( pPF, &r);
    PRIMEFIELD_deleteElement( pPF, &s);

    if (pTempBuf)
    {
        CRYPTO_FREE(hwAccelCtx, TRUE, &pTempBuf);
    }
#endif

    return status;
}

/*------------------------------------------------------------------*/

/**
 * Convert raw signature (r, s big-endian) into DER ASN.1 format.
 */
extern MSTATUS ASN1CERT_encodeRS( ubyte *pR, ubyte4 rLen,
                                  ubyte *pS, ubyte4 sLen,
                                  ubyte **ppSer, ubyte4 *pSerLen)
{
    MSTATUS status = ERR_NULL_POINTER;
    ubyte *pRBuffer = NULL;
    ubyte *pSBuffer = NULL;
    DER_ITEMPTR pTempSeq = NULL;

    if (NULL == pR || NULL == pS || NULL == ppSer || NULL == pSerLen)
        goto exit;

    /* Add a leading 0x00 to each R and S, this is required by DER_AddInteger */
    status = DIGI_MALLOC((void **)&pRBuffer, rLen + 1);
    if (OK != status)
        goto exit;

    *pRBuffer = 0x00;
    (void) DIGI_MEMCPY(pRBuffer + 1, pR, rLen);

    status = DIGI_MALLOC((void **)&pSBuffer, sLen + 1);
    if (OK != status)
        goto exit;

    *pSBuffer = 0x00;
    (void) DIGI_MEMCPY(pSBuffer + 1, pS, sLen);

    /* create a sequence with the two integer -> signature */
    if (OK > ( status = DER_AddSequence( NULL, &pTempSeq)))
        goto exit;

    if (OK > ( status = DER_AddInteger( pTempSeq, rLen + 1, pRBuffer, NULL)))
        goto exit;

    if (OK > ( status = DER_AddInteger( pTempSeq, sLen + 1, pSBuffer, NULL)))
        goto exit;

    /* serialize the sequence */
    status = DER_Serialize( pTempSeq, ppSer, pSerLen);

exit:

    if (NULL != pRBuffer)
    {
        (void) DIGI_FREE((void **) &pRBuffer);
    }

    if (NULL != pSBuffer)
    {
        (void) DIGI_FREE((void **) &pSBuffer);
    }

    if (NULL != pTempSeq)
    {
        (void) TREE_DeleteTreeItem( (TreeItem*) pTempSeq);
    }

    return status;
}

/*------------------------------------------------------------------*/

/**
@cond
@brief      This function initiates generation of ECDSA signature.

@details    This function initiates generation of ECDSA signature.

@param pSignedHead        Pointer to the DER_ITEM.
@param pSignKey           Pointer to the key. It could be MocAsymKey or ECCKey.
@param signAlgo           Hash Algorithm to be used.
@param rngFun             Random generation function
@param rngFunArg          Argument to the random generation fucntion.
@param keyType            Type of the key. Possible values:
                          \ref akt_tap_ecc
                          \ref akt_ecc
@param ppRetDErEncoding   On return, Pointer to output buffer.
@param pRetDEREncodingLen On return, Pointer to output buffer.
@param bufferLen  Length of the buffer.

@return     \c OK (0) if sucessful; otherwise a negative number error code
            defintion from merrors.h. To retrieve a string containing an
            English text error identifier corresponding to the function's
            returned error status, use the \c DISPLAY_ERROR macro.

@endcond
*/
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
static MSTATUS ASN1CERT_eccSign(
    MOC_ECC(hwAccelDescr hwAccelCtx)
    DER_ITEMPTR pSignedHead,
    AsymmetricKey* pSignKey,
    ubyte signAlgo,
    RNGFun rngFun,
    void* rngFunArg,
    ubyte **ppRetDEREncoding,
    ubyte4 *pRetDEREncodingLen
    )
#else
static MSTATUS
ASN1CERT_eccSign(MOC_ECC(hwAccelDescr hwAccelCtx) DER_ITEMPTR pSignedHead,
              ECCKey* pSignKey, ubyte signAlgo,
              RNGFun rngFun, void* rngFunArg,
              ubyte **ppRetDEREncoding, ubyte4 *pRetDEREncodingLen)
#endif
{
    MSTATUS         status;
    ubyte*          pRetDEREncoding = 0;
    ubyte4          retDEREncodingLen;
    sbyte4          elementLen;
    ubyte           copyData[MAX_DER_STORAGE];
    DER_ITEMPTR     pTemp, pR;
    ubyte*          pSignatureBuffer = 0;
    ubyte*          pRBuffer;
    ubyte*          pSBuffer;
    ubyte           signAlgoOID[2+MAX_SIG_OID_LEN];
    ubyte*          pSigItem = NULL;
    ubyte4          sigItemLen = 0;
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    PrimeFieldPtr   pPF;
#endif

    /* this function is more complicated so that we do one and only
    one memory allocation to save memory and to avoid fragmentation */

    if ((0 == pSignedHead) || (0 == pSignKey) ||
        (0 == ppRetDEREncoding) || ( 0 == pRetDEREncodingLen))
    {
        return ERR_NULL_POINTER;
    }

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if (akt_ecc == (pSignKey->type & 0xFF))
    {
        /* verify this is a signAlgo we support */
        if (OK > ( status = CRYPTO_getECDSAHashAlgoOID( signAlgo, signAlgoOID)))
            goto exit;
    }
#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
    else if (akt_ecc_ed == (pSignKey->type & 0xFF))
    {
        /* verify this is a signAlgo we support */
        if (OK > ( status = CRYPTO_getEDDSAAlgoOID(pSignKey->key.pECC, signAlgoOID)))
            goto exit;
    }
#endif
    else
    {
        status = ERR_EC_INVALID_KEY_TYPE;
        goto exit;
    }
#else
    /* verify this is a signAlgo we support */
    if (OK > ( status = CRYPTO_getECDSAHashAlgoOID( signAlgo, signAlgoOID)))
        goto exit;
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

    /* signature algo */
    if ( OK > (status = DER_AddSequence( pSignedHead, &pTemp)))
        goto exit;

    if ( OK > (status = DER_AddOID( pTemp, signAlgoOID, NULL)))
        goto exit;

    /* signature is a BITSTRING that encapsulate a sequence of
    2 INTEGERS -- might need to be padded with 0 on left so that
    INTEGER is not negative */
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    status = CRYPTO_INTERFACE_EC_getElementByteStringLen(
        pSignKey->key.pECC, (ubyte4 *) &elementLen, pSignKey->type);
    if (OK > status)
        goto exit;
#else
    pPF = EC_getUnderlyingField( pSignKey->pCurve);
#endif

    /* allocate a single buffer for the signature parameter */
#ifndef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if ( OK > ( status = PRIMEFIELD_getElementByteStringLen( pPF, &elementLen)))
        goto exit;
#endif

#if defined(__ENABLE_DIGICERT_ECC_EDDSA__) && defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__)
    if (akt_ecc_ed == pSignKey->type)
    {
        /* R and S concatenated after a 0x00 byte */
        pSignatureBuffer = (ubyte*) MALLOC(1 + 2 * elementLen);
        if (! pSignatureBuffer)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        /* first byte of a bit string is how many bits in the last byte to skip! Don't skip any */
        *pSignatureBuffer = 0x00;
        pRBuffer = pSignatureBuffer + 1;
        pSBuffer = pSignatureBuffer + 1 + elementLen;

        /* Add via DER_AddItem with type BITSTRING a empty placeholder pR */
        if (OK > (status = DER_AddItem (pSignedHead, BITSTRING, 2 * elementLen + 1, pSignatureBuffer, &pR)))
            goto exit;

        /* write the whole thing, this is neccessary so that ASN1CERT_eccSignAux can retrieve the asn1 string */
        if (OK > (status = DER_Serialize( pSignedHead, &pRetDEREncoding, &retDEREncodingLen)))
            goto exit;

        /* sign */
        status = ASN1CERT_eccSignAux(MOC_ECC(hwAccelCtx) pSignKey, DER_FIRST_CHILD(pSignedHead), signAlgo,
                                     rngFun, rngFunArg, pRBuffer, pSBuffer, elementLen);
        if (OK > status)
            goto exit;

        /* Now put the signature into the pR Item */
        if (OK > (status = DER_SetItemData( pR, 2 * elementLen + 1, pSignatureBuffer)))
            goto exit;

        /* rewrite the certificate in the allocated buffer */
        if (OK > ( status = DER_SerializeInto( pSignedHead, pRetDEREncoding, &retDEREncodingLen)))
            goto exit;
    }
    else
#endif
    {
        copyData[0] = 0; /* unused bits */
        if (OK > ( status = DER_AddItemCopyData( pSignedHead, BITSTRING, 1, copyData, &pTemp)))
            goto exit;

        /* allocate buffer for the raw signature */
        pSignatureBuffer = (ubyte*) MALLOC(  2 * elementLen);
        if (!pSignatureBuffer)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }

        /* write the whole thing so the the first child can be signed */
        if ( OK > ( status = DER_Serialize( pSignedHead, &pRetDEREncoding, &retDEREncodingLen)))
            goto exit;

        /* now generate the signature */
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
        status = ASN1CERT_eccSignAux(MOC_ECC(hwAccelCtx) pSignKey, DER_FIRST_CHILD(pSignedHead), signAlgo,
                                     rngFun, rngFunArg, pSignatureBuffer, pSignatureBuffer + elementLen, elementLen);

        if (OK > status)
            goto exit;

#else
        if ( OK > ( status = ASN1CERT_eccSignAux( MOC_ECC(hwAccelCtx) pSignKey, pPF,
                                                 DER_FIRST_CHILD(pSignedHead),
                                                 signAlgo, rngFun, rngFunArg,
                                                 pSignatureBuffer, pSignatureBuffer + elementLen,
                                                 elementLen)))
        {
            goto exit;
        }
#endif
        if (OK > ( status = ASN1CERT_encodeRS( pSignatureBuffer, elementLen,
                                               pSignatureBuffer + elementLen, elementLen,
                                               &pSigItem, &sigItemLen)))
            goto exit;

        if (OK > ( status = DER_AddDERBuffer(pTemp, sigItemLen, pSigItem, NULL)))
            goto exit;

        /* rewrite the certificate now that its been signed, free pre-signed version */
        if ( OK > ( status = DIGI_FREE((void **) &pRetDEREncoding)))
            goto exit;

        if (OK > ( status = DER_Serialize( pSignedHead, &pRetDEREncoding, &retDEREncodingLen)))
            goto exit;
    }
    *pRetDEREncodingLen = retDEREncodingLen;
    *ppRetDEREncoding = pRetDEREncoding;
    pRetDEREncoding = NULL;

exit:

    if ( pSignatureBuffer)
    {
        FREE( pSignatureBuffer);
    }

    if ( pRetDEREncoding)
    {
        FREE (pRetDEREncoding);
    }

    if ( pSigItem) 
    {
        FREE( pSigItem);
    }

    return status;
}

#ifdef __ENABLE_DIGICERT_PQC__
static MSTATUS ASN1CERT_hybridSign(MOC_ASYM(hwAccelDescr hwAccelCtx)
                                   DER_ITEMPTR pSignedHead,
                                   AsymmetricKey* pSignKey,
                                   RNGFun rngFun,
                                   void* rngFunArg,
                                   ubyte **ppRetDEREncoding,
                                   ubyte4 *pRetDEREncodingLen
                                   )
{
    MSTATUS         status = OK;
    ubyte*          pRetDEREncoding = NULL;
    ubyte4          retDEREncodingLen = 0;
    DER_ITEMPTR     pTemp = NULL, pSig = NULL;
    ubyte*          pSignatureBuffer = 0;
    ubyte           *pData = NULL;
    ubyte4          dataLen = 0;
    ubyte4          retSigLen = 0;
    ubyte4          totalSigLen = 0;
    ubyte4          qsAlgId = 0;
    ubyte*          pOid = NULL;
    ubyte*          pDomain = NULL;
    ubyte4          oidLen = 0;

    if ((0 == pSignedHead) || (0 == pSignKey) ||
        (0 == ppRetDEREncoding) || ( 0 == pRetDEREncodingLen))
    {
        return ERR_NULL_POINTER;
    }

    status = CRYPTO_INTERFACE_QS_getAlg(pSignKey->pQsCtx, &qsAlgId);
    if (OK != status)
        goto exit;

    status = CRYPTO_getAlgoOIDAlloc(pSignKey->clAlg, qsAlgId, &pOid, &oidLen);
    if (OK != status)
        goto exit;

    /* get a second copy of the OID to be used as the domain when signing */
    status = DIGI_MALLOC_MEMCPY((void **) &pDomain, oidLen, pOid, oidLen);
    if (OK != status)
        goto exit;

    /* signature algo */
    status = DER_AddSequence(pSignedHead, &pTemp);
    if (OK != status)
        goto exit;

    status = DER_AddItemOwnData( pTemp, OID, oidLen, &pOid, NULL);
    if (OK != status)
        goto exit;

    status = CRYPTO_INTERFACE_QS_compositeGetSigLen(MOC_ASYM(hwAccelCtx) pSignKey, TRUE, &totalSigLen);
    if (OK != status)
        goto exit;

    /* account for initial 0x00 byte (for BITSTRING type) */
    status = DIGI_MALLOC((void **) &pSignatureBuffer, totalSigLen + 1);
    if (OK != status)
        goto exit;

    /* Add via DER_AddItem with type BITSTRING as a placeholder pSig */
    status = DER_AddItem (pSignedHead, BITSTRING, totalSigLen + 1, pSignatureBuffer, &pSig);
    if (OK != status)
        goto exit;

    /* write the whole thing, this is neccessary so that DER_GetASNBufferInfo can retrieve the asn1 string to sign */
    status = DER_Serialize( pSignedHead, &pRetDEREncoding, &retDEREncodingLen);
    if (OK != status)
        goto exit;

    /* get the data */
    status = DER_GetASNBufferInfo( DER_FIRST_CHILD(pSignedHead), &pData, &dataLen);
    if (OK != status)
        goto exit;

    pSignatureBuffer[0] = 0x00;
    status = CRYPTO_INTERFACE_QS_compositeSign(MOC_ASYM(hwAccelCtx) pSignKey, TRUE, rngFun, rngFunArg, pDomain, oidLen,
                                               pData, dataLen, pSignatureBuffer + 1, totalSigLen, &retSigLen);
    if (OK != status)
        goto exit;

    /* Now put the signature into the pSig Item for good */
    status = DER_SetItemData( pSig, totalSigLen + 1, pSignatureBuffer);
    if (OK != status)
        goto exit;

    /* rewrite the certificate in the allocated buffer */
    status = DER_SerializeInto( pSignedHead, pRetDEREncoding, &retDEREncodingLen);
    if (OK != status)
        goto exit;

    *pRetDEREncodingLen = retDEREncodingLen;
    *ppRetDEREncoding = pRetDEREncoding;
    pRetDEREncoding = NULL;

exit:

    if ( NULL != pSignatureBuffer)
    {
        (void) DIGI_MEMSET_FREE(&pSignatureBuffer, totalSigLen + 1);
    }

    if ( NULL != pRetDEREncoding)
    {
        (void) DIGI_MEMSET_FREE(&pRetDEREncoding, retDEREncodingLen); 
    }

    if (NULL != pOid)
    {
        (void) DIGI_MEMSET_FREE(&pOid, oidLen);
    }

    if (NULL != pDomain)
    {
        (void) DIGI_MEMSET_FREE(&pDomain, oidLen);   
    }

    return status;
}

static MSTATUS ASN1CERT_qsSign(MOC_HASH(hwAccelDescr hwAccelCtx) DER_ITEMPTR pSignedHead,
                               AsymmetricKey* pSignKey,
                               RNGFun rngFun,
                               void* rngFunArg,
                               ubyte **ppRetDEREncoding,
                               ubyte4 *pRetDEREncodingLen
                               )
{
    MSTATUS         status = OK;
    ubyte*          pRetDEREncoding = NULL;
    ubyte4          retDEREncodingLen = 0;
    ubyte4          qsSigLen = 0;
    DER_ITEMPTR     pTemp = NULL, pSig = NULL;
    ubyte*          pSignatureBuffer = 0;
    ubyte           *pData = NULL;
    ubyte4          dataLen = 0;
    ubyte4          retSigLen = 0;
    ubyte4          qsAlgId = 0;
    ubyte*          pOid = NULL;
    ubyte4          oidLen = 0;

    if ((0 == pSignedHead) || (0 == pSignKey) ||
        (0 == ppRetDEREncoding) || ( 0 == pRetDEREncodingLen))
    {
        return ERR_NULL_POINTER;
    }

    /* get the qs Alg for the OID */
    status = CRYPTO_INTERFACE_QS_getAlg(pSignKey->pQsCtx, &qsAlgId);
    if (OK != status)
        goto exit;

    /* get pure QS OID */
    status = CRYPTO_getAlgoOIDAlloc(0, qsAlgId, &pOid, &oidLen);
    if (OK != status)
        goto exit;

    /* signature algo */
    status = DER_AddSequence(pSignedHead, &pTemp);
    if (OK != status)
        goto exit;

    status = DER_AddItemOwnData( pTemp, OID, oidLen, &pOid, NULL);
    if (OK != status)
        goto exit;

    /* Get the qs sig len or in some cases the maximum length */
    status = CRYPTO_INTERFACE_QS_SIG_getSignatureLen(pSignKey->pQsCtx, &qsSigLen);
    if (OK != status)
        goto exit;

    /* signature is a BITSTRING, add leading 0x00 byte */
    status = DIGI_MALLOC((void **) &pSignatureBuffer, qsSigLen + 1);
    if (OK != status)
        goto exit;

    /* Add via DER_AddItem with type BITSTRING as a placeholder pSig */
    status = DER_AddItem (pSignedHead, BITSTRING, qsSigLen + 1, pSignatureBuffer, &pSig);
    if (OK != status)
        goto exit;

    /* write the whole thing, this is neccessary so that DER_GetASNBufferInfo can retrieve the asn1 string to sign */
    status = DER_Serialize( pSignedHead, &pRetDEREncoding, &retDEREncodingLen);
    if (OK != status)
        goto exit;

    /* get the data */
    status = DER_GetASNBufferInfo( DER_FIRST_CHILD(pSignedHead), &pData, &dataLen);
    if (OK != status)
        goto exit;

    /* We'll place the signatures into the buffer first so we can get its true length */
    pSignatureBuffer[0] = 0x00;

    /* perform the qs signature */
    status = CRYPTO_INTERFACE_QS_SIG_sign(MOC_HASH(hwAccelCtx) pSignKey->pQsCtx, rngFun, rngFunArg, pData, dataLen,
                                          pSignatureBuffer + 1, qsSigLen, &retSigLen);
    if (OK != status)
        goto exit;

    /* Some QS Algorithms (such as FALCON) will have a shorter actual signature len */
    if (retSigLen < qsSigLen)
    {
        qsSigLen = retSigLen;
    }
    else if (retSigLen > qsSigLen)  /* sanity check, this should not happen */
    {
        status = ERR_INTERNAL_ERROR;
        goto exit;
    }

    /* Now put the signature into the pSig Item for good */
    status = DER_SetItemData( pSig, qsSigLen + 1, pSignatureBuffer);
    if (OK != status)
        goto exit;

    /* rewrite the certificate in the allocated buffer */
    status = DER_SerializeInto( pSignedHead, pRetDEREncoding, &retDEREncodingLen);
    if (OK != status)
        goto exit;

    *pRetDEREncodingLen = retDEREncodingLen;
    *ppRetDEREncoding = pRetDEREncoding;
    pRetDEREncoding = NULL;

exit:

    if ( pSignatureBuffer)
    {
        FREE( pSignatureBuffer);
    }

    if ( pRetDEREncoding)
    {
        FREE (pRetDEREncoding);
    }

    if (NULL != pOid)
    {
        (void) DIGI_MEMSET_FREE(&pOid, oidLen);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_PQC__ */
#endif /* (defined(__ENABLE_DIGICERT_ECC__)) */

/*------------------------------------------------------------------*/

MSTATUS
ASN1CERT_Sign(MOC_ASYM(hwAccelDescr hwAccelCtx) DER_ITEMPTR pSignedHead,
              const AsymmetricKey* pSignKey, ubyte signAlgo,
              RNGFun rngFun, void* rngFunArg,
              ubyte **ppRetDEREncoding, ubyte4 *pRetDEREncodingLen)
{
    switch ( pSignKey->type)
    {
#ifndef __DISABLE_DIGICERT_RSA__
        case akt_rsa:
#ifdef __ENABLE_DIGICERT_PKCS1__
        case akt_rsa_pss:
#endif
            return ASN1CERT_rsaSign(MOC_RSA(hwAccelCtx) pSignedHead,
                                    pSignKey->key.pRSA, signAlgo,
                                    ppRetDEREncoding, pRetDEREncodingLen,
                                    pSignKey->type, rngFunArg, pSignKey->pAlgoId);
#ifdef __ENABLE_DIGICERT_TAP__
        case akt_tap_rsa:
            return ASN1CERT_rsaSign(MOC_RSA(hwAccelCtx) pSignedHead,
                                    pSignKey->key.pMocAsymKey, signAlgo,
                                    ppRetDEREncoding, pRetDEREncodingLen,
                                    akt_tap_rsa, rngFunArg, pSignKey->pAlgoId);
#endif
#endif /* __DISABLE_DIGICERT_RSA__ */
#if (defined(__ENABLE_DIGICERT_DSA__))
        case akt_dsa:
            return ASN1CERT_dsaSign(MOC_DSA(hwAccelCtx) pSignedHead,
                                    pSignKey->key.pDSA, signAlgo,
                                    rngFun, rngFunArg,
                                    ppRetDEREncoding, pRetDEREncodingLen);
#endif
#if (defined(__ENABLE_DIGICERT_ECC__))
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
        case akt_ecc:
        case akt_ecc_ed:
#ifdef __ENABLE_DIGICERT_TAP__
        case akt_tap_ecc:
#endif
            return ASN1CERT_eccSign(MOC_ECC(hwAccelCtx)
                pSignedHead, (AsymmetricKey *)pSignKey, signAlgo, rngFun,
                rngFunArg, ppRetDEREncoding, pRetDEREncodingLen);
#else
        case akt_ecc:
            return ASN1CERT_eccSign(MOC_ECC(hwAccelCtx) pSignedHead,
                                    pSignKey->key.pECC, signAlgo,
                                    rngFun, rngFunArg,
                                    ppRetDEREncoding, pRetDEREncodingLen);
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
#if (defined(__ENABLE_DIGICERT_PQC__))
        case akt_hybrid:
            return ASN1CERT_hybridSign(MOC_ASYM(hwAccelCtx) pSignedHead,
                                       (AsymmetricKey *) pSignKey,
                                       rngFun, rngFunArg,
                                       ppRetDEREncoding, pRetDEREncodingLen);
        case akt_qs:
            return ASN1CERT_qsSign(MOC_HASH(hwAccelCtx) pSignedHead,
                                   (AsymmetricKey *) pSignKey,
                                   rngFun, rngFunArg,
                                   ppRetDEREncoding, pRetDEREncodingLen);
#endif
#endif /* __ENABLE_DIGICERT_ECC__ */
#if (defined(__ENABLE_DIGICERT_ASYM_KEY__))
        case akt_moc:
          return (ASN1CERT_mocAsymSign (
            MOC_RSA (hwAccelCtx) pSignedHead, pSignKey->key.pMocAsymKey,
            signAlgo, rngFun, rngFunArg, ppRetDEREncoding, pRetDEREncodingLen));
#endif
    default:
        break;
    }

    return ERR_BAD_KEY_TYPE;
}


/*------------------------------------------------------------------*/

/* This function will create an ASN.1 encoding of the public portion of a RSA
 * key following RFC 5280 Appendix C.1 (RSA Self-Signed Certificate). The
 * following ASN.1 encoding will be created and appended onto the ASN.1 encoding
 * passed in by the caller.
 *
 * SEQ {
 *   SEQ {
 *     OID - rsaEncryption (1.2.840.113549.1.1.1)
 *     NULL
 *   }
 *   BITSTRING {
 *     SEQ {
 *       INTEGER - RSA modulus
 *       INTEGER - RSA exponent
 *     }
 *   }
 * }
 *
 */
#ifndef __DISABLE_DIGICERT_RSA__
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
/* Method can be called in two modes
   1) If pCertificate is non-NULL it'll add the public key info to the cert 
   2) If ppSerForm is non-NULL it'll get the serialized DER for the public key info */
static MSTATUS ASN1CERT_getOrStoreRSAPublicKey(MOC_RSA(hwAccelDescr hwAccelCtx) RSAKey *pRsaKey, DER_ITEMPTR pCertificate, MAlgoId *pAlgoId, ubyte **ppSerForm, ubyte4 *pSerFormLen)
{
    MSTATUS status;
    DER_ITEMPTR pTemp = NULL;
    DER_ITEMPTR pTempRoot = NULL;
    ubyte pCopyData[MAX_DER_STORAGE];
    MRsaKeyTemplate template = { 0 };
    ubyte *pPubKeyData = NULL, *pExp, *pMod;
    ubyte *pPubAlgId = NULL;
    ubyte4 pubAlgIdLen = 0;

    /* internal method, null checks not necc */

    /* Create a SEQUENCE and add it onto the certificate if one is input. */
    status = DER_AddSequence(pCertificate, &pTempRoot);
    if (OK != status)
        goto exit;
 
     /* Create a SEQUENCE with an OID and NULL tag.
      *
      * SEQ {
      *   OID - rsaEncryption (1.2.840.113549.1.1.1)
      *   NULL
      * }
      *
      * and add it onto the previous SEQUENCE that was created.
      */
    if (NULL != pAlgoId)
    {      
        status = ALG_ID_serializeAlloc(pAlgoId, &pPubAlgId, &pubAlgIdLen);
        if (OK != status)
            goto exit;

        status = DER_AddDERBufferOwn( pTempRoot, pubAlgIdLen, (const ubyte **) &pPubAlgId, NULL );
        if (OK != status)
            goto exit;
    }
    else
    {
        status = DER_StoreAlgoOID(pTempRoot, rsaEncryption_OID, TRUE);
        if (OK != status)
            goto exit;
    }

    /* Add a BITSTRING to the SEQUENCE so now the ASN.1 encoding is
     *
     * SEQ {
     *   SEQ {
     *     OID - rsaEncryption (1.2.840.113549.1.1.1)
     *     NULL
     *   }
     *   SEQ {
     *     BITSTRING
     *   }
     * }
     */
    pCopyData[0] = 0x00;
    status = DER_AddItemCopyData(pTempRoot, BITSTRING, 1, pCopyData, &pTemp);
    if (OK != status)
        goto exit;

    /* Extract the public key information from the RSA key.
     */
    status = CRYPTO_INTERFACE_RSA_getKeyParametersAlloc( MOC_RSA(hwAccelCtx)
        pRsaKey, &template, MOC_GET_PUBLIC_KEY_DATA, akt_rsa);  /* use akt_rsa type for this API */
    if (OK != status)
        goto exit;

    if ( (0 == template.nLen) || (0 == template.eLen) )
    {
        status = ERR_BAD_KEY;
        goto exit;
    }

    /* Allocate a buffer with extra leading bytes for the modulus and exponent.
     * The ASN.1 engine will expect INTEGER values to start with a leading 0x00
     * byte.
     */
    status = DIGI_MALLOC(
        (void **) &pPubKeyData, template.nLen + template.eLen + 2);
    if (OK != status)
        goto exit;

    /* Set the leading 0x00 bytes.
     */
    pExp = pPubKeyData;
    *pExp = 0x00;
    pMod = pPubKeyData + 1 + template.eLen;
    *pMod = 0x00;

    /* Copy over the actual RSA public key data into the buffer.
     */
    status = DIGI_MEMCPY(
        pExp + 1, template.pE, template.eLen);
    if (OK != status)
        goto exit;

    status = DIGI_MEMCPY(
        pMod + 1, template.pN, template.nLen);
    if (OK != status)
        goto exit;

    /* Add SEQUENCE to the BITSTRING.
     */
    status = DER_AddItemOwnData(
        pTemp, (CONSTRUCTED | SEQUENCE), 0, &pPubKeyData, &pTemp);
    if (OK != status)
        goto exit;

    /* Add the RSA modulus to the SEQUENCE within the BITSTRING.
     */
    status = DER_AddInteger(pTemp, template.nLen + 1, pMod, NULL);
    if (OK != status)
        goto exit;

    /* Add the RSA exponent to the SEQUENCE within the BITSTRING.
     */
    status = DER_AddInteger(pTemp, template.eLen + 1, pExp, NULL);
    if (OK != status)
        goto exit;

    if (NULL != ppSerForm)
    {
        status = DER_Serialize(pTemp, ppSerForm, pSerFormLen);
    }

exit:

    if (NULL != pPubAlgId)
    {
        (void) DIGI_MEMSET_FREE(&pPubAlgId, pubAlgIdLen);
    }

    (void) CRYPTO_INTERFACE_RSA_freeKeyTemplate(pRsaKey, &template, akt_rsa);

    if (NULL != pPubKeyData)
    {
        (void) DIGI_FREE((void **) &pPubKeyData);
    }

    if (NULL == pCertificate && NULL != pTempRoot)
    {
        (void) TREE_DeleteTreeItem( (TreeItem*) pTempRoot);
    }

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS ASN1CERT_storeRSAPublicKeyInfo(
    MOC_RSA(hwAccelDescr hwAccelCtx)
    RSAKey * pRsaKey,
    DER_ITEMPTR pCertificate,
    ubyte4 keyType,
    MAlgoId *pAlgoId
    )
{
    MOC_UNUSED(keyType);

    if ( (NULL == pRsaKey) || (NULL == pCertificate) )
        return ERR_NULL_POINTER;

    return ASN1CERT_getOrStoreRSAPublicKey(MOC_RSA(hwAccelCtx) pRsaKey, pCertificate, pAlgoId, NULL, NULL);
}
#else
static MSTATUS
ASN1CERT_storeRSAPublicKeyInfo( MOC_RSA(hwAccelDescr hwAccelCtx) RSAKey* pRSAKey, DER_ITEMPTR pCertificate, ubyte4 keyType, MAlgoId *pAlgoId)
{
    DER_ITEMPTR pTemp;
    MSTATUS     status;
    ubyte       copyData[MAX_DER_STORAGE];
    sbyte4      expLen, modulusLen;
    ubyte*      expModulusBuffer = 0;
    ubyte*      pE;
    ubyte*      pN;
    ubyte      *pPubAlgId = NULL;
    ubyte4      pubAlgIdLen = 0;    

    if ( (0 == pRSAKey) || (0 == pCertificate) )
    {
        return ERR_NULL_POINTER;
    }

    /* subject public key */
    if (OK > ( status = DER_AddSequence( pCertificate, &pTemp)))
        goto exit;

    if (NULL != pAlgoId)
    {   
        status = ALG_ID_serializeAlloc(pAlgoId, &pPubAlgId, &pubAlgIdLen);
        if (OK != status)
            goto exit;

        status = DER_AddDERBufferOwn( pTemp, pubAlgIdLen, (const ubyte **) &pPubAlgId, NULL );
        if (OK != status)
            goto exit;
    }
    else
    {
        if (OK > ( status = DER_StoreAlgoOID( pTemp, rsaEncryption_OID, TRUE)))
            goto exit;
    }

    copyData[0] = 0; /* unused bits */
    if (OK > ( status = DER_AddItemCopyData( pTemp, BITSTRING, 1, copyData, &pTemp)))
        goto exit;


    /* allocate a single buffer for the key parameter */
    if (OK > (status = VLONG_byteStringFromVlong(RSA_N(pRSAKey), NULL, &modulusLen)))
        goto exit;

    if (OK > (status = VLONG_byteStringFromVlong(RSA_E(pRSAKey), NULL, &expLen)))
        goto exit;

    if ((0 == modulusLen) || (0 == expLen))
    {
        status = ERR_BAD_KEY;
        goto exit;
    }

    /* add 2 bytes to prevent negative values */
    expModulusBuffer = (ubyte*) MALLOC( modulusLen + expLen + 2);
    if ( !expModulusBuffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }
    pE = expModulusBuffer;
    *pE = 0x00; /* leading 0 */
    pN = expModulusBuffer + 1 + expLen;
    *pN = 0x00; /* leading 0 */
    if (OK > (status = VLONG_byteStringFromVlong(RSA_N(pRSAKey), pN + 1, &modulusLen)))
        goto exit;

    /* make the sequence the owner of the buffer but set length to 0 so that it is not
        written as the sequence data! */
    if (OK > ( status = DER_AddItemOwnData( pTemp, (CONSTRUCTED|SEQUENCE), 0, &expModulusBuffer, &pTemp)))
        goto exit;

    /* add the modulus with the leading zero -- DER_AddInteger will do the right thing */
    if (OK > ( status = DER_AddInteger( pTemp, modulusLen + 1, pN, NULL)))
        goto exit;

    if (OK > (status = VLONG_byteStringFromVlong(RSA_E(pRSAKey), pE + 1, &expLen)))
        goto exit;

    /* add the exponent */
    if (OK > ( status = DER_AddInteger( pTemp, expLen + 1, pE, NULL)))
        goto exit;

exit:

    if (NULL != pPubAlgId)
    {
        (void) DIGI_MEMSET_FREE(&pPubAlgId, pubAlgIdLen);
    }

    if ( expModulusBuffer)
    {
        FREE( expModulusBuffer);
    }

    return status;
}
#endif
#endif /* __DISABLE_DIGICERT_RSA__ */

/*------------------------------------------------------------------*/

#if (defined(__ENABLE_DIGICERT_ECC__))
extern MSTATUS
ASN1CERT_storeECCPublicKeyInfo(MOC_ECC(hwAccelDescr hwAccelCtx) const ECCKey *pECCKey, DER_ITEMPTR pCertificate)
{
    MSTATUS         status;
    DER_ITEMPTR     pTemp;
    DER_ITEMPTR     pAlgoID;
    const ubyte*    curveOID;
    sbyte4          keyLen;
    ubyte*          keyBuffer = 0;
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    ubyte4          curveId = 0;
#endif

    if ( (0 == pECCKey) || (0 == pCertificate) )
    {
        return ERR_NULL_POINTER;
    }

    if (OK > ( status = CRYPTO_getECCurveOID(pECCKey, &curveOID)))
        goto exit;

    /* subject public key */
    if (OK > ( status = DER_AddSequence( pCertificate, &pTemp)))
        goto exit;

    /* add the algorithm identifier sequence */
    if ( OK > ( status = DER_AddSequence( pTemp, &pAlgoID)))
        goto exit;

    /* curveOID is the public key OID for Edward's curves, check for a primeec curve */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    if ( OK > ( status = CRYPTO_INTERFACE_EC_getCurveIdFromKeyAux ((ECCKey *) pECCKey, &curveId)))
        goto exit;
    
    if (cid_EC_X25519 != curveId && cid_EC_X448 != curveId && cid_EC_Ed25519 != curveId && cid_EC_Ed448 != curveId)
#elif defined(__ENABLE_DIGICERT_ECC_ED_COMMON__)
    if (NULL != pECCKey->pCurve)
#endif
    {
        if ( OK > ( status = DER_AddOID( pAlgoID, ecPublicKey_OID, NULL)))
            return status;
    }

    if ( OK > ( status = DER_AddOID( pAlgoID, curveOID, NULL)))
        return status;

    /* allocate a buffer for the key parameter */
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    if (OK > (status = CRYPTO_INTERFACE_EC_getPointByteStringLenAux (
        (ECCKey*)pECCKey, (ubyte4*)&keyLen)))
#else
    if (OK > (status = EC_getPointByteStringLenEx (
        (ECCKey*)pECCKey, (ubyte4*)&keyLen)))
#endif
        goto exit;

    if (0 == keyLen)
    {
        status = ERR_BAD_KEY;
        goto exit;
    }

    /* add an extra byte = 0 (unused bits) */
    keyBuffer = (ubyte*) MALLOC( keyLen+1);
    if (!keyBuffer)
    {
        status = ERR_MEM_ALLOC_FAIL;
        goto exit;
    }

    keyBuffer[0] = 0; /* unused bits */

#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
    if (OK > ( status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux ( MOC_ECC(hwAccelCtx)
        (ECCKey*)pECCKey, keyBuffer+1, keyLen)))
#else
    if (OK > ( status = EC_writePublicKeyToBuffer (
        (ECCKey*)pECCKey, keyBuffer+1, keyLen)))
#endif
    {
        goto exit;
    }

    if (OK > ( status = DER_AddItemOwnData( pTemp, BITSTRING, keyLen+1, &keyBuffer, NULL)))
        goto exit;

exit:

    if ( keyBuffer)
    {
        FREE( keyBuffer);
    }

    return status;
}

/*------------------------------------------------------------------*/

#ifdef __ENABLE_DIGICERT_PQC__
/* This API can be used in two modes
   1) For pCertificate not NULL it'll add the public key info to the certificate 
   2) For ppRetDer not NULL it'll get the bitstring concatanted keys (including a leading 0x00 byte )
*/
static MSTATUS ASN1CERT_getOrStoreHybridPublicKeyInfo(MOC_ASYM(hwAccelDescr hwAccelCtx) const AsymmetricKey *pKey, DER_ITEMPTR pCertificate, ubyte **ppRetDer, ubyte4 *pRetDerLen)
{
    MSTATUS         status;
    DER_ITEMPTR     pTemp;
    DER_ITEMPTR     pAlgoID;
    ubyte4          clKeyLen;
    ubyte*          pKeyBuffer = NULL;
    ubyte4          keyBufferLen = 0;
    sbyte4          qsKeyLen;
    ubyte4          qsAlgId = 0;
    ubyte*          pOid = 0;
    ubyte4          oidLen = 0;
    ubyte*          pRsaDer = NULL;

    if (NULL == pKey)
    {
        return ERR_NULL_POINTER;
    }

    if (NULL != pCertificate)
    {
        status = CRYPTO_INTERFACE_QS_getAlg(pKey->pQsCtx, &qsAlgId);
        if (OK != status)
            goto exit;

        status = CRYPTO_getAlgoOIDAlloc(pKey->clAlg, qsAlgId, &pOid, &oidLen);
        if (OK != status)
            goto exit;

        /* subject public key */
        status = DER_AddSequence( pCertificate, &pTemp);
        if (OK != status)
            goto exit;

        /* add the algorithm identifier sequence */
        status = DER_AddSequence( pTemp, &pAlgoID);
        if (OK != status)
            goto exit;

        /* add the oid, own the pointer now */
        status = DER_AddItemOwnData( pAlgoID, OID, oidLen, &pOid, NULL);
        if (OK != status)
            goto exit;
    }

    status = CRYPTO_INTERFACE_QS_getPublicKeyLen(pKey->pQsCtx, (ubyte4 *) &qsKeyLen);
    if (OK != status)
        goto exit;

    if(pKey->clAlg < cid_RSA_2048_PKCS15) /* if ECC */
    {
        status = CRYPTO_INTERFACE_EC_getPointByteStringLenAux(pKey->key.pECC, &clKeyLen);
    }
    else /* RSA */
    {
        status = ASN1CERT_getOrStoreRSAPublicKey(MOC_RSA(hwAccelCtx) pKey->key.pRSA, NULL, pKey->pAlgoId, &pRsaDer, &clKeyLen);
    }
    if (OK != status)
        goto exit;

    keyBufferLen = clKeyLen + qsKeyLen + 5; /* account for initial 0 byte for BITSTRING and 4 byte length */
    status = DIGI_MALLOC((void **) &pKeyBuffer, keyBufferLen);
    if (OK != status)
        goto exit;

    /* BIT STRING, unused bits byte */
    pKeyBuffer[0] = 0;

    /* Little endian 4 byte length */
    pKeyBuffer[1] = (ubyte) (qsKeyLen & 0xff);
    pKeyBuffer[2] = (ubyte) ((qsKeyLen >> 8) & 0xff); 
    pKeyBuffer[3] = (ubyte) ((qsKeyLen >> 16) & 0xff); 
    pKeyBuffer[4] = (ubyte) ((qsKeyLen >> 24) & 0xff); 

    status = CRYPTO_INTERFACE_QS_getPublicKey (pKey->pQsCtx, pKeyBuffer + 5, qsKeyLen);
    if (OK != status)
        goto exit;

    if(pKey->clAlg < cid_RSA_2048_PKCS15) /* if ECC */
    {
        status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAux (MOC_ECC(hwAccelCtx) pKey->key.pECC, pKeyBuffer + 5 + qsKeyLen, clKeyLen);
    }
    else
    {
        status = DIGI_MEMCPY(pKeyBuffer + 5 + qsKeyLen, pRsaDer, clKeyLen);
    }
    if (OK != status)
        goto exit;
   
    if (NULL != pCertificate)
    {
        status = DER_AddItemOwnData( pTemp, BITSTRING, keyBufferLen, &pKeyBuffer, NULL);
        if (OK != status)
            goto exit;
    }

    if (NULL != ppRetDer)
    {
        *ppRetDer = pKeyBuffer; pKeyBuffer = NULL;
        *pRetDerLen = keyBufferLen;
    }
  
exit:

    if (NULL != pKeyBuffer)
    {
        (void) DIGI_MEMSET_FREE(&pKeyBuffer, keyBufferLen);
    }

    if (NULL != pOid)
    {
        (void) DIGI_MEMSET_FREE(&pOid, oidLen);
    }

    if (NULL != pRsaDer)
    {
        (void) DIGI_MEMSET_FREE(&pRsaDer, clKeyLen);
    }

    return status;
}

/*------------------------------------------------------------------*/

static MSTATUS ASN1CERT_storeQsPublicKeyInfo(QS_CTX *pCtx, DER_ITEMPTR pCertificate)
{
    MSTATUS         status;
    DER_ITEMPTR     pTemp;
    DER_ITEMPTR     pAlgoID;
    ubyte*          pKeyBuffer = NULL;
    sbyte4          qsKeyLen;
    ubyte4          qsAlgId = 0;
    ubyte*          pOid = NULL;
    ubyte4          oidLen = 0;

    if ( (0 == pCtx) || (0 == pCertificate) )
    {
        return ERR_NULL_POINTER;
    }

    /* get the qs Alg for the OID first */
    if (OK > ( status = CRYPTO_INTERFACE_QS_getAlg(pCtx, &qsAlgId)))
        goto exit;

    /* Get pure QS alg oid */
    if (OK > ( status = CRYPTO_getAlgoOIDAlloc(0, qsAlgId, &pOid, &oidLen)))
        goto exit;

    /* subject public key */
    if (OK > ( status = DER_AddSequence( pCertificate, &pTemp)))
        goto exit;

    /* add the algorithm identifier sequence */
    if ( OK > ( status = DER_AddSequence( pTemp, &pAlgoID)))
        goto exit;

    /* add the oid */
    if ( OK > ( status = DER_AddItemOwnData( pAlgoID, OID, oidLen, &pOid, NULL)))
        goto exit;

    /* allocate a buffer for the public key parameter */
    if (OK > (status = CRYPTO_INTERFACE_QS_getPublicKeyLen(pCtx, (ubyte4 *) &qsKeyLen)))
        goto exit;

    /* add an extra byte = 0 (unused bits) */
    status = DIGI_MALLOC((void **)&pKeyBuffer, qsKeyLen + 1);
    if (OK != status)
        goto exit;

    pKeyBuffer[0] = 0; /* unused bits */

    if (OK > ( status = CRYPTO_INTERFACE_QS_getPublicKey (pCtx, pKeyBuffer + 1, qsKeyLen)))
        goto exit;

    if (OK > ( status = DER_AddItemOwnData( pTemp, BITSTRING, qsKeyLen + 1, &pKeyBuffer, NULL)))
        goto exit;

exit:

    if ( pKeyBuffer)
    {
        (void) DIGI_MEMSET_FREE(&pKeyBuffer, qsKeyLen + 1);
    }

    if (NULL != pOid)
    {
        (void) DIGI_MEMSET_FREE(&pOid, oidLen);
    }

    return status;
}
#endif /* __ENABLE_DIGICERT_PQC__ */
#endif /* (defined(__ENABLE_DIGICERT_ECC__)) */

/*------------------------------------------------------------------*/

MSTATUS
ASN1CERT_storePublicKeyInfo(MOC_ASYM(hwAccelDescr hwAccelCtx) const AsymmetricKey* pPublicKey, DER_ITEMPTR pCertificate)
{
    switch (pPublicKey->type)
    {
#if !(defined(__DISABLE_DIGICERT_RSA__))
        case akt_rsa:
        case akt_rsa_pss:
        {
            return ASN1CERT_storeRSAPublicKeyInfo( MOC_RSA(hwAccelCtx) pPublicKey->key.pRSA, pCertificate, pPublicKey->type, pPublicKey->pAlgoId);
        }
#endif
#if (defined(__ENABLE_DIGICERT_ECC__))
        case akt_ecc:
        case akt_ecc_ed:
        {
            return ASN1CERT_storeECCPublicKeyInfo( MOC_ECC(hwAccelCtx) pPublicKey->key.pECC, pCertificate);
        }
#endif
#if (defined(__ENABLE_DIGICERT_PQC__))
        case akt_hybrid:
        {
            return ASN1CERT_getOrStoreHybridPublicKeyInfo( MOC_ASYM(hwAccelCtx) pPublicKey, pCertificate, NULL, NULL);
        }
        case akt_qs:
        {
            return ASN1CERT_storeQsPublicKeyInfo(pPublicKey->pQsCtx, pCertificate);
        }
#endif
#if (defined(__ENABLE_DIGICERT_DSA__))
        case akt_dsa:
        {
            return ASN1CERT_storeDSAPublicKeyInfo( MOC_DSA(hwAccelCtx) pPublicKey->key.pDSA, pCertificate);
        }
#endif
#if (defined(__ENABLE_DIGICERT_CRYPTO_INTERFACE__))
#if defined(__ENABLE_DIGICERT_TAP__)
        case akt_tap_rsa:
        {
            MSTATUS status;
            RSAKey *pRsaKey = NULL;
            status = CRYPTO_INTERFACE_getRSAPublicKey(
                (AsymmetricKey *) pPublicKey, &pRsaKey);
            if (OK == status)
            {
                status = ASN1CERT_storeRSAPublicKeyInfo(MOC_RSA(hwAccelCtx) pRsaKey, pCertificate, akt_tap_rsa, pPublicKey->pAlgoId);
                RSA_freeKey(&pRsaKey, NULL);

                return status;
            }
            break;
        }
#if (defined(__ENABLE_DIGICERT_ECC__))
        case akt_tap_ecc:
        {
            MSTATUS status;
            ECCKey *pEccKey = NULL;
            status = CRYPTO_INTERFACE_getECCPublicKey((AsymmetricKey*)pPublicKey, &pEccKey);
            if (OK == status)
            {
                status =  ASN1CERT_storeECCPublicKeyInfo(MOC_ECC(hwAccelCtx) pEccKey, pCertificate);
                EC_deleteKeyEx(&pEccKey);
                return status;
            }
            break;
        }
#endif
#endif
#endif
        default:
        {
            break;
        }
    }

    return ERR_BAD_KEY_TYPE;
}

/*------------------------------------------------------------------*/

extern MSTATUS ASN1CERT_sha1PublicKey(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pKey, ubyte *pResult)
{
    MSTATUS status = ERR_NULL_POINTER;

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
    MRsaKeyTemplate template = { 0 };
#if (defined(__ENABLE_DIGICERT_DSA__))
    MDsaKeyTemplate dsaTemplate = { 0 };
#endif
    vlong *pMod = NULL;
#endif

#if (defined(__ENABLE_DIGICERT_ECC__))
    ubyte*          ptBuffer = NULL;
    sbyte4          ptBufferLen;
#endif

    if (NULL == pKey || NULL == pResult)
        return status;

    switch ( pKey->type)
    {
#if (defined(__ENABLE_DIGICERT_DSA__))
        case akt_dsa:
        {
            /* serial number -> generated by SHA-1 hash of the DSA key modulus */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_DSA_getKeyParametersAlloc( MOC_DSA(hwAccelCtx)
                pKey->key.pDSA, &dsaTemplate, MOC_GET_PUBLIC_KEY_DATA);
            if (OK != status)
                goto exit;

            status = VLONG_vlongFromByteString(
                dsaTemplate.pP, dsaTemplate.pLen, &pMod, NULL);
            if (OK != status)
                goto exit;

            status = SHA1_completeDigest(
                MOC_HASH(hwAccelCtx) (ubyte *) pMod->pUnits,
                sizeof(vlong_unit) * pMod->numUnitsUsed, pResult);
            if (OK > status)
                goto exit;
#else
            if (OK > (status = SHA1_completeDigest(MOC_HASH(hwAccelCtx)
                                                    (ubyte *)DSA_P(pKey->key.pDSA)->pUnits,
                                                    sizeof(vlong_unit) * DSA_P(pKey->key.pDSA)->numUnitsUsed,
                                                    pResult)))
            {
                goto exit;
            }
#endif /* ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */
            break;
        }
#endif /* if (defined(__ENABLE_DIGICERT_DSA__)) */
#ifndef __DISABLE_DIGICERT_RSA__
        case akt_rsa:
        case akt_rsa_pss:
        {
            /* serial number -> generated by SHA-1 hash of the RSA key modulus */
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_RSA_getKeyParametersAlloc( MOC_RSA(hwAccelCtx)
                pKey->key.pRSA, &template, MOC_GET_PUBLIC_KEY_DATA,
                pKey->type);
            if (OK != status)
                goto exit;

            status = VLONG_vlongFromByteString(
                template.pN, template.nLen, &pMod, NULL);
            if (OK != status)
                goto exit;

            status = SHA1_completeDigest(
                MOC_HASH(hwAccelCtx) (ubyte *) pMod->pUnits,
                sizeof(vlong_unit) * pMod->numUnitsUsed, pResult);
            if (OK > status)
                goto exit;
#else
            if (OK > (status = SHA1_completeDigest(MOC_HASH(hwAccelCtx)
                                                   (ubyte *)RSA_N(pKey->key.pRSA)->pUnits,
                                                   sizeof(vlong_unit) * RSA_N(pKey->key.pRSA)->numUnitsUsed,
                                                   pResult)))
            {
                goto exit;
            }
#endif
            break;
        }
#endif
#ifdef __ENABLE_DIGICERT_TAP__
        case akt_tap_rsa:
        {
            TAP_Key *pTapKey = NULL;
            TAP_RSAPublicKey *pRsaTapPub = NULL;

            status = CRYPTO_INTERFACE_getTapKey((AsymmetricKey*)pKey, &pTapKey);
            if (OK != status)
                goto exit;

            pRsaTapPub = (TAP_RSAPublicKey *)(&(pTapKey->keyData.publicKey.publicKey.rsaKey));
            /* serial number -> generated by SHA-1 hash of the RSA key modulus */
            if (OK > (status = SHA1_completeDigest(MOC_HASH(hwAccelCtx)
                            (ubyte *)pRsaTapPub->pModulus,
                            pRsaTapPub->modulusLen, pResult)))
            {
                goto exit;
            }

            break;
        }
#endif
#if (defined(__ENABLE_DIGICERT_ECC__))
        case akt_ecc:
        case akt_ecc_ed:
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            /* serial number -> generated by SHA-1 hash of the point */
            if ( OK > ( status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAlloc( MOC_ECC(hwAccelCtx) pKey->key.pECC,
                                                                                  &ptBuffer,
                                                                                  (ubyte4*)&ptBufferLen,
                                                                                  pKey->type)))
            {
                goto exit;
            }
#else
            /* serial number -> generated by SHA-1 hash of the point */
            if ( OK > ( status = EC_pointToByteString( pKey->key.pECC->pCurve,
                                                      pKey->key.pECC->Qx,
                                                      pKey->key.pECC->Qy,
                                                      &ptBuffer,
                                                      &ptBufferLen)))
            {
                goto exit;
            }
#endif /* __ENABLE_DIGICERT_CRYPTO_INTERFACE__ */

            if ( OK > ( status = SHA1_completeDigest( MOC_HASH(hwAccelCtx)
                                                     ptBuffer, ptBufferLen, pResult)))
            {
                goto exit;
            }
            break;
        }
#endif /* __ENABLE_DIGICERT_ECC__ */
#ifdef __ENABLE_DIGICERT_PQC__
        case akt_hybrid:
        {
            /* serial number -> generated by SHA-1 hash of the byte string form public key */
            status = ASN1CERT_getOrStoreHybridPublicKeyInfo( MOC_ASYM(hwAccelCtx) pKey, NULL, &ptBuffer, (ubyte4 *) &ptBufferLen);
            if (OK != status)
                goto exit; 

            /* skip the leading 0x00 byte */
            status = SHA1_completeDigest( MOC_HASH(hwAccelCtx) ptBuffer + 1, ptBufferLen - 1, pResult);
            if (OK != status)
                goto exit;

            break;
        }
        case akt_qs:
        {
            status = CRYPTO_INTERFACE_QS_getPublicKeyAlloc(pKey->pQsCtx, &ptBuffer, (ubyte4 *) &ptBufferLen);
            if (OK != status)
                goto exit;

            status = SHA1_completeDigest( MOC_HASH(hwAccelCtx) ptBuffer, ptBufferLen, pResult);
            if (OK != status)
                goto exit;

            break;
        }
#endif
#if defined(__ENABLE_DIGICERT_TAP__) && defined(__ENABLE_DIGICERT_ECC__)
        case akt_tap_ecc:
        {
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            status = CRYPTO_INTERFACE_EC_writePublicKeyToBufferAlloc( MOC_ECC(hwAccelCtx)
                pKey->key.pECC, &ptBuffer, (ubyte4 *) &ptBufferLen,
                pKey->type);
            if (OK != status)
                goto exit1;

            status = SHA1_completeDigest(
                MOC_HASH(hwAccelCtx) ptBuffer, ptBufferLen, pResult);
            if (OK > status)
                goto exit1;
#else
            TAP_ECC_CURVE curve;
            PEllipticCurvePtr pECurve = NULL;
            PrimeFieldPtr pPF = NULL;
            PFEPtr              Qx = NULL;         /* public */
            PFEPtr              Qy = NULL;         /* public */
            MocAsymKey pMocAsymKey = pKey->key.pMocAsymKey;
            MEccTapKeyData *pData = (MEccTapKeyData *)(pMocAsymKey->pKeyData);
            curve = pData->pKey->keyData.algKeyInfo.eccInfo.curveId;
            switch (curve)
            {
#ifdef __ENABLE_DIGICERT_ECC_P192__
                case TAP_ECC_CURVE_NIST_P192:
                    pECurve = EC_P192;
                    break;
#endif
                case TAP_ECC_CURVE_NIST_P224:
                    pECurve = EC_P224;
                    break;
                case TAP_ECC_CURVE_NIST_P256:
                    pECurve = EC_P256;
                    break;
                case TAP_ECC_CURVE_NIST_P384:
                    pECurve = EC_P384;
                    break;
                case TAP_ECC_CURVE_NIST_P521:
                    pECurve = EC_P521;
                    break;
                default:
                    status = ERR_EC_UNSUPPORTED_CURVE;
                    goto exit1;

            }
            pPF = EC_getUnderlyingField(pECurve);
            status = PRIMEFIELD_newElement( pPF, &Qx);
            if (OK != status)
                goto exit1;
            status = PRIMEFIELD_newElement( pPF, &Qy);
            if (OK != status)
                goto exit1;

            status = PRIMEFIELD_setToByteString (
                    pPF, Qx, pData->pKey->keyData.publicKey.publicKey.eccKey.pPubX,
                    pData->pKey->keyData.publicKey.publicKey.eccKey.pubXLen);
            if (OK != status)
                goto exit1;

            status = PRIMEFIELD_setToByteString (
                    pPF, Qy, pData->pKey->keyData.publicKey.publicKey.eccKey.pPubY,
                    pData->pKey->keyData.publicKey.publicKey.eccKey.pubYLen);
            if (OK != status)
                goto exit1;


            /* serial number -> generated by SHA-1 hash of the point */
            if ( OK > ( status = EC_pointToByteString(pECurve,
                            Qx,
                            Qy,
                            &ptBuffer,
                            (sbyte4*)&ptBufferLen)))
            {
                goto exit1;
            }

            if ( OK > ( status = SHA1_completeDigest( MOC_HASH(hwAccelCtx)
                            ptBuffer, ptBufferLen, pResult)))
            {
                goto exit1;
            }
#endif
exit1:
#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
            if (NULL != ptBuffer)
            {
                DIGI_FREE((void**)&ptBuffer);
            }
#else
            PRIMEFIELD_deleteElement( pPF, &Qx);
            PRIMEFIELD_deleteElement( pPF, &Qy);
#endif
            if (OK != status)
                goto exit;
            break;

        }
#endif /* TAP and ECC */
        default:
        {
            status = ERR_BAD_KEY_TYPE;
            goto exit;
        }
    }

exit:

#ifdef __ENABLE_DIGICERT_CRYPTO_INTERFACE__
#ifndef __DISABLE_DIGICERT_RSA__
    if (pKey->type == akt_rsa || pKey->type == akt_rsa_pss)
    {
        CRYPTO_INTERFACE_RSA_freeKeyTemplate(
            pKey->key.pRSA, &template, pKey->type);
    }
#endif

#if (defined(__ENABLE_DIGICERT_DSA__))
    if (pKey->type == akt_dsa)
    {
        CRYPTO_INTERFACE_DSA_freeKeyTemplate(
            pKey->key.pDSA, &dsaTemplate);
    }
#endif

    if (NULL != pMod)
    {
        (void) VLONG_freeVlong(&pMod, NULL);
    }
#endif

#if (defined(__ENABLE_DIGICERT_ECC__))
    if (NULL != ptBuffer)
    {
        (void) DIGI_FREE((void **) &ptBuffer);
    }
#endif

    return status;
}

/*------------------------------------------------------------------*/

extern MSTATUS
ASN1CERT_generateCertificateEx(MOC_ASYM(hwAccelDescr hwAccelCtx)
                               const AsymmetricKey *pCertKey,
                               const certDistinguishedName *pSubjectInfo,
                               const AsymmetricKey *pSignKey,
                               const ASN1_ITEM *pIssuerInfo, CStream cs,
                               const ubyte* serialNumber, ubyte4 serialNumberLen,
                               ubyte signAlgo, const certExtensions* pExtensions,
                               RNGFun rngFun, void* rngFunArg,
                               ubyte **ppRetCertificate, ubyte4 *pRetCertLength)
{
    DER_ITEMPTR     pCertificate = 0;
    DER_ITEMPTR     pSignedCertificate = 0;
    DER_ITEMPTR     pTemp = 0;
    ubyte           copyData[MAX_DER_STORAGE];
    ubyte           serialNr[SHA1_RESULT_SIZE];
    ubyte           signAlgoOID[MAX_PQC_OID_LEN]; /* big enough for any classical oid too */
    ubyte *pAlgIdBuff = NULL;
    ubyte4 algIdBuffLen = 0;
    const ubyte*    issuerMemAccessBuffer = 0;
    MSTATUS         status;
#ifdef __ENABLE_DIGICERT_PQC__
    ubyte4 qsAlgId = 0;
#endif
    TimeDate date = {0};

    if ( (0 == pCertKey) || (0 == pSubjectInfo) ||
        (0 == ppRetCertificate) || ( 0 == pRetCertLength))
    {
        return ERR_NULL_POINTER;
    }

    if (!pSignKey)
    {
        pSignKey = pCertKey; /* use cert key for signing */
    }

#ifdef __ENABLE_DIGICERT_PKCS1__
    if (NULL == pSignKey->pAlgoId || ALG_ID_RSA_SSA_PSS_OID != pSignKey->pAlgoId->oidFlag)
#endif
    {
        switch (pSignKey->type)
        {
#ifdef __ENABLE_DIGICERT_TAP__
            case akt_tap_rsa:
#endif
            case akt_rsa:
            {
                if (OK > ( status = CRYPTO_getRSAHashAlgoOID( signAlgo, signAlgoOID)))
                    goto exit;
                break;
            }

#if (defined(__ENABLE_DIGICERT_ECC__))
#ifdef __ENABLE_DIGICERT_TAP__
            case akt_tap_ecc:
#endif
            case akt_ecc:
            {
                if (OK > ( status = CRYPTO_getECDSAHashAlgoOID( signAlgo, signAlgoOID)))
                    goto exit;
                break;
            }

#ifdef __ENABLE_DIGICERT_ECC_EDDSA__
            case akt_ecc_ed:
            {
                if (OK > ( status = CRYPTO_getEDDSAAlgoOID(pSignKey->key.pECC, signAlgoOID)))
                    goto exit;
                break;
            }
#endif
#ifdef __ENABLE_DIGICERT_PQC__
            case akt_hybrid:
            {
                if (OK > ( status = CRYPTO_INTERFACE_QS_getAlg(pSignKey->pQsCtx, &qsAlgId)))
                    goto exit;

                if (OK > ( status = CRYPTO_getHybridAlgoOID(pSignKey->clAlg, qsAlgId, signAlgoOID)))
                    goto exit;

                break;
            }
            case akt_qs:
            {
                if (OK > ( status = CRYPTO_INTERFACE_QS_getAlg(pSignKey->pQsCtx, &qsAlgId)))
                    goto exit;

                if (OK > ( status = CRYPTO_getQsAlgoOID(qsAlgId, signAlgoOID)))
                    goto exit;

                break;
            }
#endif
#endif /* __ENABLE_DIGICERT_ECC__ */
#if (defined(__ENABLE_DIGICERT_DSA__))
            case akt_dsa:
            {
                if (OK > ( status = CRYPTO_getDSAHashAlgoOID( signAlgo, signAlgoOID)))
                    goto exit;
                break;
            }
#endif

            default:
            {
                status = ERR_BAD_KEY_TYPE;
                goto exit;
            }
        }

    }

    /* build certificate */
    if ( OK > (status = DER_AddSequence( NULL, &pSignedCertificate)))
        goto exit;

    if ( OK > (status = DER_AddSequence( pSignedCertificate, &pCertificate)))
        goto exit;

    /* version  tag [0] + integer (2)*/
    if ( OK > (status = DER_AddTag( pCertificate, 0,  &pTemp)))
        goto exit;

    copyData[0] = 2;
    if ( OK > ( status = DER_AddItemCopyData( pTemp, INTEGER, 1, copyData, NULL)))
        goto exit;

    /* serial number: either provided or generated by hashing the key */
    if (serialNumber && serialNumberLen)
    {
        if (serialNumberLen > SHA1_RESULT_SIZE)
        {
            serialNumberLen = SHA1_RESULT_SIZE;
        }
        /* if sign bit is set, add an extra 0 byte */
        if ( 0x80 & (*serialNumber) )
        {
            serialNr[0] = 0;
            if (SHA1_RESULT_SIZE == serialNumberLen)
            {
                --serialNumberLen;
            }
            DIGI_MEMCPY(serialNr + 1, serialNumber, serialNumberLen);
            ++serialNumberLen;
        }
        else
        {
            /* serial number is 20 bytes at most -> truncate if necessary */
            DIGI_MEMCPY(serialNr, serialNumber, serialNumberLen);
        }
    }
    else
    {
        status = ASN1CERT_sha1PublicKey(MOC_ASYM(hwAccelCtx) (AsymmetricKey *) pCertKey, serialNr);
        if (OK != status)
            goto exit;

        serialNumberLen = SHA1_RESULT_SIZE;

        /* no space left, so make sure sign bit (first bit) is zero */
        serialNr[0] &= 0x7F;
        if (0 == serialNr[0])
        {
            /* make sure the first bit of next byte is not zero */
            serialNr[1] |= 0x80;
        }
    }

    if ( OK > (status = DER_AddItem( pCertificate, INTEGER, serialNumberLen, serialNr, NULL)))
        goto exit;

    /* signature */
#ifdef __ENABLE_DIGICERT_PKCS1__
    if (NULL != pSignKey->pAlgoId && ALG_ID_RSA_SSA_PSS_OID == pSignKey->pAlgoId->oidFlag)
    {   
        status = ALG_ID_serializeAlloc(pSignKey->pAlgoId, &pAlgIdBuff, &algIdBuffLen);
        if (OK != status)
            goto exit;

        status = DER_AddDERBufferOwn( pCertificate, algIdBuffLen, (const ubyte **) &pAlgIdBuff, NULL );
        if (OK != status)
            goto exit; 
    }
    else
#endif
    {
        if ( OK > ( status = DER_StoreAlgoOID( pCertificate, signAlgoOID, akt_rsa == (pSignKey->type & 0xff))))
            goto exit;
    }

    /* issuer */
    if (pIssuerInfo)
    {
        issuerMemAccessBuffer = (const ubyte*) CS_memaccess( cs,
                                                            pIssuerInfo->dataOffset,
                                                            pIssuerInfo->length);
        if ( !issuerMemAccessBuffer)
        {
            status = ERR_MEM_ALLOC_FAIL;
            goto exit;
        }
        if ( OK > ( status = DER_AddItem( pCertificate, (CONSTRUCTED|SEQUENCE),
                                         pIssuerInfo->length,
                                         issuerMemAccessBuffer, NULL)))
        {
            goto exit;
        }
    }
    else /* self signed: issuer = subject */
    {
        if ( OK > ( status = ASN1CERT_StoreDistinguishedName( pCertificate,
                                                             pSubjectInfo)))
        {
            goto exit;
        }
    }

    /* validity */
    if ( OK > ( status = DER_AddSequence( pCertificate, &pTemp)))
        goto exit;

    /* Convert dates to TimeDate object so DER_AddTime can correctly handle the form */
    if (NULL != pSubjectInfo->pStartDate && NULL != pSubjectInfo->pEndDate)
    {
        (void) DATETIME_convertFromValidityString(pSubjectInfo->pStartDate, &date); /* return is always OK */

        if ( OK > ( status = DER_AddTime( pTemp, &date, NULL)))
            goto exit;

        (void) DATETIME_convertFromValidityString(pSubjectInfo->pEndDate, &date);

        if ( OK > ( status = DER_AddTime( pTemp, &date, NULL)))
            goto exit;
    }

    /* subject */
    if ( OK > ( status = ASN1CERT_StoreDistinguishedName( pCertificate, pSubjectInfo)))
        goto exit;

    /* subject public key info, send a separete pointer for a new buffer in case the pub key has an algoId */
    if ( OK > ( status = ASN1CERT_storePublicKeyInfo(MOC_ASYM(hwAccelCtx) pCertKey, pCertificate)))
        goto exit;

    if ( pExtensions)
    {
        if ( OK > ( status = ASN1CERT_AddExtensionsToTBSCertificate( pCertificate,  pExtensions)))
            goto exit;
    }

    /* now sign (multiple copies of the same hwAccelCtx passed in for potentially different uses) */
    if  (OK > ( status = ASN1CERT_Sign( MOC_ASYM(hwAccelCtx)
                                       pSignedCertificate, pSignKey, signAlgo,
                                       rngFun, rngFunArg,
                                       ppRetCertificate, pRetCertLength)))
    {
        goto exit;
    }

exit:

    if (NULL != pAlgIdBuff)
    {
        (void) DIGI_MEMSET_FREE(&pAlgIdBuff, algIdBuffLen);
    }

    if (issuerMemAccessBuffer)
    {
        CS_stopaccess( cs, issuerMemAccessBuffer);
    }

    if ( pSignedCertificate)
    {
        TREE_DeleteTreeItem( (TreeItem*) pSignedCertificate);
    }

    return status;

} /* ASN1CERT_generateCertificate */



/*------------------------------------------------------------------*/

extern MSTATUS
ASN1CERT_generateCertificate(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pCertKey,
                                    const certDistinguishedName *pSubjectInfo,
                                    const AsymmetricKey *pSignKey, const ASN1_ITEM *pIssuerInfo,
                                    CStream cs, ubyte signAlgo, const certExtensions* pExtensions,
                                    RNGFun rngFun, void* rngFunArg,
                                    ubyte **ppRetCertificate, ubyte4 *pRetCertLength)
{
    return ASN1CERT_generateCertificateEx(MOC_ASYM(hwAccelCtx) pCertKey,
                                          pSubjectInfo, pSignKey, pIssuerInfo, cs,
                                          NULL, 0, signAlgo, pExtensions,
                                          rngFun, rngFunArg, ppRetCertificate,
                                          pRetCertLength);

} /* ASN1CERT_generateCertificate */


/*------------------------------------------------------------------*/

extern MSTATUS
ASN1CERT_generateSelfSignedCertificate(MOC_ASYM(hwAccelDescr hwAccelCtx) AsymmetricKey *pCertKey,
                             const certDistinguishedName *pSubjectInfo,
                             ubyte signAlgo, const certExtensions* pExtensions,
                             RNGFun rngFun, void* rngFunArg,
                             ubyte **ppRetCertificate, ubyte4 *pRetCertLength)
{
    CStream cs = { 0 };

    return ASN1CERT_generateCertificateEx(MOC_ASYM(hwAccelCtx) pCertKey,
                                          pSubjectInfo, 0, NULL, cs,
                                          NULL, 0, signAlgo, pExtensions,
                                          rngFun, rngFunArg, ppRetCertificate,
                                          pRetCertLength);
} /* ASN1CERT_generateSelfSignedCertificate */

#endif /* __DISABLE_DIGICERT_CERTIFICATE_GENERATION__ */
