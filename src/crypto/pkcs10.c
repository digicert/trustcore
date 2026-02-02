/*
 * pkcs10.c
 *
 * PKCS #10
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

/**
@file       pkcs10.c
@brief      Mocana SoT Platform PKCS&nbsp;\#10 functions.
@details    This file contains PKCS&nbsp;\#10 functions.

@since 2.02
@version 6.4 and later

@flags
To use this file's functions, the following flag must be defined:
+ \c \__ENABLE_DIGICERT_PKCS10__

@filedoc    pkcs10.c
*/

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mocana.h"
#include "../crypto/hw_accel.h"

#ifdef __ENABLE_DIGICERT_PKCS10__

#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../crypto/secmod.h"
#include "../common/mrtos.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../common/utils.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../crypto/sha1.h"
#include "../crypto/primefld.h"
#include "../crypto/primeec.h"
#include "../crypto/pubcrypto.h"
#include "../crypto/rsa.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../asn1/derencoder.h"
#include "../crypto/ca_mgmt.h"
#include "../crypto/asn1cert.h"
#include "../crypto/md5.h"
#include "../common/base64.h"
#include "../crypto/crypto.h"
#include "../common/memfile.h"
#include "../crypto/asn1cert.h"
#include "../crypto/pkcs10.h"
#include "../harness/harness.h"

/*------------------------------------------------------------------*/

#ifndef CSR_LINE_LENGTH
#define CSR_LINE_LENGTH     64
#endif

#define BEGIN_CSR_BLOCK     "-----BEGIN CERTIFICATE REQUEST-----\x0d\x0a"
#define END_CSR_BLOCK       "-----END CERTIFICATE REQUEST-----\x0d\x0a"


/*---------------------------------------------------------------------------*/

static MSTATUS PKCS10_AddRequestAttributesEx (
  DER_ITEMPTR pCertificationRequestInfo,
  const requestAttributesEx *pReqAttrs
  )
{
  MSTATUS         status;
  ubyte4          index;
  ubyte          *pBuffer = NULL;
  DER_ITEMPTR     pReqAttrsItem, pTempItem;

  /* add tag and optional attributes
   * The attributes are not OPTIONAL, so we need the tag (IMPLICIT [0]).
   * But if there are no attributes, that's all we need and we're done.
   */
  status = DER_AddTag (pCertificationRequestInfo, 0, &pReqAttrsItem);
  if (OK != status)
    goto exit;

  /* any attributes?
   */
  if (NULL == pReqAttrs)
    goto exit;

  /* add challengePassword if present
   */
  if (pReqAttrs->challengePwdLength > 0)
  {
    status = DER_AddSequence (pReqAttrsItem, &pTempItem);
    if (OK != status)
      goto exit;

    status = DER_AddOID (pTempItem, pkcs9_challengePassword_OID, NULL);
    if (OK != status)
      goto exit;

    status = DER_AddSet (pTempItem, &pTempItem);
    if (OK != status)
      goto exit;

    status = DER_AddItemCopyData (
      pTempItem, PRINTABLESTRING, pReqAttrs->challengePwdLength,
      (ubyte *)(pReqAttrs->pChallengePwd), NULL);
    if (OK != status)
      goto exit;
  }

  /* If there are any more attributes, add them.
   */
  for (index = 0; index < pReqAttrs->otherAttrCount; ++index)
  {
    /* An attribute is SEQUENCE {
     *   OID,
     *   value }
     * The Ex struct requires the value to already be encoded.
     */
    status = DER_AddSequence (pReqAttrsItem, &pTempItem);
    if (OK != status)
      goto exit;

    /* Copy the OID. The DER_AddOID simply copies a reference to the buffer, but
     * we can't guarantee the input buffer will be around after we return.
     */
    status = DER_AddItemCopyData (
      pTempItem, OID, (ubyte4)(pReqAttrs->pOtherAttrs[index].oid[0]),
      pReqAttrs->pOtherAttrs[index].oid + 1, NULL);
    if (OK != status)
      goto exit;

    status = DER_AddSet (pTempItem, &pTempItem);
    if (OK != status)
      goto exit;

    /* Once again we need to copy the value, not just a reference.
     */
    status = DIGI_MALLOC (
      (void **)&pBuffer, pReqAttrs->pOtherAttrs[index].valueLen);
    if (OK != status)
      goto exit;

    status = DIGI_MEMCPY (
      (void *)pBuffer, (void *)(pReqAttrs->pOtherAttrs[index].pValue),
      pReqAttrs->pOtherAttrs[index].valueLen);
    if (OK != status)
      goto exit;

    status = DER_AddDERBufferOwn (
      pTempItem, pReqAttrs->pOtherAttrs[index].valueLen,
      (const ubyte **)&pBuffer, NULL);
    if (OK != status)
      goto exit;
  }

  /* add extensions if present,
   * if not, we're done.
   */
  if (NULL == pReqAttrs->pExtensions)
    goto exit;

  /* extensionRequest ATTRIBUTE ::= {
   *   WITH SYNTAX ExtensionRequest
   *   SINGLE VALUE TRUE
   *   ID pkcs-9-at-extensionRequest
   * }
   *
   * ExtensionRequest ::= Extensions
   */
  status = DER_AddSequence (pReqAttrsItem, &pTempItem);
  if (OK != status)
    goto exit;

  status = DER_AddOID (pTempItem, pkcs9_extensionRequest_OID, NULL);
  if (OK != status)
    goto exit;

  status = DER_AddSet (pTempItem, &pTempItem);
  if (OK != status)
    goto exit;

  status = ASN1CERT_AddExtensions (pTempItem, pReqAttrs->pExtensions, NULL);

exit:

  if (NULL != pBuffer)
  {
    DIGI_FREE ((void **)&pBuffer);
  }

  return (status);
}

static MSTATUS
  PKCS10_AddRequestAttributes(DER_ITEMPTR pCertificationRequestInfo,
  const requestAttributes* pReqAttrs)
{
  requestAttributesEx reqAttrEx;

  /* Anything to add?
   */
  if (NULL == pReqAttrs)
    return (OK);

  /* "Convert" the requestAttributes into requestAttributesEx and call the Ex
   * version.
   */
  reqAttrEx.pChallengePwd = pReqAttrs->pChallengePwd;
  reqAttrEx.challengePwdLength = pReqAttrs->challengePwdLength;
  reqAttrEx.pExtensions = pReqAttrs->pExtensions;
  reqAttrEx.pOtherAttrs = NULL;
  reqAttrEx.otherAttrCount = 0;

  return (PKCS10_AddRequestAttributesEx (
    pCertificationRequestInfo, &reqAttrEx));
}

/*---------------------------------------------------------------------------*/

static MSTATUS
PKCS10_breakIntoLines(ubyte* pLineCsr, ubyte4 lineCsrLength,
                      ubyte **ppRetCsr, ubyte4 *p_retCsrLength)
{
    ubyte*  pBlockCSR = NULL;
    ubyte*  pTempLineCsr;
    ubyte4  numLines;

    /* break the data up into (CSR_LINE_LENGTH) sized blocks */
    numLines     = ((lineCsrLength + (CSR_LINE_LENGTH - 1)) / CSR_LINE_LENGTH);
    pTempLineCsr = pLineCsr;

    /* calculate the new block length */
    *p_retCsrLength = (sizeof(BEGIN_CSR_BLOCK) - 1) + lineCsrLength + numLines + numLines + (sizeof(END_CSR_BLOCK) - 1);

    /* allocate the new csr block */
    if (NULL == (*ppRetCsr = pBlockCSR = MALLOC(*p_retCsrLength)))
    {
        return ERR_MEM_ALLOC_FAIL;
    }

    /* copy the start of block identifier */
    DIGI_MEMCPY(pBlockCSR, (const ubyte *)BEGIN_CSR_BLOCK, (sizeof(BEGIN_CSR_BLOCK) - 1));
    pBlockCSR += (sizeof(BEGIN_CSR_BLOCK) - 1);

    /* copy contiguous blocks of data */
    while (1 < numLines)
    {
        DIGI_MEMCPY(pBlockCSR, pTempLineCsr, CSR_LINE_LENGTH);
        pBlockCSR[CSR_LINE_LENGTH] = MOC_CR;
        pBlockCSR[CSR_LINE_LENGTH + 1] = LF;

        pBlockCSR += CSR_LINE_LENGTH + 2;
        pTempLineCsr += CSR_LINE_LENGTH;
        lineCsrLength -= CSR_LINE_LENGTH;

        numLines--;
    }

    /* copy any remaining bytes */
    if (lineCsrLength)
    {
        DIGI_MEMCPY(pBlockCSR, pTempLineCsr, lineCsrLength);
        pBlockCSR += lineCsrLength;

        *pBlockCSR = MOC_CR; pBlockCSR++;
        *pBlockCSR = LF; pBlockCSR++;
    }

    /* copy the end of block identifier */
    DIGI_MEMCPY(pBlockCSR, (const ubyte *)END_CSR_BLOCK, (sizeof(END_CSR_BLOCK) - 1));

    return OK;
}


/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
PKCS10_GenerateCertReqFromDN(AsymmetricKey* pKey, ubyte signAlgo,
                             const certDistinguishedName *pCertInfo,
                             const requestAttributes *pReqAttrs, /* can be null */
                             ubyte** ppCertReq, ubyte4* pCertReqLength)
{
  requestAttributesEx reqAttrEx;
  requestAttributesEx *pAttrs = NULL;

  /* "Convert" the requestAttributes into requestAttributesEx if there are any,
   * and call the Ex version.
   */
  if (NULL != pReqAttrs)
  {
    reqAttrEx.pChallengePwd = pReqAttrs->pChallengePwd;
    reqAttrEx.challengePwdLength = pReqAttrs->challengePwdLength;
    reqAttrEx.pExtensions = pReqAttrs->pExtensions;
    reqAttrEx.pOtherAttrs = NULL;
    reqAttrEx.otherAttrCount = 0;

    pAttrs = &reqAttrEx;
  }

  return (PKCS10_GenerateCertReqFromDNEx (
    pKey, signAlgo, pCertInfo, pAttrs, ppCertReq, pCertReqLength));
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS PKCS10_GenerateCertReqFromDNEx2(
  AsymmetricKey *pKey,
  ubyte signAlgo,
  const certDistinguishedName *pCertInfo,
  const requestAttributesEx *pReqAttrs,
  ubyte **ppCertReq,
  ubyte4 *pCertReqLength
  )
{
  MSTATUS         status;
  DER_ITEMPTR     pCertificationRequest = NULL;
  DER_ITEMPTR     pCertificationRequestInfo = NULL;
  hwAccelDescr    hwAccelCtx;
  ubyte           copyData[MAX_DER_STORAGE];
  DER_ITEMPTR     pTemp = NULL;

  status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL (MOCANA_MSS, &hwAccelCtx);
  if (OK != status)
    goto no_channel;

  /* Create the
   *   CertificationRequest ::= SEQUENCE {
   *     certRequestInfo,
   *     signatureAlgorithm,
   *     signature }
   */
  status = DER_AddSequence (NULL, &pCertificationRequest);
  if (OK != status)
    goto exit;

  /* CertificationRequestInfo {
   *   version,
   *   Name,
   *   subjectPublicKey,
   *   attributes [0] }
   */
  status = DER_AddSequence (pCertificationRequest, &pCertificationRequestInfo);
  if (OK != status)
    goto exit;

  copyData[0] = 0;
  status = DER_AddItemCopyData (
    pCertificationRequestInfo, INTEGER, 1, copyData, NULL);
  if (OK != status)
    goto exit;

  status = ASN1CERT_StoreDistinguishedName (
    pCertificationRequestInfo, pCertInfo);
  if (OK != status)
    goto exit;

  if (NULL != pKey)
  {
    status = ASN1CERT_storePublicKeyInfo (MOC_ASYM(hwAccelCtx) pKey, pCertificationRequestInfo);
    if (OK != status)
      goto exit;
  }
  else
  {
    status = DER_AddSequence(pCertificationRequestInfo, &pTemp);
    if (OK != status)
      goto exit;
  }

  if (NULL != pReqAttrs)
  {
    status = PKCS10_AddRequestAttributesEx (pCertificationRequestInfo, pReqAttrs);
    if (status != 0)
      goto exit;
  }

  if (NULL != pKey)
  {
    /* This will sign and add the signature alg ID.
     */
    status = ASN1CERT_Sign (MOC_ASYM(hwAccelCtx)
      pCertificationRequest, pKey, signAlgo,
      RANDOM_rngFun, g_pRandomContext, ppCertReq, pCertReqLength);
  }
  else
  {
    /* Return the DER encoded CSR without signature.
     */
    status = DER_Serialize (pCertificationRequest, ppCertReq, pCertReqLength);
  }

exit:

  if (pCertificationRequest)
  {
    TREE_DeleteTreeItem ((TreeItem *)pCertificationRequest);
  }

no_channel:

  HARDWARE_ACCEL_CLOSE_CHANNEL (MOCANA_MSS, &hwAccelCtx);

  return (status);
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS PKCS10_GenerateCertReqFromDNEx (
  AsymmetricKey *pKey,
  ubyte signAlgo,
  const certDistinguishedName *pCertInfo,
  const requestAttributesEx *pReqAttrs,
  ubyte **ppCertReq,
  ubyte4 *pCertReqLength
  )
{
  MSTATUS status;

  if (NULL == pKey)
  {
    status = ERR_NULL_POINTER;
    goto exit;
  }

  status = PKCS10_GenerateCertReqFromDNEx2 (
    pKey, signAlgo, pCertInfo, pReqAttrs, ppCertReq, pCertReqLength);

exit:

  return status;
}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
PKCS10_GenerateCertReqFromASN1Name(AsymmetricKey* pKey, ubyte signAlgo,
                                   const ubyte* pASN1Name, ubyte4 asn1NameLen,
                                   const requestAttributes *pReqAttrs, /* can be null */
                                   ubyte** ppCertReq, ubyte4* pCertReqLength)
{
    hwAccelDescr    hwAccelCtx;
    DER_ITEMPTR     pCertificationRequest = 0;
    DER_ITEMPTR     pCertificationRequestInfo;
    ubyte           copyData[MAX_DER_STORAGE];
    MSTATUS         status = OK;

    if (OK > ( status = (MSTATUS)HARDWARE_ACCEL_OPEN_CHANNEL(MOCANA_MSS, &hwAccelCtx)))
        goto no_cleanup;

    if (OK > ( status = DER_AddSequence( NULL, &pCertificationRequest)))
        goto exit;

    if (OK > ( status = DER_AddSequence( pCertificationRequest, &pCertificationRequestInfo)))
        goto exit;

    copyData[0] = 0;
    if ( OK > ( status = DER_AddItemCopyData( pCertificationRequestInfo, INTEGER, 1, copyData, NULL)))
        goto exit;

    /* subject -- add the whole ASN1 sequence as is!*/
    if ( OK > ( status = DER_AddItem( pCertificationRequestInfo, (CONSTRUCTED|SEQUENCE), asn1NameLen,
                                     pASN1Name, NULL)))
    {
        goto exit;
    }

    if ( OK > ( status = ASN1CERT_storePublicKeyInfo(MOC_ASYM(hwAccelCtx) pKey, pCertificationRequestInfo)))
        goto exit;

    if (OK > ( status = PKCS10_AddRequestAttributes( pCertificationRequestInfo, pReqAttrs)))
        goto exit;

    /* add signature now */
    if ( OK > ( status = ASN1CERT_Sign(MOC_ASYM(hwAccelCtx) pCertificationRequest, pKey,
                                       signAlgo, RANDOM_rngFun, g_pRandomContext,
                                       ppCertReq, pCertReqLength)))
    {
        goto exit;
    }

exit:

    if ( pCertificationRequest)
    {
        TREE_DeleteTreeItem( (TreeItem*) pCertificationRequest);
    }

    HARDWARE_ACCEL_CLOSE_CHANNEL(MOCANA_MSS, &hwAccelCtx);

no_cleanup:
    return status;

}

/*---------------------------------------------------------------------------*/

MOC_EXTERN MSTATUS
PKCS10_CertReqToCSR( const ubyte* pCertReq, ubyte4 certReqLen,
                    ubyte** ppCsr, ubyte4* pCsrLength)
{
    MSTATUS status;
    ubyte* pLineCsr = 0;
    ubyte4 lineCsrLength;


    if (OK > (status = BASE64_encodeMessage(pCertReq, certReqLen,
                                            &pLineCsr, &lineCsrLength)))
    {
        goto exit;
    }

    if (OK > (status = PKCS10_breakIntoLines(pLineCsr, lineCsrLength,
                                             ppCsr, pCsrLength)))
    {
        goto exit;
    }

exit:

    if (pLineCsr)
    {
        FREE(pLineCsr);
    }

    return status;
}

#endif /* __ENABLE_DIGICERT_PKCS10__*/

