/*
 * parsecert.c
 *
 * Functions for parsing a cert.
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

#include "../../crypto/certops.h"
#include "../../common/base64.h"
#include "../../crypto/certops/certobj.h"

extern MSTATUS X509_parseCert (
  ubyte *pCert,
  ubyte4 certLen,
  MCertObj *ppCertObj
  )
{
  MSTATUS status;
  ubyte4 pemType, derLen, bytesRead;
  ubyte *pDer = NULL;
  MAsn1Element *pArray = NULL;
#define MOC_CERT_TEMPLATE_COUNT 32
  MAsn1TypeAndCount pTemplate[MOC_CERT_TEMPLATE_COUNT] = {
    { MASN1_TYPE_SEQUENCE, 3 },
      { MASN1_TYPE_SEQUENCE, 10 },                  /* TBSCertificate */
        { MASN1_TYPE_INTEGER | MASN1_EXPLICIT | MASN1_DEFAULT, 0 },  /* version */
        { MASN1_TYPE_INTEGER, 0 },                  /* SerialNum */
        { MASN1_TYPE_ENCODED, 0 },                  /* Sig AlgId */
        { MASN1_TYPE_SEQUENCE_OF, 1 },              /* Issuer Name */
          { MASN1_TYPE_SET_OF, 1 },                 /* RDN */
            { MASN1_TYPE_SEQUENCE, 2 },
              { MASN1_TYPE_OID, 0 },
              { MASN1_TYPE_ENCODED, 0 },
        { MASN1_TYPE_SEQUENCE, 2 },                 /* Validity */
          { MASN1_TYPE_ANY_TIME, 0 },
          { MASN1_TYPE_ANY_TIME, 0 },
        { MASN1_TYPE_SEQUENCE_OF, 1 },              /* Subject Name */
          { MASN1_TYPE_SET_OF, 1 },                 /* RDN */
            { MASN1_TYPE_SEQUENCE, 2 },
              { MASN1_TYPE_OID, 0 },
              { MASN1_TYPE_ENCODED, 0 },
        { MASN1_TYPE_SEQUENCE, 2 },                 /* key */
          { MASN1_TYPE_SEQUENCE, 2 },               /* key algID */
            { MASN1_TYPE_OID, 0 },                  /* key OID */
            { MASN1_TYPE_ENCODED | MASN1_OPTIONAL, 0 },
          { MASN1_TYPE_BIT_STRING, 0 },
        { MASN1_TYPE_BIT_STRING | MASN1_IMPLICIT | MASN1_OPTIONAL | 1, 0 },
        { MASN1_TYPE_BIT_STRING | MASN1_IMPLICIT | MASN1_OPTIONAL | 2, 0 },
        { MASN1_TYPE_SEQUENCE_OF | MASN1_EXPLICIT | MASN1_OPTIONAL | 3, 1 },
            { MASN1_TYPE_SEQUENCE, 3 },
              { MASN1_TYPE_OID, 0 },
              { MASN1_TYPE_BOOLEAN | MASN1_DEFAULT, 0 },
              { MASN1_TYPE_OCTET_STRING, 0 },
      { MASN1_TYPE_ENCODED, 0 },                    /* Sig AlgId */
      { MASN1_TYPE_BIT_STRING, 0 }                  /* signature */
  };

  status = ERR_NULL_POINTER;
  if ( (NULL == pCert) || (0 == certLen) || (NULL == ppCertObj) )
    goto exit;

  /* If the request is PEM, Base64 decode it.
   * If it is DER, copy it. We'll need a copy for the object, we need it to
   * remain alive as long as the object is alive.
   */
  derLen = certLen;
  if (0x30 != pCert[0])
  {
    status = BASE64_decodePemMessageAlloc (
      pCert, certLen, &pemType, &pDer, &derLen);
    if (OK != status)
      goto exit;
  }
  else
  {
    status = DIGI_MALLOC_MEMCPY (
      (void **)&pDer, certLen, pCert, certLen);
    if (OK != status)
      goto exit;
  }

  /* Decode the cert.
   */
  status = MAsn1CreateElementArray (
    pTemplate, MOC_CERT_TEMPLATE_COUNT, MASN1_FNCT_DECODE, MAsn1OfFunction,
    &pArray);
  if (OK != status)
    goto exit;

  status = MAsn1Decode (pDer, derLen, pArray, &bytesRead);
  if (OK != status)
    goto exit;

  /* Now store the decoded cert as an object.
   */
  status = MCreateCertObj (
    MOC_CERT_OBJ_TYPE_CERT, &pDer, derLen, &pArray,
    (MCertOrRequestObject **)ppCertObj, NULL);

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }
  if (NULL != pDer)
  {
    DIGI_FREE ((void **)&pDer);
  }

  return (status);
}

extern MSTATUS X509_freeCertObject (
  MCertObj *ppCertObj,
  struct vlong **ppVlongQueue
  )
{
  return (MFreeCertObj ((MCertOrRequestObject **)ppCertObj, ppVlongQueue));
}

