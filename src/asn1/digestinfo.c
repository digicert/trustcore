/*
 * digestinfo.c
 *
 * Functions dealing with DigestInfo.
 *
 * Copyright 2025 DigiCert Project Authors. All Rights Reserved.
 * 
 * DigiCert® TrustCore and TrustEdge are licensed under a dual-license model:
 * - **Open Source License**: GNU AGPL v3. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE
 * - **Commercial License**: Available under DigiCert’s Master Services Agreement. See: https://github.com/digicert/trustcore-test/blob/main/LICENSE_COMMERCIAL.txt  
 *   or https://www.digicert.com/master-services-agreement/
 * 
 * For commercial licensing, contact DigiCert at sales@digicert.com.*
 *
 */

#include "../common/moptions.h"
#include "../common/mtypes.h"
#include "../common/mdefs.h"
#include "../common/merrors.h"
#include "../common/mocana.h"
#include "../common/mrtos.h"
#include "../common/mem_part.h"
#include "../common/mstdlib.h"
#include "../common/random.h"
#include "../common/vlong.h"
#include "../crypto/hw_accel.h"
#include "../common/tree.h"
#include "../common/absstream.h"
#include "../asn1/oiddefs.h"
#include "../asn1/parseasn1.h"
#include "../asn1/mocasn1.h"
#include "../crypto/crypto.h"

#if (!defined(__DISABLE_DIGICERT_ASN1_DIGEST_INFO__))

MOC_EXTERN MSTATUS ASN1_buildDigestInfoAlloc (
  const ubyte *pDigest,
  ubyte4      digestLen,
  ubyte4      digestAlg,
  ubyte       **ppDigestInfo,
  ubyte4      *pDigestInfoLen
  )
{
  MSTATUS status;
  ubyte4 algIdLen, dLen, encodingLen;
  ubyte *pNewBuf = NULL;
  ubyte pDigestAlgId[MOP_MAX_DIGEST_ALG_ID_LEN];
  MAsn1Element *pArray = NULL;
  MAsn1TypeAndCount pTemplate[3] = {
    { MASN1_TYPE_SEQUENCE, 2 },
      { MASN1_TYPE_ENCODED, 0 },
      { MASN1_TYPE_OCTET_STRING, 0 }
  };

  status = ERR_NULL_POINTER;
  if ( (NULL == pDigest) || (NULL == ppDigestInfo) ||
       (NULL == pDigestInfoLen) )
    goto exit;

  /* Which algorithm?
   */
  status = ASN1_getDigestAlgIdFromFlag (
    digestAlg, (ubyte *)pDigestAlgId, sizeof (pDigestAlgId),
    &algIdLen, NULL, NULL, &dLen);
  if (OK != status)
    goto exit;

  /* Make sure the digest length matches.
   */
  status = ERR_INVALID_INPUT;
  if (digestLen != dLen)
    goto exit;

  /* Encode this
   *   30 len
   *      AlgId
   *      04 len
   *         < digest >
   */
  status = MAsn1CreateElementArray (
    pTemplate, 3, MASN1_FNCT_ENCODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  pArray[1].value.pValue = pDigestAlgId;
  pArray[1].valueLen = algIdLen;
  pArray[1].state = MASN1_STATE_SET_COMPLETE;
  pArray[2].value.pValue = (ubyte *)pDigest;
  pArray[2].valueLen = digestLen;
  pArray[2].state = MASN1_STATE_SET_COMPLETE;

  status = MAsn1Encode (pArray, NULL, 0, &encodingLen);
  if (OK == status)
    status = ERR_INVALID_INPUT;
  if (ERR_BUFFER_TOO_SMALL != status)
    goto exit;

  status = DIGI_MALLOC ((void **)&pNewBuf, encodingLen);
  if (OK != status)
    goto exit;

  status = MAsn1Encode (pArray, pNewBuf, encodingLen, &encodingLen);
  if (OK != status)
    goto exit;

  *ppDigestInfo = pNewBuf;
  *pDigestInfoLen = encodingLen;
  pNewBuf = NULL;

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }
  if (NULL != pNewBuf)
  {
    DIGI_FREE ((void **)&pNewBuf);
  }

  return (status);
}

MOC_EXTERN MSTATUS ASN1_parseDigestInfo (
  ubyte *pDigestInfo,
  ubyte4 digestInfoLen,
  ubyte **ppOid,
  ubyte4 *pOidLen,
  ubyte **ppDigest,
  ubyte4 *pDigestLen,
  ubyte4 *pDigestAlg
  )
{
  MSTATUS status;
  ubyte4 bytesRead;
  MAsn1Element *pArray = NULL;
  MAsn1TypeAndCount pTemplate[5] = {
    { MASN1_TYPE_SEQUENCE, 2 },
      { MASN1_TYPE_SEQUENCE, 2 },
        { MASN1_TYPE_OID, 0 },
        { MASN1_TYPE_ENCODED | MASN1_OPTIONAL, 0 },
      { MASN1_TYPE_OCTET_STRING, 0 }
  };

  /* We're expecting
   *   SEQ {
   *     SEQ {
   *       OID
   *       params -- all supported will be nothing or 05 00 }
   *     OCTET STRING
   */
  status = MAsn1CreateElementArray (
    pTemplate, 5, MASN1_FNCT_DECODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  status = MAsn1Decode (pDigestInfo, digestInfoLen, pArray, &bytesRead);
  if (OK != status)
    goto exit;

  /* Get the ht_ flag for the algorithm.
   */
  status = ASN1_getDigestFlagFromOid (
    pArray[2].encoding.pEncoding, pArray[2].encodingLen, pDigestAlg);
  if (OK != status)
    goto exit;

  *ppOid = pArray[2].value.pValue;
  *pOidLen = pArray[2].valueLen;
  *ppDigest = pArray[4].value.pValue;
  *pDigestLen = pArray[4].valueLen;

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }

  return (status);
}

#endif /* (!defined(__DISABLE_DIGICERT_ASN1_DIGEST_INFO__)) */
