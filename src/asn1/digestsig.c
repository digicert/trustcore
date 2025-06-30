/*
 * digestsig.c
 *
 * Functions that get digest from sig AlgId.
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
#include "../asn1/mocasn1.h"
#include "../asn1/parseasn1.h"
#include "../crypto/crypto.h"

#if (!defined(__DISABLE_MOCANA_ASN1_GET_DIGEST_FROM_ALG_ID__))

/* Get the ht_ flag for the digest algorithm from the PSS algId.
 */
MSTATUS GetDigestFromPss (
  ubyte *pSigAlgId,
  ubyte4 sigAlgIdLen,
  ubyte4 *pDigestAlg
  );

MOC_EXTERN MSTATUS ASN1_getDigestFromSigAlgId (
  ubyte *pSigAlgId,
  ubyte4 sigAlgIdLen,
  ubyte *pDigestAlgId,
  ubyte4 bufferSize,
  ubyte4 *pDigestAlgIdLen,
  ubyte **ppDigestOid,
  ubyte4 *pDigestOidLen,
  ubyte4 *pDigestLen
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  ubyte4 index, bufSize, lastByte, digestAlg;
  /* If more signature OIDs come down the road, bupdate this list.
   */
#define MOP_SIG_ALG_ID_COUNT    6
#define MOP_RSA_SHA1_P1_INDEX   0
#define MOP_DSA_SHA1_INDEX      1
#define MOP_DSA_SHA224_INDEX    2
#define MOP_ECDSA_SHA1_INDEX    3
#define MOP_ECDSA_SHA224_INDEX  4
#define MOP_HMAC_INDEX          5
  ubyte pRsaSha1[MOP_RSA_SHA1_P1_OID_LEN] = {
    MOP_RSA_SHA1_P1_OID
  };
  ubyte pDsaSha1[MOP_DSA_SHA1_ALG_ID_LEN] = {
    MOP_DSA_SHA1_ALG_ID
  };
  ubyte pDsaSha224[MOP_DSA_SHA224_ALG_ID_LEN] = {
    MOP_DSA_SHA224_ALG_ID
  };
  ubyte pEcdsaSha1[MOP_ECDSA_SHA1_ALG_ID_LEN] = {
    MOP_ECDSA_SHA1_ALG_ID
  };
  ubyte pEcdsaSha224[MOP_ECDSA_SHA224_ALG_ID_LEN] = {
    MOP_ECDSA_SHA224_ALG_ID
  };
  ubyte pHmac[MOP_HMAC_ALG_ID_LEN] = {
    MOP_HMAC_ALG_ID
  };
  ubyte *pList[MOP_SIG_ALG_ID_COUNT];
  ubyte4 pLenList[MOP_SIG_ALG_ID_COUNT];

  pList[MOP_RSA_SHA1_P1_INDEX] = pRsaSha1;
  pLenList[MOP_RSA_SHA1_P1_INDEX] = MOP_RSA_SHA1_P1_OID_LEN;
  pList[MOP_DSA_SHA1_INDEX] = pDsaSha1;
  pLenList[MOP_DSA_SHA1_INDEX] = MOP_DSA_SHA1_ALG_ID_LEN;
  pList[MOP_DSA_SHA224_INDEX] = pDsaSha224;
  pLenList[MOP_DSA_SHA224_INDEX] = MOP_DSA_SHA224_ALG_ID_LEN;
  pList[MOP_ECDSA_SHA1_INDEX] = pEcdsaSha1;
  pLenList[MOP_ECDSA_SHA1_INDEX] = MOP_ECDSA_SHA1_ALG_ID_LEN;
  pList[MOP_ECDSA_SHA224_INDEX] = pEcdsaSha224;
  pLenList[MOP_ECDSA_SHA224_INDEX] = MOP_ECDSA_SHA224_ALG_ID_LEN;
  pList[MOP_HMAC_INDEX] = pHmac;
  pLenList[MOP_HMAC_INDEX] = MOP_HMAC_ALG_ID_LEN;

  status = ERR_NULL_POINTER;
  if ( (NULL == pSigAlgId) || (0 == sigAlgIdLen) )
    goto exit;

  bufSize = 0;
  if (NULL != pDigestAlgId)
    bufSize = bufferSize;

  /* Cycle through the known sig algIds.
   */
  lastByte = 0;
  for (index = 0; index < MOP_SIG_ALG_ID_COUNT; ++index)
  {
    status = ASN1_compareOID (
      pList[index], pLenList[index], pSigAlgId, sigAlgIdLen, &lastByte,
      &cmpResult);
    if (OK != status)
      goto exit;

    if (0 == cmpResult)
      break;
  }

  status = ERR_UNSUPPORTED_OPERATION;
  switch (index)
  {
    default:
      /* If we went through the list without a match, error.
       */
      goto exit;

    case MOP_RSA_SHA1_P1_INDEX:
      /* This is RSA with SHA-1. Except the last byte can indicate SHA-1 to
       * SHA-512 and even PSS.
       */
      switch (lastByte)
      {
        default:
          goto exit;

        case MOP_RSA_SHA1_BYTE:
          digestAlg = ht_sha1;
          break;

        case MOP_RSA_SHA256_BYTE:
          digestAlg = ht_sha256;
          break;

        case MOP_RSA_SHA384_BYTE:
          digestAlg = ht_sha384;
          break;

        case MOP_RSA_SHA512_BYTE:
          digestAlg = ht_sha512;
          break;

        case MOP_RSA_PSS_BYTE:
          status = GetDigestFromPss (
            pSigAlgId, sigAlgIdLen, &digestAlg);
          if (OK != status)
            goto exit;
      }

      break;

    case MOP_DSA_SHA1_INDEX:
      if (MOP_DSA_SHA1_BYTE != lastByte)
        goto exit;

      digestAlg = ht_sha1;
      break;

    case MOP_DSA_SHA224_INDEX:
      /* This is DSA with SHA-224, except the last byte could also indicate
       * SHA-256.
       */
      digestAlg = ht_sha224;
      if (MOP_DSA_SHA224_BYTE != lastByte)
      {
        if (MOP_DSA_SHA256_BYTE != lastByte)
          goto exit;

        digestAlg = ht_sha256;
      }
      break;

    case MOP_ECDSA_SHA1_INDEX:
      if (MOP_ECDSA_SHA1_BYTE != lastByte)
        goto exit;

      digestAlg = ht_sha1;
      break;

    case MOP_ECDSA_SHA224_INDEX:
      /* This is ECDSA with SHA-224, except the last byte could also indicate
       * SHA-256 to SHA-512
       */
      switch (lastByte)
      {
        default:
          goto exit;

        case MOP_ECDSA_SHA224_BYTE:
          digestAlg = ht_sha224;
          break;

        case MOP_ECDSA_SHA256_BYTE:
          digestAlg = ht_sha256;
          break;

        case MOP_ECDSA_SHA384_BYTE:
          digestAlg = ht_sha384;
          break;

        case MOP_ECDSA_SHA512_BYTE:
          digestAlg = ht_sha512;
          break;
      }
      break;

    case MOP_HMAC_INDEX:
      /* This is HMAC, the last byte indicates which digest alg.
       */
      switch (lastByte)
      {
        default:
          goto exit;

        case MOP_HMAC_SHA1_LAST_BYTE:
          digestAlg = ht_sha1;
          break;

        case MOP_HMAC_SHA224_LAST_BYTE:
          digestAlg = ht_sha224;
          break;

        case MOP_HMAC_SHA256_LAST_BYTE:
          digestAlg = ht_sha256;
          break;

        case MOP_HMAC_SHA384_LAST_BYTE:
          digestAlg = ht_sha384;
          break;

        case MOP_HMAC_SHA512_LAST_BYTE:
          digestAlg = ht_sha512;
          break;
      }
      break;
  }

  status = ASN1_getDigestAlgIdFromFlag (
    digestAlg, pDigestAlgId, bufSize, pDigestAlgIdLen,
    ppDigestOid, pDigestOidLen, pDigestLen);

exit:

  return (status);
}

MSTATUS GetDigestFromPss (
  ubyte *pSigAlgId,
  ubyte4 sigAlgIdLen,
  ubyte4 *pDigestAlg
  )
{
  MSTATUS status;
  ubyte4 bytesRead;
  MAsn1Element *pArray = NULL;
  MAsn1TypeAndCount pTemplate[7] = {
    { MASN1_TYPE_SEQUENCE, 2 },
      { MASN1_TYPE_OID, 0 },
      { MASN1_TYPE_SEQUENCE, 4 },
        { MASN1_TYPE_ENCODED | MASN1_EXPLICIT | MASN1_DEFAULT, 0 },
        { MASN1_TYPE_ENCODED | MASN1_EXPLICIT | MASN1_DEFAULT | 1, 0 },
        { MASN1_TYPE_INTEGER | MASN1_EXPLICIT | MASN1_DEFAULT | 2, 0 },
        { MASN1_TYPE_INTEGER | MASN1_EXPLICIT | MASN1_DEFAULT | 3, 0 }
  };

  status = MAsn1CreateElementArray (
    pTemplate, 7, MASN1_FNCT_DECODE, MAsn1OfFunction, &pArray);
  if (OK != status)
    goto exit;

  status = MAsn1Decode (pSigAlgId, sigAlgIdLen, pArray, &bytesRead);
  if (OK != status)
    goto exit;

  /* If there is no digest algorithm specified, return SHA-1.
   */
  *pDigestAlg = ht_sha1;
  if (NULL != pArray[3].value.pValue)
  {
    status = ASN1_getDigestFlagFromOid (
      pArray[3].value.pValue, pArray[3].valueLen, pDigestAlg);
  }

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }

  return (status);
}

#endif /* (!defined(__DISABLE_MOCANA_ASN1_GET_DIGEST_FROM_ALG_ID__)) */
