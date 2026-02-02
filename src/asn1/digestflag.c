/*
 * digestflag.c
 *
 * Functions that convert algId and OID to ht_ flag.
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
#include "../crypto/crypto.h"

#if (!defined(__DISABLE_DIGICERT_ASN1_GET_DIGEST_FLAG__))

extern MSTATUS ASN1_getDigestFlagFromOid (
  const ubyte *pDigestOid,
  ubyte4      oidLen,
  ubyte4      *pDigestAlg
  )
{
  MSTATUS status;
  sbyte4 cmpResult;
  ubyte4 lastByte;
  ubyte pMd2Oid[MOP_MD2_OID_LEN] = {
    MOP_MD2_OID
  };
  ubyte pSha1Oid[MOP_SHA1_OID_LEN] = {
    MOP_SHA1_OID
  };
  ubyte pSha224Oid[MOP_SHA224_OID_LEN] = {
    MOP_SHA224_OID
  };

  status = ERR_NULL_POINTER;
  if ( (NULL == pDigestOid) || (NULL == pDigestAlg) )
    goto exit;

  status = ASN1_compareOID (
    pSha1Oid, MOP_SHA1_OID_LEN, pDigestOid, oidLen, NULL, &cmpResult);
  if (OK != status)
    goto exit;

  *pDigestAlg = ht_sha1;
  if (0 == cmpResult)
    goto exit;

  *pDigestAlg = ht_none;
  status = ASN1_compareOID (
    pSha224Oid, MOP_SHA224_OID_LEN, pDigestOid, oidLen, &lastByte, &cmpResult);
  if (OK != status)
    goto exit;

  if (0 != cmpResult)
  {
    status = ASN1_compareOID (
      pMd2Oid, MOP_MD2_OID_LEN, pDigestOid, oidLen, &lastByte, &cmpResult);
    if (OK != status)
      goto exit;

    if (0 != cmpResult)
      goto exit;

    /* Change the last byte so it doesn't collide with the SHA bytes.
     */
    lastByte += 100;
  }

  switch (lastByte)
  {
    default:
      /* *pDigestAlg is currently at ht_none.
       */
      goto exit;

    case (MOP_MD2_LAST_BYTE + 100):
      *pDigestAlg = ht_md2;
      goto exit;

    case (MOP_MD4_LAST_BYTE + 100):
      *pDigestAlg = ht_md4;
      goto exit;

    case (MOP_MD5_LAST_BYTE + 100):
      *pDigestAlg = ht_md5;
      goto exit;

    case MOP_SHA224_LAST_BYTE:
      *pDigestAlg = ht_sha224;
      goto exit;

    case MOP_SHA256_LAST_BYTE:
      *pDigestAlg = ht_sha256;
      goto exit;

    case MOP_SHA384_LAST_BYTE:
      *pDigestAlg = ht_sha384;
      goto exit;

    case MOP_SHA512_LAST_BYTE:
      *pDigestAlg = ht_sha512;
      goto exit;

    case MOP_SHA3_224_LAST_BYTE:
      *pDigestAlg = ht_sha3_224;
      goto exit;

    case MOP_SHA3_256_LAST_BYTE:
      *pDigestAlg = ht_sha3_256;
      goto exit;

    case MOP_SHA3_384_LAST_BYTE:
      *pDigestAlg = ht_sha3_384;
      goto exit;

    case MOP_SHA3_512_LAST_BYTE:
      *pDigestAlg = ht_sha3_512;
      goto exit;

    case MOP_SHAKE128_LAST_BYTE:
      *pDigestAlg = ht_shake128;
      goto exit;

    case MOP_SHAKE256_LAST_BYTE:
      *pDigestAlg = ht_shake256;
      goto exit;
  }

exit:

  return (status);
}

extern MSTATUS ASN1_getDigestAlgIdFromFlag (
  ubyte4 digestAlg,
  ubyte *pDigestAlgId,
  ubyte4 bufferSize,
  ubyte4 *pDigestAlgIdLen,
  ubyte **ppDigestOid,
  ubyte4 *pDigestOidLen,
  ubyte4 *pDigestLen
  )
{
  MSTATUS status;
  ubyte4 index, algIdLen, oidLen, dLen;
  ubyte *pAlgId;
  ubyte pSha1AlgId[MOP_SHA1_ALG_ID_LEN] = {
    MOP_SHA1_ALG_ID
  };
  ubyte pSha224AlgId[MOP_SHA224_ALG_ID_LEN] = {
    MOP_SHA224_ALG_ID
  };
  ubyte pMd2AlgId[MOP_MD2_ALG_ID_LEN] = {
    MOP_MD2_ALG_ID
  };

  status = ERR_NULL_POINTER;
  if (NULL == pDigestAlgIdLen)
    goto exit;

  /* Init to SHA-224. If it is SHA-1, change everything, if another SHA, change
   * the last byte.
   */
  pAlgId = pSha224AlgId;
  algIdLen = MOP_SHA224_ALG_ID_LEN;
  oidLen = MOP_SHA224_OID_LEN;
  index = MOP_SHA224_OID_LEN + MOP_SHA224_OID_OFFSET - 1;
  switch (digestAlg)
  {
    default:
      status = ERR_INVALID_INPUT;
      goto exit;

    case ht_md2:
      pAlgId = pMd2AlgId;
      algIdLen = MOP_MD2_ALG_ID_LEN;
      oidLen = MOP_MD2_OID_LEN;
      dLen = 16;
      break;

    case ht_md4:
      pMd2AlgId[MOP_MD2_ALGID_LAST_BYTE_OFFSET] = MOP_MD4_LAST_BYTE;
      pAlgId = pMd2AlgId;
      algIdLen = MOP_MD2_ALG_ID_LEN; /* sme lengths as md2*/
      oidLen = MOP_MD2_OID_LEN;
      dLen = 16;
      break;

    case ht_md5:
      pMd2AlgId[MOP_MD2_ALGID_LAST_BYTE_OFFSET] = MOP_MD5_LAST_BYTE;
      pAlgId = pMd2AlgId;
      algIdLen = MOP_MD2_ALG_ID_LEN; /* sme lengths as md2*/
      oidLen = MOP_MD2_OID_LEN;
      dLen = 16;
      break;

    case ht_sha1:
      pAlgId = pSha1AlgId;
      algIdLen = MOP_SHA1_ALG_ID_LEN;
      oidLen = MOP_SHA1_OID_LEN;
      dLen = 20;
      break;

    case ht_sha224:
      dLen = 28;
      break;

    case ht_sha256:
      dLen = 32;
      pSha224AlgId[index] = MOP_SHA256_LAST_BYTE;
      break;

    case ht_sha384:
      dLen = 48;
      pSha224AlgId[index] = MOP_SHA384_LAST_BYTE;
      break;

    case ht_sha512:
      dLen = 64;
      pSha224AlgId[index] = MOP_SHA512_LAST_BYTE;
      break;

    case ht_sha3_224:
      dLen = 28;
      pSha224AlgId[index] = MOP_SHA3_224_LAST_BYTE;
      break;

    case ht_sha3_256:
      dLen = 32;
      pSha224AlgId[index] = MOP_SHA3_256_LAST_BYTE;
      break;

    case ht_sha3_384:
      dLen = 48;
      pSha224AlgId[index] = MOP_SHA3_384_LAST_BYTE;
      break;

    case ht_sha3_512:
      dLen = 64;
      pSha224AlgId[index] = MOP_SHA3_512_LAST_BYTE;
      break;

    case ht_shake128:
      dLen = 32;
      pSha224AlgId[index] = MOP_SHAKE128_LAST_BYTE;
      break;

    case ht_shake256:
      dLen = 64;
      pSha224AlgId[index] = MOP_SHAKE256_LAST_BYTE;
  }

  *pDigestAlgIdLen = algIdLen;
  status = ERR_BUFFER_TOO_SMALL;
  if (bufferSize < algIdLen)
    goto exit;

  status = DIGI_MEMCPY (
    (void *)pDigestAlgId, (void *)pAlgId, algIdLen);
  if (OK != status)
    goto exit;

  /* The OID always begins at pAlgId + 2 ( one byte for tag, one for length) */
  if (NULL != ppDigestOid)
    *ppDigestOid = pDigestAlgId + 2;
  if (NULL != pDigestOidLen)
    *pDigestOidLen = oidLen;
  if (NULL != pDigestLen)
    *pDigestLen = dLen;

exit:

  return (status);
}

#endif /* (!defined(__DISABLE_DIGICERT_ASN1_GET_DIGEST_FLAG__)) */
