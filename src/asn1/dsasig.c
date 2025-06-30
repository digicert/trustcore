/*
 * dsasig.c
 *
 * Mocana Asymmetric functions encoding and decoding a DSA signature.
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

/* Convert the arrays into byte arrays, when the size of the ints are 4.
 * The lengths are likely the same, but can be different.
 * The caller must make sure the buffers are big enough (rLen * 4 and sLen * 4).
 * The function will place all the bytes into the output buffer, even leading 00
 * bytes.
 */
MSTATUS DsaSigConvertArray4 (
  ubyte4 *pRVal,
  ubyte4 rLen,
  ubyte *pBufR,
  ubyte4 *pSVal,
  ubyte4 sLen,
  ubyte *pBufS
  );

/* Same as DsaSigConvertArray4, except ubyte8 *.
 */
MSTATUS DsaSigConvertArray8 (
  ubyte8 *pRVal,
  ubyte4 rLen,
  ubyte *pBufR,
  ubyte8 *pSVal,
  ubyte4 sLen,
  ubyte *pBufS
  );

MOC_EXTERN MSTATUS ASN1_buildDsaSignature (
  void *pRVal,
  ubyte4 rLen,
  void *pSVal,
  ubyte4 sLen,
  ubyte4 intSize,
  ubyte *pSignature,
  ubyte4 bufferSize,
  ubyte4 *pSignatureLen
  )
{
  MSTATUS status;
  ubyte4 byteCount;
  ubyte *pRBytes, *pSBytes;
  ubyte *pBuf = NULL;
  MAsn1Element *pArray = NULL;
  MAsn1TypeAndCount pTemplate[3] = {
    { MASN1_TYPE_SEQUENCE, 2 },
      { MASN1_TYPE_INTEGER, 0 },
      { MASN1_TYPE_INTEGER, 0 }
  };

  /* Convert the values into canonical ints.
   */
  byteCount = (rLen * intSize) + (sLen * intSize);
  status = MOC_MALLOC ((void **)&pBuf, byteCount);
  if (OK != status)
    goto exit;

  pRBytes = pBuf;
  pSBytes = pBuf + (rLen * intSize);

  if (8 == intSize)
  {
    status = DsaSigConvertArray8 (
      (ubyte8 *)pRVal, rLen, pRBytes, (ubyte8 *)pSVal, sLen, pSBytes);
  }
  else
  {
    status = DsaSigConvertArray4 (
      (ubyte4 *)pRVal, rLen, pRBytes, (ubyte4 *)pSVal, sLen, pSBytes);
  }
  if (OK != status)
    goto exit;

  /* Now encode.
   */
  status = MAsn1CreateElementArray (
    pTemplate, 3, MASN1_FNCT_ENCODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  status = MAsn1SetInteger (
    pArray + 1, pRBytes, rLen * intSize, TRUE, 0);
  if (OK != status)
    goto exit;

  status = MAsn1SetInteger (
    pArray + 2, pSBytes, sLen * intSize, TRUE, 0);
  if (OK != status)
    goto exit;

  status = MAsn1Encode (pArray, pSignature, bufferSize, pSignatureLen);

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }
  if (NULL != pBuf)
  {
    MOC_FREE ((void **)&pBuf);
  }

  return (status);
}

extern MSTATUS ASN1_parseDsaSignature (
  ubyte *pSignature,
  ubyte4 signatureLen,
  ubyte **ppRVal,
  ubyte4 *pRValLen,
  ubyte **ppSVal,
  ubyte4 *pSValLen
  )
{
  MSTATUS status;
  ubyte4 bytesRead;
  MAsn1Element *pArray = NULL;
  MAsn1TypeAndCount pTemplate[3] = {
    { MASN1_TYPE_SEQUENCE, 2 },
      { MASN1_TYPE_INTEGER, 0 },
      { MASN1_TYPE_INTEGER, 0 }
  };

  status = MAsn1CreateElementArray (
    pTemplate, 3, MASN1_FNCT_DECODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  status = MAsn1Decode (
    pSignature, signatureLen, pArray, &bytesRead);
  if (OK != status)
    goto exit;

  *ppRVal = pArray[1].value.pValue;
  *pRValLen = pArray[1].valueLen;
  *ppSVal = pArray[2].value.pValue;
  *pSValLen = pArray[2].valueLen;

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }

  return (status);
}

MSTATUS DsaSigConvertArray4 (
  ubyte4 *pRVal,
  ubyte4 rLen,
  ubyte *pBufR,
  ubyte4 *pSVal,
  ubyte4 sLen,
  ubyte *pBufS
  )
{
  ubyte4 index, indexV, indexB, len;
  ubyte4 current;
  ubyte4 *pVal;
  ubyte *pBuf;

  pVal = pRVal;
  pBuf = pBufR;
  len = rLen;
  for (index = 0; index < 2; ++index)
  {
    if (index > 0)
    {
      pVal = pSVal;
      pBuf = pBufS;
      len = sLen;
    }

    indexB = 0;
    for (indexV = len; indexV > 0; --indexV)
    {
      current = pVal[indexV - 1];
      pBuf[indexB]     = (ubyte)(current >> 24);
      pBuf[indexB + 1] = (ubyte)(current >> 16);
      pBuf[indexB + 2] = (ubyte)(current >>  8);
      pBuf[indexB + 3] = (ubyte)(current);
      indexB += 4;
    }
  }

  return (OK);
}

MSTATUS DsaSigConvertArray8 (
  ubyte8 *pRVal,
  ubyte4 rLen,
  ubyte *pBufR,
  ubyte8 *pSVal,
  ubyte4 sLen,
  ubyte *pBufS
  )
{
  ubyte4 index, indexV, indexB, len;
  ubyte8 current;
  ubyte8 *pVal;
  ubyte *pBuf;

  pVal = pRVal;
  pBuf = pBufR;
  len = rLen;
  for (index = 0; index < 2; ++index)
  {
    if (index > 0)
    {
      pVal = pSVal;
      pBuf = pBufS;
      len = sLen;
    }

    indexB = 0;
    for (indexV = len; indexV > 0; --indexV)
    {
#if __MOCANA_MAX_INT__ == 64
      current = pVal[indexV - 1];
      pBuf[indexB]     = (ubyte)(current >> 56);
      pBuf[indexB + 1] = (ubyte)(current >> 48);
      pBuf[indexB + 2] = (ubyte)(current >> 40);
      pBuf[indexB + 3] = (ubyte)(current >> 32);
      pBuf[indexB + 4] = (ubyte)(current >> 24);
      pBuf[indexB + 5] = (ubyte)(current >> 16);
      pBuf[indexB + 6] = (ubyte)(current >>  8);
      pBuf[indexB + 7] = (ubyte)(current);
#else
      current.lower32 = pVal[indexV - 1].lower32;
      current.upper32 = pVal[indexV - 1].upper32;
      pBuf[indexB]     = (ubyte)(current.upper32 >> 24);
      pBuf[indexB + 1] = (ubyte)(current.upper32 >> 16);
      pBuf[indexB + 2] = (ubyte)(current.upper32 >> 8);
      pBuf[indexB + 3] = (ubyte)(current.upper32);
      pBuf[indexB + 4] = (ubyte)(current.lower32 >> 24);
      pBuf[indexB + 5] = (ubyte)(current.lower32 >> 16);
      pBuf[indexB + 6] = (ubyte)(current.lower32 >>  8);
      pBuf[indexB + 7] = (ubyte)(current.lower32);
#endif
      indexB += 8;
    }
  }

  return (OK);
}
