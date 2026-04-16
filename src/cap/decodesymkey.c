/*
 * decodesymkey.c
 *
 * Decode a symmetric key
 *
 * Copyright 2026 DigiCert, Inc. All Rights Reserved.
 *
 * DigiCert® TrustCore SDK and TrustEdge are licensed under a dual-license model:
 *
 * 1. **Open Source License**: GNU Affero General Public License v3.0 (AGPL v3).
 * See: https://github.com/digicert/trustcore/blob/main/LICENSE.md
 * 2. **Commercial License**: Available under DigiCert's Master Services Agreement.
 * See: https://www.digicert.com/master-services-agreement/
 *
 * *Use of TrustCore SDK or TrustEdge outside the scope of AGPL v3 requires a commercial license.*
 * *Contact DigiCert at sales@digicert.com for more details.*
 */
/**
@file       decodesymkey.c
@brief      Decode a symmetric key
@details    Add details here.

@filedoc    decodesymkey.c
*/

#include "../cap/capsym.h"
#include "../asn1/mocasn1.h"

#if (defined(__ENABLE_DIGICERT_SYM__))

extern MSTATUS CRYPTO_loadEncodedSymKey (
  MocSymCtx pSymCtx,
  ubyte *pEncodedKey,
  ubyte4 encodedKeyLen
  )
{
  MSTATUS status;
  MSymOperatorData inputInfo;

  status = ERR_NULL_POINTER;
  if ( (NULL == pSymCtx) || (NULL == pEncodedKey) )
    goto exit;

  if (NULL == pSymCtx->SymOperator)
    goto exit;

  inputInfo.pData = pEncodedKey;
  inputInfo.length = encodedKeyLen;

  status = pSymCtx->SymOperator (
    pSymCtx, NULL, MOC_SYM_OP_DECODE_KEY, (void *)&inputInfo, NULL);

exit:

  return (status);
}

MSTATUS MocSym_parseSymKeyEncoding (
  MSymOperatorData *pEncodedKey,
  ubyte *pExpectedOid,
  ubyte4 expectedOidLen,
  sbyte4 expectedDeviceType,
  ubyte **ppKeyData,
  ubyte4 *pKeyDataLen
  )
{
  MSTATUS status;
  sbyte4 cmpResult, deviceType;
  ubyte4 bytesRead, index;
  MAsn1Element *pArray = NULL;
  MAsn1TypeAndCount pTemplate[4] = {
    { MASN1_TYPE_SEQUENCE, 3 },
      { MASN1_TYPE_OID, 0 },
      { MASN1_TYPE_INTEGER, 0 },
      { MASN1_TYPE_OCTET_STRING, 0 }
  };

  status = ERR_NULL_POINTER;
  if ( (NULL == pEncodedKey) || (NULL == pExpectedOid) ||
       (NULL == ppKeyData) || (NULL == pKeyDataLen) )
    goto exit;

  status = MAsn1CreateElementArray (
    pTemplate, 4, MASN1_FNCT_DECODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  status = MAsn1Decode (
    pEncodedKey->pData, pEncodedKey->length, pArray, &bytesRead);
  if (OK != status)
    goto exit;

  /* Make sure we have values.
   */
  status = ERR_BAD_KEY;
  if ( (NULL == pArray[1].value.pValue) || (NULL == pArray[2].value.pValue) ||
       (NULL == pArray[3].value.pValue) )
    goto exit;

  /* The deviceType (the INTEGER) must be representable as an sbyte4.
   */
  if ( (4 < pArray[2].valueLen) || (0 == pArray[2].valueLen) )
    goto exit;

  deviceType = 0;
  for (index = 0; index < pArray[2].valueLen; ++index)
  {
    deviceType <<= 8;
    deviceType += ((sbyte4)(pArray[2].value.pValue[index]) & 0xff);
  }

  if ( (pArray[1].valueLen != expectedOidLen) ||
       (deviceType != expectedDeviceType) )
    goto exit;

  status = DIGI_MEMCMP (
    (void *)pExpectedOid, (void *)(pArray[1].value.pValue),
    expectedOidLen, &cmpResult);
  if (OK != status)
    goto exit;

  status = ERR_BAD_KEY;
  if (0 != cmpResult)
    goto exit;

  *ppKeyData = pArray[3].value.pValue;
  *pKeyDataLen = pArray[3].valueLen;

  status = OK;

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_SYM__)) */
