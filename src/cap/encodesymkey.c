/*
 * encodesymkey.c
 *
 * Encode a symmetric key
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
@file       encodesymkey.c
@brief      Encode a symmetric key
@details    Add details here.

@filedoc    encodesymkey.c
*/
#include "../cap/capsym.h"
#include "../asn1/mocasn1.h"

#if (defined(__ENABLE_DIGICERT_SYM__))

extern MSTATUS CRYPTO_encodeSymKey (
  MocSymCtx pSymCtx,
  ubyte *pKeyBuf,
  ubyte4 bufferSize,
  ubyte4 *pKeyLen
  )
{
  MSTATUS status;
  MSymOperatorBuffer outputInfo;

  status = ERR_NULL_POINTER;
  if ( (NULL == pSymCtx) || (NULL == pKeyLen) )
    goto exit;

  if (NULL == pSymCtx->SymOperator)
    goto exit;

  outputInfo.pBuffer = pKeyBuf;
  outputInfo.bufferSize = bufferSize;
  outputInfo.pOutputLen = pKeyLen;

  status = pSymCtx->SymOperator (
    pSymCtx, NULL, MOC_SYM_OP_ENCODE_KEY, NULL, (void *)&outputInfo);

exit:

  return (status);
}

MSTATUS MocSym_buildSymKeyEncoding (
  ubyte *pOid,
  ubyte4 oidLen,
  sbyte4 deviceType,
  ubyte *pKeyData,
  ubyte4 keyDataLen,
  MSymOperatorBuffer *pOpBuffer,
  intBoolean rawData
  )
{
  MSTATUS status;
  ubyte4 bufferSize;
  MAsn1Element *pArray = NULL;
  MAsn1TypeAndCount pTemplate[4] = {
    { MASN1_TYPE_SEQUENCE, 3 },
      { MASN1_TYPE_OID, 0 },
      { MASN1_TYPE_INTEGER, 0 },
      { MASN1_TYPE_OCTET_STRING, 0 }
  };

  status = ERR_NULL_POINTER;
  if (NULL == pOpBuffer)
    goto exit;

  if (NULL == pOpBuffer->pOutputLen)
    goto exit;

  bufferSize = 0;
  if (NULL != pOpBuffer->pBuffer)
    bufferSize = pOpBuffer->bufferSize;

  if (TRUE == rawData)
  {
    /* Return only the raw keydata */
    status = ERR_BUFFER_TOO_SMALL;
    *(pOpBuffer->pOutputLen) = keyDataLen;
    if (bufferSize < keyDataLen)
      goto exit;

    /* Copy the raw data to the buffer and return */
    status = DIGI_MEMCPY (
      (void *)pOpBuffer->pBuffer, (void *)pKeyData, keyDataLen);
    goto exit;
  }

  /* Check for NULL after the check for raw data so objects without OIDs
   * can still get the raw data out */
  if (NULL == pOid)
    goto exit;

  status = MAsn1CreateElementArray (
    pTemplate, 4, MASN1_FNCT_ENCODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  pArray[1].value.pValue = pOid;
  pArray[1].valueLen = oidLen;
  pArray[1].state = MASN1_STATE_SET_COMPLETE;

  status = MAsn1SetInteger (
    pArray + 2, NULL, 0, TRUE, deviceType);
  if (OK != status)
    goto exit;

  pArray[3].value.pValue = pKeyData;
  pArray[3].valueLen = keyDataLen;
  pArray[3].state = MASN1_STATE_SET_COMPLETE;

  status = MAsn1Encode (
    pArray, pOpBuffer->pBuffer, bufferSize, pOpBuffer->pOutputLen);

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_SYM__)) */
