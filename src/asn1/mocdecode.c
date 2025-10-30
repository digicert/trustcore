/*
 * mocdecode.c
 *
 * DER decode.
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

#include "../asn1/mocasn1.h"

/* Just return an error, because if we get indef, that's wrong.
 */
MSTATUS IndefiniteLengthDataReturnError (
  void *pCallbackInfo,
  ubyte *pData,
  ubyte4 dataLen,
  MAsn1Element *pElement
  );

MOC_EXTERN MSTATUS MAsn1Decode (
  const ubyte  *pEncoding,
  ubyte4       encodingLen,
  MAsn1Element *pElement,
  ubyte4       *pBytesRead
  )
{
  MSTATUS status;
  intBoolean isComplete;

  /* Call the IndefDecode with  a callback that returns an error. In that way, if
   * we run across indefinite, we'll return an error.
   */
  status = MAsn1DecodeIndefiniteUpdateFlag (
    (ubyte *)pEncoding, encodingLen, (MASN1_DECODE_LAST_CALL | MASN1_DECODE_NO_INDEF),
    pElement, IndefiniteLengthDataReturnError, NULL, pBytesRead, &isComplete);
  if (OK != status)
    goto exit;

  status = ERR_ASN_UNEXPECTED_END;
  if (FALSE != isComplete)
    status = OK;

exit:

  return (status);
}

MSTATUS MAsn1DecodeUpdate (
  ubyte *pEncoding,
  ubyte4 encodingLen,
  MAsn1Element *pElement,
  ubyte4 *pBytesRead,
  intBoolean *pIsComplete
  )
{
  return MAsn1DecodeUpdateFlag(pEncoding,
                               encodingLen,
                               MASN1_DECODE_UPDATE,
                               pElement,
                               pBytesRead,
                               pIsComplete);
}

MSTATUS MAsn1DecodeUpdateFlag (
  ubyte *pEncoding,
  ubyte4 encodingLen,
  ubyte4 decodeFlag,
  MAsn1Element *pElement,
  ubyte4 *pBytesRead,
  intBoolean *pIsComplete
  )
{
  MSTATUS status;
  ubyte4 newFlag;

  /* Call the IndefDecode with  a callback that returns an error. In that way, if
   * we run across indefinite, we'll return an error.
   */
  newFlag = decodeFlag | MASN1_DECODE_NO_INDEF;
  status = MAsn1DecodeIndefiniteUpdateFlag (
    pEncoding, encodingLen, newFlag,  pElement,
    IndefiniteLengthDataReturnError, NULL, pBytesRead, pIsComplete);
  if (OK != status)
    goto exit;

exit:

  return (status);
}

MSTATUS IndefiniteLengthDataReturnError (
  void *pCallbackInfo,
  ubyte *pData,
  ubyte4 dataLen,
  MAsn1Element *pElement
  )
{
  MOC_UNUSED(pCallbackInfo);
  MOC_UNUSED(pData);
  MOC_UNUSED(dataLen);
  MOC_UNUSED(pElement);
  return (ERR_ASN_INDEFINITE_LEN_NOT_ALLOWED);
}
