/*
 * encext.c
 *
 * Encode an extension.
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

MSTATUS MEncodeExtensionAlloc (
  ubyte *pOid,
  ubyte4 oidLen,
  intBoolean isCritical,
  ubyte *pValue,
  ubyte4 valueLen,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  )
{
  MSTATUS status;
  MAsn1Element *pArray = NULL;
  MAsn1TypeAndCount pTemplate[4] = {
    { MASN1_TYPE_SEQUENCE, 3 },
      { MASN1_TYPE_OID, 0 },
      { MASN1_TYPE_BOOLEAN | MASN1_DEFAULT, 0 },
      { MASN1_TYPE_OCTET_STRING, 0 },
  };

  status = ERR_NULL_POINTER;
  if ( (NULL == pValue) || (0 == valueLen) || (NULL == pOid) || (0 == oidLen) )
    goto exit;

  status = MAsn1CreateElementArray (
    pTemplate, 4, MASN1_FNCT_ENCODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  pArray[1].value.pValue = pOid;
  pArray[1].valueLen = oidLen;
  pArray[1].state = MASN1_STATE_SET_COMPLETE;
  if (FALSE != isCritical)
  {
    status = MAsn1SetBoolean (pArray + 2, TRUE);
    if (OK != status)
      goto exit;
  }
  pArray[3].value.pValue = pValue;
  pArray[3].valueLen = valueLen;
  pArray[3].state = MASN1_STATE_SET_COMPLETE;

  status = MAsn1EncodeAlloc (pArray, ppEncoding, pEncodingLen);

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }

  return (status);
}
