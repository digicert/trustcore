/*
 * simplerdn.c
 *
 * Encode a simple RDN.
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

MSTATUS MEncodeSimpleRdnAlloc (
  ubyte *pOid,
  ubyte4 oidLen,
  ubyte4 type,
  ubyte *pValue,
  ubyte4 valueLen,
  ubyte **ppEncoding,
  ubyte4 *pEncodingLen
  )
{
  MSTATUS status;
  MAsn1Element *pArray = NULL;
  /* Even though the definition is really a SET OF, because we will only have one
   * OF entry, we can just say SET.
   */
  MAsn1TypeAndCount pTemplate[4] = {
    { MASN1_TYPE_SET, 1 },
      { MASN1_TYPE_SEQUENCE, 2 },
        { MASN1_TYPE_OID, 0 },
        { MASN1_TYPE_PRINT_STRING, 0 },
  };

  status = ERR_NULL_POINTER;
  if ( (NULL == pValue) || (0 == valueLen) || (NULL == pOid) || (0 == oidLen) )
    goto exit;

  pTemplate[3].tagSpecial = type;

  status = MAsn1CreateElementArray (
    pTemplate, 4, MASN1_FNCT_ENCODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  pArray[2].value.pValue = pOid;
  pArray[2].valueLen = oidLen;
  pArray[2].state = MASN1_STATE_SET_COMPLETE;
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
