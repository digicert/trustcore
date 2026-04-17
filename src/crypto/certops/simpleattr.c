/*
 * simpleattr.c
 *
 * Encode a simple attribute or RDN.
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
 *
 */

#include "../../crypto/certops.h"

MSTATUS MEncodeSimpleAttrAlloc (
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
    { MASN1_TYPE_SEQUENCE, 2 },
      { MASN1_TYPE_OID, 0 },
      { MASN1_TYPE_SET, 1 },
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

  pArray[1].value.pValue = pOid;
  pArray[1].valueLen = oidLen;
  pArray[1].state = MASN1_STATE_SET_COMPLETE;
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
