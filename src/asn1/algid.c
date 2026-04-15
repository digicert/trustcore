/*
 * algid.c
 *
 * parsing an algorithm identifier.
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

MOC_EXTERN MSTATUS ASN1_parseAlgId (
  ubyte *pAlgId,
  ubyte4 algIdLen,
  ubyte **ppOid,
  ubyte4 *pOidLen,
  ubyte **ppParams,
  ubyte4 *pParamsLen
  )
{
  MSTATUS status;
  ubyte4 bytesRead;
  MAsn1Element *pArray = NULL;
  MAsn1TypeAndCount pTemplate[3] = {
    { MASN1_TYPE_SEQUENCE, 2 },
      { MASN1_TYPE_OID, 0 },
      { MASN1_TYPE_ENCODED | MASN1_OPTIONAL, 0 }
  };

  *ppOid = NULL;
  *pOidLen = 0;
  *ppParams = NULL;
  *pParamsLen = 0;

  status = MAsn1CreateElementArray (
    pTemplate, 3, MASN1_FNCT_DECODE, NULL, &pArray);
  if (OK != status)
    goto exit;

  status = MAsn1Decode (pAlgId, algIdLen, pArray, &bytesRead);
  if (OK != status)
    goto exit;

  *ppOid = pArray[1].value.pValue;
  *pOidLen = pArray[1].valueLen;
  *ppParams = pArray[2].value.pValue;
  *pParamsLen = pArray[2].valueLen;

exit:

  if (NULL != pArray)
  {
    MAsn1FreeElementArray (&pArray);
  }

  return (status);
}
