/*
 * getunique.c
 *
 * Functions for getting UniqueId out of a cert object.
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
#include "../../common/base64.h"
#include "../../crypto/certops/certobj.h"

extern MSTATUS MGetUniqueId (
  MCertObj pCertObj,
  ubyte4 whichId,
  ubyte **ppUniqueId,
  ubyte4 *pUniqueIdLen
  )
{
  MSTATUS status;
  ubyte4 index;
  MCertOrRequestObject *pObj = (MCertOrRequestObject *)pCertObj;

  status = ERR_NULL_POINTER;
  if ( (NULL == pCertObj) || (NULL == ppUniqueId) || (NULL == pUniqueIdLen) )
    goto exit;

  *ppUniqueId = NULL;
  *pUniqueIdLen = 0;

  if (NULL == pObj->pArray)
    goto exit;

  status = ERR_INVALID_INPUT;
  if (MOC_CERT_OBJ_TYPE_CERT != pObj->type)
    goto exit;

  index = MOC_CERT_ARRAY_INDEX_ISSUER_UNIQUE;
  if (MOC_ISSUER != whichId)
  {
    if (MOC_SUBJECT != whichId)
      goto exit;

    index = MOC_CERT_ARRAY_INDEX_SUBJ_UNIQUE;
  }

  /* If there is no UniqueID (it's OPTIONAL, there migh be none), just return
   * NULL (we init the return to NULL/0).
   */
  status = OK;
  if ( (NULL == pObj->pArray[index].value.pValue) ||
       (2 > pObj->pArray[index].valueLen) )
    goto exit;

  /* For unique ID, we want the value (the V of TLV). Except it is a BIT STRING,
   * so skip the first octet (unused bits).
   */
  *ppUniqueId = pObj->pArray[index].value.pValue + 1;
  *pUniqueIdLen = pObj->pArray[index].valueLen - 1;

exit:

  return (status);
}
