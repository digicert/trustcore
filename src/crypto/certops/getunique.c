/*
 * getunique.c
 *
 * Functions for getting UniqueId out of a cert object.
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
