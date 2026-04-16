/*
 * getname.c
 *
 * Functions for getting Name elements out of an object.
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
#include "../../crypto/certops/certobj.h"

extern MSTATUS MGetName (
  struct MCertOrRequestObject *pObject,
  ubyte4 whichName,
  ubyte **ppNameDer,
  ubyte4 *pNameDerLen
  )
{
  MSTATUS status;
  ubyte4 index;
  MCertOrRequestObject *pObj = (MCertOrRequestObject *)pObject;

  status = ERR_NULL_POINTER;
  if ( (NULL == pObj) || (NULL == ppNameDer) || (NULL == pNameDerLen) )
    goto exit;

  if (NULL == pObj->pArray)
    goto exit;

  status = ERR_INVALID_INPUT;
  index = MOC_CERT_ARRAY_INDEX_ISSNAME;
  if (MOC_ISSUER == whichName)
  {
    /* If the caller asked for the issuerName and this is a request, error.
     */
    if (MOC_CERT_OBJ_TYPE_CERT != pObj->type)
      goto exit;
  }
  else
  {
    if (MOC_SUBJECT != whichName)
      goto exit;

    index = MOC_REQUEST_ARRAY_INDEX_NAME;
    if (MOC_CERT_OBJ_TYPE_CERT == pObj->type)
      index = MOC_CERT_ARRAY_INDEX_SUBJNAME;
  }

  *ppNameDer = pObj->pArray[index].encoding.pEncoding;
  *pNameDerLen = pObj->pArray[index].encodingLen;

  status = OK;

exit:

  return (status);
}
