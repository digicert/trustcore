/*
 * getname.c
 *
 * Functions for getting Name elements out of an object.
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
