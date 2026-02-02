/*
 * getvalidity.c
 *
 * Functions for getting the validity dates out of a cert object.
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

extern MSTATUS MGetValidityDates (
  MCertObj pCertObj,
  TimeDate *pNotBefore,
  TimeDate *pNotAfter
  )
{
  MSTATUS status;
  MCertOrRequestObject *pObj = (MCertOrRequestObject *)pCertObj;

  status = ERR_NULL_POINTER;
  if ( (NULL == pCertObj) || (NULL == pNotBefore) || (NULL == pNotAfter) )
    goto exit;

  if (NULL == pObj->pArray)
    goto exit;

  status = ERR_INVALID_INPUT;
  if (MOC_CERT_OBJ_TYPE_CERT != pObj->type)
    goto exit;

  status = DATETIME_convertFromValidityString2 (
    pObj->pArray[MOC_CERT_ARRAY_INDEX_NOT_BEFORE].value.pValue,
    pObj->pArray[MOC_CERT_ARRAY_INDEX_NOT_BEFORE].valueLen, pNotBefore);
  if (OK != status)
    goto exit;

  status = DATETIME_convertFromValidityString2 (
    pObj->pArray[MOC_CERT_ARRAY_INDEX_NOT_AFTER].value.pValue,
    pObj->pArray[MOC_CERT_ARRAY_INDEX_NOT_AFTER].valueLen, pNotAfter);

exit:

  return (status);
}

