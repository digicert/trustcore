/*
 * getserial.c
 *
 * Functions for getting the serial number out of a cert object.
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

extern MSTATUS MGetSerialNum (
  MCertObj pCertObj,
  ubyte **ppSerialNum,
  ubyte4 *pSerialNumLen
  )
{
  MSTATUS status;
  MCertOrRequestObject *pObj = (MCertOrRequestObject *)pCertObj;

  status = ERR_NULL_POINTER;
  if ( (NULL == pCertObj) || (NULL == ppSerialNum) || (NULL == pSerialNumLen) )
    goto exit;

  if (NULL == pObj->pArray)
    goto exit;

  status = ERR_INVALID_INPUT;
  if (MOC_CERT_OBJ_TYPE_CERT != pObj->type)
    goto exit;

  *ppSerialNum = pObj->pArray[MOC_CERT_ARRAY_INDEX_SERIAL_NUM].value.pValue;
  *pSerialNumLen = pObj->pArray[MOC_CERT_ARRAY_INDEX_SERIAL_NUM].valueLen;

  status = OK;

exit:

  return (status);
}
