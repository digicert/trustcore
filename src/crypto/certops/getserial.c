/*
 * getserial.c
 *
 * Functions for getting the serial number out of a cert object.
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
