/*
 * province.c
 *
 * Functions for handling the StateOrProvinceName element of an X.500 Name.
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

extern MSTATUS NameTypeStateOrProvince (
  ubyte4 operation,
  ubyte *pValue,
  ubyte4 valueLen,
  void *pInfo
  )
{
  MSTATUS status;
  ubyte pOid[MOP_STATE_PROVINCE_NAME_OID_LEN] = { MOP_STATE_PROVINCE_NAME_OID };

  status = ERR_NOT_IMPLEMENTED;
  switch (operation)
  {
    default:
      goto exit;

    case MOC_NAME_OP_DECODE_RDN:
      status = MGetSimpleValue (
        (MGetAttributeData *)pInfo, pOid, MOP_STATE_PROVINCE_NAME_OID_LEN);
      goto exit;

    case MOC_NAME_OP_ENCODE_RDN:
      status = ERR_NULL_POINTER;
      if (NULL == pInfo)
        goto exit;

      status = MEncodeSimpleRdnAlloc (
        pOid + 2, MOP_STATE_PROVINCE_NAME_OID_LEN - 2,
        MASN1_TYPE_UTF8_STRING, pValue, valueLen,
        &(((MSymOperatorData *)pInfo)->pData),
        &(((MSymOperatorData *)pInfo)->length));
  }

exit:

  return (status);
}
