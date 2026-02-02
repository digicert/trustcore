/*
 * organization.c
 *
 * Functions for handling the OrganizationName element of an X.500 Name.
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

extern MSTATUS NameTypeOrganization (
  ubyte4 operation,
  ubyte *pValue,
  ubyte4 valueLen,
  void *pInfo
  )
{
  MSTATUS status;
  ubyte pOid[MOP_ORGANIZATION_NAME_OID_LEN] = { MOP_ORGANIZATION_NAME_OID };

  status = ERR_NOT_IMPLEMENTED;
  switch (operation)
  {
    default:
      goto exit;

    case MOC_NAME_OP_DECODE_RDN:
      status = MGetSimpleValue (
        (MGetAttributeData *)pInfo, pOid, MOP_ORGANIZATION_NAME_OID_LEN);
      goto exit;

    case MOC_NAME_OP_ENCODE_RDN:
      status = ERR_NULL_POINTER;
      if (NULL == pInfo)
        goto exit;

      status = MEncodeSimpleRdnAlloc (
        pOid + 2, MOP_ORGANIZATION_NAME_OID_LEN - 2,
        MASN1_TYPE_UTF8_STRING, pValue, valueLen,
        &(((MSymOperatorData *)pInfo)->pData),
        &(((MSymOperatorData *)pInfo)->length));
  }

exit:

  return status;
}

