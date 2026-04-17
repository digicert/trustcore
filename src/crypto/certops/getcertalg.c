/*
 * getcertalg.c
 *
 * Functions for getting the algorithm out of a cert or request (either key or
 * sig).
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

extern MSTATUS MGetSignatureKeyAlg (
  struct MCertOrRequestObject *pObject,
  ubyte4 *pAlgorithm
  )
{
  MSTATUS status;
  ubyte4 index, algIdLen;
  ubyte *pAlgId;
  MCertOrRequestObject *pObj = (MCertOrRequestObject *)pObject;

  index = MOC_REQUEST_ARRAY_INDEX_SIG_ALGID;
  if (MOC_CERT_OBJ_TYPE_CERT == pObj->type)
    index = MOC_CERT_ARRAY_INDEX_SIG_ALG_ID_SIGNED;

  pAlgId = pObj->pArray[index].encoding.pEncoding;
  algIdLen = pObj->pArray[index].encodingLen;

  status = ASN1_getPublicKeyAlgFlagFromOid (pAlgId, algIdLen, pAlgorithm);

exit:

  return (status);
}

extern MSTATUS MGetCertOrRequestKeyAlg (
  struct MCertOrRequestObject *pObject,
  ubyte4 *pAlgorithm
  )
{
  MSTATUS status;
  ubyte4 index, algIdLen;
  ubyte *pAlgId;
  MCertOrRequestObject *pObj = (MCertOrRequestObject *)pObject;

  index = MOC_REQUEST_ARRAY_INDEX_KEY_OID;
  if (MOC_CERT_OBJ_TYPE_CERT == pObj->type)
    index = MOC_CERT_ARRAY_INDEX_KEY_OID;

  pAlgId = pObj->pArray[index].encoding.pEncoding;
  algIdLen = pObj->pArray[index].encodingLen;

  status = ASN1_getKeyFlagFromOid (pAlgId, algIdLen, pAlgorithm);

exit:

  return (status);
}
