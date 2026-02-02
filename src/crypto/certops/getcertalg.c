/*
 * getcertalg.c
 *
 * Functions for getting the algorithm out of a cert or request (either key or
 * sig).
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
