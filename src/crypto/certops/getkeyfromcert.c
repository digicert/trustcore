/*
 * getkeyfromcert.c
 *
 * Functions for getting a key out of a cert.
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

MOC_EXTERN MSTATUS MGetPublicKeyFromCertOrRequest (
  struct MCertOrRequestObject *pObject,
  MocCtx pMocCtx,
  MocAsymKey *ppKeyObj,
  ubyte **ppSubjPubKey,
  ubyte4 *pSubjPubKeyLen,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  ubyte4 index;
  MCertOrRequestObject *pObj = (MCertOrRequestObject *)pObject;

  status = ERR_NULL_POINTER;
  if (NULL == pObject)
    goto exit;

  if (NULL == pObj->pArray)
    goto exit;

  index = MOC_REQUEST_ARRAY_INDEX_KEY;
  if (MOC_CERT_OBJ_TYPE_CERT == pObj->type)
    index = MOC_CERT_ARRAY_INDEX_KEY;

  if ( (NULL == pObj->pArray[index].encoding.pEncoding) ||
       (0 == pObj->pArray[index].encodingLen) )
    goto exit;

  status = OK;

  if ( (NULL != ppSubjPubKey) && (NULL != pSubjPubKeyLen) )
  {
    *ppSubjPubKey = pObj->pArray[index].encoding.pEncoding;
    *pSubjPubKeyLen = pObj->pArray[index].encodingLen;
  }

  if (NULL != ppKeyObj)
  {
    status = CRYPTO_deserializeMocAsymKey (
      pObj->pArray[index].encoding.pEncoding, pObj->pArray[index].encodingLen,
      pMocCtx, ppKeyObj, ppVlongQueue);
  }

exit:

  return (status);
}
