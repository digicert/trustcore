/*
 * getkeyfromcert.c
 *
 * Functions for getting a key out of a cert.
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
