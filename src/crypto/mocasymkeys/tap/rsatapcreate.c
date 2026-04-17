/*
 * rsatapcreate.c
 *
 * Create and initialize TAP RSA keys.
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

#include "../../../crypto/mocasymkeys/mocsw/commonrsa.h"
#include "../../../crypto/mocasymkeys/tap/rsatap.h"

#if defined(__ENABLE_DIGICERT_ASYM_KEY__) && defined(__ENABLE_DIGICERT_TAP__)

MSTATUS RsaTapCreate (
  MocAsymKey pMocAsymKey,
  void *pCreateInfo,
  keyOperation keyOp
  )
{
  MSTATUS status;
  MRsaTapCreateArgs *pCreateArgs = NULL;
  MRsaTapKeyData *pNewData;
  MRsaTapKeyData *pData;

  /* Allocate space for the local info */
  status = DIGI_CALLOC (
    (void **)&pNewData, 1, sizeof(MRsaTapKeyData));
  if (OK != status)
    goto exit;

  pData = pNewData;
  pMocAsymKey->pKeyData = (void *)pNewData;
  pNewData = NULL;

  /* If available, store the creation info (TAP context and credential) in
   * the local info we just allocated.  If pCreateInfo is not NULL, it is very
   * likely that this create call is occuring during a deserialization operation.
   * */
  if (NULL != pCreateInfo)
  {
    pCreateArgs = (MRsaTapCreateArgs *)pCreateInfo;

    if (NULL != pCreateArgs->pTapCtx)
    {
      pData->pTapCtx = pCreateArgs->pTapCtx;
    }

    if (NULL != pCreateArgs->pKeyCredentials)
    {
      pData->pKeyCredentials = pCreateArgs->pKeyCredentials;
    }

    if (NULL != pCreateArgs->pEntityCredentials)
    {
      pData->pEntityCredentials = pCreateArgs->pEntityCredentials;
    }

    if (NULL != pCreateArgs->pKeyAttributes)
    {
      pData->pKeyAttributes = pCreateArgs->pKeyAttributes;
    }

    if (NULL != pCreateArgs->Callback)
    {
      pData->Callback = pCreateArgs->Callback;
    }
  }

  pMocAsymKey->KeyOperator = KeyOperatorRsaTap;
  pMocAsymKey->localType = MOC_LOCAL_KEY_RSA_PRI_TAP;

  /* If we got a callback, call it now */
  if (NULL != pData->Callback)
  {
    status = pData->Callback (
      pMocAsymKey->pMocCtx, keyOp, (void *)pData);
  }

exit:
  return status;
}

#endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__)) etc... */
