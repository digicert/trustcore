/*
 * asymalgid.c
 *
 * Asymmetric functions dealing with algorithm identifier.
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

#include "../../../crypto/mocasym.h"
#include "../../../crypto/mocasymkeys/mocsw/commonasym.h"

#if (defined(__ENABLE_DIGICERT_ASYM_KEY__))

MSTATUS CommonReturnAlgId (
  MocAsymKey pMocAsymKey,
  MKeyOperatorBuffer *pOutputInfo
  )
{
  MSTATUS status;
  MAsymCommonKeyData *pData = (MAsymCommonKeyData *)(pMocAsymKey->pKeyData);

  status = ERR_INVALID_INPUT;
  if (NULL != pData)
  {
    if (NULL != pData->pAlgId)
    {
      status = ERR_BUFFER_TOO_SMALL;
      *(pOutputInfo->pLength) = pData->algIdLen;
      if (pOutputInfo->bufferSize < pData->algIdLen)
        goto exit;

      status = DIGI_MEMCPY (
        (void *)(pOutputInfo->pBuffer), (void *)(pData->pAlgId),
        pData->algIdLen);
    }
  }

exit:

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__)) */
