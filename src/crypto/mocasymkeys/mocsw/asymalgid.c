/*
 * asymalgid.c
 *
 * Asymmetric functions dealing with algorithm identifier.
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
