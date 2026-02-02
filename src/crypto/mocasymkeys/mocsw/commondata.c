/*
 * commondata.c
 *
 * Functions dealing with common data: MAsymCommonKeyData.
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

MOC_EXTERN MSTATUS LoadCommonKeyData (
  MocAsymKey pMocAsymKey,
  ubyte *pNewAlgId,
  ubyte4 newAlgIdLen,
  MocSymCtx *ppNewDigestCtx
  )
{
  MSTATUS status;
  MAsymCommonKeyData *pData = (MAsymCommonKeyData *)(pMocAsymKey->pKeyData);

  /* If there is a new alg ID, free the old and copy the new.
   */
  status = OK;
  if ( (NULL != pNewAlgId) && (newAlgIdLen != 0) )
  {
    if (NULL != pData->pAlgId)
    {
      status = DIGI_FREE ((void **)&(pData->pAlgId));
      if (OK != status)
        goto exit;

      pData->algIdLen = 0;
    }

    status = DIGI_MALLOC_MEMCPY (
      (void *)&(pData->pAlgId), newAlgIdLen, (void *)pNewAlgId,
      newAlgIdLen);
    if (OK != status)
      goto exit;

    pData->algIdLen = newAlgIdLen;
  }

  /* If there is a digest object, free any older and load the new one.
   */
  if (NULL != ppNewDigestCtx)
  {
    if (NULL != *ppNewDigestCtx)
    {
      if (NULL != pData->pDigestCtx)
      {
#if __ENABLE_DIGICERT_SYMCTX_FREE__
        status = CRYPTO_freeMocSymCtx (&(pData->pDigestCtx));
        if (OK != status)
          goto exit;
#endif
      }

      pData->pDigestCtx = *ppNewDigestCtx;
      *ppNewDigestCtx = NULL;
    }
  }

exit:

  return (status);
}

MOC_EXTERN MSTATUS FreeCommonKeyData (
  MocAsymKey pMocAsymKey
  )
{
  MSTATUS status;
#if __ENABLE_DIGICERT_SYMCTX_FREE__
  MSTATUS fStatus;
#endif
  MAsymCommonKeyData *pData = (MAsymCommonKeyData *)(pMocAsymKey->pKeyData);

  status = OK;
  if (NULL != pData)
  {
    if (NULL != pData->pAlgId)
    {
      status = DIGI_FREE ((void **)&(pData->pAlgId));
      pData->algIdLen = 0;
    }
    if (NULL != pData->pDigestCtx)
    {
#if __ENABLE_DIGICERT_SYMCTX_FREE__
      fStatus = CRYPTO_freeMocSymCtx (&(pData->pDigestCtx));
      if (OK == status)
        status = fStatus;
#endif
    }
  }

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__)) */
