/*
 * rsatapsize.c
 *
 * Get the size of a TAP RSA key in an object with MRsaTapKeyData as pKey.
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

#include "../../../crypto/mocasymkeys/tap/rsatap.h"

#if defined(__ENABLE_DIGICERT_ASYM_KEY__) && defined(__ENABLE_DIGICERT_TAP__)

MSTATUS RsaTapGetSecuritySize (
  MocAsymKey pMocAsymKey,
  ubyte4 *pSecuritySize
  )
{
  MSTATUS status;
  MRsaTapKeyData *pInfo = (MRsaTapKeyData *)(pMocAsymKey->pKeyData);

  status = ERR_NULL_POINTER;
  if (NULL == pInfo)
    goto exit;

  if (NULL == pInfo->pKey)
    goto exit;

  /* The caller expects the security strength in bits, however the modulusLen
   * is stored in bits so we multiply by 8 */
  *pSecuritySize = pInfo->pKey->keyData.publicKey.publicKey.rsaKey.modulusLen * 8;
  status = OK;

exit:
  return status;
}

#endif /* __ENABLE_DIGICERT_ASYM_KEY__ && __ENABLE_DIGICERT_TAP__ */
