/*
 * rsatapsize.c
 *
 * Get the size of a TAP RSA key in an object with MRsaTapKeyData as pKey.
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
