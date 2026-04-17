/*
 * algsupport.c
 *
 * Functions that build supporting algorithms needed in cert operations.
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

MSTATUS MGetDigestFlagFromKeySize (
  MocAsymKey pKey,
  ubyte4 *pDigestAlg
  )
{
  MSTATUS status;
  ubyte4 securitySize, digestAlg;

  status = ERR_NULL_POINTER;
  if ( (NULL == pKey) || (NULL == pDigestAlg) )
    goto exit;

  /* Get the security size.
   */
  status = pKey->KeyOperator (
    pKey, NULL, MOC_ASYM_OP_GET_SECURITY_SIZE, NULL, (void *)&securitySize, NULL);
  if (OK != status)
    goto exit;

  digestAlg = ht_sha1;
  if (1024 < securitySize)
  {
    digestAlg = ht_sha224;
    if (2048 < securitySize)
    {
      digestAlg = ht_sha256;
      if (3072 < securitySize)
      {
        digestAlg = ht_sha384;
        if (7680 < securitySize)
          digestAlg = ht_sha512;
      }
    }
  }

  *pDigestAlg = digestAlg;

exit:

  return (status);
}
