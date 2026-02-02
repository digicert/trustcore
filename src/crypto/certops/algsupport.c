/*
 * algsupport.c
 *
 * Functions that build supporting algorithms needed in cert operations.
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
