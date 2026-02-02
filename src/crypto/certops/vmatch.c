/*
 * vmatch.c
 *
 * Functions for validating that a private key and cert match (they are partners).
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

extern MSTATUS X509_validateKeyCertMatch (
  MocAsymKey pPriKey,
  MCertObj pCert,
  intBoolean *pIsMatch,
  vlong **ppVlongQueue
  )
{
  MSTATUS status;
  ubyte4 getKeyDataLen;
  ubyte *pGetKeyData;
  MocAsymKey pPubKey = NULL;

  status = ERR_NULL_POINTER;
  if ( (NULL == pPriKey) || (NULL == pCert) || (NULL == pIsMatch) )
    goto exit;

  *pIsMatch = FALSE;

  /* One way to match keys is to perform a private key operation witht he given
   * key, then see if the public key operation works using the cert.
   * However, we don't want to do that, the private key operation might be
   * hardware (HSM, TPM, SGX, SEE, etc), and we don't want to call on the
   * hardware unnecessarily. It's also time-consuming, so we avoid doing so.
   */

  /* Get the public key out of the cert, get the public key out of the private
   * key, see if they are the same.
   * It is possible to have different DER encodings. It shouldn't happen, but it
   * can. It is possible that the DER of a pub key in the cert will not be the
   * same DER encoding that we generate. Hence, we can't simply do a memcmp.
   */
  status = MGetPublicKeyFromCertOrRequest (
    (struct MCertOrRequestObject *)pCert, NULL, NULL,
    &pGetKeyData, &getKeyDataLen, ppVlongQueue);
  if (OK != status)
    goto exit;

  status = CRYPTO_getPubFromPri (pPriKey, &pPubKey, ppVlongQueue);
  if (OK != status)
    goto exit;

  status = CRYPTO_isMatchingKey (pPubKey, pGetKeyData, getKeyDataLen, pIsMatch);

exit:

  if (NULL != pPubKey)
  {
    CRYPTO_freeMocAsymKey(&pPubKey, ppVlongQueue);
  }

  return (status);
}
