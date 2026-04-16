/*
 * kmatch.c
 *
 * public key compare
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
 */

/**
@file       kmatch.c
@brief      public key compare
@details    Add details here.

@filedoc    kmatch.c
*/
#include "../cap/capasym.h"

#if (defined(__ENABLE_DIGICERT_ASYM_KEY__))

extern MSTATUS CRYPTO_isMatchingKey (
  MocAsymKey pPubKey,
  ubyte *pDerPubKey,
  ubyte4 derPubKeyLen,
  intBoolean *pIsMatch
  )
{
  MSTATUS status;
  MKeyOperatorData inputInfo;

  status = ERR_NULL_POINTER;
  if ( (NULL == pPubKey) || (NULL == pDerPubKey) || (0 == derPubKeyLen) ||
    (NULL == pIsMatch) )
    goto exit;

  status = ERR_INVALID_ARG;
  if (NULL == pPubKey->KeyOperator)
    goto exit;

  inputInfo.pData = pDerPubKey;
  inputInfo.length = derPubKeyLen;

  status = pPubKey->KeyOperator (
    pPubKey, pPubKey->pMocCtx, MOC_ASYM_OP_IS_SAME_PUB_KEY, (void *)&inputInfo,
    (void *)pIsMatch, NULL);

exit:

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__)) */
