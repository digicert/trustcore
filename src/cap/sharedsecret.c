/*
 * sharedsecret.c
 *
 * SFTP Developer API
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
@file       sharedsecret.c
@brief      Shared Secret Functions.
@details    Add details here.

@filedoc    sharedsecret.c
*/
#include "../cap/capasym.h"

#if (defined(__ENABLE_DIGICERT_ASYM_KEY__))

extern MSTATUS CRYPTO_computeSharedSecret (
  MocAsymKey pPrivateKey,
  MocAsymKey pPublicKey,
  ubyte *pPublicValue,
  ubyte4 publicValueLen,
  void *pAdditionalOpInfo,
  ubyte *pSharedSecret,
  ubyte4 bufferSize,
  ubyte4 *pSecretLen,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  ubyte4 pubValLen, bufSize;
  ubyte *pGetPubVal = NULL;
  MKeyOperatorDataReturn getPubVal;
  MKeyOperatorData pubVal;
  MKeyOperatorBuffer returnInfo;

  status = ERR_NULL_POINTER;
  if ( (NULL == pPrivateKey) || (NULL == pSecretLen) )
    goto exit;

  status = ERR_INVALID_ARG;
  if (NULL == pPrivateKey->KeyOperator)
    goto exit;

  /* Init to this. If the key is not NULL, we'll overwrite it.
   */
  pubVal.pData = pPublicValue;
  pubVal.length = publicValueLen;

  /* Init the general override structure */
  pubVal.pAdditionalOpInfo = pAdditionalOpInfo;

  bufSize = 0;
  if (NULL != pSharedSecret)
    bufSize = bufferSize;

  /* If the public key is not NULL, we need to get the pub value.
   */
  if (NULL != pPublicKey)
  {
    if (NULL == pPublicKey->KeyOperator)
      goto exit;

    getPubVal.ppData = &pGetPubVal;
    getPubVal.pLength = &pubValLen;
    status = pPublicKey->KeyOperator (
      pPublicKey, pPublicKey->pMocCtx, MOC_ASYM_OP_GET_PUB_VALUE, NULL,
      (void *)&getPubVal, ppVlongQueue);
    if (OK != status)
      goto exit;

    pubVal.pData = pGetPubVal;
    pubVal.length = pubValLen;
  }

  returnInfo.pBuffer = pSharedSecret;
  returnInfo.bufferSize = bufSize;
  returnInfo.pLength = pSecretLen;

  status = pPrivateKey->KeyOperator (
    pPrivateKey, pPrivateKey->pMocCtx, MOC_ASYM_OP_COMPUTE_SHARED_SECRET,
    (void *)&pubVal, (void *)&returnInfo, ppVlongQueue);

exit:

  if (NULL != pGetPubVal)
  {
    DIGI_FREE ((void **)&pGetPubVal);
  }

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__)) */
