/*
 * sharedsecret.c
 *
 * SFTP Developer API
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
