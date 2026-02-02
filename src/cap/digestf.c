/*
 * digestf.c
 *
 * Message Digest Functions
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
@file       digestf.c
@brief      Message Digest Functions
@details    Add details here.

@filedoc    digestf.c
*/
#include "../cap/capsym.h"
#include "../asn1/mocasn1.h"

#if (defined(__ENABLE_DIGICERT_SYM__))

extern MSTATUS CRYPTO_digestInit (
  MocSymCtx pSymCtx
  )
{
  MSTATUS status;

  status = ERR_NULL_POINTER;
  if (NULL == pSymCtx)
    goto exit;

  if (NULL == pSymCtx->SymOperator)
    goto exit;

  status = pSymCtx->SymOperator (
    pSymCtx, NULL, MOC_SYM_OP_DIGEST_INIT, NULL, NULL);
  if (OK != status)
    goto exit;

  pSymCtx->state = CTX_STATE_INIT;

exit:

  return (status);
}

extern MSTATUS CRYPTO_digestInitCustom (
  MocSymCtx pSymCtx,
  void *pInitialConstants
  )
{
  MSTATUS status = ERR_NULL_POINTER;
  
  if (NULL == pSymCtx || NULL == pSymCtx->SymOperator)
    goto exit;
  
  status = pSymCtx->SymOperator (pSymCtx, NULL, MOC_SYM_OP_DIGEST_INIT_CUSTOM, pInitialConstants, NULL);
  if (OK != status)
    goto exit;
  
  pSymCtx->state = CTX_STATE_INIT;
  
exit:
  
  return status;
}

extern MSTATUS CRYPTO_digestUpdate (
  MocSymCtx pSymCtx,
  ubyte *pDataToDigest,
  ubyte4 dataToDigestLen
  )
{
  MSTATUS status;
  MSymOperatorData inputInfo;

  inputInfo.pData = pDataToDigest;
  inputInfo.length = dataToDigestLen;

  status = ERR_NULL_POINTER;
  if (NULL == pSymCtx)
    goto exit;

  if (NULL == pSymCtx->SymOperator)
    goto exit;

  /* If the state indicates create, this object was never initialized */
  status = ERR_CRYPTO_CTX_STATE;
  if (CTX_STATE_CREATE == pSymCtx->state)
    goto exit;

  status = pSymCtx->SymOperator (
    pSymCtx, NULL, MOC_SYM_OP_DIGEST_UPDATE, (void *)&inputInfo, NULL);
  if (OK != status)
    goto exit;

  pSymCtx->state = CTX_STATE_UPDATE;

exit:

  return (status);
}

extern MSTATUS CRYPTO_digestInfoFinal (
  MocSymCtx pSymCtx,
  ubyte *pDataToDigest,
  ubyte4 dataToDigestLen,
  ubyte *pDigestInfo,
  ubyte4 bufferSize,
  ubyte4 *pDigestInfoLen
  )
{
  MSTATUS status;
  ubyte4 bufSize, digestSize, algIdLen, offset;
  ubyte pAlgId[MOP_MAX_DIGEST_ALG_ID_LEN];
  MSymOperatorBuffer outputInfo;

  status = ERR_NULL_POINTER;
  if ( (NULL == pSymCtx) || (NULL == pDigestInfoLen) )
    goto exit;

  if (NULL == pSymCtx->SymOperator)
    goto exit;

  status = ERR_CRYPTO_CTX_STATE;
  if ((CTX_STATE_INIT != pSymCtx->state) &&
    (CTX_STATE_UPDATE != pSymCtx->state))
    goto exit;

  bufSize = 0;
  if (NULL != pDigestInfo)
    bufSize = bufferSize;

  /* How big is the digest?
   */
  status = pSymCtx->SymOperator (
    pSymCtx, NULL, MOC_SYM_OP_DIGEST_SIZE, NULL, (void *)&digestSize);
  if (OK != status)
    goto exit;

  /* Get the algId.
   */
  outputInfo.pBuffer = (ubyte *)pAlgId;
  outputInfo.bufferSize = MOP_MAX_DIGEST_ALG_ID_LEN;
  outputInfo.pOutputLen = &algIdLen;
  status = pSymCtx->SymOperator (
    pSymCtx, NULL, MOC_SYM_OP_GET_ALG_ID, NULL, (void *)&outputInfo);
  if (OK != status)
    goto exit;

  /* The digestInfo will be
   *   30 len
   *      AlgId
   *      04 digestLen
   *         <digest>
   * Because the largest digest is 64 bytes, and the largest digest algId is 15,
   * we know the length values will never be more than one octet. The biggest
   * DigestInfo is for SHA-512
   *   30 51
   *      30 0D
   *         <OID and params>
   *      04 40
   *         <64 bytes of digest>
   * This means we know that the total length of output will be digestLen +
   * algIdLen + 4.
   */
  *pDigestInfoLen = digestSize + algIdLen + 4;
  status = ERR_BUFFER_TOO_SMALL;
  if (bufSize < *pDigestInfoLen)
    goto exit;

  pDigestInfo[0] = 0x30;
  pDigestInfo[1] = (ubyte)(digestSize + algIdLen + 2);
  status = DIGI_MEMCPY (
    (void *)(pDigestInfo + 2), (void *)pAlgId, algIdLen);
  if (OK != status)
    goto exit;

  offset = algIdLen + 2;
  pDigestInfo[offset] = 0x04;
  pDigestInfo[offset + 1] = (ubyte)digestSize;

  status = CRYPTO_digestFinal (
    pSymCtx, pDataToDigest, dataToDigestLen, pDigestInfo + offset + 2,
    digestSize, &bufSize);
  if (OK != status)
    goto exit;

  pSymCtx->state = CTX_STATE_FINAL;

exit:

  return (status);
}

extern MSTATUS CRYPTO_digestFinal (
  MocSymCtx pSymCtx,
  ubyte *pDataToDigest,
  ubyte4 dataToDigestLen,
  ubyte *pDigest,
  ubyte4 bufferSize,
  ubyte4 *pDigestLen
  )
{
  MSTATUS status;
  MSymOperatorData inputInfo;
  MSymOperatorBuffer outputInfo;

  status = ERR_NULL_POINTER;
  if ( (NULL == pSymCtx) || (NULL == pDigestLen) )
    goto exit;

  if (NULL == pSymCtx->SymOperator)
    goto exit;

  /* If the state indicates create, this object was never initialized */
  status = ERR_CRYPTO_CTX_STATE;
  if (CTX_STATE_CREATE == pSymCtx->state)
    goto exit;

  inputInfo.pData = pDataToDigest;
  inputInfo.length = dataToDigestLen;
  outputInfo.pBuffer = pDigest;
  outputInfo.bufferSize = bufferSize;
  outputInfo.pOutputLen = pDigestLen;

  status = pSymCtx->SymOperator (
    pSymCtx, NULL, MOC_SYM_OP_DIGEST_FINAL, (void *)&inputInfo,
    (void *)&outputInfo);
  if (OK != status)
    goto exit;

  pSymCtx->state = CTX_STATE_FINAL;

exit:

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_SYM__)) */
