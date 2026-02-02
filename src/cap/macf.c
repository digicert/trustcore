/*
 * macf.c
 *
 * MAC Functions
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
@file       macf.c
@brief      MAC Functions
@details    Add details here.

@filedoc    macf.c
*/
#include "../cap/capsym.h"

#if (defined(__ENABLE_DIGICERT_SYM__))

extern MSTATUS CRYPTO_macInit (
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
    pSymCtx, NULL, MOC_SYM_OP_MAC_INIT, NULL, NULL);
  if (OK != status)
    goto exit;

  pSymCtx->state = CTX_STATE_INIT;

exit:

  return (status);
}

extern MSTATUS CRYPTO_macUpdate (
  MocSymCtx pSymCtx,
  ubyte *pDataToMac,
  ubyte4 dataToMacLen
  )
{
  MSTATUS status;
  MSymOperatorData inputInfo;

  inputInfo.pData = pDataToMac;
  inputInfo.length = dataToMacLen;

  status = ERR_NULL_POINTER;
  if (NULL == pSymCtx)
    goto exit;

  if (NULL == pSymCtx->SymOperator)
    goto exit;

  status = ERR_CRYPTO_CTX_STATE;
  if ((CTX_STATE_INIT != pSymCtx->state) &&
    (CTX_STATE_UPDATE != pSymCtx->state))
    goto exit;

  status = pSymCtx->SymOperator (
    pSymCtx, NULL, MOC_SYM_OP_MAC_UPDATE, (void *)&inputInfo, NULL);
  if (OK != status)
    goto exit;

  pSymCtx->state = CTX_STATE_UPDATE;

exit:

  return (status);
}

extern MSTATUS CRYPTO_macFinal (
  MocSymCtx pSymCtx,
  ubyte *pDataToMac,
  ubyte4 dataToMacLen,
  ubyte *pMac,
  ubyte4 bufferSize,
  ubyte4 *pMacLen
  )
{
  MSTATUS status;
  MSymOperatorData inputInfo;
  MSymOperatorBuffer outputInfo;

  status = ERR_NULL_POINTER;
  if ( (NULL == pSymCtx) || (NULL == pMacLen) )
    goto exit;

  if (NULL == pSymCtx->SymOperator)
    goto exit;

  status = ERR_CRYPTO_CTX_STATE;
  if ((CTX_STATE_INIT != pSymCtx->state) &&
    (CTX_STATE_UPDATE != pSymCtx->state))
    goto exit;

  inputInfo.pData = pDataToMac;
  inputInfo.length = dataToMacLen;
  outputInfo.pBuffer = pMac;
  outputInfo.bufferSize = bufferSize;
  outputInfo.pOutputLen = pMacLen;

  status = pSymCtx->SymOperator (
    pSymCtx, NULL, MOC_SYM_OP_MAC_FINAL, (void *)&inputInfo,
    (void *)&outputInfo);
  if (OK != status)
    goto exit;

  pSymCtx->state = CTX_STATE_FINAL;

exit:

  return (status);
}

#endif /* (defined(__ENABLE_DIGICERT_SYM__)) */
