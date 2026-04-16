/*
 * macf.c
 *
 * MAC Functions
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
