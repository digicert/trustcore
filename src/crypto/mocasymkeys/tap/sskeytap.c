/*
 * sskeysw.c
 *
 * Operator for TAP secure storage of Asym keys.
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

#include "../../../crypto/mocasymkeys/tap/sstap.h"

#if defined(__ENABLE_DIGICERT_ASYM_KEY__) && \
    defined(__ENABLE_DIGICERT_TAP__)

MOC_EXTERN MSTATUS KeyOperatorSSTap (
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;

  switch (keyOp)
  {
    default:
      status = ERR_NOT_IMPLEMENTED;
      goto exit;

    case MOC_ASYM_OP_GET_LOCAL_TYPE:
      status = ERR_NULL_POINTER;
      if (NULL != pOutputInfo)
      {
        status = OK;
        *((ubyte4 *)(pOutputInfo)) = (MOC_LOCAL_TYPE_SS_TAP);
      }
      break;

    case MOC_ASYM_OP_DESERIALIZE:
      status = SSTapDeserializeKey (
        (MKeyOperatorData *) pInputInfo,
        (MKeyOperatorDataReturn *) pOutputInfo);
      break;

    case MOC_ASYM_OP_SERIALIZE:       
      status = SSTapSerializeKey (
        (MKeyOperatorData *) pInputInfo,
        (MKeyOperatorDataReturn *) pOutputInfo);
      break;
    
    case MOC_ASYM_OP_GET_PARAMS:
      status = SSTapGetTapInfo (
        (MKeyOperatorData *) pInputInfo,
        (MKeyObjectInfo *) pOutputInfo);
      break;
  }

exit:

  return status;
}

#endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__)) etc */
