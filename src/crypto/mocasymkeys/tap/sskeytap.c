/*
 * sskeysw.c
 *
 * Operator for TAP secure storage of Asym keys.
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
