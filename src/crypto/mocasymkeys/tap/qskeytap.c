/*
 * qskeytap.c
 *
 * Operator for TAP version of QS Custom Key.
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

#include "../../../crypto/mocasymkeys/tap/qstap.h"

#if defined(__ENABLE_DIGICERT_ASYM_KEY__) && \
    defined(__ENABLE_DIGICERT_PQC__) && \
    defined(__ENABLE_DIGICERT_TAP__)

MOC_EXTERN MSTATUS KeyOperatorQsTap (
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  )
{
  MSTATUS status;
  serializedKeyFormat keyFormat;

  switch (keyOp)
  {
    default:
      status = ERR_NOT_IMPLEMENTED;
      goto exit;

    case MOC_ASYM_OP_GET_LOCAL_TYPE:
      status = ERR_NULL_POINTER;
      if (NULL != pOutputInfo)
      {
        /* This operator is generic to all pqc algs but mark it as mldsa so crypto interface core knows 
           how to initialize it. */
        status = OK;
        *((ubyte4 *)(pOutputInfo)) = (MOC_LOCAL_KEY_QS_OPERATOR_TAP | MOC_LOCAL_KEY_PQC_MLDSA);
      }
      break;

    case MOC_ASYM_OP_CREATE:
    case MOC_ASYM_OP_CREATE_PUB:
    case MOC_ASYM_OP_CREATE_PRI:
      status = QsTapCreate (pMocAsymKey, pInputInfo, keyOp);
      break;

    case MOC_ASYM_OP_PUB_FROM_PRI:
      status = QsTapGetPubFromPri (
        pMocAsymKey, (MocAsymKey *)pOutputInfo);
      break;

    case MOC_ASYM_OP_SERIALIZE:
      keyFormat = noFormat;
      if (NULL != pInputInfo)
        keyFormat = *((serializedKeyFormat *)pInputInfo);
 
      status = QsTapSerializeKey (
        pMocAsymKey, keyFormat, (MKeyOperatorDataReturn *)pOutputInfo);
      break;

    case MOC_ASYM_OP_DESERIALIZE:
      status = QsTapDeserializeKey (
        pMocAsymKey, (MKeyOperatorData *)pInputInfo);
      break;

    case MOC_ASYM_OP_GET_LOCAL_KEY:
       status = ERR_NULL_POINTER;
       if (NULL != pOutputInfo)
       {
         status = OK;
         *((void **)pOutputInfo) = NULL;
 
         if (NULL != pMocAsymKey->pKeyData)
         {
           *((void **)pOutputInfo) =
             (void *)(((MQsTapKeyData *)(pMocAsymKey->pKeyData))->pKey);
         }
       }
 
       break;

    case MOC_ASYM_OP_FREE:
       status = QsTapFreeKey (pMocAsymKey);
       break;
  }

exit:

  return (status);
}
#endif /* (defined(__ENABLE_DIGICERT_ASYM_KEY__)) etc */
