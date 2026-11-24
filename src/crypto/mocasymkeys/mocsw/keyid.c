/*
 * keyid.c
 *
 * Operator for keys identified by ID.
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

#include "../../../crypto/mocasymkeys/mocsw/id.h"

#if defined(__ENABLE_DIGICERT_ASYM_KEY__)

MOC_EXTERN MSTATUS KeyOperatorId (
  MocAsymKey pMocAsymKey,
  MocCtx pMocCtx,
  keyOperation keyOp,
  void *pInputInfo,
  void *pOutputInfo,
  struct vlong **ppVlongQueue
  )
{
  switch (keyOp)
  {
    case MOC_ASYM_OP_GET_LOCAL_TYPE:
      if (NULL == pOutputInfo)
        return ERR_NULL_POINTER;
      *((ubyte4 *) pOutputInfo) = MOC_LOCAL_TYPE_ID;
      return OK;

    case MOC_ASYM_OP_GET_PARAMS:
#if defined(__ENABLE_DIGICERT_SERIALIZE__)
    {
      MKeyOperatorData *pInput = (MKeyOperatorData *) pInputInfo;
      MKeyObjectInfo *pInfo = (MKeyObjectInfo *) pOutputInfo;
      ubyte pOid[MOP_TAP_KEY_ID_ALG_ID_LEN] = {MOP_TAP_KEY_ID_ALG_ID};

      if (NULL == pInput || NULL == pInfo || NULL == pInput->pData)
        return ERR_NULL_POINTER;

      return IdParseAsn1(pInput->pData, pInput->length, pOid, sizeof(pOid),
                         NULL, NULL, NULL, &pInfo->provider, &pInfo->moduleId);
    }
#else
      return ERR_NOT_IMPLEMENTED;
#endif

    case MOC_ASYM_OP_DESERIALIZE:
#if defined(__ENABLE_DIGICERT_SERIALIZE__)
      return IdDeserializeKey((MKeyOperatorData *) pInputInfo,
                              (MKeyObjectInfo *) pOutputInfo);
#else
      return ERR_NOT_IMPLEMENTED;
#endif

    case MOC_ASYM_OP_SERIALIZE:
#if defined(__ENABLE_DIGICERT_SERIALIZE__)
      return IdSerializeKey((MKeyOperatorData *) pInputInfo,
                            (MKeyOperatorDataReturn *) pOutputInfo);
#else
      return ERR_NOT_IMPLEMENTED;
#endif

    default:
      return ERR_NOT_IMPLEMENTED;
  }
}

#endif
