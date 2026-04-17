/*
 * chachapolymbedop.c
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

#include "../../../crypto/mocsym.h"


#if defined(__ENABLE_DIGICERT_CHACHA20_MBED__) && defined(__ENABLE_DIGICERT_POLY1305_MBED__)

#include "../../../crypto/mocsymalgs/mbed/mbedchachapoly.h"

MOC_EXTERN MSTATUS SymOperatorChaChaPoly(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  )
{
  MSTATUS status;

  switch (symOp)
  {
    default:
      status = ERR_NOT_IMPLEMENTED;
      break;

    case MOC_SYM_OP_GET_LOCAL_TYPE:
      status = ERR_NULL_POINTER;
      if (NULL != pOutputInfo)
      {
        *((ubyte4 *) pOutputInfo) = MOC_LOCAL_TYPE_CHACHAPOLY_OPERATOR;
        status = OK;
      }
      break;

    case MOC_SYM_OP_CREATE:
      status = MChaChaPolyMbedCreate(pMocSymCtx, (sbyte4 *) pInputInfo);
      break;

    case MOC_SYM_OP_UPDATE_OP_DATA:
      status = MChaChaPolyMbedUpdateInfo(
        pMocSymCtx, (MChaChaUpdateData *) pInputInfo);
      break;

    case MOC_SYM_OP_LOAD_KEY:
      status = MChaChaPolyMbedLoadKey(
        pMocSymCtx, (MSymOperatorData *) pInputInfo);
      break;

    case MOC_SYM_OP_ENCRYPT_INIT:
    case MOC_SYM_OP_DECRYPT_INIT:
      status = MChaChaPolyMbedInit(pMocSymCtx);
      break;

    case MOC_SYM_OP_ENCRYPT_UPDATE:
    case MOC_SYM_OP_DECRYPT_UPDATE:
      status = MChaChaPolyMbedUpdate(
        pMocSymCtx, (MSymOperatorData *) pInputInfo,
        (MSymOperatorBuffer *) pOutputInfo);
      break;

    case MOC_SYM_OP_ENCRYPT_FINAL:
    case MOC_SYM_OP_DECRYPT_FINAL:
      status = MChaChaPolyMbedFinal(
        pMocSymCtx, (MSymOperatorData *) pInputInfo,
        (MSymOperatorBuffer *) pOutputInfo);
      break;

    case MOC_SYM_OP_CLONE:
      status = MChaChaPolyMbedClone(
          pMocSymCtx, (MocSymCtx) pOutputInfo);
      break;

    case MOC_SYM_OP_FREE:
      status = MChaChaPolyMbedFree (pMocSymCtx);
      break;
  }

  return status;
}
#endif
