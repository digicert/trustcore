/*
 * chacha20mbedop.c
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

#include "../../../crypto/mocsym.h"


#ifdef __ENABLE_DIGICERT_CHACHA20_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbedchacha20.h"

MOC_EXTERN MSTATUS SymOperatorChaCha20(
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
        *((ubyte4 *) pOutputInfo) = MOC_LOCAL_TYPE_CHACHA20_OPERATOR;
        status = OK;
      }
      break;

    case MOC_SYM_OP_CREATE:
      status = MChaCha20MbedCreate(pMocSymCtx, (MChaChaUpdateData *) pInputInfo);
      break;

    case MOC_SYM_OP_UPDATE_OP_DATA:
      status = MChaCha20MbedUpdateInfo(
        pMocSymCtx, (MChaChaUpdateData *) pInputInfo);
      break;

    case MOC_SYM_OP_LOAD_KEY:
      status = MChaCha20MbedLoadKey(
        pMocSymCtx, (MSymOperatorData *) pInputInfo);
      break;

    case MOC_SYM_OP_ENCRYPT_INIT:
    case MOC_SYM_OP_DECRYPT_INIT:
      status = MChaCha20MbedInit(pMocSymCtx);
      break;

    case MOC_SYM_OP_ENCRYPT_UPDATE:
    case MOC_SYM_OP_DECRYPT_UPDATE:
    case MOC_SYM_OP_ENCRYPT_FINAL:
    case MOC_SYM_OP_DECRYPT_FINAL:
      status = MChaCha20MbedUpdate(
        pMocSymCtx, (MSymOperatorData *) pInputInfo,
        (MSymOperatorBuffer *) pOutputInfo);
      break;

    case MOC_SYM_OP_FREE:
      status = MChaCha20MbedFree (pMocSymCtx);
      break;
  }

  return status;
}
#endif
