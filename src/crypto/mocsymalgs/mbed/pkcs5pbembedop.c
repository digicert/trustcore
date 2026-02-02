/*
 * pkcs5pbembedop.c
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


#ifdef __ENABLE_DIGICERT_PKCS5_MBED__

#include "mbedpkcs5pbe.h"

MOC_EXTERN MSTATUS SymOperatorPkcs5Pbe(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  )
{
  MSTATUS status;

  switch(symOp)
  {
    case MOC_SYM_OP_GET_LOCAL_TYPE:
      status = ERR_NULL_POINTER;
      if (NULL != pOutputInfo)
      {
        *((ubyte4 *) pOutputInfo) = MOC_LOCAL_TYPE_PKCS5_PBE_OPERATOR;
        status = OK;
      }
      break;

    case MOC_SYM_OP_CREATE:
      status = MPkcs5PbeMbedCreate (pMocSymCtx, (ubyte *) pInputInfo);
      break;

    case MOC_SYM_OP_ENCRYPT_INIT:
      status = MPkcs5PbeMbedInitEncrypt(pMocSymCtx);
      break;

    case MOC_SYM_OP_DECRYPT_INIT:
      status = MPkcs5PbeMbedInitDecrypt(pMocSymCtx);
      break;

    case MOC_SYM_OP_ENCRYPT_UPDATE:
    case MOC_SYM_OP_ENCRYPT_FINAL:
      status = MPkcs5PbeMbedCipher(pMocSymCtx, MBEDTLS_PKCS5_ENCRYPT, (MSymOperatorData *) pInputInfo, (MSymOperatorBuffer *) pOutputInfo);
      break;

    case MOC_SYM_OP_DECRYPT_UPDATE:
    case MOC_SYM_OP_DECRYPT_FINAL:
      status = MPkcs5PbeMbedCipher(pMocSymCtx, MBEDTLS_PKCS5_DECRYPT, (MSymOperatorData *) pInputInfo, (MSymOperatorBuffer *) pOutputInfo);
      break;

    case MOC_SYM_OP_DERIVE_KEY:
      status = MPkcs5PbeMbedDeriveKey (pMocSymCtx, (MSymOperatorBuffer *) pOutputInfo);
      break;

    case MOC_SYM_OP_FREE:
      status = MPkcs5PbeMbedFree (pMocSymCtx);
      break;

    default:
      status = ERR_NOT_IMPLEMENTED;
      break;
  }

  return status;
}
#endif /* ifdef __ENABLE_DIGICERT_PKCS5_MBED__ */
