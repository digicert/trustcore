/*
 * sha256mbedop.c
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


#ifdef __ENABLE_DIGICERT_SHA256_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbeddigestcommon.h"
#include "mbedtls/sha256.h"

#define SHA256_RESULT_SIZE 32
#define SHA256_BLOCK_SIZE  64

#define SHA256_START_FLAG 0

int MbedSha256StartWrapper(
  void *pCtx
  );

extern MSTATUS SymOperatorSha256(
  MocSymCtx pMocSymCtx,
  MocCtx pMocCtx,
  symOperation symOp,
  void *pInputInfo,
  void *pOutputInfo
  )
{
  MSTATUS status;
  
  status = ERR_NULL_POINTER;
  if (NULL == pMocSymCtx)
    goto exit;

  switch (symOp)
  {
    default:
      status = ERR_NOT_IMPLEMENTED;
      goto exit;
    
    case MOC_SYM_OP_GET_LOCAL_TYPE:
      status = ERR_NULL_POINTER;
      if (NULL != pOutputInfo)
      {
        *((ubyte4 *)pOutputInfo) = MOC_LOCAL_TYPE_SHA256_OPERATOR;
        status = OK;
      }
      break;
  
    case MOC_SYM_OP_CREATE:
      status = MbedDigestCreate(
        pMocSymCtx, SymOperatorSha256, pInputInfo,
        sizeof(mbedtls_sha256_context), MOC_LOCAL_TYPE_SHA256_OPERATOR);
      break;
    
    case MOC_SYM_OP_DIGEST_INIT:
      status = MbedDigestInit(
        pMocSymCtx, (MbedDigestInitFunc) mbedtls_sha256_init,
        MbedSha256StartWrapper);
      break;
    
    case MOC_SYM_OP_DIGEST_UPDATE:
      status = MbedDigestUpdate(
        pMocSymCtx, (MSymOperatorData *) pInputInfo,
        (MbedDigestUpdateFunc) mbedtls_sha256_update_ret);
      break;
    
    case MOC_SYM_OP_DIGEST_FINAL:
      status = MbedDigestFinal(
        pMocSymCtx, (MSymOperatorData *) pInputInfo,
        (MSymOperatorBuffer *) pOutputInfo,
        (MbedDigestUpdateFunc) mbedtls_sha256_update_ret,
        (MbedDigestFinalFunc) mbedtls_sha256_finish_ret,
        SHA256_RESULT_SIZE);
      break;
    
    case MOC_SYM_OP_CLONE:
      status = MbedDigestClone(
        pMocSymCtx, (MocSymCtx) pOutputInfo,
        (MbedDigestCloneFunc) mbedtls_sha256_clone);
      break;

    case MOC_SYM_OP_DIGEST_SIZE:
      status = ERR_NULL_POINTER;
      if (NULL != pOutputInfo)
      {
        *((ubyte4 *)pOutputInfo) = SHA256_RESULT_SIZE;
        status = OK;
      }
      break;

    case MOC_SYM_OP_BLOCK_SIZE:
      status = ERR_NULL_POINTER;
      if (NULL != pOutputInfo)
      {
        *((ubyte4 *)pOutputInfo) = SHA256_BLOCK_SIZE;
        status = OK;
      }
      break;
  
    case MOC_SYM_OP_FREE:
      status = MbedDigestFree(
        pMocSymCtx, (MbedDigestFreeFunc) mbedtls_sha256_free);
  }

exit:

  return status;
}

int MbedSha256StartWrapper(
  void *pCtx
  )
{
  return mbedtls_sha256_starts_ret(pCtx, SHA256_START_FLAG);
}
#endif
