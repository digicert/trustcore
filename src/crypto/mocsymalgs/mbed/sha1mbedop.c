/*
 * sha1mbedop.c
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


#ifdef __ENABLE_DIGICERT_SHA1_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbeddigestcommon.h"
#include "../../../crypto/mocsymalgs/mbed/mbedsha1.h"
#include "mbedtls/sha1.h"

#define SHA1_RESULT_SIZE 20
#define SHA1_BLOCK_SIZE  64

extern MSTATUS SymOperatorSha1(
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
        *((ubyte4 *)pOutputInfo) = MOC_LOCAL_TYPE_SHA1_OPERATOR;
        status = OK;
      }
      break;
    
    case MOC_SYM_OP_CREATE:
      status = MbedDigestCreate(
        pMocSymCtx, SymOperatorSha1, pInputInfo,
        sizeof(mbedtls_sha1_context), MOC_LOCAL_TYPE_SHA1_OPERATOR);
      break;
    
    case MOC_SYM_OP_DIGEST_INIT:
      status = MbedDigestInit(
        pMocSymCtx, (MbedDigestInitFunc) mbedtls_sha1_init,
        (MbedDigestStartFunc) mbedtls_sha1_starts_ret);
      break;
    
    case MOC_SYM_OP_DIGEST_INIT_CUSTOM:
      status = MbedSha1InitCustom(
        pMocSymCtx, (MSha1InitData *) pInputInfo);
      break;
      
    case MOC_SYM_OP_DIGEST_UPDATE:
      status = MbedDigestUpdate(
        pMocSymCtx, (MSymOperatorData *) pInputInfo,
        (MbedDigestUpdateFunc) mbedtls_sha1_update_ret);
      break;
    
    case MOC_SYM_OP_DIGEST_FINAL:
      status = MbedDigestFinal(
        pMocSymCtx, (MSymOperatorData *) pInputInfo,
        (MSymOperatorBuffer *) pOutputInfo,
        (MbedDigestUpdateFunc) mbedtls_sha1_update_ret,
        (MbedDigestFinalFunc) mbedtls_sha1_finish_ret,
        SHA1_RESULT_SIZE);
      break;
      
    case MOC_SYM_OP_DO_RAW_TRANSFORM:
      status = MbedSha1RawTransform(
        pMocSymCtx, (MSymOperatorData *) pInputInfo,
       (MSymOperatorBuffer *) pOutputInfo);
      break;
      
    case MOC_SYM_OP_CLONE:
      status = MbedDigestClone(
        pMocSymCtx, (MocSymCtx) pOutputInfo,
        (MbedDigestCloneFunc) mbedtls_sha1_clone);
      break;
    
    case MOC_SYM_OP_DIGEST_SIZE:
      status = ERR_NULL_POINTER;
      if (NULL != pOutputInfo)
      {
        *((ubyte4 *)pOutputInfo) = SHA1_RESULT_SIZE;
        status = OK;
      }
      break;

    case MOC_SYM_OP_BLOCK_SIZE:
      status = ERR_NULL_POINTER;
      if (NULL != pOutputInfo)
      {
        *((ubyte4 *)pOutputInfo) = SHA1_BLOCK_SIZE;
        status = OK;
      }
      break;
    
    case MOC_SYM_OP_FREE:
      status = MbedDigestFree(
        pMocSymCtx, (MbedDigestFreeFunc) mbedtls_sha1_free);
  }

exit:
  
  return status;
}
#endif /* __ENABLE_DIGICERT_SHA1_MBED__ */
