/*
 * md5mbedop.c
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


#ifdef __ENABLE_DIGICERT_MD5_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbeddigestcommon.h"
#include "mbedtls/md5.h"

#define MD5_RESULT_SIZE 16
#define MD5_BLOCK_SIZE  64

extern MSTATUS SymOperatorMd5(
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
        *((ubyte4 *)pOutputInfo) = MOC_LOCAL_TYPE_MD5_OPERATOR;
        status = OK;
      }
      break;
    
    case MOC_SYM_OP_CREATE:
      status = MbedDigestCreate(
        pMocSymCtx, SymOperatorMd5, pInputInfo,
        sizeof(mbedtls_md5_context), MOC_LOCAL_TYPE_MD5_OPERATOR);
      break;
    
    case MOC_SYM_OP_DIGEST_INIT:
      status = MbedDigestInit(
        pMocSymCtx, (MbedDigestInitFunc) mbedtls_md5_init,
        (MbedDigestStartFunc) mbedtls_md5_starts_ret);
      break;
    
    case MOC_SYM_OP_DIGEST_UPDATE:
      status = MbedDigestUpdate(
        pMocSymCtx, (MSymOperatorData *) pInputInfo,
        (MbedDigestUpdateFunc) mbedtls_md5_update_ret);
      break;
    
    case MOC_SYM_OP_DIGEST_FINAL:
      status = MbedDigestFinal(
        pMocSymCtx, (MSymOperatorData *) pInputInfo,
        (MSymOperatorBuffer *) pOutputInfo,
        (MbedDigestUpdateFunc) mbedtls_md5_update_ret,
        (MbedDigestFinalFunc) mbedtls_md5_finish_ret,
        MD5_RESULT_SIZE);
      break;
    
    case MOC_SYM_OP_CLONE:
      status = MbedDigestClone(
        pMocSymCtx, (MocSymCtx) pOutputInfo,
        (MbedDigestCloneFunc) mbedtls_md5_clone);
      break;
    
    case MOC_SYM_OP_DIGEST_SIZE:
      status = ERR_NULL_POINTER;
      if (NULL != pOutputInfo)
      {
        *((ubyte4 *)pOutputInfo) = MD5_RESULT_SIZE;
        status = OK;
      }
      break;

    case MOC_SYM_OP_BLOCK_SIZE:
      status = ERR_NULL_POINTER;
      if (NULL != pOutputInfo)
      {
        *((ubyte4 *)pOutputInfo) = MD5_BLOCK_SIZE;
        status = OK;
      }
      break;
    
    case MOC_SYM_OP_FREE:
      status = MbedDigestFree(
        pMocSymCtx, (MbedDigestFreeFunc) mbedtls_md5_free);
  }

exit:
  
  return status;
}
#endif /* __ENABLE_DIGICERT_MD5_MBED__ */
