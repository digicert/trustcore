/*
 * md4mbedop.c
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


#ifdef __ENABLE_DIGICERT_MD4_MBED__

#include "../../../crypto/mocsymalgs/mbed/mbeddigestcommon.h"
#include "mbedtls/md4.h"

#define MD4_RESULT_SIZE 16
#define MD4_BLOCK_SIZE  64

extern MSTATUS SymOperatorMd4(
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
        *((ubyte4 *)pOutputInfo) = MOC_LOCAL_TYPE_MD4_OPERATOR;
        status = OK;
      }
      break;
    
    case MOC_SYM_OP_CREATE:
      status = MbedDigestCreate(
        pMocSymCtx, SymOperatorMd4, pInputInfo,
        sizeof(mbedtls_md4_context), MOC_LOCAL_TYPE_MD4_OPERATOR);
      break;
    
    case MOC_SYM_OP_DIGEST_INIT:
      status = MbedDigestInit(
        pMocSymCtx, (MbedDigestInitFunc) mbedtls_md4_init,
        (MbedDigestStartFunc) mbedtls_md4_starts_ret);
      break;
    
    case MOC_SYM_OP_DIGEST_UPDATE:
      status = MbedDigestUpdate(
        pMocSymCtx, (MSymOperatorData *) pInputInfo,
        (MbedDigestUpdateFunc) mbedtls_md4_update_ret);
      break;
    
    case MOC_SYM_OP_DIGEST_FINAL:
      status = MbedDigestFinal(
        pMocSymCtx, (MSymOperatorData *) pInputInfo,
        (MSymOperatorBuffer *) pOutputInfo,
        (MbedDigestUpdateFunc) mbedtls_md4_update_ret,
        (MbedDigestFinalFunc) mbedtls_md4_finish_ret,
        MD4_RESULT_SIZE);
      break;
    
    case MOC_SYM_OP_CLONE:
      status = MbedDigestClone(
        pMocSymCtx, (MocSymCtx) pOutputInfo,
        (MbedDigestCloneFunc) mbedtls_md4_clone);
      break;
    
    case MOC_SYM_OP_DIGEST_SIZE:
      status = ERR_NULL_POINTER;
      if (NULL != pOutputInfo)
      {
        *((ubyte4 *)pOutputInfo) = MD4_RESULT_SIZE;
        status = OK;
      }
      break;

    case MOC_SYM_OP_BLOCK_SIZE:
      status = ERR_NULL_POINTER;
      if (NULL != pOutputInfo)
      {
        *((ubyte4 *)pOutputInfo) = MD4_BLOCK_SIZE;
        status = OK;
      }
      break;
    
    case MOC_SYM_OP_FREE:
      status = MbedDigestFree(
        pMocSymCtx, (MbedDigestFreeFunc) mbedtls_md4_free);
  }

exit:
  
  return status;
}
#endif /* __ENABLE_DIGICERT_MD4_MBED__ */
