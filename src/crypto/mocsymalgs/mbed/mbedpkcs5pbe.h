/*
 * mbedpkcs5pbe.h
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

#include "mbedtls/pkcs5.h"

#ifndef __MBED_PKCS5_PBE_H__
#define __MBED_PKCS5_PBE_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct MbedPkcs5PbeInfo
{

  mbedtls_md_context_t *pMbedCtx;
  void *pOpData;
  mbedtls_asn1_buf *pPBEparams;

} MbedPkcs5PbeInfo;


MOC_EXTERN MSTATUS MPkcs5PbeMbedCreate (
  MocSymCtx pSymCtx,
  void *pOpInputData
  );

MOC_EXTERN MSTATUS MPkcs5PbeMbedDeriveKey (
  MocSymCtx pSymCtx,
  MSymOperatorBuffer *pOutput
  );

MOC_EXTERN MSTATUS MPkcs5PbeMbedInitEncrypt (
  MocSymCtx pSymCtx
  );

MOC_EXTERN MSTATUS MPkcs5PbeMbedInitDecrypt (
  MocSymCtx pSymCtx
  );

MOC_EXTERN MSTATUS MPkcs5PbeMbedCipher(
  MocSymCtx pSymCtx, 
  sbyte4 direction, 
  MSymOperatorData *pInput,
  MSymOperatorBuffer * pOutput
  );

MOC_EXTERN MSTATUS MPkcs5PbeMbedFree (
  MocSymCtx pSymCtx
  );

#ifdef __cplusplus
}
#endif

#endif /* __MBED_PKCS5_PBE_H__ */
