/*
 * mbedpkcs5pbe.h
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
