/*
 * mbedsha1.h
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

#ifndef __DIGICERT_MBED_SHA1_H__
#define __DIGICERT_MBED_SHA1_H__

#ifdef __cplusplus
extern "C" {
#endif

MOC_EXTERN MSTATUS MbedSha1InitCustom(
  MocSymCtx pMocSymCtx,
  MSha1InitData *pInitConsts
  );
  
MOC_EXTERN MSTATUS MbedSha1RawTransform(
  MocSymCtx pMocSymCtx,
  MSymOperatorData *pInputInfo,
  MSymOperatorBuffer *pOutputInfo
  );
  
#ifdef __cplusplus
}
#endif

#endif /* __DIGICERT_MBED_SHA1_H__ */

