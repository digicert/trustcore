/*
 * mbedsha1.h
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

