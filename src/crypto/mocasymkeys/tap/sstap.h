/*
 * sstap.h
 *
 * Functions for performing Secure Storage TAP operations.
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

#include "../../../crypto/mocasym.h"
#include "../../../crypto/mocasymkeys/mocsw/commonasym.h"
#include "../../../tap/tap_api.h"
#include "../../../tap/tap_smp.h"

#ifndef __DIGICERT_ASYM_SS_TAP_HEADER__
#define __DIGICERT_ASYM_SS_TAP_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ENABLE_DIGICERT_TAP__)

MOC_EXTERN MSTATUS SSTapSerializeKey (
  MKeyOperatorData *pInput,
  MKeyOperatorDataReturn *pOutput
  );

MOC_EXTERN MSTATUS SSTapDeserializeKey (
  MKeyOperatorData *pInput,
  MKeyOperatorDataReturn *pOutput
  );

MOC_EXTERN MSTATUS SSTapGetTapInfo(
  MKeyOperatorData *pInput,
  MKeyObjectInfo *pTapInfo
  );

#endif /* defined(__ENABLE_DIGICERT_TAP__) */

#ifdef __cplusplus
}
#endif

#endif /* __DIGICERT_ASYM_SS_TAP_HEADER__ */
