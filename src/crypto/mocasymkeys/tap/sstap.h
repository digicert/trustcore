/*
 * sstap.h
 *
 * Functions for performing Secure Storage TAP operations.
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
