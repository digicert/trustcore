/*
 * sstap.h
 *
 * Functions for performing Secure Storage TAP operations.
 *
 * Copyright Mocana Corp 2023. All Rights Reserved.
 * Proprietary and Confidential Material.
 *
 */

#include "../../../crypto/mocasym.h"
#include "../../../crypto/mocasymkeys/mocsw/commonasym.h"
#include "../../../tap/tap_api.h"
#include "../../../tap/tap_smp.h"

#ifndef __MOCANA_ASYM_SS_TAP_HEADER__
#define __MOCANA_ASYM_SS_TAP_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ENABLE_MOCANA_TAP__)

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

#endif /* defined(__ENABLE_MOCANA_TAP__) */

#ifdef __cplusplus
}
#endif

#endif /* __MOCANA_ASYM_SS_TAP_HEADER__ */
