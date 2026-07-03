/*
 * idtap.h
 *
 * Functions for performing TAP key by Id operations.
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

#ifndef __DIGICERT_ASYM_ID_TAP_HEADER__
#define __DIGICERT_ASYM_ID_TAP_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ENABLE_DIGICERT_TAP__)

/* first two methods are externed so Secure Storage TAP operator
   can make use of them */
MOC_EXTERN MSTATUS IdTapCreateAsn1(
  ubyte4 provider,
  ubyte4 moduleId,
  ubyte4 tokenId,
  ubyte *pOid,
  ubyte4 oidLen,
  ubyte *pId,
  ubyte4 idLen,
  ubyte **ppOut,
  ubyte4 *pOutLen);

MOC_EXTERN MSTATUS IdTapParseAsn1(
  ubyte *pInput,
  ubyte4 inputLen,
  ubyte *pOid,
  ubyte4 oidLen,
  TAP_Buffer *pId,
  ubyte4 *pTokenId,
  ubyte4 *pProvider,
  ubyte4 *pModule);

MOC_EXTERN MSTATUS IdTapSerializeKey (
  MKeyOperatorData *pInput,
  MKeyOperatorDataReturn *pOutput
  );

MOC_EXTERN MSTATUS IdTapDeserializeKey (
  MKeyOperatorData *pInput,
  MKeyOperatorDataReturn *pOutput
  );

MOC_EXTERN MSTATUS IdTapGetTapInfo(
  MKeyOperatorData *pInput,
  MKeyObjectInfo *pTapInfo,
  byteBoolean isSS
  );

MOC_EXTERN MSTATUS IdTapLoadKeyData (
  TAP_Buffer *pKeyId,
  TAP_KEY_ALGORITHM expectedKeyAlgo,
  MocAsymKey pMocAsymKey,
  TAP_Key **ppOutKey
  );

#endif /* defined(__ENABLE_DIGICERT_TAP__) */

#ifdef __cplusplus
}
#endif

#endif /* __DIGICERT_ASYM_ID_TAP_HEADER__ */
