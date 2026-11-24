/*
 * id.h
 *
 * ASN.1 helpers for keys identified by ID.
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

#ifndef __DIGICERT_ASYM_KEY_ID_HEADER__
#define __DIGICERT_ASYM_KEY_ID_HEADER__

#include "../../../crypto/mocasym.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ENABLE_DIGICERT_ASYM_KEY__) && defined(__ENABLE_DIGICERT_SERIALIZE__)

/* ppId and pIdLen must either both be NULL or both be non-NULL. */
MOC_EXTERN MSTATUS IdParseAsn1 (
  ubyte *pInput, ubyte4 inputLen, ubyte *pOid, ubyte4 oidLen,
  ubyte **ppId, ubyte4 *pIdLen, ubyte4 *pTokenId,
  ubyte4 *pProvider, ubyte4 *pModule);

MOC_EXTERN MSTATUS IdCreateAsn1 (
  ubyte4 provider, ubyte4 moduleId, ubyte4 tokenId, ubyte *pOid, ubyte4 oidLen,
  ubyte *pId, ubyte4 idLen, ubyte **ppOut, ubyte4 *pOutLen);

MOC_EXTERN MSTATUS IdSerializeKey (
  MKeyOperatorData *pInput, MKeyOperatorDataReturn *pOutput);

MOC_EXTERN MSTATUS IdDeserializeKey (
  MKeyOperatorData *pInput, MKeyObjectInfo *pOutput);

#endif

#ifdef __cplusplus
}
#endif

#endif /* __DIGICERT_ASYM_KEY_ID_HEADER__ */
