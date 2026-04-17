/*
 * mbedpoly1305.h
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

#include "mbedtls/poly1305.h"

#ifndef __MBEDPOLY1305_HEADER__
#define __MBEDPOLY1305_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#define MOC_POLY1305_KEY_LEN 32
#define MOC_POLY1305_MAC_LEN 16

typedef struct
{
  mbedtls_poly1305_context *pPolyCtx;
  ubyte pKey[MOC_POLY1305_KEY_LEN];
  ubyte4 keyLen;
} MbedPolyInfo;


MOC_EXTERN MSTATUS MPoly1305MbedCreate (
  MocSymCtx pSymCtx
  );

MOC_EXTERN MSTATUS MPoly1305MbedLoadKey (
  MocSymCtx pSymCtx,
  MSymOperatorData *pKeyData
  );

MOC_EXTERN MSTATUS MPoly1305MbedInit (
  MocSymCtx pSymCtx
  );

MOC_EXTERN MSTATUS MPoly1305MbedUpdate (
  MocSymCtx pSymCtx,
  MSymOperatorData *pInput
  );

MOC_EXTERN MSTATUS MPoly1305MbedFinal (
  MocSymCtx pSymCtx,
  MSymOperatorData *pInput,
  MSymOperatorBuffer *pOutput
  );

MOC_EXTERN MSTATUS MPoly1305MbedFreeData (
  MbedPolyInfo **ppCtx
  );

MOC_EXTERN MSTATUS MPoly1305MbedFree (
  MocSymCtx pSymCtx
  );

MOC_EXTERN MSTATUS MPoly1305MbedClone(
  MocSymCtx pCtx,
  MocSymCtx pCopyCtx
  );


#ifdef __cplusplus
}
#endif

#endif /* __MBEDPOLY1305_HEADER__ */
