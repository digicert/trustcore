/*
 * mbedchachapoly.h
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

#include "mbedtls/chachapoly.h"

#ifndef __MBEDCHACHAPOLY_HEADER__
#define __MBEDCHACHAPOLY_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CHACHA20_KEY_LEN
#define CHACHA20_KEY_LEN 32
#endif

#ifndef CHACHA20_NONCE_LEN
#define CHACHA20_NONCE_LEN 12
#endif

#ifndef CHACHAPOLY_TAG_LEN
#define CHACHAPOLY_TAG_LEN 16
#endif

typedef struct
{
  mbedtls_chachapoly_context *pAeadCtx;
  ubyte pNonce[CHACHA20_NONCE_LEN];
  sbyte4 encrypt;

} MbedChaChaPolyInfo;

MOC_EXTERN MSTATUS MChaChaPolyMbedCreate (
  MocSymCtx pCtx,
  sbyte4 *pEncrypt
  );

MOC_EXTERN MSTATUS MChaChaPolyMbedLoadKey (
  MocSymCtx pCtx,
  MSymOperatorData *pKeyData
  );

MOC_EXTERN MSTATUS MChaChaPolyMbedUpdateInfo (
  MocSymCtx pCtx,
  MChaChaUpdateData *pInput
  );

MOC_EXTERN MSTATUS MChaChaPolyMbedInit (
  MocSymCtx pCtx
  );

MOC_EXTERN MSTATUS MChaChaPolyMbedUpdate (
  MocSymCtx pCtx,
  MSymOperatorData *pInput,
  MSymOperatorBuffer *pOutput
  );

MOC_EXTERN MSTATUS MChaChaPolyMbedFinal (
  MocSymCtx pCtx,
  MSymOperatorData *pInput,
  MSymOperatorBuffer *pOutput
  );

MOC_EXTERN MSTATUS MChaChaPolyMbedFree (
  MocSymCtx pCtx
  );

MOC_EXTERN MSTATUS MChaChaPolyMbedClone(
  MocSymCtx pCtx,
  MocSymCtx pCopyCtx
  );

#ifdef __cplusplus
}
#endif

#endif /* __MBEDCHACHAPOLY_HEADER__ */
