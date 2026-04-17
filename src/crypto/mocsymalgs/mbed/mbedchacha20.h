/*
 * mbedchacha20.h
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

#include "mbedtls/chacha20.h"

#ifndef __MBEDCHACHA20_HEADER__
#define __MBEDCHACHA20_HEADER__

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CHACHA20_KEY_LEN
#define CHACHA20_KEY_LEN 32
#endif

#ifndef CHACHA20_NONCE_LEN
#define CHACHA20_NONCE_LEN 12
#endif

typedef struct
{
  mbedtls_chacha20_context *pMbedChaChaCtx;

  ubyte pKey[CHACHA20_KEY_LEN];
  ubyte4 keyLen;

  ubyte pNonce[CHACHA20_NONCE_LEN];
  ubyte4 nonceLen;

  ubyte4 counter;

} MbedChaChaInfo;


MOC_EXTERN MSTATUS MChaCha20MbedCreate (
  MocSymCtx pCtx,
  MChaChaUpdateData *pInput
  );

MOC_EXTERN MSTATUS MChaCha20MbedLoadKey (
  MocSymCtx pCtx,
  MSymOperatorData *pKeyData
  );

MOC_EXTERN MSTATUS MChaCha20MbedUpdateInfo (
  MocSymCtx pCtx,
  MChaChaUpdateData *pInput
  );

MOC_EXTERN MSTATUS MChaCha20MbedInit (
  MocSymCtx pCtx
  );

MOC_EXTERN MSTATUS MChaCha20MbedUpdate (
  MocSymCtx pCtx,
  MSymOperatorData *pInput,
  MSymOperatorBuffer *pOutput
  );

MOC_EXTERN MSTATUS MChaCha20MbedFree (
  MocSymCtx pCtx
  );

#ifdef __cplusplus
}
#endif

#endif /* __MBEDCHACHA20_HEADER__ */
