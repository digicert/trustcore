/**
 * @file sapi2_rng.h
 * @brief This file contains code required to use the TPMs random number generator.
 *
 * @flags
 *  To enable this file's functions, the following flags must be defined in
 * moptions.h:
 *
 *  + \c \__ENABLE_DIGICERT_TPM2__
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
#ifndef __SAPI2_RNG_H__
#define __SAPI2_RNG_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "sapi2_context.h"

typedef struct {
    ubyte2 bytesRequested;
} GetRandomIn;

typedef struct {
    TPM2B_DIGEST randomBytes;
} GetRandomOut;

typedef struct {
    TPM2B_SENSITIVE_DATA *pInData;
} StirRandomIn;

MOC_EXTERN TSS2_RC SAPI2_RNG_GetRandom(
        SAPI2_CONTEXT *pSapiContext,
        GetRandomIn *pIn,
        GetRandomOut *pOut
);

MOC_EXTERN TSS2_RC SAPI2_RNG_StirRandom(
        SAPI2_CONTEXT *pSapiContext,
        StirRandomIn *pIn
);

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
#endif /* __SAPI2_RNG_H__ */
