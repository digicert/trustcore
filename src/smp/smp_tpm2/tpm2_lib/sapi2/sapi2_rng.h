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
