/**
 * @file fapi2_rng.h
 * @brief This file contains functions to use the TPM2 random number
 * generator.
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
#ifndef __FAPI2_RNG_H__
#define __FAPI2_RNG_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "fapi2_context.h"

/*
 * Use this function to get random data from the TPM. The number of
 * bytes returned by the TPM will be no larger than the digest
 * produced by the largest digest algorithm supported by the TPM.
 */
MOC_EXTERN TSS2_RC FAPI2_RNG_getRandomData(
        FAPI2_CONTEXT *pCtx,
        RngGetRandomDataIn *pIn,
        RngGetRandomDataOut *pOut
);

/*
 * This function can be used to add additional state to the TPM
 * RNG.
 */
MOC_EXTERN TSS2_RC FAPI2_RNG_stirRNG(
        FAPI2_CONTEXT *pCtx,
        RngStirRNGIn *pIn
);
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
#endif /* __FAPI2_RNG_H__ */
