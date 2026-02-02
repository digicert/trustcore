/**
 * @file fapi2_data.h
 * @brief This file contains definitions to perform data operations using
 * the TPM such as sealing/unsealing data.
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
#ifndef __FAPI2_DATA_H__
#define __FAPI2_DATA_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "fapi2_context.h"

/*
 * This function protects the given data blob using the TPM. The
 * blob is encrypted and integrity protected by the TPM and can
 * only be unsealed/unprotected using the same authValue. With TPM2.0
 * sealing data is no more than creating an object with TPM2_Create.
 * The authValue of the SRK is expected to be set and correct in the
 * context as the sealed object will be created under the SRK.
 * DA Protection for the sealed object is disabled.
 */
MOC_EXTERN TSS2_RC FAPI2_DATA_seal(
        FAPI2_CONTEXT *pCtx,
        DataSealIn *pIn,
        DataSealOut *pOut
);

/*
 * This function unseals a sealed data blob from the TPM.
 */
MOC_EXTERN TSS2_RC FAPI2_DATA_unseal(
        FAPI2_CONTEXT *pCtx,
        DataUnsealIn *pIn,
        DataUnsealOut *pOut
);

/*
 * This function uses the TPM to digest a given data buffer using the specified
 * hash algorithm.
 */
MOC_EXTERN TSS2_RC FAPI2_DATA_digest(
        FAPI2_CONTEXT *pCtx,
        DataDigestIn *pIn,
        DataDigestOut *pOut
);
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
#endif /* __FAPI2_DATA_H__ */
