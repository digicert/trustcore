/**
 * @file fapi2_attestation.h
 * @brief This file contains code and structures required for attestation.
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
#ifndef __FAPI2_ATTESTATION_H__
#define __FAPI2_ATTESTATION_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "fapi2_context.h"

/*
 * This API can be used to get a PCR quote signed by the TPM. An Attestation key
 * must be provided to sign the quote structure. Typically, a nonce is provided
 * to this API to ensure freshness of the quote but any other qualifying data
 * may be used.
 */
MOC_EXTERN TSS2_RC FAPI2_ATTESTATION_getQuote(
        FAPI2_CONTEXT *pCtx,
        AttestationGetQuoteIn *pIn,
        AttestationGetQuoteOut *pOut
);
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
#endif /* __FAPI2_ATTESTATION_H__ */
