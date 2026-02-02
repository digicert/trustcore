/**
 * @file sapi2_attestation.h
 * @brief This file contains code required to execute TPM2 attestation commands such as quote.
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
#ifndef __SAPI2_ATTESTATION_H__
#define __SAPI2_ATTESTATION_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "sapi2_context.h"
#include "sapi2_handles.h"

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pSignHandle;
    TPM2B_AUTH *pAuthSignHandle;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
    TPM2B_DATA *pQualifyingData;
    TPMT_SIG_SCHEME *pScheme;
    TPML_PCR_SELECTION *pPcrSelection;
} QuoteIn;

typedef struct {
    TPM2B_ATTEST quote;
    TPMT_SIGNATURE signature;
} QuoteOut;

MOC_EXTERN TSS2_RC SAPI2_ATTESTATION_Quote(
        SAPI2_CONTEXT *pSapiContext,
        QuoteIn *pIn,
        QuoteOut *pOut
);
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /* __SAPI2_ATTESTATION_H__ */
