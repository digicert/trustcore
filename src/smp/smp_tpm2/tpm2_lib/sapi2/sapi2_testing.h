/**
 * @file sapi2_testing.h
 * @brief This file contains code required to execute TPM test commands.
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
#ifndef __SAPI2_TESTING_H__
#define __SAPI2_TESTING_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "sapi2_context.h"
#include "sapi2_handles.h"

typedef struct {
    TPMI_YES_NO fullTest;
} SelfTestIn;

typedef struct {
    TPM2B_MAX_BUFFER outData;
    TPM2_RC testResult;
} GetTestResultOut;

MOC_EXTERN TSS2_RC SAPI2_TESTING_SelfTest(
        SAPI2_CONTEXT *pSapiContext,
        SelfTestIn *pIn
);

MOC_EXTERN TSS2_RC SAPI2_TESTING_GetTestResult(
        SAPI2_CONTEXT *pSapiContext,
        GetTestResultOut *pOut
);
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
#endif /* __SAPI2_TESTING_H__ */
