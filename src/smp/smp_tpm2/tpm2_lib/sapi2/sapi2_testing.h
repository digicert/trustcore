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
