/**
 * @file fapi2_testing.h
 * @brief This file contains code for testing the TPM2.
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
#ifndef __FAPI2_TESTING_H__
#define __FAPI2_TESTING_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "fapi2_context.h"

/*
 * This function tells the TPM to perform a selftest.
 */
MOC_EXTERN TSS2_RC FAPI2_TESTING_SelfTest(
        FAPI2_CONTEXT *pCtx,
        TestingSelfTestIn *pIn,
        TestingSelfTestOut *pOut
);


/*
 * This function gets the result of the last selftest performed.
 */
TSS2_RC FAPI2_TESTING_getTestResult(
        FAPI2_CONTEXT *pCtx,
        TestingSelfTestOut *pOut
);

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /* __FAPI2_TESTING_H__ */
