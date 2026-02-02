/**
 * @file fapi2_ea_internal.h
 * @brief This file contains code for using TPM2's enhanced policy authorization.
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
#ifndef __FAPI2_EA_INTERNAL_H__
#define __FAPI2_EA_INTERNAL_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "fapi2_context.h"

typedef struct {

    /*
     * Policy nodes that need to be executed
     */
    ubyte2 numPolicyTerms;
    PolicyAuthNode *pObjectPolicy;

    /*
     * Policy session in which the policy is to be executed.
     * If pSession is NULL, a trial policy session will be started
     * and the policy executed.
     */
    MOCTPM2_OBJECT_HANDLE *pSession;
} EaExecutePolicyIn;

typedef struct {
    /*
     * Digest of the executed policy
     */
    TPM2B_DIGEST policyDigest;
} EaExecutePolicyOut;

MOC_EXTERN TSS2_RC FAPI2_EA_executePolicy(
        FAPI2_CONTEXT *pCtx,
        EaExecutePolicyIn *pIn,
        EaExecutePolicyOut *pOut
);
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /* __FAPI2_EA_INTERNAL_H__ */
