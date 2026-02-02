/**
 * @file sapi2_signature.h
 * @brief This file contains code required to execute TPM2 asymmetric primitive
 * commands.
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
#ifndef __SAPI2_SIGNATURE_H__
#define __SAPI2_SIGNATURE_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "sapi2_context.h"
#include "sapi2_handles.h"

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pObjectHandle;
    TPM2B_DIGEST *pDigest;
    TPMT_SIG_SCHEME *pInScheme;
    TPMT_TK_HASHCHECK *pValidation;
    TPM2B_AUTH *pAuthObjectHandle;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} SignIn;

typedef struct {
    TPMT_SIGNATURE signature;
} SignOut;

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pObjectHandle;
    TPM2B_DIGEST *pDigest;
    TPMT_SIGNATURE *pSignature;
} VerifySignatureIn;

typedef struct {
    TPMT_TK_VERIFIED validation;
} VerifySignatureOut;

MOC_EXTERN TSS2_RC SAPI2_SIGNATURE_Sign(
        SAPI2_CONTEXT *pSapiContext,
        SignIn *pIn,
        SignOut *pOut
);

MOC_EXTERN TSS2_RC SAPI2_SIGNATURE_VerifySignature(
        SAPI2_CONTEXT *pSapiContext,
        VerifySignatureIn *pIn,
        VerifySignatureOut *pOut
);

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /* __SAPI2_SIGNATURE_H__ */
