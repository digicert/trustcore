/**
 * @file sapi2_enhanced_auth.h
 * @brief This file contains code required to execute TPM2 enhanced authorization
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
#ifndef __SAPI2_ENAHANCED_AUTH_H__
#define __SAPI2_ENAHANCED_AUTH_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pPolicySession;
} PolicyGetDigestIn;

typedef struct {
    TPM2B_DIGEST policyDigest;
} PolicyGetDigestOut;

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pPolicySession;
    TPM2B_NAME		*pObjectName;
    TPM2B_NAME		*pNewParentName;
    TPMI_YES_NO		includeObject;
} PolicyDuplicationSelectIn;

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pPolicySession;
    TPM2_CC code ;
} PolicyCommandCodeIn;

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pPolicySession;
} PolicyAuthValueIn;

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pAuthObject;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
    TPM2B_AUTH *pAuthObjectAuth;
    MOCTPM2_OBJECT_HANDLE *pPolicySession;
    TPM2B_NONCE *pNonceTpm;
    TPM2B_DIGEST *pCpHash;
    TPM2B_NONCE *pPolicyRef;
    sbyte4 expiration;
} PolicySecretIn;

typedef struct {
    TPM2B_TIMEOUT timeout;
    TPMT_TK_AUTH policyTicket;
} PolicySecretOut;

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pAuthObject;
    MOCTPM2_OBJECT_HANDLE *pPolicySession;
    TPM2B_NONCE *pNonceTpm;
    TPM2B_DIGEST *pCpHash;
    TPM2B_NONCE *pPolicyRef;
    sbyte4 expiration;
    TPMT_SIGNATURE *pAuth;
} PolicySignedIn;

typedef struct {
    TPM2B_TIMEOUT timeout;
    TPMT_TK_AUTH policyTicket;
} PolicySignedOut;


typedef struct {
    MOCTPM2_OBJECT_HANDLE *pPolicySession;
    TPM2B_DIGEST *pPCRdigest;
    TPML_PCR_SELECTION *pPcrs;
} PolicyPCRIn;

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pPolicySession;
    TPM2B_DIGEST *pApprovedPolicy;
    TPM2B_NONCE *pPolicyRef;
    TPM2B_NAME *pKeySign;
    TPMT_TK_VERIFIED *pCheckTicket;
}PolicyAuthorizeIn;

typedef struct {
    /*
     * Indicates if authHandle should be for authorization
     * or if pNvIndexHandle is used. If TRUE,
     * pNvIndexHandle->tpm2Handle is used and pAuthHandleAuth
     * will be assumed to be the authValue of the NV index.
     * If FALSE, authHandle will be checked to ensure it is
     * either TPM2_RH_OWNER or TPM2_RH_PLATFORM and pAuthHandleAuth
     * will be assumed to be the authValue of authHandle.
     */
    byteBoolean useNvHandleForAuth;
    TPMI_RH_PROVISION authHandle;
    MOCTPM2_OBJECT_HANDLE *pNvIndexHandle;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
    TPM2B_AUTH *pAuthHandleAuth;
    MOCTPM2_OBJECT_HANDLE *pPolicySession;
} PolicyAuthorizeNVIn;

TSS2_RC SAPI2_EA_PolicyGetDigest(
        SAPI2_CONTEXT *pSapiContext,
        PolicyGetDigestIn *pIn,
        PolicyGetDigestOut *pOut
);

TSS2_RC SAPI2_EA_PolicyAuthValue(
        SAPI2_CONTEXT *pSapiContext,
        PolicyAuthValueIn *pIn
);

TSS2_RC SAPI2_EA_PolicyAuthorize(
        SAPI2_CONTEXT *pSapiContext,
        PolicyAuthorizeIn *pIn
);

TSS2_RC SAPI2_EA_PolicyAuthorizeNV(
        SAPI2_CONTEXT *pSapiContext,
        PolicyAuthorizeNVIn *pIn
);

TSS2_RC SAPI2_EA_PolicyPCR(
        SAPI2_CONTEXT *pSapiContext,
        PolicyPCRIn *pIn
);

TSS2_RC SAPI2_EA_PolicySecret(
        SAPI2_CONTEXT *pSapiContext,
        PolicySecretIn *pIn,
        PolicySecretOut *pOut
);

TSS2_RC SAPI2_EA_PolicySigned(
        SAPI2_CONTEXT *pSapiContext,
        PolicySignedIn *pIn,
        PolicySignedOut *pOut
);
TSS2_RC SAPI2_EA_PolicyDuplicationSelect(
        SAPI2_CONTEXT *pSapiContext,
        PolicyDuplicationSelectIn *pIn
);
TSS2_RC SAPI2_EA_PolicyCommandCode(
        SAPI2_CONTEXT *pSapiContext,
        PolicyCommandCodeIn *pIn
);

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
#endif /* __SAPI2_ENAHANCED_AUTH_H__ */
