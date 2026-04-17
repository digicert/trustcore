/**
 * @file sapi2_session.h
 * @brief This file contains SAPI2 session management functions for TPM2.
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

#ifndef __SAPI2_SESSION_H__
#define __SAPI2_SESSION_H__

#if (defined(__ENABLE_DIGICERT_TPM2__))

#include "../tpm2_types.h"
#include "sapi2_handles.h"
#include "sapi2_context.h"

/* TODO: RK: For now we support only 2 sessions since they will only be used
 * for authorizations. We dont support other command attributes so we dont
 * require more than 2 sessions for any given command.
 */
#define SAPI2_MAX_SESSIONS 2

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pTpmKey;
    MOCTPM2_OBJECT_HANDLE *pBind;
    TPM2B_NONCE nonceCaller;
    TPM2_SE sessionType;
    TPMT_SYM_DEF symmetric;
    TPMI_ALG_HASH authHash;
} StartAuthSessionIn;

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pSessionHandle;
} StartAuthSessionOut;

typedef struct
{
    ubyte4 digestSize;
    TPM2_ALG_ID hashAlgId;
    TPM2B_NONCE nonceOlder;
    TPM2B_NONCE nonceNewer;
    TPMA_SESSION attributes;
    ubyte sessionKey[sizeof(TPMU_HA)];
    ubyte4 keyLen;
    TPM2_SE sessionType;
    byteBoolean sessionHaspolicyAuthValue;
} MOCTPM2_SESSION;

MOC_EXTERN TSS2_RC SAPI2_SESSION_setSessionAttributes(
        MOCTPM2_OBJECT_HANDLE *pSessionHandle,
        TPMA_SESSION attributes);

MOC_EXTERN TSS2_RC SAPI2_SESSION_clearSessionAttributes(
        MOCTPM2_OBJECT_HANDLE *pSessionHandle,
        TPMA_SESSION attributes);

MOC_EXTERN TSS2_RC SAPI2_SESSION_StartAuthSession(
        SAPI2_CONTEXT *pSapiContext,
        StartAuthSessionIn *pIn,
        StartAuthSessionOut *pOut
);

TSS2_RC SAPI2_SESSION_getNonceNewer(
        MOCTPM2_OBJECT_HANDLE *pSessionHandle,
        TPM2B_NONCE **pNonceNewer
);

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /* __SAPI2_SESSION_H__ */
