/**
 * @file sapi2_sequence.h
 * @brief This file contains code required to execute TPM2 sequence commands such as hash
 * and hmac
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
#ifndef __SAPI2_SEQUENCE_H__
#define __SAPI2_SEQUENCE_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "sapi2_context.h"
#include "sapi2_handles.h"

typedef struct {
    TPM2B_AUTH *pSequenceAuth;
    TPMI_ALG_HASH hashAlg;
} HashSequenceStartIn;

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pHashSequenceHandle;
} HashSequenceStartOut;

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pHashSequenceHandle;
    TPM2B_AUTH *pSequenceAuth;
    TPM2B_MAX_BUFFER *pMaxBuffer;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} SequenceUpdateIn;

typedef struct {
    /*
     * Handle will be invalidated and free'd upon successfull completetion
     * of the command
     */
    MOCTPM2_OBJECT_HANDLE **ppHashSequenceHandle;
    TPM2B_AUTH *pSequenceAuth;
    TPM2B_MAX_BUFFER *pMaxBuffer;
    TPMI_RH_HIERARCHY hierarchy;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} SequenceCompleteIn;

typedef struct {
    TPM2B_DIGEST result;
    TPMT_TK_HASHCHECK validation;
} SequenceCompleteOut;


MOC_EXTERN TSS2_RC SAPI2_SEQUENCE_HashSequenceStart(
        SAPI2_CONTEXT *pSapiContext,
        HashSequenceStartIn *pIn,
        HashSequenceStartOut *pOut
);

MOC_EXTERN TSS2_RC SAPI2_SEQUENCE_SequenceUpdate(
        SAPI2_CONTEXT *pSapiContext,
        SequenceUpdateIn *pIn
);

MOC_EXTERN TSS2_RC SAPI2_SEQUENCE_SequenceComplete(
        SAPI2_CONTEXT *pSapiContext,
        SequenceCompleteIn *pIn,
        SequenceCompleteOut *pOut
);
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /* __SAPI2_SEQUENCE_H__ */
