/**
 * @file sapi2_integrity.h
 * @brief This file contains code required to execute PCR related commands.
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
#ifndef __SAPI2_INTEGRITY_H__
#define __SAPI2_INTEGRITY_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "sapi2_context.h"
#include "sapi2_handles.h"

typedef struct {
    TPMI_DH_PCR pcrHandle;
    TPML_DIGEST_VALUES *pDigests;
    TPM2B_AUTH *pAuthPcrHandle;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} PCRExtendIn;

typedef struct {
    TPMI_DH_PCR pcrHandle;
    TPM2B_EVENT *pEventData;
    TPM2B_AUTH *pAuthPcrHandle;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} PCREventIn;

typedef struct {
    TPML_DIGEST_VALUES digests;
} PCREventOut;

typedef struct {
    TPML_PCR_SELECTION *pPcrSelectionIn;
} PCRReadIn;

typedef struct {
    ubyte4 pcrUpdateCounter;
    TPML_PCR_SELECTION pcrSelectionOut;
    TPML_DIGEST pcrValues;
} PCRReadOut;

typedef struct {
    TPMI_DH_PCR pcrHandle;
    TPM2B_DIGEST *pNewAuth;
    TPM2B_AUTH *pAuthPcrHandle;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} PCRSetAuthValueIn;

typedef struct {
    TPMI_DH_PCR pcrHandle;
    TPM2B_AUTH *pAuthPcrHandle;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} PCRResetIn;

MOC_EXTERN TSS2_RC SAPI2_INTEGRITY_PCRExtend(
        SAPI2_CONTEXT *pSapiContext,
        PCRExtendIn *pIn
);

MOC_EXTERN TSS2_RC SAPI2_INTEGRITY_PCREvent(
        SAPI2_CONTEXT *pSapiContext,
        PCREventIn *pIn,
        PCREventOut *pOut
);

MOC_EXTERN TSS2_RC SAPI2_INTEGRITY_PCRRead(
        SAPI2_CONTEXT *pSapiContext,
        PCRReadIn *pIn,
        PCRReadOut *pOut
);

MOC_EXTERN TSS2_RC SAPI2_INTEGRITY_PCRSetAuthValue(
        SAPI2_CONTEXT *pSapiContext,
        PCRSetAuthValueIn *pIn
);

MOC_EXTERN TSS2_RC SAPI2_INTEGRITY_PCRReset(
        SAPI2_CONTEXT *pSapiContext,
        PCRResetIn *pIn
);

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
#endif /* __SAPI2_INTEGRITY_H__ */
