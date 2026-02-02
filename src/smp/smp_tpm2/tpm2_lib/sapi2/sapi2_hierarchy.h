/**
 * @file sapi2_hierarchy.h
 * @brief This file contains code required to execute hierarchy commands.
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
#ifndef __SAPI2_HIERARCHY_H__
#define __SAPI2_HIERARCHY_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "sapi2_context.h"
#include "sapi2_handles.h"

typedef struct {
    TPMI_RH_HIERARCHY_AUTH authHandle;
    TPM2B_AUTH *pNewAuth;
    TPM2B_AUTH *pCurrentAuth;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} HierarchyChangeAuthIn;

typedef struct {
    TPMI_RH_HIERARCHY primaryHandle;
    TPM2B_SENSITIVE_CREATE *pInSensitive;
    TPM2B_PUBLIC *pInPublic;
    TPM2B_DATA *pOutsideInfo;
    TPML_PCR_SELECTION *pCreationPCR;
    TPM2B_AUTH *pAuthPrimaryHandle;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} CreatePrimaryIn;

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pObjectHandle;
    TPM2B_PUBLIC outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST creationHash;
    TPMT_TK_CREATION creationTicket;
} CreatePrimaryOut;

typedef struct {
    TPMI_RH_HIERARCHY primaryHandle;
    TPMI_RH_ENABLES enable;
    TPMI_YES_NO state;
    TPM2B_AUTH *pAuthPrimaryHandle;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} HierarchyControlIn;

typedef struct {
    TPMI_RH_CLEAR authHandle;
    TPM2B_AUTH *pAuthAuthHandle;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} ClearIn;

typedef struct {
    TPMI_RH_CLEAR authHandle;
    TPM2B_AUTH *pAuthAuthHandle;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} DALockoutResetIn;

typedef struct {
    TPMI_RH_CLEAR authHandle;
    TPM2B_AUTH *pAuthAuthHandle;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
    TPM2_DA_LOCKOUT_PARAMETERS lockoutParameters;
} DALockoutParametersIn;

typedef struct {
    TPMI_RH_CLEAR authHandle;
    TPMI_YES_NO disable;
    TPM2B_AUTH *pAuthAuthHandle;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} ClearControlIn;

MOC_EXTERN TSS2_RC SAPI2_HIERARCHY_HierarchyChangeAuth(
        SAPI2_CONTEXT *pSapiContext,
        HierarchyChangeAuthIn *pIn
);

MOC_EXTERN TSS2_RC
SAPI2_HIERARCHY_CreatePrimary(
        SAPI2_CONTEXT *pSapiContext,
        CreatePrimaryIn *pIn,
        CreatePrimaryOut *pOut
);

MOC_EXTERN TSS2_RC
SAPI2_HIERARCHY_HierarchyControl(
        SAPI2_CONTEXT *pSapiContext,
        HierarchyControlIn *pIn
);

MOC_EXTERN TSS2_RC
SAPI2_HIERARCHY_Clear(
        SAPI2_CONTEXT *pSapiContext,
        ClearIn *pIn
);

TSS2_RC
SAPI2_HIERARCHY_DALockoutReset(
        SAPI2_CONTEXT *pSapiContext,
        DALockoutResetIn *pIn
);

MOC_EXTERN TSS2_RC
SAPI2_HIERARCHY_ClearControl(
        SAPI2_CONTEXT *pSapiContext,
        ClearControlIn *pIn
);

MOC_EXTERN TSS2_RC
SAPI2_HIERARCHY_DALockoutParameters(
        SAPI2_CONTEXT *pSapiContext,
        DALockoutParametersIn *pIn
);

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /* __SAPI2_HIERARCHY_H__ */
