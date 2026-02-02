/**
 * @file sapi2_object.h
 * @brief This file contains code required to execute object commands.
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
#ifndef __SAPI2_OBJECT_H__
#define __SAPI2_OBJECT_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "sapi2_context.h"
#include "sapi2_handles.h"

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pParentHandle;
    TPM2B_SENSITIVE_CREATE *pInSensitive;
    TPM2B_PUBLIC *pInPublic;
    TPM2B_DATA *pOutsideInfo;
    TPML_PCR_SELECTION *pCreationPCR;
    TPM2B_AUTH *pAuthParentHandle;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} CreateIn;

typedef struct {
    TPM2B_PRIVATE outPrivate;
    TPM2B_PUBLIC outPublic;
    TPM2B_CREATION_DATA creationData;
    TPM2B_DIGEST creationHash;
    TPMT_TK_CREATION creationTicket;
} CreateOut;

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pHandle;
    MOCTPM2_OBJECT_HANDLE *pNewParentHandle;
    TPM2B_DATA *pEncryptKeyIn;
    TPMT_SYM_DEF_OBJECT *pSymmetricAlg;
    TPM2B_AUTH *pAuthHandle;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} DuplicateIn;

typedef struct {
    TPM2B_DATA			encryptionKeyOut;
    TPM2B_PRIVATE		duplicate;
    TPM2B_ENCRYPTED_SECRET	outSymSeed;
} DuplicateOut;

typedef struct {
    MOCTPM2_OBJECT_HANDLE		*pParentHandle;
    TPM2B_DATA			        *pEncryptionKey;
    TPM2B_PUBLIC		        *pObjectPublic;
    TPM2B_PRIVATE		        *pDuplicate;
    TPM2B_ENCRYPTED_SECRET	    *pInSymSeed;
    TPMT_SYM_DEF_OBJECT		    *pSymmetricAlg;
    TPM2B_AUTH *pAuthParentHandle;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} ImportIn;

typedef struct {
    TPM2B_PRIVATE	outPrivate;
} ImportOut;

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pParentHandle;
    TPM2B_PRIVATE *pInPrivate;
    TPM2B_PUBLIC *pInPublic;
    TPM2B_AUTH *pAuthParentHandle;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} LoadIn;

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pObjectHandle;
} LoadOut;

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pItemHandle;
    TPM2B_AUTH *pAuthItemHandle;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} UnsealIn;

typedef struct {
    TPM2B_SENSITIVE_DATA outData;
} UnsealOut;

typedef struct {
    /*
     * The caller can provide one or both of the following fields.
     * pObjectHandle will take precedence if provided. If not
     * objectHandle will be used.
     */
    MOCTPM2_OBJECT_HANDLE *pObjectHandle;
    TPMI_DH_OBJECT objectHandle;
} ReadPublicIn;

typedef struct {
    TPM2B_PUBLIC outPublic;
    TPM2B_NAME name;
    TPM2B_NAME qualifiedName;
} ReadPublicOut;

typedef struct {
    TPM2B_SENSITIVE *pInSensitive;
    TPM2B_PUBLIC *pInPublic;
    TPMI_RH_HIERARCHY hierarchy;
} LoadExternalIn;

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pObjectHandle;
} LoadExternalOut;

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pParentHandle;
    MOCTPM2_OBJECT_HANDLE *pObjectHandle;
    TPM2B_AUTH *pAuthObjectHandle;
    TPM2B_AUTH *pNewAuth;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} ObjectChangeAuthIn;

typedef struct {
    TPM2B_PRIVATE outPrivate;
} ObjectChangeAuthOut;

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pObjectHandle;
    TPM2B_DIGEST *pCredential;
    TPM2B_NAME *pName;
} MakeCredentialIn;

typedef struct {
    TPM2B_ID_OBJECT credentialBlob;
    TPM2B_ENCRYPTED_SECRET secret;
} MakeCredentialOut;

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pActivateHandle;
    TPM2B_AUTH *pAuthActivateHandle;
    MOCTPM2_OBJECT_HANDLE *pAuthSessionActivateHandle;
    MOCTPM2_OBJECT_HANDLE *pKeyHandle;
    TPM2B_AUTH *pAuthKeyHandle;
    MOCTPM2_OBJECT_HANDLE *pAuthSessionKeyHandle;
    TPM2B_ID_OBJECT *pCredentialBlob;
    TPM2B_ENCRYPTED_SECRET *pSecret;
} ActivateCredentialIn;

typedef struct {
    TPM2B_DIGEST certInfo;
} ActivateCredentialOut;

MOC_EXTERN TSS2_RC SAPI2_OBJECT_Create(
        SAPI2_CONTEXT *pSapiContext,
        CreateIn *pIn,
        CreateOut *pOut
);

MOC_EXTERN TSS2_RC SAPI2_OBJECT_Load(
        SAPI2_CONTEXT *pSapiContext,
        LoadIn *pIn,
        LoadOut *pOut
);

MOC_EXTERN TSS2_RC SAPI2_OBJECT_Unseal(
        SAPI2_CONTEXT *pSapiContext,
        UnsealIn *pIn,
        UnsealOut *pOut
);

MOC_EXTERN TSS2_RC SAPI2_OBJECT_ReadPublic(
        SAPI2_CONTEXT *pSapiContext,
        ReadPublicIn *pIn,
        ReadPublicOut *pOut
);

TSS2_RC SAPI2_OBJECT_LoadExternal(
        SAPI2_CONTEXT *pSapiContext,
        LoadExternalIn *pIn,
        LoadExternalOut *pOut
);

TSS2_RC SAPI2_OBJECT_ObjectChangeAuth(
        SAPI2_CONTEXT *pSapiContext,
        ObjectChangeAuthIn *pIn,
        ObjectChangeAuthOut *pOut
);

MOC_EXTERN TSS2_RC SAPI2_OBJECT_MakeCredential(
        SAPI2_CONTEXT *pSapiContext,
        MakeCredentialIn *pIn,
        MakeCredentialOut *pOut
);

MOC_EXTERN TSS2_RC SAPI2_OBJECT_ActivateCredential(
        SAPI2_CONTEXT *pSapiContext,
        ActivateCredentialIn *pIn,
        ActivateCredentialOut *pOut
);

TSS2_RC SAPI2_OBJECT_DuplicateKey(
        SAPI2_CONTEXT *pSapiContext,
        DuplicateIn *pIn,
        DuplicateOut *pOut
);

TSS2_RC SAPI2_OBJECT_ImportDuplicateKey(
        SAPI2_CONTEXT *pSapiContext,
        ImportIn *pIn,
        ImportOut *pOut
);

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /* __SAPI2_OBJECT_H__ */
