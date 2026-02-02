/**
 * @file sapi2_nv.h
 * @brief This file contains code required to execute TPM2 NV commands.
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
#ifndef __SAPI2_NV_H__
#define __SAPI2_NV_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "sapi2_context.h"
#include "sapi2_handles.h"

typedef struct {
    TPMI_RH_PROVISION authHandle;
    TPM2B_AUTH *pNvAuth;
    TPM2B_NV_PUBLIC *pPublicInfo;
    TPM2B_AUTH *pAuthHandleAuth;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} NVDefineSpaceIn;

typedef struct {
    MOCTPM2_OBJECT_HANDLE *pNvIndexHandle;
} NVDefineSpaceOut;

typedef struct {
    TPMI_RH_PROVISION authHandle;
    /*
     * This handle will be invalid if SAPI2_NV_NVUndefineSpace
     * is successful.
     */
    MOCTPM2_OBJECT_HANDLE **ppNvIndexHandle;
    TPM2B_AUTH *pAuthHandleAuth;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} NVUndefineSpaceIn;

typedef struct {
    /*
     * Indicates if authHandle should be for authprization
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
    TPM2B_MAX_NV_BUFFER *pData;
    ubyte2 offset;
    TPM2B_AUTH *pAuthHandleAuth;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} NVWriteIn;

typedef struct {
    /*
     * Indicates if authHandle should be for authprization
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
    ubyte2 size;
    ubyte2 offset;
    TPM2B_AUTH *pAuthHandleAuth;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} NVReadIn;

typedef struct {
    TPM2B_MAX_NV_BUFFER data;
} NVReadOut;

typedef struct {
    /*
     * The caller can provide one or both of the following fields.
     * pNvIndexHandle will take precedence if provided. If not
     * nvIndex will be used.
     */
    MOCTPM2_OBJECT_HANDLE *pNvIndexHandle;
    TPMI_RH_NV_INDEX nvIndex;
} NVReadPublicIn;

typedef struct {
    TPM2B_NV_PUBLIC nvPublic;
    TPM2B_NAME nvName;
} NVReadPublicOut;

typedef struct {
    /*
     * Indicates if authHandle should be for authprization
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

    TPM2B_AUTH *pAuthHandleAuth;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} NVIncrementIn;

typedef struct {
    /*
     * Indicates if authHandle should be for authprization
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
    TPM2B_MAX_NV_BUFFER *pData;
    TPM2B_AUTH *pAuthHandleAuth;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} NVExtendIn;

typedef struct {
    /*
     * Indicates if authHandle should be for authprization
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
    ubyte8 *pBits;
    TPM2B_AUTH *pAuthHandleAuth;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} NVSetBitsIn;

typedef struct {
    /*
     * Indicates if authHandle should be for authprization
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

    TPM2B_AUTH *pAuthHandleAuth;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} NVWriteLockIn;

typedef struct {
    TPMI_RH_PROVISION authHandle;
    TPM2B_AUTH *pAuthHandleAuth;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} NVGlobalWriteLockIn;

typedef struct {
    /*
     * Indicates if authHandle should be for authprization
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

    TPM2B_AUTH *pAuthHandleAuth;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
} NVReadLockIn;

MOC_EXTERN TSS2_RC SAPI2_NV_NVDefineSpace(
        SAPI2_CONTEXT *pSapiContext,
        NVDefineSpaceIn *pIn,
        NVDefineSpaceOut *pOut
);

MOC_EXTERN TSS2_RC SAPI2_NV_NVUndefineSpace(
        SAPI2_CONTEXT *pSapiContext,
        NVUndefineSpaceIn *pIn
);

MOC_EXTERN TSS2_RC SAPI2_NV_NVWrite(
        SAPI2_CONTEXT *pSapiContext,
        NVWriteIn *pIn
);

MOC_EXTERN TSS2_RC SAPI2_NV_NVRead(
        SAPI2_CONTEXT *pSapiContext,
        NVReadIn *pIn,
        NVReadOut *pOut
);

MOC_EXTERN TSS2_RC SAPI2_NV_NVReadPublic(
        SAPI2_CONTEXT *pSapiContext,
        NVReadPublicIn *pIn,
        NVReadPublicOut *pOut
);

MOC_EXTERN TSS2_RC SAPI2_NV_NVIncrement(
        SAPI2_CONTEXT *pSapiContext,
        NVIncrementIn *pIn
);

MOC_EXTERN TSS2_RC SAPI2_NV_NVExtend(
        SAPI2_CONTEXT *pSapiContext,
        NVExtendIn *pIn
);

MOC_EXTERN TSS2_RC SAPI2_NV_NVSetBits(
        SAPI2_CONTEXT *pSapiContext,
        NVSetBitsIn *pIn
);

MOC_EXTERN TSS2_RC SAPI2_NV_NVWriteLock(
        SAPI2_CONTEXT *pSapiContext,
        NVWriteLockIn *pIn
);

/*
 * After using this function, a caller must call
 * SAPI2_NV_NVUpdateNameWithAttribute to update the
 * name of the NV index. See comments for
 * SAPI2_NV_NVUpdateNameWithAttribute for more.
 */

MOC_EXTERN TSS2_RC SAPI2_NV_NVGlobalWriteLock(
        SAPI2_CONTEXT *pSapiContext,
        NVGlobalWriteLockIn *pIn
);

MOC_EXTERN TSS2_RC SAPI2_NV_NVReadLock(
        SAPI2_CONTEXT *pSapiContext,
        NVReadLockIn *pIn
);

/*
 * This helper function updates the name of an NV index when
 * the NV index is written to or locked. WHen an NV index is
 * written or locked, attributes in the public area of the index
 * are updated and the name must be updated for further use of the
 * NV index. THis is automatically done for all required commands
 * EXCEPT SAPI2_NV_NVGlobalWriteLock. This command updates the public
 * area of ALL NV index's with TPMA_NV_GLOBALLOCK set. Since SAPI does
 * not keep track of all index's this function must be called manually
 * after SAPI2_NV_NVGlobalWriteLock is called.
 */
MOC_EXTERN TSS2_RC SAPI2_NV_NVUpdateNameWithAttribute(
        MOCTPM2_OBJECT_HANDLE *pNvIndexHandle,
        TPMA_NV nvAttr
);
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /* __SAPI2_NV_H__ */
