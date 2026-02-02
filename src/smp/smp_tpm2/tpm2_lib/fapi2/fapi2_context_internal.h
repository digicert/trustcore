/**
 * @file fapi2_context_internal.h
 * @brief This file contains definitions internal to fapi context.
 * This file must not be included by applications.
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
#ifndef __FAPI2_CONTEXT_INTERNAL_H__
#define __FAPI2_CONTEXT_INTERNAL_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "fapi2_context.h"
#include "../sapi2/sapi2.h"

typedef struct FAPI2_CONTEXT
{
    struct {
        TPMI_ALG_HASH sessionAlg;
        ubyte2 sessionAlgSize;
        TPM2_SE sessionType;
        TPMT_SYM_DEF paramEnc;
        TPMA_SESSION sessionAttributes;
    } sessionParams;

    struct {
        byteBoolean lockoutAuthValid;
        TPM2B_AUTH lockoutAuth;
        byteBoolean endorsementAuthValid;
        TPM2B_AUTH endorsementAuth;
        byteBoolean ownerAuthValid;
        TPM2B_AUTH ownerAuth;
    } authValues;

    struct {
        FAPI2_OBJECT *pEK;
        FAPI2_OBJECT *pSRK;
        MOCTPM2_OBJECT_HANDLE *pEKHandle;
        MOCTPM2_OBJECT_HANDLE *pSRKHandle;
    } primaryKeys;

    struct {
        ubyte objCacheSize;
        ubyte numUsed;

        struct {
            ubyte4 refCount;
            FAPI2_OBJECT *pObject;
        } *pObjectList;
    } objCache;

    TPMI_ALG_HASH nameAlg;
    ubyte2 nameAlgSize;
    TPMI_ALG_HASH tpmContextHashAlg;
    ubyte2 tpmContextHashAlgLen;
    ubyte4 maxNvIndexSize;
    ubyte4 maxNvTransactionSize;
    SAPI2_CONTEXT *pSapiCtx;
    ubyte provision;
} FAPI2_CONTEXT;


typedef struct {
    /*
     * Pointer to FAPI2_OBJECT that needs to be loaded. This parameter
     * cannot be NULL.
     */
    FAPI2_OBJECT *pObj;

    /*
     * Pointer to the authValue of the object. This parameter cannot be
     * NULL.
     */
    TPM2B_AUTH *pAuthObj;
} ContextLoadObjectExIn;

typedef struct {
    /*
     * Name of the object. The Name is cryptographically unique and identifies
     * a given TPM object. The name can be used to identify/use objects after
     * creation.
     */
    TPM2B_NAME objName;
} ContextLoadObjectExOut;

/*
 * This function loads a given object into the context and returns a handle(name)
 * to the object that can be used with the given context. Providing a handle
 * instead of passing around FAPI2_OBJECT structures is more efficient, especially
 * in case there is a remote application using FAPI2.
 */
MOC_EXTERN TSS2_RC FAPI2_CONTEXT_loadObjectEx(
        FAPI2_CONTEXT *pCtx,
        ContextLoadObjectExIn *pIn,
        ContextLoadObjectExOut *pOut
);

/*
 * This function looks up a FAPI2_OBJECT corresponding the given name.
 * It will return a failure if an object is not found.
 */
TSS2_RC FAPI2_CONTEXT_lookupObject(
        FAPI2_CONTEXT *pCtx,
        TPM2B_NAME *pName,
        FAPI2_OBJECT **ppObject
);

/*
 * This function looks up a FAPI2_OBJECT corresponding to the given primary
 * handle. It will return a failure if an object is not found.
 */
TSS2_RC FAPI2_CONTEXT_lookupPrimaryObjectByHandle(
        FAPI2_CONTEXT *pCtx,
        TPM2_HANDLE objectHandle,
        FAPI2_OBJECT **ppObject
);
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /* __FAPI2_CONTEXT_INTERNAL_H__ */
