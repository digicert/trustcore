/**
 * @file sapi2_ctx_mgmt.h
 * @brief This file contains code required to execute TPM2 context management
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
#ifndef __SAPI2_CTX_MGMT_H__
#define __SAPI2_CTX_MGMT_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "sapi2_context.h"
#include "sapi2_handles.h"

typedef struct {
    /*
     * This handle will be invalid if SAPI2_CTX_MGMT_FlushContext
     * is successful.
     */
    MOCTPM2_OBJECT_HANDLE **ppObjectHandle;
} FlushContextIn;

typedef struct {
    TPMI_RH_PROVISION authHandle;
    MOCTPM2_OBJECT_HANDLE *pObjectHandle;
    TPMI_DH_PERSISTENT persistentHandle;
    TPM2B_AUTH *pAuthAuthHandle;
    MOCTPM2_OBJECT_HANDLE *pAuthSession;
}EvictControlIn;

typedef struct {
    /*
     * The object handle MAY become invalid/NULL if the EvicControl API evicts the
     * object at the persistent handle. A new Handle is returned if EvictControl
     * converts a transient object into persistent object.
     */
    MOCTPM2_OBJECT_HANDLE *pPersistentHandle;
} EvictControlOut;

MOC_EXTERN TSS2_RC SAPI2_CTX_MGMT_FlushContext(
        SAPI2_CONTEXT *pSapiContext,
        FlushContextIn *pIn
);

MOC_EXTERN TSS2_RC SAPI2_CTX_MGMT_EvictControl(
        SAPI2_CONTEXT *pSapiContext,
        EvictControlIn *pIn,
        EvictControlOut *pOut
);
#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /* __SAPI2_CTX_MGMT_H__ */
