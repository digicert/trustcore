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
