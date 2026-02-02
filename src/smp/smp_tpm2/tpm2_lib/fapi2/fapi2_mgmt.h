/**
 * @file fapi2_mgmt.h
 * @brief This file contains code and data structures for managing
 * the TPM2.
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
#ifndef __FAPI2_MGMT_H__
#define __FAPI2_MGMT_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "fapi2_context.h"

/*
 * This function gets a 32 bit value indicating the PCR's that are
 * available for a particular hash algorithm.
 */
MOC_EXTERN TSS2_RC FAPI2_MGMT_getPCRSelection(
        FAPI2_CONTEXT *pCtx,
        MgmtGetPcrSelectionIn *pIn,
        MgmtGetPcrSelectionOut *pOut
);

/*
 * This function is a direct map of the TPM2_GetCapability command. Its
 * use and input parameter values are documented in the TPM2 library
 * specifications. It is recommended to use wrapper/helper functions
 * for capability to simply application programming. This is provided
 * for advanced tpm users.
 */
MOC_EXTERN TSS2_RC FAPI2_MGMT_getCapability(
        FAPI2_CONTEXT *pCtx,
        MgmtCapabilityIn *pIn,
        MgmtCapabilityOut *pOut
);

/*
 * This function persists and object at the provided index. The function looks
 * up the transient object using the provided key name and stores it at the
 * index provided by the caller.
 */
MOC_EXTERN TSS2_RC FAPI2_MGMT_persistObject(
    FAPI2_CONTEXT *pCtx,
    TPM2B_NAME *pKeyName,
    ubyte4 objectId
    );

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */

#endif /* __FAPI2_MGMT_H__ */
