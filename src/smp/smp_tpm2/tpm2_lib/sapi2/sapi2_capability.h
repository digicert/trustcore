
/**
 * @file sapi2_capability.h
 *
 * @brief This file has the structures used by TPM2 capability commands.
 *
 * @flags
 *  To enable this file's functions, the following flags must be defined in moptions.h:
 *  + \c \__ENABLE_DIGICERT_HW_SECURITY_MODULE__
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
#ifndef __SAPI2_CAPABILITY_H__
#define __SAPI2_CAPABILITY_H__

#include "../../../../common/moptions.h"

#if (defined(__ENABLE_DIGICERT_TPM2__))
#include "../tpm2_types.h"
#include "sapi2_context.h"

typedef struct {
    TPM2_CAP capability;
    ubyte4 property;
    ubyte4 propertyCount;
} GetCapabilityIn;

typedef struct {
    TPMI_YES_NO moreData;
    TPMS_CAPABILITY_DATA capabilityData;
} GetCapabilityOut;

MOC_EXTERN TSS2_RC SAPI2_CAPABILITY_GetCapability(
        SAPI2_CONTEXT *pSapiContext,
        GetCapabilityIn *pIn,
        GetCapabilityOut *pOut
);

#endif  /* (defined(__ENABLE_DIGICERT_TPM2__)) */
#endif /* __SAPI2_CAPABILITY_H__ */
