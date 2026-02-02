
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
